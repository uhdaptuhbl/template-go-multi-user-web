---
feature: 004-release-automation
created: 2026-09-19
updated: 2026-09-19
---

# Design: Release automation

## Overview

A `release.yml` workflow triggers on `v*.*.*` tags. It re-runs the same gates CI runs, then
hands the build to GoReleaser, which cross-compiles both architectures, assembles a
multi-architecture image through `docker buildx`, pushes it to GHCR, signs it keylessly with
cosign, and writes the release notes. On a public repository a following step reads the
digests GoReleaser recorded and attaches GitHub build provenance to them; see the change log
in `requirements.md` for why that step is conditional and signing is not. A `dependabot.yml` covers the three ecosystems
this repository actually has.

This satisfies `AC-004.1` through `AC-004.12`.

## Alternatives considered

| Option | Trade-off | Verdict |
| --- | --- | --- |
| GoReleaser | One config covers cross-compilation, image assembly, signing, and notes; `dockers_v2` is documented as alpha | **Chosen** |
| Hand-written workflow calling `docker buildx` and a mage target | No new tool, consistent with ADR 0009's "targets are Go" reasoning; but cross-compilation, tag computation, changelog grouping, and digest plumbing all become hand-maintained YAML | Rejected: reimplements GoReleaser badly |
| `ko` | Builds distroless images natively with no Dockerfile at all, excellent for pure-Go services | Rejected: discards the reviewed Dockerfile from `003` and the control it gives over the runtime base |
| GoReleaser's stable `dockers` + `docker_manifests` | Not alpha, but needs one entry per architecture plus a manifest entry, and does not produce the `digests.txt` that provenance needs | Rejected: more configuration, and it is the path being retired in GoReleaser v3 |
| Publishing to Docker Hub | Wider reach | Rejected: needs stored credentials, which the constraints forbid; GHCR authenticates with the workflow token |
| Doing nothing | Releases stay manual | Rejected: the problem statement is that manual releases are unreconstructable |

`dockers_v2` being alpha is the one real risk taken here. It is accepted because the action
pins GoReleaser to `~> v2`, because the alternative is the configuration GoReleaser v3
removes, and because a break surfaces at release time on a tag rather than silently in a
running service.

## Architecture

```
git tag v1.2.3
  |
  v
.github/workflows/release.yml
  |
  +-- gate job ......... calls .github/workflows/ci.yml
  |                      (lint, race tests, integration, tidy, build, vuln)
  |
  +-- release job ...... needs: gate
       |
       +-- goreleaser --clean
       |     |
       |     +-- build ......... linux/amd64 + linux/arm64 binaries, ldflags stamped
       |     +-- dockers_v2 .... buildx builds Dockerfile.release from a context
       |     |                   holding both binaries; pushes the manifest to GHCR
       |     +-- docker_signs .. cosign sign, keyless, over image@digest
       |     +-- changelog ..... Conventional Commit grouping into the release notes
       |     +-- dist/digests.txt
       |
       +-- actions/attest-build-provenance   (public repositories only)
             reads dist/digests.txt, attaches provenance to each digest
```

Two Dockerfiles exist afterwards, and that is a deliberate cost:

- `Dockerfile` stays the self-contained multi-stage build. It is what `mage Docker` runs and
  what a contributor builds from a clean checkout with no GoReleaser installed.
- `Dockerfile.release` is the assembly-only form GoReleaser needs, because `dockers_v2`
  presents a context that already holds the compiled binaries under `linux/amd64/` and
  `linux/arm64/`. It compiles nothing.

Both must copy into the same runtime base and set the same user, or a release image differs
from what a contributor tested. `Dockerfile.release` is kept to a handful of lines to make
divergence visible, and the `build` job in `ci.yml` already builds `Dockerfile` on every push,
so the two are exercised on different events rather than neither being exercised.

## Interfaces

**Workflow trigger.** `on.push.tags: ['v*.*.*']`. No `workflow_dispatch`, no `pull_request`.

**Gate reuse.** `ci.yml` gains a `workflow_call` trigger and the release calls it, rather than
restating its commands. Two copies of a gate drift, and the copy that drifts is the one that
runs less often, which here is the one guarding publication.

**Permissions.** `contents: write` to create the release, `packages: write` to push to GHCR,
`id-token: write` for keyless signing and provenance, `attestations: write` to record the
attestation, and `artifact-metadata: write` for its storage record. The workflow default is
`contents: read`; only the publishing job widens it, so the gate job holds none of them.

**Published image.** `ghcr.io/<owner>/<repo>`, tagged `X.Y.Z`, `X.Y`, `X`, and `latest`, with
OCI annotations for source, revision, and version.

**Verification, as an operator would run it:**

```sh
cosign verify ghcr.io/<owner>/<repo>:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/<owner>/<repo>:X.Y.Z --repo <owner>/<repo>
```

**Dependabot.** Three ecosystems: `gomod`, `github-actions`, and `docker`. Weekly. Grouped so
that a week of patch bumps arrives as one pull request rather than fifteen.

## Data

None. This feature persists nothing and migrates nothing. The only new durable artifacts are
the published image, its signature, and its attestation, all of which live in the registry.

## Failure modes

| Failure | Detection | Result |
| --- | --- | --- |
| Lint, test, or vulnerability gate fails | The gate job fails | No artifact is published; `AC-004.6` |
| Tag does not match `v*.*.*` | The trigger does not match | Workflow never starts; `AC-004.7` |
| `docker buildx` cannot build an architecture | GoReleaser exits non-zero | Nothing is pushed; the manifest is assembled and pushed as one unit |
| cosign signing fails | `docker_signs` exits non-zero | The release fails. The image may already be in the registry at this point, which is the honest failure: the digest is untagged-but-present and the release is marked failed rather than complete; `AC-004.10` |
| Provenance attestation fails | The attest step fails | The release fails, leaving a signed but unattested image, for the same reason. The step does not run at all on a private repository, so it cannot fail there |
| GoReleaser config drifts from schema | `goreleaser check` in CI | Caught on pull request rather than at release time |
| `Dockerfile.release` drifts from `Dockerfile` | Not automatically detected | Accepted risk, mitigated by keeping the release file trivially short and building the other on every push |

The two partial-failure rows are stated rather than papered over: making a registry push
transactional with signing is not something GitHub Actions offers, and pretending otherwise
in a template would teach the wrong lesson to every repository copied from it.

## Security and privacy

- **Trust boundary crossed:** this repository's workflow becomes a publisher of artifacts
  others run. Signing exists so that boundary is checkable rather than assumed.
- **No stored secrets.** Registry auth is `GITHUB_TOKEN`; signing identity is the workflow's
  OIDC token. There is no key to leak, rotate, or accidentally commit. Verification is by
  workflow identity, so a signature proves which workflow in which repository produced it.
- **Tag-only trigger.** A release cannot be started from a fork or from a pull request, so the
  publishing permissions are unreachable by unreviewed code.
- **Least privilege per job.** The gate job runs with `contents: read` only.
- **No personal data.** The release path handles none.

## Test strategy

Following `003`: these are workflow and packaging concerns with no meaningful unit tests, so
each criterion names the command that demonstrates it.

- Static: `goreleaser check` validates the configuration, and runs in CI on every pull
  request, so a broken release config is caught before a tag depends on it.
- Local dry run: `goreleaser release --snapshot --clean` builds both architectures and the
  image without publishing, signing, or tagging. This is the pre-tag rehearsal and is exposed
  as a mage target so it is not a command to remember.
- End-to-end: the first real tag. Verified by pulling the published image, running
  `cosign verify` and `gh attestation verify` against it, and confirming the binary reports
  the tagged version.
- Dependabot is verified by its first pull request running CI, which is observable rather
  than testable in advance.

## Observability

No new runtime telemetry: nothing here runs in the service. The release itself is observable
through the workflow run, the GitHub Release, and the registry. The one question worth asking
later is "which commit is this running image", and `AC-004.4` answers it by stamping the
commit into the binary, which `internal/buildinfo` already logs at startup and publishes as
the `build_info` metric.
