---
feature: 004-release-automation
created: 2026-09-19
updated: 2026-09-20
status: unverified
---

# Requirements: Release automation

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

`003-build-and-release` deliberately stopped at CI and named release automation as a later
decision. The consequence is that there is no way to ship this service other than by hand:
a maintainer builds an image locally, tags it from memory, and pushes it from a workstation
whose Go version, Docker version, and working tree state nobody can reconstruct afterwards.
Nothing records which commit produced a running image, nothing lets a consumer check that an
image came from this repository rather than from someone who guessed the name, and nothing
tells a maintainer that a dependency has moved on.

The cost lands at the worst moment. When an incident asks "what is actually deployed", the
answer is a person's memory. When a supply-chain advisory lands, the answer to "was our image
built from clean source" is also a person's memory.

## Goal

Pushing a semantic version tag produces a multi-architecture container image on GHCR that is
signed, carries build provenance, and comes with release notes generated from the commit
history; and dependency updates arrive as pull requests rather than as a periodic manual
sweep.

## Non-goals

- **Deploying anything.** This publishes artifacts. Choosing a deployment platform and
  wiring a rollout remains out of scope, as it was in `003`.
- **Binary archives.** Only a container image is published. `docs/adr/0007` fixes the
  deployment topology as a container behind a reverse proxy, so tarballs would be an
  artifact with no consumer.
- **Automatic version bumping.** Tags are created by a human. Nothing here computes the next
  version from commit messages.
- **Automatic merging of dependency updates.** Dependabot opens pull requests; CI gates them;
  a human merges them.

## User stories

### Story 1: Maintainer ships a version

As a `maintainer`, I want pushing a version tag to publish the corresponding image, so that
releasing does not depend on the state of my workstation.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-004.1`: WHEN a tag matching `v*.*.*` is pushed, the system SHALL build and publish a container image to `ghcr.io` under this repository's owner and name.
- `AC-004.2`: The published image SHALL be a multi-architecture manifest covering `linux/amd64` and `linux/arm64`.
- `AC-004.3`: WHEN an image is published for tag `vX.Y.Z`, the system SHALL tag it `X.Y.Z`, `X.Y`, `X`, and `latest`.
- `AC-004.4`: WHEN an image is published, the binary inside it SHALL report the released version, the tagged commit, and the build date through the mechanism `AC-003.2` established.
- `AC-004.5`: WHEN a release is published, the system SHALL generate release notes grouping the Conventional Commit subjects added since the previous tag.
- `AC-004.6`: IF lint, the race-enabled test suite, or the vulnerability scan fails, THEN the system SHALL NOT publish any artifact.
- `AC-004.7`: IF a pushed tag does not match `v*.*.*`, THEN the system SHALL NOT start a release.

### Story 2: Consumer verifies where an image came from

As an `operator pulling the image`, I want each image to carry a signature and provenance, so
that I can establish it was built by this repository's workflow from a known commit before I
run it.

**Acceptance criteria**:

- `AC-004.8`: WHEN an image is published, the system SHALL produce a keyless Sigstore signature over the published digest, verifiable with `cosign verify` against this repository's workflow identity.
- `AC-004.9`: WHERE the repository is public, WHEN an image is published, the system SHALL attach a build provenance attestation covering the published digest, verifiable with `gh attestation verify`.
- `AC-004.10`: IF signing fails, or IF attestation is attempted and fails, THEN the release SHALL fail rather than complete unsigned.

### Story 3: Maintainer keeps dependencies current

As a `maintainer`, I want dependency updates proposed automatically, so that the vulnerability
gate in CI is not the first place a stale dependency is noticed.

**Acceptance criteria**:

- `AC-004.11`: The system SHALL open pull requests for outdated Go module requirements, GitHub Actions versions, and container base images on a weekly schedule.
- `AC-004.12`: WHEN a dependency pull request is opened, CI SHALL run against it unchanged, so that an update that breaks the build cannot merge green.

## Constraints

- **No long-lived registry credentials.** Publishing uses the workflow's `GITHUB_TOKEN` with
  `packages: write`; signing uses GitHub's OIDC identity with `id-token: write`. A stored
  registry password or a cosign private key in secrets is not acceptable, because a template
  copied into other repositories would propagate the practice along with the files.
- **Publishing is reachable only from a tag.** A release must not be startable from a branch
  push or a pull request, since either would let unreviewed code claim a version.
- **Toolchain parity with CI.** The release must build with the Go version `go.mod` names, so
  that the artifact matches what the gates tested.
- **No fork-reachable secrets.** The release workflow must not run on `pull_request`, where a
  fork could otherwise reach the token.

## Open questions

- **SBOM.** `dockers_v2` exposes an `sbom` key that attaches a bill of materials to the image
  for approximately one line of configuration. It is deliberately left out of the criteria
  above pending a decision, because an SBOM that nothing consumes is a published artifact
  nobody checks, while `govulncheck` already answers the call-graph question an SBOM only
  approximates. Recorded here rather than silently included.

## Change log

Amendments after approval, newest first.

- `2026-09-20`: Status changed from `implemented` to `unverified`. No tag has ever been
  pushed, so the release workflow has never run, and every criterion here is verified by
  something that only a real release produces: a published image, a `cosign verify`, a
  `gh attestation verify`, a Dependabot pull request. The configuration validates and the
  workflow is committed, but nothing in this spec has been observed to hold. Returns to
  `implemented` after the first tag, if the criteria hold.
- `2026-09-19`: `AC-004.9` narrowed to public repositories, and `AC-004.10` follows it.
  GitHub issues artifact attestations only for public repositories, and for private or
  internal ones on GitHub Enterprise Cloud; this repository is private and not on GHEC, so
  the criterion as first written could not hold here. Keyless signing is unaffected and stays
  unconditional, because Sigstore imposes no equivalent restriction. Written as an EARS
  optional-feature clause rather than deleted, so a public project bootstrapped from this
  repository still has the criterion it needs.
- `2026-09-19`: Created. Picks up the release automation `003` listed as a non-goal.
