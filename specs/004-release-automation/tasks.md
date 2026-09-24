---
feature: 004-release-automation
created: 2026-09-19
updated: 2026-09-24
---

# Tasks: Release automation

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Add `.goreleaser.yaml` with `version: 2`, a `builds` entry cross-compiling
      `./cmd/service` for `linux/amd64` and `linux/arm64` with `CGO_ENABLED=0`, `-trimpath`,
      and the same `-X main.version/commit/buildDate` ldflags `magefile.go` stamps, plus a
      `changelog` section grouping Conventional Commit types.
  - Satisfies: `AC-004.4`, `AC-004.5`
  - Verify: `goreleaser check && goreleaser build --snapshot --clean --single-target`

- [x] **T2** Add `Dockerfile.release`: assembly only, copying the architecture-specific
      binary GoReleaser places in the build context into
      `gcr.io/distroless/static-debian12:nonroot`, with the same `EXPOSE`, `USER`, and
      `ENTRYPOINT` as `Dockerfile`.
  - Satisfies: `AC-004.2`
  - Verify: `go tool mage snapshot`, then `docker run --rm` the resulting
    platform-suffixed image and confirm it logs the stamped version and binds both listeners

- [x] **T3** Add the `dockers_v2` section to `.goreleaser.yaml`: `ghcr.io` image name from
      the repository owner and name, both platforms, the `X.Y.Z`/`X.Y`/`X`/`latest` tag set,
      OCI annotations, and `dockerfile: Dockerfile.release`.
  - Satisfies: `AC-004.1`, `AC-004.2`, `AC-004.3`
  - Verify: `goreleaser check` and a snapshot run producing a local multi-arch manifest

- [x] **T4** Add the `docker_signs` section configuring keyless cosign signing over
      `${artifact}@${digest}`, disabled on snapshot builds.
  - Satisfies: `AC-004.8`, `AC-004.10`
  - Verify: `goreleaser check`; end-to-end by `cosign verify` after the first real tag

- [x] **T5** Add `.github/workflows/release.yml`: triggered only by `v*.*.*` tags, a `gate`
      job calling `ci.yml` through a new `workflow_call` trigger, and a `release` job that
      needs it, checks out with `fetch-depth: 0`, logs in to GHCR, and runs
      `goreleaser/goreleaser-action@v7` pinned to `~> v2`.
  - Satisfies: `AC-004.1`, `AC-004.6`, `AC-004.7`
  - Verify: `actionlint .github/workflows/release.yml`; end-to-end on the first tag

- [x] **T6** Add the provenance step to the `release` job: `actions/attest-build-provenance`
      reading `dist/digests.txt`, with `attestations: write` and `id-token: write`.
  - Satisfies: `AC-004.9`, `AC-004.10`
  - Verify: `gh attestation verify oci://ghcr.io/<owner>/service:<version> --repo <owner>/service`

- [x] **T7** Add a `goreleaser check` step to `ci.yml`, so a release configuration that no
      longer validates fails on the pull request that broke it rather than on the next tag.
  - Satisfies: `AC-004.6`
  - Verify: `goreleaser check` locally; the job appearing on the next pull request

- [x] **T8** Add `ReleaseCheck` and `Snapshot` targets to `magefile.go` wrapping
      `goreleaser check` and `goreleaser release --snapshot --clean`, so the pre-tag
      rehearsal is a target rather than a remembered command.
  - Satisfies: `AC-004.5`
  - Verify: `go tool mage -l` lists both; `go tool mage snapshot` builds without publishing

- [x] **T9** Add `.github/dependabot.yml` covering `gomod`, `github-actions`, and `docker`
      on a weekly schedule, with minor and patch updates grouped per ecosystem.
  - Satisfies: `AC-004.11`, `AC-004.12`
  - Verify: the file validates in the repository's Insights > Dependency graph > Dependabot
    tab, and the first pull request it opens runs CI

- [x] **T10** Document the release procedure and the two verification commands in
      `README.md`, and close this spec by setting `requirements.md` to `status: implemented`.
  - Satisfies: all of the above
  - Verify: `README.md` names the tag format, the published image, and both verify commands

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-004.1` | T3, T5 | First tag publishes to `ghcr.io`; `docker pull` succeeds |
| `AC-004.2` | T2, T3 | `docker manifest inspect` lists both platforms |
| `AC-004.3` | T3 | `docker pull` of each of the four tags resolves to one digest |
| `AC-004.4` | T1 | Container logs report the tagged version and commit at startup |
| `AC-004.5` | T1, T8 | The GitHub Release body groups the commits since the previous tag |
| `AC-004.6` | T5, T7 | A deliberately failing test on a tag branch leaves the registry unchanged |
| `AC-004.7` | T5 | Pushing a non-matching tag starts no workflow run |
| `AC-004.8` | T4 | `cosign verify` with the workflow certificate identity |
| `AC-004.9` | T6 | `gh attestation verify oci://...` |
| `AC-004.10` | T4, T6 | Both steps are unconditional in the job; no `continue-on-error` |
| `AC-004.11` | T9 | Dependabot opens its first grouped pull request |
| `AC-004.12` | T9 | That pull request shows the CI checks |

## Deferred

- **SBOM attachment.** `dockers_v2` has an `sbom` key that would cost one line. Left out
  pending the open question in `requirements.md`, not because it is hard.
- **Release-time deployment.** Publishing only; see the non-goals.
- **`actionlint` as a CI job.** Worth adding for the workflows generally, but it belongs to a
  CI-hardening change rather than to this one.
