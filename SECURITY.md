# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository's Security tab. Do not open a public issue for a
vulnerability, and do not send a pull request that fixes one before it has been
discussed: either of those publishes the problem before there is a release that
fixes it.

Expect an acknowledgement within a week. This is a small project with one
maintainer, so a fix takes as long as it takes; you will be kept updated on
progress rather than left waiting.

## Supported versions

The most recent released version. There are no long-term support branches, and
no backports to earlier tags.

## What is in scope

- The published container image and the binary inside it.
- Anything reachable on the application listener.

## What is not in scope

- **The administrative listener** (`/metrics`, `/debug/pprof/`, `/version`,
  health, and readiness). It binds loopback by default and is documented as requiring a
  network policy if it is moved. Reaching profiling endpoints that were
  deliberately exposed is a deployment finding, not a vulnerability in this
  software. See `README.md` and `docs/adr/0007-deployment-topology.md`.
- **Running without a TLS-terminating reverse proxy.** The service is
  documented as unsafe to expose directly to the internet; `docs/adr/0007`
  records why.
- **Trusting forwarded headers from an untrusted peer.** Nothing is trusted
  unless an operator lists its network in `SERVICE_PROXY_TRUSTED_CIDRS`. See
  `docs/adr/0008-proxy-trust-and-request-identity.md`.

## Verifying a release

Every published image is signed, and images from public builds carry provenance.
The commands are in `README.md` under Releases. An image that fails
verification should be treated as untrusted and reported.
