---
feature: 007-local-gateway
created: 2026-09-20
updated: 2026-09-24
status: implemented
---

# Requirements: Local gateway

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

`docs/adr/0007-deployment-topology.md` is accepted and says this service is always deployed
behind a TLS-terminating reverse proxy. Everything downstream of that decision is built:
the service reads `X-Forwarded-For` and `X-Request-Id`, but only from a peer inside
`SERVICE_PROXY_TRUSTED_CIDRS`, and that list defaults to empty so an unconfigured
deployment cannot be lied to about who a request came from.

Nothing a developer can run exercises any of it. The local Compose stack points a browser
straight at the application listener, which is the one topology the ADR says never happens.
The consequence is that the proxy-facing code path has no way to be wrong locally. A
misconfigured `X-Forwarded-For`, a trusted-CIDR list that does not contain the proxy, or a
proxy that forwards a client's own correlation ID all produce a stack that works in
development and attributes every request to the load balancer in production, or worse,
believes whatever a client claims about itself.

There is a second cost. A developer who has never seen the stack with a proxy in it has no
reference for what the real one should send, and the first production nginx configuration
gets written from memory.

## Goal

Once this ships, `docker compose up` gives a developer the topology the ADR describes: a
reverse proxy in front, the application listener reachable only through it, forwarded
headers set the way a real edge sets them, and the service configured to believe them. The
proxy configuration is a file in the repository that a production deployment can start
from rather than a paragraph in a README.

## Non-goals

This feature does not terminate TLS locally. A certificate a developer has to trust, or a
browser warning they have to click through, buys nothing here: what is being exercised is
the forwarded-header contract, which is identical over plain HTTP. TLS remains the
production proxy's job under ADR 0007, and `X-Forwarded-Proto` is set to `https` nowhere
locally, because saying so would be a lie the service could act on.

This feature does not make the local stack a production deployment artifact. There is no
certificate lifecycle, no HTTP-to-HTTPS redirect, no HSTS, no compression, and no rate
limiting. Those belong to the real proxy and are named in ADR 0007 as its responsibilities.

This feature does not change the administrative listener's exposure. It stays published to
loopback on the host and is not routed through the gateway.

This feature does not change any Go code. Every criterion below is about a configuration
artifact, and the service already implements the behaviour they exercise.

## User stories

### Story 1: The topology the ADR describes

As a developer, I want the local stack to put a reverse proxy in front of the service, so
that what I run locally is the shape the service is actually deployed in.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-007.1`: The local stack SHALL route application requests through a reverse proxy, and
  the application listener SHALL NOT be published to the host.
- `AC-007.2`: The reverse proxy SHALL serve plain HTTP, and SHALL NOT claim a request
  arrived over HTTPS.
- `AC-007.3`: The reverse proxy SHALL NOT route to the administrative listener.
- `AC-007.4`: The Compose file SHALL validate with `docker compose config`.

### Story 2: Forwarded headers an edge proxy sets

As a developer, I want the proxy to set the forwarded headers the way a real edge sets
them, so that a mistake in how the service reads them is visible locally rather than in
production.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-007.5`: The reverse proxy SHALL set `X-Forwarded-For` to the address of the peer that
  connected to it, discarding any value the client supplied.
- `AC-007.6`: The reverse proxy SHALL set `X-Request-Id` to a value it generates,
  discarding any value the client supplied.
- `AC-007.7`: The reverse proxy SHALL set `X-Forwarded-Proto` to the scheme the client used
  and SHALL preserve the client's `Host`.
- `AC-007.8`: WHEN a request is made through the gateway, the response SHALL carry the
  `X-Request-Id` the proxy generated.
- `AC-007.9`: WHEN a request is made through the gateway, the request the service logs
  SHALL be attributed to the address that connected to the proxy rather than to the proxy.

### Story 3: A service configured to believe it

As a developer, I want the service configured to trust the gateway, so that the forwarded
values are acted on rather than discarded and the trust configuration itself is exercised.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-007.10`: The local stack SHALL set `SERVICE_PROXY_TRUSTED_CIDRS` to a network that
  contains the gateway and nothing outside the Compose stack.
- `AC-007.11`: The Compose stack SHALL declare the network's subnet explicitly rather than
  relying on the address pool Docker happens to allocate.

## Constraints

- The gateway adds one hop on a local machine. It is not on any latency budget this project
  has, and no measurement is required.
- The proxy image is pinned to a specific tag, as every other image in the stack is.
- Every criterion here is about a configuration artifact rather than about running Go code,
  so each is verified by a named command under the artifact-criterion exception in
  `CLAUDE.md` rather than by a unit test.

## Open questions

None.

## Change log

Amendments after approval, newest first.

- `2026-09-20`: Initial version.
