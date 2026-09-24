---
feature: 002-server-hardening
created: 2026-09-17
updated: 2026-09-24
status: implemented
---

# Requirements: Server hardening

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

The server today has no defenses against the failure modes every production HTTP service
eventually hits: a panicking handler takes down the process instead of one request, an
unbounded request body or header set can exhaust memory, there is no way to correlate a log
line with the request that produced it or the client that sent it, shutdown drops
in-flight connections instead of draining them, embedded frontend assets are served without
cache validation or basic security headers, and there is no way to shed load when the
service is overwhelmed. An operator running this service today has no observable signal for any
of this until it has already caused an outage or a support ticket they cannot trace back to
a request.

## Goal

Once this ships, the server survives a panicking handler, rejects oversized requests, gives
every request a stable correlation ID an operator can use to find its log line, drains
cleanly during shutdown and rollout, serves frontend assets with correct caching and
security headers, sheds load instead of falling over when overwhelmed, and reports its own
version and configuration on startup so a deployed instance can be identified without
guessing.

## Non-goals

This feature does not implement TLS termination, HTTP-to-HTTPS redirection, HSTS, or
response compression. Those belong to the reverse proxy per
`docs/adr/0007-deployment-topology.md`, which settles that the service is always deployed behind
a TLS-terminating proxy and is not shaped to defend itself against direct exposure.

This feature does not implement authentication or authorization.

This feature does not ship Kubernetes manifests. Deployment guidance is documented in the
README rather than shipped as manifests in this repository.

## User stories

### Story 1: Failure containment

As an operator, I want a panicking handler to fail one request instead of the process, so
that a bug in one code path does not take down every in-flight request the server is
handling.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.1`: IF a handler panics, THEN the system SHALL log the panic value and its stack
  at error level, mark the active span as errored, and respond 500 with
  `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}` when no response has
  yet been written.
- `AC-002.2`: IF a handler panics with `http.ErrAbortHandler`, THEN the system SHALL abandon
  the response without logging a stack.
- `AC-002.3`: The system SHALL route the HTTP server's own error output to the zap logger at
  error level rather than to standard error.
- `AC-002.4`: IF a request body exceeds the configured limit, THEN the system SHALL respond
  413 with
  `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`.
- `AC-002.5`: The system SHALL reject a request whose request line and headers exceed the
  configured maximum.

### Story 2: Correlation

As an operator, I want every request to carry a stable, trustworthy identifier and an
accurately attributed client address, so that I can trace a user's report to the exact log
line it produced without believing a header a client could have forged.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.6`: WHEN a request arrives without an `X-Request-Id` header, the system SHALL
  generate an identifier of exactly 32 lowercase hexadecimal characters for it.
- `AC-002.7`: WHEN a request arrives from a trusted peer carrying an `X-Request-Id` matching
  `^[A-Za-z0-9._-]{1,64}$`, the system SHALL adopt that value as the request identifier.
- `AC-002.8`: IF a request carrying `X-Request-Id` arrives from a peer that is not trusted,
  THEN the system SHALL ignore the supplied value and generate one.
- `AC-002.9`: The system SHALL return the request identifier in the `X-Request-Id` response
  header and include it as `request_id` in that request's log entry.
- `AC-002.10`: WHEN a request arrives from a trusted peer carrying `X-Forwarded-For`, the
  system SHALL log `client_ip` as the rightmost address in that header that is not itself a
  trusted peer, stopping the search at the first entry that is not a parseable address and
  logging the connection's remote address when the search stops or finds nothing.
- `AC-002.11`: IF the peer is not trusted, THEN the system SHALL log `client_ip` as the
  connection's remote address and ignore `X-Forwarded-For`.
- `AC-002.12`: The system SHALL log a request that responded 5xx at error level, 4xx at warn
  level, and any other status at info level.

### Story 3: Rollout and shutdown

As an operator running this service under an orchestrator, I want the service to fail readiness
before it stops accepting connections and to keep reporting liveness while draining, so that
a rolling deploy or scale-down event does not drop in-flight or newly arriving requests.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.13`: WHEN `GET /readyz` is requested on either listener while the process is
  serving, the system SHALL respond 200 with `{"status":"ready"}`.
- `AC-002.14`: WHEN shutdown begins, the system SHALL respond 503 with
  `{"status":"draining"}` to `GET /readyz` before it stops accepting new connections.
- `AC-002.15`: WHEN shutdown begins, the system SHALL continue serving for the configured
  pre-drain delay after readiness starts failing and before listeners stop accepting
  connections.
- `AC-002.16`: WHILE the process is draining, `GET /healthz` SHALL continue to respond 200
  with `{"status":"ok"}`.
- `AC-002.17`: The administrative listener SHALL bind `127.0.0.1:9090` when nothing
  overrides it.

### Story 4: Frontend delivery

As an operator, I want embedded frontend assets served with correct cache validation and
baseline security headers, so that browsers revalidate stale assets instead of serving them
forever, and so that the frontend is not needlessly exposed to sniffing, referrer leakage, or
unrestricted script sources.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.18`: WHEN an embedded frontend asset is served, the system SHALL set an `ETag`
  derived from that asset's content, and SHALL respond 304 to a subsequent request whose
  `If-None-Match` matches it.
- `AC-002.19`: WHEN an embedded frontend asset is served, the system SHALL set
  `Cache-Control: no-cache`, so that a cache revalidates against the `ETag` rather than
  serving a stale asset.
- `AC-002.20`: WHEN a response is served by the frontend handler, the system SHALL set
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a
  `Content-Security-Policy` header.

### Story 5: Load shedding

As an operator, I want the server to shed excess load and bound how long a single request
can occupy a handler, so that an overload condition degrades as explicit, retryable errors
instead of unbounded queuing or a stuck handler holding resources indefinitely.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.21`: WHERE a maximum in-flight request count is configured, IF it is exceeded,
  THEN the system SHALL respond 503 with `Retry-After: 1` and
  `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`.
- `AC-002.22`: WHERE a handler timeout is configured, the system SHALL cancel a request's
  context once the timeout elapses.

### Story 6: Build operability

As an operator, I want a running instance to report its own version, build, and
configuration on startup, expose that identity as a metric, and answer for it on demand, so
that I can identify what is actually deployed without guessing, shelling into the host, or
hunting for a log line that has since rotated away.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-002.23`: WHEN the process starts, the system SHALL log one entry naming its version,
  its git commit, and its Go version.
- `AC-002.24`: WHEN the process starts, the system SHALL log its effective configuration
  with secret-typed values redacted.
- `AC-002.25`: The system SHALL expose a `build_info` metric with value 1 carrying
  `version`, `commit`, `build_date`, and `go_version` labels.
- `AC-002.26`: WHEN `GET /version` is requested on the administrative listener, the system
  SHALL respond 200 with a JSON body carrying its version, git commit, build date, Go
  version, and the time the process started.
- `AC-002.27`: The system SHALL NOT serve the version endpoint on the application listener.
- `AC-002.28`: The system SHALL apply a read-header timeout, a read timeout, a write
  timeout, and an idle timeout to every listener, each with a non-zero default.
- `AC-002.29`: The administrative listener SHALL NOT serve the frontend or any application
  route.

## Constraints

- The pre-drain delay defaults to 5s.
- The request body limit and the request header limit each default to 1 MiB.
- The in-flight request cap and the handler timeout both default to disabled, because a
  wrong ceiling rejects legitimate traffic and the right one is not knowable before the
  service has a workload.

## Open questions

None.

## Change log

Amendments after approval, newest first.

- `2026-09-24`: No criterion changed. The `ProxyConfig` snippet in `design.md` showed the
  struct tag as `PROXY_TRUSTED_CIDRS`. The tag is `TRUSTED_CIDRS`, and the variable is
  `SERVICE_PROXY_TRUSTED_CIDRS` only because the group is loaded under the
  `SERVICE_PROXY_` prefix. The snippet now matches the code.
- `2026-09-20`: `AC-002.28` and `AC-002.29` added by the same uncited-test triage that
  produced the spec 001 additions. The four `http.Server` timeouts are the main thing
  standing between this process and a client that opens a connection and never finishes a
  request, and nothing required them to exist or to have defaults. `AC-002.27` stated the
  negative for `/version` alone where the rule is general.
- `2026-09-20`: `AC-002.1`, `AC-002.4`, and `AC-002.21` restated for the error document
  `docs/adr/0010-json-api-response-conventions.md` settles: a top-level `errors` array
  borrowing JSON:API's member names, in place of the singular `{"error": {...}}` object
  those criteria specified. The singular shape held one failure, which forces a second shape
  the first time an endpoint validates two fields, and its member names were this project's
  own invention where borrowed ones cost nothing. The codes and statuses are unchanged; the
  `message` member becomes `detail`, and a `title` naming the kind of failure joins it.
- `2026-09-19`: Story 6 extended with `AC-002.26` and `AC-002.27`, and `AC-002.25` amended to
  add the `build_date` and `go_version` labels. As shipped, the build date reached no running
  process at all: it was named only in the start-up log entry, so once that line rotated away
  there was no way to ask a live instance when its binary was built. The metric carried
  version and commit but neither of the other two. `AC-002.27` is stated explicitly because
  build identity is a disclosure: naming the exact release tells an attacker which
  vulnerabilities to try, so the endpoint belongs with pprof behind the loopback-bound
  administrative listener rather than on the public port.
- `2026-09-19`: `AC-002.10` amended to state what happens at an entry that is not a parseable
  address. As first written it named only "the rightmost address that is not itself a trusted
  peer", which left an unparseable hop with no defined handling; the implementation skipped
  it, closing the gap it left and letting the walk continue into entries the client supplied.
  Where the real client is itself inside a trusted CIDR, that returned a spoofable value. The
  criterion now requires an unparseable entry to end the search, which is the conservative
  reading and the one the implementation follows.
- `2026-09-17`: Implementation complete; every criterion is cited by a passing test.
- `2026-09-17`: Initial approved version.
