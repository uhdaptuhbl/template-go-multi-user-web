---
feature: 002-server-hardening
created: 2026-09-17
updated: 2026-09-24
---

# Design: Server hardening

How the approved requirements will be met. Free to change as implementation proceeds;
changing this file does not require amending `requirements.md`.

## Overview

`internal/server` today builds a mux with two middleware layers (tracing, then request
logging) and a `RunAll`/`Serve` pair that shuts a server down on context cancellation with no
readiness signal and no pre-drain window. This feature adds the layers a service standing
behind a load balancer needs before it can be trusted with real traffic: a bounded request
body and header size, a cap on requests being handled concurrently, a per-request handler
timeout, panic recovery that still produces a served-request log line, a request identity
that survives a hop through an untrusted proxy, a readiness endpoint that a load balancer can
use to stop sending new traffic before the process actually stops accepting it, and a
shutdown sequence with an explicit pre-drain delay. None of it depends on the frontend stack
decision in `docs/adr/0002-frontend-stack.md`, and none of it touches `internal/web`.

## Alternatives considered

| Option | Trade-off | Verdict |
| --- | --- | --- |
| `http.TimeoutHandler` for the handler timeout | Buffers the entire response in a `bytes.Buffer` before writing anything, so a streaming handler (SSE, chunked JSON, a long download) cannot flush incrementally and a large response doubles memory use for the duration of the request. A context deadline set on the request context lets a handler that checks `ctx.Err()` or selects on `ctx.Done()` stop early and still write what it has. | Rejected |
| A UUID dependency (e.g. `google/uuid`) for request identifiers | The identifier is generated once, compared for the trusted-header pattern, and written to a header and a log field; it is never parsed back into its structured form, so a UUID library buys type safety nothing here needs. `docs/adr/0006-configuration-loading.md` already argues against dependencies that only save a few lines. 32 lowercase hex characters from `crypto/rand` is one `io.ReadFull` call and one `hex.EncodeToString`. | Rejected |
| `golang.org/x/net/netutil.LimitListener` for the in-flight cap | Caps concurrent TCP connections, not concurrent requests. With `IdleTimeout` keeping keep-alive connections open between requests, a connection can sit idle while holding a slot, so the configured number stops meaning "at most N requests being handled" and starts meaning something that depends on client keep-alive behavior. A middleware-level semaphore counts requests directly, which is what `SERVICE_SERVER_MAX_IN_FLIGHT` is meant to bound. | Rejected |
| Long-lived immutable caching (`Cache-Control: max-age=31536000, immutable`) for assets served from `internal/web` | Safe only when the asset URL changes whenever its content does, which requires content-hashed filenames from the frontend build. `docs/adr/0002-frontend-stack.md` is still open, so there is no build pipeline to hash anything yet; shipping a long cache lifetime now would mean a client stuck on a stale, possibly broken, asset with no way to invalidate it until the cache expires. | Rejected |
| Do nothing (ship without any of these layers) | Leaves the server willing to buffer an unbounded request body, run a handler forever, accept unlimited concurrent requests, and stop with no warning to a load balancer. Acceptable for local development, not for anything reachable in production. | Rejected |

`docs/adr/0008-proxy-trust-and-request-identity.md` already records the trust-boundary
decision (trusted-CIDR allowlist for forwarded headers and request IDs) as an accepted ADR;
this design implements that decision rather than re-deciding it.

## Architecture

The application mux gains five new middleware layers around the existing tracing and
request-logging pair. Order matters here more than anywhere else in this feature, because
each layer's placement determines what it can see and what it can protect. `NewMux`, from
outermost to innermost:

```
otelhttp tracing
  -> security headers
    -> request ID
      -> request logging (status recorder)
        -> panic recovery
          -> in-flight limiter
            -> handler timeout
              -> request body limit
                -> ServeMux
```

Reasons for each placement:

- **otelhttp tracing is outermost** so every layer below it, including the ones that can
  reject a request outright, runs inside a span. A request rejected by the in-flight limiter
  still gets a trace, which is what makes 503s from load shedding visible in the same place as
  everything else.
- **Security headers sit directly inside tracing and outside everything that writes a
  response**, so the 413 from the body limit and the 503 from the in-flight limiter carry
  the same headers as a normal response, and so does anything a caller-supplied middleware
  answers on its own.
- **Request ID is next**, inside tracing but outside logging, because the request-served log
  line needs the ID to already be in the request context by the time it is written, and
  because the span itself benefits from carrying the ID as an attribute for cross-referencing
  a trace to a log line without a collector query.
- **Request logging sits directly inside request ID and directly outside panic recovery.**
  This is the placement the middleware order in this section exists to state precisely: a
  panic recovered by the layer just inside logging still passes back through the logging
  layer's deferred completion, so the log line it produces (a) is still emitted at all instead
  of being lost with the crashed goroutine, (b) records `status: 500` via the same
  `statusRecorder` that records every other response, and (c) carries `request_id` because
  request ID has already run by the time logging's deferred code executes. Putting recovery
  outside logging would mean a panic never reaches a log line; putting request ID inside
  logging would mean a panic log carries no correlation ID.
- **Panic recovery sits directly outside the in-flight limiter** so that a handler panicking
  cannot leak its reservation. The recovery layer's deferred release must run before the
  limiter's own release logic decides the slot is free, which a `defer` stack unwinding
  outside-in naturally guarantees when recovery wraps the limiter.
- **The in-flight limiter is outside the handler timeout** so that a request already queued or
  rejected for lack of capacity never starts a timeout clock at all; the timeout is a property
  of requests that were actually admitted to run.
- **The handler timeout is outside the request body limit** so that a slow-body upload is
  still bounded by the same deadline as the rest of the request's handling, rather than by an
  independent clock that could let a deliberately slow body drip past the timeout meant to
  bound the whole request.
- **The request body limit is innermost**, directly wrapping the `ServeMux`, because it acts
  on `r.Body` via `http.MaxBytesReader` and needs to be the last thing to touch the request
  before a handler reads from it; wrapping it further out would still work, but placing it
  last keeps the responsibility "cap what handlers can read" next to the handlers themselves.

The administrative mux (`NewAdminMux`) is unaffected by this ordering: it already carries
neither tracing nor request logging, by design, and this feature does not change that. It
does gain its own body-size, in-flight, and timeout limits via the `SERVICE_ADMIN_` prefixed
configuration, applied through the same middleware constructors, since `/debug/pprof/profile`
and a metrics scrape are just as capable of being slow or numerous as an application request.

`server.Readiness` is a new small piece of shared state, not a middleware: it is read by the
`GET /readyz` handler registered on the application mux, and written once by `RunAll` when
shutdown begins. It has no dependency on the mux construction order above; it is a value both
sides hold a reference to, similar to how `logger` is already threaded through.

`server.TrustedProxies` is consulted by the request-ID and request-logging middleware, not by
a separate layer, because both need the same answer to "was this connection's peer a trusted
proxy" to decide whether to believe `X-Forwarded-For` and `X-Request-Id` respectively. It is
computed once from `SERVICE_PROXY_TRUSTED_CIDRS` at startup and passed into `NewMux` alongside
`Config`, the same way `logger` and `ui` already are.

Ownership: everything above lives in `internal/server`, the package that already owns
`NewMux`, `NewAdminMux`, `Config`, and the `Serve`/`RunAll` lifecycle. `internal/config`
gains the new `SERVICE_*` fields on `server.Config` and the new `server.LifecycleConfig` and
`server.ProxyConfig` types, composed into the top-level `config.Config` the same way `Server`
and `Admin` already are. `internal/web` and `internal/telemetry` are read but not changed:
the frontend handler is still passed into `NewMux` as `ui http.Handler`, and telemetry's
existing `build_info` gauge (see Observability) is read, not added by this feature.

## Interfaces

New and changed exported surface in `internal/server`:

```go
// Readiness reports whether the process should still receive new traffic.
type Readiness struct{ /* unexported */ }

// NewReadiness returns a Readiness that reports ready until SetDraining is called.
func NewReadiness() *Readiness

// SetDraining marks the process as no longer accepting new traffic.
func (r *Readiness) SetDraining()

// Draining reports whether SetDraining has been called.
func (r *Readiness) Draining() bool

// LifecycleConfig controls the shutdown sequence RunAll drives.
type LifecycleConfig struct {
	PreDrainDelay time.Duration `env:"LIFECYCLE_PRE_DRAIN_DELAY, overwrite" json:"pre_drain_delay" validate:"gte=0"`
}

// ProxyConfig names the networks a forwarded header may be trusted from.
type ProxyConfig struct {
	TrustedCIDRs []string `env:"TRUSTED_CIDRS, overwrite" json:"trusted_cidrs"`
}

// TrustedProxies is a parsed, queryable form of ProxyConfig's CIDR list.
type TrustedProxies struct{ /* unexported */ }

// NewTrustedProxies parses cfg's CIDR list into a TrustedProxies.
func NewTrustedProxies(cfg ProxyConfig) (TrustedProxies, error)

// TrustsPeer reports whether r's connection remote address falls inside a
// configured trusted network.
func (t TrustedProxies) TrustsPeer(r *http.Request) bool

// ClientIP returns the request's client address: the rightmost untrusted entry
// of a trusted X-Forwarded-For chain, or the connection's own remote address
// when the peer is not trusted, the header is absent, or the walk reaches an
// entry that is not a parseable address.
func (t TrustedProxies) ClientIP(r *http.Request) string

// RequestIDHeader is the header carrying the request identifier, both inbound
// from a trusted proxy and outbound in every response.
const RequestIDHeader = "X-Request-Id"

// RequestIDFromContext returns the request ID stored in ctx by the request ID
// middleware, or the empty string outside a request handled by NewMux.
func RequestIDFromContext(ctx context.Context) string

// NewMux returns the root HTTP handler, wrapped in the full middleware chain
// this feature adds around the existing tracing and request-logging layers.
// Later features extend this signature further; see specs/005, specs/007, and
// specs/008 for the parameters this feature did not introduce.
func NewMux(cfg Config, proxies TrustedProxies, ready *Readiness, logger *zap.Logger, telemetry Telemetry, ui http.Handler, api func(*http.ServeMux), middleware ...func(http.Handler) http.Handler) http.Handler

// RunAll runs every server concurrently, drains readiness and waits
// cfg.PreDrainDelay before cancelling their shared context on shutdown, and
// returns the first error reported.
func RunAll(ctx context.Context, cfg LifecycleConfig, ready *Readiness, logger *zap.Logger, servers ...*Server) error
```

New HTTP endpoints on the application mux, registered alongside the existing
`GET /healthz`:

- `GET /readyz` returns `200` with body `{"status":"ready"}` while `ready.Draining()` is
  false, and `503` with body `{"status":"draining"}` once it is true. It carries no
  `Retry-After` header: a load balancer polling readiness needs no retry hint, it needs to
  stop routing here, which is a different signal from the load-shedding case below.

Error responses this feature adds, all with `Content-Type: application/json` and the
top-level `errors` array `docs/adr/0010-json-api-response-conventions.md` settles:

- `500 internal` -- written by the panic recovery middleware after logging the panic, body
  `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`. The
  panic's value and stack are logged, never included in the response.
- `413 payload_too_large` -- written when `http.MaxBytesReader` reports the body exceeded
  `SERVICE_SERVER_MAX_REQUEST_BODY_BYTES` (or the `SERVICE_ADMIN_` equivalent on the
  administrative mux), body
  `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`.
- `503 overloaded` -- written by the in-flight limiter when `SERVICE_SERVER_MAX_IN_FLIGHT`
  (nonzero) is already reached, with header `Retry-After: 1` and body
  `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`. See
  Observability for why the
  value is fixed at one second rather than configurable.

## Data

No persisted schema, migration, or storage of any kind is added. `Readiness` and
`TrustedProxies` are in-process values scoped to the lifetime of the running process; neither
is written to disk or a database, and there is nothing to migrate or roll back.

## Failure modes

- **Handler exceeds `SERVICE_SERVER_HANDLER_TIMEOUT`.** The request's context is cancelled;
  a handler that does not observe `ctx.Done()` runs to completion regardless, since this is a
  contract handlers are expected to honor, not one this feature can force. A handler timeout
  is a distinct condition from overload and is not translated into the `503 overloaded`
  load-shedding response: if the handler has not yet written a status by the time the context
  deadline expires, the connection is simply left to the handler's own eventual write, which
  will fail once the client or server has moved on. Left disabled by default (`0s`, meaning no
  timeout) because a global handler timeout can cut off a legitimately slow but correct
  request; an operator opts in once the expected latency envelope for their handlers is known.
- **In-flight limiter is at capacity.** New requests fail fast with `503 overloaded` rather
  than queuing, because an unbounded queue behind a capacity limit is the same unbounded
  memory growth the limiter exists to prevent, just moved one step later. Left disabled by
  default (`0`, meaning unlimited) for the same reason as the handler timeout: it needs a
  capacity number from the deployment before it can be set usefully.
- **Request body exceeds the configured maximum.** `http.MaxBytesReader` returns an error on
  the next read past the limit; the body-limit middleware translates that specific error into
  `413 payload_too_large` and any other read error is left to propagate as the connection
  error it already is, not reinterpreted as a payload problem it may not be.
- **A handler panics.** The recovery middleware recovers exactly once per request, logs the
  panic value and a stack trace at `Error` level with `request_id`, writes `500 internal` if
  no response has been written yet, and lets `withRequestLogging`'s deferred completion record
  the request as served with `status: 500`. A panic during response writing after headers are
  already sent cannot be converted into a clean 500 (net/http has already started the
  response), so the connection is closed the same way `net/http`'s own panic handling would
  close it; only the logging behavior changes, not the wire behavior.
- **A CIDR entry in `SERVICE_PROXY_TRUSTED_CIDRS` fails to parse.** `NewTrustedProxies`
  returns an error, which fails process startup the same way any other configuration
  validation failure does; there is no partial-trust state where some entries are honored and
  a malformed one is silently dropped.
- **An `X-Forwarded-For` entry is not a parseable address.** The walk ends there and the
  connection's remote address is used. Dropping the entry instead would close the gap it left
  and let the walk continue one hop further left, into a value the client was free to choose;
  that is exploitable whenever the true client sits inside a trusted CIDR. `unknown` is a
  value proxies in the Squid lineage emit, so this is not a hypothetical input.
- **`X-Request-Id` from a trusted peer does not match `^[A-Za-z0-9._-]{1,64}$`.** The
  supplied value is discarded and a fresh identifier is generated, exactly as if the header
  had been absent. This is a silent fallback rather than a rejected request, because a
  malformed correlation ID from an otherwise-trusted proxy is a proxy misconfiguration to
  notice in logs, not a reason to fail the user's request.
- **Second SIGTERM/SIGINT during shutdown.** `internal/signals.ForceExitOnSecond` (unchanged
  by this feature) exits with status 1 immediately, abandoning whatever is still in flight;
  see Architecture's shutdown sequence for where this can interrupt the drain.

## Security and privacy

The trust boundary this feature introduces is exactly the one
`docs/adr/0008-proxy-trust-and-request-identity.md` already decided: forwarded request
metadata, meaning `X-Forwarded-For` and `X-Request-Id`, is believed only when the TCP peer
that sent it falls inside a network listed in `SERVICE_PROXY_TRUSTED_CIDRS`, which defaults to
empty. An unconfigured deployment trusts nothing it did not itself observe: `ClientIP` returns
the connection's own remote address and every request gets a freshly generated identifier,
regardless of what headers a client sends. This is the safe default because it is also the
default; there is no separate "safe mode" flag to remember to set.

`TrustsPeer` and `ClientIP` are called once per request, from the request-ID middleware
(for `X-Request-Id`) and from request logging (for `client_ip`), against the same
`TrustedProxies` value built once at startup from validated configuration. No handler or
downstream code is expected to re-derive trust; `RequestIDFromContext` and the `client_ip`
log field are the only sanctioned ways to read either value once the middleware chain has run.

Input validation: a client-or-proxy-supplied `X-Request-Id` is validated against
`^[A-Za-z0-9._-]{1,64}$` before it is adopted, bounding both content and length before the
value reaches a log field, a response header, or a span attribute. `X-Forwarded-For` is
walked right to left and only entries at or before the first untrusted hop are considered,
per the ADR, so a client cannot plant extra entries ahead of a trusted proxy's own value to
make an arbitrary address appear as the trusted result.

No personal data beyond the client IP address (already logged today via the connection's
remote address) is newly handled by this feature. Panic values and stack traces logged by
the recovery middleware are operational data about the process, not about a request's
content, and are never echoed to the client.

## Test strategy

- **Unit** (`go test ./internal/server/...`): each middleware in isolation with
  `httptest.NewRecorder` and a stub inner handler -- panic recovery given a handler that
  panics, the in-flight limiter given a handler that blocks until signalled, the body limit
  given an `io.Reader` larger than the configured maximum, the handler timeout given a
  handler that never returns, request ID given a range of valid, invalid, and absent
  `X-Request-Id` values from both a trusted and an untrusted stub peer address. `Readiness`
  and `TrustedProxies` are unit tested directly: `TrustsPeer` and `ClientIP` against a table
  of CIDR configurations and forwarded-header chains, since this is exactly the kind of
  boundary-condition logic (multi-hop chains, malformed CIDRs, IPv6) that is cheap to get
  wrong and cheap to test at this layer.
- **Integration** (build-tagged, real listener): `RunAll` driven against real `httptest`-style
  listeners on ephemeral ports, asserting the full shutdown sequence -- readiness flips to
  draining before the pre-drain delay elapses, `GET /readyz` observably returns 503 during
  the delay while `GET /healthz` still returns 200, and the server's context is not cancelled
  until the delay has passed. This needs a real HTTP round trip because the property under
  test is the interaction between three real components (context cancellation, the readiness
  handler, and a live listener) rather than any one function's return value.
- **End-to-end**: not added by this feature. There is no user-visible flow through
  `internal/web` that this feature changes; the frontend is unselected per
  `docs/adr/0002-frontend-stack.md`, so there is nothing yet for a Playwright-level test to
  drive.

Test doubles: a fake `net.Conn`/`http.ResponseWriter` pairing supplied by
`httptest.NewRecorder` and `httptest.NewRequest` stands in for the real listener in unit
tests, since the layer under test (a single middleware) does not need a live socket to
exercise its logic; the integration tests above use real listeners specifically because the
process boundary they cross (an actual accept loop under `Shutdown`) is the thing being
verified. A clock is not injected for the pre-drain delay; the integration test instead uses
a small real delay (on the order of tens of milliseconds) and asserts ordering via readiness
state transitions rather than via elapsed wall-clock time, avoiding both a fake-clock
dependency and a flaky sleep-based assertion.

## Observability

- `request_id` -- a stable identifier a support agent or an operator can read out of a user's
  bug report (echoed in the `X-Request-Id` response header) and grep for directly in the log
  stream. It answers "which log lines belong to this one user's request" without a trace
  collector configured, which matters because tracing is optional per
  `docs/adr/0004-use-opentelemetry-for-tracing.md` and most deployments will not have one.
- `client_ip` -- the request's actual client address, resolved through the trust boundary
  above rather than taken from the raw header. It answers "is this one client hammering the
  service, or is this general load," which a raw connection-count metric cannot distinguish
  once a shared proxy is in front of every request.
- The level split introduced by panic recovery and the new error responses (an ordinary
  request stays at `Info`, a recovered panic and a load-shedding rejection are logged at
  `Error` and `Warn` respectively) answers "is anything actually broken right now" with a
  single log-level filter: `grep '"level":"error"'` finds every 5xx-producing panic without
  wading through the request-served line for every successful request.
- `build_info` (already exposed by `internal/telemetry`, read rather than added here, and
  consulted alongside this feature's readiness endpoint in the same operational picture) --
  answers "which build is actually running" when a rollout is in progress and `/readyz` is
  flipping between old and new instances.
- The `Retry-After: 1` header on the `503 overloaded` load-shedding response tells a
  well-behaved client or reverse proxy how long to wait before retrying, so backoff behavior
  is signalled at the protocol level rather than left for every caller to guess. The body is
  `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`, distinct
  from the `readyz`
  draining body, because overload and drain are different operational states: overload means
  "try again very soon," drain means "stop sending traffic here at all."

## Shutdown sequence

The ordered steps the process takes on receiving `SIGTERM` (or `SIGINT`):

1. `signal.NotifyContext` cancels the root context the process was started with.
2. `RunAll` observes the cancellation and immediately calls `ready.SetDraining()`, so `GET
   /readyz` starts answering `503 {"status":"draining"}` on the very next poll. `GET /healthz`
   is unaffected: liveness and readiness are different questions, and the process is still
   alive and still serving.
3. `RunAll` logs that it is entering the pre-drain window and waits
   `SERVICE_LIFECYCLE_PRE_DRAIN_DELAY` (default 5s) before doing anything else. During this
   window the servers keep serving normally; the delay exists to give an external load
   balancer time to notice the failed readiness check and stop routing new connections here
   before the servers actually start shutting down, so that requests already in flight when
   the signal arrived are not joined by new ones arriving after the process has decided to
   drain.
4. Once the delay elapses, `RunAll` cancels the context shared by every `Server.Serve` call.
   Each `Serve` calls `http.Server.Shutdown` under its own `ShutdownTimeout`, exactly as it
   does today: `Shutdown` stops accepting new connections and waits for in-flight requests to
   finish, up to that timeout, after which they are cut off.
5. A second `SIGTERM`/`SIGINT` received at any point from step 1 onward is handled by the
   existing, unchanged `internal/signals.ForceExitOnSecond`: it force-exits the process with
   status 1 immediately, abandoning whatever is still in flight. This is what distinguishes an
   operator waiting for the drain from one who has given up on it.
