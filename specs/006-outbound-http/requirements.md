---
feature: 006-outbound-http
created: 2026-09-20
updated: 2026-09-24
status: implemented
---

# Requirements: Outbound HTTP

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

Nothing in this repository makes an outbound HTTP request, and the first service built on
it will. The obvious way to make one is `http.Get` or `http.DefaultClient`, and both are
wrong in the same three ways. They have no timeout at all, so a request to a peer that
accepts a connection and then stops talking hangs until the process is restarted, holding
whatever inbound request triggered it. They share one transport across every caller in the
process, so a limit raised for one dependency is raised for all of them and a connection
pool exhausted by one starves the rest. They carry no trace context, so a request that
crosses into another service starts a new trace there and the two halves of one user
action cannot be joined.

Each of those failures is invisible in development, where every dependency is local, fast,
and up. They appear the first time a dependency is slow, which is also the moment the
service most needs to shed load rather than accumulate it.

## Goal

Once this ships, a service built on this template obtains an outbound HTTP client from one
constructor, and that client has a bounded lifetime for every request, a connection pool
sized for one dependency rather than for the process, and trace context propagated to the
peer, without the caller having to know that any of those are decisions.

## Non-goals

This feature does not retry a failed request, back off between attempts, or open a circuit
after repeated failures. Retrying is safe only for an operation the caller knows to be
idempotent, and that is a property of the call site rather than of the client; a retry
policy applied underneath a caller who did not ask for one turns one duplicate payment into
several. A service that needs retries adds them at the call site, where the idempotency is
known.

This feature does not add a service discovery mechanism, a request signing scheme,
authentication to an upstream, or response caching. Each belongs to a specific dependency
rather than to the act of making a request.

This feature does not make an outbound request from this service. There is nothing for it
to call. The package is the thing being added; a caller arrives with the first feature that
needs one.

This feature does not wrap the response body, the request builder, or the error type. The
client handed back is an `*http.Client`, so a caller uses the standard library it already
knows and can pass it to any third-party SDK that accepts one.

## User stories

### Story 1: A request that cannot hang

As a developer calling another service, I want every outbound request bounded in time, so
that a dependency which stops responding cannot hold an inbound request or a goroutine
open indefinitely.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-006.1`: The system SHALL provide an HTTP client whose every request is bounded by a
  total timeout, and that timeout SHALL be positive by default.
- `AC-006.2`: The system SHALL separately bound the time spent establishing a connection,
  completing a TLS handshake, and waiting for response headers, each with a positive
  default shorter than the total timeout.
- `AC-006.3`: WHEN a request exceeds its total timeout, the system SHALL return an error
  that a caller can identify as a timeout rather than as an unspecified failure.
- `AC-006.4`: WHEN the context given to a request is cancelled, the system SHALL abandon
  the request rather than wait for the timeout.
- `AC-006.5`: IF a configured timeout is not positive, THEN the system SHALL refuse to
  build the client and name the setting at fault.

### Story 2: A pool sized for one dependency

As an operator, I want each outbound dependency to have its own connection pool with its
own limits, so that one slow peer cannot exhaust the connections every other peer needs.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-006.6`: The system SHALL give each client its own connection pool, not shared with
  any other client or with the standard library's default transport.
- `AC-006.7`: The system SHALL bound the total number of connections and the number of idle
  connections a client may hold, and SHALL bound how long an idle connection is kept.
- `AC-006.8`: WHEN a client is no longer needed, the system SHALL provide a way to close
  its idle connections.
- `AC-006.9`: IF a configured pool limit is negative, THEN the system SHALL refuse to build
  the client and name the setting at fault.

### Story 3: A trace that crosses the boundary

As a developer debugging a request that spans two services, I want outbound requests to
carry this service's trace context and to be recorded as spans, so that both halves of one
user action appear in one trace.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-006.10`: The system SHALL record a client span for each outbound request through the
  tracer provider, meter provider, and propagator supplied to the constructor, and WHERE
  none is supplied the system SHALL record nothing and inject no trace context.
- `AC-006.11`: The system SHALL NOT read the tracer provider, meter provider, or propagator
  from the OpenTelemetry package-level globals.
- `AC-006.12`: WHEN a request is made with a context carrying an active span, the system
  SHALL inject that context into the outbound request headers using the supplied
  propagator.

### Story 4: Settings an operator can see

As an operator, I want the outbound client's timeouts and pool limits to be ordinary
configuration, so that they appear in the effective configuration the process logs and can
be changed without a rebuild.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-006.13`: The system SHALL express every timeout and pool limit as a field of a
  configuration struct that declares the environment variable it is read from and has a
  documented default, so that composing the struct is all a service does to make the
  settings configurable.
- `AC-006.14`: The system SHALL render every duration and size in that configuration in the
  same notation an operator writes it in.
- `AC-006.15`: The system SHALL route an outbound request through the proxy the standard
  library's proxy environment variables name, on the same terms the standard library's
  default transport does.

## Constraints

- The default total timeout is 30s, matching the application listener's `WRITE_TIMEOUT`, so
  an outbound call cannot outlive the inbound request that triggered it by default.
- The default connection, TLS handshake, and response header timeouts are 5s each, chosen
  to be shorter than the total so that a failure to reach a peer is distinguishable from a
  peer that is slow to answer.
- Default pool limits are 100 connections per host, 100 idle connections in total, 10 idle
  connections per host, and a 90s idle connection timeout. The total idle count and the
  idle timeout are Go's own `DefaultTransport` values. The other two are not: the standard
  library leaves connections per host unbounded, so one slow peer can open as many as the
  service has goroutines, and holds only 2 idle per host, so a busy caller reconnects
  constantly.
- The client adds no dependency beyond `net/http` and the `otelhttp` instrumentation
  already in `go.mod`.

## Open questions

None.

## Change log

Amendments after approval, newest first.

- `2026-09-21`: `AC-006.15` added. Building the transport field by field rather than
  cloning `http.DefaultTransport` left `Proxy` nil, and a nil `Proxy` is not "no proxy
  configured" but "ignore the one the operator configured": every request went direct,
  which behind an egress gateway fails and behind a corporate proxy leaks past it. The
  original criteria said nothing either way, so the omission was a side effect of a
  decision about pool values rather than a decision about proxies. Taking the standard
  library's rule back is what a caller who was handed an `*http.Client` already expects.
- `2026-09-20`: `AC-006.13` restated. It required the settings to be "read from the
  environment", which nothing in this repository can satisfy: no service here calls
  anything, so nothing composes the struct and no variable exists to read. Implementing it
  literally would have meant adding a configuration block for a client that is never built,
  which tells an operator to set variables that change nothing. The criterion now asks for
  what the package can actually provide and be tested on: a field per setting, each
  declaring its variable and carrying a documented default, so the first service that needs
  an outbound client composes the struct and gets the variables with it. The variables
  themselves are documented when a service names them, since the prefix is the composing
  struct's to choose.
- `2026-09-20`: Initial version.
