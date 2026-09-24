---
status: accepted
date: 2026-09-17
---

# 8. Proxy trust and request identity

## Context and Problem Statement

This service expects to run behind a TLS-terminating proxy rather than facing the internet
directly, per the topology settled for this project. A proxy in front of the service means
the TCP peer address the server sees is the proxy's, not the client's, and the proxy is the
only party positioned to say what the real client address was. That fact arrives as a header,
conventionally `X-Forwarded-For`, and headers are just bytes a client can also send.

Believing a forwarded header from an untrusted peer lets any client forge its own source
address in logs and metrics, and forge a correlation ID that ties its requests to someone
else's, or that carries a value never meant to reach a log line. Neither failure is
hypothetical: both are the direct consequence of treating a header as fact without asking who
sent it. The decision is not whether to read `X-Forwarded-For` and `X-Request-Id` at all,
since a deployment behind a proxy needs both, but under what condition their contents are
trusted, and what happens when that condition is not met.

## Decision Drivers

- **The default deployment has no proxy configured yet.** Whatever the default behavior is,
  it must be safe for a bare, directly-reachable instance, not just for the eventual
  production topology.
- **Multi-hop correctness.** `X-Forwarded-For` accumulates one entry per hop, and a chain of
  proxies means the header can contain a mix of trusted and client-supplied values in the same
  list.
- **Log injection.** Whatever reaches a log field as a request identifier must be bounded in
  content and length, because a log stream is a place hostile input should not be able to
  reach unfiltered.
- **No new dependency for a value that is only ever compared and logged**, consistent with
  the bounded dependency surface `docs/adr/0006-configuration-loading.md` already argues for.
- **Operator diagnosability.** A user reporting a problem must be traceable to a specific log
  line without requiring a trace collector to be configured, since tracing itself is optional
  per `docs/adr/0004-use-opentelemetry-for-tracing.md`.

## Considered Options

- Trusted-CIDR allowlist: forwarded metadata is believed only from peers inside a configured
  list of trusted networks
- Trust any `X-Forwarded-For` unconditionally
- Trust a fixed single hop count
- No forwarded-header support at all

## Decision Outcome

Chosen: **forwarded request metadata is believed only from peers inside an explicitly
configured trusted-CIDR list, which defaults to empty.**

This is the only option among those considered where the safe state and the default state are
the same thing. An operator who deploys it without configuring anything gets a server
that trusts nothing it did not itself observe, rather than one that is silently forgeable
until someone remembers to lock it down.

### Consequences

- `SERVICE_PROXY_TRUSTED_CIDRS` is a comma-separated CIDR list. Empty means trust nothing, so
  an unconfigured deployment logs the connection's own remote address and ignores every
  forwarded header. The safe case is the unconfigured one.
- `X-Forwarded-For` is read right to left, and the client address is the rightmost entry that
  is not itself a trusted proxy. Reading left to right, or taking the leftmost entry, trusts a
  value the client controls.
- An entry that is not a parseable address ends the walk, and the connection's remote address
  is used. Skipping it would close the gap it left and carry the walk one hop further left,
  into a value the client chose; that is reachable whenever the true client is itself inside a
  trusted CIDR.
- `X-Request-Id` is adopted from a trusted peer when it matches `^[A-Za-z0-9._-]{1,64}$`, and
  is otherwise generated. The pattern bounds what reaches a log field, so a hostile value
  cannot inject newlines or unbounded length into the log stream.
- Identifiers are generated as 16 bytes from `crypto/rand` rendered as 32 lowercase hex
  characters. No new dependency: a UUID library would add one for a value that is never
  parsed, only compared and logged.
- The request identifier is echoed in the `X-Request-Id` response header so an operator can
  move from a user's report to the log line without a trace collector configured.

## Pros and Cons of the Options

### Trusted-CIDR allowlist

- Good: safe by default, since an empty list trusts nothing.
- Good: correct in multi-hop topologies, because trust is evaluated per hop rather than
  assumed for the whole header.
- Good: matches how the proxy actually authenticates itself, by network location, rather than
  by an assumption about chain shape.
- Bad: requires the operator to configure the proxy's network before forwarded headers take
  effect. An unconfigured deployment behind a real proxy logs proxy addresses until this is
  set.
- Bad: CIDR parsing and right-to-left walking is code this project owns and must test, rather
  than a one-line check.

### Trust any `X-Forwarded-For` unconditionally

- Good: works immediately with no configuration, in front of any proxy.
- Bad: forgeable by construction. Any client can set its own `X-Forwarded-For` and have it
  believed, defeating the header's purpose entirely.
- Bad: `X-Request-Id` under the same rule lets a client plant an arbitrary value in every log
  line the request produces.

### Trust a fixed single hop count

- Good: simpler than a CIDR list, since it is just "peel off the last N entries."
- Bad: silently wrong when the topology gains or loses a hop. A second proxy added later, or a
  load balancer removed, changes the hop count without changing any code, and the server keeps
  trusting a position in the list rather than a network it actually verified.
- Bad: does not distinguish a trusted hop from an untrusted one; it only counts them, so a
  client that adds extra entries to the header can still shift which value lands at the
  trusted position.

### No forwarded-header support at all

- Good: simplest possible implementation, with no trust decision to get wrong.
- Bad: every request would be attributed to the ingress address, making per-client diagnosis
  impossible. Behind a proxy, that is every request in the deployment attributed to one
  address.

## More Information

This decision assumes the topology recorded for this service generally: always behind a
TLS-terminating proxy, never internet-facing directly. That assumption is what makes an
explicit trusted-CIDR list practical, since the proxy's network is something the operator
who deploys it already knows and controls.

Revisit this record if a deployment needs to trust forwarded headers from a dynamic or
unpredictable set of peers, since a static CIDR list assumes the trusted network is knowable
in advance.
