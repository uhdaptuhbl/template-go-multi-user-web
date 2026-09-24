---
status: accepted
date: 2026-09-17
---

# 7. Deployment topology

## Context and Problem Statement

Server hardening work has to shape the binary around a real deployment, not a hypothetical
one, because readiness semantics, shutdown behavior, and the boundary of what the binary is
responsible for all depend on what sits in front of it. Two different topologies have been
discussed informally: a single instance behind nginx on a VM, and multiple instances behind
an orchestrator that load balances, restarts failed instances, and removes an instance from
rotation before it disappears.

The choice is expensive to reverse in the direction that matters most. If the binary is built
assuming it always has a reverse proxy in front of it, and someone later exposes it directly,
that is a security incident rather than a configuration change. If the binary is built to
defend itself against direct exposure, TLS termination, HTTP/2, and response compression all
become code the project has to write, patch, and reason about, none of which nginx does not
already do better. This record settles which side of that line the project stands on, so the
answer is enforceable rather than folklore repeated in code review.

Readiness and shutdown are downstream of the same choice. An orchestrated environment removes
an unhealthy or terminating instance from its load balancer asynchronously: the instance is
marked for removal, but in-flight and newly arriving connections can still reach it until
that removal propagates. A static nginx upstream on a single VM has no such propagation delay
because there is nothing to update remotely. Deciding the topology first is what makes the
shutdown sequencing decision below a consequence rather than a second, unrelated choice.

## Decision Drivers

- The binary's scope should stop where infrastructure whose job is exactly that begins.
  Certificate lifecycle, cipher policy, and compression are solved problems at the proxy
  layer.
- Zero-downtime deployment requires that traffic never reaches an instance that is not ready,
  and never reaches one that has stopped accepting connections.
- The failure mode of getting this wrong is not a bug report; it is either a dropped
  connection during every deploy or a binary that is safe to point straight at the internet
  when it is not.
- The distinction between "can serve" and "is alive" only matters if something acts on it
  differently, and an orchestrator is the thing that does: it routes on readiness and
  restarts on liveness.
- A single-maintainer project should not carry code whose only justification is a topology
  nobody runs.

## Considered Options

- Always behind a TLS-terminating reverse proxy, orchestrated shape
- Behind a reverse proxy on a VM only, no pre-drain sequencing
- Terminate TLS in the binary

## Decision Outcome

Chosen: **service is always deployed behind a TLS-terminating reverse proxy, and is shaped
for an orchestrated environment.**

### Consequences

- The binary never terminates TLS, never serves HTTP/2 directly, and never compresses
  responses. nginx owns certificates, the HTTP-to-HTTPS redirect, HSTS, and `gzip`/`brotli`.
- The binary is not safe to expose directly to an untrusted network, and that is a
  deliberate constraint rather than an unfinished feature.
- Readiness is distinct from liveness, because an orchestrator routes on readiness and
  restarts on liveness. `GET /readyz` is added; `GET /healthz` keeps reporting liveness only.
- Shutdown fails readiness first, holds for a configurable pre-drain delay, and only then
  stops accepting connections, because endpoint removal in Kubernetes is asynchronous and a
  pod that stops accepting the instant it receives SIGTERM returns 502s for as long as
  propagation takes. The delay defaults to 5s and is set to 0s on a static nginx upstream,
  where it is unnecessary but harmless.

## Pros and Cons of the Options

### Always behind a TLS-terminating reverse proxy, orchestrated shape

- Good: the binary's scope stays bounded to application concerns; certificate handling,
  HSTS, and compression live where they are already solved.
- Good: the pre-drain delay makes rolling deploys and scale-down events safe under an
  orchestrator's asynchronous endpoint removal, and costs nothing on a simpler topology
  because the delay is just a configuration value.
- Good: `/readyz` and `/healthz` map directly onto the two probe types every orchestrator
  already expects, so no adapter layer is needed.
- Bad: the binary is unsafe to run standalone, which is a constraint every deployment
  document and onboarding note has to repeat.
- Bad: local development and ad hoc testing need a proxy in front to see production-shaped
  behavior, which is one more moving part than running the binary alone.

### Behind a reverse proxy on a VM only, no pre-drain sequencing

- Good: simpler shutdown path, since a static upstream has no asynchronous removal to wait
  out.
- Good: matches the project's current deployment reality most closely today.
- Bad: rejected. The pre-drain delay costs one config field and a timer, and retrofitting it
  means reopening the shutdown path a second time.

### Terminate TLS in the binary

- Good: one process to deploy, with no separate proxy layer to configure or keep patched.
- Good: works without any infrastructure decision made in advance.
- Bad: rejected by the project owner: it puts certificate lifecycle, renewal, and cipher
  policy inside an application that has no reason to own them.

## More Information

`docs/adr/0005-use-opentelemetry-metrics-with-prometheus.md` already places the
administrative listener, which carries liveness and profiling, off the public port. This
record extends that boundary: everything the binary is not built to defend against, TLS
termination included, stays outside the process entirely.

Revisit this record if a deployment target ever needs the binary to run without a proxy in
front of it. That is a different security posture, not an incremental change, and should be
a new decision rather than an edit to this one.
