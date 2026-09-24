---
feature: 007-local-gateway
created: 2026-09-20
updated: 2026-09-24
---

# Design: Local gateway

## Overview

One new service in `deploy/local/compose.yaml`, `gateway`, running nginx with a
configuration file checked in at `deploy/local/nginx.conf`. It is the only service whose
application port is published to the host. The `app` service loses its published `8080`
and keeps its published admin port, and gains
`SERVICE_PROXY_TRUSTED_CIDRS` naming the gateway's own fixed address as a `/32`, not the
Compose network's subnet; see Security for why trusting the whole subnet would be wrong.

The Compose file declares that network with an explicit subnet, because the gateway's
fixed address has to fall inside it and a value that matches whatever Docker's address
pool happened to allocate today is a value that stops matching on another machine. It also
sets `ip_range` to the upper half of the subnet, so Docker assigns every other container an
address there. Without it, whichever container started first could already hold the
gateway's fixed address, and the gateway then failed to start with "Address already in use".

No Go code changes. The service already reads both forwarded headers and already gates
them on the trusted-CIDR list; this feature is the configuration that exercises that path.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Leave the stack as it is and document the contract | The contract is then checked by reading. Every failure mode here is a header set slightly wrong, which reading does not catch. |
| Terminate TLS locally with a self-signed certificate | Buys nothing the plain-HTTP path does not already exercise, and costs a certificate to generate, trust, and rotate, plus a browser warning per developer. The forwarded-header contract is identical either way. |
| Use Caddy or Traefik instead of nginx | ADR 0007 names nginx. A local stack that exercises a different proxy's defaults is exercising the wrong thing, and the file would not be a starting point for the real configuration. |
| Keep the application port published alongside the gateway | Then the topology the ADR forbids is still one URL away, and the one a developer bookmarks first. The direct path is available by editing one line when it is genuinely wanted. |
| `X-Forwarded-For $proxy_add_x_forwarded_for` | Appends the peer to whatever the client already sent. See Security below: it is exactly the hole the trusted-CIDR list exists to close. |
| Route the admin listener through the gateway on a separate path | pprof and metrics on the same public port is what the operational-endpoint rule in `CLAUDE.md` exists to prevent. |

## Architecture

```
host :8080 -> gateway (nginx) -> app:8080   application listener
host :9090 ----------------------> app:9090   administrative listener, loopback only
                                   app:9090 <- prometheus, over the compose network
```

The gateway serves one `location /` and proxies everything to `http://app:8080`. There is
no routing decision to make: the service owns its own routes and the gateway exists to set
headers, not to dispatch.

`app` is reachable by service name on the Compose network, which is how Prometheus already
scrapes it. Removing the published `8080` changes nothing for Prometheus or Jaeger.

## Interfaces

The interface is four request headers, which is the whole of what the gateway contributes:

| Header | Value | Why |
| --- | --- | --- |
| `X-Forwarded-For` | `$remote_addr` | The peer that connected to nginx. Replaced, not appended. |
| `X-Request-Id` | `$request_id` | nginx's per-request identifier: 32 hexadecimal characters, which is exactly what the service's own generator produces and what `validRequestID` accepts. |
| `X-Forwarded-Proto` | `$scheme` | `http` locally. Not hard-coded to `https`, which would be a claim the service could act on and which is false here. |
| `Host` | `$host` | The name the client asked for, so a redirect or an absolute URL the service builds names the address the client can reach. |

## Data

No persistent data. The nginx configuration is the only new artifact, and the gateway's
fixed address is the only new value that two files have to agree on: the `networks` block
assigns it via `ipv4_address` and `SERVICE_PROXY_TRUSTED_CIDRS` restates it as a `/32`.
They are adjacent in one file, and a mismatch fails visibly, because the service then
attributes every request to the gateway.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| The trusted-CIDR value does not contain the gateway | The service ignores both forwarded headers, attributes every request to the gateway's address, and generates its own request ID. Visible in the first log line. |
| `app` is not up when the gateway starts | nginx resolves `app` at request time for a proxy_pass with a variable, and at start-up otherwise. The configuration uses the literal form, so `depends_on` is what orders them; a request before the app is listening returns 502 from nginx. |
| A client sends its own `X-Forwarded-For` or `X-Request-Id` | Both are discarded at the gateway. The service never sees them. |
| The gateway is bypassed by publishing the app port again | The service's peer is then the Docker bridge gateway, which is inside the trusted CIDR, so a directly-connecting client would be believed. This is why the port is unpublished rather than merely unused. |

## Security and privacy

The forwarding rule is the one decision here with a wrong answer that looks right.
`$proxy_add_x_forwarded_for` is the form most nginx examples use: it appends the connecting
peer to whatever the client already sent. Behind a trusted edge that is correct, because
each hop's contribution is verifiable back to the edge. nginx *is* the edge here, so
anything already in the header came from the client and is unverifiable.

That matters because of how the service reads the header. `TrustedProxies.ClientIP` walks
`X-Forwarded-For` right to left and returns the first address that is not itself a trusted
proxy. With the appending form, a client sending `X-Forwarded-For: 1.2.3.4` produces
`1.2.3.4, <peer>`; on this stack the peer is the Docker bridge address, which is inside the
trusted CIDR, so the walk continues left and attributes the request to `1.2.3.4`. Replacing
the header rather than appending closes that, and it is the correct rule for an edge
regardless.

The same reasoning applies to `X-Request-Id`. The service adopts a supplied identifier from
a trusted peer, and the gateway is trusted, so forwarding the client's value would hand a
client the ability to choose its own correlation ID and to collide with someone else's
deliberately. The gateway generates one instead.

The administrative listener is not routed through the gateway and stays published to
loopback only. Nothing about this feature widens it.

## Test strategy

Every criterion is about a configuration artifact rather than about running Go code, so
each is verified by a command under the artifact-criterion exception in `CLAUDE.md`. The
commands are in `tasks.md`.

Two of them bring the stack up and make a real request through it, which is the only way to
observe `AC-007.8` and `AC-007.9`: the headers are set by nginx and read by the service, so
neither half on its own demonstrates the contract holds.

## Observability

Unchanged. The service's own request log already carries `client_ip` and `request_id`, and
the point of this feature is that both now come from the gateway rather than from the
service's fallbacks. nginx's own access log goes to stdout, where `docker compose logs`
already collects it.
