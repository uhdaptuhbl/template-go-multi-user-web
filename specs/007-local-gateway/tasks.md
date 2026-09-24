---
feature: 007-local-gateway
created: 2026-09-20
updated: 2026-09-24
---

# Tasks: Local gateway

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances.

Every criterion here is about a configuration artifact rather than about running Go code,
so each task names the command that verifies it under the artifact-criterion exception in
`CLAUDE.md`, and that command is the citation.

Several commands below assume the stack is up:

```sh
docker compose -f deploy/local/compose.yaml up -d --build
```

and that it is taken down afterwards with `down -v`.

## Checklist

- [x] **T1** Add `deploy/local/nginx.conf` setting the four forwarded headers, replacing
  rather than appending `X-Forwarded-For` and generating `X-Request-Id`
  - Satisfies: `AC-007.2`, `AC-007.5`, `AC-007.6`, `AC-007.7`
  - Verify: `docker compose -f deploy/local/compose.yaml exec -T gateway nginx -T | grep -E 'listen|proxy_set_header'`
    reports `listen 8080`, `$remote_addr`, `$request_id`, `$scheme`, `$host`, and no `ssl`
- [x] **T2** Add the `gateway` service, declare the `service` network with an explicit
  subnet, give the gateway a fixed address, and unpublish the application port
  - Satisfies: `AC-007.1`, `AC-007.4`, `AC-007.11`
  - Verify: `docker compose -f deploy/local/compose.yaml config -q`;
    `docker compose -f deploy/local/compose.yaml ps --format '{{.Service}} {{.Ports}}'`
    shows `app` with no published 8080 and `gateway` with `127.0.0.1:8080->8080/tcp`
- [x] **T3** Set `SERVICE_PROXY_TRUSTED_CIDRS` to the gateway's address alone
  - Satisfies: `AC-007.10`
  - Verify: `grep -n 'TRUSTED_CIDRS' deploy/local/compose.yaml` names the same address as
    the gateway's `ipv4_address`
- [x] **T4** Confirm the contract end to end against the running stack
  - Satisfies: `AC-007.5`, `AC-007.6`, `AC-007.8`, `AC-007.9`
  - Verify: `curl -si -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Request-Id: CLIENTSPOOF' http://localhost:8080/healthz`
    returns a 32-hexadecimal-character `X-Request-Id` that is not `CLIENTSPOOF`, and the
    matching entry in `docker compose -f deploy/local/compose.yaml logs app` has
    `client_ip` equal to the bridge address that connected to the gateway, not `1.2.3.4`
    and not the gateway's own address
- [x] **T5** Confirm the administrative listener is not reachable through the gateway
  - Satisfies: `AC-007.3`
  - Verify: `curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/metrics` is 404
    while the same path on `http://localhost:9090` is 200
- [x] **T6** Document the topology in `README.md`
  - Satisfies: `AC-007.1`
  - Verify: `grep -n 'gateway' README.md`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Verification |
| --- | --- | --- |
| `AC-007.1` | T2, T6 | `docker compose ps` shows no published application port |
| `AC-007.2` | T1 | `nginx -T` shows `listen 8080` and no `ssl` directive |
| `AC-007.3` | T5 | `/metrics` is 404 through the gateway, 200 on the admin listener |
| `AC-007.4` | T2 | `docker compose config -q` |
| `AC-007.5` | T1, T4 | logged `client_ip` is the connecting peer, not the supplied `1.2.3.4` |
| `AC-007.6` | T1, T4 | response `X-Request-Id` is generated, not the supplied `CLIENTSPOOF` |
| `AC-007.7` | T1 | `nginx -T` shows `$scheme` and `$host` |
| `AC-007.8` | T4 | response carries `X-Request-Id` |
| `AC-007.9` | T4 | logged `client_ip` is the bridge address, not the gateway's |
| `AC-007.10` | T3 | `TRUSTED_CIDRS` matches the gateway's fixed address |
| `AC-007.11` | T2 | the `networks` block declares a subnet |

## Deferred

- The stack's Jaeger instance was never reachable before this change:
  `jaegertracing/jaeger:2` does not resolve, because that repository publishes no floating
  major tag. Fixed here rather than deferred, since the stack cannot be brought up at all
  otherwise, and noted in `specs/005-service-scaffolding/requirements.md`'s change log,
  where the criterion that was supposed to catch it lives.
- No assertion is made that a span reached Jaeger. `/healthz` is excluded from tracing by
  design, so the requests these tasks make produce none, and adding a traced request to
  the verification would be testing `internal/telemetry` from a Compose file.
