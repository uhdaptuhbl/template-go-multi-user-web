---
feature: 006-outbound-http
created: 2026-09-20
updated: 2026-09-24
---

# Tasks: Outbound HTTP

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Add `internal/httpclient/doc.go`, `Config`, `Default`, and validation in
  `internal/httpclient/config.go`, with `configtype.Duration` for every duration and env
  tags mirroring `server.Config`
  - Satisfies: `AC-006.13`, `AC-006.14`
  - Verify: `go test ./internal/httpclient/ -run 'TestDefault|TestConfigRenders' -race`
- [x] **T2** Add `New` in `internal/httpclient/client.go`, building the private transport
  and applying the total timeout, and rejecting a non-positive timeout or negative limit
  - Satisfies: `AC-006.1`, `AC-006.2`, `AC-006.5`, `AC-006.6`, `AC-006.7`, `AC-006.9`
  - Verify: `go test ./internal/httpclient/ -run 'TestNew' -race`
- [x] **T3** Cover request-lifetime behaviour against an `httptest.Server`: a total timeout
  that fires and reports as a timeout, and a cancelled context that is abandoned at once
  - Satisfies: `AC-006.3`, `AC-006.4`
  - Verify: `go test ./internal/httpclient/ -run 'TestClientTimeout|TestClientAbandons' -race`
- [x] **T4** Cover idle connection closing
  - Satisfies: `AC-006.8`
  - Verify: `go test ./internal/httpclient/ -run 'TestCloseIdleConnections' -race`
- [x] **T5** Wrap the transport in `otelhttp.NewTransport` with the supplied providers, and
  assert the recorded span and the injected `traceparent` against an SDK recorder
  - Satisfies: `AC-006.10`, `AC-006.11`, `AC-006.12`
  - Verify: `go test ./internal/httpclient/ -run 'TestClientRecords|TestClientPropagates|TestClientIgnores' -race`
- [x] **T6** Document in `README.md` that outbound settings arrive with the struct a
  service composes, naming the variable suffixes, and assert the tags exist
  - Satisfies: `AC-006.13`
  - Verify: `go test ./internal/httpclient/ -run TestEverySettingDeclaresItsVariable -race`

- [x] **T7** Restore the standard library's proxy rule on the constructed transport
  - Satisfies: `AC-006.15`
  - Verify: `go test ./internal/httpclient/ -run TestNewTransportHonoursTheProxyEnvironment -race`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-006.1` | T2 | `TestDefaultBoundsEveryPhase`, `TestNewAppliesTheTotalTimeout` |
| `AC-006.2` | T2 | `TestDefaultBoundsEveryPhase`, `TestNewAppliesEveryPhaseTimeoutAndPoolLimit` |
| `AC-006.3` | T3 | `TestClientTimeoutEndsARequestAPeerWillNotAnswer` |
| `AC-006.4` | T3 | `TestClientAbandonsARequestWhenItsContextIsCancelled` |
| `AC-006.5` | T2 | `TestNewRejectsSettingsThatCannotBeMeant`, `TestNewReportsEveryBadSettingAtOnce` |
| `AC-006.6` | T2 | `TestNewGivesEachClientItsOwnPool` |
| `AC-006.7` | T2 | `TestDefaultBoundsThePool`, `TestNewAppliesEveryPhaseTimeoutAndPoolLimit` |
| `AC-006.8` | T4 | `TestCloseIdleConnectionsReleasesThePool` |
| `AC-006.9` | T2 | `TestNewRejectsSettingsThatCannotBeMeant`, `TestNewReportsEveryBadSettingAtOnce` |
| `AC-006.10` | T5 | `TestClientRecordsASpanThroughTheSuppliedProvider`, `TestClientRecordsNothingWithoutAProvider`, `TestClientInjectsNothingWithoutAPropagator` |
| `AC-006.11` | T5 | `TestClientIgnoresTheOpenTelemetryGlobals` |
| `AC-006.12` | T5 | `TestClientPropagatesTheTraceContext` |
| `AC-006.13` | T1, T6 | `TestEverySettingDeclaresItsVariable` |
| `AC-006.14` | T1 | `TestConfigRendersInTheNotationAnOperatorWrites` |
| `AC-006.15` | T7 | `TestNewTransportHonoursTheProxyEnvironment` |



## Deferred

Nothing. `AC-006.13` was restated rather than deferred; see the change log in
`requirements.md`.
