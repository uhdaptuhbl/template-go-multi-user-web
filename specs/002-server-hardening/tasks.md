---
feature: 002-server-hardening
created: 2026-09-17
updated: 2026-09-24
---

# Tasks: Server hardening

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Add a JSON error helper in `internal/server/errors.go` that writes a structured
  error body with the correct status code and content type
  - Satisfies: `AC-002.1`, `AC-002.4`, `AC-002.21`
  - Verify: `go test ./internal/server/ -run TestWriteJSONError -race`
- [x] **T2** Add trusted-proxy CIDR parsing and client address resolution in
  `internal/server/proxy.go`, reading `X-Forwarded-For` right to left only when the peer is
  trusted
  - Satisfies: `AC-002.10`, `AC-002.11`
  - Verify: `go test ./internal/server/ -run TestTrustedProxiesClientIP -race`
- [x] **T3** Add readiness state tracking and the `/readyz` handler in
  `internal/server/readiness.go`, reporting ready while serving and draining once shutdown
  begins
  - Satisfies: `AC-002.13`, `AC-002.14`, `AC-002.16`
  - Verify: `go test ./internal/server/ -run 'TestReadinessHandler' -race`
- [x] **T4** Add a status-recording response writer in
  `internal/server/responsewriter.go` that captures the status code written to it
  - Satisfies: `AC-002.12`
  - Verify: `go test ./internal/server/ -run TestStatusRecorderWritten -race`
- [x] **T5** Add panic recovery middleware in `internal/server/recovery.go` that logs a
  panic and returns a 500, but re-panics `http.ErrAbortHandler` without logging a stack
  - Satisfies: `AC-002.1`, `AC-002.2`
  - Verify: `go test ./internal/server/ -run 'TestPanicRecovery' -race`
- [x] **T6** Add request identity handling in `internal/server/requestid.go`: generate a
  32-hex-character id when absent, adopt a well-formed id from a trusted peer, and discard
  one from an untrusted peer
  - Satisfies: `AC-002.6`, `AC-002.7`, `AC-002.8`, `AC-002.9`
  - Verify: `go test ./internal/server/ -run 'TestRequestID' -race`
- [x] **T7** Add body size limiting, an in-flight request limiter, and a handler timeout in
  `internal/server/limits.go`
  - Satisfies: `AC-002.4`, `AC-002.21`, `AC-002.22`
  - Verify: `go test ./internal/server/ -run 'TestRequestBodyLimit|TestInFlightLimitShedsExcess|TestHandlerTimeout' -race`
- [x] **T8** Add server config fields, wire `ErrorLog` and `MaxHeaderBytes`, and implement
  lifecycle management with a pre-drain delay in `internal/server/server.go`
  - Satisfies: `AC-002.3`, `AC-002.5`, `AC-002.15`
  - Verify: `go test ./internal/server/ -run 'TestServerErrorLogGoesToZap|TestServerSetsMaxHeaderBytes|TestRunAllFailsReadinessBeforeClosingListeners' -race`
- [x] **T9** Add content `ETag`, cache-control, and security headers to the frontend handler
  in `internal/web/web.go`
  - Satisfies: `AC-002.18`, `AC-002.19`, `AC-002.20`
  - Verify: `go test ./internal/web/ -run 'TestHandlerRevalidatesWithETag|TestHandlerSetsCacheHeaders|TestHandlerSetsSecurityHeaders' -race`
- [x] **T10** Add a `build_info` metric carrying version and commit labels in
  `internal/telemetry/metrics.go`
  - Satisfies: `AC-002.25`
  - Verify: `go test ./internal/telemetry/ -run TestRecordBuildInfoExposesLabels -race`
- [x] **T11** Compose the application mux in `internal/server/handler.go`, wiring recovery,
  request id, and status-based request log levels
  - Satisfies: `AC-002.12`
  - Verify: `go test ./internal/server/ -run 'TestMuxRecoversHandlerPanic|TestMuxServesReadiness|TestRequestLogCarriesCorrelationFields|TestRequestLogLevelFollowsStatus' -race`
- [x] **T12** Default the admin listener to `127.0.0.1:9090` and serve `/readyz` on it in
  `internal/server/admin.go`
  - Satisfies: `AC-002.17`, `AC-002.26`, `AC-002.27`, `AC-002.29`
  - Verify: `go test ./internal/server/ -run 'TestDefaultAdminConfigBindsLoopback|TestAdminMuxServesReadiness|TestNewVersionHandler|TestVersionResponseJSONKeys|TestUnstampedBuildReportsUnknown|TestNewAdminMuxRouting|TestVersionOverTheWire|TestApplicationMuxDoesNotServeVersion|TestNewAdminMuxDoesNotServeTheApplication' -race`
- [x] **T13** Add lifecycle and trusted-proxy config sections, with CIDR validation, in
  `internal/config/config.go`
  - Satisfies: `AC-002.10`, `AC-002.11`, `AC-002.15`, `AC-002.17`
  - Verify: `go test ./internal/config/ -run 'TestLoadRejectsInvalidTrustedCIDR|TestLoadDefaultsLifecycleAndProxy|TestLoadOverridesLifecycleAndProxy' -race`
- [x] **T14** Log startup version and commit information and the effective, secret-redacted
  configuration in `cmd/service/main.go`
  - Satisfies: `AC-002.23`, `AC-002.24`
  - Verify: `go test ./cmd/service/ -run 'TestInfoLog|TestLogEffectiveRedactsSecrets' -race`
- [x] **T15** Add integration tests covering drain sequencing, request limits, and frontend
  revalidation over the wire
  - Satisfies: `AC-002.14`, `AC-002.15`, `AC-002.16`, `AC-002.18`
  - Verify: `go test -race -tags=integration ./internal/server/ ./internal/web/`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-002.1` | T1, T5, T11 | `TestWriteJSONError`, `TestPanicRecoveryWritesInternalError`, `TestPanicRecoveryPreservesWrittenResponse`, `TestMuxRecoversHandlerPanic`, `TestNewAdminMuxRecoversFromAPanic`, `TestWriteJSONError` |
| `AC-002.2` | T5 | `TestPanicRecoveryRepanicsOnErrAbortHandler` |
| `AC-002.3` | T8 | `TestServerErrorLogGoesToZap` |
| `AC-002.4` | T1, T7, T15 | `TestWriteJSONError`, `TestRequestBodyLimitRejectsDeclaredOversizedBody`, `TestRequestBodyLimitRejectsUndeclaredOversizedBody`, `TestRequestBodyLimitDisabled`, `TestRequestBodyLimitOverTheWire`, `TestNewAdminMuxRefusesAnOversizedBody` |
| `AC-002.5` | T8 | `TestServerSetsMaxHeaderBytes` |
| `AC-002.6` | T6 | `TestRequestIDGeneratedWhenAbsent` |
| `AC-002.7` | T6 | `TestRequestIDAdoptedFromTrustedPeer`, `TestRequestIDRejectsMalformedValue` |
| `AC-002.8` | T6 | `TestRequestIDRejectedFromUntrustedPeer` |
| `AC-002.9` | T6, T11, T15 | `TestRequestIDGeneratedWhenAbsent`, `TestRequestLogCarriesCorrelationFields`, `TestRequestIDEchoedOverTheWire` |
| `AC-002.10` | T2, T13 | `TestTrustedProxiesClientIP`, `TestLoadRejectsInvalidTrustedCIDR`, `TestLoadAcceptsTheTrustedCIDRFormsTheParserAccepts`, `TestProxyConfigValidateAcceptsWhatTheParserAccepts` |
| `AC-002.11` | T2, T11, T13 | `TestTrustedProxiesClientIP`, `TestRequestLogCarriesCorrelationFields`, `TestLoadRejectsInvalidTrustedCIDR` |
| `AC-002.12` | T4, T11 | `TestStatusRecorderWritten`, `TestRequestLogLevelFollowsStatus` |
| `AC-002.13` | T3, T11, T12 | `TestReadinessHandlerReady`, `TestMuxServesReadiness`, `TestAdminMuxServesReadiness`, `TestNewMuxRouting` |
| `AC-002.14` | T3, T8, T15 | `TestReadinessHandlerDraining`, `TestRunAllFailsReadinessBeforeClosingListeners`, `TestDrainSequence` |
| `AC-002.15` | T8, T13, T15 | `TestRunAllFailsReadinessBeforeClosingListeners`, `TestLoadDefaultsLifecycleAndProxy`, `TestLoadOverridesLifecycleAndProxy`, `TestDrainSequence`, `TestInFlightRequestCompletesDuringDrain` |
| `AC-002.16` | T12, T15 | `TestAdminMuxServesReadiness`, `TestDrainSequence` |
| `AC-002.17` | T12, T13 | `TestDefaultAdminConfigBindsLoopback`, `TestLoadDefaultsLifecycleAndProxy`, `TestDefaultAdminConfigUsesItsOwnPort`, `TestLoadReturnsTheDefaultsWhenNothingIsSet` |
| `AC-002.18` | T9, T15 | `TestHandlerRevalidatesWithETag`, `TestFrontendRevalidationOverTheWire` |
| `AC-002.19` | T9 | `TestHandlerSetsCacheHeaders` |
| `AC-002.20` | T9 | `TestHandlerSetsSecurityHeaders` |
| `AC-002.21` | T1, T7 | `TestWriteJSONError`, `TestInFlightLimitShedsExcess` |
| `AC-002.22` | T7 | `TestHandlerTimeoutCancelsContext`, `TestHandlerTimeoutDisabled` |
| `AC-002.23` | T14 | `TestInfoLog` |
| `AC-002.24` | T14 | `TestLogEffectiveRedactsSecrets`, `TestDurationRendersAsADurationString`, `TestByteSizeRendersWithASuffixWhenItIsExact`, `TestBothTypesSurviveAJSONRoundTrip` |
| `AC-002.25` | T10 | `TestRecordBuildInfoExposesLabels` |
| `AC-002.26` | T12 | `TestNewVersionHandler`, `TestVersionResponseJSONKeys`, `TestUnstampedBuildReportsUnknown`, `TestNewAdminMuxRouting`, `TestVersionOverTheWire` |
| `AC-002.27` | T12 | `TestApplicationMuxDoesNotServeVersion`, `TestVersionOverTheWire` |
| `AC-002.28` | T13 | `TestNewAppliesEveryConfiguredTimeout`, `TestDefaultConfigSetsEveryTimeout` |
| `AC-002.29` | T12 | `TestNewAdminMuxDoesNotServeTheApplication` |

## Deferred

Work identified during implementation but deliberately not done here, with where it went:
a new feature spec, an ADR, or an issue. Keeps scope honest without losing the finding.
