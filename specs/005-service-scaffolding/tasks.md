---
feature: 005-service-scaffolding
created: 2026-09-19
updated: 2026-09-24
---

# Tasks: Service scaffolding

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Add `WriteJSON`, `WriteError`, `ClientError`, and `DecodeJSON` in
  `internal/server/json.go`, mapping every `encoding/json` failure and the body limit to a
  `ClientError`
  - Satisfies: `AC-005.1`, `AC-005.2`, `AC-005.3`, `AC-005.4`, `AC-005.5`, `AC-005.6`
  - Verify: `go test ./internal/server/ -run 'TestWriteJSON|TestDecodeJSON|TestWriteError' -race`
- [x] **T2** Switch the health, readiness, and version handlers to `WriteJSON`
  - Satisfies: `AC-005.1`
  - Verify: `go test ./internal/server/ -run 'TestHealthResponseBody|TestReadinessHandler|TestVersion' -race`
- [x] **T3** Add check registration and concurrent evaluation to `Readiness` in
  `internal/server/readiness.go`, with draining taking precedence
  - Satisfies: `AC-005.7`, `AC-005.8`, `AC-005.9`, `AC-005.10`, `AC-005.11`, `AC-005.12`
  - Verify: `go test ./internal/server/ -run 'TestReadiness|TestAddCheck' -race`
- [x] **T4** Add `withSecurityHeaders` in `internal/server/headers.go` and place it outermost
  in `NewMux`
  - Satisfies: `AC-005.13`, `AC-005.14`
  - Verify: `go test ./internal/server/ -run 'SecurityHeaders' -race`
- [x] **T5** Add `deploy/local/compose.yaml` and `deploy/local/prometheus.yml`
  - Satisfies: `AC-005.15`
  - Verify: `docker compose -f deploy/local/compose.yaml up -d --build`, then
    `curl -s http://localhost:9091/api/v1/targets` reports the `service` pool `up` with no
    error. `config -q` alone is not enough: it resolves no image and passed while the
    stack could not start.
- [x] **T6** Pin golangci-lint with a tool directive and route the `Lint` target and the CI
  lint job through it
  - Satisfies: `AC-005.16`
  - Verify: `go tool golangci-lint version` reports `2.13.2`; `go tool mage lint` passes;
    `grep -n 'go tool mage lint' .github/workflows/ci.yml`
- [x] **T7** Document the helpers, the readiness registry, the headers, the Compose stack,
  and the pinned linter in `README.md` and `CONTRIBUTING.md`
  - Satisfies: `AC-005.15`, `AC-005.16`
  - Verify: review
- [x] **T8** Return the providers from `internal/telemetry` instead of installing them
  globally, give `NewMux` a `Telemetry` parameter it passes to `otelhttp`, and wire both
  through `cmd/service`
  - Satisfies: `AC-005.17`, `AC-005.18`, `AC-005.21`, `AC-005.22`, `AC-005.23`
  - Verify: `go test ./internal/server/ ./internal/telemetry/ -run 'Telemetry|Global|Propagation|MeterProvider|Metrics|SDKErrors' -race`
- [x] **T9** Move signal setup into `main`, give `run` its context, signal channel, lookuper,
  and exit function, and add `cmd/service/main_test.go`
  - Satisfies: `AC-005.19`
  - Verify: `go test ./cmd/... -race`
- [x] **T10** Replace the singular error envelope with the plural `errors` document
  `docs/adr/0010-json-api-response-conventions.md` settles: `errorDocument`, `errorObject`,
  and per-code titles in `internal/server/errors.go`; `ClientError.Pointer`, the walk that
  collects every joined client error, and `decodePointer` in `internal/server/json.go`
  - Satisfies: `AC-005.2`, `AC-005.4`, `AC-005.6`, `AC-005.20`
  - Verify: `go test ./internal/server/ -run 'TestWriteJSONError|TestWriteError|TestDecodeJSON' -race`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition.

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-005.1` | T1, T2 | `TestWriteJSONEncodesTheValue` |
| `AC-005.2` | T1, T10 | `TestWriteJSONReportsAnUnencodableValueAsInternal` |
| `AC-005.3` | T1 | `TestDecodeJSONRequiresAJSONContentType` |
| `AC-005.4` | T1, T10 | `TestDecodeJSONNamesWhatIsWrong`, `TestDecodeJSONLocatesTheOffendingMember` |
| `AC-005.5` | T1 | `TestDecodeJSONReportsAnOversizedBodyAsTooLarge` |
| `AC-005.6` | T1, T10 | `TestWriteErrorMapsClientErrorsAndHidesTheRest`, `TestWriteErrorReportsEveryJoinedClientError` |
| `AC-005.7` | T3 | `TestReadinessHandlerConsultsRegisteredChecks` |
| `AC-005.8` | T3 | `TestReadinessHandlerConsultsRegisteredChecks` |
| `AC-005.9` | T3 | `TestReadinessCheckIsCancelledAtTheTimeout` |
| `AC-005.10` | T3 | `TestReadinessCheckPanicCountsAsFailed` |
| `AC-005.11` | T3 | `TestReadinessDrainingSkipsChecks` |
| `AC-005.12` | T3 | `TestAddCheckRejectsADuplicateName` |
| `AC-005.13` | T4 | `TestMuxSetsSecurityHeadersOnEveryResponse`, `TestNewAdminMuxSetsSecurityHeaders` |
| `AC-005.14` | T4 | `TestSecurityHeadersYieldToAHandlersOwnPolicy` |
| `AC-005.15` | T5, T7 | `docker compose up -d --build`, then Prometheus reports the `service` target `up` |
| `AC-005.16` | T6, T7 | `go tool golangci-lint version` |
| `AC-005.17` | T8 | `TestMuxRecordsThroughTheSuppliedTelemetry`, `TestMuxWithZeroTelemetryIgnoresInboundTraceHeaders`, `TestSetupMetricsExposesInstrumentsRecordedThroughItsMeterProvider` |
| `AC-005.18` | T8 | `TestSetupInstallsNoGlobalProviders` |
| `AC-005.19` | T9 | `TestRunStartsAndShutsDownCleanly`, `TestRunReportsAConfigurationFailure` |
| `AC-005.20` | T10 | `TestWriteErrorReportsEveryJoinedClientError` |
| `AC-005.21` | T8 | `TestSetupMetricsCollectsGoRuntimeMetrics` |
| `AC-005.22` | T8 | `TestSetupMetricsReportsTheServiceResource` |
| `AC-005.23` | T8 | `TestSetupTracingRoutesSDKErrorsToTheLogger` |

## Deferred

- Renaming the project to neutral placeholders and a bootstrap target that rewrites module
  path, owner, image name, and environment prefix: after the copy into the template
  repository, when its final name is known.
- Grafana in the Compose stack: Jaeger's and Prometheus's own UIs cover a local session.
