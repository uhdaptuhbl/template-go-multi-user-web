---
feature: 001-server-foundation
created: 2026-09-17
updated: 2026-09-24
---

# Tasks: Server foundation

This is a repair decomposition, not new construction. The code and most of its tests already
exist on `main`; each task either cites an acceptance criterion on the existing test that
already proves it, or, where genuinely no test proves it, adds one under a mutation check
(break the line the test is meant to cover, confirm the new test fails with the expected
message, restore it). Adding a citation to a test's doc comment and writing a new test are
both scoped to `*_test.go` files; no production code changes.

Order tasks so the suite is green at every boundary; no task should depend on a later one.

## Checklist

- [x] **T1** Cite the configuration-loading criteria on their existing tests
  - Add `// Covers AC-001.1.` to `TestLoadAppliesEnvironmentValuesOverTheDefaults`
    (`internal/config/config_test.go`).
  - Add `// Covers AC-001.2.` to `TestDecodeReportsStructTagValidationFailures`
    (`internal/config/loader_test.go`).
  - Add `// Covers AC-001.3.` to `TestLoadTreatsAnEmptyVariableAsUnset`
    (`internal/config/config_test.go`).
  - Satisfies: `AC-001.1`, `AC-001.2`, `AC-001.3`
  - Verify: `go test ./internal/config/...`

- [x] **T2** Prove and cite the default listener addresses
  - AC-001.4 (application listener defaults to `:8080`) is covered by
    `TestLoadDefaultsLifecycleAndProxy` (`internal/config/config_test.go`), which asserts the
    literal `:8080`, not by a dedicated `TestDefaultConfigUsesPort8080` as originally planned
    here; no new test was added.
  - Add `// Covers AC-001.5.` to `TestDefaultAdminConfigUsesItsOwnPort`
    (`internal/server/admin_test.go`).
  - Satisfies: `AC-001.4`, `AC-001.5`
  - Verify: `go test ./internal/config/... ./internal/server/... -run 'TestLoadDefaultsLifecycleAndProxy|TestDefaultAdminConfigUsesItsOwnPort'`

- [x] **T3** Cite the health-endpoint criterion
  - Add `// Covers AC-001.6.` to `TestHealthResponseBody`
    (`internal/server/handler_test.go`), which proves the response body and status on the
    application listener.
  - Add a line to `TestNewAdminMuxRouting`'s existing doc comment noting it also covers
    `AC-001.6` for the administrative listener (the "health is served" case), since that is
    the only test proving the health route is mounted there too.
  - Satisfies: `AC-001.6`
  - Verify: `go test ./internal/server/... -run 'TestHealthResponseBody|TestNewAdminMuxRouting'`

- [x] **T4** Prove and cite that metrics and profiling are administrative-only
  - Add `// Covers AC-001.9, AC-001.10.` to `TestNewAdminMuxRouting`
    (`internal/server/admin_test.go`), which proves both are served on the administrative
    listener.
  - No existing test asserts the application listener (`NewMux`) does *not* expose
    `/metrics` or `/debug/pprof/`; its catch-all route means both currently fall through to
    the UI handler rather than 404ing, which is not the same as proving the real metrics or
    pprof handlers are absent. Write `TestNewMuxDoesNotServeAdministrativeRoutes` in
    `internal/server/handler_test.go`, asserting `GET /metrics` and
    `GET /debug/pprof/` against `testMux(t)` reach the stand-in UI handler rather than
    anything metrics- or pprof-shaped (for example, by giving `testUI` a distinguishing
    response body and asserting on it). Under mutation check: temporarily register the real
    metrics/pprof handlers on `NewMux`, confirm the new test fails, then revert. Add
    `// Covers AC-001.9, AC-001.10.` to it.
  - Satisfies: `AC-001.9`, `AC-001.10`
  - Verify: `go test ./internal/server/... -run 'TestNewAdminMuxRouting|TestNewMuxDoesNotServeAdministrativeRoutes'`

- [x] **T5** Cite the embedded-frontend criteria
  - Add `// Covers AC-001.7.` to `TestNewMuxRouting`
    (`internal/server/handler_test.go`), whose "unmatched path falls through to ui" case
    proves it.
  - Add `// Covers AC-001.8.` to `TestHandlerServesEmbeddedAssets`
    (`internal/web/web_test.go`), whose "missing asset is not found" case proves it.
  - Satisfies: `AC-001.7`, `AC-001.8`
  - Verify: `go test ./internal/server/... -run TestNewMuxRouting && go test ./internal/web/... -run TestHandlerServesEmbeddedAssets`

- [x] **T6** Cite the shutdown and listener-failure criteria
  - Add `// Covers AC-001.11.` to `TestServeShutsDownWhenContextIsCancelled`
    (`internal/server/server_test.go`).
  - Add `// Covers AC-001.12.` to `TestForceExitOnSecondExitsAfterASecondSignal`
    (`internal/signals/signals_test.go`).
  - Add `// Covers AC-001.13.` to `TestRunAllReturnsWhenOneServerFails`
    (`internal/server/server_test.go`).
  - Satisfies: `AC-001.11`, `AC-001.12`, `AC-001.13`
  - Verify: `go test ./internal/server/... -run 'TestServeShutsDownWhenContextIsCancelled|TestRunAllReturnsWhenOneServerFails' && go test ./internal/signals/... -run TestForceExitOnSecondExitsAfterASecondSignal`

- [x] **T7** Cite the request-logging and trace-exclusion criteria
  - Add `// Covers AC-001.14.` to `TestWithRequestLoggingEmitsOneEntryDescribingTheRequest`
    (`internal/server/handler_test.go`), which proves the method/path/status/duration
    fields; the `route` field it also names is proven separately by
    `TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace`, so add
    `// Also covers the route field of AC-001.14.` there too.
  - Add `// Covers AC-001.15.` to `TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace`
    (`internal/server/tracing_test.go`).
  - Add `// Covers AC-001.16.` to `TestShouldTraceExcludesTheLivenessProbe`
    (`internal/server/tracing_test.go`).
  - Satisfies: `AC-001.14`, `AC-001.15`, `AC-001.16`
  - Verify: `go test ./internal/server/... -run 'TestWithRequestLoggingEmitsOneEntryDescribingTheRequest|TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace|TestShouldTraceExcludesTheLivenessProbe'`

- [x] **T8** Cite the no-op-tracer-provider criterion
  - Add `// Covers AC-001.17.` to `TestSetupTracingWithoutAnEndpointLeavesExportDisabled`
    (`internal/telemetry/telemetry_test.go`).
  - Satisfies: `AC-001.17`
  - Verify: `go test ./internal/telemetry/... -run TestSetupTracingWithoutAnEndpointLeavesExportDisabled`

- [x] **T9** Append the traces path to the general collector endpoint
  - `telemetry.Config.TracesEndpoint` returns the signal-specific endpoint as given, or the
    general endpoint with `v1/traces` appended, respecting a trailing slash.
  - Satisfies: `AC-001.33`
  - Verify: `go test ./internal/telemetry/... -run 'TracesEndpoint|SignalPath'`

## Traceability

| Criterion | Tasks | Test |
| --- | --- | --- |
| `AC-001.1` | T1 | `TestLoadAppliesEnvironmentValuesOverTheDefaults`, `TestLoadAcceptsIPv6ListenAddresses`, `TestDecodeReadsValuesIntoTheTarget`, `TestDecodeAppliesDefaultsAndLetsValuesOverrideThem`, `TestDecodeReadsTheProcessEnvironmentWhenNoLookuperIsGiven`, `TestDurationReadsWhatAnOperatorWrites`, `TestByteSizeReadsWhatAnOperatorWrites` |
| `AC-001.2` | T1 | `TestDecodeReportsStructTagValidationFailures`, `TestDecodeRunsTheCustomValidatorOnEachImmediateField`, `TestLoadRejectsAnEphemeralListenPort`, `TestListenAddressesNamesEachVariableFromItsTags`, `TestLoadReportsMistakesInSeparateSettingsGroupsTogether`, `TestLoadRequiresTheReadTimeoutToCoverTheHeaderTimeout`, `TestLoadRequiresTheHandlerTimeoutToFitInsideTheWriteTimeout`, `TestDecodeReportsDecodeFailures`, `TestDecodeReportsEveryValidationFailureAtOnce`, `TestDecodeValidatesNestedStructFields`, `TestDecodeReportsCustomValidationFailures`, `TestDecodeReportsFieldAndTargetValidationFailuresTogether`, `TestDecodeJoinsFailuresFromEveryFieldValidator`, `TestNewTrustedProxiesRejectsInvalidCIDR`, `TestDurationRejectsWhatIsNotADuration`, `TestByteSizeRejectsWhatIsNotASize`, `TestByteSizeRejectsASizeThatOverflows`, `TestByteSizeAcceptsTheLargestSizeThatFits` |
| `AC-001.3` | T1 | `TestLoadTreatsAnEmptyVariableAsUnset`, `TestDecodeLeavesUnsetOptionalFieldsAtTheirZeroValue`, `TestEmptyTextLeavesTheValueAlone` |
| `AC-001.4` | T2 | `TestLoadReturnsTheDefaultsWhenNothingIsSet` |
| `AC-001.5` | T2 | `TestDefaultAdminConfigUsesItsOwnPort`, `TestLoadConfiguresTheTwoListenersIndependently` |
| `AC-001.6` | T3 | `TestHealthResponseBody` (application listener), `TestNewAdminMuxRouting` (administrative listener), `TestNewMuxRouting` |
| `AC-001.7` | T5 | `TestNewMuxRouting` |
| `AC-001.8` | T5 | `TestHandlerServesEmbeddedAssets` |
| `AC-001.9` | T4 | `TestNewAdminMuxRouting` (exposed on admin), `TestNewMuxDoesNotServeAdministrativeRoutes` (absent from the application listener) |
| `AC-001.10` | T4 | `TestNewAdminMuxRouting` (exposed on admin), `TestNewMuxDoesNotServeAdministrativeRoutes` (absent from the application listener) |
| `AC-001.11` | T6 | `TestServeShutsDownWhenContextIsCancelled`, `TestRunAllStopsEveryServerWhenTheContextIsCancelled` |
| `AC-001.12` | T6 | `TestForceExitOnSecondExitsAfterASecondSignal`, `TestForceExitOnSecondIgnoresTheFirstSignal` |
| `AC-001.13` | T6 | `TestRunAllReturnsWhenOneServerFails`, `TestRunReportsUnusableAddress`, `TestServeReportsAListenerFailure` |
| `AC-001.14` | T7 | `TestWithRequestLoggingEmitsOneEntryDescribingTheRequest`, `TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace`, `TestWithRequestLoggingPreservesTheResponse`, `TestWithRequestLoggingReportsOKWhenTheHandlerOmitsWriteHeader` |
| `AC-001.15` | T7 | `TestWithRequestLoggingCorrelatesTheLogEntryWithTheTrace`, `TestSetupTracingWithAnEndpointEnablesExport` |
| `AC-001.16` | T7 | `TestShouldTraceExcludesTheLivenessProbe` |
| `AC-001.17` | T8 | `TestSetupTracingWithoutAnEndpointLeavesExportDisabled`, `TestDefaultConfigNamesTheServiceAndLeavesExportDisabled`, `TestSetupTracingProvidesPropagationEvenWhenDisabled` |
| `AC-001.18` | T1 | `TestDecodeReportsEveryValidationFailureAtOnce`, `TestDecodeJoinsFailuresFromEveryFieldValidator`, `TestDecodeReportsFieldAndTargetValidationFailuresTogether`, `TestDecodeRunsTheCustomValidatorOnEachImmediateField`, `TestDecodeRunsTheTargetValidatorAfterItsFields` |
| `AC-001.19` | T1 | `TestDecodeLabelsAnUntaggedFieldByItsName`, `TestListenAddressesNamesEachVariableFromItsTags` |
| `AC-001.20` | T1 | `TestDefaultComposesEachPackagesOwnDefaults`, `TestDecodeResolvesNestedStructsUnderTheirPrefix` |
| `AC-001.21` | T1 | `TestLoadReadsTelemetryVariablesWithoutTheProjectPrefix` |
| `AC-001.22` | T1, T8 | `TestLoadPrefersTheSignalSpecificTracesEndpoint`, `TestTracesEndpointPrefersTheSignalSpecificSetting` |
| `AC-001.23` | T1 | `TestLoadTakesTheServiceVersionFromTheBuildRatherThanTheEnvironment` |
| `AC-001.24` | T7 | `TestNew`, `TestDefaultConfigProducesAUsableLogger`, `TestNewFromConfigPassesBothSettingsThrough` |
| `AC-001.25` | T7 | `TestNewSlogHandlerRoutesRecordsToZap`, `TestInstallSlogDefaultRoutesThePackageLevelSlogLoggerToZap`, `TestNewSlogHandlerAppliesZapLevelFiltering` |
| `AC-001.26` | T1 | `TestSecretStringRedactsInEveryStringRepresentation`, `TestSecretStringRedactsWhenItHoldsNothing`, `TestSecretStringLogValueIsAString`, `TestSecretStringDoesNotReachAnSlogHandler`, `TestSecretStringMarshalsAsRedactedText`, `TestSecretStringMarshalsAsRedactedJSON`, `TestSecretStringSurvivesAJSONRoundTripAsRedactedText`, `TestDecodeLoadsSecretStringFieldsWithoutRevealingThem` |
| `AC-001.27` | T1 | `TestSecretStringExposeReturnsThePlaintext` |
| `AC-001.28` | T1 | `TestSecretStringUnmarshalsTextVerbatim`, `TestSecretStringUnmarshalsJSONStrings`, `TestSecretStringUnmarshalsJSONIntoAStructField`, `TestSecretStringRejectsJSONThatIsNotAString`, `TestSecretStringWrapsMalformedJSONErrors`, `TestDecodeLoadsSecretStringFieldsWithoutRevealingThem`, `TestDecodeValidatesSecretStringFields` |
| `AC-001.29` | T7 | `TestWithRequestLoggingNamesTheSpanAfterTheMatchedRoute` |
| `AC-001.30` | T7 | `TestWithRequestLoggingOmitsTraceFieldsWhenNoSpanIsActive` |
| `AC-001.31` | T1 | `TestDecodeDoesNotRunCustomValidatorsBelowTheFirstLevel` |
| `AC-001.32` | T1 | `TestDecodeAppliesMutatorsToResolvedValues`, `TestDecodeReportsMutatorFailures` |
| `AC-001.33` | T9 | `TestTracesEndpointAppendsTheSignalPathToTheGeneralEndpoint`, `TestSetupTracingExportsToTheSignalPathOfTheGeneralEndpoint` |

## Deferred

- Whether the application listener should explicitly 404 `/metrics` and `/debug/pprof/*`
  rather than falling through to the frontend catch-all is unresolved; the criterion only
  requires the real handlers be administrative-only, which the current routing already
  satisfies. Revisit if the frontend's own routing ever needs those path prefixes.
- Resolved 2026-09-20: `config.SecretString`'s redaction behavior was tested but cited by no
  acceptance criterion, because no field in `config.Config` used it yet. `AC-001.26` now
  states the redaction rule, and the tests that cite it live in
  `internal/secret/secret_test.go`, where the type moved (see
  `docs/adr/0006-configuration-loading.md`).
