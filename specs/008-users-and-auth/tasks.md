---
feature: 008-users-and-auth
created: 2026-09-22
updated: 2026-09-24
status: implemented
---

# Tasks: Users and auth

Ordered decomposition of the design into increments. Each task is independently verifiable,
small enough to complete in one sitting, and cites the acceptance criteria it advances. Each
is built test-first.

Order tasks so the suite is green at every boundary; no task should depend on a later one.
Per the project's testing standard, each test cites the criterion IDs it satisfies in its doc
comment ("covers AC-008.n"); test function names state behavior and do not carry the ID. A
verify command below therefore runs the packages that hold a task's tests, and the Traceability
table names the individual tests for each criterion.

Most of these packages hold their tests behind the `integration` build tag, and those tests need
PostgreSQL: set `SERVICE_TEST_DB_DSN` to a server's connection string, or leave it unset and have
a Docker daemon available, in which case each package starts a disposable container. With
neither, the database-backed tests skip rather than fail, so a skip is not a pass.

## Checklist

- [x] **T-1** Define the auth error codes and their human-readable titles, covering the
  distinct failure conditions the ceremonies and login orchestration raise.
  - Satisfies: `AC-008.33`, `AC-008.34`, `AC-008.42`
  - Verify: `go test -count=1 -tags integration ./internal/server/ ./internal/authz/ ./internal/auth/`
- [x] **T-2** Add the store abstraction, select the driver from configuration, and provide
  the shims the rest of the feature builds on.
  - Satisfies: `AC-008.1`, `AC-008.2`, `AC-008.5`
  - Verify: `go test -count=1 -tags integration ./internal/store/ ./cmd/service/`
- [x] **T-3** Write the migrations and seed data the store needs, including the fixtures the
  integration suite relies on.
  - Satisfies: `AC-008.2`, `AC-008.3`, `AC-008.4`, `AC-008.31`
  - Verify: `go test -count=1 -tags integration ./internal/store/migrations/`
- [x] **T-4** Add the mail sender, inert when disabled so no message escapes an environment
  that has not configured one.
  - Satisfies: `AC-008.27`
  - Verify: `go test -count=1 ./internal/mail/`
- [x] **T-5** Add the rate limiter shared by the ceremonies and login orchestration.
  - Satisfies: `AC-008.37`
  - Verify: `go test -count=1 ./internal/ratelimit/`
- [x] **T-6** Add users and identities: the records and their relationship, and the
  operations that create, look up, and link them.
  - Satisfies: `AC-008.6`, `AC-008.7`, `AC-008.8`, `AC-008.9`, `AC-008.10`
  - Verify: `go test -count=1 -tags integration ./internal/user/`
- [x] **T-7** Add sessions: issuance, lookup, expiry, and revocation.
  - Satisfies: `AC-008.11`, `AC-008.12`, `AC-008.13`, `AC-008.14`, `AC-008.15`, `AC-008.16`,
    `AC-008.17`
  - Verify: `go test -count=1 -tags integration ./internal/session/`
- [x] **T-8** Add the audit recorder that logs the security-relevant events the rest of the
  feature raises.
  - Satisfies: `AC-008.38`, `AC-008.39`, `AC-008.40`
  - Verify: `go test -count=1 -tags integration ./internal/audit/`
- [x] **T-9** Add permissions, roles, and the checker that resolves a subject's access.
  - Satisfies: `AC-008.31`, `AC-008.32`
  - Verify: `go test -count=1 -tags integration ./internal/authz/`
- [x] **T-10** Add the OIDC ceremony: redirect, callback, and identity linkage.
  - Satisfies: `AC-008.20`, `AC-008.21`, `AC-008.22`
  - Verify: `go test -count=1 -tags integration ./internal/auth/oidc/ ./internal/authflow/`
- [x] **T-11** Add the passkey ceremony: registration and assertion.
  - Satisfies: `AC-008.23`, `AC-008.24`, `AC-008.25`, `AC-008.26`
  - Verify: `go test -count=1 -tags integration ./internal/auth/passkey/`
- [x] **T-12** Add the email code ceremony: issuance, delivery, and verification.
  - Satisfies: `AC-008.27`, `AC-008.28`, `AC-008.30`
  - Verify: `go test -count=1 -tags integration ./internal/auth/otp/`
- [x] **T-13** Add login orchestration that ties a completed ceremony to a user, session, and
  error response.
  - Satisfies: `AC-008.8`, `AC-008.9`, `AC-008.17`, `AC-008.36`, `AC-008.42`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestLogIn_'`
- [x] **T-14** Add the session middleware and CSRF protection that guard authenticated
  requests.
  - Satisfies: `AC-008.14`, `AC-008.18`, `AC-008.19`, `AC-008.34`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestAuthenticate_|TestRejectCrossSite|TestRequireAuthentication_'`
- [x] **T-15** Add the permission middleware that enforces the checker's decision on a route.
  - Satisfies: `AC-008.32`, `AC-008.33`
  - Verify: `go test -count=1 ./internal/authz/ -run 'TestRequirePermission'`
- [x] **T-16** Add the HTTP surface for login, session, and ceremony endpoints.
  - Satisfies: `AC-008.16`, `AC-008.26`, `AC-008.29`, `AC-008.35`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestHandle'`
- [x] **T-17** Add bootstrap administrator provisioning: an account whose verified email address
  is in the configured bootstrap list is admitted past the signup policy and created holding
  the administrator role, granted once at that creation and never again at a later login. The
  list applies only while no active administrator exists.
  - Satisfies: `AC-008.36`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'Bootstrap'`
- [x] **T-18** Add configuration and its validation for the feature's settings.
  - Satisfies: `AC-008.40`, `AC-008.41`
  - Verify: `go test -count=1 ./internal/config/ ./internal/session/`
- [x] **T-19** Wire the feature into process startup, including the store driver chosen in
  T-2.
  - Satisfies: `AC-008.3`, `AC-008.5`
  - Verify: `go test -count=1 -tags integration ./cmd/service/`
- [x] **T-20** Add the integration suite exercising the feature against a real store.
  - Satisfies: `AC-008.2`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestIntegration_'`
- [x] **T-21** Write the operator documentation for configuring and running the feature.
  - Satisfies: `AC-008.41`
  - Verify: `grep -n '__Host-' README.md`
- [x] **T-22** Add the account management repository layer over users and identities.
  - Satisfies: `AC-008.45`, `AC-008.46`, `AC-008.47`
  - Verify: `go test -count=1 -tags integration ./internal/user/`
- [x] **T-23** Add the account management service rules: validation, ownership, and the
  constraints on what a subject may change.
  - Satisfies: `AC-008.43`, `AC-008.44`, `AC-008.50`, `AC-008.52`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestUpdateDisplayName|TestRemove|TestDeleteAccount|TestSetStatus|TestRestoreAccount'`
- [x] **T-24** Add the account management HTTP surface.
  - Satisfies: `AC-008.48`, `AC-008.49`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestHandleMe|TestHandleAdmin'`
- [x] **T-25** Add the deleted-account purge that removes a deleted user's remaining data on
  schedule.
  - Satisfies: `AC-008.51`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ ./internal/user/ -run 'Purge'`
- [x] **T-26** Add durable audit attribution so an audit entry survives the actor's account
  being deleted.
  - Satisfies: `AC-008.53`
  - Verify: `go test -count=1 -tags integration ./internal/audit/`
- [x] **T-27** Add runtime settings that an administrator can change without a restart.
  - Satisfies: `AC-008.74`, `AC-008.75`, `AC-008.76`
  - Verify: `go test -count=1 -tags integration ./internal/settings/ ./internal/auth/ -run 'Settings|TestApply|TestOverride|TestLoad'`
- [x] **T-28** Add invites: creation, expiry, redemption, and the constraints on reuse.
  - Satisfies: `AC-008.62`, `AC-008.63`, `AC-008.64`, `AC-008.65`, `AC-008.66`, `AC-008.67`,
    `AC-008.69`
  - Verify: `go test -count=1 -tags integration ./internal/invite/`
- [x] **T-29** Add signup admission rules governing who may create an account and under what
  condition.
  - Satisfies: `AC-008.54`, `AC-008.55`, `AC-008.56`, `AC-008.57`, `AC-008.58`, `AC-008.59`,
    `AC-008.60`, `AC-008.61`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestAdmitAccount_'`
- [x] **T-30** Carry an invite through the OIDC and email code ceremonies in server-side state,
  so redemption completes whichever of the two a signup uses. A passkey login never creates an
  account, so it carries no invite.
  - Satisfies: `AC-008.70`
  - Verify: `go test -count=1 -tags integration ./internal/auth/oidc/ ./internal/auth/otp/`
- [x] **T-31** Add the approval queue for signups that require administrator sign-off.
  - Satisfies: `AC-008.71`, `AC-008.72`, `AC-008.73`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'Approv|Reject|RequireApproval'`
- [x] **T-32** Add the invite QR code and its redemption landing page.
  - Satisfies: `AC-008.68`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestHandleInviteQR|TestHandleInviteRedeem|TestIntegration_InviteQR'`
- [x] **T-33** Reissue the session cookie at most hourly with a lifetime capped by the
  absolute expiry, and skip session resolution for the health and readiness probes.
  - Satisfies: `AC-008.77`, `AC-008.84`
  - Verify: `go test -count=1 -tags integration ./internal/store/migrations/ ./internal/session/ ./internal/auth/ ./cmd/service/ -run 'TestMigration5AddsSessionCookieIssuedAt|TestReissueCookie|TestAuthenticateReissuesCookieOnStaleSession|TestAuthenticateSkipsSessionLookupForHealthProbes|TestReadinessFailsClosedWhenTheDatabaseBecomesUnreachable'`
- [x] **T-34** Make a rejected account's rejection final: refuse to restore it or change its
  status by any other path.
  - Satisfies: `AC-008.78`
  - Verify: `go test -count=1 -tags integration ./internal/user/ ./internal/auth/ -run 'TestRejectSetsRejectedAt|TestRestoreRefusesARejectedAccount|TestPatchStatusActiveOnRejectedAccountIs409|TestPatchStatusSuspendedOnRejectedAccountIs409'`
- [x] **T-35** Grant the bootstrap administrator role exactly once, only at account creation,
  and never again at login; once an active administrator exists, the list grants nothing.
  - Satisfies: `AC-008.79`
  - Verify: `go test -count=1 -tags integration ./internal/user/ ./internal/auth/ -run 'TestMarkBootstrapAdminGrantedTxMarksOnceAndOnlyOnce|TestBootstrapAccountCreatedAtSignupHoldsAdminAndIsMarked|TestBootstrapAdminIsNotRegrantedAfterDemotion|TestExistingAccountAddedToBootstrapListIsNotGrantedAtLogin'`
- [x] **T-36** Add a configured ceiling on invite lifetime, enforced on both an issued invite's
  TTL and the configured default.
  - Satisfies: `AC-008.80`
  - Verify: `go test -count=1 -tags integration ./internal/config/ ./internal/settings/ ./internal/invite/ ./internal/auth/ -run 'TestApplyRejectsDefaultTTLAboveInviteMaxTTL|TestDefaultAuthConfigInviteLimits|TestCreateRejectsTTLAboveMax|TestCreateCapsDefaultTTLAtMax|TestHandleInvitesCreate_TTLAboveMaxIs400'`
- [x] **T-37** Add a configured default redemption limit an invite gets when its issuer names
  none.
  - Satisfies: `AC-008.81`
  - Verify: `go test -count=1 -tags integration ./internal/config/ ./internal/settings/ ./internal/invite/ -run 'TestLoadExposesInviteLimitsFromOptions|TestDefaultAuthConfigInviteLimits|TestCreateUsesConfiguredDefaultMaxUses'`
- [x] **T-38** Bind an email one-time code to the browser that requested it, so an earlier
  code from the same browser is invalidated and one from another browser is not, and so an
  outstanding invite carries forward onto the new code.
  - Satisfies: `AC-008.82`
  - Verify: `go test -count=1 -tags integration ./internal/store/migrations/ ./internal/auth/otp/ ./internal/auth/ -run 'TestMigration6AddsOTPCodeBinding|TestRequestFromAnotherBindingLeavesTheFirstCodeLive|TestRequestFromSameBindingInvalidatesEarlierCode|TestRequestWithoutInviteCarriesForwardTheOutstandingInvite|TestHandleOTPStart_SetsBindingCookie|TestHandleOTP_AttackerCannotStripVictimsInvite'`
- [x] **T-39** Reject an email code presented by a browser other than the one that requested
  it, without counting the attempt against any code's limit.
  - Satisfies: `AC-008.83`
  - Verify: `go test -count=1 -tags integration ./internal/auth/otp/ ./internal/auth/ -run 'TestVerifyFromAnotherBindingFailsWithoutCountingAnAttempt|TestHandleOTPVerify_WithoutBindingCookieIs401'`
- [x] **T-40** Answer the readiness probe 503 while the database is unreachable, consistent
  with T-33's health-probe exemption from session resolution.
  - Satisfies: `AC-008.84`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ ./cmd/service/ -run 'TestAuthenticateSkipsSessionLookupForHealthProbes|TestReadinessFailsClosedWhenTheDatabaseBecomesUnreachable'`
- [x] **T-41** Refuse to start when no authentication method is enabled, naming the variables
  that enable one.
  - Satisfies: `AC-008.85`
  - Verify: `go test -count=1 ./internal/config/ -run 'TestAuthConfigValidateRejectsNoAuthenticationMethod'`
- [x] **T-42** Continue a sign-in without its invite when the invite presented at the OIDC
  start route is dead, so the signup policy alone decides admission.
  - Satisfies: `AC-008.86`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestHandleOIDCStart_DeadInviteContinuesWithoutInvite'`
- [x] **T-43** Redact an invite token from every log line, audit record, and trace attribute
  on every outcome the invite routes can reach.
  - Satisfies: `AC-008.87`
  - Verify: `go test -count=1 -tags integration ./internal/server/ ./internal/auth/ ./internal/authz/ -run 'TestInviteTokenNotLoggedOrTracedOnMatchedRoute|TestInviteTokenNotLoggedOrTracedOnUnmatchedMethod|TestInviteTokenNotLoggedOrTracedOnUnmatchedSubpath|TestInviteTokenNotLoggedOrTracedWhenShedBeforeTheMux|TestInviteTokenNotLoggedByCrossSiteRejection|TestInviteTokenNotLoggedByPermissionDenial|TestInviteLandingStillRoutesTheRealToken'`
- [x] **T-44** Record exactly one audit event for a client's first refusal on a rate limit,
  and none for its repeat refusals until a request from it is admitted again.
  - Satisfies: `AC-008.88`
  - Verify: `go test -count=1 -tags integration ./internal/ratelimit/ ./internal/auth/ -run 'TestDecideReportsFirstRefusalOnlyOnce|TestDecideResetsFirstRefusalAfterAnAllow|TestRateLimitedRecordsOneAuditEventPerRefusalRun|TestHandleOTPVerify_FirstRefusalAuditsEmailSubject'`
- [x] **T-45** Accept an identity token whose `email_verified` claim is the string form of a
  boolean.
  - Satisfies: `AC-008.89`
  - Verify: `go test -count=1 -tags integration ./internal/auth/oidc/ -run 'TestFinishAcceptsEmailVerifiedSentAsAString'`
- [x] **T-46** Answer 404 when an administrator revokes the sessions of an account that does
  not exist.
  - Satisfies: `AC-008.90`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ -run 'TestHandleAdminUsersSessions_UnknownID_ReturnsExact404Body|TestHandleAdminUsersStatus_UnknownID_ReturnsExact404Body|TestHandleAdminUsersRoles_UnknownTarget_ReturnsExact404Body'`
- [x] **T-47** Stop writing recipient addresses to the mail and email-code logs, and log
  the cause of a failed send.
  - Satisfies: `AC-008.91`
  - Verify: `go test -count=1 ./internal/mail/ -run TestSendDoesNotLogTheRecipient` and
    `go test -count=1 -tags integration ./internal/auth/otp/ -run TestRequestDoesNotLogTheAddressWhenTheSenderFails`
- [x] **T-48** Give every test a criterion citation or a stated exemption, and write the
  criteria the sweeper's tests were verifying without one.
  - Satisfies: `AC-008.92`, `AC-008.93`
  - Verify: `go test -count=1 -tags integration ./internal/auth/ ./internal/invite/ -run 'TestSweeper|TestDeleteExpired'`

## Traceability

Every criterion appears at least once, confirming nothing was dropped in decomposition. The
Test column names tests that exercise the criterion; where one test covers only part of a
criterion, several are listed. A criterion whose tests leave part of it unobserved is listed
under Deferred and in the verification status of `requirements.md`.

| Criterion | Task | Test |
| --- | --- | --- |
| AC-008.1 | T-2 | `TestApplyCreatesEveryTableFromMigration1` (internal/store/migrations/migrations_test.go); `TestNativeColumnTypesReachTheDatabase` (internal/store/migrations/migrations_test.go); `TestMigration4AddsFollowUpColumnsAndIndexes` (internal/store/migrations/migrations_test.go) |
| AC-008.2 | T-2, T-3, T-20 | `TestRunFailsStartupAgainstAnUnreachableDatabase` (cmd/service/main_integration_test.go); `TestConfigValidateRejectsWhatCannotNameAReachableServer` (internal/store/config_test.go) |
| AC-008.3 | T-3, T-19 | `TestApplyReachesVersion3AndIsIdempotent` (internal/store/migrations/migrations_test.go); `TestRunAppliesEveryPendingMigrationBeforeAcceptingRequests` (cmd/service/main_integration_test.go) |
| AC-008.4 | T-3 | `TestApplyAgainstACorruptedMigrationTableReturnsAWrappedError` (internal/store/migrations/migrations_test.go); `TestRunFailingMigrationStopsTheProcessAndNamesIt` (cmd/service/main_integration_test.go) |
| AC-008.5 | T-2, T-19 | `TestRunFailsStartupAgainstAnUnreachableDatabase` (cmd/service/main_integration_test.go); `TestOpenFailsWithinConnectTimeoutAgainstAClosedPort` (internal/store/store_test.go) |
| AC-008.6 | T-6 | `TestLogIn_VerifiedEmailCollision_CreatesAccountWithNullEmail` (internal/auth/service_test.go); `TestCreateWithIdentityWithTakenEmailReturnsErrEmailTakenAndLeavesNoPartialRow` (internal/user/repository_test.go) |
| AC-008.7 | T-6 | `TestByIdentityReturnsNotFoundForUnknownPair` (internal/user/repository_test.go); `TestLinkIdentityWithPairBelongingToAnotherAccountReturnsErrIdentityLinked` (internal/user/repository_test.go); `TestLogIn_ExistingActiveAccount_IssuesSession` (internal/auth/service_test.go) |
| AC-008.8 | T-6, T-13 | `TestIntegration_UnknownUserProviderLoginGrantsSession` (internal/auth/integration_test.go); `TestCreateWithIdentityThenByIdentityReturnsSameAccount` (internal/user/repository_test.go) |
| AC-008.9 | T-6, T-13 | `TestLogIn_VerifiedEmailCollision_CreatesAccountWithNullEmail` (internal/auth/service_test.go); `TestFinishPropagatesEmailVerifiedFalse` (internal/auth/oidc/oidc_test.go) |
| AC-008.10 | T-6 | `TestLinkIdentity_Success_ResolvesThroughByIdentity` (internal/auth/service_test.go); `TestFinishIdentityLink_MatchingSession_Links` (internal/auth/account_test.go); `TestLinkIdentityAttachesSecondIdentityAndIdentitiesForReturnsBoth` (internal/user/repository_test.go) |
| AC-008.11 | T-7 | `TestIssueReturnsTokenAndMatchingDigest` (internal/session/session_test.go); `TestStoreTokenFromRequestReturnsCookieValue` (internal/session/cookie_test.go) |
| AC-008.12 | T-7 | `TestIssueReturnsTokenAndMatchingDigest` (internal/session/session_test.go) |
| AC-008.13 | T-7 | `TestStoreSetCookieSetsAttributes` (internal/session/cookie_test.go); `TestStoreSetCookieOmitsSecureWhenConfiguredInsecure` (internal/session/cookie_test.go) |
| AC-008.14 | T-7, T-14 | `TestLookupFailsAfterIdleTimeout` (internal/session/session_test.go); `TestLookupSucceedsUntilAbsoluteExpiryDespiteRepeatedUse` (internal/session/session_test.go); `TestAuthenticate_ExpiredSession_RunsNextAndClearsCookie` (internal/auth/middleware_test.go) |
| AC-008.15 | T-7 | `TestIntegration_LogoutRevokesSession` (internal/auth/integration_test.go); `TestRevokeTokenInvalidatesSession` (internal/session/session_test.go) |
| AC-008.16 | T-7, T-16 | `TestHandleMeSessions_CurrentFlagsExactlyCallersSession` (internal/auth/handlers_test.go); `TestIntegration_OwnerDeletesSessionWithoutAffectingOthers` (internal/auth/integration_test.go); `TestSessionsListRendersNullClientIPAsNull` (internal/auth/handlers_test.go) |
| AC-008.17 | T-7, T-13 | `TestIntegration_SecondLoginRegeneratesSessionAndRevokesPrior` (internal/auth/integration_test.go); `TestLogIn_RevokesPriorSessionUnconditionally` (internal/auth/service_test.go) |
| AC-008.18 | T-14 | `TestRejectCrossSite` (internal/auth/middleware_test.go); `TestIntegration_CrossSiteLogoutRejected` (internal/auth/integration_test.go); `TestRunWiresCrossSiteRejectionAndReadiness` (cmd/service/main_integration_test.go); `TestRejectCrossSiteNavigation` (internal/auth/middleware_test.go); `TestHandleMeIdentitiesLinkStart_CrossSiteNavigation_Returns403` (internal/auth/handlers_account_test.go) |
| AC-008.19 | T-14 | `TestRejectCrossSite` (internal/auth/middleware_test.go); `TestRejectCrossSiteAlways` (internal/auth/middleware_test.go) |
| AC-008.20 | T-10 | `TestStartReturnsAuthorizationURLWithExpectedParameters` (internal/auth/oidc/oidc_test.go); `TestIntegration_UnknownUserProviderLoginGrantsSession` (internal/auth/integration_test.go) |
| AC-008.21 | T-10 | `TestFinishUnknownStateReturnsErrInvalidState` (internal/auth/oidc/oidc_test.go); `TestFinishReplayedStateReturnsErrInvalidState` (internal/auth/oidc/oidc_test.go); `TestConsumeAfterTTLReturnsNotFound` (internal/authflow/authflow_test.go); `TestRunSweepsExpiredCeremonyStateOnTheConfiguredInterval` (cmd/service/main_integration_test.go) |
| AC-008.22 | T-10 | `TestFinishRejectsInvalidTokens` (internal/auth/oidc/oidc_test.go); `TestFinishExpiredWithinSkewSucceeds` (internal/auth/oidc/oidc_test.go); `TestFinishRejectsIdentityTokenFromTheWrongIssuer` (internal/auth/criteria_integration_test.go) |
| AC-008.23 | T-11 | `TestBeginRegistrationPersistsFlowAndReturnsChallenge` (internal/auth/passkey/passkey_test.go); `TestFinishRegistrationOwnerCheckRunsBeforeTheSessionIsDecoded` (internal/auth/passkey/passkey_test.go); `TestPasskeyRegistrationCompletesWithAScriptedAuthenticator` (internal/auth/passkey_ceremony_integration_test.go) |
| AC-008.24 | T-11 | `TestBeginLoginReturnsNoAllowedCredentials` (internal/auth/passkey/passkey_test.go); `TestFinishLoginWithUnknownFlowReturnsErrVerification` (internal/auth/passkey/passkey_test.go); `TestPasskeyLoginAuthenticatesTheCredentialOwner` (internal/auth/passkey_ceremony_integration_test.go) |
| AC-008.25 | T-11 | `TestEvaluateSignCount` (internal/auth/passkey/passkey_test.go); `TestRecordUseAdvancesSignCountAndSetsCloneWarning` (internal/auth/passkey/credential_test.go); `TestPasskeyAssertionWithAStaleCounterIsRejectedAndFlagged` (internal/auth/passkey_ceremony_integration_test.go) |
| AC-008.26 | T-11, T-16 | `TestHandleMeCredentials_OwnershipIsolationAndListingScope` (internal/auth/handlers_test.go); `TestMeCredentialsRoutesExistWithPasskeysDisabled` (internal/auth/handlers_test.go) |
| AC-008.27 | T-4, T-12 | `TestIntegration_EnabledOTPStartIsIdenticalAndCodeIsSingleUse` (internal/auth/integration_test.go); `TestVerifyRejectsAnExpiredCode` (internal/auth/otp/otp_test.go); `TestVerifyRejectsTheSameCodeTwice` (internal/auth/otp/otp_test.go) |
| AC-008.28 | T-12 | `TestVerifyExhaustsAttemptsThenRejectsTheCorrectCode` (internal/auth/otp/otp_test.go) |
| AC-008.29 | T-16 | `TestHandleProviders_OTPDisabled_OmitsEntryAndOTPRoutesAnswer404` (internal/auth/handlers_test.go); `TestIntegration_DisabledOTPAnswersNotFound` (internal/auth/integration_test.go) |
| AC-008.30 | T-12 | `TestHandleOTPStart_IdenticalForKnownAndUnknown` (internal/auth/handlers_test.go); `TestRequestForKnownAndUnknownAddressAreIndistinguishable` (internal/auth/otp/otp_test.go) |
| AC-008.31 | T-3, T-9 | `TestSeedRolesAndPermissions` (internal/store/migrations/migrations_test.go); `TestPermissionsFor_Member` (internal/authz/checker_test.go); `TestSetRoles_Replaces` (internal/authz/checker_test.go) |
| AC-008.32 | T-9, T-15 | `TestRequirePermissionRejectsSimilarPrefixPermission` (internal/authz/middleware_test.go); `TestRequirePermissionRunsNextHandlerWhenSubjectHoldsPermission` (internal/authz/middleware_test.go) |
| AC-008.33 | T-1, T-15 | `TestRequirePermissionRejectsSubjectWithoutPermission` (internal/authz/middleware_test.go); `TestIntegration_MemberForbiddenFromAdminUsers` (internal/auth/integration_test.go) |
| AC-008.34 | T-1, T-14 | `TestRequireAuthentication_NoSubject_Returns401` (internal/auth/middleware_test.go); `TestIntegration_NoCookieRejectsMe` (internal/auth/integration_test.go) |
| AC-008.35 | T-16 | `TestHandleMeCredentials_OwnershipIsolationAndListingScope` (internal/auth/handlers_test.go); `TestHandleInvitesList_MemberSeesOwnAdminSeesAll` (internal/auth/handlers_invite_test.go); `TestIdentitiesForReturnsOnlyOwnIdentities` (internal/user/repository_test.go) |
| AC-008.36 | T-13, T-17 | `TestLogIn_BootstrapAdmin_RequiresVerifiedEmail` (internal/auth/service_test.go); `TestIntegration_BootstrapAdminBreaksSignupDeadlock` (internal/auth/integration_test.go); `TestBootstrapAccountCreatedAtSignupHoldsAdminAndIsMarked` (internal/auth/signup_test.go); `TestBootstrapListIgnoredWhileAnActiveAdminExists` (internal/auth/signup_test.go); `TestConcurrentFirstBootstrapSignupsGrantOneAdmin` (internal/auth/signup_test.go) |
| AC-008.37 | T-5 | `TestRateLimit_AuthRouteOverBurst_ReturnsExact429Body` (internal/auth/handlers_test.go); `TestIntegration_RateLimitAnswersExactBody` (internal/auth/integration_test.go); `TestAllowKeepsIndependentBucketsPerKey` (internal/ratelimit/ratelimit_test.go); `TestKeyForIP` (internal/ratelimit/ratelimit_test.go); `TestRateLimitedKeysIPv6ByPrefix` (internal/auth/handlers_test.go) |
| AC-008.38 | T-8 | `TestIntegration_AuditTrailRecordsExpectedRows` (internal/auth/integration_test.go); `TestHandleAdminUsersRoles_RecordsGrantedAndRevokedAuditRows` (internal/auth/handlers_test.go); `TestHandleMeSessionsDeleteAll_RecordsSessionRevokedAudit` (internal/auth/handlers_account_test.go); `TestRecordTxRollsBackWithTheTransaction` (internal/audit/audit_test.go); `TestFinishLoginUnknownCredentialReturnsNilOwnerWithErrVerification` (internal/auth/passkey/passkey_test.go); `TestHandleWebAuthnLoginFinish_UnknownCredentialAuditsAnonymousWebauthn` (internal/auth/handlers_test.go); `TestLogIn_SuspendedAccountFailureAuditsUserSubject` (internal/auth/service_test.go); `TestPasskeyAssertionWithAStaleCounterIsRejectedAndFlagged` (internal/auth/passkey_ceremony_integration_test.go) |
| AC-008.39 | T-8 | `TestIntegration_AuditTrailRecordsExpectedRows` (internal/auth/integration_test.go); `TestKnownActorStoresUserRef` (internal/audit/audit_test.go); `TestAnonymousActorRoundTrips` (internal/audit/audit_test.go); `TestIntegration_StateChangingRequestAuditRowCarriesAllFiveContractHFields` (internal/auth/criteria_integration_test.go); `TestValidateSubjectRestrictsKinds` (internal/audit/subject_test.go) |
| AC-008.40 | T-8, T-18 | `TestIntegration_NoDigestLeaksInSessionsOrLogs` (internal/auth/integration_test.go); `TestMiddleware_NeverLogsTokenOrCookieHeader` (internal/auth/middleware_test.go); `TestLoadedConfigJSONNeverContainsAPlaintextSecret` (internal/config/config_test.go); `TestDetail` (internal/audit/audit_test.go); `TestHandleInviteRedeem_ThroughNewMux_NeverLogsTheToken` (internal/auth/handlers_invite_test.go); `TestHandleInviteRedeem_RateLimited_NeverLogsTheToken` (internal/auth/handlers_invite_test.go) |
| AC-008.41 | T-18, T-21 | `TestConfigValidate` (internal/session/cookie_test.go); `TestLoadRejectsAHostCookieThatIsNotSecure` (internal/config/config_test.go) |
| AC-008.42 | T-1, T-13 | `TestHandleOTPVerify_SessionRotationAndReplay` (internal/auth/handlers_test.go); `TestWriteJSONErrorAuthCodes` (internal/server/errors_test.go); `TestHandleOTPVerify_SuspendedAccountAnswersIdenticallyToWrongCode` (internal/auth/criteria_integration_test.go) |
| AC-008.43 | T-23 | `TestHandleOIDCCallback_LinkSameSession_AttachesIdentityWithoutSessionCookie` (internal/auth/handlers_account_test.go); `TestFinishIdentityLink_IdentityOwnedByAnotherAccount_RefusesNothingLinked` (internal/auth/account_test.go) |
| AC-008.44 | T-23 | `TestRemoveCredential_LastFactor_Refuses` (internal/auth/account_test.go); `TestRemoveIdentity_LastFactor_Refuses` (internal/auth/account_test.go) |
| AC-008.45 | T-22 | `TestHandleMePatch_Success_UpdatesDisplayNameAndPersists` (internal/auth/handlers_account_test.go); `TestUpdateDisplayName_Success` (internal/auth/account_test.go) |
| AC-008.46 | T-22 | `TestDeleteAccount_Success_RevokesSessionsPreventsLoginRetainsRows` (internal/auth/account_test.go); `TestHandleMeDelete_Success_ClearsCookieAndSessionIsGone` (internal/auth/handlers_account_test.go) |
| AC-008.47 | T-22 | `TestSetStatus_Suspend_RevokesSessions` (internal/auth/account_test.go); `TestLogIn_SuspendedAccount_ReturnsErrSuspended` (internal/auth/service_test.go); `TestHandleAdminUsersStatus_Suspend_TargetCookieBecomesUnauthenticated` (internal/auth/handlers_account_test.go); `TestSetStatus_Reactivate_RecordsAudit` (internal/auth/account_test.go) |
| AC-008.48 | T-24 | `TestHandleAdminUsersSessions_InvalidatesTargetLeavesActorWorking` (internal/auth/handlers_account_test.go); `TestHandleMeSessionsDeleteAll_RevokesEverySessionAndClearsCookie` (internal/auth/handlers_account_test.go) |
| AC-008.49 | T-24 | `TestHandleAdminAudit_NewestFirstLimitAndCursor` (internal/auth/handlers_account_test.go); `TestListOrdersMostRecentFirstAndPagesByCursor` (internal/audit/audit_test.go); `TestListPagesAcrossEventsSharingATimestamp` (internal/audit/audit_test.go); `TestParseCursorRoundTripAndRejectsGarbage` (internal/audit/subject_test.go); `TestHandleAdminAudit_ExactlyFullLastPage_NextCursorIsNull` (internal/auth/handlers_account_test.go); `TestHandleAdminAudit_MalformedCursorBefore_ReturnsExact400Body` (internal/auth/handlers_account_test.go); `TestHandleAdminAudit_NullClientIP_RendersAsJSONNull` (internal/auth/handlers_account_test.go) |
| AC-008.50 | T-23 | `TestHandleAdminUsersRoles_LastAdmin_ReturnsExact409AndLeavesRoleUnchanged` (internal/auth/handlers_test.go); `TestSetStatus_LastAdmin_Refuses` (internal/auth/account_test.go); `TestDeleteAccount_LastAdmin_Refuses` (internal/auth/account_test.go); `TestConcurrentDemotionsOfTheLastTwoAdminsLeaveOne` (internal/auth/account_test.go) |
| AC-008.51 | T-25 | `TestPurgeExpired_RemovesExpiredLeavesInWindowAndSurvivesAsActorRef` (internal/auth/account_test.go); `TestPurgeDeletedBeforeRemovesRowDeletedBeforeCutoffAndCascades` (internal/user/repository_test.go); `TestRunSweepsImmediatelyAtStart` (internal/auth/sweeper_test.go) |
| AC-008.52 | T-23 | `TestRestoreAccount_WithinGracePeriod_Succeeds` (internal/auth/account_test.go); `TestRestoreAccount_OutsideGracePeriod_ReturnsErrGraceExpired` (internal/auth/account_test.go); `TestHandleAdminUsersStatus_ActiveOnDeletedWithinGrace_Restores` (internal/auth/handlers_account_test.go); `TestSetStatusAgainstDeletedTargetReturnsErrIsDeleted` (internal/user/repository_test.go); `TestSetStatusTxAgainstDeletedTargetReturnsErrIsDeleted` (internal/user/repository_test.go); `TestRestoreAgainstNonDeletedStatusReturnsFalse` (internal/user/repository_test.go); `TestHandleAdminUsersStatus_SuspendDeletedAccount_ReturnsExact409BodyAndLeavesDeleted` (internal/auth/handlers_account_test.go); `TestRestoreStillRevivesASelfDeletedAccount` (internal/user/repository_test.go) |
| AC-008.53 | T-26 | `TestIntegration_AuditSurvivesPurge` (internal/auth/integration_test.go); `TestActorIDNulledOnActorDeletionLeavesActorRefUnchanged` (internal/audit/audit_test.go) |
| AC-008.54 | T-29 | `TestAdmitAccount_InviteIgnoredForExistingIdentity` (internal/auth/signup_test.go); `TestLogIn_ExistingIdentity_IgnoresSignupPolicy` (internal/auth/signup_test.go) |
| AC-008.55 | T-29 | `TestAdmitAccount_SignupDisabled` (internal/auth/signup_test.go); `TestIntegration_SignupDisabledBlocksNewAccount` (internal/auth/integration_test.go) |
| AC-008.56 | T-29 | `TestAdmitAccount_InviteRequired_NoInviteCarried` (internal/auth/signup_test.go); `TestIntegration_InviteRequiredSignupRoundTrip` (internal/auth/integration_test.go) |
| AC-008.57 | T-29 | `TestAdmitAccount_InviteInvalid_Variants` (internal/auth/signup_test.go); `TestHandleInviteRedeem_DeadTokens_Redirect303WithErrorInviteInvalid` (internal/auth/handlers_invite_test.go); `TestLookupFailsIndistinguishablyForDeadTokens` (internal/invite/invite_test.go); `TestHandleInviteLanding_InfrastructureErrorIsNotJSON` (internal/auth/handlers_invite_test.go) |
| AC-008.58 | T-29 | `TestAdmitAccount_InviteEmailBinding` (internal/auth/signup_test.go); `TestIntegration_EmailBoundInviteEnforcesVerifiedMatch` (internal/auth/integration_test.go) |
| AC-008.59 | T-29 | `TestAdmitAccount_BootstrapExemption_BreaksDeadlock` (internal/auth/signup_test.go); `TestIntegration_BootstrapAdminBreaksSignupDeadlock` (internal/auth/integration_test.go) |
| AC-008.60 | T-29 | `TestAdmitAccount_SignupDisabled` (internal/auth/signup_test.go); `TestAdmitAccount_OrderedRules_SignupDisabledBeforeInviteRequired` (internal/auth/signup_test.go) |
| AC-008.61 | T-29 | `TestLoadTxSeesAnUpdateMadeEarlierInTheSameTransaction` (internal/settings/settings_test.go); `TestCreateWithIdentityTxInsertsRowsVisibleWithinCallerTransaction` (internal/user/repository_test.go); `TestLoadTxBlocksAPolicyChangeUntilTheTransactionEnds` (internal/settings/settings_test.go) |
| AC-008.62 | T-28 | `TestHandleInvitesCreate_Success_ReturnsTokenURLAndQRURL` (internal/auth/handlers_invite_test.go); `TestCreateRejectsMaxUsesAboveCeiling` (internal/invite/invite_test.go); `TestCreateWithZeroTTLUsesConfiguredDefault` (internal/invite/invite_test.go) |
| AC-008.63 | T-28 | `TestHandleInvitesCreate_Success_ReturnsTokenURLAndQRURL` (internal/auth/handlers_invite_test.go); `TestHandleInvitesGet_BodyExcludesTokenURLAndQRURL` (internal/auth/handlers_invite_test.go); `TestHandleInvitesGet_ShapeMatchesCreateWithoutSecrets` (internal/auth/handlers_invite_test.go) |
| AC-008.64 | T-28 | `TestCreateReturnsTokenLookupResolves` (internal/invite/invite_test.go) |
| AC-008.65 | T-28 | `TestRedeemTxConcurrentSingleUseSucceedsOnce` (internal/invite/invite_test.go); `TestRedeemTxMultiUseSucceedsExactlyMaxUsesTimes` (internal/invite/invite_test.go); `TestAdmitAccount_ConcurrentRedemption_SingleUseInvite_ConditionalUpdateSerializes` (internal/auth/signup_test.go) |
| AC-008.66 | T-28 | `TestCreateQuotaCountsOnlyLiveInvites` (internal/invite/invite_test.go); `TestHandleInvitesCreate_QuotaExhausted_ReturnsConflict` (internal/auth/handlers_invite_test.go); `TestCreateReadsQuotaInsideTransaction` (internal/invite/invite_test.go) |
| AC-008.67 | T-28 | `TestHandleInvitesList_MemberSeesOwnAdminSeesAll` (internal/auth/handlers_invite_test.go); `TestHandleInvitesDelete_AnotherMembersInvite_Returns404AndLeavesLive` (internal/auth/handlers_invite_test.go); `TestRevokeIsScopedToIssuer` (internal/invite/invite_test.go); `TestListWithMalformedCursorReturnsErrInvalidCursor` (internal/invite/invite_test.go); `TestHandleInvitesList_MalformedCursor_ReturnsExact400Body` (internal/auth/handlers_invite_test.go) |
| AC-008.68 | T-32 | `TestHandleInviteQR_MadeUpToken_Returns200ImagePNG` (internal/auth/handlers_invite_test.go); `TestIntegration_InviteQRPerformsNoDatabaseLookup` (internal/auth/integration_test.go) |
| AC-008.69 | T-28 | `TestAdmitAccount_ConcurrentRedemption_SingleUseInvite_ConditionalUpdateSerializes` (internal/auth/signup_test.go); `TestDeleteExpiredKeepsFullySpentInvites` (internal/invite/invite_test.go); `TestPurgeExpired_InviteAttributionSurvivesIssuerPurge` (internal/auth/criteria_integration_test.go) |
| AC-008.70 | T-30 | `TestVerifyReturnsTheInviteTheCodeWasRequestedWith` (internal/auth/otp/otp_test.go); `TestStartFinishRoundTripReturnsClaimsAndInvite` (internal/auth/oidc/oidc_test.go); `TestIntegration_InviteRequiredSignupRoundTrip` (internal/auth/integration_test.go) |
| AC-008.71 | T-31 | `TestAdmitAccount_RequireApproval` (internal/auth/signup_test.go); `TestIntegration_ApprovalQueueEndToEnd` (internal/auth/integration_test.go) |
| AC-008.72 | T-31 | `TestIntegration_ApprovalQueueEndToEnd` (internal/auth/integration_test.go); `TestHandleAdminUsersReject_ActiveAccount_ReturnsConflictNotPendingAndLeavesActive` (internal/auth/handlers_invite_test.go); `TestIntegration_UserWriteDoesNotGrantApproval` (internal/auth/integration_test.go) |
| AC-008.73 | T-31 | `TestHandleAdminUsersApprove_PendingAccount_Returns200AndAllowsLogin` (internal/auth/handlers_invite_test.go); `TestIntegration_ApprovalQueueEndToEnd` (internal/auth/integration_test.go) |
| AC-008.74 | T-27 | `TestHandleAdminSettingsPatch_Success_ChangesOneKeyLeavesRest` (internal/auth/handlers_invite_test.go); `TestApplyChangesOnlyTheNamedField` (internal/settings/settings_test.go); `TestIntegration_SignupDisabledBlocksNewAccount` (internal/auth/integration_test.go); `TestApplyRejectsDefaultTTLAboveInt32` (internal/settings/settings_test.go); `TestWarnIfSignupUnreachableUsesEffectiveSetting` (cmd/service/main_test.go) |
| AC-008.75 | T-27 | `TestIntegration_LockedSettingRefusesPatchButAllowsOthers` (internal/auth/integration_test.go); `TestOverrideLocksApplyAndLeavesOtherFieldsUnwritten` (internal/settings/settings_test.go) |
| AC-008.76 | T-27 | `TestHandleAdminSettingsPatch_RecordsExactlyOneAuditRowNamingActorAndChange` (internal/auth/criteria_integration_test.go) |
| AC-008.77 | T-33 | `TestMigration5AddsSessionCookieIssuedAt` (internal/store/migrations/migrations_test.go); `TestReissueCookieAfterAnHour` (internal/session/session_test.go); `TestReissueCookieMaxAgeCappedByAbsoluteExpiry` (internal/session/session_test.go); `TestReissueCookieConcurrentCallsWriteOnce` (internal/session/session_test.go); `TestAuthenticateReissuesCookieOnStaleSession` (internal/auth/middleware_test.go) |
| AC-008.78 | T-34 | `TestRejectSetsRejectedAt` (internal/user/repository_test.go); `TestRestoreRefusesARejectedAccount` (internal/user/repository_test.go); `TestPatchStatusActiveOnRejectedAccountIs409` (internal/auth/handlers_account_test.go); `TestPatchStatusSuspendedOnRejectedAccountIs409` (internal/auth/handlers_account_test.go) |
| AC-008.79 | T-35 | `TestMarkBootstrapAdminGrantedTxMarksOnceAndOnlyOnce` (internal/user/repository_test.go); `TestBootstrapAccountCreatedAtSignupHoldsAdminAndIsMarked` (internal/auth/signup_test.go); `TestBootstrapAdminIsNotRegrantedAfterDemotion` (internal/auth/signup_test.go); `TestExistingAccountAddedToBootstrapListIsNotGrantedAtLogin` (internal/auth/signup_test.go); `TestBootstrapListIgnoredWhileAnActiveAdminExists` (internal/auth/signup_test.go); `TestPurgedBootstrapAdminDoesNotRegainAdminOnReSignup` (internal/auth/signup_test.go) |
| AC-008.80 | T-36 | `TestApplyRejectsDefaultTTLAboveInviteMaxTTL` (internal/settings/settings_test.go); `TestDefaultAuthConfigInviteLimits` (internal/config/auth_test.go); `TestCreateRejectsTTLAboveMax` (internal/invite/invite_test.go); `TestCreateCapsDefaultTTLAtMax` (internal/invite/invite_test.go); `TestHandleInvitesCreate_TTLAboveMaxIs400` (internal/auth/handlers_invite_test.go) |
| AC-008.81 | T-37 | `TestLoadExposesInviteLimitsFromOptions` (internal/settings/settings_test.go); `TestDefaultAuthConfigInviteLimits` (internal/config/auth_test.go); `TestCreateUsesConfiguredDefaultMaxUses` (internal/invite/invite_test.go) |
| AC-008.82 | T-38 | `TestMigration6AddsOTPCodeBinding` (internal/store/migrations/migrations_test.go); `TestRequestFromAnotherBindingLeavesTheFirstCodeLive` (internal/auth/otp/otp_test.go); `TestRequestFromSameBindingInvalidatesEarlierCode` (internal/auth/otp/otp_test.go); `TestRequestWithoutInviteCarriesForwardTheOutstandingInvite` (internal/auth/otp/otp_test.go); `TestHandleOTPStart_SetsBindingCookie` (internal/auth/handlers_test.go); `TestHandleOTP_AttackerCannotStripVictimsInvite` (internal/auth/handlers_test.go) |
| AC-008.83 | T-39 | `TestVerifyFromAnotherBindingFailsWithoutCountingAnAttempt` (internal/auth/otp/otp_test.go); `TestHandleOTPVerify_WithoutBindingCookieIs401` (internal/auth/handlers_test.go) |
| AC-008.84 | T-33, T-40 | `TestAuthenticateSkipsSessionLookupForHealthProbes` (internal/auth/middleware_test.go); `TestReadinessFailsClosedWhenTheDatabaseBecomesUnreachable` (cmd/service/main_integration_test.go) |
| AC-008.85 | T-41 | `TestAuthConfigValidateRejectsNoAuthenticationMethod` (internal/config/auth_test.go) |
| AC-008.86 | T-42 | `TestHandleOIDCStart_DeadInviteContinuesWithoutInvite` (internal/auth/handlers_test.go) |
| AC-008.87 | T-43 | `TestInviteTokenNotLoggedOrTracedOnMatchedRoute` (internal/server/invite_redaction_test.go); `TestInviteTokenNotLoggedOrTracedOnUnmatchedMethod` (internal/server/invite_redaction_test.go); `TestInviteTokenNotLoggedOrTracedOnUnmatchedSubpath` (internal/server/invite_redaction_test.go); `TestInviteTokenNotLoggedOrTracedWhenShedBeforeTheMux` (internal/server/invite_redaction_test.go); `TestInviteTokenNotLoggedByCrossSiteRejection` (internal/auth/invite_redaction_test.go); `TestInviteTokenNotLoggedByPermissionDenial` (internal/authz/invite_redaction_test.go); `TestInviteLandingStillRoutesTheRealToken` (internal/server/invite_redaction_test.go) |
| AC-008.88 | T-44 | `TestDecideReportsFirstRefusalOnlyOnce` (internal/ratelimit/ratelimit_test.go); `TestDecideResetsFirstRefusalAfterAnAllow` (internal/ratelimit/ratelimit_test.go); `TestRateLimitedRecordsOneAuditEventPerRefusalRun` (internal/auth/handlers_test.go); `TestHandleOTPVerify_FirstRefusalAuditsEmailSubject` (internal/auth/handlers_test.go) |
| AC-008.89 | T-45 | `TestFinishAcceptsEmailVerifiedSentAsAString` (internal/auth/oidc/oidc_test.go) |
| AC-008.90 | T-46 | `TestHandleAdminUsersSessions_UnknownID_ReturnsExact404Body` (internal/auth/handlers_account_test.go); `TestHandleAdminUsersStatus_UnknownID_ReturnsExact404Body` (internal/auth/handlers_account_test.go); `TestHandleAdminUsersRoles_UnknownTarget_ReturnsExact404Body` (internal/auth/handlers_test.go) |
| AC-008.91 | T-47 | `TestSendDoesNotLogTheRecipientOnFailure`, `TestSendDoesNotLogTheRecipientOnSuccess` (internal/mail/send_log_test.go); `TestRequestDoesNotLogTheAddressWhenTheSenderFails` (internal/auth/otp/otp_test.go) |
| AC-008.92 | T-48 | `TestSweeperSweepOnce_RemovesExpiredLeavesLive` (internal/auth/sweeper_test.go); `TestSweeperSweepOnce_InviteRetainWindow` (internal/auth/sweeper_test.go); `TestDeleteExpiredKeepsRevokedInvites` (internal/invite/invite_test.go); `TestDeleteExpiredKeepsFullySpentInvites` (internal/invite/invite_test.go) |
| AC-008.93 | T-48 | `TestSweeperSweepOnce_SessionsCleanerFailureDoesNotStopOtherCleaners` (internal/auth/sweeper_test.go); `TestSweeperRun_FailingCleanerDoesNotStopTheLoop` (internal/auth/sweeper_test.go) |

Two tests support this pass without citing a criterion, per the testing standard's exception
for a test that constrains something other than the running service (a build-input mistake) or
pins a third party's documented behavior: `TestUTCNowIsUTC` (cmd/service/main_test.go) is a
build invariant, not service behavior. `TestOIDCBindingCookieMaxAgeFollowsFlowTTL`
(internal/auth/handlers_test.go) asserts the OIDC binding cookie's `Max-Age` tracks the
configured flow TTL; `AC-008.21` governs rejecting an unknown, expired, or already-used state
value at the callback, not the binding cookie's lifetime at the start route, so this test
supports the design's ceremony-window reasoning without being a citation for AC-008.21 or any
other existing criterion.

## Deferred

Every criterion is now observed by at least one test; there is nothing left in this section.
`AC-008.23` through `AC-008.25` are observed by the scripted WebAuthn authenticator in
`internal/auth/passkey_ceremony_integration_test.go`, and `AC-008.61` is observed by
`TestLoadTxBlocksAPolicyChangeUntilTheTransactionEnds` (`internal/settings/settings_test.go`),
which shows the signup policy read holds a lock until the account-creation transaction ends.
`requirements.md` now carries `status: implemented`.

Also out of this spec's scope, recorded here so it is not lost:

- The readiness endpoint's behavior when the database is unavailable is implemented and tested
  but has no criterion in this spec. It belongs to spec 005's readiness criteria, or to a new
  criterion here if the database check is considered part of this feature.
- Audit log paging uses a strict timestamp cursor, so rows that share the boundary timestamp
  can be skipped between pages. `AC-008.49` does not address paging; this is a defect to fix
  with a compound cursor, not a criterion change.
- Authentication metrics are a possible follow-up: sign-in attempts per method and outcome,
  and the rule that refused each blocked signup (design.md's Contract M).
  Today these are visible only in the audit log and request logs. This needs criteria before
  any code, and the metric names must stay on the administrative listener like every other
  metric.

## Deferred follow-ups

| Finding | Where | Why deferred | Would touch |
| --- | --- | --- | --- |
| D-48 | internal/auth/otp/otp.go:129 | recorded: kept synchronous by decision P6; no account-existence leak | internal/auth/otp/otp.go |
| SR-1 | OTP guess budget (accepted): internal/auth/handlers.go:773 keys the verify limiter per (address, binding) (`otp-verify:` Decide call), and internal/auth/otp/otp.go:217-221 (Request's invalidateOutstanding) invalidates only same-binding codes | accepted by decision: 8-digit codes (10^8), about 2 years to a 50% chance at defaults, the victim receives every code by email; capping live codes across bindings would contradict AC-008.82 | internal/auth/handlers.go, internal/auth/otp/otp.go |
| SR-2 | OTP start lockout (pre-existing): internal/auth/handlers.go:705 keys the start limiter per address only (`otp-start:`), so anyone can spend a victim's start allowance and block their code requests | recorded by decision: any per-address limit can be spent by strangers, a stranger-triggered code is bound to the stranger's browser so it cannot help the victim, and per-requester keys raise the guess budget; passkey and provider sign-in are unaffected | internal/auth/handlers.go |
| SR-3 | Default invite max uses above the limit: internal/invite/invite.go:648-655 (resolveMaxUses) and internal/settings/settings.go:251 | not a security finding; misconfiguration fails closed: SERVICE_AUTH_INVITE_DEFAULT_MAX_USES above invite_max_uses_limit makes every invite created without max_uses fail with ErrMaxUsesTooHigh, and neither startup nor Apply checks default <= limit, so an admin can lower the limit below the default | internal/invite/invite.go, internal/settings/settings.go |
| SR-4 | Stored default TTL above a lowered ceiling: internal/invite/invite.go:669-677 (resolveTTL) | not a security finding; capping keeps the ceiling: a stored default TTL above a later-lowered invite max TTL is silently capped rather than rejected, though the PATCH path does reject (internal/settings/settings.go:274-281) | internal/invite/invite.go |
| SR-5 | ttl_secs overflow: internal/auth/handlers_invite.go:131 | not a security finding; the result is still bounded by the ceiling or default: `time.Duration(req.TTLSecs)*time.Second` overflows for very large ttl_secs, and a value that wraps negative silently takes the default instead of a 400 | internal/auth/handlers_invite.go |
| SR-6 | Audit rows dropped for an empty email: internal/auth/handlers.go:776 and :788 | not a security finding; gap in AC-008.38 / AC-008.88 coverage for malformed input: an empty email yields audit subject "email:", which validateSubject (internal/audit/audit.go:294) rejects, so auth.rate_limited and otp.completed failure rows are dropped and only logged | internal/auth/handlers.go |
| SR-7 | Doc comment claims the carried invite comes from the newest invalidated row: internal/auth/otp/otp.go:205-217 (comment) vs. :218-221 (`UPDATE ... RETURNING` with no `ORDER BY`) | not a security finding; comment accuracy | internal/auth/otp/otp.go |
| SR-8 | OIDC provider key `email` not reserved: internal/config/auth.go:222 (`LoadProviders` loop has no check against `otp.Provider`), internal/auth/otp/otp.go:25 | hardening; requires operator misconfiguration: a provider keyed `email` would share the identity namespace with the email-code path | internal/config/auth.go, internal/auth/otp/otp.go |
| SR-9 | Pending-approval refusal writes no audit row: internal/auth/signup.go:257 (the `ErrApprovalPending` return) and internal/auth/handlers.go:815-820 (handleOTPVerify's LogIn failure branch) write no audit call, unlike design.md's step 9 (design.md:742-746), which describes the login flow recording its own completed action with outcome=failure, detail naming "pending approval" | pre-existing; not a security finding | internal/auth/signup.go, internal/auth/handlers.go |
| SR-10 | Rejection is final per account only: a rejected user can apply again with a different identity, creating a new pending account that approval still gates (AC-008.78, requirements.md:313) | consistent with AC-008.78 as written; approval still gates the new account | internal/user/repository.go, internal/auth/signup.go |
