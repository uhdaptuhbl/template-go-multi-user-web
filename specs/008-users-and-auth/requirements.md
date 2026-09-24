---
feature: 008-users-and-auth
created: 2026-09-22
updated: 2026-09-24
status: implemented
---

# Requirements: Users and authentication

`status` is one of `draft`, `approved`, `implemented`, `unverified`, `superseded`; see the
feature lifecycle in `CLAUDE.md`.

## Problem

The service has no notion of a user today. Every request is anonymous, nothing distinguishes
one caller from another, and nothing can be restricted to the person who created it. That
blocks any feature that needs to remember who did something or to show one person only their
own data.

Building that notion piecemeal, inside whichever feature first needs it, produces a second and
third identity model the day a second and third feature need one too, each with its own idea of
what a session is, how long it lasts, and who is allowed to do what. This feature is the one
place identity, authentication, sessions, and authorization get decided, so later features
consume a settled answer instead of inventing their own.

The people this affects most directly are whoever operates the deployment and whoever is
allowed to sign up: an operator with no way to control who can create an account today has no
choice but to leave the service open to anyone who can reach it, or to not deploy the feature
that needs identity at all.

## Goal

Once this ships, a person can create an account by signing in through an identity provider or an
emailed one-time code, and can then register a passkey to sign in with later; the service
remembers who they are across requests with a session that can be listed and revoked; every
request that touches another user's data is checked against a permission rather than trusted on
its face; and an operator can choose whether signup is open, invite-only, or subject to manual
approval, and can administer accounts, roles, and invites once it is running.

## Non-goals

This feature does not decide what any other feature does with a signed-in user's identity. It
provides the identity, the session, and the permission check; what a route requires and what it
does with the result is that route's own concern.

This feature does not implement a password-based login path. The supported ways to prove
identity are an external identity provider, a passkey, and an emailed one-time code; a
service-issued password is out of scope.

This feature does not build an end-user-facing account recovery flow beyond what the supported
authentication methods already provide (an alternate provider, an alternate passkey, or a new
email code). There is no "forgot password" flow, because there is no password.

This feature does not change how the service handles any request that does not authenticate.
Existing unauthenticated behavior is unaffected except where a route is deliberately gated
behind the permission checks this feature introduces.

## User stories

### Story 1: Persistence

As an operator, I want every account, credential, session, and audit record kept in a durable
store that the service refuses to run without, so that identity and authorization decisions
survive a restart and are never silently backed by memory that a redeploy would erase.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.1`: The system SHALL persist user accounts, external identities, credentials,
  sessions, roles, permissions, and audit events in a SQL database.
- `AC-008.2`: IF the configured database connection string does not name a reachable PostgreSQL
  server, THEN the system SHALL fail startup and SHALL NOT fall back to another store.
- `AC-008.3`: WHEN the process starts and automatic migration is enabled, the system SHALL apply
  every pending migration before accepting requests.
- `AC-008.4`: IF a migration fails, THEN the system SHALL stop the process and report the
  migration that failed.
- `AC-008.5`: IF the database is unreachable at startup, THEN the system SHALL stop the process
  rather than serve traffic.
- `AC-008.84`: WHILE the database is unreachable, the system SHALL answer the readiness probe
  with 503.
- `AC-008.85`: IF no authentication method is enabled, THEN the system SHALL refuse to start
  and SHALL name the variables that enable one.
- `AC-008.92`: The system SHALL periodically remove expired sessions, expired sign-in
  ceremonies, and expired email codes, and invites that expired longer ago than the
  configured retention, except an invite that was revoked or fully redeemed.
- `AC-008.93`: IF removing one kind of expired record fails, THEN the system SHALL still
  remove the other kinds, and SHALL try again at the next removal.

### Story 2: Identity

As a user, I want the service to recognize me by a stable internal identity rather than by
whichever email address I happened to sign in with, so that changing my email, or signing in
through a second provider, does not fracture my account or silently merge me into someone
else's.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.6`: The system SHALL identify an account by an internal identifier and SHALL NOT treat
  an email address as an identity key.
- `AC-008.7`: The system SHALL treat each external identity as a unique pairing of provider and
  provider-issued subject.
- `AC-008.8`: WHEN authentication succeeds for a provider and subject pairing that is not yet
  known, the system SHALL create an account and link that identity to it.
- `AC-008.9`: IF authentication presents an email address that matches an existing account but
  was not verified by its issuer, THEN the system SHALL NOT link the identity to that account.
  Rationale: an unverified email is a claim the issuer itself would not vouch for, so honoring
  it would let an attacker attach their own login to a victim's account by simply asserting the
  victim's address.
- `AC-008.10`: WHILE a user is authenticated, the system SHALL allow an additional identity to
  be linked to that user's account.

### Story 3: Sessions

As a user, I want a session that survives across requests, can be inspected and ended from
wherever I signed in, and cannot be reused by anyone who steals a copy of the underlying value,
so that being signed in is convenient without being a standing risk.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.11`: WHEN authentication succeeds, the system SHALL issue a session token of at least
  256 bits of entropy drawn from a cryptographically secure source, carried in a cookie.
- `AC-008.12`: The system SHALL persist only a cryptographic digest of a session token and SHALL
  NOT persist the token itself.
- `AC-008.13`: The system SHALL mark the session cookie HttpOnly, SameSite=Lax, and Path=/, and
  WHERE secure cookies are enabled SHALL also mark it Secure.
- `AC-008.14`: IF a session has passed either its idle expiry or its absolute expiry, THEN the
  system SHALL treat the request as unauthenticated.
- `AC-008.15`: WHEN a user logs out, the system SHALL discard the session so the same token is
  no longer accepted.
- `AC-008.16`: The system SHALL allow a user to list and to revoke their own sessions.
- `AC-008.17`: WHEN authentication succeeds on a request that already carried a session, the
  system SHALL issue a new session identifier and discard the previous session.
- `AC-008.77`: WHEN an authenticated request arrives more than one hour after its session
  cookie was last issued, the system SHALL issue the cookie again with a lifetime equal to the
  shorter of the idle timeout and the time left before the session's absolute expiry.
  Rationale: a cookie whose lifetime is only the idle timeout, issued once at login, expires in
  the browser while the server-side session is still valid, so an active user is signed out
  long before the absolute lifetime is reached.
- `AC-008.18`: IF a state-changing request carries a session cookie and its Sec-Fetch-Site or
  Origin header indicates another site, THEN the system SHALL reject the request.
- `AC-008.19`: IF a state-changing request carries a session cookie and carries neither a
  Sec-Fetch-Site nor an Origin header, THEN the system SHALL reject the request.
  Rationale: a same-site browser request reliably sends one of these headers, so their joint
  absence on a cookie-bearing request is itself the signature of a forged cross-site request
  rather than a legitimate client to accommodate.

### Story 4: Authentication by identity provider

As a user, I want to sign in through an external identity provider using a flow that cannot be
replayed or intercepted, so that I can use an account I already have without trusting this
service with a password.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.20`: WHEN a provider login begins, the system SHALL use the authorization code flow
  with a proof key for code exchange, a single-use state value, and a nonce.
- `AC-008.21`: IF a provider callback presents a state value that is unknown, expired, or
  already used, THEN the system SHALL reject the login.
- `AC-008.22`: IF a provider's identity token fails signature, issuer, audience, expiry, or
  nonce validation, THEN the system SHALL reject the login.
- `AC-008.89`: WHEN a provider reports whether an email address is verified as the string
  `true` or `false` rather than a boolean, the system SHALL treat it as the matching boolean.

### Story 5: Authentication by passkey

As a user, I want to register and sign in with a passkey, so that I can authenticate without a
password and with protection against a cloned credential.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.23`: WHERE passkeys are enabled, the system SHALL allow an authenticated user to
  register a passkey.
- `AC-008.24`: WHEN a passkey assertion verifies, the system SHALL authenticate the account that
  owns the credential.
- `AC-008.25`: IF a passkey assertion presents a signature counter that has not advanced, THEN
  the system SHALL reject it and SHALL record that the credential may be cloned.
- `AC-008.26`: The system SHALL allow a user to list and to remove their own passkeys.

### Story 6: Authentication by email code

As a user without a passkey or a supported provider account, I want to sign in with a one-time
code sent to my email, so that I still have a way in without a password.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.27`: WHERE email codes are enabled, the system SHALL send a single-use code to the
  supplied address and SHALL accept that code once, within its configured lifetime.
- `AC-008.28`: IF an email code is presented incorrectly as many times as the configured
  maximum, THEN the system SHALL invalidate it.
- `AC-008.29`: WHERE email codes are disabled, the system SHALL NOT expose their endpoints.
- `AC-008.30`: The system SHALL respond to an email code request identically whether or not the
  address belongs to an existing account.
  Rationale: a response that varies by account existence lets anyone enumerate which email
  addresses have accounts, without needing to guess a code at all.
- `AC-008.82`: WHEN an email code is requested, the system SHALL bind the code to the browser
  that requested it, and SHALL invalidate only earlier codes that the same browser requested
  for the same address.
- `AC-008.83`: IF an email code is presented by a browser other than the one that requested
  it, THEN the system SHALL reject it as an authentication failure and SHALL NOT count it
  against any code's attempts.
  Rationale: codes shared per address let anyone who knows an address burn its live code,
  strip the invite it carries, and drain its verification limit; binding a code to its
  requesting browser confines those effects to the requester's own codes.

### Story 7: Authorization

As an operator, I want every request checked against a specific permission rather than a role
name, and every response about a user's own data scoped to that user, so that granting someone a
narrow role cannot accidentally hand them access a broader one was meant to guard.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.31`: The system SHALL grant permissions to roles and roles to users.
- `AC-008.32`: The system SHALL authorize a request by permission and SHALL NOT authorize it by
  role name.
- `AC-008.33`: IF an authenticated request lacks the permission a route requires, THEN the
  system SHALL reject it as forbidden.
- `AC-008.34`: IF an unauthenticated request reaches a route that requires authentication, THEN
  the system SHALL reject it as unauthenticated.
- `AC-008.35`: The system SHALL restrict every response describing a user-owned resource to
  resources owned by the requesting user, unless the request carries a permission that widens
  it.
  Rationale: without an explicit-widening rule, a resource-listing endpoint defaults to leaking
  every user's data to every authenticated caller the moment ownership scoping is forgotten on
  one route.
- `AC-008.36`: WHEN an account whose verified email address appears in the configured bootstrap
  administrator list is created while no active account holds the administrator role, the
  system SHALL grant it the administrator role.
- `AC-008.79`: WHEN an account has once received the administrator role through the bootstrap
  administrator list, the system SHALL NOT grant it that role through the list again. IF an
  active account holds the administrator role when an account is created, THEN the system
  SHALL NOT exempt that account from the admission rules or grant it the administrator role
  through the list.
  Rationale: otherwise demoting a bootstrap administrator lasts only until their next login,
  and an operator must also edit the environment to make a demotion stick. The list exists to
  create the first administrator; once one exists, further administrators are granted by an
  administrator.

### Story 8: Rate limiting

As an operator, I want authentication requests rate-limited per client, so that a single client
cannot exhaust login attempts, email codes, or provider callbacks by brute force.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.37`: The system SHALL limit the rate of authentication requests per client address and
  SHALL reject requests above that rate.

### Story 9: Audit

As an operator, I want every authentication attempt, session revocation, and role change
recorded with who did it and what happened, so that I can reconstruct what occurred after an
incident.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.38`: The system SHALL record an audit event for every authentication attempt the
  rate limit admits, every session revocation, and every role change.
- `AC-008.39`: Each audit event SHALL carry the request identifier, the client address, the
  acting account where one is known, the action, and the outcome.

### Story 10: Secrecy

As an operator, I want secrets that would let someone impersonate a user or the service itself
kept out of logs and audit records, and out of any misconfiguration that would send them over an
insecure channel, so that a log leak or a review of the audit trail cannot itself become a
credential leak.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.40`: The system SHALL NOT write a session token, an email code, a provider client
  secret, or a mail password to any log or audit record.
- `AC-008.87`: The system SHALL NOT write an invite token to any log, audit record, or trace
  attribute, whatever the outcome of the request that carried it.
- `AC-008.91`: The system SHALL NOT write the address an email is sent to into any log,
  whether or not the send succeeds.
- `AC-008.88`: WHEN a client first exceeds an authentication rate limit, the system SHALL
  record one audit event, and SHALL NOT record another for that client and limit until a
  request from it has been admitted again.
- `AC-008.41`: IF the session cookie name carries the __Host- prefix while secure cookies are
  disabled, THEN the system SHALL fail configuration validation at startup.
- `AC-008.42`: IF authentication fails, THEN the system SHALL return the same response
  regardless of whether the account exists, the credential is wrong, or the account is
  suspended.
  Rationale: a response that distinguishes these cases turns the login endpoint into an oracle
  for which email addresses have accounts and which of those are suspended.

### Story 11: Account management

As a user, I want to manage my own display name, my linked identities, and my own deletion, and
as an administrator I want to suspend, reactivate, and audit any account without ever being able
to leave the service with no administrator at all, so that account lifecycle is self-service
where it can be and recoverable where it can't.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.43`: The system SHALL allow an authenticated account to attach an additional external
  identity to itself, and SHALL attach it only to the account that is signed in.
- `AC-008.44`: IF removing a credential or an external identity would leave an account with no
  usable authentication method, THEN the system SHALL refuse the removal.
  Rationale: an account with no remaining way to authenticate is permanently locked out, which
  is a self-inflicted denial of service the system can prevent at the moment of removal.
- `AC-008.45`: The system SHALL allow an account to change its own display name.
- `AC-008.46`: The system SHALL allow an account to delete itself. WHEN it does, the system
  SHALL revoke every session it holds and SHALL prevent it from authenticating, while retaining
  its record until the configured grace period elapses.
- `AC-008.47`: The system SHALL allow a permitted administrator to suspend and to reactivate any
  account, and a suspended account SHALL NOT authenticate.
- `AC-008.48`: The system SHALL allow a permitted administrator to revoke every session
  belonging to another account, and SHALL allow an account to revoke every session of its own.
- `AC-008.90`: IF an administrator's action on an account names an account that does not
  exist, THEN the system SHALL answer that it was not found and SHALL change nothing.
- `AC-008.49`: The system SHALL allow a permitted administrator to read the audit log, most
  recent first.
- `AC-008.50`: IF an action would leave no active account holding the administrator role, THEN
  the system SHALL refuse that action, whether it is a role change, a suspension, or a
  self-deletion.
  Rationale: an administrator role that can be dropped to zero holders removes anyone's ability
  to reverse the mistake, whereas refusing the last removal costs nothing when it was
  unintentional and can still be done deliberately by first granting the role elsewhere.
- `AC-008.51`: WHEN a deleted account has been deleted for longer than the configured grace
  period, the system SHALL permanently remove it and its identities, credentials, and sessions.
- `AC-008.52`: WHILE a deleted account is within its grace period, the system SHALL allow a
  permitted administrator to restore it, and SHALL refuse restoration afterwards.
- `AC-008.78`: IF an account was rejected while awaiting approval, THEN the system SHALL
  refuse to restore it or to change its status.
  Rationale: rejection shares the deleted state so the sweeper can purge it, and without this
  rule the restore path would admit a rejected signup without anyone approving it.
- `AC-008.53`: The system SHALL retain each audit event's acting-account reference after that
  account is permanently removed.
  Rationale: the audit trail exists to answer "who did this" after the fact, and a reference
  that disappears along with the account it names defeats that purpose for exactly the accounts
  most likely to be the subject of a later investigation.

### Story 12: Signup admission

As an operator, I want to control whether authenticating with an unrecognized identity is
allowed to create a new account, and to have that decision made consistently at the one moment
it matters, so that the service can run open, invite-only, or fully closed to new signups.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.54`: The system SHALL decide whether an authentication that matches no known identity
  may create an account, and SHALL make that decision only at account creation.
- `AC-008.55`: WHERE self-service signup is disabled, the system SHALL refuse to create an
  account and SHALL NOT issue a session.
- `AC-008.56`: WHERE an invite is required, IF a signup presents no valid invite, THEN the
  system SHALL refuse to create an account.
- `AC-008.57`: IF an invite is unknown, expired, revoked, or has reached its redemption limit,
  THEN the system SHALL refuse to redeem it and SHALL NOT distinguish those cases in its
  response.
  Rationale: distinguishing these cases in the response tells an attacker which invite tokens
  exist and which have merely expired or been used up, information a refusal alone does not
  need to give away.
- `AC-008.58`: IF an invite is bound to an email address, THEN the system SHALL redeem it only
  for a signup whose issuer verified that same address.
  Rationale: an email-bound invite is meant to admit one specific person; redeeming it for an
  unverified or different address defeats the binding and lets the invite be handed off to
  whoever intercepts it.
- `AC-008.59`: WHEN a signup presents a verified email address that appears in the configured
  bootstrap administrator list while no active account holds the administrator role, the
  system SHALL admit it regardless of the signup policy.
  Rationale: the bootstrap administrator list exists precisely to guarantee an operator can get
  an administrator account onto a freshly deployed, otherwise closed instance, so it must bypass
  the same policy it would otherwise be blocked by.
- `AC-008.60`: WHEN the system refuses to create an account, it SHALL record an audit event
  naming which rule refused.
- `AC-008.61`: The system SHALL evaluate the signup policy within the same transaction that
  creates the account.
  Rationale: evaluating the policy outside the account-creation transaction opens a window in
  which two concurrent signups, or a policy change mid-request, could both pass the check before
  either account exists, admitting more accounts than the policy allows.
- `AC-008.86`: IF a sign-in begins with an invite that is unknown, expired, revoked, or
  spent, THEN the system SHALL continue the sign-in without that invite, so that the signup
  policy alone decides whether an account may be created.

### Story 13: Invites

As a user permitted to invite others, I want to issue a single-use or multi-use invite bound to
an email or open to any holder, and to see and revoke what I've issued, so that I can extend
access to specific people without an administrator doing it for me.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.62`: The system SHALL allow a permitted account to issue an invite that is either
  bound to one email address or redeemable by any holder, carrying a redemption limit and an
  expiry.
- `AC-008.63`: The system SHALL disclose an invite's token exactly once, when it is issued, and
  SHALL NOT disclose it in any later response.
  Rationale: an invite token is a bearer credential for creating an account; showing it again
  later would let anyone who can read that later response redeem the invite, not just the
  person it was issued to.
- `AC-008.64`: The system SHALL persist only a cryptographic digest of an invite token and SHALL
  NOT persist the token itself.
- `AC-008.65`: The system SHALL NOT allow an invite to be redeemed more times than its
  redemption limit, including under concurrent redemption.
- `AC-008.66`: The system SHALL limit how many invites an account may have outstanding by a
  configurable quota, and SHALL refuse issuance beyond it.
- `AC-008.67`: The system SHALL allow an account to list and revoke the invites it issued, and
  SHALL allow a permitted administrator to list and revoke any invite.
- `AC-008.68`: The system SHALL provide a scannable image encoding an invite's redemption URL.
- `AC-008.69`: The system SHALL record which invite admitted each account, and SHALL retain that
  attribution after the issuing account is permanently removed.
- `AC-008.80`: IF an invite is requested with a lifetime longer than the configured maximum
  invite lifetime, or the default invite lifetime is set longer than that maximum, THEN the
  system SHALL reject the request as invalid.
- `AC-008.81`: WHEN an invite is issued without a redemption limit, the system SHALL give it
  the configured default redemption limit.
- `AC-008.70`: The system SHALL carry an invite through a login ceremony in server-side state and
  SHALL NOT carry it in a cookie.
  Rationale: a login ceremony can span a redirect to and back from an external provider, during
  which a cookie is the kind of value a cross-site or man-in-the-middle actor could read or
  substitute; server-side state keyed to the ceremony avoids exposing the invite on that path.

### Story 14: Approval

As an operator running an approval-gated deployment, I want a newly signed-up account held
inactive until an administrator approves it, so that admission is a deliberate decision rather
than automatic the moment someone completes a signup.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.71`: WHERE approval is required, WHEN a signup is admitted, the system SHALL create
  the account in a state that cannot authenticate and SHALL NOT issue a session.
- `AC-008.72`: The system SHALL allow a permitted administrator to list accounts awaiting
  approval and to approve or reject each of them.
- `AC-008.73`: WHEN an account awaiting approval is approved, the system SHALL allow it to
  authenticate on its next attempt.

### Story 15: Runtime policy

As an operator, I want to change the signup policy while the service is running, except where
I've locked a value from the environment on purpose, so that I can tighten or loosen admission
without a restart while still being able to pin a setting that must not drift.

**Acceptance criteria** (EARS notation, IDs stable for the life of the feature):

- `AC-008.74`: The system SHALL allow a permitted administrator to read and change the signup
  policy while running, and the change SHALL take effect without restarting the process.
- `AC-008.75`: WHERE a signup policy value is overridden by the environment, the system SHALL
  refuse to change it and SHALL report that it is locked.
  Rationale: an environment-set value represents a deliberate deployment-time decision; letting
  a runtime change silently override it would make the environment configuration a lie about
  what the running service actually does.
- `AC-008.76`: The system SHALL record an audit event for every change to the signup policy,
  naming the acting account.

## Constraints

- Session tokens, email codes, invite tokens, and passkey challenges are generated from a
  cryptographically secure random source; no criterion in this document permits a
  non-cryptographic generator for any of them.
- Every timestamp compared against an expiry (session, invite, email code, provider state) uses
  a single injected clock, so tests can control time deterministically per this project's
  testing standards.
- This feature does not set a numeric latency or throughput budget of its own; authentication
  and session checks execute on every gated request, so their cost is bounded by the same
  operational limits as the rest of the service rather than by a separate figure here.

## Verification status

Every criterion has now been observed to hold at least once. The criteria below were the last
to be observed, after the first close-out, and each names the test that observed it:

- `AC-008.3`: `TestRunAppliesEveryPendingMigrationBeforeAcceptingRequests`
  (`cmd/service/main_integration_test.go`), against a schema
  `storetest.NewUnmigratedPool` leaves unmigrated.
- `AC-008.4`: `TestRunFailingMigrationStopsTheProcessAndNamesIt`
  (`cmd/service/main_integration_test.go`), against a schema with a `users` table
  pre-created in a shape that collides with the first migration.
- `AC-008.22`: `TestFinishRejectsIdentityTokenFromTheWrongIssuer`
  (`internal/auth/criteria_integration_test.go`).
- `AC-008.39`: `TestIntegration_StateChangingRequestAuditRowCarriesAllFiveContractHFields`
  (`internal/auth/criteria_integration_test.go`).
- `AC-008.42`: `TestHandleOTPVerify_SuspendedAccountAnswersIdenticallyToWrongCode`
  (`internal/auth/criteria_integration_test.go`).
- `AC-008.69`: `TestPurgeExpired_InviteAttributionSurvivesIssuerPurge`
  (`internal/auth/criteria_integration_test.go`).
- `AC-008.76`: `TestHandleAdminSettingsPatch_RecordsExactlyOneAuditRowNamingActorAndChange`
  (`internal/auth/criteria_integration_test.go`).
- `AC-008.23` through `AC-008.25`: `TestPasskeyRegistrationCompletesWithAScriptedAuthenticator`,
  `TestPasskeyLoginAuthenticatesTheCredentialOwner`, and
  `TestPasskeyAssertionWithAStaleCounterIsRejectedAndFlagged`
  (`internal/auth/passkey_ceremony_integration_test.go`), driving a full registration and login
  ceremony, including a stale-counter assertion, with a scripted WebAuthn authenticator.
- `AC-008.61`: `TestLoadTxBlocksAPolicyChangeUntilTheTransactionEnds`
  (`internal/settings/settings_test.go`), showing the signup policy read holds a lock until the
  account-creation transaction ends.

## Open questions

None.

## Change log

Amendments after approval, newest first.

- `2026-09-24`: `AC-008.92` and `AC-008.93` added. A sweep of the test suite found that the
  sweeper's removal of expired records had tests but no criterion, so nothing required the
  behavior they checked. The criteria state what those tests already verified; no code
  changed.
- `2026-09-24`: `AC-008.91` added. Every outbound email logged its recipient address, and
  a failed email code logged it a second time. An address is personal data, and the
  subject or the failure's cause is enough to diagnose delivery. Neither log line now
  carries the address, and the mail failure line now carries the error it was missing.
- `2026-09-24`: `AC-008.90` added. Changing an unknown account's status or roles already
  answered 404, but revoking its sessions answered 204, so a mistyped id looked like a
  successful revocation. All three now answer 404.
- `2026-09-24`: `AC-008.89` added. OpenID Connect Core defines `email_verified` as a boolean,
  but some providers send it as a string, and decoding one failed every login through that
  provider.
- `2026-09-24`: `AC-008.28` reworded from "more times than the configured maximum" to "as
  many times as the configured maximum". The shipped behavior, which the criterion's test
  pins, invalidates a code on the wrong guess that reaches the maximum, so a code allows at
  most that many guesses in total; the old wording implied one guess more. Behavior is
  unchanged. Status remains `implemented`.
- `2026-09-24`: `AC-008.36`, `AC-008.59`, and `AC-008.79` amended: the bootstrap
  administrator list applies only while no active administrator exists, so a demoted
  bootstrap administrator cannot regain the role by deleting their account and signing up
  again after it is purged. Status remains `implemented`.
- `2026-09-24`: Verification complete. `AC-008.23` through `AC-008.25` observed with a
  scripted WebAuthn authenticator, and `AC-008.61` observed by a test showing the signup
  policy read holds a lock until the account-creation transaction ends. Status set to
  `implemented`. No criterion was changed.
- `2026-09-23`: Follow-up amendments. `AC-008.38` now counts only attempts the rate limit
  admits, because auditing every refused request would let a flood write one audit row per
  request; `AC-008.88` records the first refusal instead. Added `AC-008.77` through
  `AC-008.88` for the session cookie re-issue, rejected-account finality, one-time bootstrap
  grant, invite lifetime ceiling and default redemption limit, browser-bound email codes,
  readiness, the no-authentication-method startup check, dead invites at sign-in start,
  invite-token redaction, and rate-limit auditing.
- `2026-09-23`: Verification status updated. `internal/store/storetest` gained
  `NewUnmigratedPool`, an exported entry point that returns a fresh, uniquely schemad
  configuration without applying migrations, closing the gap the earlier entry named for
  `AC-008.3` and `AC-008.4`. `AC-008.3` and `AC-008.4` are now observed and moved out of the
  not-yet-observed list. `AC-008.23` through `AC-008.25` and `AC-008.61` remain unobserved,
  unchanged. Status remains `unverified`. No criterion was changed.
- `2026-09-23`: Verification status updated. `AC-008.22`, `AC-008.39`, `AC-008.42`, `AC-008.69`,
  and `AC-008.76` are now observed and moved out of the not-yet-observed list. `AC-008.3` and
  `AC-008.4` remain unobserved, now with the specific gap named: `internal/store/storetest`
  exposes no way to obtain an unmigrated database. `AC-008.61` remains unobserved, now with the
  specific reason named: no deterministic, non-flaky test was found for it without a production
  change. `AC-008.23` through `AC-008.25` remain unobserved, unchanged, still needing a scripted
  or real WebAuthn authenticator. Status remains `unverified`. No criterion was changed.
- `2026-09-23`: Close-out. Status set to `unverified`, and a verification status section added
  listing the criteria not yet fully observed and what would observe each. The Goal no longer
  says an account can be created by signing in with a passkey: a passkey is registered by an
  account that is already signed in (`AC-008.23`), and a passkey login only reaches the account
  that owns the credential (`AC-008.24`), so no criterion ever allowed a passkey signup. No
  criterion was changed.
- `2026-09-22`: Initial version.
