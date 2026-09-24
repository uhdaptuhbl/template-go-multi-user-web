---
status: accepted
date: 2026-09-22
---

# 12. Authentication model

## Context and Problem Statement

This service is a public multi-user service with no existing accounts. There is no migration to
carry forward and no installed base whose login method must keep working, which makes this
the one moment where the authentication model can be chosen rather than inherited. Every
method it ships from here becomes a permanent support and security commitment: a method
shipped today cannot be quietly dropped once accounts depend on it, and a method not shipped
today is cheap to add later if a real need for it appears. The decision is which methods to
ship, how an authenticated request maps to an account, and how authenticating relates to
being allowed to have an account at all.

## Decision Drivers

- **No installed base to break.** This is the one point in the project's life where the
  authentication surface can be chosen on its merits rather than constrained by what already
  works for existing users.
- **A public service is under continuous credential-stuffing and phishing pressure**, unlike
  an internal tool with a small, known user set.
- **Every method shipped is a permanent commitment.** Removing a login method after accounts
  depend on it is a support incident, not a refactor.
- **Identity must survive an email address changing hands**, since providers reassign
  addresses and a user's own address changes over the life of an account.
- **Admission control and authentication are different questions asked by different code**,
  and conflating them is how an allowlist ends up doing double duty as a signup gate.
- **No mechanism should be forgeable by ambient state**, such as a cookie set by whichever
  party can reach the origin, when the mechanism is deciding something as consequential as
  which invite a signup consumes.

## Considered Options

- Passwordless authentication: OIDC, WebAuthn passkeys, and an opt-in email one-time-code
  fallback
- Password authentication with the usual supporting machinery: hashing, reset flow, breach
  checking, lockout, and TOTP
- Password authentication as a fallback alongside passwordless methods

## Decision Outcome

Chosen: **passwordless authentication only, via three methods in order of preference:**

1. **OIDC authorization code flow with PKCE** against configured providers, Google first.
2. **WebAuthn passkeys**, which also serve users unwilling to involve an identity provider.
3. **Email one-time codes**, disabled by default, as the fallback for users with neither of
   the above.

Identity is keyed on `(provider, subject)`, never on an email address. Admission is decided
once, at the moment an authentication resolves to no existing identity, and is governed
independently of which method the user chose.

### Explicitly rejected: password authentication

A password is not one feature; it is a commitment to roughly six pieces of supporting
machinery, each with its own ongoing cost:

- An Argon2id parameter policy that must be re-tuned as hardware improves, or the hash
  weakens under the operator's feet without any code change to point at.
- Single-use, time-limited reset tokens, which is its own state machine with its own set of
  expiry and reuse bugs to get right.
- A mail dependency that the reset flow makes mandatory rather than optional. Nothing else in
  a passwordless design requires mail to exist at all, since only the disabled-by-default OTP
  fallback touches it.
- Breach-corpus checking, so a user is not permitted to set a password already known to be
  compromised.
- Lockout and throttling tuned finely enough to slow an attacker without becoming a
  denial-of-service lever that lets an attacker lock a named victim out of their own account.
- TOTP enrollment with recovery codes, because password-only authentication is not acceptable
  for a public service on its own, which means a password implementation is never done at
  "password" -- it is done at "password plus a second factor."

Each of the three chosen methods sidesteps this list by construction rather than by careful
tuning: OIDC and passkeys are phishing-resistant, and OIDC additionally delegates its second
factor to a provider that already runs one. None of the three needs a password reset flow,
because none of the three has a password to reset.

### Decision: identity is keyed on `(provider, subject)`, never on an email address

An OIDC provider's `sub` claim is stable for the life of the account; the email address
attached to it is not. A provider may let a user change their address, and some providers
reassign an address once its previous owner abandons it. Keying identity on email means an
account silently changes hands the day the provider does, with no action from either party.
Keying it on `(provider, subject)` avoids that failure by construction: the subject does not
move.

A `users` row may carry many `identities` rows, one per `(provider, subject)` pair, so a
single account can be reached through Google today and a passkey tomorrow without either
identity depending on the other's address.

### Decision: automatic account linking by email address is forbidden

A login presenting an email that matches an existing account creates no link to that account.
Linking a second identity to an existing account happens only while already authenticated as
that account, through an explicit "add a sign-in method" action, never as a side effect of a
new login attempt.

This is not a convenience left on the table; it closes a known account-takeover path.
Auto-linking on an unverified address lets an attacker claim someone else's account by
signing up with an identity provider that will assert any address the attacker types.
Auto-linking on a verified address is not safe either, for the same reason keying on email is
rejected above: a provider may reassign a verified address to a new owner, and that new owner
presenting it would silently inherit the previous owner's account.

### Decision: MFA is delegated, not implemented

This service ships no TOTP enrollment of its own. Each method carries its own answer to the second
factor:

- **OIDC**: the provider owns MFA. Whatever factor Google or another configured provider
  requires of the user is enforced before the service ever sees an authorization code.
- **Passkeys**: WebAuthn user verification combines possession of the authenticator with a
  local factor, such as a PIN or biometric, in one ceremony, so no separate second factor is
  needed.
- **Email one-time codes**: possession of the mailbox is the only factor, which makes this
  the weakest of the three. That weakness is the reason it is disabled by default rather than
  offered on equal footing with the other two.

### Decision: authenticating and being admitted are separate questions

Verifying who somebody is does not decide whether they may have an account here. Admission is
decided once, at the moment an authentication resolves to no existing identity, by the
signup admission rules, and never again once an account exists. Three independent switches
govern admission, evaluated as a conjunction:

- Whether self-service signup is possible at all.
- Whether an invite is required to sign up.
- Whether a new account waits for approval before it can do anything.

These are three independent switches rather than one mode enum because the combinations that
matter in practice are conjunctions of them ("open, but every new account needs approval" is
a real deployment shape, and so is "invite-only, no approval needed"), and an enum that has to
express a conjunction grows a new value per combination until its name stops describing what
it does.

### Explicitly rejected: an email allowlist

An allowlist was the obvious fourth switch, and it does not work here for a reason this same
record creates. Since an unverified asserted address cannot be trusted, an allowlist can only
ever be evaluated against a verified one. That leaves no path in for any identity from a
provider that asserts no email at all, or an unverified one: there is nothing to check the
list against. Invites and approval cover the same ground without that gap, because both are
checked against something the server itself issued or a human actually decided, rather than
against a string the provider chose to hand back.

### Decision: an invite is carried in server-side ceremony state, never in a cookie

The invite token reaches a ceremony at exactly two places: as a query parameter on
`GET /api/v1/auth/oidc/{provider}/start`, and as a body field on
`POST /api/v1/auth/otp/start`. It first arrives at `GET /i/{token}`, the link an invite is
shared as, which only redirects the browser to `/?invite=<token>` for the frontend to pass on
to one of those two routes; that route holds no state and starts no ceremony. From there it is
stored in `auth_flows.data` for the OIDC ceremony, or `otp_codes.invite_id` for the OTP
ceremony. Those are the only two ceremonies that can create an account, since passkey
registration requires an already-authenticated caller and therefore never admits a new account
on its own, so no third carrier is needed.

A cookie was considered, since carrying the invite as a cookie set at the point the user
clicked the invite link is the more common pattern, and it was rejected. A cookie is ambient
authority: it is forgeable by anyone who can set a cookie on the origin, and it attaches to
whatever signup happens next in that browser rather than to the ceremony it was meant to
accompany. A shared machine would spend the previous visitor's invite on whoever signs up
next, with no ceremony boundary to stop it. Flow state keyed to a specific `auth_flows` row
has none of those properties, since it lives and dies with the one ceremony it belongs to.

Had a cookie been chosen anyway, it would have had to be `SameSite=Lax`, because the OIDC
callback arrives as a top-level cross-site navigation from the provider, on which a `Strict`
cookie is not sent. The mechanism would have failed closed on exactly the path it exists to
support, with no error visible to explain why the invite silently vanished.

### Decision: the invite token is stored only as a SHA-256 digest

An invite URL is shown exactly once, at creation, and the server never stores anything that
lets it be redisplayed. This follows the rule already applied to sessions, and it has the
same consequence: a lost invite link is revoked and reissued, not recovered, because there is
nothing on the server able to recover it.

### Decision: bootstrap administrator addresses are exempt from the admission rules while no active administrator exists

Without an exemption, a deployment that starts closed -- signup disabled, or invite-only with
no invites yet issued -- has no way to create its first account, and therefore no way to
create the first administrator who would issue invites or open signup. The exemption applies
only to an address verifiably asserted by the authenticating provider, so it cannot be
claimed by asserting somebody else's address through a provider willing to assert anything.

The exemption, and the administrator grant it carries, apply only while the instance has no
active administrator: the account-creation transaction takes the last-admin advisory lock and
counts active administrators before deciding, the same lock and count `DeleteAccount`,
`SetStatus`, and `ReplaceRoles` already use. Without this gate, an administrator who demotes a
bootstrap-listed account does not make the demotion stick: the demoted account can delete
itself, wait out the deletion grace period, and sign up again with the same address, at which
point nothing it once held survives to refuse it the role a second time -- the list would grant
it again as if it were still the instance's first administrator. Gating on an empty
administrator set closes that path: once any administrator exists, a listed address is
admitted, and denied, exactly like an unlisted one.

### Consequences

- No password column, no password reset flow, and no password-related configuration exists
  anywhere in the codebase. This is a deliberate constraint the codebase is built to, not a
  gap waiting to be filled in later.
- Users depend on having access to a configured identity provider, a passkey-capable device,
  or a working mail path for the OTP fallback. A user with none of the three has no way in.
- Operators who enable none of the three methods have a service nobody can log into.
  Configuration validation reports this at startup rather than letting it surface as a
  silent lockout discovered by the first user who tries.
- A deployment that starts with signup closed and no bootstrap administrator address
  configured has no way in for anyone. Configuration validation warns about this but does not
  treat it as fatal, since an operator restoring a populated database from backup is in
  exactly that state legitimately, with existing accounts already present.
- Admission logic (open signup, invite requirement, approval requirement) is written and
  reasoned about independently of which of the three authentication methods produced the
  login attempt, which keeps a future fourth method from requiring changes to admission at
  all.

## Pros and Cons of the Options

### Passwordless authentication (OIDC, passkeys, opt-in email OTP)

- Good: none of the three methods requires the six-part password support surface described
  above.
- Good: two of the three methods are phishing-resistant by construction, and the third is
  disabled by default in acknowledgment of its weaker guarantee.
- Good: MFA is delegated rather than implemented, so the service owns no TOTP enrollment,
  recovery-code generation, or recovery-code storage.
- Bad: a user with no identity-provider account, no passkey-capable device, and no configured
  OTP fallback has no way to authenticate at all.
- Bad: WebAuthn and OIDC are both more code to integrate correctly than a password field,
  even though neither carries the long-tail maintenance cost a password does.

### Password authentication with full supporting machinery

- Good: familiar to every user, and requires no external provider or hardware.
- Bad: brings the full six-part cost enumerated above, as a permanent commitment rather than
  a one-time build.
- Bad: is not phishing-resistant, so it is the method most exposed to the credential-stuffing
  and phishing pressure a public service draws.
- Bad: is not acceptable on its own for a public service, which means it was never actually
  being considered without also committing to TOTP and recovery codes on top of it.

### Password authentication as a fallback alongside passwordless methods

- Good: covers the user who has none of an identity provider, a passkey device, or a working
  mail path.
- Bad: still incurs the full six-part cost, since a fallback password is not exempt from
  hashing policy, reset flows, breach checking, or lockout tuning just because it is a
  fallback.
- Bad: with no installed base to serve, the user this fallback covers is hypothetical today,
  while the maintenance cost is certain and ongoing.

## More Information

- `docs/adr/0013-authorization-model.md`, where what an authenticated identity is permitted
  to do is decided.
- `docs/adr/0014-session-management.md`, where the session issued after a successful
  authentication is decided.
- `docs/adr/0015-configuration-sources-and-precedence.md`, where the storage and precedence of
  the three admission switches (self-service signup, invite requirement, approval
  requirement) is decided, and why they are not environment variables.
