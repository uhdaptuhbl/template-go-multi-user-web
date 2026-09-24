---
feature: 008-users-and-auth
created: 2026-09-22
updated: 2026-09-24
status: implemented
---

# Design: Users and auth

How the approved requirements will be met. Free to change as implementation proceeds;
changing this file does not require amending `requirements.md`.

## Overview

The service gains a Postgres-backed identity system: accounts, three login paths (OpenID
Connect, WebAuthn passkeys, and email one-time codes), server-side sessions, an invite and
approval gate on signup, a permission-based authorization layer, and an append-only audit
trail. Each concern is its own package under `internal/`, wired together by
`internal/auth` at the HTTP surface. The schema is one initial migration, reproduced below,
run by a migration runner in `internal/store` against `internal/store/migrations`.

## Alternatives considered

| Option | Trade-off | Verdict |
| --- | --- | --- |
| JWT sessions | Cannot be revoked before expiry without a denylist, which reintroduces the server-side state a JWT was meant to avoid, and now the JWT's own signing key becomes a secret whose compromise forges any session. A stored, hashed random token revokes with one row update and carries no forgeable claims. | Rejected |
| A synchronizer-token CSRF scheme | Requires a second cookie or hidden field threaded through every form and a same-origin check duplicated at every mutating handler. The session cookie is `SameSite=Lax`, and every state-changing request that carries it is checked against its `Sec-Fetch-Site` and `Origin` headers and refused when either names another site or both are absent. The identity-link start route, a `GET` that cannot be turned into a state-changing method, is checked the same way but on every method, and passes rather than rejects when a request carries neither header, since a top-level navigation gives no `Sec-Fetch-Site`-and-`Origin` guarantee the way a fetch does. That closes the cross-site request path a synchronizer token exists to close, for no added state; `SameSite=Lax` is kept as defense in depth, per ADR 0014. | Rejected |
| A `role` enum column instead of a permission table | An enum couples "what a user may do" to a fixed, small list of named roles; adding a narrower permission means either overloading an existing role or a schema change to widen the enum, which `ALTER TYPE ... ADD VALUE` cannot run inside a transaction. `roles` / `permissions` / `role_permissions` let an operator compose a new role from existing permissions with ordinary rows. | Rejected |
| An embedded SQLite engine alongside Postgres | Two storage engines to migrate, back up, and reason about consistency across, for a feature that has no requirement pointing at SQLite. Postgres is already the project's store. | Rejected |
| Storing session tokens rather than digests | A stolen database dump would hand out live session tokens directly instead of digests that cannot be turned back into the token that produced them. See Session lifecycle. | Rejected |
| An email or domain allowlist for signup | An allowlist decides admission by an asserted address, but an unverified asserted address may not be trusted, and a provider that asserts no email or an unverified one leaves no address to check at all: an allowlist could never admit those users, closing a path invite and approval both leave open. | Rejected |
| A mode enum instead of three independent switches | `signup_enabled`, `signup_require_invite`, and `signup_require_approval` are independent axes: invite-only-with-approval, open-with-approval, and invite-only-without-approval are all real operating modes, and an enum would need one value per combination, growing every time a future switch is added. Three booleans compose without a schema change. | Rejected |
| Caching the settings row | The row changes rarely but governs whether an account may be created at all; a cache is either stale on another replica right when an operator flips a switch, or it needs its own invalidation channel to stay correct, which is more moving parts than reading one row per attempt. See Signup admission path. | Rejected |

If a rejected alternative is a decision that will outlive this feature, record an ADR in
`docs/adr/` and link it here rather than burying it in a feature spec.

## Architecture

```
internal/store/           Pool construction, connection lifecycle, and the migration runner
internal/store/migrations Embedded, Postgres-only SQL migrations
internal/secret/          A string type that redacts itself in logs and JSON
internal/authflow/        Short-lived, single-use server-side ceremony state (auth_flows)
internal/user/            Accounts and external identities
internal/session/         Session issue, lookup, refresh, and revoke
internal/audit/           Append-only audit event recorder
internal/authz/           Permissions, roles, the permission checker and its middleware,
                          and the authenticated subject carried on a request context
internal/mail/            SMTP sender, inert when disabled
internal/ratelimit/       Per-key token-bucket limiter
internal/settings/        The single runtime settings row, read uncached on every use
internal/invite/          Invite issue, lookup, redemption, revocation, and QR rendering
internal/auth/oidc/       OpenID Connect relying party ceremony
internal/auth/passkey/    WebAuthn registration and assertion ceremony
internal/auth/otp/        Email one-time code issue and verification
internal/auth/            Login orchestration, session middleware, and the HTTP surface
```

`internal/store` owns pool construction, connection lifecycle, and the migration runner,
and nothing else, because every other package below needs a `*pgxpool.Pool` and none of
them should own the decision of how it is built or when migrations run; that decision has
exactly one owner. `internal/store/migrations` holds only embedded SQL and stays
Postgres-only rather than dialect-abstracted, because the project has one production
database and an abstraction with a single implementation is a cost with no matching
benefit.

`internal/secret` is a leaf package holding the redacting string type used for provider
client secrets, the mail password, and similar configuration values, so a value that must
never reach a log is redacted by its type rather than by every caller remembering to.

`internal/authflow` owns the `auth_flows` table: it stores the state an OIDC or WebAuthn
ceremony needs between its start and finish requests and consumes it atomically, so a
replayed flow identifier finds nothing. Both ceremony packages use it rather than each
holding their own copy of the same single-use store.

`internal/user` owns accounts and external identities together because an identity row has
no meaning on its own: it exists to resolve to a `users` row, and splitting that resolution
across two packages would mean either package could get it wrong independently.

`internal/session` is its own package, not folded into `internal/user` or `internal/auth`,
because a session's lifecycle (issue, refresh, revoke, sweep) is orthogonal to how the
session came to be issued. Every login path converges on the same session package after it
succeeds, which is the point: the three login ceremonies differ, sessions do not.

`internal/audit` is a single append-only recorder shared by every other package, because an
audit trail that each package wrote to independently would have no guaranteed schema or
completeness; centralizing it is what makes "every state-changing action is audited" a
property of the package rather than a convention every caller has to remember.

`internal/authz` holds permissions, roles, the checker, its middleware, and the
authenticated subject type together because they form one control: a subject without a
permission set is meaningless, and a permission set without a place to check it against a
route changes nothing. Keeping the subject type here too, rather than in `internal/user` or
`internal/session`, means the one package that resolves "who is allowed to do this" is also
the one that defines what "who" means on a request context, so no other package can
introduce a second notion of the authenticated subject.

`internal/mail` is a thin SMTP sender, inert (a sender that discards every message and
reports success) when unconfigured, so the email code route behaves the same whether or
not mail is set up. It is its own package because `internal/auth/otp` needs to send a code but should not itself own
network or credential configuration for outbound mail, and other future features may also
want to send mail.

`internal/ratelimit` is a per-key token-bucket limiter. Every route under the auth prefix
except logout takes a bucket keyed on the client address, as does the invite landing route
`GET /i/{file}`, and the email code start and verify routes also take a bucket keyed on the
normalized address, so a guess campaign spread across many client addresses is still
bounded per mailbox. Logout is exempt because it presents no credential to guess, and a
client at its limit must still be able to end its session. A request over the limit is
answered `429` before any ceremony runs; only the first refusal in a run is audited (see
Rate-limit auditing). It is its own package because more than one caller needs the same
bucket semantics and neither should reimplement it.

`internal/settings` owns exactly the single runtime settings row and reads it uncached on
every use, because the switches it holds gate account creation and a stale read is a
security-relevant bug, not a performance one; see Signup admission path for what that
avoids.

`internal/invite` owns invite issue, lookup, redemption, revocation, and QR rendering
together because an invite's lifecycle is one linear story from creation to a single
terminal state (used up, expired, or revoked), and QR rendering is just an alternate
encoding of the same token the invite already carries, not a separate concern.

`internal/auth/oidc`, `internal/auth/passkey`, and `internal/auth/otp` are separate packages
under `internal/auth/` because each wraps a distinct third-party ceremony (an OpenID
Connect relying party exchange, a WebAuthn registration/assertion pair, and an emailed
one-time code) with its own request/response shapes, its own error modes, and in the OIDC
and WebAuthn cases its own external library; collapsing them into one package would mean one
file per ceremony inside a single package doing the same job as three packages, with none of
the benefit of a compiler-enforced boundary between them.

`internal/auth` itself is the orchestration layer: it is the one package that knows about
all three ceremony sub-packages, `internal/session`, `internal/user`, and
`internal/settings`, and it is where the HTTP handlers and the session-resolution middleware
live, because login orchestration is precisely the job of turning three different proofs of
identity into one session, and that job has to sit above the packages it coordinates rather
than inside any one of them.

## Interfaces

Exported Go types and functions are documented in their package doc comments, which this
design does not restate. The HTTP surface is registered in one place,
`internal/auth/routes.go`, and is:

| Route | Purpose |
| --- | --- |
| `GET /api/v1/auth/providers` | The login methods this deployment offers |
| `GET /api/v1/auth/oidc/{provider}/start`, `.../callback` | OIDC login; the callback also completes an identity link |
| `POST /api/v1/auth/webauthn/register/start`, `.../finish` | Passkey registration, authenticated |
| `POST /api/v1/auth/webauthn/login/start`, `.../finish` | Passkey login |
| `POST /api/v1/auth/otp/start`, `.../verify` | Email code login; absent when email codes are disabled |
| `POST /api/v1/auth/logout` | Ends the caller's session |
| `GET`, `PATCH`, `DELETE /api/v1/me` | Read, rename, and self-delete the caller's account |
| `/api/v1/me/sessions`, `/me/identities`, `/me/credentials` | List and revoke the caller's own sessions, identities, and passkeys |
| `GET /api/v1/me/identities/{provider}/link/start` | Start linking another OIDC identity to the signed-in account; refuses a request the browser marks cross-site with `403 cross_site` before any link flow starts |
| `/api/v1/admin/users` and its `roles`, `status`, `sessions`, `approve`, `reject` subroutes | Account administration and the approval queue |
| `GET /api/v1/admin/audit` | The audit log, newest first, with a cursor |
| `GET`, `PATCH /api/v1/admin/settings` | Read and change the runtime signup policy |
| `/api/v1/invites` | Issue, list, read, and revoke invites |
| `GET /i/{file}` | Invite landing redirect, or its QR image when `file` ends in `.png` |

The invite landing route is one registration rather than two because Go's `ServeMux` cannot
register both `GET /i/{token}` and `GET /i/{token}.png`: a wildcard must be a whole path
segment. The handler dispatches on the `.png` suffix. The landing redirect answers `303` to
`/?invite=<token>`, or to `/?error=invite_invalid` when the token is dead; the
QR image is rendered from the token alone, with no database lookup, so a made-up token still
receives an image and the image route cannot be used to probe which tokens exist.

Every request whose path starts with `/i/` is redacted by `internal/server`'s
`withInvitePathRedaction`, the outermost layer `NewMux` builds, before cross-site rejection,
session authentication, or the mux itself sees it: the access log and the active trace span
record the redacted form (`/i/{token}` or `/i/{token}.png`) rather than the raw path carrying
the bearer token, for a successful redemption, one the per-route rate limiter refuses, one
answered earlier in the middleware chain (a cross-site rejection, a permission denial), and one
that matches no route at all. `withRoutePattern` restores the real path immediately before the
mux runs, so routing and `r.PathValue` still see the actual token. See Observability and
security's Invite token redaction for what this does not cover.

`GET /api/v1/invites` answers `400 invalid_request` when its cursor is not a UUID `List`
itself could have issued, the same body `GET /api/v1/admin/audit` gives its own malformed
cursor, rather than a `500`.

Error bodies use the shared `internal/server` error shape. The auth-specific codes are
`unauthenticated` (401, used for every failed login whatever the cause, including a
suspended account), `forbidden` (403), `cross_site` (403), the admission refusals
`signup_disabled`, `invite_required`, `invite_invalid`, `invite_email_mismatch`, and
`approval_pending` (each 403), `conflict` for a last-administrator refusal (409),
`not_pending`, `is_pending`, `invite_quota_exhausted`, and `setting_locked` (each 409), and
`rate_limited` (429).

### Deployment requirements

`SERVICE_AUTH_PUBLIC_ORIGIN` is required at startup whenever WebAuthn is enabled, because
the relying party origin is fixed when the passkey service is built rather than derived from
each request's `Host` header, which a client controls. The relying party ID defaults to the
host of the public origin, without its port, unless `SERVICE_AUTH_WEBAUTHN_RP_ID` sets it.
The same origin is required when email codes or any OIDC provider are enabled, since the
cross-site check and the provider redirect URL both depend on it.

## Data

### Schema

Reproduced exactly as the initial migration:

```sql
-- +goose Up
CREATE TABLE users (
    id                UUID PRIMARY KEY,
    display_name      TEXT NOT NULL,
    email             TEXT,
    email_verified_at TIMESTAMPTZ,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'deleted')),
    deleted_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    CONSTRAINT users_deleted_at_matches_status CHECK (
        (status = 'deleted') = (deleted_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
CREATE INDEX users_deleted_at_idx ON users (deleted_at) WHERE status = 'deleted';

CREATE TABLE identities (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX identities_provider_subject_key ON identities (provider, subject);
CREATE INDEX identities_user_id_idx ON identities (user_id);

CREATE TABLE credentials (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BYTEA NOT NULL,
    public_key       BYTEA NOT NULL,
    attestation_type TEXT NOT NULL,
    transports       JSONB NOT NULL DEFAULT '[]'::jsonb,
    aaguid           BYTEA NOT NULL,
    sign_count       BIGINT NOT NULL DEFAULT 0,
    clone_warning    BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible  BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state     BOOLEAN NOT NULL DEFAULT FALSE,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    last_used_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX credentials_credential_id_key ON credentials (credential_id);
CREATE INDEX credentials_user_id_idx ON credentials (user_id);

CREATE TABLE sessions (
    id                  BYTEA PRIMARY KEY,
    public_id           UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at          TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    client_ip           INET,
    user_agent          TEXT NOT NULL,
    methods             JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE UNIQUE INDEX sessions_public_id_key ON sessions (public_id);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_idle_expires_at_idx ON sessions (idle_expires_at);

CREATE TABLE auth_flows (
    id         BYTEA PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('oidc', 'oidc_link', 'webauthn_register', 'webauthn_login')),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX auth_flows_expires_at_idx ON auth_flows (expires_at);

CREATE TABLE settings (
    id                      BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    signup_enabled          BOOLEAN NOT NULL,
    signup_require_invite   BOOLEAN NOT NULL,
    signup_require_approval BOOLEAN NOT NULL,
    invite_default_quota    INTEGER NOT NULL CHECK (invite_default_quota >= 0),
    invite_default_ttl_secs INTEGER NOT NULL CHECK (invite_default_ttl_secs > 0),
    invite_max_uses_limit   INTEGER NOT NULL CHECK (invite_max_uses_limit > 0),
    updated_at              TIMESTAMPTZ NOT NULL,
    updated_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by_ref          TEXT NOT NULL
);

CREATE TABLE invites (
    id             UUID PRIMARY KEY,
    token_hash     BYTEA NOT NULL,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_ref TEXT NOT NULL,
    email          TEXT,
    note           TEXT NOT NULL DEFAULT '',
    max_uses       INTEGER NOT NULL CHECK (max_uses > 0),
    uses           INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    created_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    CONSTRAINT invites_uses_within_max CHECK (uses <= max_uses)
);
CREATE UNIQUE INDEX invites_token_hash_key ON invites (token_hash);
CREATE INDEX invites_created_by_idx ON invites (created_by);
CREATE INDEX invites_expires_at_idx ON invites (expires_at);
CREATE INDEX invites_email_lower_idx ON invites (lower(email)) WHERE email IS NOT NULL;

CREATE TABLE invite_redemptions (
    id          UUID PRIMARY KEY,
    invite_id   UUID NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    user_ref    TEXT NOT NULL,
    redeemed_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX invite_redemptions_invite_id_idx ON invite_redemptions (invite_id);
CREATE UNIQUE INDEX invite_redemptions_user_id_key ON invite_redemptions (user_id);

CREATE TABLE otp_codes (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   BYTEA NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    invite_id   UUID REFERENCES invites(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX otp_codes_email_idx ON otp_codes (lower(email));
CREATE INDEX otp_codes_expires_at_idx ON otp_codes (expires_at);

CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX roles_name_key ON roles (name);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE UNIQUE INDEX permissions_name_key ON permissions (name);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_events (
    id          UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ref   TEXT NOT NULL,
    subject     TEXT NOT NULL,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    client_ip   INET,
    request_id  TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_actor_id_idx ON audit_events (actor_id);
CREATE INDEX audit_events_action_idx ON audit_events (action);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE permissions;
DROP TABLE roles;
DROP TABLE otp_codes;
DROP TABLE invite_redemptions;
DROP TABLE invites;
DROP TABLE settings;
DROP TABLE auth_flows;
DROP TABLE sessions;
DROP TABLE credentials;
DROP TABLE identities;
DROP TABLE users;
```

### Type rules

- Identifiers are `UUID` holding application-generated UUIDv7 values.
- Timestamps are `TIMESTAMPTZ` written in UTC, with no `DEFAULT now()` anywhere, so the
  injected clock stays the single source of time.
- Booleans are `BOOLEAN`.
- Binary is `BYTEA` carrying raw bytes, never base64 text.
- Structured values are `JSONB`.
- Client addresses are `INET`.
- Closed value sets are `TEXT` with a `CHECK` constraint rather than a Postgres `ENUM`,
  because widening a `CHECK` is an ordinary migration while altering an `ENUM` is not.

### Migration and rollback path

This is the initial migration for the feature: the up path creates every table listed
above in one transaction, and the down path drops them in reverse dependency order, as
shown. There is no existing data to migrate, since none of these tables exist before this
feature. Any later change to this schema is a new, separate migration file; this file is
not edited once merged.

Three later migrations extend this schema:

- `00004_auth_follow_ups.sql` adds `users.rejected_at` and `users.bootstrap_admin_granted_at`,
  both `TIMESTAMPTZ`, plus `users_rejected_implies_deleted` (`CHECK (rejected_at IS NULL OR
  status = 'deleted')`), so a rejected account is representable only as a deleted one.
  `rejected_at` is what makes a rejection final: `Reject` sets it alongside `deleted_at`, and
  `Restore` and any status write both refuse a row where it is non-null, so a rejected signup
  cannot be revived by the same path that revives an ordinary self-deletion. The migration
  also replaces `audit_events_occurred_at_idx` with `audit_events_occurred_at_id_idx` on
  `(occurred_at DESC, id DESC)`, matching the compound cursor `internal/audit.Cursor.String`
  now encodes.
- `00005_session_cookie_issued_at.sql` adds `sessions.cookie_issued_at` (`TIMESTAMPTZ NOT
  NULL`, backfilled from `created_at`), which `ReissueCookie`'s compare-and-set reads and
  writes; see Session lifecycle.
- `00006_otp_code_binding.sql` adds `otp_codes.binding_hash` (`BYTEA NOT NULL`, requiring a
  `DELETE FROM otp_codes` first since no existing row has one) and
  `otp_codes_email_binding_idx` on `(email, binding_hash)`, which the invalidation and lookup
  queries in Data flow: email one-time code login use.

## Data flow: OpenID Connect login

1. `GET` the login-start route. An optional `invite` query parameter is resolved before the
   ceremony state is written: a live invite's ID is carried into `auth_flows`, but an invite
   token that is unknown, expired, revoked, or already spent resolves to no invite at all
   rather than refusing the request, so a dead invite at the start of a sign-in never blocks
   the sign-in itself; the signup policy alone decides later whether the resulting account may
   be created. `internal/auth` asks `internal/auth/oidc` to build an authorization request; the
   relying party ceremony state (nonce, PKCE verifier, return path, and the resolved invite ID)
   is written to `auth_flows` with `kind = 'oidc'`. Emits `auth.oidc.started`
   (`outcome = 'success'`), with `actor_id` null and `actor_ref` describing the anonymous
   caller.
2. The browser is redirected to the identity provider and returns to the callback route
   with a code and state.
3. `internal/auth/oidc` looks up the matching row in `auth_flows` by its flow id, exchanges
   the code for tokens directly with the provider, and validates the ID token (issuer,
   audience, nonce, signature, expiry with the leeway named in Failure modes).
4. `internal/user` looks up `identities` by `(provider, subject)`.
   - Found: resolves to the linked `users` row.
   - Not found: this is a new external identity. If the caller is already authenticated
     (an account-linking flow, `kind = 'oidc_link'`), a row is inserted into `identities`
     and `identity.linked` is emitted. Otherwise this falls to the Signup admission path
     below, which may insert a new `users` row via Contract M and then an `identities` row.
5. On success, `internal/session` issues a session (see Session lifecycle) and the
   `auth_flows` row is deleted. `internal/audit` records `auth.oidc.completed`
   (`outcome = 'success'`, `actor_id` set to the resolved user).
6. On any failure in steps 3 to 5 (bad state, invalid token, provider error, admission
   denial), no session is issued and `auth.oidc.completed` is recorded with
   `outcome = 'failure'` and the reason in `detail`.
7. The response sets the session cookie (carrying `sessions.public_id`) and redirects to
   the flow's stored return path.

## Data flow: WebAuthn passkey login

Registration (adding a passkey to an already-authenticated account):

1. `POST` the registration-start route, authenticated. `internal/auth/passkey` builds a
   WebAuthn creation challenge and writes it to `auth_flows` with
   `kind = 'webauthn_register'`.
2. The browser's authenticator produces an attestation; the browser posts it back.
3. `internal/auth/passkey` verifies the attestation against the stored challenge in
   `auth_flows`, then `internal/user` (owning `credentials` alongside accounts and
   identities per the package layout) inserts a row into `credentials` for the
   authenticated user. The `auth_flows` row is deleted.
4. `internal/audit` records `auth.passkey.registered` (`outcome = 'success'`, `actor_id`
   the account). A failed verification records the same action with
   `outcome = 'failure'`.

Removal of a passkey follows the same shape without a challenge: the row is deleted from
`credentials` and `internal/audit` records `auth.passkey.removed`.

Login (assertion, unauthenticated):

1. `POST` the login-start route with no identifier: the login is discoverable, so the
   challenge carries no allowed-credential list and the authenticator offers whichever
   passkey the user picks. `internal/auth/passkey` builds the assertion challenge and
   writes it to `auth_flows` with `kind = 'webauthn_login'`.
2. The browser's authenticator signs the challenge; the browser posts the assertion back.
3. `internal/auth/passkey` looks up the matching row by `credentials.credential_id`,
   verifies the signature against the stored `public_key`, checks `sign_count` has
   advanced (clone detection: a `sign_count` that has not advanced sets
   `credentials.clone_warning`), and updates `credentials.sign_count` and
   `credentials.last_used_at`. The `auth_flows` row is deleted.
4. On success, `internal/user` resolves the credential's `user_id` to its `users` row,
   `internal/session` issues a session, and `internal/audit` records
   `auth.passkey.completed` (`outcome = 'success'`). On failure (unknown credential, bad
   signature, clone warning treated as a hard failure, expired flow), the same action is
   recorded with `outcome = 'failure'` and no session is issued.
5. The response sets the session cookie and redirects.

A passkey login never creates an account and never reaches Contract M: a credential only
exists on an account that was already signed in when it was registered. For the same reason
the passkey ceremony carries no invite.

## Data flow: email one-time code login

1. `POST` the code-request route with an email address. The request carries a binding cookie,
   `__Host-service_otp_binding` (or `service_otp_binding` without secure cookies): the handler
   reads an existing value or generates a fresh one and always writes it back, so the browser
   that requested the code is identifiable on the verify request without the address alone
   having to prove it. `internal/ratelimit` checks and consumes a bucket keyed on the client
   address and one keyed on the normalized email address; a request over either limit is
   answered `429`, and only the first refusal in a run is audited. `internal/auth/otp` generates a code, hashes it, hashes
   the binding cookie's value (SHA-256, stored as `otp_codes.binding_hash`, never the cookie
   value itself), and inserts a row into `otp_codes` (carrying an `invite_id` when the request
   carried an invite token, so that step 4's admission check can reach it). Before inserting,
   it invalidates the caller's own earlier outstanding codes for that address: the invalidation
   query is scoped to `(email, binding_hash)`, so a request from a different browser for the
   same address leaves the first browser's code live rather than invalidating it, and an
   outstanding invite on an invalidated row carries forward onto the new row rather than being
   dropped. `internal/mail` sends the code; a send failure is logged and does not change the
   response (see Failure modes). `internal/audit` records `auth.otp.requested` with
   `outcome = 'success'` once the row is written, whether or not delivery succeeded.
2. The response is `202 Accepted` whether or not the address belongs to an existing
   account and whether or not mail delivery succeeded, so the endpoint is neither an
   account-existence oracle nor a mail-server oracle.
3. `POST` the code-verification route with the address and the submitted code. The request
   must carry the same binding cookie the start request set; an absent binding cookie is
   answered `401 unauthenticated` before any code lookup runs. `internal/auth/otp` looks up
   the newest unconsumed, unexpired row in `otp_codes` for that `(address, binding_hash)` pair,
   compares the hash, and increments `otp_codes.attempts` on a miss up to a named limit past
   which the row is treated as consumed and failed. A code presented with a binding that does
   not match the row that address's outstanding code was requested under fails verification
   without matching any row at all, so it does not increment `attempts` on any code: the
   per-address verify rate limit key additionally includes the binding, so a wrong-binding
   guess still costs the guesser's own limit rather than draining the victim's.
4. On a hash match, `otp_codes.consumed_at` is set. `internal/user` looks up the identity
   keyed on (`email`, normalized address), the same `(provider, subject)` lookup every
   method uses, never an account by its `users.email` (ADR 0012 forbids resolving a login
   by email). If none exists, this falls to the Signup admission path below (Contract M),
   which may insert a `users` row and mark `email_verified_at` since the OTP round trip is
   itself an email-ownership proof. Because this identity is the only way an emailed code
   reaches an account, the last-sign-in-method rule counts it as a usable method while email
   codes are enabled, and counts a verified `users.email` with no such identity as nothing.
   By the same reasoning the rule counts an OpenID Connect identity only while its provider
   is still configured: one whose provider an operator removed can no longer sign anyone in.
5. `internal/session` issues a session. `internal/audit` records `auth.otp.completed`
   (`outcome = 'success'`, `actor_id` the resolved or newly created user). A wrong code,
   an expired or already-consumed row, an attempts-limit breach, or an admission denial
   records `auth.otp.completed` with `outcome = 'failure'` and no session.
6. The response sets the session cookie.

## Session lifecycle

**Token shape.** A session token is 32 bytes from `crypto/rand`, encoded base64url for
transport in the cookie. Only its raw SHA-256 digest is stored, in `sessions.id`
(`BYTEA`). `sessions.public_id` is a separate, independently generated UUIDv7 that is what
responses and any URL path carry (for example a session-management listing); the digest
never leaves the server, so a response body or a log line naming a session by its
`public_id` cannot be turned back into the token that authenticates it.

**Lifetimes.** The cookie is named `__Host-service_session` by default, is `HttpOnly`,
`SameSite=Lax`, `Path=/`, and `Secure` unless secure cookies are disabled. The idle window
defaults to 30 days (720h) and the absolute ceiling to 90 days (2160h); both are
configurable.

**Issue.** On a successful login (any of the three paths), `internal/session` generates the
token, computes and stores its digest along with `user_id`, `created_at`, `last_seen_at`,
`idle_expires_at`, `absolute_expires_at`, `client_ip`, `user_agent`, and the `methods` array
recording which ceremony produced it. The cookie carries the raw token.

**Per-request lookup and idle refresh.** `internal/auth`'s session middleware hashes the
incoming cookie token, looks up `sessions` by `id` (the digest), and rejects if no row
matches or if `idle_expires_at` or `absolute_expires_at` has passed. On a valid hit, it
updates `last_seen_at` and pushes `idle_expires_at` forward by the configured idle window,
capped at `absolute_expires_at`, so a session cannot be kept alive past its hard ceiling by
continued use. The middleware (`Authenticate`) skips session resolution entirely for
`/healthz` and `/readyz`: a health probe carrying a stale or foreign cookie must not turn a
liveness or readiness check into a database round trip or a 503 tied to session state.

**Cookie re-issue.** The cookie the browser holds is not reissued on every request. Its
`Max-Age` is set once, at issue or at the next re-issue, to the shorter of the configured idle
timeout and the time remaining before `absolute_expires_at`, so a browser cookie whose
`Max-Age` was set once at login does not expire client-side while the server-side session is
still valid. `sessions.cookie_issued_at` records when the cookie's `Max-Age` was last computed.
On a valid hit, if the request arrives more than one hour after `cookie_issued_at`, `Store`'s
`ReissueCookie` recomputes `Max-Age` the same way and writes a fresh `Set-Cookie` header and a
fresh `cookie_issued_at`. The database write is a compare-and-set,
`UPDATE sessions SET cookie_issued_at = $2 WHERE id = $1 AND cookie_issued_at = $3`, guarded by
the value `ReissueCookie` read moments earlier, so two concurrent requests racing the same
stale session write the new timestamp exactly once rather than each unconditionally
overwriting the other's write.

**Regeneration on authentication.** Completing a login issues a fresh token and revokes the
session the request already carried, if any, rather than mutating it in place, so a token
observed before the login is no longer valid after it. Linking an additional identity to a
signed-in account does not rotate the session: it changes which proofs can reach the
account, not what the current session may do, and the link callback sets no cookie.

**Explicit revoke.** Logout deletes the caller's own `sessions` row by its digest and
records `auth.logout`. An administrative or self-service revoke of a specific session
(session management, or an account-suspension action) deletes it by `public_id` and
records `session.revoked`, distinct from `auth.logout` because the actor and the subject
session may differ. Revoking every session at once (an account revoking all of its own, or
an administrator revoking all of another account's) records one `session.revoked` event per
call, not one per session, with the subject `user:<id>` naming the account whose sessions
were revoked.

**Background sweep.** A periodic job deletes expired rows from `sessions` (by
`idle_expires_at` or `absolute_expires_at` in the past), `auth_flows` (by `expires_at`), and
`otp_codes` (by `expires_at`), so failed or abandoned ceremonies and lapsed sessions do not
accumulate. The same sweep also deletes an invite once it has been expired for
`SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY`, and, as its last step, permanently purges every
account whose `SERVICE_AUTH_DELETED_GRACE_PERIOD` has elapsed since `deleted_at`, along with
its identities and credentials. The sweep runs on `SERVICE_SESSION_CLEANUP_INTERVAL`, and its
first run happens immediately at startup rather than one interval after it, so a process that
restarts more often than its configured interval still purges accounts past their grace period
instead of letting expired rows grow unbounded (an earlier review finding, now fixed). The sweep is a
maintenance operation, not a security control: the per-request lookup already rejects an
expired row before the sweep reaches it.

## Authorization path

Cross-site rejection and session authentication run inside the server's own middleware
chain, passed to `server.NewMux` as its innermost middleware rather than wrapping the mux's
result. Security headers, request ID assignment, access logging, panic recovery, the
in-flight request limit, and the handler timeout all wrap them, so a cross-site rejection or
an unauthenticated request still carries every one of those. Cross-site rejection runs
outermost of the two, ahead of authentication, which runs before any route handler. A
route's own per-route rate limiter still runs after both, since it sits inside the route
handler itself.

1. Session middleware (in `internal/auth`) resolves the incoming request to an account per
   the lookup above and places an `authz` subject on the request context.
2. `authz.Checker` resolves that subject's effective permission set by joining
   `user_roles`, `role_permissions`, and `permissions` for the account.
3. `authz.RequirePermission` is route middleware that checks the resolved set contains the
   permission the route declares, and rejects with a 403 if not, before the handler runs.
4. Inside the handler, the query still carries its own ownership predicate (for example
   `WHERE user_id = $1` scoped to the caller, or an equivalent explicit ownership check for
   an admin-scoped query).

The permission check and the ownership predicate are two separate controls, and neither
substitutes for the other. `RequirePermission` answers "is this account allowed to use this
route at all"; the ownership predicate answers "does this specific row belong to the caller
making this specific request." A route that only checks the permission would let any holder
of that permission read or write every account's rows through it; a query that only filters
by ownership but sits behind no permission check would let an unrelated authenticated
account reach the route at all. Both must hold.

The repository methods carrying that ownership predicate, beyond the ones named elsewhere in
this document, include `internal/user.Repository.CountIdentities` and its
`CountIdentitiesTx` transaction-scoped form, `internal/auth/passkey.Repository.CountFor` and
its `CountForTx` form, and `internal/session.Store.RevokeAllForTx`, each scoped to one
`user_id`. Every one of these carries a test asserting both halves of the ownership
predicate: that the owner's own row (or count) comes back, and that another account's row
is not included, per the two-sided assertion this design requires of any owner-scoped test,
not only that the caller's data appears.

`PATCH /api/v1/admin/users/{id}/roles` (`Service.ReplaceRoles`) now runs its role write inside
a transaction holding the same last-admin advisory lock (`pg_advisory_xact_lock`) that
`DeleteAccount` and `SetStatus` already held, so a role change racing a concurrent demotion or
deletion of one of the last two administrators cannot leave zero active administrators by
interleaving between two transactions that each individually looked safe.

## Signup admission path

Authenticating proves who somebody is; admission decides whether they may become an account
at all. These are different questions, and the requirements and this design keep them
separate on purpose: every login path above can resolve a caller's asserted identity
without that identity being allowed to turn into a `users` row, and it is exactly the
conflation of the two that lets a gate end up with a hole in it, because a check written
against "is this login valid" quietly ends up standing in for "may this login create an
account."

**Where the switches live.** `signup_enabled`, `signup_require_invite`, and
`signup_require_approval` live in the `settings` table rather than in environment
configuration, because they are operational policy an administrator changes at runtime
without a deploy, and because a value read from `settings` inside the same transaction that
might insert a `users` row is a value every process and every replica sees identically at
the instant of the decision; an environment variable is fixed at process start and would
let two replicas started at different times disagree about whether signup is open.

**Uncached read.** `internal/settings` is read with no cache layer, inside the
account-creation transaction, on every admission decision. This avoids a specific failure: a
cached value would go stale the moment an administrator flips a switch on one node while
other replicas keep serving requests against their own cached copy, so signup could stay
open on some replicas after being disabled, or a revoked invite requirement could lapse
briefly on others. Reading the row fresh, inside the same transaction as the write it gates,
means the two can never disagree.

**Invites as bearer credentials.** `internal/invite` treats an invite as a bearer
credential: the token itself is never stored, only its digest in `invites.token_hash`,
mirroring the session-token pattern above and for the same reason (a database dump does not
hand out live invite tokens). Possession of the token, not authentication as any prior
account, is what redemption checks.

**Contract M.** Contract M is the single place a `users` row is inserted on the login path,
named so because no other code path is permitted to do it: every one of the three login
flows above, when it resolves to no existing account, routes through this one gate rather
than inserting a row of its own. It is the ordered admission rules, run inside one
transaction:

1. Bootstrap exemption: if the authentication presents a verified email address that
   appears in the configured bootstrap administrator list, no existing account already
   holds that address, and no active account currently holds the administrator role, the
   account is created active and bypasses the checks below, since there is otherwise no way
   to reach an admin console on a closed instance. The active-administrator count is read
   inside the same transaction, after taking the last-admin advisory lock `internal/auth`'s
   `account.go` already defines (`lastAdminAdvisoryLockKey`), the same lock and count
   `DeleteAccount`, `SetStatus`, and `ReplaceRoles` use: the lock is taken only when the
   address is on the list, not on every signup, so an ordinary signup pays nothing extra.
   Holding the lock to commit means two concurrent first signups by two listed addresses on
   an empty instance serialize rather than race: the first to commit becomes administrator,
   and the second sees one active administrator and falls through to the checks below like
   an unlisted address. The list exists to create the first administrator; once one exists,
   further administrators are granted by an administrator, not by the list. The check is
   against the list, not against whether any account exists yet: an empty database with no
   list configured admits nobody past a closed policy. The check is made against the settled
   address: the one this authentication has already verified belongs to the caller, not an
   asserted or pre-verification value, per an earlier review finding. This is what the code
   does; it is not a separate rule layered on top of the address the rest of Contract M
   already uses.
2. Policy read: `internal/settings` is read fresh, as above.
3. Signup-enabled check: if `signup_enabled` is false, the attempt is rejected and
   `signup.blocked` is recorded.
4. Invite-required check: if `signup_require_invite` is true, an invite token must be
   present on the attempt, or the attempt is rejected and `signup.blocked` is recorded.
5. Invite validity: when an invite token is present, it must resolve to a non-revoked,
   non-expired `invites` row with `uses < max_uses`, or the attempt is rejected and
   `signup.blocked` is recorded.
6. Invite email binding: when the invite row carries a non-null `email`, the asserted
   identity's address must match it case-insensitively, or the attempt is rejected and
   `signup.blocked` is recorded.
7. Account creation: a `users` row is inserted, with `status = 'pending'` if
   `signup_require_approval` is true and `status = 'active'` otherwise, and
   `user.created` is recorded. This and every other audit row Contract M writes (steps 7 and
   8) are written with `internal/audit`'s `RecordTx`, against the same transaction as the
   insert it describes, rather than `Record` against an autocommit connection after the fact:
   a signup that rolls back therefore leaves neither a `users` row nor an audit row claiming
   one was created, and the two can never disagree about whether the account exists.
8. Invite redemption: when an invite was used, `invites.uses` is incremented and a row is
   inserted into `invite_redemptions`, and `invite.redeemed` is recorded, also through
   `RecordTx` inside the same creation transaction.
9. Pending-account rule: an account left at `status = 'pending'` by step 7 does not receive
   a session; the login flow that reached Contract M records its own `outcome = 'failure'`
   equivalent (the flow's own completed action, `outcome = 'failure'`, `detail` naming
   "pending approval") and the caller is told an administrator must approve the account,
   which happens separately through `user.approved` or `user.rejected`.

**Bootstrap administrator role.** The bootstrap grant happens exactly once per account, and
only inside the account-creation transaction: when Contract M's bootstrap exemption (step 1)
creates a new account, that account is created holding the administrator role and
`users.bootstrap_admin_granted_at` is stamped in the same transaction via
`MarkBootstrapAdminGrantedTx`'s compare-and-set (`... WHERE id = $1 AND
bootstrap_admin_granted_at IS NULL`), recording `user.role.granted` with the reason
`bootstrap_admin_list`. The grant is never made at login: an account that already exists,
whether or not its address is on the bootstrap list, is not re-granted the role by logging in,
and an account created before this feature or before its address was added to the list is not
retroactively granted it either. A consequence, and a deliberate one, is that demoting a
bootstrap-listed account's administrator role sticks: nothing at login re-grants it, so an
operator does not also have to edit the environment to make a demotion permanent.

Neither the one-grant-per-account marker nor "never at login" was, on its own, enough to make a
demotion stick: an administrator who demotes a bootstrap-listed account could previously have
that account delete itself (permitted, since it no longer holds admin), wait out the deletion
grace period so the sweeper purges its row and identities, and sign up again with the same
address. Nothing about that new account's row carries the old one's history, so step 1's
bootstrap exemption would grant it the role again as if it were the instance's first
administrator. Gating step 1 on the active-administrator count, as described there, closes
this: the exemption, and the grant it carries, are only ever available while the instance has
no active administrator. When a bootstrap-listed address signs up while one or more
administrators are active, it receives no exemption and is admitted, or refused, by steps 2
through 9 exactly like an unlisted address; listing several addresses at once grants the role
only to whichever of them signs up first, and that administrator promotes the others through
`PATCH /api/v1/admin/users/{id}/roles` if it chooses to.

**Approval queue.** An administrator lists pending accounts with the users listing's status
filter and approves or rejects each one. Approve moves a pending account to active and
records `user.approved`; reject moves it to deleted, where the ordinary grace period and
purge apply, and records `user.rejected`. Both act only on a pending account: against any
other status they answer `409` with `not_pending` and change nothing, so reject cannot be
used as a second path to delete an active account.

**Deleted-account status writes.** `PATCH /api/v1/admin/users/{id}/status` against a
self-deleted account answers the same `409` conflict body as `ErrLastAdmin` and
`ErrSelfAction`, and leaves the account deleted, whatever status the request names. Only
`status: active` restores it, and only within its grace period; a request naming any other
status is a no-op refusal, not a partial change.

**Runtime settings.** `PATCH /api/v1/admin/settings` changes only the keys the body names.
A body that names no recognised key is refused `400 invalid_request` rather than answered as
a no-op, and a value outside its allowed range (a negative quota, a non-positive lifetime or
use ceiling) is refused `400 invalid_request`. A key locked by the environment is refused
`409 setting_locked`, and the response to `GET` lists the locked keys. A successful change
records `settings.updated` with the subject `settings:global` and the changed keys in its
detail.

**Invite lifetime ceiling and default redemption limit.** `SERVICE_AUTH_INVITE_MAX_TTL`
(default `336h`, fourteen days) is the longest lifetime an invite may be issued with and the
ceiling `invite_default_ttl_secs` itself may not exceed; `Create` refuses a request naming a
longer TTL, and `settings.Apply` refuses setting a default TTL above this ceiling, both with
`400 invalid_request`. `SERVICE_AUTH_INVITE_DEFAULT_MAX_USES` (default `1`) is the redemption
limit an invite gets when its issuer names none. Both are read from configuration, not the
`settings` table, since the ceiling and the fallback are deployment-time decisions rather than
runtime policy an administrator changes without a deploy, unlike the three signup switches
above.

**Invite quota, read inside the transaction.** `Create` reads the issuer's live-invite count,
for the quota check, inside the same transaction that inserts the new invite, behind a
transaction-scoped advisory lock (`pg_advisory_xact_lock(hashtextextended($1::text, 0))`,
keyed on the issuer) taken before the count. Postgres' default READ COMMITTED isolation would
otherwise let two concurrent `Create` calls for the same issuer both read the same count
before either commits, letting an issuer at quota end up over it; the lock, not the
transaction boundary alone, is what serializes them.

**Get and list share Create's response shape.** `GET /api/v1/invites/{id}` and `GET
/api/v1/invites` render the same `inviteResponse` shape `POST /api/v1/invites` does, with
`url`, `token`, and `qr_url` omitted (`omitempty`) rather than reintroduced with a second
shape, since those three fields are exactly the once-only secrets `AC-008.63` says must not
be disclosed again.

**Invite audit.** Issuing an invite records `invite.created`, revoking one records
`invite.revoked`, and admission through one records `invite.redeemed`.

Because Contract M is the only inserter of `users` rows on the login path, an operator
auditing `user.created` events has a complete list of every account ever created through
login, and no login ceremony, however it is later extended, can create one by skipping
these nine checks.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Database unreachable mid-request | The request fails closed: `503` with an `unavailable` error body. No partial answer (a session accepted without its row committed, or a permission check silently passing) is returned. |
| SMTP unreachable | `internal/auth/otp`'s code-request route still returns its normal `202 Accepted`, since a code row was written regardless of delivery. The send failure is logged, and `auth.otp.requested` is recorded with `outcome = 'success'` because the code was issued; the audit trail does not record delivery. Mail-server state is never observable to the caller. |
| Database unreachable at a readiness probe | The readiness endpoint answers `503` with the body `{"status": "not_ready", "failing": ["database"]}`, naming the failed check but not the error, which goes to the log. It answers `200` with `{"status": "ready"}` again once the database responds. |
| An identity provider's discovery document is unreachable at startup | The OIDC provider is configured lazily: `internal/auth/oidc` does not fetch discovery at process start, so the process starts regardless of a third party's outage. The first login attempt against that provider while discovery is still unreachable returns `503`. |
| Clock skew between this service and a provider | The identity token's expiry (`exp`) and not-before (`nbf`) checks in `internal/auth/oidc` allow a configurable leeway, 30 seconds by default, so ordinary clock drift between this service and the provider does not reject an otherwise valid token, while leaving that leeway small enough that it does not meaningfully extend a token's usable lifetime. |

## Security and privacy

Trust boundaries: the browser is untrusted and every login ceremony is designed so that a
value the browser echoes back (an OIDC `state`, a WebAuthn challenge, an OTP code) is
checked against a server-held record in `auth_flows` or `otp_codes` rather than trusted on
its own. The identity provider is trusted only for the claims inside a token whose signature
this service verifies against the provider's own published keys; it is not trusted to decide
admission, which is Contract M's job alone. Personal data handled: email addresses (in
`users`, `identities`, `otp_codes`, `invites`), display names, client IP addresses (in
`sessions` and `audit_events`), and WebAuthn public key material (not secret, but
identifying). Session and invite tokens are stored only as digests, per Session lifecycle
and Signup admission path above, so that a database compromise does not hand out live
credentials.

## Test strategy

Unit tests cover `internal/session` token/digest round-tripping and expiry arithmetic,
`internal/authz.Checker` permission resolution, `internal/invite` state transitions, and
`internal/settings` reads, all against a real Postgres instance per the project's
prefer-real-collaborators rule (the database is a process boundary the test cannot avoid,
so it is exercised for real rather than mocked) rather than an in-memory fake. Integration
tests drive each of the three login flows through `internal/auth`'s HTTP surface end to end,
including a fake but protocol-correct OIDC provider, because no unit-level slice of any one
ceremony demonstrates that a cookie is actually issued at the end. The passkey ceremony is now
driven the same way, end to end, with a scripted, in-process WebAuthn authenticator
(`github.com/descope/virtualwebauthn`) standing in for a browser's, so a full registration and
a full login, including a stale-counter assertion, are observed rather than only the
attestation and assertion verification the WebAuthn library itself performs. Contract M's nine ordered rules are table-driven integration tests, one
per rule's rejection path plus the success path, since each rule's effect is only observable
as a row (or its absence) after a transaction commits.

## Observability

Every action listed under Data flow above is a structured audit event
(`internal/audit`), which is the primary observability surface for this feature: each
carries `occurred_at`, the actor, the subject acted on, the outcome, the client IP, and the
request id, so "who did what, and did it succeed" is answerable from `audit_events` alone
without correlating logs. Session issue, refresh-rejection, and revoke additionally emit
zap log lines at the point of the per-request lookup, answering the operational question
"why did this specific request's session get rejected" (expired vs. not found vs. absolute
ceiling reached) which the audit trail's action-level granularity does not carry. This
feature emits no metrics of its own. Login attempt counts and outcomes per path are the
`auth.oidc.completed`, `auth.passkey.completed`, and `auth.otp.completed` audit rows and their
`outcome`, and Contract M rejection reasons are the `signup.blocked` rows, whose detail names
the rule that refused. Dedicated metrics for both, so an operator can see unusual load or
failure on a login path or the admission gate without querying audit rows, are a possible
follow-up; no criterion or task asks for them yet.

The audit log is paged newest first with a compound cursor, `<RFC3339Nano UTC>_<uuid>` (an
`audit_events.occurred_at` formatted with `time.RFC3339Nano` in UTC, an underscore, then the
row's `id`), which `Cursor.String` encodes and `ParseCursor` decodes, rejecting anything else
as a malformed cursor. The next page asks for rows strictly after that `(occurred_at, id)` pair
in the `(occurred_at DESC, id DESC)` ordering `audit_events_occurred_at_id_idx` (migration
00004) serves, so rows sharing the boundary timestamp are no longer skipped between pages, the
defect the single-`occurred_at` cursor above used to have. `GET /api/v1/admin/audit`'s response
carries the cursor for the next page as `next_cursor`, which is JSON `null`, not an empty
string, once the last page has been returned.

**Invite token redaction.** `withInvitePathRedaction` (`internal/server`) is the outermost
layer `NewMux` builds: every other middleware named at the top of Authorization path,
including cross-site rejection and session authentication, runs inside it, and the access log
and the active trace span see the redacted route pattern `/i/{token}` or `/i/{token}.png`
rather than the raw path carrying the bearer token (AC-008.87). Because it keys on the `/i/`
path prefix rather than on a matched route, this holds for every outcome the route can reach,
including a redemption the per-route rate limiter refuses with `429`, a request a cross-site
rejection or a permission denial answers before the mux runs, and a request whose path starts
with `/i/` but matches no registered route at all. An earlier review finding identified gaps
here (a request shed before the mux, an unmatched method or subpath) still carrying the raw path
because redaction ran only after the mux matched; the fix moved redaction outside every other
layer, closing them, which is what the paragraph above and this one now describe.

**Audit subject kinds.** `internal/audit.validateSubject` restricts every recorded `Subject`
to one of a fixed set of `<kind>:<value>` prefixes: `user`, `email`, `provider`, `settings`,
`invite`, `session`, `credential`, `identity`, and `anonymous`. The `anonymous` kind carries
two values in use today, `anonymous:webauthn` (a passkey assertion against a credential no
account resolved, recorded before authentication can name an account at all) and
`anonymous:ip` (a rate-limit refusal recorded before any credential was presented, keyed on
the client address rather than an account).

**Rate-limit auditing.** The first request a client has refused for a given rate-limit key
records exactly one `auth.rate_limited` audit event; a client that keeps retrying while still
over the limit does not get a second one for the same limit until a request from it is
admitted again, which is what keeps a sustained flood from writing one audit row per refused
request (AC-008.88). `internal/ratelimit`'s limiter tracks this per key so the "first refusal
only" decision does not depend on the caller remembering to check.

**Email-code requests with no address.** The email-code start limiter is keyed on the
normalised address, so every request whose address is empty or only whitespace shares one
bucket, `otp-start:`, whichever client sent it. This is intended and will stay as it is
unless it causes a problem nobody foresaw. Only junk requests land in that bucket: no real
sign-in has an empty address, and the per-address limiter sits behind the per-IP one, which
still bounds each client. No audit event is recorded for a refusal in that bucket, because
an empty address yields no valid audit subject.

**IPv6 rate limiting.** `ratelimit.KeyForIP` keys an IPv4 address, including an IPv4-mapped
IPv6 address, by itself, and keys an IPv6 address by its `/64` prefix in `netip.Prefix` string
form (for example `2001:db8:1:2::/64`), so a client that rotates through addresses inside the
same `/64` (routine behavior for IPv6 privacy addressing) still shares one bucket rather than
getting a fresh one per address.

**QR scale parameter.** `GET /i/{file}` accepts an optional `scale` query parameter that sets
the pixel scale of the rendered QR code, read only when the request names the `.png` form of
the route; an absent or unparseable value falls back to `defaultQRScale`. The parameter takes
no database lookup, the same as the unscaled image, so this remains true regardless of scale:
the QR route cannot be used to probe which tokens exist. An earlier review finding noted this
parameter is not mentioned by the contract calling QR rendering "a pure function from the path
segment"; the
decision is to keep the parameter, since it has no behavioral defect, and this paragraph is
that documentation.
