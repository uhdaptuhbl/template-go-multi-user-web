# template-go-multi-user-web

A Go service that serves a browser-based interface from a single binary.

## Using this template

This repository is a starting point, not a dependency. Nothing here imports it; a project
made from it owns every file and edits them freely.

It carries everything in
[template-go-http-server](https://github.com/uhdaptuhbl/template-go-http-server) plus a
multi-user layer: PostgreSQL persistence, passwordless sign-in (OpenID Connect, passkeys, and
emailed one-time codes), sessions, roles, invites, an approval queue, and an audit log. Start
from the smaller template instead if the service has no accounts.

### With gonew

[`gonew`](https://pkg.go.dev/golang.org/x/tools/cmd/gonew) copies the tree and rewrites the
module path and its imports in one step:

```sh
go run golang.org/x/tools/cmd/gonew@latest \
    github.com/uhdaptuhbl/template-go-multi-user-web \
    github.com/you/your-service
cd your-service
go tool mage bootstrap
```

`gonew` rewrites the module path and the import paths that follow from it. It rewrites
nothing else, so the rename below still has to be done by hand.

### Standalone

Clone it, or use GitHub's "Use this template" button, then drop the history that is not
yours:

```sh
git clone git@github.com:uhdaptuhbl/template-go-multi-user-web.git your-service
cd your-service
rm -rf .git && git init
go mod edit -module github.com/you/your-service
grep -rl github.com/uhdaptuhbl/template-go-multi-user-web --exclude-dir=.git . \
  | xargs sed -i 's|github.com/uhdaptuhbl/template-go-multi-user-web|github.com/you/your-service|g'
go tool mage bootstrap
```

`go mod edit` rewrites `go.mod` alone, which is why the `sed` is there: the import
statements naming the old path have to move with it or nothing compiles. `gonew` above does
both in one step, which is the only reason to prefer it.

`mage bootstrap` runs the lint and unit gates, which need no database. `go tool mage
integration` needs Docker or a reachable Postgres; see Development below.

### What to rename

The template names itself `service` throughout, which is deliberately generic so that a
forgotten rename is visible rather than plausible. Five substitutions cover it, and none of
them is derived from another:

| What | From | Where |
| --- | --- | --- |
| Module path | `github.com/uhdaptuhbl/template-go-multi-user-web` | `go.mod`, every import, `.golangci.yaml`'s `depguard` allow prefix |
| Environment prefix | `SERVICE_` | `internal/config/` struct tags, `.env.example`, `deploy/local/compose.yaml`, this file |
| Binary and image name | `service` | `cmd/service/`, `magefile.go`, both Dockerfiles, `.goreleaser.yaml`, `.github/workflows/` |
| Reported service name | `telemetry.DefaultServiceName` | `internal/telemetry/telemetry.go`, one constant |
| Name shown to users | `service` | the passkey display name default in `internal/config/auth.go`, the session cookie name in `internal/session/config.go`, the sign-in email in `internal/auth/otp/otp.go`, `internal/web/dist/index.html`, and the local database credentials in `deploy/local/compose.yaml` |

```sh
grep -rn 'SERVICE_\|service' --exclude-dir=.git .
```

finds all of them. Prose in this file, `CLAUDE.md`, `docs/adr/`, and `specs/` describes the
template rather than your service, and is yours to rewrite.

### What to decide

- **`docs/adr/0002-frontend-stack.md` is open,** deliberately. It records four options for
  the frontend and the four things that must be settled to close it, including the JSON
  field-naming convention that `docs/adr/0010-json-api-response-conventions.md` defers to
  it. The account API in `specs/008-users-and-auth/` already ships `snake_case` members, so
  settle the convention before a client depends on them. Accept the record, or supersede it,
  before writing frontend code.
- **`specs/001-` through `specs/008-` describe this template's own behaviour,** not yours.
  They are worked examples of the three-document pattern `CLAUDE.md` requires, and their
  criteria are cited by the tests in this repository. Keep them, and number your first
  feature `009-`.
- **The signup policy defaults suit a small invited group:** signup on, invite required,
  approval off. Review Who may sign up below, and set `SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS`
  before the first start.
- **`CLAUDE.md` is the engineering constitution,** including the one deliberate departure
  from common Go idiom (one declaration per line). Read it before the first commit; change
  it if you disagree with it, rather than drifting from it silently.
- **The licence is Apache 2.0.** Your service's own code is yours to license as you like.

## Requirements

- Go 1.27 or later
- [GoReleaser](https://goreleaser.com) 2.x, only to rehearse or check a release
- Docker, only to build the image or run the local observability stack

golangci-lint and mage need no install: both are pinned as tools in `go.mod` and run through
`go tool`.

## Running

```sh
go run ./cmd/service
```

Two listeners start. The application listener on `:8080` serves users:

| Route | Purpose |
| --- | --- |
| `GET /healthz` | Liveness check; returns `{"status":"ok"}` |
| `GET /readyz` | Readiness check; `200 {"status":"ready"}` while serving, `503 {"status":"not_ready","failing":["<check>"]}` when a registered dependency check fails, `503 {"status":"draining"}` once shutdown has begun |
| `GET /` | The embedded frontend |

Every response from this listener carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Content-Security-Policy: frame-ancestors 'none'`; the frontend
handler replaces the last with the fuller policy its assets need.

The administrative listener on `127.0.0.1:9090` serves operators:

| Route | Purpose |
| --- | --- |
| `GET /metrics` | Prometheus exposition, including Go runtime metrics |
| `GET /healthz` | The same liveness check, so this port is sufficient alone |
| `GET /readyz` | The same readiness check, with the same three answers |
| `GET /version` | The running build: version, commit, build date, Go version, and process start time |
| `GET /debug/pprof/` | Runtime profiling |

`GET /version` answers what the start-up log entry said, for when that line has rotated
away:

```console
$ curl -s 127.0.0.1:9090/version
{"version":"1.4.0","commit":"a1b2c3d","build_date":"2026-09-19T08:11:04Z","go_version":"go1.27.1","started_at":"2026-09-19T08:14:22Z"}
```

It is deliberately absent from the application listener: naming the exact release tells
anyone who can reach it which vulnerabilities to try. The same values are also labels on the
`build_info` metric, for tooling that would rather join on them than parse JSON.

The administrative listener binds loopback by default. Reaching it from elsewhere requires
setting `SERVICE_ADMIN_ADDR`, and doing so requires a network policy, because the profiling
endpoints will dump the heap, every goroutine's stack, and the process command line to
anyone who can reach them.

Readiness consults nothing by default. A dependency the process cannot serve without is
registered in `cmd/service/main.go` with `ready.AddCheck("database", db.PingContext)`; every
probe then runs each check concurrently under a one-second deadline and answers `not_ready`,
naming the failing checks, until they pass. The check's error goes to the log, not the
response.

On shutdown, readiness starts failing first, so a load balancer or orchestrator stops
sending new traffic. The process keeps serving for `SERVICE_LIFECYCLE_PRE_DRAIN_DELAY`, to
give that signal time to propagate, then the listeners stop accepting new connections and
in-flight requests get up to `SHUTDOWN_TIMEOUT` to finish. A second `SIGINT` or `SIGTERM`
during this window abandons in-flight requests and exits with status 1. If either listener
fails to start, the process stops rather than running half of what was asked for.

### Authentication and account routes

The application listener also serves the authentication and account management API under
`/api/v1`, plus two short redemption routes outside it. A route whose method is disabled is not
registered at all, so a caller reaches a `404` rather than a response that says the method is off.

**Authentication**

| Route | Purpose |
| --- | --- |
| `GET /api/v1/auth/providers` | Lists the authentication methods this deployment has enabled |
| `GET /api/v1/auth/oidc/{provider}/start` | Begins a login through an OpenID Connect provider; present only when at least one is configured |
| `GET /api/v1/auth/oidc/{provider}/callback` | Completes an OpenID Connect login or identity-link ceremony; present only when at least one provider is configured |
| `POST /api/v1/auth/webauthn/register/start` | Begins registering a passkey for the signed-in caller; present only when WebAuthn is enabled |
| `POST /api/v1/auth/webauthn/register/finish` | Completes passkey registration; present only when WebAuthn is enabled |
| `POST /api/v1/auth/webauthn/login/start` | Begins a passkey login; present only when WebAuthn is enabled |
| `POST /api/v1/auth/webauthn/login/finish` | Completes a passkey login; present only when WebAuthn is enabled |
| `POST /api/v1/auth/otp/start` | Requests an emailed one-time login code; present only when email codes are enabled |
| `POST /api/v1/auth/otp/verify` | Verifies an emailed one-time code and signs in; present only when email codes are enabled |
| `POST /api/v1/auth/logout` | Revokes the current session and clears its cookie |

**Self-service**

| Route | Purpose |
| --- | --- |
| `GET /api/v1/me` | The signed-in caller's own account |
| `PATCH /api/v1/me` | Changes the signed-in caller's display name |
| `DELETE /api/v1/me` | Deletes the signed-in caller's own account; see Account deletion below |
| `GET /api/v1/me/sessions` | The caller's own live sessions |
| `DELETE /api/v1/me/sessions` | Revokes every session the caller holds |
| `DELETE /api/v1/me/sessions/{id}` | Revokes one of the caller's own sessions |
| `GET /api/v1/me/credentials` | The caller's own registered passkeys; present only when WebAuthn is enabled |
| `DELETE /api/v1/me/credentials/{id}` | Removes a passkey; present only when WebAuthn is enabled |
| `GET /api/v1/me/identities` | The caller's own linked external identities |
| `GET /api/v1/me/identities/{provider}/link/start` | Begins linking another external identity to the caller's account; present only when at least one provider is configured |
| `DELETE /api/v1/me/identities/{id}` | Detaches one of the caller's own external identities |
| `GET /api/v1/invites` | The caller's own invites, or every invite for a caller who can manage them |
| `POST /api/v1/invites` | Issues an invite; see Invites below |
| `GET /api/v1/invites/{id}` | One invite the caller owns or can manage |
| `DELETE /api/v1/invites/{id}` | Revokes an invite |
| `GET /i/<token>` | Redeems an invite link, redirecting to the landing page |
| `GET /i/<token>.png` | Renders a QR code of the same invite link |

An account cannot remove its last authentication method: `DELETE /api/v1/me/credentials/{id}` and
`DELETE /api/v1/me/identities/{id}` both answer `409` and change nothing when the caller has no
other passkey, external identity, or (with email codes enabled and the address verified) usable
email code login left. This is a refusal an operator will otherwise be asked to explain as a bug.

`GET /api/v1/me/identities/{provider}/link/start` refuses with `403 cross_site` a navigation the
browser itself marks cross-site, before any link flow starts, so an attacker page cannot
redirect a signed-in victim into attaching another identity to their account.

**Administrative**

| Route | Purpose |
| --- | --- |
| `GET /api/v1/admin/users` | Lists accounts, optionally filtered by `status` |
| `PATCH /api/v1/admin/users/{id}/roles` | Replaces an account's roles |
| `PATCH /api/v1/admin/users/{id}/status` | Suspends or reactivates an account |
| `POST /api/v1/admin/users/{id}/approve` | Approves a pending account; see Approving new accounts below |
| `POST /api/v1/admin/users/{id}/reject` | Rejects a pending account |
| `DELETE /api/v1/admin/users/{id}/sessions` | Revokes every session an account holds |
| `GET /api/v1/admin/audit` | The audit log |
| `GET /api/v1/admin/settings` | The current signup and invite policy |
| `PATCH /api/v1/admin/settings` | Changes the signup and invite policy; see Who may sign up below |

The last active administrator cannot be suspended, demoted out of the administrator role, or
deleted: each of those actions answers `409` and changes nothing while it would leave zero active
administrators. This, too, is a refusal rather than a bug.

`GET /api/v1/admin/audit` pages newest first. Its `before` query parameter, when present, must be
the exact string an earlier call returned as `next_cursor`: `<RFC3339Nano UTC timestamp>_<uuid>`.
An unparseable `before` answers `400 invalid_request`. `next_cursor` in the response names the
cursor for the next page, or JSON `null` once the last page has been returned.

### Configuration

Every setting is read from the environment, over a default that works unconfigured. A value
that fails validation stops the process at startup and names the field, rather than surfacing
later as odd behaviour. See `docs/adr/0006-configuration-loading.md`.

`.env.example` documents the logging, listener, lifecycle, proxy-trust, and telemetry variables
below at their defaults, ready to copy to `.env`; it does not yet cover the database,
authentication, session, or mail variables documented further down. Nothing in the process reads
that file: it is loaded by whatever runs the binary, such as `docker run --env-file`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVICE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SERVICE_LOG_FORMAT` | `console` | `console` or `json` |
| `SERVICE_SERVER_ADDR` | `:8080` | Application listener, `host:port` |
| `SERVICE_ADMIN_ADDR` | `127.0.0.1:9090` | Administrative listener, `host:port` |
| `SERVICE_LIFECYCLE_PRE_DRAIN_DELAY` | `5s` | Time between readiness failing and listeners closing |
| `SERVICE_PROXY_TRUSTED_CIDRS` | (empty) | Comma-separated CIDRs whose forwarded headers are believed |
| `SERVICE_SERVER_MAX_HEADER_BYTES` | `1MiB` | Request line plus headers ceiling |
| `SERVICE_SERVER_MAX_REQUEST_BODY_BYTES` | `1MiB` | Request body ceiling |
| `SERVICE_SERVER_MAX_IN_FLIGHT` | `0` | Concurrent request cap; 0 disables |
| `SERVICE_SERVER_HANDLER_TIMEOUT` | `0s` | Per-request handler deadline; 0 disables, otherwise shorter than `WRITE_TIMEOUT` |

Every `SERVICE_SERVER_*` row above has a `SERVICE_ADMIN_*` counterpart that configures the
administrative listener the same way. `SERVICE_ADMIN_ADDR` is listed separately only because
its default differs.

Both listeners also accept `READ_HEADER_TIMEOUT`, `READ_TIMEOUT`, `WRITE_TIMEOUT`,
`IDLE_TIMEOUT`, and `SHUTDOWN_TIMEOUT` under their own prefix, each a Go duration such as
`30s`. They are tuned to release resources from stalled clients without interrupting ordinary
requests, so changing them is rarely necessary. `READ_TIMEOUT` bounds the whole request and so
must be at least `READ_HEADER_TIMEOUT`; the process refuses to start otherwise.

A duration needs its unit: `30` is refused, because it could mean either seconds or
milliseconds depending on who is reading. A size is a plain count of bytes, or a count with a
suffix, binary (`KiB`, `MiB`, `GiB`, `TiB`) or decimal (`KB`, `MB`, `GB`, `TB`). Both render
in the same notation in the configuration the process logs at startup, so a value read out of
a log can be pasted back into the environment unchanged.

A listen address is `host:port`, where the host may be omitted to bind every interface, or be
a hostname, an IPv4 literal, or a bracketed IPv6 literal such as `[::1]:9090`. Port 0 is
refused: it asks the kernel for a port that nothing can be told to route to.

A variable that is set but empty counts as unset, so an exported-but-empty variable cannot
blank a listen address.

Log output is never sampled. Every served request produces one entry at any request rate,
which is what makes the request log usable for accounting rather than just for spot checks.
Dropping entries under load is a decision for the log pipeline, which can see the whole
stream; a process that samples from inside a single message bucket discards exactly the
traffic that is most worth keeping.

Telemetry is configured through the standard OpenTelemetry variables instead, without this
project's prefix, because the OpenTelemetry specification fixes those names.

### Database

PostgreSQL is required; there is no embedded fallback. The minimum supported server version is 16.
`SERVICE_DB_DSN` has no default and the process refuses to start without it, because a service that
cannot read its own accounts must not serve traffic. Migrations apply automatically at startup
unless `SERVICE_DB_MIGRATE_ON_START=false`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVICE_DB_DSN` | (none, required) | PostgreSQL connection string |
| `SERVICE_DB_MAX_CONNS` | `25` | Maximum pooled connections |
| `SERVICE_DB_MIN_CONNS` | `2` | Connections kept warm |
| `SERVICE_DB_MAX_CONN_LIFETIME` | `30m` | How long a connection is reused before replacement |
| `SERVICE_DB_MAX_CONN_IDLE_TIME` | `5m` | How long an unused connection is kept |
| `SERVICE_DB_CONNECT_TIMEOUT` | `10s` | Bounds the startup connection and its verifying ping |
| `SERVICE_DB_MIGRATE_ON_START` | `true` | Applies pending migrations before serving traffic |

A worked local development DSN:

```
postgres://service:service@localhost:5432/service?sslmode=disable
```

That value is for local development only. A real deployment must use `sslmode=require` or
stronger.

### Running Postgres

```sh
docker compose -f deploy/local/compose.yaml up -d postgres
```

starts the disposable Postgres container the local compose stack adds, and

```sh
docker compose -f deploy/local/compose.yaml down -v
```

stops it and discards its data. This is a developer convenience, not a deployment artifact.

The application's database role needs only `CONNECT` on the database, `USAGE` on its schema, and
`SELECT`, `INSERT`, `UPDATE`, `DELETE` on its tables. It needs DDL privileges too only while
`SERVICE_DB_MIGRATE_ON_START` is true; a deployment that applies migrations out of band ahead of
time can run the service itself with a role that holds none.

Back up and restore with:

```sh
pg_dump -Fc -d "$SERVICE_DB_DSN" -f service.dump
pg_restore -d "$SERVICE_DB_DSN" --clean --if-exists service.dump
```

A backup taken while the service is running is consistent, because `pg_dump` reads from a single
snapshot. Restoring an older dump against a newer binary is not supported, because migrations only
move forward.

### Authentication

There is no password login, and this is deliberate: see `docs/adr/0012-authentication-model.md`.
An account signs in through an OpenID Connect provider, a passkey, or an emailed one-time code.

`SERVICE_AUTH_PUBLIC_ORIGIN` is this service's externally reachable origin, for example
`https://app.example.com`, with no path, query, or trailing slash. It is required whenever an
emailed code or any OpenID Connect provider is enabled, and it is also required at startup for
WebAuthn, which is **enabled by default**: an unconfigured deployment must therefore either set
this variable or set `SERVICE_AUTH_WEBAUTHN_ENABLED=false`, or the process refuses to start. It
must use `https` when `SERVICE_SESSION_COOKIE_SECURE=true`, which is also the default. The passkey
relying party ID defaults to this origin's host when `SERVICE_AUTH_WEBAUTHN_RP_ID` is left unset.

A worked Google OpenID Connect provider:

```sh
SERVICE_AUTH_OIDC_PROVIDERS=google
SERVICE_AUTH_OIDC_GOOGLE_ISSUER=https://accounts.google.com
SERVICE_AUTH_OIDC_GOOGLE_CLIENT_ID=...
SERVICE_AUTH_OIDC_GOOGLE_CLIENT_SECRET=...
```

Register this exact redirect URI with Google:
`<SERVICE_AUTH_PUBLIC_ORIGIN>/api/v1/auth/oidc/google/callback`, for example
`https://app.example.com/api/v1/auth/oidc/google/callback`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVICE_AUTH_WEBAUTHN_ENABLED` | `true` | Registers the passkey routes |
| `SERVICE_AUTH_WEBAUTHN_RP_ID` | (empty) | Relying party identifier; empty means the host of `SERVICE_AUTH_PUBLIC_ORIGIN` |
| `SERVICE_AUTH_WEBAUTHN_RP_DISPLAY_NAME` | `service` | Name an authenticator shows the user |
| `SERVICE_AUTH_OTP_ENABLED` | `false` | Registers the emailed one-time code routes |
| `SERVICE_AUTH_OTP_CODE_TTL` | `10m` | How long an emailed code stays valid |
| `SERVICE_AUTH_OTP_MAX_ATTEMPTS` | `5` | Wrong guesses that invalidate a code |
| `SERVICE_AUTH_FLOW_TTL` | `10m` | How long OIDC and WebAuthn ceremony state survives between its two requests |
| `SERVICE_AUTH_INVITE_TOKEN_BYTES` | `32` | Entropy an invite token carries before base64url encoding; minimum `16` |
| `SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY` | `2160h` | How long an expired invite is kept before the sweeper removes it |
| `SERVICE_AUTH_INVITE_MAX_TTL` | `336h` | The longest lifetime an invite may be issued with, and the ceiling on the configured default invite lifetime |
| `SERVICE_AUTH_INVITE_DEFAULT_MAX_USES` | `1` | The redemption limit an invite gets when issued without one |
| `SERVICE_AUTH_OIDC_<KEY>_SCOPES` | `openid,email,profile` | Scopes requested from that OIDC provider |
| `SERVICE_AUTH_OIDC_<KEY>_DISPLAY_NAME` | Title-cased `<KEY>` | Name shown for that OIDC provider |
| `SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS` | (empty) | Addresses granted the administrator role while no administrator exists yet; see Who may sign up below |

Enabling `SERVICE_AUTH_OTP_ENABLED` without also setting `SERVICE_SMTP_ENABLED=true` fails
startup validation; see Mail below.

The process refuses to start if every authentication method ends up disabled: no OIDC provider
configured, WebAuthn disabled, and email codes disabled. The startup error names the variables
that enable one (`SERVICE_AUTH_OIDC_PROVIDERS`, `SERVICE_AUTH_WEBAUTHN_ENABLED`,
`SERVICE_AUTH_OTP_ENABLED`), because a deployment with no way to authenticate has no way to reach
an admin console either.

`SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS` grants the administrator role once per account, only at the
moment that account is created because its verified email address was on the list, and only
while no active account holds the administrator role yet. An account created any other way, or
one whose address is added to the list after the account already exists, is never granted the
role by this mechanism. Once any administrator exists, a listed address gets no special
treatment: it is admitted, or refused, by the ordinary signup policy exactly like an unlisted
address. Listing several addresses at once grants the role only to whichever of them signs up
first; that administrator promotes the others afterward through
`PATCH /api/v1/admin/users/{id}/roles`. Demotion sticks: nothing at login re-grants the role, and
because the list is exempt only while no administrator exists, deleting the account and signing
up again after the deletion grace period elapses does not regain it either. Removing the
administrator role from a bootstrap-listed account is permanent without also having to edit the
environment.

Every authentication route, plus the `/i/` redemption and QR routes, is rate limited per client IP
address: `SERVICE_AUTH_RATE_LIMIT_PER_MINUTE` (default `10`) and `SERVICE_AUTH_RATE_LIMIT_BURST`
(default `20`). A caller that exceeds it is answered `429`.

### Account deletion

`DELETE /api/v1/me` takes effect immediately: every session the account holds is revoked, and it
cannot sign in again from that moment. The record itself is kept for
`SERVICE_AUTH_DELETED_GRACE_PERIOD` (`720h`, thirty days, by default) so an administrator can
restore it with `PATCH /api/v1/admin/users/{id}/status` and `{"status":"active"}`, within that
window. After that window, the sweeper destroys
the account, its identities, and its credentials permanently; the audit log keeps what it recorded
but no longer names a live account. Setting the grace period to `0` purges the account on the next
sweep, for an erasure request that must be honoured immediately.

**Only `active` restores a deleted account, and only within the grace period.** A status write
against a deleted account naming any other status, such as `suspended`, answers `409` conflict
and leaves the account deleted and unchanged.

**The email address stays reserved for the whole grace period.** A user who deletes an account
cannot immediately sign up again with the same address, because the deleted row still holds it
until the sweeper purges it.

### Who may sign up

The three switches that decide who may create an account, whether an invite is required, and
whether a new account needs administrator approval live in the database rather than the
environment, and are changed with `PATCH /api/v1/admin/settings` without restarting anything; see
`docs/adr/0015-configuration-sources-and-precedence.md`. The shipped defaults are signup on,
invite required, approval off, and a member invite quota of zero.

Reading the policy:

```sh
curl -s https://app.example.com/api/v1/admin/settings -H "Cookie: __Host-service_session=..."
```

Changing one key:

```sh
curl -s -X PATCH https://app.example.com/api/v1/admin/settings \
  -H "Cookie: __Host-service_session=..." \
  -H "Content-Type: application/json" \
  -d '{"signup_require_approval": true}'
```

`SERVICE_AUTH_SIGNUP_ENABLED` is a break-glass override of `signup_enabled`. Once it is set, it
locks that key against the API until the variable is unset again, and
`GET /api/v1/admin/settings` reports it in its `locked` array.

**A deployment that starts with signup disabled and no `SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS` can
never create its first account. Set that variable before the first start, or start with signup
enabled long enough to create yourself.** The process only warns about this at startup; it has no
way to fail loudly at a moment when nobody has tried to sign in yet.

The recovery procedure, for an operator who already hit this and therefore has no account and no
API to call: set `SERVICE_AUTH_BOOTSTRAP_ADMIN_EMAILS` to the intended administrator's address and
restart, then sign in through any configured provider that verifies that address, which grants
`admin` immediately. If no configured provider verifies that address, set
`SERVICE_AUTH_SIGNUP_ENABLED=true`, restart, create the account, then unset the variable and
restart again. There is deliberately no offline account-creation command: a binary that can mint
an administrator is a binary that can be made to mint one.

### Invites

An invite is either bound to one email address or redeemable by any holder up to a use limit, and
both kinds expire, defaulting to `invite_default_ttl_secs` (`1209600`, fourteen days).

```sh
curl -s -X POST https://app.example.com/api/v1/invites \
  -H "Cookie: __Host-service_session=..." \
  -H "Content-Type: application/json" \
  -d '{"email":"cousin@example.com","note":"cousin","max_uses":1}'
```

```json
{"id":"...","url":"https://app.example.com/i/nEo4...","token":"nEo4...","qr_url":"https://app.example.com/i/nEo4....png","email":"cousin@example.com","note":"cousin","max_uses":1,"uses":0,"created_at":"...","expires_at":"...","revoked_at":null,"state":"live"}
```

**The link is shown exactly once and cannot be recovered:** only its digest is stored, so a lost
link must be revoked and reissued rather than looked up. `GET /i/<token>.png` renders a QR code of
the same link for printing or screen-sharing.

The access log and trace spans record the route pattern `/i/{file}` for both invite routes,
never the raw path, so the token itself never reaches a log or a trace collector. This includes
a request the per-IP rate limiter refuses with `429`, a request answered earlier in the
middleware chain (a cross-site rejection, a permission denial), and a request whose path starts
with `/i/` but matches no route at all, since redaction is keyed on the path prefix and applied
before anything else in the chain runs, not only once a route has matched.

A member may issue invites only once an administrator raises `invite_default_quota` above zero
through `PATCH /api/v1/admin/settings`. The quota counts invites that are still live, not invites
ever issued. Revoking an invite with `DELETE /api/v1/invites/{id}` stops future redemptions but
does not affect accounts it already created.

### Approving new accounts

With `signup_require_approval` on, a new account is created but cannot sign in: its owner is
redirected with `error=approval_pending` instead of receiving a session.
`GET /api/v1/admin/users?status=pending` is the approval queue. `POST
/api/v1/admin/users/{id}/approve` approves an account and `POST /api/v1/admin/users/{id}/reject`
rejects one; either against an account whose status is not `pending` answers `409` and changes
nothing. Rejecting soft-deletes rather than destroys, so a rejection made in error is recoverable
for the same grace period every other deletion gets.

### Sessions

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVICE_SESSION_COOKIE_NAME` | `__Host-service_session` | The session cookie's name |
| `SERVICE_SESSION_COOKIE_SECURE` | `true` | Sets the cookie's `Secure` attribute |
| `SERVICE_SESSION_IDLE_TIMEOUT` | `720h` | How long a session survives without use |
| `SERVICE_SESSION_ABSOLUTE_TIMEOUT` | `2160h` | A session's hard lifetime, whether or not it is used |
| `SERVICE_SESSION_CLEANUP_INTERVAL` | `1h` | How often expired sessions, ceremony state, one-time codes, expired invites, and deleted accounts past their grace period are swept |

**A cookie name beginning with `__Host-` requires `SERVICE_SESSION_COOKIE_SECURE=true`. The
process refuses to start otherwise, because a browser silently discards such a cookie and every
login would appear to succeed and then fail.**

`SERVICE_SESSION_CLEANUP_INTERVAL` also drives removal of an invite once it has been expired for
`SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY`, and, as the last step of every sweep, the permanent
purge of every account whose `SERVICE_AUTH_DELETED_GRACE_PERIOD` has elapsed. The first sweep
runs immediately at startup, not one interval after it, so a process that restarts more often
than its configured interval still purges accounts on schedule.

### Mail

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVICE_SMTP_ENABLED` | `false` | Whether mail can be sent at all |
| `SERVICE_SMTP_HOST` | (empty) | SMTP server hostname |
| `SERVICE_SMTP_PORT` | `587` | SMTP server port |
| `SERVICE_SMTP_USERNAME` | (empty) | SMTP username; empty sends unauthenticated |
| `SERVICE_SMTP_PASSWORD` | (empty) | SMTP password |
| `SERVICE_SMTP_FROM` | (empty) | Envelope and header sender address |
| `SERVICE_SMTP_TLS_POLICY` | `starttls` | `starttls`, `tls`, or `none` |
| `SERVICE_SMTP_TIMEOUT` | `10s` | Bounds a single send |

Mail is disabled by default. Enabling `SERVICE_AUTH_OTP_ENABLED` without also setting
`SERVICE_SMTP_ENABLED=true` fails startup validation.

### Calling another service

`internal/httpclient` builds outbound HTTP clients. Use it rather than `http.Get` or
`http.DefaultClient`: those have no timeout, share one connection pool with everything else
in the process, and send no trace context, so a slow dependency holds the inbound request
that triggered it and the two halves of one user action land in two traces.

```go
client, err := httpclient.New(httpclient.Default(), httpclient.Telemetry{
	TracerProvider: tracerProvider,
	MeterProvider:  meterProvider,
	Propagator:     propagator,
})
```

What comes back is an ordinary `*http.Client`, so it can be handed to any SDK that takes
one. Build one per dependency rather than one for the process: the pool limits that suit a
dependency are a property of that dependency, and a shared pool exhausted by one peer
starves the rest.

Requests honour `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` on the same terms the standard
library's default transport does, so a service deployed behind an egress gateway needs no
change here.

The client does not retry, back off, or open a circuit. Retrying is safe only for a call
the caller knows to be idempotent, which is knowledge the call site has and the client does
not.

`httpclient.Config` carries the timeouts and pool limits, each with an `env` tag and no
prefix of its own. A service composes it into its configuration under whatever prefix names
the dependency, and the settings then appear in the effective configuration logged at
start-up like any other:

```go
type Config struct {
	Billing httpclient.Config `env:", prefix=SERVICE_BILLING_" json:"billing"`
}
```

That declares `SERVICE_BILLING_TIMEOUT`, `SERVICE_BILLING_CONNECT_TIMEOUT`,
`SERVICE_BILLING_TLS_HANDSHAKE_TIMEOUT`, `SERVICE_BILLING_RESPONSE_HEADER_TIMEOUT`,
`SERVICE_BILLING_MAX_CONNS_PER_HOST`, `SERVICE_BILLING_MAX_IDLE_CONNS`,
`SERVICE_BILLING_MAX_IDLE_CONNS_PER_HOST`, and `SERVICE_BILLING_IDLE_CONN_TIMEOUT`.
Defaults are on the `Default*` constants in the package. No variable exists until a service
composes the struct, which is why none is listed in the table above.

### Tracing

Tracing is off until a collector is configured, through the standard OpenTelemetry variables:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 OTEL_SERVICE_NAME=service go run ./cmd/service
```

`OTEL_EXPORTER_OTLP_ENDPOINT` is the collector's base URL: traces go to its `/v1/traces` path.
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` names a traces-only collector by its full URL, used exactly
as given, and takes precedence over the general endpoint when both are set, as the
OpenTelemetry specification requires.
With no endpoint set, the tracing pipeline hands back a no-op tracer provider and
instrumentation costs a few comparisons per request. Providers are passed to the HTTP
instrumentation explicitly through `server.Telemetry` rather than read from OpenTelemetry's
process-wide globals. Inbound `traceparent` headers are still read and propagated either
way, so this process is never the hop where a distributed trace breaks. Request log lines
carry `trace_id` and `span_id` when a span is active. See
`docs/adr/0004-use-opentelemetry-for-tracing.md`.

### Local observability

```sh
docker compose -f deploy/local/compose.yaml up --build
```

builds the image and runs it behind an nginx gateway, beside Jaeger and Prometheus, wired
together: the service exports traces to Jaeger over OTLP/HTTP, and Prometheus scrapes the
administrative listener, which is bound to all interfaces inside the Compose network so it
can be reached by service name. Traces are at `http://localhost:16686`, metrics at
`http://localhost:9091`, the service at `http://localhost:8080`. Every published port is
bound to loopback on the host, so the stack is not offered to any network the machine
happens to be on; inside the Compose network the containers still reach each other by name.

The gateway is there because `docs/adr/0007-deployment-topology.md` says the service is
always deployed behind a reverse proxy, and everything downstream of that decision, the
forwarded client address and the correlation ID, has no way to be wrong locally if nothing
local sets those headers. `http://localhost:8080` is the gateway; the application listener
is not published, so the direct path the ADR rules out is not the one a developer
bookmarks. `deploy/local/nginx.conf` is a starting point for a real proxy configuration:
no TLS, no redirect, no HSTS, no compression, all of which belong to the production proxy,
but the `proxy_set_header` block carries over unchanged, and the comments there explain why
`X-Forwarded-For` is replaced rather than appended. `SERVICE_PROXY_TRUSTED_CIDRS` names the
gateway's address alone, which is what makes the service believe those headers. See
`specs/007-local-gateway/`.

This is a developer convenience, not a deployment artifact.

## Deployment

This service must run behind a TLS-terminating reverse proxy. It is not safe to expose directly
to the internet. See `docs/adr/0007-deployment-topology.md`.

Kubernetes probes point at the administrative listener on port 9090, since `/healthz` and
`/readyz` are operational endpoints and are not served on the application listener:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

`terminationGracePeriodSeconds` must exceed `SERVICE_LIFECYCLE_PRE_DRAIN_DELAY` plus
`SERVICE_SERVER_SHUTDOWN_TIMEOUT`, or the kubelet will `SIGKILL` the process mid-drain.

An nginx `location` block forwards the client address and a request ID:

```nginx
location / {
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Request-Id $request_id;
    proxy_pass http://127.0.0.1:8080;
}
```

Neither header is believed unless the proxy's address is listed in
`SERVICE_PROXY_TRUSTED_CIDRS`. Every entry must be a network rather than a bare address, so
`10.0.0.0/8` and `2001:db8::/32` are accepted and `10.0.0.1` is not. An entry that does not
parse stops the process at startup: a typo in a trust boundary must not silently narrow it.
Empty entries, which a trailing or doubled comma leaves behind, are ignored.

Compression and HSTS are the proxy's job and are deliberately absent from the binary.

## Building

```sh
go tool mage -l
```

lists the available targets. No global install is needed: the mage version is pinned by the
tool directive in `go.mod`. The targets are:

| Target | Purpose |
| --- | --- |
| `Build` | Compiles the server into `bin/service` with version information stamped in |
| `Test` | Runs the unit test suite |
| `Race` | Runs the unit test suite under the race detector, the form CI gates on |
| `Integration` | Runs the build-tagged integration suite |
| `Lint` | Runs the `go.mod`-pinned golangci-lint against the repository root configuration, then again over the build-tagged integration suite |
| `Cover` | Runs the test suite with coverage and reports the per-function summary |
| `Vuln` | Scans dependencies and the standard library for known vulnerabilities |
| `Tidy` | Prunes and refreshes the module requirements |
| `Docker` | Builds the container image |
| `ReleaseCheck` | Validates `.goreleaser.yaml` without building anything |
| `Snapshot` | Builds both release architectures and their images locally, publishing nothing |
| `Run` | Builds and starts the server with the current working configuration |
| `Clean` | Removes build and coverage output |

`go tool mage docker` builds the container image. The admin listener binds loopback inside
the container too, so scraping it from outside requires setting `SERVICE_ADMIN_ADDR`.

## Releases

Pushing a tag of the form `vX.Y.Z` publishes a multi-architecture image to
`ghcr.io/uhdaptuhbl/service`, tagged `X.Y.Z`, `X.Y`, `X`, and `latest`, with release notes
generated from the commit subjects since the previous tag. Nothing else is published: the
image is the artifact, and `docs/adr/0007-deployment-topology.md` says why there is no loose
binary beside it.

Rehearse first. The release workflow's next chance to fail is otherwise the tag itself:

```sh
go tool mage releasecheck   # the configuration parses
go tool mage snapshot       # both architectures and both images, published nowhere
git tag -a v1.2.3 -m "v1.2.3" && git push origin v1.2.3
```

A snapshot builds one image per architecture with a platform suffix rather than a single
manifest, because buildx cannot load a multi-platform manifest into a local daemon.

The same lint, race, and vulnerability gates CI applies to a branch run again on the tag,
before anything is published. A tag that does not match `v*.*.*` starts nothing.

### Verifying an image

Every published image is signed with a keyless Sigstore signature whose identity is this
repository's release workflow, so verification asks "which workflow in which repository built
this" rather than "do I have the right public key". There is no key to distribute:

```sh
cosign verify ghcr.io/uhdaptuhbl/service:1.2.3 \
  --certificate-identity-regexp '^https://github.com/uhdaptuhbl/template-go-multi-user-web/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Public repositories additionally carry a build provenance attestation:

```sh
gh attestation verify oci://ghcr.io/uhdaptuhbl/service:1.2.3 --repo uhdaptuhbl/template-go-multi-user-web
```

This repository is private, where GitHub does not issue attestations outside Enterprise
Cloud, so that step is skipped here and runs unchanged in a public project built from this
one. Signing is not affected. See `specs/004-release-automation/`.

## Development

```sh
go tool mage race
go tool mage lint
go tool mage integration
```

All three must pass before a change is considered done; they are the same commands CI
gates on. `CONTRIBUTING.md` covers setup and how a change is shaped, and `CLAUDE.md` holds
the full definition of done.

`go tool mage integration` runs `go test -race -tags=integration ./...`. Every database test
lives behind that build tag. It starts a throwaway Postgres container automatically when
`SERVICE_TEST_DB_DSN` is unset; setting `SERVICE_TEST_DB_DSN` points it at an existing server
instead. When neither a Docker daemon nor a reachable server is available, it skips rather than
fails.

## Layout

```
cmd/service/         Entrypoint: wiring only, no business logic
internal/buildinfo/  The binary's build identity, stamped in at link time
internal/config/     Environment decoding and validation
internal/configtype/ Setting types that read and render the way an operator writes them
internal/httpclient/ Outbound HTTP clients: bounded, pooled per dependency, traced
internal/logging/    Zap logger construction and the slog-to-zap bridge
internal/server/     HTTP listeners, routing, middleware, graceful shutdown
internal/signals/    Second-signal handling during shutdown
internal/telemetry/  OpenTelemetry tracing and metrics setup
internal/web/        Embeds and serves the built frontend
internal/secret/     Generic secret-string redaction, independent of configuration decoding
internal/store/      Postgres connection pool, its limits, and its health check
internal/store/migrations/ Goose-driven schema migrations, applied at startup
internal/store/storetest/  A disposable Postgres for the integration suite
internal/mail/       SMTP delivery for emailed one-time codes
internal/ratelimit/  Per-key token-bucket rate limiting for authentication routes
internal/user/       Accounts and their external identities
internal/session/    Session issuance, cookies, and expiry
internal/audit/      The append-only audit log
internal/authz/      Roles, permissions, and the last-admin rule
internal/authflow/   Server-side state for a login or link ceremony's two requests
internal/settings/   The runtime signup and invite policy
internal/invite/     Invite issuance, redemption, and QR rendering
internal/auth/       Authentication routes, sessions, signup admission, and account management
internal/auth/oidc/     OpenID Connect provider registry and login ceremonies
internal/auth/passkey/  WebAuthn registration and assertion ceremonies
internal/auth/otp/      Emailed one-time login codes
deploy/local/        Compose stack: the service behind a gateway, with traces, metrics, and Postgres
docs/adr/            Architecture decision records
specs/               Per-feature requirements, design, and tasks
```

A feature route lives in `internal/server` or a package beside it and is registered through
the `api` function `NewMux` takes, the way `internal/auth` registers its routes.
`server.DecodeJSON` reads its request, `server.WriteJSON` writes its response, and
`server.WriteError` turns an error into the one error body every endpoint shares: a
top-level `errors` array whose members borrow JSON:API's names, described in
`docs/adr/0010-json-api-response-conventions.md`. A handler that wants the client to learn
anything about a failure returns a `server.ClientError`; `errors.Join` several of them and
each becomes its own error object, so a validation failure reports every bad field at once.
Any other error is a 500 whose cause reaches the log and never the client.

There is no frontend source tree yet. `CLAUDE.md` fixes its location as `ui/`;
`docs/adr/0002-frontend-stack.md` is still open and decides the stack that goes there.
Whatever that turns out to be, its build writes into `internal/web/dist/` rather than a
`dist/` beside the source, because `go:embed` cannot reference paths outside its own package
directory.

## Documentation

- `CLAUDE.md`: engineering standards, development model, and definition of done
- `CONTRIBUTING.md`: setup, the gates to run, and commit conventions
- `CODE_OF_CONDUCT.md`: the Contributor Covenant, and how to report a problem
- `SECURITY.md`: how to report a vulnerability, and what is in scope
- `.env.example`: the logging, listener, lifecycle, proxy-trust, and telemetry variables at
  their defaults
- `docs/adr/`: architecture decisions, including open ones recorded as `proposed`
- `specs/templates/`: the three documents each feature carries

## License

Apache License 2.0. See [LICENSE](LICENSE). A project started from this template may
relicense its own work; the template imposes no restriction beyond Apache 2.0's terms.
