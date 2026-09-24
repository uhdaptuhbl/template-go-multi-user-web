---
status: accepted
date: 2026-09-22
---

# 14. Session management

## Context and Problem Statement

The browser frontend is served by the same binary, from the same origin, as the API it
calls. There is no service-to-service token requirement here: nothing downstream of this
service needs to verify a caller's identity independently, and nothing upstream of it hands
tokens to a second party. The only consumer of a session credential is the browser that
received it.

A public multi-user service has a baseline expectation that does not follow automatically
from any authentication scheme: a user who loses a device, or suspects one, must be able to
log out everywhere and have that take effect immediately. Whatever holds a user's
authenticated state after login has to be revocable on demand, not merely expirable on a
timer. This record settles how that state is held, what the browser carries on each request,
and how the request that changes state is told apart from one a hostile site forged.

## Decision Drivers

- **Immediate revocability.** "Log out everywhere" must invalidate every other session the
  instant it is requested, not at the next natural expiry.
- **Single origin.** The frontend and the API share an origin, so nothing here needs to
  survive being read by a second service or a second origin.
- **Credential material must survive a database leak.** A backup or a dump reaching the wrong
  hands must not hand out live sessions.
- **Cookie behavior must be safe by default**, consistent with this project's preference,
  recorded in `docs/adr/0008-proxy-trust-and-request-identity.md`, for a default state that is
  also the safe state.
- **CSRF defense must not depend on JavaScript running on the page**, since it has to hold for
  a plain HTML form submission as well as a fetch call.

## Considered Options

### Session representation

- Opaque server-side session tokens, with the session record held in the database
- JSON Web Tokens, signed and held only by the browser

### Stored credential form

- Store a SHA-256 digest of the token
- Store the token itself

### Cookie shape

- `__Host-service_session`, `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure`, no `Domain`
- A conventionally-named cookie with `Domain` set to the deployment's host

### CSRF defense

- Header inspection: `Sec-Fetch-Site`, falling back to `Origin`
- Synchronizer token pattern (a per-session CSRF token embedded in forms and verified on
  submit)

## Decision Outcome

Chosen: **opaque server-side session tokens, held in a cookie, with the session record in the
database. The database stores a SHA-256 digest of the token, never the token. The cookie is
named `__Host-service_session` with `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure`, and no
`Domain`. CSRF is defended by inspecting `Sec-Fetch-Site` and `Origin` on state-changing
requests, not by a synchronizer token.**

### Opaque tokens over JSON Web Tokens

Statelessness is the entire case for a JWT, and it is not a case this service can spend: the
frontend and the API already share an origin, so there is no second party a stateless token
would let this service avoid coordinating with. What a JWT buys here is paid for with real
costs. A JWT cannot be revoked before it expires without reintroducing a server-side check per
token, which erases the statelessness it was chosen for. It requires a signing key that must
be generated, stored, and rotated, and rotation itself invalidates every outstanding token
unless the old key is kept around to verify against. And a JWT invites a well-documented
family of implementation mistakes, algorithm confusion between `none` and a real algorithm,
accepting a token signed with the wrong key, trusting unvalidated claims, that an opaque
random string cannot have, because an opaque string carries no algorithm and no claims to get
wrong. An opaque server-side session, checked against a database row on every request, gives
immediate revocation for free and has no signing key to manage.

### The database stores a digest, not the token

A session cookie is a bearer credential: whoever holds the string is treated as the user it
belongs to, with no further proof required. A database dump or a backup leak that contained
the tokens themselves would hand out every live session it captured. Storing a SHA-256 digest
instead means a leak of the table yields values that authenticate nothing; a presented token is
hashed on lookup and matched against the stored digest, so the comparison never needs the
plaintext to be stored anywhere.

### The `__Host-` cookie prefix

The `__Host-` prefix is a browser-enforced constraint, not a convention: a browser refuses to
accept a cookie named with that prefix unless the cookie also sets `Secure`, sets `Path=/`,
and omits `Domain` entirely. Meeting those three conditions removes an entire class of
subdomain cookie-fixation attack, where a cookie scoped by `Domain` to a parent domain can be
set by a compromised or attacker-controlled subdomain and then ridden by the real service. A
conventionally-named cookie with `Domain` set was considered and rejected for exactly that
reason: it works, but it leaves that class of attack available for no benefit this project
needs, since the service is never split across subdomains that would require a shared cookie
scope.

`SERVICE_SESSION_COOKIE_SECURE=false` exists only to allow local development over plain HTTP,
where a browser has nothing to negotiate TLS with. Startup validation rejects the combination
of a `__Host-`-prefixed cookie name with `Secure` disabled, because a browser would silently
drop such a cookie rather than error, and a login that appears to succeed but never leaves a
usable session is a worse failure mode than refusing to start.

### Two independent expiries

A session carries an idle timeout, which advances on every authenticated request and defaults
to 30 days, and an absolute lifetime, which is fixed at session creation and never moves,
defaulting to 90 days. The idle timeout keeps an inactive session from lingering forever; the
absolute lifetime bounds how long a continuously-used session can live before it is forced to
reauthenticate, independent of how active it has been. Either one expiring ends the session.

The session cookie's own lifetime follows the server-side session rather than being set once
at login. It is issued with a MaxAge equal to the shorter of the idle timeout and the time
left before absolute expiry, and it is issued again on an authenticated request once an hour
has passed since it was last issued, so an active browser keeps its cookie for as long as the
server keeps the session.

### Session identifier regeneration on authentication

The session identifier is regenerated on every successful authentication, and the session row
that existed before authentication, if any, is deleted rather than reused. This closes session
fixation: an attacker who set a victim's pre-authentication session identifier, by any means,
gains nothing once that identifier stops being valid the moment the victim actually logs in.

### CSRF: header inspection, not a synchronizer token

On every request whose method is not `GET`, `HEAD`, or `OPTIONS`, and which carries the
session cookie, the request is accepted only if one of two checks passes: `Sec-Fetch-Site` is
present and its value is `same-origin` or `none`, or, when `Sec-Fetch-Site` is absent, the
`Origin` header is present and matches the configured public origin exactly. A request with
neither header is rejected with 403, not treated as trusted by default. A modern browser
always sends one of the two on a cross-origin state-changing request, so a request presenting
neither did not originate from a browser context this service has any reason to trust, and a
non-browser client is free to set `Origin` explicitly if it wants to be trusted. Rejecting the
absence of both, rather than treating it as permissive, is what makes this a defense rather
than a formality.

`SameSite=Lax` on the cookie is retained as defense in depth, not as the primary control: it
does not cover every navigation case a state-changing request can arrive through, most notably
a top-level form navigation, which `Lax` still allows to carry the cookie. The header check
above is the control that actually has to hold.

A synchronizer token was considered and rejected on complexity relative to what it buys here.
It requires a token to be minted, embedded in every form and every API client's state, and
verified server-side on every submission, and every one of those steps is a place to get it
wrong. The header check needs no state to mint, embed, or verify; it reads headers the browser
already sends and cannot be told to omit.

### Consequences

- Every authenticated request costs one indexed primary-key lookup, keyed on the token digest,
  plus a small update to advance the idle timeout, plus one query resolving the account's
  permissions through its roles. None is free, but all are cheap and well within what a single
  database instance handles at this service's scale.
- Revocation is immediate: deleting a session row ends that session on its very next request,
  and "log out everywhere" is deleting every row belonging to a user.
- A user can be shown their own active sessions and end any of them individually, since each
  is a distinct, addressable row.
- If horizontal scaling later makes the per-request write to advance the idle timeout costly,
  the answer is a cache in front of the session table, for example a short-lived in-memory or
  Redis-backed read-through cache, not a switch to JWTs. That keeps revocation immediate while
  removing the write from the hot path.

## More Information

- `docs/adr/0012-authentication-model.md`, which settles how a user establishes the session
  this record manages.
- `docs/adr/0007-deployment-topology.md`, which is why `Secure` is always the correct setting
  in a real deployment: the service is never reachable except behind a TLS-terminating proxy.
- [MDN: Set-Cookie, cookie prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes)
- [MDN: Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
