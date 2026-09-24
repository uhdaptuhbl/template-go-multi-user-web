---
status: accepted
date: 2026-09-22
---

# 15. Configuration sources and precedence

## Context and Problem Statement

`docs/adr/0006-configuration-loading.md` established environment-only configuration: values
are read once at startup through `internal/config`, validated, and held immutable for the
life of the process. That record was correct for what existed then, where nothing needed to
change without a restart.

The signup policy breaks that assumption. It needs to change during an incident without a
redeploy, it needs to take effect on every replica at once the moment it changes, and it
needs an audit row naming who changed it. An environment variable satisfies none of the
three: changing it means a redeploy, a redeploy does not reach every replica atomically, and
an environment variable has no author.

There are now two ways to configure this service, and the question this record answers is
which setting goes where, how the two interact when they disagree, and what happens when an
operator needs to override the database from outside it.

## Decision Drivers

- **Runtime mutability without a redeploy.** An operator closing signup during an incident
  cannot wait for a build and a rollout.
- **Immediate effect on every replica.** A policy change must not be visible on some
  instances and not others while a rollout catches up.
- **An audit trail naming who changed a setting and when**, which an environment variable
  exported into a deployment manifest does not carry.
- **No cross-replica cache invalidation problem.** Whatever is chosen must not require
  inventing a mechanism to tell every replica a value changed.
- **A deploy-only escape hatch that an attacker holding a session cookie cannot reach**, for
  the case where the runtime source itself is being used against the operator.
- **Consistency with ADR 0006.** The environment remains the source for anything that cannot
  change without a restart anyway; this record must not quietly duplicate that layer.

## Considered Options

- Keep every setting in the environment, including signup policy, accepting a redeploy per
  change
- Move signup policy into a `settings` table in Postgres, read live, with environment
  variables answering everything else
- Move signup policy into Postgres and cache it in each replica's memory, invalidated on
  change

## Decision Outcome

Chosen: **two sources, divided by the question each answers**, with a single break-glass
environment override for the one setting an incident responder needs fastest, and the
database row read live rather than cached.

### The environment answers what this process is connected to and what it is permitted to do

The DSN, the secrets, the cookie attributes, the timeouts, and which authentication methods
exist at all stay in the environment, unchanged from ADR 0006. None of those can change
without a restart anyway: a new authentication method needs code, a new timeout needs the
server rebuilt around it, and a changed DSN needs a new connection pool. Putting them in a
runtime-mutable store would not make them runtime-mutable in any way that matters, and it
would spread the configuration surface across two places for no benefit.

### The `settings` table answers who may join right now

Anything that can be decided while the process is running, and that an operator may need to
change under pressure, belongs in the table instead. This feature puts six settings there:

- `signup_enabled`
- `signup_require_invite`
- `signup_require_approval`
- `invite_default_quota`
- `invite_default_ttl_secs`
- `invite_max_uses_limit`

Adding a seventh is a migration and an entry in this record, not a judgment call made at the
call site. The dividing line is the driver above, not convenience: a setting goes in the
table because an operator needs to change it without a restart, not because it happens to be
easy to add a column for.

### One break-glass override: `SERVICE_AUTH_SIGNUP_ENABLED`

When this environment variable is set, it replaces the `signup_enabled` column entirely,
locks that key against `PATCH /api/v1/admin/settings`, and is reported in that endpoint's
`locked` array so an operator reading the response can see why a write was rejected.

The scenario it exists for: an administrator account is compromised and is opening the doors
faster than an operator holding the admin API can close them. `PATCH
/api/v1/admin/settings` is reachable by anyone holding a valid admin session, which is
exactly the credential that scenario assumes is no longer trustworthy. The deploy surface is
not: it is the one an attacker holding a session cookie does not control, because reaching it
requires access this feature's threat model does not grant to a compromised session.

There is one override, not six. Closing signup entirely subsumes every narrower restriction
that could be layered under it: an invite requirement or an approval requirement only matters
if signup is open at all, so overriding those independently while leaving `signup_enabled`
readable from the database buys nothing an incident responder needs. Five more overrides
would also be five more ways for the two sources to disagree, five more entries in the
`locked` array to explain, and five more paths an operator must remember exist. One override,
covering the one action that actually stops the bleeding, is the smaller surface.

### The settings row is read live and never cached

`signup_enabled`, `signup_require_invite`, `signup_require_approval`, and the three invite
defaults are read directly from the database on every account creation and every invite
issuance. This looks like an oversight the first time it is read, so the reasoning is
recorded rather than just the rule.

The table this reads from is one row, and Postgres keeps a one-row table's pages in shared
buffers; there is no measurable cost to remove by caching it. Caching it would introduce
cross-replica invalidation, which is the only genuinely hard problem this design would
otherwise contain: some mechanism to tell every other replica a value changed, a TTL to
bound how stale a replica's view is allowed to get, and a failure mode for what a replica
does when it cannot reach whatever tells it to invalidate. All of that would be paid in
exchange for nothing, since the thing being cached is already as cheap to read as a value
already in memory. Reading live also delivers the driver this record opened with directly: a
policy change takes effect everywhere the instant its transaction commits, with no
propagation delay to reason about.

### The policy is read inside the transaction that acts on it

Reading policy at handler entry and creating the account, or issuing the invite, several
round trips later is a race. An operator closing signup during an incident would lose it: a
request that read `signup_enabled = true` a moment before the operator's `PATCH` committed
would still create the account after the door was supposedly shut. Reading the settings row
inside the same transaction that inserts the account or the invite closes that window.
`READ COMMITTED`, Postgres's default, is sufficient for this: nothing here needs
`SERIALIZABLE`, because the property being protected is "this transaction saw a policy that
was still current when it read it," not a property spanning multiple transactions.

## Pros and Cons of the Options

### Keep every setting in the environment, including signup policy

- Good: one configuration mechanism, exactly what ADR 0006 already built and this record
  would not need to extend.
- Bad: closing signup during an incident needs a redeploy, which is too slow for the
  scenario that motivates wanting a toggle at all.
- Bad: a redeploy does not reach every replica atomically, so a rolling update leaves some
  replicas honoring the old policy while others honor the new one.
- Bad: no audit trail naming who changed the value, since an environment variable in a
  deployment manifest carries no author.

### Move signup policy into a `settings` table, read live

- Good: changes take effect without a redeploy and on every replica at once, the moment the
  transaction that wrote them commits.
- Good: a one-row table is cheap enough in Postgres's shared buffers that reading it on
  every relevant request costs nothing measurable.
- Good: no cross-replica invalidation problem, because there is nothing to invalidate.
- Good: writes go through `PATCH /api/v1/admin/settings`, which can record who made the
  change.
- Bad: there are now two places to look when a behavior is unexplained: the environment and
  the database.
- Bad: startup validation can no longer prove the service is correctly configured on its
  own, since half the policy is data rather than something the loader can see.

### Move signup policy into Postgres and cache it in each replica's memory

- Good: removes even the cost of a one-row read on the request path, though that cost is
  already immeasurable.
- Bad: introduces cross-replica cache invalidation, the exact hard problem the chosen option
  avoids, in exchange for a performance gain nothing here needs.
- Bad: a policy change is only as fast as the slowest replica's cache TTL, which reintroduces
  the propagation delay the chosen option exists to remove.
- Revisit when: the settings table grows far beyond a handful of rows and is read on a path
  hot enough that a single-row lookup is measured to matter, which this feature's traffic
  does not approach.

## More Information

**Consequences.** There are now two places to look when a behavior is unexplained, which is
the real cost of this decision. `GET /api/v1/admin/settings` exists partly so the second
place, the database, is inspectable without a database client: an operator can read the
effective policy the same way they would read an environment-backed setting, through the
API rather than a query. Startup validation can no longer prove the service is correctly
configured on its own, because half the policy is data and data is not present at startup
validation time. A misconfigured `SERVICE_AUTH_SIGNUP_ENABLED` is discoverable only through
the `locked` array in the settings response, which is why that field is in the response body
rather than left implied by a write simply failing.

- `docs/adr/0006-configuration-loading.md`, on environment-based configuration loading, which
  this record extends rather than supersedes.
- `docs/adr/0012-authentication-model.md`, on the authentication model that owns the
  admission rules this policy governs.
