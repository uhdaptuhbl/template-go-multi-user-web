---
status: accepted
date: 2026-09-22
---

# 13. Authorization model

## Context and Problem Statement

The service's users-and-auth feature needs two kinds of authorized actor from day one:
administrators who manage accounts across the service, and ordinary members who manage only
their own. A further kind, ad-hoc groups of users sharing access to something neither owns
outright, is planned but not part of this feature. The authorization model chosen now must
answer both questions in front of it, admin versus member, without requiring a rework of
every protected handler when groups arrive later.

The question is not only which roles exist, but what a handler checks to decide whether a
request may proceed, and where the check lives that decides a member can see their own
session but not someone else's.

## Decision Drivers

- **Two actor kinds ship now; a third is planned.** Whatever shape ships must not need every
  handler touched again when groups are added.
- **Role names are configuration, not code.** A role's membership and its permissions can
  change without a deploy; what a handler requires should not have to change alongside it.
- **Ownership and permission are different questions.** Being allowed to act on user resources
  in general is not the same question as which row a specific request may touch.
- **Testability with real collaborators**, consistent with this project's preference for
  exercising real code paths over mocked ones.
- **A future policy engine must be a contained swap**, not a rewrite of every call site that
  makes an authorization decision.

## Considered Options

- A single `role` enum column on `users`, checked by name in each handler
- Role-based access control checked at permission granularity, with ownership enforced in the
  data layer
- `github.com/casbin/casbin`
- Open Policy Agent (OPA) with Rego
- SpiceDB or OpenFGA, Zanzibar-style relationship-based access control

## Decision Outcome

Chosen: **role-based access control checked at permission granularity, plus ownership scoping
enforced in the data layer.** Roles hold permissions, users hold roles, and a handler requires
a named permission rather than a named role. Two roles ship: `admin`, which holds every
permission, and `member`, which holds none for authorization purposes.

### Go code never branches on a role name

A handler that needs administrative access requires the permission `user.role.grant`, or
another permission from the set below; it never checks `user.role == "admin"`. The reason is
where the rule ends up living. A role name is a label an operator can rename or repurpose
without recompiling anything, and a role's membership in a permission is exactly the kind of
fact that belongs in the database rather than in Go source. A role name embedded in a
conditional is an authorization rule that no longer lives in the database: it has leaked into
the binary, and changing it now requires a code change and a release instead of a data change.
Checking a permission instead keeps every authorization rule in one place, the roles and their
grants, and keeps the handler asking the only question it is entitled to ask: does this caller
hold this permission.

Two rules are the exception, and both name the `admin` role in Go because they are about that
role itself rather than about access to a route. The last-administrator guard refuses any
role change, suspension, or self-deletion that would leave no active account holding `admin`,
since a permission check cannot express "the last holder of this role". The bootstrap grant
gives `admin` to an address on the configured bootstrap list, since the list exists to create
the first administrator before any role can be granted through the API. Neither rule decides
whether a request may proceed on its own; every route still requires a permission.

### `member` holding no permissions is correct

Every self-service action, a member reading their own profile, listing their own sessions,
revoking their own session, is authorized by ownership, not by a permission. Ownership is
expressed as a `WHERE user_id = $N` predicate in the query that fetches the row, not as a
permission check earlier in the handler. The reason is what a permission check can and cannot
prove: a permission check that passes still returns another user's row if the query that
follows it does not scope the result to the caller. Permission answers "is this actor allowed
to do this kind of thing at all," and that answer is the same for every member regardless of
which row they are asking about; only the query, at the moment it selects rows, knows which
row belongs to the caller. Putting ownership there rather than in a permission check means the
two questions cannot be answered by the wrong code: a route that returns a user-owned resource
without a `user_id` predicate scoped to the caller is a defect, not a missing permission, and
is caught by reading the query rather than by reading the handler's authorization check.

The nine permissions this feature ships are `user.read`, `user.write`, `user.role.grant`,
`session.revoke.any`, `audit.read`, `user.approve`, `invite.create`, `invite.manage`, and
`settings.manage`. `admin` holds all nine. `member` holds `invite.create` and nothing else,
and `invite.create` is inert while the invite quota configured for members is zero. Every
other capability a member has, reading and updating their own profile, listing and revoking
their own sessions, is an ownership predicate rather than a permission grant, which is why
`member` is described here as holding no permissions for authorization purposes even though
its row in the roles table is not literally empty.

### One type carries every authorization decision

Authorization decisions route through a single type, `authz.Checker`, rather than being
scattered across handlers as ad hoc lookups against the roles and permissions tables. A
handler asks the checker whether the current user holds a named permission; it does not query
role or permission tables itself. Substituting a different mechanism later, a rules engine or
a relationship-based store, is contained to what implements `authz.Checker` rather than spread
across every handler that currently calls it.

## Pros and Cons of the Options

### A single `role` enum column on `users`

- Good: cheapest option to build; one column, one check.
- Bad: every new capability becomes a code change, since there is no permission to grant
  separately from the role itself.
- Bad: role names end up in conditionals throughout the handler layer, which is the exact
  outcome this record rejects above.

### Role-based access control at permission granularity, with ownership in the data layer

- Good: a handler's requirement, a named permission, is stable even as which roles grant it
  changes.
- Good: ownership enforcement lives next to the query it protects, where it can be read and
  reviewed in one place.
- Good: two roles and nine permissions are simple enough to seed as fixed data, with no policy
  language or second process to operate.
- Bad: adding a genuinely novel access pattern, such as sharing a resource with another
  specific user rather than with everyone who holds a role, does not fit this model without
  extension.

### `github.com/casbin/casbin`

- Good: an in-process policy engine with a real policy language, capable of expressing
  ownership, roles, and more without a second service to run.
- Bad: buys expressiveness this feature does not need yet: two roles and predicate-based
  ownership do not need a policy DSL to express.
- Revisit when: a deployment needs its authorization rules changed without a release, which
  casbin's externalized policy model is built for and a fixed roles table is not.

### Open Policy Agent (OPA) with Rego

- Good: decouples policy from the service entirely, in a language built for exactly this
  problem, with tooling for testing policies in isolation.
- Bad: a second process and a second language for a service whose entire policy surface today
  is nine permissions and two roles.
- Revisit when: authorization rules need to be authored, tested, and deployed independently of
  the service's own release cycle by people who are not writing Go.

### SpiceDB or OpenFGA, Zanzibar-style relationship-based access control

- Good: the right model for nested groups, resource sharing between users, and delegated
  administration at scale, since relationships compose in ways a flat roles table cannot
  express.
- Bad: a new external service, a new data model to migrate into, and capability this feature's
  two roles and ownership predicates do not need.
- Revisit when: resource sharing between users becomes a product requirement, since that is
  exactly the shape these systems exist to answer and a permissions table does not.

## More Information

Adding groups later means adding `groups`, `group_members`, and `group_roles` tables and
widening `authz.Checker` to union group-derived permissions with a user's directly held ones.
No table shipped by this feature changes shape when that happens, and no handler changes: each
one still asks `authz.Checker` for the same named permission it always did.

- `docs/adr/0012-authentication-model.md`, on how a request arrives with an authenticated
  identity in the first place, which this record assumes as its input.
- `docs/adr/0011-persistence-and-data-access.md`, on the query conventions ownership
  predicates are written against.
