---
status: accepted
date: 2026-09-22
---

# 11. Persistence and data access

## Context and Problem Statement

This service has no persistence of any kind today. It is a public multi-user service, and the
users-and-auth feature it is about to grow needs durable users, identities, credentials,
sessions, roles, and an audit log. None of that survives a restart without a database, and
choosing one is not a decision this project can defer: it changes what the binary is, what an
operator must run alongside it, and what a contributor needs installed to run the tests.

Introducing any database turns an external service that was previously optional into a hard
runtime dependency. That fact, not the choice of vendor, is the part of this decision with the
widest blast radius, and it is recorded here alongside the vendor choice rather than assumed
away.

The library question underneath the engine choice, how Go code talks to that database, was
settled by the user on 2026-09-18. This record documents both decisions together, since the
engine choice is what makes the library choice possible.

## Decision Drivers

- Result rows must map onto Go structs without hand-written `rows.Scan` call sites at every
  query. A project of this size cannot afford to hand-maintain scan code for every table as it
  grows.
- With one engine settled, nothing needs to abstract over SQL dialects. A library whose value
  proposition is dialect portability is buying something this project does not use.
- This project's linter set is strict: `ireturn`, `interfacebloat`, `wrapcheck`, and
  `depguard` in strict mode all constrain what a data-access library can look like before it
  is even evaluated on merit.
- The project prefers real collaborators over mocks in tests, which favors a library that is
  easy to run against a real database in CI over one whose interfaces are designed to be
  mocked.

## Considered Options

### Engine

- Postgres only
- SQLite only
- Support both, behind a common interface

### Data access library (Postgres only)

- `github.com/jackc/pgx/v5` used directly, with `pgxpool` for pooling and
  `pgx.CollectRows`/`pgx.RowToStructByName` for struct mapping
- `github.com/sqlc-dev/sqlc` generating against the pgx/v5 driver
- `github.com/jmoiron/sqlx` over `pgx/v5/stdlib`
- `github.com/uptrace/bun`
- `entgo.io/ent`
- `gorm.io/gorm`

### Migration runner

- `github.com/pressly/goose/v3`
- `github.com/golang-migrate/migrate`
- `github.com/jackc/tern`
- `ariga/atlas`
- A hand-rolled runner over `embed.FS` and a `schema_migrations` table

## Decision Outcome

Chosen: **Postgres is the only supported engine; `github.com/jackc/pgx/v5`, used directly, is
both the driver and the data-access library; `github.com/pressly/goose/v3` runs migrations
written as plain `.sql` files.**

### Postgres is the only supported engine

SQLite was considered and rejected on 2026-09-18. SQLite would have preserved a self-sufficient
single binary with no external service to run, but it permits one writer and does not scale
past one instance, and a public multi-user service needs both concurrent writers and the option
to run more than one instance. Supporting both engines behind a common interface was also
considered and rejected: it would have forced every table onto a lowest-common-denominator
schema of `TEXT` and `INTEGER` columns, giving up the native `UUID`, `TIMESTAMPTZ`, `BOOLEAN`,
`BYTEA`, `JSONB`, and `INET` types in favor of encoding all of them as text or integers, plus a
placeholder-rebinding step between the two drivers' parameter syntaxes, plus a second full
integration test run in CI for the second engine. That is a permanent tax on every table this
project ever adds, for the sake of a deployment mode, single-binary SQLite, that this service
does not target. Postgres alone was chosen instead.

### Data access: pgx/v5, used directly

Each option was assessed against the two drivers above, against `ireturn`,
`interfacebloat`, `wrapcheck`, and strict `depguard`, and against the project's preference for
real collaborators over mocks.

`pgx/v5` used directly handles `UUID`, `TIMESTAMPTZ`, `JSONB`, `INET`, and arrays natively, with
no `database/sql` layer flattening them back to strings. Struct mapping has been built into pgx
since v5 (`pgx.CollectRows` with `pgx.RowToStructByName`), so the row-scanning constraint is met
without a second library. SQL is written by hand and stays reviewable. The cost is that a query
is checked only at runtime, and the pool type is pgx's own rather than the standard library's,
so a future second engine would be a rewrite rather than a driver swap; that cost is accepted as
a consequence of the engine decision above.

`sqlc`, generating against the pgx/v5 driver, was the strongest option on type safety: it
checks a query against the real schema at generation time, so a renamed column breaks the build
instead of a request. Its disqualifier under the earlier dual-engine plan, needing per-engine
code generation, no longer applies now that there is one engine. It was set aside anyway for the
weight it adds: a code-generation step in the build, a `sqlc.yaml`, generated code checked into
the tree, and a new Magefile target. It remains the standing alternative, see below.

`sqlx` over `pgx/v5/stdlib` is familiar and thin, but it buys struct scanning that pgx v5 now
provides natively, while the `database/sql` layer underneath it loses the native type handling
pgx gives when used directly. Its reason to exist, portability across `database/sql` drivers,
is exactly the motive this project no longer has.

`bun` is a pleasant query builder with struct mapping and solid Postgres support, but its
dialect abstraction is paying for a flexibility this project has already given up by settling
on one engine.

`ent` is schema-as-code with generated typed accessors, and would be the best fit for the
relationship-heavy queries a groups feature will eventually need. It carries the heaviest
concept load of any option here, and it brings its own Atlas-based migration engine, which
would displace goose rather than sit alongside it.

`gorm` needs the least code to write, but it is reflection- and struct-tag-driven in a way that
obscures the SQL actually issued. That sits badly with a codebase whose standards are built
around making behavior explicit and reviewable at the call site.

`pgx/v5` used directly is the one that adds no build step among the options that genuinely fit,
and this project's standards prefer the simpler of two approaches that both solve the problem.
Pooling is `pgxpool.Pool`; row-to-struct mapping is `pgx.CollectRows` with
`pgx.RowToStructByName`. There is no ORM and no second access layer.

### A query builder is permitted, but only for genuinely dynamic SQL

This permission is bounded deliberately, because an unbounded one would erode the reviewability
that motivated hand-written SQL in the first place. The rule: a query whose text is fixed is
written as a fixed string. A builder may be introduced only for a query whose shape varies at
runtime, for example a listing whose `WHERE` clause depends on which optional filters a caller
supplied. The named candidate for that case is `github.com/Masterminds/squirrel` with
`PlaceholderFormat(squirrel.Dollar)`, chosen because it produces a SQL string and an argument
slice and hands both to the existing `pgx` call, so it composes with this decision instead of
replacing it.

No unit in the users-and-auth feature needs one. Every query there has a fixed shape, including
both administrative listings, whose only variable is a keyset cursor, which makes each of them
two fixed statements rather than one built one. Adding `squirrel` as a dependency is a separate
change, gated on a real dynamic query appearing, and it must extend the `depguard` allow-list in
the same commit that introduces it.

### Migrations: goose, with plain SQL files

`goose` was chosen over the alternatives it was weighed against:

`golang-migrate/migrate` is comparably mature and has a pgx/v5 driver, but it wants a separate
up file and a separate down file for every migration, doubling the file count for a project
whose down-migrations are almost never run.

`tern` is the purist choice: Postgres-only and pgx-native, from the same author as the driver
already chosen, and it needs no `database/sql` handle at all. It loses on reach, a much smaller
community than goose, and it uses its own migration file format with a `---- create above`
separator convention rather than plain SQL. The wart it would remove is the two-line
`database/sql` bridge described below, which is not worth the narrower ecosystem.

`atlas` is the most capable option, and the only one that can lint a migration and refuse a
destructive change in review. It was rejected for now on weight: it is an external binary in
the build, a second schema-definition concept alongside the SQL already being hand-written, and
some of its capabilities sit behind a hosted service. It is named explicitly as the option to
revisit if migration review ever becomes a recurring source of incidents, since that is a real
capability goose does not have.

A hand-rolled runner over `embed.FS` and a `schema_migrations` table would be around a hundred
lines and no dependency, but it would have to re-earn advisory locking, ordering, and
partial-failure reporting, all of which goose already gets right.

Migrations live as plain `.sql` files under `internal/store/migrations`, embedded with
`embed.FS` so the binary carries its own schema.

### On the `database/sql` handle goose needs

goose needs a `database/sql` handle, and that does not mean a second connection pool:
`pgx/v5/stdlib` can adapt the existing `pgxpool.Pool` to a `database/sql.DB`, so the bridge
costs two lines and opens no extra connections. It exists for the migration runner alone; every
other code path in the service uses `pgxpool.Pool` directly.

### The standing alternative

`sqlc` is the standing alternative if queries verified against the schema at build time later
become worth a code-generation step. Switching to it later is a mechanical migration rather
than a rewrite, because it takes these same hand-written queries as its input.

### The type mapping

Having settled on one engine, the full type mapping is recorded here as its consequence:

| Kind of value | Postgres type | Notes |
| --- | --- | --- |
| Identifiers | `UUID` | Application-generated UUIDv7, not a `gen_random_uuid()` column default, which would produce version 4 and scatter index writes. |
| Timestamps | `TIMESTAMPTZ` | No column default. A default would override the injected clock the tests depend on. |
| Booleans | `BOOLEAN` | |
| Digests and credential material | `BYTEA` | No base64 encoding at the storage layer. |
| Structured values | `JSONB` | |
| Client addresses | `INET` | Nullable. |
| Enumerated strings | `TEXT` with a `CHECK` constraint | Not a Postgres `ENUM`. An `ENUM` value cannot be removed once added, which constrains how migrations may be batched. |

### Consequences

- The binary is no longer a complete deployment by itself. An operator must run and back up a
  Postgres instance alongside it, and the README must say so.
- Startup now has a dependency that can be down. The process refuses to start without a reachable
  database, and readiness reports the database's state, rather than the service reporting itself
  healthy while unable to serve any request that touches storage.
- Developers and CI need Docker or a reachable Postgres server to run the database-backed tests.
  By the project's own test pyramid these were always integration tests; they are now honestly
  labelled as such instead of being tests that happened to need nothing running.
- Every table gets Postgres's native types, at the cost that this service cannot be deployed
  against any other engine without a substantial rewrite of the storage layer.

## More Information

- [pgx](https://github.com/jackc/pgx)
- [pgxpool](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool)
- [sqlc](https://github.com/sqlc-dev/sqlc)
- [sqlx](https://github.com/jmoiron/sqlx)
- [bun](https://github.com/uptrace/bun)
- [ent](https://entgo.io/)
- [gorm](https://gorm.io/)
- [squirrel](https://github.com/Masterminds/squirrel)
- [goose](https://github.com/pressly/goose)
- [golang-migrate/migrate](https://github.com/golang-migrate/migrate)
- [tern](https://github.com/jackc/tern)
- [atlas](https://atlasgo.io/)
- `docs/adr/0006-configuration-loading.md`, on bounded dependency surface
- `docs/adr/0009-build-and-release-tooling.md`, on preferring the simpler of two options that
  both solve the problem
