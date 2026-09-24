---
status: accepted
date: 2026-09-15
---

# 6. Configuration loading

## Context and Problem Statement

Configuration has been deliberately deferred so far. Listen addresses are compile-time
defaults, and the README says plainly that the flag and config-file approach is left until a
feature needs it. That was the right call while there was nothing to configure, and it has
stopped being true: there are now two listen addresses, five timeouts, a log level, a log
format, and a telemetry service identity, all hard-coded.

One mechanism already exists and is not in scope to change. Telemetry is configured through the
standard OpenTelemetry environment variables, because their names and precedence are fixed by
the OpenTelemetry specification rather than chosen by this project. Whatever is decided here has
to sit alongside that without turning configuration into two systems that disagree.

The decision is expensive to reverse for the usual reason: the loader's shape appears in every
config struct, and its idioms (struct tags, defaults, validation, precedence rules) spread
through them. Replacing it later is a sweep, not a swap.

## Decision Drivers

- **Bounded dependency surface.** `depguard` runs in strict allow-list mode, so every
  dependency is a deliberate decision. Configuration is a small problem and should not arrive
  with a large tree attached.
- **No global mutable state.** CLAUDE.md forbids it. A loader whose primary API is a package
  level singleton is in direct tension with that, and with passing config explicitly as a
  dependency.
- **Testable without touching the process environment.** The testing standards want fakes only
  at process boundaries, and the environment is exactly such a boundary. A loader that can read
  from an injected source, rather than only from `os.Environ`, is testable without
  `t.Setenv` serialising the suite.
- **Deployment shape.** A single binary serving a browser UI, most plausibly run as a container
  or a service unit. That is the case environment variables were designed for.
- **Secret handling.** Credentials will eventually be configured, and the value that arrives
  must not be loggable by accident.
- **Unknown: whether a user-editable config file is required.** This depends on product shape,
  which is undecided for the same reason `docs/adr/0002-frontend-stack.md` is still open. It is
  the one driver that could change the answer.

## Considered Options

- `github.com/sethvargo/go-envconfig`
- `github.com/spf13/viper`
- Standard library only: `os.Getenv` plus `flag`

## Decision Outcome

Chosen: **`github.com/sethvargo/go-envconfig`**, with `github.com/go-playground/validator/v10`
for validation. Configuration is read from environment variables into structs each package owns,
composed by `internal/config`.

The reasoning, heaviest first:

**1. The dependency surface is not close.** Measured on a trivial program importing each:

| | Modules in graph | Total linked packages | External linked packages |
| --- | --- | --- | --- |
| go-envconfig v1.4.3 | 2 | 76 | 1 |
| viper v1.21.0 | 26 | 236 | 53 |

Fifty-three external packages to read configuration, in a project whose lint gate exists partly
to make each dependency a conscious choice, is a poor trade for capability that is not needed.

**2. Viper's main strengths are all things this project has no requirement for.** Multiple file
formats, live reload on change, remote providers, and flag binding are real advantages in a
tool that needs them. None is on the driver list above. Paying their complexity now, against
the possibility of wanting one later, is the same mistake ADR 0002 avoids by not choosing a
frontend framework before knowing whether the product needs one.

**3. Viper's ergonomics work against two explicit project rules.** Its familiar API is a package
level singleton (`viper.Get`, `viper.SetDefault`), which is the global mutable state CLAUDE.md
forbids. It can be used with an explicit `*viper.Viper` instance instead, but then the
documentation, examples, and most answers a future reader finds are written against the form
this project does not permit. Its keys are also case-insensitive and its precedence chain is
long, which produces the class of bug where a value is silently not what you think it is.

**4. go-envconfig's `Lookuper` is the testing seam the standards ask for.** Configuration is
decoded from an injected map instead of the real environment, so config tests neither mutate
process state nor serialise against each other.

**5. The environment path is already the one in use.** Telemetry is configured that way by
specification. Choosing an environment-first loader makes one mechanism, not two.

**The honest case against this decision:** a self-hosted service with a browser UI is exactly
the kind of software whose operators eventually want to edit a file on disk rather than manage a
long environment block, and if that requirement arrives, environment-only will feel wrong. Two
things make it a weak objection. It is speculative, whereas the dependency cost is measured and
immediate. And it is cheap to answer without Viper: decode a file into the same struct with the
standard library or a single YAML package, and keep environment variables as the override layer.
That is additive, and it is a smaller change than removing Viper would be.

If a requirement appears for operator-editable configuration with live reload, or for reading
configuration from a remote provider, Viper becomes the better answer and this record should be
superseded rather than defended.

### Consequences

**Structure.** Each package owns the `Config` struct for its own settings and a `DefaultConfig`
that returns its defaults. `internal/config` composes them into one top-level `Config` and
contributes no settings of its own, so adding a setting is a one-package change. The two HTTP
listeners are two instances of the same `server.Config` under different prefixes, because they
are the same kind of thing bound in different places.

**Precedence.** Defaults are the base layer, environment variables are the only override, and a
value the caller supplies from outside the environment (currently the build version) is applied
before decoding. There is no file layer and no flag layer; adding one means amending this
record with where it sits in the order.

**Defaults are struct values, not tags.** Each package's defaults live in its `DefaultConfig`
function rather than in `env:"...,default=..."` tags, because two instances of one struct need
different defaults and a tag cannot express that. This has a consequence that must not be
forgotten: **go-envconfig skips a field that already holds a non-zero value unless its tag says
`overwrite`.** Every environment-loadable field therefore carries `, overwrite`, and a new field
added without it will silently ignore its variable. `TestLoadAppliesEnvironmentValuesOverTheDefaults`
exists to catch that.

A related measured behaviour: a variable that is set but empty is treated as absent, so it does
not overwrite. That is the outcome to want, since an exported-but-empty variable would otherwise
blank a listen address.

**Validation.** `go-playground/validator/v10` is adopted alongside the loader, with
`WithRequiredStructEnabled()`. It is a second dependency and was a separate decision: the
alternative was hand-written checks. It wins because the checks would otherwise be spread across
every package that owns a `Config`, and because a wrong value should be reported by name at
startup rather than becoming a confusing failure later.

A struct may also implement `CustomValidator` for rules a tag cannot express. The hook runs on
the decode target and on each of the target's immediate struct fields, which is what lets a
package keep a rule about its own settings while the composed `Config` keeps the ones that span
packages. It is not followed any deeper, because the composition is one level deep by design.
Struct-tag validation gates them, so a custom validator never has to defend against values the
tags already reject. The hooks do not gate each other: every one of them runs and their failures
are joined, because an operator writing a configuration from scratch should learn about every
wrong settings group from a single run rather than one per restart. The cost is that a hook may
not assume another succeeded, so one that reads state another derives checks what it reads.

Two rules use it today. The composed `Config` refuses a listen port of 0: it binds a port
nothing can be told to route to, which serves a test holding the listener and cannot serve a
deployment. `server.ProxyConfig` parses its trusted-CIDR list with the same function the request
path uses, so what starts the process is exactly what will later parse, rather than a `dive,cidr`
tag's stricter and separately maintained idea of it.

**Variable names live in the tags only.** A field's own validator knows what is wrong with its
values but not what an operator calls them, because two instances of one config type are told
apart solely by the prefix the composing struct gives them. `internal/config` therefore reads
that prefix off the tag by reflection to label each failure, and derives the full variable names
its listen-address messages use the same way. Writing those names out a second time would put
the text an operator is told to export in two places, where renaming a prefix keeps compiling
and only the advice goes stale.

**Secrets.** `secret.String`, in the leaf package `internal/secret`, redacts through
`fmt.Stringer`, `fmt.GoStringer`, `slog.LogValuer`, and both the text and JSON marshalers, and
exposes its plaintext only through an explicitly named `Expose` method that is greppable in
review. `config.SecretString` is an alias for it. Because it redacts on marshal, an encoded
config is a report and never a source to reload from.

The type lives in its own package, not in `internal/config`, because of an import cycle.
`internal/config` composes the configuration types of the packages it configures, and several
of those hold a secret: `store.Config` the database DSN, `mail.Config` the SMTP password, and
`oidc.ProviderConfig` each provider's client secret. Those packages cannot import
`internal/config` back, so the type has to live below all of them. It began in
`internal/config` and moved when spec 008 added users and authentication (commit `10dc037`).

**`log/slog` exception.** `internal/secret` is added to the `depguard` exception that
`docs/adr/0003-use-uber-zap-for-logging.md` previously granted only to `internal/logging`. The
reason: `slog` does not consult `fmt.Stringer` for a string-kinded value, so `fmt.Stringer`
alone would not stop a secret reaching a handler through the slog bridge. The exception is
scoped to that one package and buys a redaction guarantee, not a logging path: nothing in
`internal/secret` logs. `depguard` has no rule inheritance, so the package's rule is a copy of
the main deny list minus `log/slog`; a deny added to the main list must be added there too.

**JSON tags.** Every field carries one, so the whole configuration can be reported as a
structured document. Their casing follows `tagliatelle`'s `snake_case` setting, which ADR 0002
must settle for wire-facing types generally.
## Pros and Cons of the Options

### go-envconfig

- Good: one external package linked. Nothing to audit but the thing itself.
- Good: struct-tag decoding into a caller-owned struct, with no global state and no singleton.
- Good: `Lookuper` makes the environment injectable, so tests need no process mutation.
- Good: matches the environment-variable mechanism telemetry already requires.
- Bad: environment variables only. A config file needs separate code, though it can decode into
  the same struct.
- Bad: no flag support. Combining with the standard `flag` package is straightforward but is
  code this project would own.
- Bad: smaller community than Viper, so fewer worked examples for unusual cases.

### viper

- Good: one mechanism covering files, environment, flags, defaults, and remote providers, with a
  defined precedence between them.
- Good: live reload, which nothing else here offers without being written.
- Good: very widely used, so most questions have an existing answer.
- Bad: 53 external linked packages for a small problem, against a strict dependency allow list.
- Bad: its idiomatic API is a global singleton, which CLAUDE.md forbids; using it correctly here
  means writing against the form the documentation does not show.
- Bad: case-insensitive keys and a long precedence chain make "this value is not what I set"
  a recurring failure mode.
- Bad: brings capability that is not on the driver list, and complexity is paid up front while
  the benefit is hypothetical.

### Standard library only

- Good: zero dependencies, nothing to keep patched, and no behaviour to learn.
- Good: entirely explicit. There is no precedence chain to be surprised by.
- Bad: every field is hand-parsed, hand-defaulted, and hand-validated. The boilerplate grows
  linearly with the config surface and is exactly the kind of repetitive code where a missing
  default or an unchecked parse error hides.
- Bad: named here as the honest baseline. It is a reasonable answer at five settings and a poor
  one at thirty, and the current surface is already past five.

## More Information

`internal/config/doc.go` documents the composition and layering rules for the reader who reaches
the package before this record.

This record was edited in place on 2026-09-24, once, by the owner's decision, to describe the
move of the secret type and its `log/slog` exception to `internal/secret`. A short-lived
successor record, 0016, had said the same thing; it was withdrawn in favor of this edit.
Accepted records are otherwise immutable.

The prototype this decision started from used a grouped `var` block, had no `doc.go`, and used
`testify` in its tests. All three were brought in line with the project standards when it was
adopted; `testify` was replaced with the standard library and `github.com/google/go-cmp`.
