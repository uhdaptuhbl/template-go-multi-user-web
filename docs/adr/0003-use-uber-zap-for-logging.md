---
status: accepted
date: 2026-09-15
---

# 3. Use Uber Zap for logging, with an inbound slog bridge

## Context and Problem Statement

The service needs application logging that is machine-parseable in production and cheap
enough to leave enabled on hot paths. The choice is effectively permanent: the logger appears
in nearly every package's constructor signature, so replacing it later is a mechanical edit
across the whole codebase rather than a local swap.

Two constraints pull in opposite directions. Application code wants a single, fast, typed
logging API. Third-party libraries increasingly emit `log/slog` records, because `slog` has
become the interoperability surface for Go logging. A project that simply forbids `slog`
loses those records silently; a project that adopts `slog` everywhere pays its cost on every
call site.

A secondary problem is leakage: if any implicit-stdout mechanism stays available, diagnostic
output drifts into `fmt.Println` during debugging and ships that way, producing output with
no level, no fields, and no correlation ID.

## Decision Drivers

- Structured, level-aware output that a log aggregator can query by field.
- Low allocation cost, so logging is never the reason a hot path is under-instrumented.
- Library log records must reach the same sink as application logs, not vanish.
- One logging path, mechanically enforced rather than left to reviewer vigilance.
- Injected as a dependency, consistent with the project's no-global-mutable-state rule.

## Considered Options

- `go.uber.org/zap` as the primary API, with a `slog` handler bridging library records in
- `log/slog` as the primary API, with a zap backend via `zapslog`
- `log/slog` alone
- `github.com/rs/zerolog`

## Decision Outcome

Chosen: **`go.uber.org/zap` as the primary logging API, with an inbound `slog`-to-zap
bridge.**

Application code logs through zap's strongly typed field API, not the `SugaredLogger`, with
the logger passed explicitly as a dependency. A single package, `internal/logging`, adapts
`slog` records into the same zap core and installs that handler so any dependency emitting
`slog` records lands in the same output stream. The bridge is the only place `log/slog` is
imported.

The inverse arrangement, writing against `*slog.Logger` with zap as the backend, was
considered and deliberately rejected: it accepts the slower API at every call site to buy
interop that a single bridge package already provides.

Enforcement is mechanical, in `.golangci.yaml`:

- `depguard` splits into two rules. The `main` rule denies `log`, `log/slog`, and `logrus`
  everywhere; the `logging-bridge` rule permits `log/slog` only under
  `internal/logging/`.
- `forbidigo` denies `fmt.Print`, `fmt.Printf`, `fmt.Println`, and the builtin
  `print`/`println`. `fmt.Errorf`, `fmt.Sprintf`, and `fmt.Fprintf` to an explicit writer
  remain permitted, since error wrapping depends on the first and HTTP response writing on
  the last.
- `ireturn` permits returning `log/slog.Handler`, which the bridge must do.

### Consequences

- Good: one fast, typed API at every call site, and library `slog` records still reach the
  same sink.
- Good: `log/slog` appears in exactly one package, so the blast radius of a future logging
  change is one file rather than the whole tree.
- Good: a forgotten debug print fails lint rather than reaching production.
- Bad: a third-party dependency where the standard library has a credible answer, plus a
  bridge package that would not exist under plain `slog`.
- Bad: the `internal/logging/` path is now load-bearing in `.golangci.yaml`. Moving the
  bridge means updating the depguard rule, and the coupling is easy to miss.
- Bad: zap's typed API is more verbose at the call site than `slog`'s.
- Neutral: libraries wanting a `*log.Logger` are adapted with `zap.NewStdLog`.

## Pros and Cons of the Options

### zap primary, with an inbound slog bridge

- Good: fastest option at the call sites that matter, with a zero-allocation typed path.
- Good: interop cost is paid once, in one package, rather than on every log line.
- Bad: two logging concepts exist in the codebase, even if only one is reachable from
  application code.

### slog primary, zap backend via `zapslog`

- Good: standard-library API at call sites, so the logging dependency is swappable.
- Good: no bridge package; library records arrive natively.
- Bad: `slog`'s API is measurably slower and more allocation-heavy than zap's typed fields.
- Bad: accepts a weaker call-site API permanently to solve an interop problem that is
  already solved locally. This is the option rejected most deliberately.

### `log/slog` alone

- Good: no dependency, guaranteed-stable interface.
- Bad: slower under load, and the handler ecosystem is still thinner than zap's.

### `github.com/rs/zerolog`

- Good: performance comparable to zap.
- Bad: smaller ecosystem, and the chained builder makes it easy to omit the terminal call
  that actually emits the line.

## More Information

- [uber-go/zap](https://github.com/uber-go/zap)
- [zapslog handler](https://pkg.go.dev/go.uber.org/zap/exp/zapslog)
- [log/slog package documentation](https://pkg.go.dev/log/slog)

Superseding this ADR means editing every constructor that accepts a logger.
