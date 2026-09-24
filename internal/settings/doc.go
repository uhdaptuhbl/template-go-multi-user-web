// Package settings owns the single runtime settings row: the signup and
// invite policy an administrator can change while the process keeps running.
// It is read live on every call and never cached, so a change takes effect on
// every replica at once with nothing to invalidate. ADR 0015 records why this
// configuration lives in Postgres rather than in the environment.
package settings
