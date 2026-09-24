// Package migrations embeds this service's Postgres schema and seed data,
// and applies them with goose. The binary carries its own schema and needs no
// files on disk to bootstrap a database.
package migrations
