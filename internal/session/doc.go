// Package session owns server-side sessions: opaque tokens issued to
// browsers, their digests persisted so the database never holds a usable
// credential, two independent expiries, and the cookie they travel in.
package session
