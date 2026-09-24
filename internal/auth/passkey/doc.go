// Package passkey runs the WebAuthn registration and assertion ceremonies and
// owns the credential records they produce. Binary credential material --
// credential identifiers, public keys, and AAGUIDs -- is stored as raw bytes
// in BYTEA columns, with no encoding step on its way into or out of the
// database.
package passkey
