// Package httpclient builds outbound HTTP clients with bounded requests, a
// pool of their own, and trace context propagated to the peer.
//
// It exists because the three obvious ways to make an outbound request are
// wrong in the same three ways. http.Get and http.DefaultClient have no
// timeout, so a peer that accepts a connection and then stops talking holds
// the caller until the process restarts. They share one transport across the
// whole process, so a pool exhausted by one dependency starves every other.
// And they carry no trace context, so a request that crosses into another
// service starts a second trace there and the two halves of one user action
// cannot be joined.
//
// One client is built per dependency rather than per process, because the
// limits that suit a dependency are a property of that dependency. What comes
// back is an ordinary *http.Client, so a caller uses the standard library it
// already knows and can hand it to any SDK that accepts one.
//
// Retries, backoff, and circuit breaking are deliberately absent. Retrying is
// safe only for an operation the caller knows to be idempotent, and that is
// knowledge the call site has and this package does not; a retry applied
// underneath a caller who did not ask for one turns one duplicate write into
// several. See specs/006-outbound-http/.
package httpclient
