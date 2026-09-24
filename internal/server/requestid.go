package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// RequestIDHeader carries a request's correlation identifier, inbound from a
// trusted proxy and outbound on every response.
const RequestIDHeader = "X-Request-Id"

// requestIDBytes is the number of random bytes in a generated identifier.
// Sixteen is what a UUID carries, rendered here as 32 hexadecimal characters
// without taking a dependency for a value that is only ever compared and logged.
const requestIDBytes = 16

// maxRequestIDLength bounds an adopted identifier, so that a hostile proxy
// cannot push an unbounded string into every log line about a request.
const maxRequestIDLength = 64

// requestIDContextKey is the context key an identifier is stored under. It is an
// unexported empty struct type, which is what makes collision with another
// package's key impossible.
type requestIDContextKey struct{}

// RequestIDFromContext returns the correlation identifier assigned to the
// request ctx belongs to, or the empty string outside a request.
func RequestIDFromContext(ctx context.Context) string {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	if !ok {
		return ""
	}

	return id
}

// withRequestID assigns every request a correlation identifier, echoes it in the
// response, and puts it in the request context for the rest of the chain.
func withRequestID(proxies TrustedProxies, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID(proxies, r)

		// Set before the handler runs, so the header is present even on a
		// response the handler writes immediately.
		w.Header().Set(RequestIDHeader, id)

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id)))
	})
}

// requestID adopts a trusted peer's identifier when it is well formed, and
// generates one otherwise.
//
// An identifier from an untrusted peer is discarded rather than sanitised: a
// client that can choose its own correlation ID can make two unrelated requests
// indistinguishable in the logs, or collide deliberately with someone else's.
func requestID(proxies TrustedProxies, r *http.Request) string {
	supplied := r.Header.Get(RequestIDHeader)
	if supplied != "" && validRequestID(supplied) && proxies.TrustsPeer(r) {
		return supplied
	}

	return newRequestID()
}

// validRequestID reports whether s is safe to adopt: 1 to 64 characters drawn
// from A-Z, a-z, 0-9, and the three separators dot, underscore, and hyphen.
func validRequestID(s string) bool {
	if s == "" || len(s) > maxRequestIDLength {
		return false
	}

	for i := range len(s) {
		if !isRequestIDByte(s[i]) {
			return false
		}
	}

	return true
}

// isRequestIDByte reports whether c may appear in an adopted identifier.
func isRequestIDByte(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '-'
}

// newRequestID returns 16 random bytes rendered as 32 lowercase hexadecimal
// characters.
//
// crypto/rand.Read has no failure path to handle: since Go 1.24 it is
// documented never to return an error, panicking instead if the system source
// is unavailable, which is not a condition this process could recover from.
func newRequestID() string {
	buf := make([]byte, requestIDBytes)

	rand.Read(buf)

	return hex.EncodeToString(buf)
}
