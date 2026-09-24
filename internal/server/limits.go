package server

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// retryAfterOverloaded is the Retry-After value sent with a shed request. One
// second is short enough that a client's own timeout does not expire waiting,
// and long enough to be worth honouring.
const retryAfterOverloaded = "1"

// withRequestBodyLimit caps how many bytes a handler may read from a request
// body. A limit of zero or less disables the middleware entirely.
//
// Both halves are needed. The Content-Length check rejects a declared oversized
// body before a byte is read, and MaxBytesReader catches the body that lies
// about its length or does not declare one at all.
func withRequestBodyLimit(limit int64, logger *zap.Logger, next http.Handler) http.Handler {
	if limit <= 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			writeJSONError(w, logger, http.StatusRequestEntityTooLarge, errorCodePayloadTooLarge, "")

			return
		}

		r.Body = http.MaxBytesReader(unwrapWriter(w), r.Body, limit)

		next.ServeHTTP(w, r)
	})
}

// unwrapWriter walks a chain of response-writer wrappers down to the writer
// underneath them all.
//
// MaxBytesReader tells net/http to stop reading and drop the connection by
// type-asserting the writer it was handed to an unexported interface, and it
// does not unwrap first. Every middleware between it and the server therefore
// hides that signal: the request is still refused with 413, but the
// connection is kept alive and the server drains the rest of a body it has
// already rejected. In this chain withRequestLogging's recorder and
// otelhttp's wrapper both sit in the way, and both implement Unwrap.
func unwrapWriter(w http.ResponseWriter) http.ResponseWriter {
	for {
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}

		w = unwrapper.Unwrap()
	}
}

// withInFlightLimit caps concurrently served requests. A limit of zero or less
// disables the middleware entirely.
//
// Requests over the cap are shed immediately rather than queued: a queue in
// front of an overloaded server converts a fast failure the client can retry
// into a slow one it cannot, and grows without bound while it does so.
func withInFlightLimit(limit int, logger *zap.Logger, next http.Handler) http.Handler {
	if limit <= 0 {
		return next
	}

	slots := make(chan struct{}, limit)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", retryAfterOverloaded)
			writeJSONError(w, logger, http.StatusServiceUnavailable, errorCodeOverloaded, "")

			return
		}

		next.ServeHTTP(w, r)
	})
}

// withHandlerTimeout bounds one request by cancelling its context once timeout
// elapses. A timeout of zero or less disables the middleware entirely.
//
// A context deadline rather than http.TimeoutHandler: that handler buffers the
// entire response in memory so it can replace it with its own 503, which breaks
// streaming responses and costs memory proportional to the largest response. The
// cost of this choice is that a handler which ignores its context is not
// interrupted; WriteTimeout remains the backstop for that case.
func withHandlerTimeout(timeout time.Duration, next http.Handler) http.Handler {
	if timeout <= 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
