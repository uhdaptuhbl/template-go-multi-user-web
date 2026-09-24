package server

import (
	"fmt"
	"net/http"
)

// statusRecorder captures the response status code, which http.ResponseWriter
// does not otherwise expose to middleware, and remembers whether anything has
// been written yet.
//
// The second job is what lets panic recovery decide between writing a 500 and
// abandoning a response whose status line has already gone out, where writing
// again would only produce a superfluous-WriteHeader warning and a corrupt body.
type statusRecorder struct {
	http.ResponseWriter

	status  int
	written bool
}

// WriteHeader records the first status code written and delegates to the
// wrapped writer. Later calls are passed through so that net/http reports the
// duplicate, but they do not overwrite what was recorded.
func (r *statusRecorder) WriteHeader(status int) {
	if !r.written {
		r.status = status
		r.written = true
	}

	r.ResponseWriter.WriteHeader(status)
}

// Write records that the response has begun before delegating to the wrapped
// writer, because a handler that writes a body without calling WriteHeader has
// still committed to a 200.
//
// The wrapped writer's error is wrapped rather than replaced, so that a caller
// matching a sentinel such as http.ErrContentLength with errors.Is still finds
// it, and the byte count is passed through unchanged because io.Copy and
// io.WriteString rely on it to detect a short write.
func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true

	written, err := r.ResponseWriter.Write(b)
	if err != nil {
		return written, fmt.Errorf("writing response body: %w", err)
	}

	return written, nil
}

// Written reports whether a status line or any body bytes have been written.
func (r *statusRecorder) Written() bool {
	return r.written
}

// Unwrap returns the wrapped writer, which is how http.ResponseController
// reaches the capabilities this type does not implement itself.
//
// Without it, a handler behind this middleware cannot flush, hijack, or set a
// deadline: ResponseController walks the chain by calling Unwrap and gives up
// with a "not supported" error when a wrapper does not provide it.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
