package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// withPanicRecovery turns a panicking handler into a logged 500 rather than a
// dropped connection.
//
// net/http already recovers a handler panic per connection, so the process
// survives either way. What it does not do is write a response, tell the zap
// logger, or mark the span: the client sees the connection close and the stack
// goes wherever the server's ErrorLog points. This middleware makes the failure
// observable and the response well formed.
func withPanicRecovery(logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func(ctx context.Context) {
			recovered := recover()
			if recovered == nil {
				return
			}

			// http.ErrAbortHandler is the standard library's documented way for
			// a handler to abandon a response on purpose. net/http suppresses
			// it, and so must this: logging a stack for it would report a
			// deliberate act as a fault. Matched with errors.Is rather than by
			// identity, so a handler that panics with the sentinel wrapped in
			// its own context is still recognised as a deliberate abort.
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}

			logger.Error("recovered panic serving request",
				zap.Any("panic", recovered),
				zap.String("method", r.Method),
				zap.String("path", LoggedPath(r)),
				zap.String("request_id", RequestIDFromContext(ctx)),
				zap.Stack("stack"),
			)

			span := trace.SpanFromContext(ctx)
			span.RecordError(fmt.Errorf("panic serving request: %v", recovered))
			span.SetStatus(codes.Error, "panic serving request")

			// A panic after the response has begun cannot be turned into a 500:
			// the status line is already on the wire, and writing another would
			// produce a superfluous-WriteHeader warning and a corrupt body. The
			// log entry above is all that can be salvaged.
			if recorder, ok := w.(*statusRecorder); ok && recorder.Written() {
				return
			}

			writeJSONError(w, logger, http.StatusInternalServerError, errorCodeInternal, "")
		}(r.Context())

		next.ServeHTTP(w, r)
	})
}
