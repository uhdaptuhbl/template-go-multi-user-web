package server

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Telemetry carries the OpenTelemetry providers the HTTP instrumentation
// records through. They are passed in rather than read from the otel package's
// globals, so that what a handler reports is a property of how it was built and
// a test can supply its own.
//
// The zero value records nothing: a nil field is replaced by that signal's no-op
// implementation, and a nil Propagator by one that reads and writes nothing.
type Telemetry struct {
	// TracerProvider creates the span for each request.
	TracerProvider trace.TracerProvider
	// MeterProvider records request duration and size.
	MeterProvider metric.MeterProvider
	// Propagator reads an inbound trace context from request headers.
	Propagator propagation.TextMapPropagator
}

// healthPath is the liveness endpoint, named as a constant because both the
// route and the tracing filter that excludes it have to agree.
const healthPath = "/healthz"

// healthResponse is the body returned by the health endpoint.
type healthResponse struct {
	Status string `json:"status"`
}

// NewMux returns the root HTTP handler: operational endpoints plus ui for
// everything else, wrapped in the middleware chain below. Feature routes are
// registered here as they are specified.
//
// api, when non-nil, is called with the bare mux before any middleware is
// applied and before the "/" catch-all is registered, so a caller may
// register application routes such as "/api/v1/" without this package
// importing them and without those routes losing to the frontend fallback.
//
// middleware wraps the mux innermost, before withRequestBodyLimit and every
// layer below, so a caller's own middleware -- session resolution and
// cross-site rejection, for cmd/service/main.go -- runs inside tracing,
// security headers, request identity, request logging, panic recovery, the
// in-flight limiter, the handler timeout, and the body limit, rather than
// wrapping this function's result from the outside where none of those layers
// would see the request. The first element is the outermost of the ones
// supplied, so NewMux(..., a, b) yields a(b(mux)) inside the chain; per-route
// rate limiting, where a route registers it, still runs after middleware,
// because a route's own handler sits behind everything supplied here.
//
// The chain is built inside out, so the assignments below read in reverse of the
// order a request passes through them. Outermost first, a request meets:
// tracing, security headers, request identity, request logging, panic recovery,
// the in-flight limiter, the handler timeout, the body limit, the supplied
// middleware in the order given, and then the mux.
//
// Each placement is load bearing. Invite path redaction sits outside
// everything, tracing included, so that no layer, span processor, or sampler
// sees an invite token in the path; withRoutePattern, innermost, puts the
// real path back for the mux alone. Logging sits inside tracing so the span exists
// by the time an entry is written, which is what lets a log line carry the trace
// and span identifiers. Panic recovery sits inside logging so a recovered panic
// is still logged as a served request with status 500, and inside request
// identity so the panic entry carries the same request_id as everything else
// about that request. Security headers sit outside everything that writes a
// response, so the 413 from the body limit and the 503 from the limiter carry
// them too, and so does anything the supplied middleware answers itself.
func NewMux(cfg Config, proxies TrustedProxies, ready *Readiness, logger *zap.Logger, telemetry Telemetry, ui http.Handler, api func(*http.ServeMux), middleware ...func(http.Handler) http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+healthPath, newHealthHandler(logger))
	mux.Handle("GET "+readyPath, newReadinessHandler(ready, logger))

	if api != nil {
		api(mux)
	}

	mux.Handle("/", ui)

	var handler = withRoutePattern(mux)

	for _, wrap := range slices.Backward(middleware) {
		handler = wrap(handler)
	}

	handler = withRequestBodyLimit(cfg.MaxRequestBodyBytes.Bytes(), logger, handler)
	handler = withHandlerTimeout(cfg.HandlerTimeout.Duration(), handler)
	handler = withInFlightLimit(cfg.MaxInFlight, logger, handler)
	handler = withPanicRecovery(logger, handler)
	handler = withRequestLogging(proxies, logger, handler)
	handler = withRequestID(proxies, handler)
	handler = withSecurityHeaders(handler)

	return withInvitePathRedaction(newTracingHandler(telemetry, handler))
}

// withRoutePattern wraps the bare mux, innermost of everything NewMux builds
// including any supplied middleware. It restores the real path
// withInvitePathRedaction replaced, so the mux routes, redirects, and fills
// r.PathValue from the path the client sent, and it records the route
// ServeMux matched into the request's requestMeta once next has returned.
//
// It has to sit here, immediately around the mux, rather than anywhere
// closer to withRequestLogging: any middleware in between that calls
// r.WithContext before invoking next -- auth.Service.Authenticate and
// withHandlerTimeout both do -- hands the mux a different *http.Request than
// the one an outer middleware is still holding, and ServeMux sets Pattern
// only on the instance that actually reaches it. Recording it here, on the
// same r the mux just routed, and reading it back later through the shared
// requestMeta pointer rather than through r.Pattern is what survives that
// cloning.
func withRoutePattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routed := withOriginalPath(r)

		next.ServeHTTP(w, routed)

		// routed shares r's context, and with it the requestMeta; only
		// routed, the request the mux saw, has Pattern set.
		if meta := requestMetaFromContext(r.Context()); meta != nil {
			meta.pattern = routed.Pattern
		}
	})
}

// newTracingHandler wraps next in OpenTelemetry HTTP instrumentation recording
// through telemetry's providers, substituting the no-op for each signal
// telemetry leaves nil. Probe requests are filtered out; shouldTrace says why.
func newTracingHandler(telemetry Telemetry, next http.Handler) http.Handler {
	tracer := telemetry.TracerProvider
	if tracer == nil {
		tracer = tracenoop.NewTracerProvider()
	}

	meter := telemetry.MeterProvider
	if meter == nil {
		meter = metricnoop.NewMeterProvider()
	}

	propagator := telemetry.Propagator
	if propagator == nil {
		propagator = propagation.NewCompositeTextMapPropagator()
	}

	return otelhttp.NewHandler(next, "http.server",
		otelhttp.WithFilter(shouldTrace),
		otelhttp.WithTracerProvider(tracer),
		otelhttp.WithMeterProvider(meter),
		otelhttp.WithPropagators(propagator),
	)
}

// shouldTrace reports whether a span should be created for r.
//
// Probes are excluded. They arrive every few seconds forever, carry no
// information about application behavior, and would otherwise dominate trace
// storage while pushing real requests out of any sampled view.
func shouldTrace(r *http.Request) bool {
	return r.URL.Path != healthPath && r.URL.Path != readyPath
}

// newHealthHandler reports that the process is up and serving. It deliberately
// checks nothing else: a readiness endpoint that probes dependencies is a
// separate concern, added when there are dependencies to probe.
func newHealthHandler(logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, logger, http.StatusOK, healthResponse{Status: "ok"})
	})
}

// withRequestLogging logs one entry per request once next has returned, and
// names the request's span after the route that matched.
//
// Both jobs have to happen after next returns, because the matched route is not
// known until the mux has routed. matchedRoute reads it back through the
// shared requestMeta rather than through r.Pattern directly, because a
// middleware between this one and the mux may have handed the mux a
// different *http.Request than the one held here; see withRoutePattern's own
// doc comment for why.
func withRequestLogging(proxies TrustedProxies, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// Installed before next runs and read back below through the same r,
		// so that anything further in can leave state here, such as the
		// matched route, for the access-log entry this middleware writes
		// once next returns. It also carries the redacted invite path, if
		// any, that LoggedPath reports.
		ctx := contextWithRequestMeta(r.Context())
		r = r.WithContext(ctx)

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)
		span := trace.SpanFromContext(ctx)
		route := matchedRoute(r)

		// The default span name from HTTP instrumentation is the same for every
		// request. The matched route is the useful name: it distinguishes
		// endpoints without the unbounded cardinality of a raw path.
		if route != "" {
			span.SetName(spanRouteName(r.Method, route))
		}

		fields := []zap.Field{
			zap.String("method", r.Method),
			zap.String("path", LoggedPath(r)),
			zap.String("route", route),
			zap.Int("status", recorder.status),
			zap.Duration("duration", duration),
			zap.String("request_id", RequestIDFromContext(ctx)),
			zap.String("client_ip", proxies.ClientIP(r)),
		}

		// Invalid when tracing is disabled, or on a request the tracing filter
		// excluded. Emitting the zero identifiers would imply a trace that does
		// not exist.
		if sc := span.SpanContext(); sc.IsValid() {
			fields = append(fields,
				zap.String("trace_id", sc.TraceID().String()),
				zap.String("span_id", sc.SpanID().String()),
			)
		}

		logger.Log(levelForStatus(recorder.status), "request served", fields...)
	})
}

// levelForStatus maps a response status to the level its entry is logged at.
//
// One level for every outcome makes a failure invisible in a stream dominated by
// successes: an operator filtering for errors should find the 500s without
// knowing this project's log message strings.
func levelForStatus(status int) zapcore.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return zapcore.ErrorLevel
	case status >= http.StatusBadRequest:
		return zapcore.WarnLevel
	default:
		return zapcore.InfoLevel
	}
}

// spanRouteName builds the "{method} {route}" span name the OpenTelemetry HTTP
// conventions ask for.
//
// A ServeMux pattern registered with a method already contains it, as in
// "GET /healthz", while a pattern registered without one, as in "/", does not.
// Prepending unconditionally would yield "GET GET /healthz".
func spanRouteName(method, pattern string) string {
	if strings.HasPrefix(pattern, method+" ") {
		return pattern
	}

	return method + " " + pattern
}
