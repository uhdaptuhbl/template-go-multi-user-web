package server

import (
	"net/http"
	"net/http/pprof"

	"go.uber.org/zap"
)

// DefaultAdminAddr is the address the administrative listener binds when Config
// does not override it.
//
// Loopback, not every interface. These endpoints will dump the heap, every
// goroutine's stack, and the process command line to whoever asks, so the
// unconfigured case has to be the safe one. Exposing them to a scraper is a
// deliberate act: set SERVICE_ADMIN_ADDR and put a network policy in front of
// it.
const DefaultAdminAddr = "127.0.0.1:9090"

// DefaultAdminConfig returns the administrative listener's configuration.
//
// The timeouts match the application listener's. In particular WriteTimeout stays
// non-zero even though pprof profiles stream for their full duration: net/http/pprof
// extends the write deadline by the requested profile length when a WriteTimeout is
// set, so profiling works without weakening the timeout for every other endpoint.
func DefaultAdminConfig() Config {
	cfg := DefaultConfig()
	cfg.Addr = DefaultAdminAddr

	return cfg
}

// NewAdminMux returns the administrative HTTP handler: metrics exposition, the
// probe endpoints, the version report, and runtime profiling.
//
// This handler must not be reachable from an untrusted network. Profiling
// endpoints will dump the heap, every goroutine's stack, and the command line of
// the running process to anyone who asks.
//
// Three pieces of the application chain are here too, and for the same reasons
// they are there. Panic recovery, because the metrics handler is third-party
// code walking a registry this process fills, and an unrecovered panic there
// drops the scrape with nothing logged to say why. The body limit, because
// /debug/pprof/symbol reads a request body and an unbounded read is an
// allocation anyone who reaches this port controls; the configured megabyte
// holds roughly fifty thousand addresses, far past any real symbolization
// request. Security headers, because pprof's index is HTML a browser renders.
//
// What is deliberately absent is request logging and tracing. Metric scrapes
// arrive every few seconds forever, so logging them buries application
// requests, and tracing an operator's profiling session describes nothing
// about the application's behavior. One consequence is worth knowing: panic
// recovery detects an already-started response by looking for the status
// recorder that request logging installs, so without logging it cannot tell,
// and a panic after the first write produces a superfluous-WriteHeader
// warning. That is the correct trade here, where the alternative is logging
// every scrape to make a case that needs a panicking pprof handler.
func NewAdminMux(cfg Config, logger *zap.Logger, ready *Readiness, process ProcessInfo, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /metrics", metrics)

	// Both probes are also served on the application listener, which is what
	// load balancers and orchestrators generally reach. Registered here too so
	// that the administrative port is sufficient on its own.
	mux.Handle("GET "+healthPath, newHealthHandler(logger))
	mux.Handle("GET "+readyPath, newReadinessHandler(ready, logger))

	// This listener only. Naming the exact release a process is running tells
	// anyone who can reach it which vulnerabilities to try, so it sits behind
	// the same boundary as the profiling endpoints rather than on the port that
	// serves users.
	mux.Handle("GET "+versionPath, newVersionHandler(process, logger))

	// Registered explicitly rather than by importing net/http/pprof for its
	// side effects, which would install these routes on http.DefaultServeMux
	// from an init() function: both the implicit registration and the shared
	// global mux are things this project rules out.
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	// Symbol is the one profiling route that needs POST. `go tool pprof`
	// sends the address list to symbolize in the request body, because the
	// list routinely outgrows what fits in a query string. Registering it
	// for GET alone leaves symbolization failing against this process,
	// which is most of the value of exposing the endpoint at all. Both
	// methods are named rather than dropping the method entirely, so every
	// other verb still gets a 405.
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	// Built inside out, so these read in reverse of the order a request meets
	// them: security headers outermost, so the 413 below carries them too,
	// then panic recovery, then the body limit.
	var handler http.Handler = mux

	handler = withRequestBodyLimit(cfg.MaxRequestBodyBytes.Bytes(), logger, handler)
	handler = withPanicRecovery(logger, handler)

	return withSecurityHeaders(handler)
}
