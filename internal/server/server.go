package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// DefaultAddr is the address the server listens on when Config does not
// override it.
const DefaultAddr = ":8080"

// DefaultMaxHeaderBytes is the ceiling on a request's line and headers. It is
// net/http's own default, restated here because a limit that exists only as a
// library default cannot be configured or seen.
const DefaultMaxHeaderBytes configtype.ByteSize = 1 << 20

// DefaultMaxRequestBodyBytes is the ceiling on a request body. A megabyte suits
// a JSON API and a form post; an endpoint that accepts uploads raises it
// deliberately rather than inheriting no limit at all.
const DefaultMaxRequestBodyBytes configtype.ByteSize = 1 << 20

// DefaultPreDrainDelay is how long the process keeps serving after readiness
// starts failing and before listeners stop accepting connections. Endpoint
// removal in an orchestrator is asynchronous, so a process that stops accepting
// the instant it is signalled is still being routed to when it does.
const DefaultPreDrainDelay = configtype.Duration(5 * time.Second)

// Config holds the server's listen address and timeouts.
type Config struct {
	// Addr is the TCP address to listen on, in host:port form. The host may be
	// empty to bind every interface, a hostname, an IPv4 literal, or a
	// bracketed IPv6 literal.
	//
	// The validation is a union because neither rule covers the address space
	// on its own: hostname_port accepts an empty or named host but rejects a
	// bracketed IPv6 literal, and tcp_addr requires an IP literal for the host
	// and so rejects both the empty and the named form. Neither resolves a
	// name, so validation performs no lookups.
	//
	// The union bounds the shape of the address and not what the port means.
	// It is inconsistent about port 0 on its own, accepting it beside an IP
	// literal and rejecting it beside an empty or named host, so a configured
	// port 0 is refused uniformly one layer up, where the composed
	// configuration is validated. Serve still binds one for a Config built in
	// code, which is how the tests get a port the kernel picked.
	Addr string `env:"ADDR, overwrite" json:"addr" validate:"required,hostname_port|tcp_addr"`
	// ReadHeaderTimeout bounds how long reading request headers may take. It
	// is the timeout that prevents a slow-header client from holding a
	// connection open indefinitely.
	ReadHeaderTimeout configtype.Duration `env:"READ_HEADER_TIMEOUT, overwrite" json:"read_header_timeout" validate:"gt=0"`
	// ReadTimeout bounds reading the entire request, headers and body, and
	// must cover ReadHeaderTimeout. net/http arms the header deadline first
	// and swaps in the whole-request deadline once the headers are parsed,
	// both measured from the same moment: a total below the header bound
	// therefore does not shorten the header phase at all, and instead hands
	// the body read a deadline that has already expired whenever the headers
	// took longer than it.
	ReadTimeout configtype.Duration `env:"READ_TIMEOUT, overwrite" json:"read_timeout" validate:"gt=0,gtefield=ReadHeaderTimeout"`
	// WriteTimeout bounds writing the response. It stays positive on purpose:
	// net/http/pprof extends the write deadline by the requested profile
	// duration only when a WriteTimeout is set, so zeroing it to allow long
	// profiles would remove the extension along with the timeout.
	WriteTimeout configtype.Duration `env:"WRITE_TIMEOUT, overwrite" json:"write_timeout" validate:"gt=0"`
	// IdleTimeout bounds how long a keep-alive connection may sit unused.
	IdleTimeout configtype.Duration `env:"IDLE_TIMEOUT, overwrite" json:"idle_timeout" validate:"gt=0"`
	// ShutdownTimeout bounds how long in-flight requests may take to finish
	// once shutdown begins. Requests still running when it expires are cut off.
	ShutdownTimeout configtype.Duration `env:"SHUTDOWN_TIMEOUT, overwrite" json:"shutdown_timeout" validate:"gt=0"`
	// MaxHeaderBytes bounds the request line and headers together. A request
	// exceeding it is rejected by net/http before any handler runs.
	MaxHeaderBytes configtype.ByteSize `env:"MAX_HEADER_BYTES, overwrite" json:"max_header_bytes" validate:"gt=0"`
	// MaxRequestBodyBytes bounds how many bytes a handler may read from a
	// request body before the request is refused.
	MaxRequestBodyBytes configtype.ByteSize `env:"MAX_REQUEST_BODY_BYTES, overwrite" json:"max_request_body_bytes" validate:"gt=0"`
	// MaxInFlight caps concurrently served requests. Zero disables the cap,
	// which is the default: the right ceiling is a property of a workload this
	// service does not have yet, and a wrong one refuses legitimate traffic.
	MaxInFlight int `env:"MAX_IN_FLIGHT, overwrite" json:"max_in_flight" validate:"gte=0"`
	// HandlerTimeout bounds one request's handler by cancelling its context.
	// Zero disables it, leaving WriteTimeout as the only bound.
	//
	// When set it must be strictly shorter than WriteTimeout. net/http arms the
	// write deadline immediately before the handler runs, so the two clocks
	// start together; cancelling the handler's context at or after the moment
	// writes stop working leaves it no budget to act on the cancellation, and
	// the setting can produce no outcome a client observes. Being shorter does
	// not by itself guarantee the response fits in what remains of the write
	// budget, which is a property of the handler rather than of configuration.
	//
	// omitempty preserves zero as "disabled": it stops the chain before the
	// comparison, which an unset field would otherwise fail.
	HandlerTimeout configtype.Duration `env:"HANDLER_TIMEOUT, overwrite" json:"handler_timeout" validate:"gte=0,omitempty,ltfield=WriteTimeout"`
}

// DefaultConfig returns a Config with timeouts short enough to release
// resources from stalled clients and long enough not to interrupt ordinary
// requests.
func DefaultConfig() Config {
	return Config{
		Addr:                DefaultAddr,
		ReadHeaderTimeout:   configtype.Duration(5 * time.Second),
		ReadTimeout:         configtype.Duration(30 * time.Second),
		WriteTimeout:        configtype.Duration(30 * time.Second),
		IdleTimeout:         configtype.Duration(120 * time.Second),
		ShutdownTimeout:     configtype.Duration(15 * time.Second),
		MaxHeaderBytes:      DefaultMaxHeaderBytes,
		MaxRequestBodyBytes: DefaultMaxRequestBodyBytes,
		MaxInFlight:         0,
		HandlerTimeout:      0,
	}
}

// LifecycleConfig holds the process-wide shutdown sequencing that is not a
// property of any one listener.
type LifecycleConfig struct {
	// PreDrainDelay is how long the process keeps serving after readiness
	// starts failing and before listeners stop accepting connections. Set it to
	// zero behind a static reverse proxy, where there is no routing table to
	// propagate a change through.
	PreDrainDelay configtype.Duration `env:"PRE_DRAIN_DELAY, overwrite" json:"pre_drain_delay" validate:"gte=0"`
}

// DefaultLifecycleConfig returns the shutdown sequencing used when nothing
// overrides it.
func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{PreDrainDelay: DefaultPreDrainDelay}
}

// Server serves HTTP requests and shuts down gracefully on context
// cancellation.
type Server struct {
	httpServer      *http.Server
	logger          *zap.Logger
	shutdownTimeout time.Duration
}

// New builds a Server that serves handler using cfg, logging lifecycle events
// to logger.
func New(cfg Config, logger *zap.Logger, handler http.Handler) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration(),
			ReadTimeout:       cfg.ReadTimeout.Duration(),
			WriteTimeout:      cfg.WriteTimeout.Duration(),
			IdleTimeout:       cfg.IdleTimeout.Duration(),
			MaxHeaderBytes:    int(cfg.MaxHeaderBytes.Bytes()),
			// net/http writes its own connection-level failures here: malformed
			// requests, TLS handshake errors, and the panics it recovers itself.
			// Left unset they go to the standard log package's stderr output,
			// unstructured, unlevelled, and separate from everything else this
			// process emits.
			ErrorLog: zap.NewStdLog(logger.Named("http")),
		},
		logger:          logger,
		shutdownTimeout: cfg.ShutdownTimeout.Duration(),
	}
}

// RunAll runs every server concurrently until ctx is cancelled or any one of
// them stops with an error, and returns the first error reported.
//
// A failure in one server shuts down the rest. Serving the application without
// its administrative listener, or the reverse, is a half-started process that
// looks healthy while missing something the operator asked for, so the whole
// process stops instead.
//
// Cancelling ctx starts a sequenced shutdown rather than an immediate one; see
// drain.
func RunAll(ctx context.Context, cfg LifecycleConfig, ready *Readiness, logger *zap.Logger, servers ...*Server) error {
	// Deliberately not derived from ctx: cancellation reaches the servers
	// through drain, which holds them open for the pre-drain delay first.
	serveCtx, stopServing := context.WithCancel(context.WithoutCancel(ctx))
	defer stopServing()

	// The group's context is cancelled the moment any server returns an error,
	// which is what stops the remaining servers on a failed listener: that is
	// not a graceful shutdown, so they stop now rather than after the pre-drain
	// delay. Wait still waits for every server, so the process does not exit
	// while another is still draining in-flight requests.
	group, groupCtx := errgroup.WithContext(serveCtx)

	for _, srv := range servers {
		group.Go(func() error {
			return srv.Run(groupCtx)
		})
	}

	// The drain sequencer cannot fail, so it is not part of the error group. It
	// is still waited on, because a goroutine whose exit no one waits on is a
	// leak, and because it must not call stopServing after RunAll has returned.
	done := make(chan struct{})

	var sequencer sync.WaitGroup

	sequencer.Go(func() {
		drain(ctx, done, cfg, ready, logger, stopServing)
	})

	err := group.Wait()

	close(done)
	sequencer.Wait()

	if err != nil {
		// Returned unwrapped: Run already names the address and the operation.
		//nolint:wrapcheck // see comment above
		return err
	}

	return nil
}

// drain sequences a graceful shutdown: readiness starts failing, the process
// keeps serving for the pre-drain delay so whatever routes traffic here observes
// the change, and only then are the listeners told to stop.
//
// Skipping the delay is what produces the errors a graceful shutdown is meant to
// avoid: an orchestrator removes an endpoint asynchronously, so connections
// arrive for a short while after the signal, and a closed listener turns each of
// them into a 502 the client attributes to the service rather than to the
// deployment.
func drain(ctx context.Context, done <-chan struct{}, cfg LifecycleConfig, ready *Readiness, logger *zap.Logger, stopServing func()) {
	select {
	case <-ctx.Done():
	case <-done:
		// Every server exited on its own; there is nothing to sequence.
		return
	}

	ready.SetDraining()

	logger.Info("readiness failing, holding before drain",
		zap.Duration("pre_drain_delay", cfg.PreDrainDelay.Duration()),
	)

	timer := time.NewTimer(cfg.PreDrainDelay.Duration())
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-done:
	}

	stopServing()
}

// Run listens on the configured address and serves until ctx is cancelled or
// the listener fails.
func (s *Server) Run(ctx context.Context) error {
	var config net.ListenConfig

	listener, err := config.Listen(ctx, "tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.httpServer.Addr, err)
	}

	return s.Serve(ctx, listener)
}

// Serve serves on listener until ctx is cancelled or the listener fails.
// Cancelling ctx begins a graceful shutdown bounded by the configured shutdown
// timeout. Serve takes ownership of listener and closes it before returning.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	serveErr := make(chan error, 1)

	go func() {
		err := s.httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("serving http: %w", err)
			return
		}

		serveErr <- nil
	}()

	// Scoped to the bound address rather than the configured one, so that a
	// port of 0 reports what the kernel actually chose. Several servers run in
	// one process, so every lifecycle line needs to say which one it is about.
	logger := s.logger.With(zap.String("addr", listener.Addr().String()))

	logger.Info("http server listening")

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down", zap.Duration("timeout", s.shutdownTimeout))

	// ctx is already cancelled, so the shutdown deadline is derived from a
	// context that does not inherit that cancellation.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down http server: %w", err)
	}

	if err := <-serveErr; err != nil {
		return err
	}

	logger.Info("shutdown complete")

	return nil
}
