package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// readyPath is the readiness endpoint, named as a constant because the route
// registration on both listeners has to agree on it.
const readyPath = "/readyz"

// DefaultReadinessCheckTimeout bounds one readiness probe's checks together.
// One second is under the default probe timeout of every orchestrator this
// process is documented for, so a hung dependency produces a 503 the prober
// can act on rather than a probe that times out and tells it nothing.
const DefaultReadinessCheckTimeout = time.Second

// Check reports whether one dependency is able to serve this process. It
// returns nil when the dependency is usable and an error saying why otherwise.
//
// A check must honour ctx: it is cancelled when the probe's timeout elapses,
// and a check that ignores it holds the probe open past that point. A check
// that panics counts as failed rather than taking the process down.
type Check func(ctx context.Context) error

// readinessResponse is the body returned by the readiness endpoint.
type readinessResponse struct {
	Status string `json:"status"`
	// Failing names the checks that did not pass, present only when at least
	// one failed. Names only: what went wrong goes to the log, because this
	// endpoint is served on the application listener.
	Failing []string `json:"failing,omitempty"`
}

// namedCheck is one registered readiness check.
type namedCheck struct {
	name  string
	check Check
}

// Readiness reports whether this process should be sent new traffic.
//
// It is deliberately separate from liveness: a draining process is healthy and
// must not be restarted, it simply should not receive new requests. Conflating
// the two makes a rolling deployment look like a crash loop.
//
// With no checks registered it is a function of draining alone. A check
// registered with AddCheck is consulted on every probe while serving, so a
// dependency this process cannot do without, such as its database, can take
// it out of rotation until the dependency is back.
//
// The zero value is usable and times its checks out after
// DefaultReadinessCheckTimeout. NewReadiness is the clearer way to obtain one.
type Readiness struct {
	draining     atomic.Bool
	checkTimeout time.Duration

	mu     sync.Mutex
	checks []namedCheck
}

// NewReadiness returns a Readiness that reports ready and runs no checks.
func NewReadiness() *Readiness {
	return &Readiness{checkTimeout: DefaultReadinessCheckTimeout}
}

// AddCheck registers check under name, which appears in the readiness body when
// the check fails. It panics on a duplicate name, as http.ServeMux does on a
// duplicate pattern: registration happens once at start-up, and a collision
// there is a programming error rather than a condition to handle.
func (r *Readiness) AddCheck(name string, check Check) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if slices.ContainsFunc(r.checks, func(c namedCheck) bool { return c.name == name }) {
		panic(fmt.Sprintf("server: readiness check %q registered twice", name))
	}

	r.checks = append(r.checks, namedCheck{name: name, check: check})
}

// SetDraining marks the process as no longer accepting new traffic. It is
// idempotent and safe to call from any goroutine, so both a shutdown sequencer
// and a failing listener may call it without coordinating.
func (r *Readiness) SetDraining() {
	r.draining.Store(true)
}

// Draining reports whether shutdown has begun.
func (r *Readiness) Draining() bool {
	return r.draining.Load()
}

// failing runs every registered check concurrently and returns the names of
// those that failed, sorted, logging each failure with its cause.
//
// Each check's failure is independently meaningful, so each records its result
// in its own slot and nothing is lost to a first-error-wins group. A slot per
// goroutine needs no mutex.
func (r *Readiness) failing(ctx context.Context, logger *zap.Logger) []string {
	r.mu.Lock()
	checks := slices.Clone(r.checks)
	r.mu.Unlock()

	if len(checks) == 0 {
		return nil
	}

	// Zero when the value was composed as a struct literal rather than through
	// NewReadiness. Passing that to WithTimeout would expire the context before
	// a single check ran and report every dependency as down.
	timeout := r.checkTimeout
	if timeout <= 0 {
		timeout = DefaultReadinessCheckTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make([]error, len(checks))

	var wg sync.WaitGroup

	for i, c := range checks {
		wg.Go(func() {
			results[i] = runCheck(ctx, c.check)
		})
	}

	wg.Wait()

	var failed []string

	for i, err := range results {
		if err == nil {
			continue
		}

		logger.Warn("readiness check failed", zap.String("check", checks[i].name), zap.Error(err))

		failed = append(failed, checks[i].name)
	}

	slices.Sort(failed)

	return failed
}

// runCheck runs one check, converting a panic into an error. The goroutine
// wg.Go starts has no recovery of its own, so without this a panicking check
// would take the process down rather than fail one probe.
func runCheck(ctx context.Context, check Check) error {
	var err error

	// The recovery lives in a closure so the result can be assigned from the
	// deferred function without a named return, which this project does not
	// use.
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("check panicked: %v", recovered)
			}
		}()

		err = check(ctx)
	}()

	return err
}

// newReadinessHandler reports whether the process should receive new traffic:
// 200 while serving and every check passes, 503 once draining or when a check
// fails.
//
// Draining wins over the checks and skips them: a process on its way out is
// not a routing target whatever its dependencies say, and the answer should
// not wait on them.
//
// Readiness here means "this process is willing to take work", so a check
// should name a dependency without which requests cannot be served at all. A
// shared dependency that is merely slow must not simultaneously remove every
// replica from rotation.
func newReadinessHandler(ready *Readiness, logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ready.Draining() {
			WriteJSON(w, logger, http.StatusServiceUnavailable, readinessResponse{Status: "draining"})

			return
		}

		if failed := ready.failing(r.Context(), logger); len(failed) > 0 {
			WriteJSON(w, logger, http.StatusServiceUnavailable, readinessResponse{Status: "not_ready", Failing: failed})

			return
		}

		WriteJSON(w, logger, http.StatusOK, readinessResponse{Status: "ready"})
	})
}
