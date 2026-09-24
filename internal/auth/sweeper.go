package auth

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
)

// cleanerTimeout bounds how long a single cleaner call may take within one
// sweep, so a hung database does not wedge the sweep loop indefinitely.
const cleanerTimeout = 30 * time.Second

// Sweeper periodically removes expired sessions, ceremony state, one-time
// codes, and accounts whose deletion grace period has elapsed.
type Sweeper struct {
	interval     time.Duration
	logger       *zap.Logger
	sessions     *session.Store
	flows        *authflow.Store
	codes        *otp.Service
	invites      *invite.Service
	inviteRetain time.Duration
	accounts     *Service
}

// NewSweeper returns a sweeper that runs every interval, deleting through each
// supplied cleaner. codes may be nil, in which case the codes cleaner is
// skipped on every sweep: the emailed one-time code path is disabled by
// default and has no table to clean when no code has ever been issued.
// inviteRetain is passed through to invite.Service's DeleteExpired unchanged,
// so an invite is only removed once it has been expired for that long.
// accounts must not be nil: it is what every sweep uses, as its last step, to
// permanently purge accounts whose deletion grace period has elapsed.
func NewSweeper(interval time.Duration, logger *zap.Logger, sessions *session.Store, flows *authflow.Store, codes *otp.Service, invites *invite.Service, inviteRetain time.Duration, accounts *Service) *Sweeper {
	return &Sweeper{
		interval:     interval,
		logger:       logger,
		sessions:     sessions,
		flows:        flows,
		codes:        codes,
		invites:      invites,
		inviteRetain: inviteRetain,
		accounts:     accounts,
	}
}

// Run sweeps once immediately, unless ctx is already cancelled, and then
// sweeps again on its interval until ctx is cancelled, at which point it
// returns nil. The immediate sweep matters because a process that restarts
// more than once per interval would otherwise never sweep at all between
// restarts. It logs one debug line per sweep naming how many rows each
// cleaner removed, and one warn line when a cleaner returns an error, without
// stopping: a failed sweep is retried on the next tick rather than taking the
// process down.
func (s *Sweeper) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}

	s.sweepOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.sweepOnce(ctx)
		}
	}
}

// sweepOnce runs every configured cleaner exactly once, bounding each with
// cleanerTimeout, and logs the outcome: one debug line naming how many rows
// each cleaner removed, and one warn line per cleaner that failed. A failing
// cleaner does not prevent the remaining cleaners in the same sweep from
// running.
func (s *Sweeper) sweepOnce(ctx context.Context) {
	sessionsRemoved, err := runCleaner(ctx, "sessions", s.sessions.DeleteExpired)
	if err != nil {
		s.logger.Warn("auth: sweeper cleaner failed", zap.String("cleaner", "sessions"), zap.Error(err))
	}

	flowsRemoved, err := runCleaner(ctx, "flows", s.flows.DeleteExpired)
	if err != nil {
		s.logger.Warn("auth: sweeper cleaner failed", zap.String("cleaner", "flows"), zap.Error(err))
	}

	var codesRemoved int64

	if s.codes != nil {
		codesRemoved, err = runCleaner(ctx, "codes", s.codes.DeleteExpired)
		if err != nil {
			s.logger.Warn("auth: sweeper cleaner failed", zap.String("cleaner", "codes"), zap.Error(err))
		}
	}

	invitesRemoved, err := runCleaner(ctx, "invites", func(cleanCtx context.Context) (int64, error) {
		return s.invites.DeleteExpired(cleanCtx, s.inviteRetain)
	})
	if err != nil {
		s.logger.Warn("auth: sweeper cleaner failed", zap.String("cleaner", "invites"), zap.Error(err))
	}

	s.logger.Debug("auth: sweep completed",
		zap.Int64("sessions_removed", sessionsRemoved),
		zap.Int64("flows_removed", flowsRemoved),
		zap.Int64("codes_removed", codesRemoved),
		zap.Int64("invites_removed", invitesRemoved),
	)

	s.sweepAccounts(ctx)
}

// sweepAccounts runs last in every sweep, purging every account whose
// deletion grace period has elapsed. Unlike the other cleaners, a failure
// here logs at error level naming the cutoff it was purging against, because
// an account that should have been permanently removed and was not is a
// retention problem, not a routine cleanup miss. It logs one info line
// naming how many accounts it purged, but only when that count is at least
// one: a sweep that purges nothing is the ordinary case and not worth a line
// every interval.
func (s *Sweeper) sweepAccounts(ctx context.Context) {
	cleanCtx, cancel := context.WithTimeout(ctx, cleanerTimeout)
	defer cancel()

	purged, err := s.accounts.PurgeExpired(cleanCtx)
	if err != nil {
		s.logger.Error("auth: sweeper purging expired accounts",
			zap.Time("cutoff", s.accounts.purgeCutoff()),
			zap.Error(err),
		)

		return
	}

	if purged > 0 {
		s.logger.Info("auth: sweep purged expired accounts", zap.Int("purged", purged))
	}
}

// runCleaner calls clean with a context derived from ctx and bounded by
// cleanerTimeout, so one slow or hung cleaner cannot consume the rest of the
// sweep's budget. It wraps a returned error with name, so a warn line logged
// from the result names which cleaner failed even before its zap fields are
// added.
func runCleaner(ctx context.Context, name string, clean func(context.Context) (int64, error)) (int64, error) {
	cleanCtx, cancel := context.WithTimeout(ctx, cleanerTimeout)
	defer cancel()

	removed, err := clean(cleanCtx)
	if err != nil {
		return 0, fmt.Errorf("auth: sweeping %s: %w", name, err)
	}

	return removed, nil
}
