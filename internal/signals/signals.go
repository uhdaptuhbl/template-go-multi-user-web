package signals

import (
	"os"

	"go.uber.org/zap"
)

// ForceExitCode is the status the process reports when a second signal cuts
// shutdown short. It is non-zero because in-flight requests were abandoned:
// the process did not finish what it had accepted.
const ForceExitCode = 1

// ForceExitOnSecond consumes one signal from sigs without acting on it, then
// terminates the process by calling exit once a second arrives.
//
// The first signal is the one that began the graceful shutdown, which is
// already being handled elsewhere. The second is what distinguishes an
// operator waiting for the drain from one who has given up on it. Without
// this, repeated interrupts do nothing at all: signal.NotifyContext keeps a
// handler installed for the whole shutdown window, and an installed handler
// suppresses the runtime's default terminate behaviour, so the only way out
// of a wedged drain is SIGKILL from another terminal.
//
// Callers run it in a goroutine and pass os.Exit as exit. On the ordinary
// path it never returns, because the process finishes shutting down and exits
// while it is still blocked on the second signal. It is therefore given no
// context to cancel: there is nothing to release, and a goroutine parked on a
// channel read costs nothing.
func ForceExitOnSecond(sigs <-chan os.Signal, logger *zap.Logger, exit func(int)) {
	<-sigs

	sig := <-sigs

	logger.Warn("second signal received, abandoning in-flight requests",
		zap.String("signal", sig.String()),
		zap.Int("exit_code", ForceExitCode),
	)

	exit(ForceExitCode)
}
