package signals

import (
	"os"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestForceExitOnSecondExitsAfterASecondSignal covers AC-001.12.
func TestForceExitOnSecondExitsAfterASecondSignal(t *testing.T) {
	t.Parallel()

	// Buffered, so neither send can block. An implementation that exits on the
	// first signal then has no receiver for the second, and this test has to
	// fail on its assertion rather than deadlock on the send.
	sigs := make(chan os.Signal, 2)
	exited := make(chan int, 1)

	go ForceExitOnSecond(sigs, zap.NewNop(), func(code int) { exited <- code })

	sigs <- syscall.SIGTERM
	sigs <- os.Interrupt

	select {
	case code := <-exited:
		// The literal is deliberate. Comparing against ForceExitCode would
		// assert the constant equals itself and would still pass if the
		// constant were changed to report success.
		if code != 1 {
			t.Errorf("got exit code %d, want 1", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ForceExitOnSecond did not exit within 10s of the second signal")
	}
}

// TestForceExitOnSecondIgnoresTheFirstSignal covers AC-001.12.
// The first signal is the one that starts the graceful shutdown, so acting on
// it would defeat the drain this exists to protect.
func TestForceExitOnSecondIgnoresTheFirstSignal(t *testing.T) {
	t.Parallel()

	// Unbuffered, so the send below returns only once the goroutine has taken
	// the signal. That makes the assertion deterministic rather than a race
	// against a timer: at the moment the send completes the goroutine is
	// necessarily blocked on its second receive, so it cannot yet have exited.
	sigs := make(chan os.Signal)
	exited := make(chan int, 1)

	go ForceExitOnSecond(sigs, zap.NewNop(), func(code int) { exited <- code })

	sigs <- os.Interrupt

	select {
	case code := <-exited:
		t.Fatalf("exited with code %d after a single signal, want no exit", code)
	default:
	}
}
