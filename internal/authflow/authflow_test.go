//go:build integration

package authflow_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// jsonEqual reports whether a and b decode to the same value. Postgres's
// JSONB column reformats whitespace on round trip, so a byte comparison of
// the raw text is the wrong assumption about a third party's behavior.
func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()

	var decodedA any
	if err := json.Unmarshal(a, &decodedA); err != nil {
		t.Fatalf("jsonEqual: unmarshaling %s: %v", a, err)
	}

	var decodedB any
	if err := json.Unmarshal(b, &decodedB); err != nil {
		t.Fatalf("jsonEqual: unmarshaling %s: %v", b, err)
	}

	return reflect.DeepEqual(decodedA, decodedB)
}

// testClock is a mutable clock for tests that need to advance time
// deterministically.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// newTestClock returns a testClock starting at the given time.
func newTestClock(start time.Time) *testClock {
	return &testClock{now: start}
}

// Now returns the clock's current time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Advance moves the clock forward by d.
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// TestBeginConsumeRoundTrip covers AC-008.21: a flow begun by Begin is returned intact by Consume.
func TestBeginConsumeRoundTrip(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)
	data := json.RawMessage(`{"state":"abc"}`)

	id, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, data)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	flow, err := flows.Consume(t.Context(), authflow.KindOIDC, id)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	if !jsonEqual(t, flow.Data, data) {
		t.Fatalf("Consume: got data %s, want %s", flow.Data, data)
	}
}

// TestConsumeIsSingleUse covers AC-008.21: consuming the same identifier a second time returns ErrNotFound, so ceremony state cannot be replayed.
func TestConsumeIsSingleUse(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)

	id, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if _, consumeErr := flows.Consume(t.Context(), authflow.KindOIDC, id); consumeErr != nil {
		t.Fatalf("first Consume: %v", consumeErr)
	}

	if _, consumeErr := flows.Consume(t.Context(), authflow.KindOIDC, id); !errors.Is(consumeErr, authflow.ErrNotFound) {
		t.Fatalf("second Consume: got %v, want ErrNotFound", consumeErr)
	}
}

// TestConsumeWrongKindLeavesFlowIntact covers AC-008.21: Consume under the wrong Kind returns ErrNotFound and leaves the flow consumable under its own Kind.
func TestConsumeWrongKindLeavesFlowIntact(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)
	data := json.RawMessage(`{"state":"abc"}`)

	id, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, data)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if _, wrongKindErr := flows.Consume(t.Context(), authflow.KindWebAuthnLogin, id); !errors.Is(wrongKindErr, authflow.ErrNotFound) {
		t.Fatalf("wrong-kind Consume: got %v, want ErrNotFound", wrongKindErr)
	}

	flow, err := flows.Consume(t.Context(), authflow.KindOIDC, id)
	if err != nil {
		t.Fatalf("right-kind Consume: %v", err)
	}

	if !jsonEqual(t, flow.Data, data) {
		t.Fatalf("right-kind Consume: got data %s, want %s", flow.Data, data)
	}
}

// TestConsumeAfterTTLReturnsNotFound covers AC-008.21: a flow past its expiry is no longer consumable.
func TestConsumeAfterTTLReturnsNotFound(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)

	id, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	clock.Advance(2 * time.Minute)

	if _, consumeErr := flows.Consume(t.Context(), authflow.KindOIDC, id); !errors.Is(consumeErr, authflow.ErrNotFound) {
		t.Fatalf("Consume after TTL: got %v, want ErrNotFound", consumeErr)
	}
}

// TestConcurrentConsumeSeesExactlyOneSuccess covers AC-008.21: two concurrent Consume calls on one flow yield exactly one success.
func TestConcurrentConsumeSeesExactlyOneSuccess(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)

	id, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	const attempts = 2
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)

	for i := range attempts {
		go func(i int) {
			defer wg.Done()

			_, errs[i] = flows.Consume(t.Context(), authflow.KindOIDC, id)
		}(i)
	}

	wg.Wait()

	var successes int
	var notFound int

	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, authflow.ErrNotFound):
			notFound++
		default:
			t.Fatalf("concurrent Consume: unexpected error %v", err)
		}
	}

	if successes != 1 || notFound != 1 {
		t.Fatalf("concurrent Consume: got %d successes and %d not-found, want 1 and 1", successes, notFound)
	}
}

// TestDeleteExpiredRemovesOnlyExpiredFlows covers AC-008.21: DeleteExpired removes expired flows and leaves live ones untouched.
func TestDeleteExpiredRemovesOnlyExpiredFlows(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)

	expiredID, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin expired: %v", err)
	}

	clock.Advance(2 * time.Minute)

	liveID, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Begin live: %v", err)
	}

	removed, err := flows.DeleteExpired(t.Context())
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if removed != 1 {
		t.Fatalf("DeleteExpired: removed %d, want 1", removed)
	}

	if _, consumeErr := flows.Consume(t.Context(), authflow.KindOIDC, expiredID); !errors.Is(consumeErr, authflow.ErrNotFound) {
		t.Fatalf("Consume expired after DeleteExpired: got %v, want ErrNotFound", consumeErr)
	}

	if _, consumeErr := flows.Consume(t.Context(), authflow.KindOIDC, liveID); consumeErr != nil {
		t.Fatalf("Consume live after DeleteExpired: %v", consumeErr)
	}
}

// TestBeginNeverReturnsSameIdentifier covers AC-008.21: Begin returns a fresh identifier on every call.
func TestBeginNeverReturnsSameIdentifier(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Now())
	handle := storetest.NewWithClock(t, clock.Now)
	flows := authflow.NewStore(handle, time.Minute, clock.Now)

	first, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("first Begin: %v", err)
	}

	second, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("second Begin: %v", err)
	}

	if first == second {
		t.Fatalf("Begin: two calls returned the same identifier %s", first)
	}
}
