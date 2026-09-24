package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// TestAllowPermitsBurstThenDenies covers AC-008.37.
func TestAllowPermitsBurstThenDenies(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 3, clock)

	tests := []struct {
		name string
		want bool
	}{
		{name: "first", want: true},
		{name: "second", want: true},
		{name: "third", want: true},
		{name: "fourth, burst exhausted", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := limiter.Allow("client-a"); got != tt.want {
				t.Errorf("Allow(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestAllowRefillsAfterAMinute covers AC-008.37.
func TestAllowRefillsAfterAMinute(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 1, clock)

	if got := limiter.Allow("client-a"); !got {
		t.Fatalf("Allow() first call = %v, want true", got)
	}

	if got := limiter.Allow("client-a"); got {
		t.Fatalf("Allow() before refill = %v, want false", got)
	}

	now = now.Add(time.Minute)

	if got := limiter.Allow("client-a"); !got {
		t.Errorf("Allow() after refill = %v, want true", got)
	}
}

// TestAllowKeepsIndependentBucketsPerKey covers AC-008.37.
func TestAllowKeepsIndependentBucketsPerKey(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 1, clock)

	if got := limiter.Allow("client-a"); !got {
		t.Fatalf("Allow(client-a) = %v, want true", got)
	}

	if got := limiter.Allow("client-a"); got {
		t.Fatalf("Allow(client-a) second call = %v, want false", got)
	}

	if got := limiter.Allow("client-b"); !got {
		t.Errorf("Allow(client-b) = %v, want true, independent of client-a's exhausted bucket", got)
	}
}

// TestReapDiscardsOnlyStaleBuckets covers AC-008.37.
func TestReapDiscardsOnlyStaleBuckets(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 1, clock)

	limiter.Allow("stale")

	now = now.Add(time.Hour)

	limiter.Allow("fresh")

	limiter.Reap(time.Minute)

	limiter.mu.Lock()
	_, staleExists := limiter.buckets["stale"]
	_, freshExists := limiter.buckets["fresh"]
	limiter.mu.Unlock()

	if staleExists {
		t.Errorf("bucket %q still present after Reap, want it discarded", "stale")
	}

	if !freshExists {
		t.Errorf("bucket %q missing after Reap, want it kept", "fresh")
	}
}

// TestDecideReportsFirstRefusalOnlyOnce covers AC-008.88.
func TestDecideReportsFirstRefusalOnlyOnce(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 2, clock)

	tests := []struct {
		name        string
		wantAllowed bool
		wantFirst   bool
	}{
		{name: "first burst token", wantAllowed: true, wantFirst: false},
		{name: "second burst token", wantAllowed: true, wantFirst: false},
		{name: "first refusal", wantAllowed: false, wantFirst: true},
		{name: "second refusal, not first", wantAllowed: false, wantFirst: false},
		{name: "third refusal, not first", wantAllowed: false, wantFirst: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limiter.Decide("client-a")
			if got.Allowed != tt.wantAllowed {
				t.Errorf("Decide(%q).Allowed = %v, want %v", tt.name, got.Allowed, tt.wantAllowed)
			}

			if got.FirstRefusal != tt.wantFirst {
				t.Errorf("Decide(%q).FirstRefusal = %v, want %v", tt.name, got.FirstRefusal, tt.wantFirst)
			}
		})
	}
}

// TestDecideResetsFirstRefusalAfterAnAllow covers AC-008.88.
func TestDecideResetsFirstRefusalAfterAnAllow(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := start
	clock := func() time.Time { return now }

	limiter := New(60, 1, clock)

	if got := limiter.Decide("client-a"); !got.Allowed {
		t.Fatalf("Decide() first call Allowed = %v, want true", got.Allowed)
	}

	first := limiter.Decide("client-a")
	if first.Allowed || !first.FirstRefusal {
		t.Fatalf("Decide() second call = %+v, want a first refusal", first)
	}

	second := limiter.Decide("client-a")
	if second.Allowed || second.FirstRefusal {
		t.Fatalf("Decide() third call = %+v, want a refusal that is not first", second)
	}

	now = now.Add(time.Minute)

	afterRefill := limiter.Decide("client-a")
	if !afterRefill.Allowed {
		t.Fatalf("Decide() after refill = %+v, want Allowed true", afterRefill)
	}

	nextRefusal := limiter.Decide("client-a")
	if nextRefusal.Allowed || !nextRefusal.FirstRefusal {
		t.Fatalf("Decide() after the allow = %+v, want a first refusal again", nextRefusal)
	}
}

// TestKeyForIP covers AC-008.37.
func TestKeyForIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "IPv4 address", ip: "192.0.2.7", want: "192.0.2.7"},
		{name: "IPv4-mapped IPv6 address unmaps", ip: "::ffff:192.0.2.7", want: "192.0.2.7"},
		{name: "IPv6 address collapses to its /64", ip: "2001:db8:1:2:aaaa::1", want: "2001:db8:1:2::/64"},
		{name: "different host in the same /64 collapses the same way", ip: "2001:db8:1:2:bbbb::9", want: "2001:db8:1:2::/64"},
		{name: "non-IP string passes through unchanged", ip: "not-an-ip", want: "not-an-ip"},
		{name: "empty string passes through unchanged", ip: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := KeyForIP(tt.ip); got != tt.want {
				t.Errorf("KeyForIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// TestAllowIsSafeForConcurrentUseOnTheSameKey covers AC-008.37.
func TestAllowIsSafeForConcurrentUseOnTheSameKey(t *testing.T) {
	t.Parallel()

	limiter := New(1000, 1000, nil)

	var wg sync.WaitGroup

	for range 20 {
		wg.Go(func() {
			for range 20 {
				limiter.Allow("shared")
			}
		})
	}

	wg.Wait()
}
