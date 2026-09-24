package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// bucket pairs a token-bucket limiter with the last time it was used, so
// Reap can tell an idle key from an active one, and whether it is currently
// in a run of refusals, so Decide can tell a first refusal from a repeat.
type bucket struct {
	limiter  *rate.Limiter
	lastUsed time.Time
	refusing bool
}

// Decision is the outcome of one rate-limit check.
type Decision struct {
	// Allowed reports whether the event may proceed.
	Allowed bool
	// FirstRefusal reports whether this refusal is the first for its key since the key was
	// last allowed (or since the key was first seen). It is false whenever Allowed is true.
	FirstRefusal bool
}

// Limiter allows a bounded rate of events per key, forgetting a key that has
// gone quiet so a long-running process does not accumulate one bucket per
// address that ever reached it.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	perMinute int
	burst     int
	now       func() time.Time
}

// New returns a limiter allowing perMinute events per key per minute with the
// given burst, using now as its clock so tests need no sleeping. Passing a nil
// clock uses time.Now.
func New(perMinute, burst int, now func() time.Time) *Limiter {
	clock := now
	if clock == nil {
		clock = time.Now
	}

	return &Limiter{
		buckets:   make(map[string]*bucket),
		perMinute: perMinute,
		burst:     burst,
		now:       clock,
	}
}

// Allow reports whether an event for key may proceed, consuming one token when
// it may.
func (l *Limiter) Allow(key string) bool {
	return l.Decide(key).Allowed
}

// Decide reports whether an event for key may proceed, consuming one token when it may, and
// whether a refusal is the first in a run of refusals for key.
func (l *Limiter) Decide(key string) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	current := l.now()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			limiter: rate.NewLimiter(rate.Limit(float64(l.perMinute)/60), l.burst),
		}
		l.buckets[key] = b
	}

	b.lastUsed = current

	if b.limiter.AllowN(current, 1) {
		b.refusing = false
		return Decision{Allowed: true}
	}

	firstRefusal := !b.refusing
	b.refusing = true

	return Decision{Allowed: false, FirstRefusal: firstRefusal}
}

// KeyForIP returns the rate-limit key for a client address: an IPv4 address (including an
// IPv4-mapped IPv6 address, unmapped) as itself, an IPv6 address as its /64 prefix in
// netip.Prefix string form (for example "2001:db8:1:2::/64"), and any string that does not
// parse as an address unchanged.
func KeyForIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	unmapped := addr.Unmap()
	if unmapped.Is4() {
		return unmapped.String()
	}

	return netip.PrefixFrom(unmapped, 64).Masked().String()
}

// Reap discards buckets untouched for longer than idle. The caller runs it on
// a ticker.
func (l *Limiter) Reap(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	current := l.now()

	for key, b := range l.buckets {
		if current.Sub(b.lastUsed) > idle {
			delete(l.buckets, key)
		}
	}
}
