//go:build integration

package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// clock is a manually advanced clock for tests that must control the passage
// of time without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock returns a clock starting at the current wall time.
func newClock() *clock {
	return &clock{now: time.Now()}
}

// Now returns the clock's current time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Advance moves the clock forward by d.
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// testConfig returns a Config with short, distinct idle and absolute
// timeouts, so a test can cross either expiry by advancing the clock a small
// amount.
func testConfig() Config {
	cfg := DefaultConfig()
	cfg.IdleTimeout = configtype.Duration(10 * time.Minute)
	cfg.AbsoluteTimeout = configtype.Duration(20 * time.Minute)

	return cfg
}

// newTestStore returns a Store backed by a fresh migrated database and c's
// clock.
func newTestStore(t *testing.T, c *clock) (*Store, *store.Handle) {
	t.Helper()

	h := storetest.New(t)

	return NewStore(h, testConfig(), c.Now), h
}

// newReissueTestStore returns a Store using DefaultConfig's ordinary idle and
// absolute timeouts, backed by a fresh migrated database and c's clock. The
// ReissueCookie tests advance the clock by roughly an hour to cross
// cookieReissueInterval, which would collide with testConfig's short
// 10-minute idle timeout that the rest of this file's Lookup and expiry
// tests rely on.
func newReissueTestStore(t *testing.T, c *clock) (*Store, *store.Handle) {
	t.Helper()

	h := storetest.New(t)

	return NewStore(h, DefaultConfig(), c.Now), h
}

// insertUser inserts a minimal user row with the given status directly,
// since internal/user is a separate package this unit does not depend on.
func insertUser(t *testing.T, h *store.Handle, status string) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("insertUser: generating id: %v", err)
	}

	now := time.Now()

	const insertUserQuery = `
INSERT INTO users (id, display_name, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
`

	if _, execErr := h.Pool().Exec(t.Context(), insertUserQuery, id, "test user", status, now, now); execErr != nil {
		t.Fatalf("insertUser: inserting: %v", execErr)
	}

	return id
}

// TestIssueReturnsTokenAndMatchingDigest covers AC-008.11 and AC-008.12.
func TestIssueReturnsTokenAndMatchingDigest(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	sess, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if len(token) != 43 {
		t.Errorf("len(token) = %d, want 43", len(token))
	}

	if len(sess.ID) != 32 {
		t.Errorf("len(sess.ID) = %d, want 32", len(sess.ID))
	}

	digest := Digest(token)
	if !bytes.Equal(sess.ID, digest) {
		t.Errorf("sess.ID = %x, want Digest(token) = %x", sess.ID, digest)
	}

	if string(sess.ID) == token {
		t.Error("sess.ID equals the raw token; it must be a digest, not the token itself")
	}
}

// TestIssueProducesUniqueTokensAndPublicIDs covers AC-008.11.
func TestIssueProducesUniqueTokensAndPublicIDs(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	first, firstToken, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	second, secondToken, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if firstToken == secondToken {
		t.Error("two calls to Issue produced the same token")
	}

	if first.PublicID == second.PublicID {
		t.Error("two calls to Issue produced the same PublicID")
	}
}

// TestLookupSucceedsWithCorrectToken covers AC-008.14.
func TestLookupSucceedsWithCorrectToken(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	issued, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	found, err := sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if found.PublicID != issued.PublicID {
		t.Errorf("found.PublicID = %v, want %v", found.PublicID, issued.PublicID)
	}
}

// TestLookupFailsWithWrongToken covers AC-008.14.
func TestLookupFailsWithWrongToken(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	_, _, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = sessions.Lookup(t.Context(), "this-token-was-never-issued-000000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup() error = %v, want ErrNotFound", err)
	}
}

// TestLookupFailsAfterIdleTimeout covers AC-008.14.
func TestLookupFailsAfterIdleTimeout(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	_, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	c.Advance(11 * time.Minute)

	_, err = sessions.Lookup(t.Context(), token)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup() after idle timeout error = %v, want ErrNotFound", err)
	}
}

// TestLookupSucceedsUntilAbsoluteExpiryDespiteRepeatedUse proves the
// absolute expiry never advances even though every Lookup call refreshes the
// idle expiry.
// Covers AC-008.14.
func TestLookupSucceedsUntilAbsoluteExpiryDespiteRepeatedUse(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	_, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Advance just under the idle timeout, repeatedly, well past what the
	// idle timeout alone would allow, proving the absolute expiry is the one
	// enforced.
	for range 2 {
		c.Advance(9 * time.Minute)

		if _, lookupErr := sessions.Lookup(t.Context(), token); lookupErr != nil {
			t.Fatalf("Lookup() error = %v, want success while under both expiries", lookupErr)
		}
	}

	c.Advance(9 * time.Minute)

	_, err = sessions.Lookup(t.Context(), token)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup() past AbsoluteExpiresAt error = %v, want ErrNotFound", err)
	}
}

// TestLookupCapsIdleExpiryAtAbsoluteExpiry covers AC-008.14: the idle
// refresh a Lookup applies never pushes idle_expires_at past
// absolute_expires_at, so the stored idle expiry never names a time the
// session cannot reach.
func TestLookupCapsIdleExpiryAtAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	issued, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// A use at nine minutes keeps the session inside its idle window. A use
	// six minutes later, fifteen minutes in, would have a ten-minute idle
	// refresh land five minutes past the twenty-minute absolute expiry.
	c.Advance(9 * time.Minute)

	if _, err = sessions.Lookup(t.Context(), token); err != nil {
		t.Fatalf("first Lookup() error = %v", err)
	}

	c.Advance(6 * time.Minute)

	looked, err := sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if looked.IdleExpiresAt.After(looked.AbsoluteExpiresAt) {
		t.Errorf("Lookup() IdleExpiresAt = %v, after AbsoluteExpiresAt %v", looked.IdleExpiresAt, looked.AbsoluteExpiresAt)
	}

	if !looked.AbsoluteExpiresAt.Equal(issued.AbsoluteExpiresAt.Truncate(time.Microsecond)) {
		t.Errorf("Lookup() AbsoluteExpiresAt = %v, want unchanged %v", looked.AbsoluteExpiresAt, issued.AbsoluteExpiresAt)
	}
}

// TestLookupFailsForSuspendedAccount covers AC-008.47.
func TestLookupFailsForSuspendedAccount(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "suspended")

	_, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = sessions.Lookup(t.Context(), token)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup() for suspended account error = %v, want ErrNotFound", err)
	}
}

// TestRevokeTokenInvalidatesSession covers AC-008.15.
func TestRevokeTokenInvalidatesSession(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	_, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if revokeErr := sessions.RevokeToken(t.Context(), token); revokeErr != nil {
		t.Fatalf("RevokeToken() error = %v", revokeErr)
	}

	_, err = sessions.Lookup(t.Context(), token)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup() after RevokeToken error = %v, want ErrNotFound", err)
	}
}

// TestDeleteExpiredRemovesExpiredAndKeepsLive covers AC-008.14.
func TestDeleteExpiredRemovesExpiredAndKeepsLive(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	expiring, _, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	c.Advance(25 * time.Minute)

	live, liveToken, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	deleted, err := sessions.DeleteExpired(t.Context())
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	if deleted != 1 {
		t.Errorf("DeleteExpired() deleted = %d, want 1", deleted)
	}

	if _, liveErr := sessions.Lookup(t.Context(), liveToken); liveErr != nil {
		t.Errorf("Lookup() for the live session, error = %v, want success", liveErr)
	}

	remaining, err := sessions.ListFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListFor() error = %v", err)
	}

	var sawLive bool

	for _, s := range remaining {
		if s.PublicID == expiring.PublicID {
			t.Error("DeleteExpired left the expired session in place")
		}

		if s.PublicID == live.PublicID {
			sawLive = true
		}
	}

	if !sawLive {
		t.Error("DeleteExpired removed the live session as well as the expired one")
	}
}

// TestSessionMarshalJSONFails asserts a Session can never be serialized
// directly, and that a failed attempt emits no byte of the session digest.
// Covers AC-008.40.
func TestSessionMarshalJSONFails(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	sess, _, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	out, err := json.Marshal(sess)
	if err == nil {
		t.Fatal("json.Marshal(Session) error = nil, want an error")
	}

	if len(sess.ID) > 0 && bytesContain(out, sess.ID) {
		t.Error("json.Marshal(Session) output contains a byte sequence of the session digest")
	}
}

// bytesContain reports whether needle appears anywhere in haystack.
func bytesContain(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}

	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true

		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false

				break
			}
		}

		if match {
			return true
		}
	}

	return false
}

// TestRevokeIsScopedToOwner is the ownership isolation test (design.md's
// "Authorization path") for Revoke.
// Covers AC-008.35.
func TestRevokeIsScopedToOwner(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userA := insertUser(t, h, "active")
	userB := insertUser(t, h, "active")

	sessA, tokenA, err := sessions.Issue(t.Context(), userA, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() for A, error = %v", err)
	}

	_, tokenB, err := sessions.Issue(t.Context(), userB, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	sessB, err := sessions.Lookup(t.Context(), tokenB)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	deleted, err := sessions.Revoke(t.Context(), userA, sessB.PublicID)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if deleted {
		t.Error("Revoke() deleted = true, want false when the caller does not own the session")
	}

	if _, bLookupErr := sessions.Lookup(t.Context(), tokenB); bLookupErr != nil {
		t.Errorf("Lookup() for B's session after A's Revoke, error = %v, want success", bLookupErr)
	}

	// The negative half above passes for a predicate that deletes nothing at
	// all, so prove the positive half in the same test: A revoking A's own
	// session does delete it.
	ownDeleted, err := sessions.Revoke(t.Context(), userA, sessA.PublicID)
	if err != nil {
		t.Fatalf("Revoke() for A's own session, error = %v", err)
	}

	if !ownDeleted {
		t.Error("Revoke() deleted = false for the caller's own session, want true")
	}

	if _, lookupErr := sessions.Lookup(t.Context(), tokenA); !errors.Is(lookupErr, ErrNotFound) {
		t.Errorf("Lookup() for A's own revoked session, error = %v, want ErrNotFound", lookupErr)
	}
}

// TestRevokeAllForIsScopedToOwner is the ownership isolation test
// (design.md's "Authorization path") for RevokeAllFor.
// Covers AC-008.35.
func TestRevokeAllForIsScopedToOwner(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userA := insertUser(t, h, "active")
	userB := insertUser(t, h, "active")

	_, tokenB, err := sessions.Issue(t.Context(), userB, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	deleted, err := sessions.RevokeAllFor(t.Context(), userA)
	if err != nil {
		t.Fatalf("RevokeAllFor() error = %v", err)
	}

	if deleted != 0 {
		t.Errorf("RevokeAllFor() deleted = %d, want 0 when the caller owns nothing", deleted)
	}

	if _, bLookupErr := sessions.Lookup(t.Context(), tokenB); bLookupErr != nil {
		t.Errorf("Lookup() for B's session after A's RevokeAllFor, error = %v, want success", bLookupErr)
	}

	// Everything above also passes for a predicate that deletes nothing at
	// all, so give A a session of its own and prove the positive half: the
	// same call clears A's sessions and still leaves B's alone.
	_, tokenA, err := sessions.Issue(t.Context(), userA, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() for A, error = %v", err)
	}

	ownDeleted, err := sessions.RevokeAllFor(t.Context(), userA)
	if err != nil {
		t.Fatalf("RevokeAllFor() for A's own sessions, error = %v", err)
	}

	if ownDeleted != 1 {
		t.Errorf("RevokeAllFor() deleted = %d for the caller's own sessions, want 1", ownDeleted)
	}

	if _, lookupErr := sessions.Lookup(t.Context(), tokenA); !errors.Is(lookupErr, ErrNotFound) {
		t.Errorf("Lookup() for A's own revoked session, error = %v, want ErrNotFound", lookupErr)
	}

	if _, lookupErr := sessions.Lookup(t.Context(), tokenB); lookupErr != nil {
		t.Errorf("Lookup() for B's session after A cleared its own, error = %v, want success", lookupErr)
	}
}

// TestRevokeAllForTxRemovesRowsAndCommits covers the transactional form of
// revoking every session for an account (AC-008.48): RevokeAllForTx removes
// every session for an account and, once the caller commits, the removal
// is visible through the ordinary pool-backed Lookup.
func TestRevokeAllForTxRemovesRowsAndCommits(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userID := insertUser(t, h, "active")

	_, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	deleted, err := sessions.RevokeAllForTx(t.Context(), tx, userID)
	if err != nil {
		t.Fatalf("RevokeAllForTx() error = %v, want nil", err)
	}

	if deleted != 1 {
		t.Fatalf("RevokeAllForTx() deleted = %d, want 1", deleted)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v", commitErr)
	}

	if _, lookupErr := sessions.Lookup(t.Context(), token); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("Lookup() after committed RevokeAllForTx, error = %v, want ErrNotFound", lookupErr)
	}
}

// TestRevokeAllForTxIsScopedToOwner mirrors TestRevokeAllForIsScopedToOwner
// for the transactional variant: acting through userA removes none of
// userB's sessions.
// Covers AC-008.35.
func TestRevokeAllForTxIsScopedToOwner(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userA := insertUser(t, h, "active")
	userB := insertUser(t, h, "active")

	_, tokenB, err := sessions.Issue(t.Context(), userB, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			t.Logf("Rollback() error = %v", rollbackErr)
		}
	}()

	deleted, err := sessions.RevokeAllForTx(t.Context(), tx, userA)
	if err != nil {
		t.Fatalf("RevokeAllForTx() error = %v, want nil", err)
	}

	if deleted != 0 {
		t.Fatalf("RevokeAllForTx() deleted = %d, want 0 when the caller owns nothing", deleted)
	}

	if commitErr := tx.Commit(t.Context()); commitErr != nil {
		t.Fatalf("Commit() error = %v", commitErr)
	}

	if _, lookupErr := sessions.Lookup(t.Context(), tokenB); lookupErr != nil {
		t.Fatalf("Lookup() for B's session after A's RevokeAllForTx, error = %v, want success", lookupErr)
	}
}

// TestListForReturnsOnlyOwnSessions is the ownership isolation test
// (design.md's "Authorization path") for ListFor.
// Covers AC-008.16 and AC-008.35.
func TestListForReturnsOnlyOwnSessions(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newTestStore(t, c)
	userA := insertUser(t, h, "active")
	userB := insertUser(t, h, "active")

	sessA, _, err := sessions.Issue(t.Context(), userA, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	sessB, _, err := sessions.Issue(t.Context(), userB, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	listA, err := sessions.ListFor(t.Context(), userA)
	if err != nil {
		t.Fatalf("ListFor() error = %v", err)
	}

	foundA := false

	for _, s := range listA {
		if s.PublicID == sessB.PublicID {
			t.Error("ListFor(userA) contains userB's session")
		}

		if s.PublicID == sessA.PublicID {
			foundA = true
		}
	}

	if !foundA {
		t.Error("ListFor(userA) does not contain userA's own session")
	}
}

// TestReissueCookieAfterAnHour covers AC-008.77: a session's cookie is not
// resent before cookieReissueInterval has passed since it was last issued,
// and is resent, with a fresh cookie_issued_at and a MaxAge equal to the
// configured idle timeout, once it has.
func TestReissueCookieAfterAnHour(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newReissueTestStore(t, c)
	userID := insertUser(t, h, "active")

	sess, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	c.Advance(59 * time.Minute)

	earlyRec := httptest.NewRecorder()
	if reissueErr := sessions.ReissueCookie(t.Context(), earlyRec, token, sess); reissueErr != nil {
		t.Fatalf("ReissueCookie() error = %v", reissueErr)
	}

	if len(earlyRec.Result().Cookies()) != 0 {
		t.Fatal("ReissueCookie() wrote a Set-Cookie header before cookieReissueInterval had passed")
	}

	c.Advance(2 * time.Minute) // total 61m since Issue

	lateRec := httptest.NewRecorder()
	if reissueErr := sessions.ReissueCookie(t.Context(), lateRec, token, sess); reissueErr != nil {
		t.Fatalf("ReissueCookie() error = %v", reissueErr)
	}

	cookie := resultCookie(t, lateRec, sessions.cfg.CookieName)

	wantMaxAge := int(sessions.cfg.IdleTimeout.Duration().Seconds())
	if cookie.MaxAge != wantMaxAge {
		t.Errorf("MaxAge = %d, want %d", cookie.MaxAge, wantMaxAge)
	}

	updated, err := sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if !updated.CookieIssuedAt.After(sess.CookieIssuedAt) {
		t.Errorf("CookieIssuedAt = %v, want later than %v", updated.CookieIssuedAt, sess.CookieIssuedAt)
	}
}

// TestReissueCookieMaxAgeCappedByAbsoluteExpiry covers AC-008.77: MaxAge
// never outlives the session's absolute expiry, even though it is
// ordinarily set to the (much longer) idle timeout.
func TestReissueCookieMaxAgeCappedByAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	c := newClock()
	h := storetest.New(t)

	cfg := DefaultConfig()
	cfg.IdleTimeout = configtype.Duration(24 * time.Hour)
	cfg.AbsoluteTimeout = configtype.Duration(71 * time.Minute)

	sessions := NewStore(h, cfg, c.Now)
	userID := insertUser(t, h, "active")

	sess, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	c.Advance(61 * time.Minute)

	rec := httptest.NewRecorder()
	if reissueErr := sessions.ReissueCookie(t.Context(), rec, token, sess); reissueErr != nil {
		t.Fatalf("ReissueCookie() error = %v", reissueErr)
	}

	cookie := resultCookie(t, rec, cfg.CookieName)

	const wantMaxAge = 600
	if cookie.MaxAge != wantMaxAge {
		t.Errorf("MaxAge = %d, want %d", cookie.MaxAge, wantMaxAge)
	}
}

// TestReissueCookieConcurrentCallsWriteOnce covers AC-008.77: two callers
// racing to reissue the same stale cookie must not both win. The
// compare-and-set in ReissueCookie's UPDATE means exactly one of them sees a
// changed row and writes the Set-Cookie header; the other finds the column
// already advanced and does nothing.
func TestReissueCookieConcurrentCallsWriteOnce(t *testing.T) {
	t.Parallel()

	c := newClock()
	sessions, h := newReissueTestStore(t, c)
	userID := insertUser(t, h, "active")

	sess, token, err := sessions.Issue(t.Context(), userID, "203.0.113.5", "test-agent", []string{MethodOTP})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	c.Advance(61 * time.Minute)

	firstRec := httptest.NewRecorder()
	secondRec := httptest.NewRecorder()

	var firstErr error
	var secondErr error
	var wg sync.WaitGroup

	wg.Go(func() {
		firstErr = sessions.ReissueCookie(t.Context(), firstRec, token, sess)
	})
	wg.Go(func() {
		secondErr = sessions.ReissueCookie(t.Context(), secondRec, token, sess)
	})

	wg.Wait()

	if firstErr != nil {
		t.Fatalf("first ReissueCookie() error = %v", firstErr)
	}

	if secondErr != nil {
		t.Fatalf("second ReissueCookie() error = %v", secondErr)
	}

	firstWrote := len(firstRec.Result().Cookies()) > 0
	secondWrote := len(secondRec.Result().Cookies()) > 0

	if firstWrote == secondWrote {
		t.Fatalf("first wrote a cookie = %v, second wrote a cookie = %v; want exactly one", firstWrote, secondWrote)
	}
}
