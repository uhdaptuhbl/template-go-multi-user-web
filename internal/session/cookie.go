package session

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// cookieReissueInterval is how long after a session cookie was last issued an
// authenticated request issues it again, so an active browser's cookie
// tracks the server-side session while most requests write no Set-Cookie
// header.
const cookieReissueInterval = time.Hour

// SetCookie writes the session cookie carrying token, with Path=/, HttpOnly,
// SameSite=Lax, no Domain, Secure when configured, and a MaxAge equal to the
// lesser of the idle timeout and the time remaining until sess's absolute
// expiry, at least one second.
func (s *Store) SetCookie(w http.ResponseWriter, token string, sess Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.cookieMaxAge(sess),
	})
}

// cookieMaxAge returns SetCookie's MaxAge for sess: the whole seconds of the
// lesser of the configured idle timeout and the time remaining until sess's
// absolute expiry, floored at one second so a session with almost no
// absolute life left still gets a cookie a browser will store rather than
// discard outright.
func (s *Store) cookieMaxAge(sess Session) int {
	maxAge := s.cfg.IdleTimeout.Duration()

	if remaining := sess.AbsoluteExpiresAt.Sub(s.now()); remaining < maxAge {
		maxAge = remaining
	}

	return max(int(maxAge.Seconds()), 1)
}

// ReissueCookie sends the session cookie again, and records that it did, when
// cookieReissueInterval has passed since sess.CookieIssuedAt. It does nothing
// otherwise.
//
// The write is a compare-and-set: it updates cookie_issued_at only if the
// column still holds the value sess carries, and reports how many rows
// changed. When no row changed, a concurrent request already re-issued the
// cookie for this session, so this call writes nothing and returns nil
// rather than sending a second Set-Cookie header for the same refresh.
func (s *Store) ReissueCookie(ctx context.Context, w http.ResponseWriter, token string, sess Session) error {
	now := s.now()

	if now.Sub(sess.CookieIssuedAt) < cookieReissueInterval {
		return nil
	}

	const reissueQuery = `UPDATE sessions SET cookie_issued_at = $2 WHERE id = $1 AND cookie_issued_at = $3`

	tag, err := s.handle.Pool().Exec(ctx, reissueQuery, sess.ID, now, sess.CookieIssuedAt)
	if err != nil {
		return fmt.Errorf("session: reissuing cookie: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return nil
	}

	s.SetCookie(w, token, sess)

	return nil
}

// ClearCookie overwrites the session cookie with an empty value and a negative
// MaxAge, using the same attributes, so a browser drops it.
func (s *Store) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// TokenFromRequest returns the raw session token the request presents, or an
// empty string when it presents none.
func (s *Store) TokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}
