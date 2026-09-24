package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// testCookieConfig returns a Config suitable for cookie tests. Its cookie
// name deliberately omits the __Host- prefix so a secure-false test config
// stays valid on its own terms.
func testCookieConfig() Config {
	cfg := DefaultConfig()
	cfg.CookieName = "service_session"

	return cfg
}

// farFutureSession returns a Session whose AbsoluteExpiresAt is far enough in
// the future that SetCookie's MaxAge is governed by the configured idle
// timeout rather than by absolute expiry, for tests in this file that assert
// on cookie attributes other than MaxAge.
func farFutureSession() Session {
	return Session{AbsoluteExpiresAt: time.Now().Add(365 * 24 * time.Hour)}
}

// resultCookie returns the single Set-Cookie header rec captured, matched by
// name.
func resultCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}

	t.Fatalf("resultCookie: no cookie named %q was set", name)

	return nil
}

// TestStoreSetCookieSetsAttributes covers AC-008.13.
func TestStoreSetCookieSetsAttributes(t *testing.T) {
	t.Parallel()

	cfg := testCookieConfig()
	cfg.CookieSecure = true
	store := NewStore(nil, cfg, time.Now)

	rec := httptest.NewRecorder()
	store.SetCookie(rec, "token-value", farFutureSession())

	cookie := resultCookie(t, rec, cfg.CookieName)

	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}

	if !cookie.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want SameSiteLaxMode", cookie.SameSite)
	}

	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}

	if cookie.Domain != "" {
		t.Errorf("Domain = %q, want empty", cookie.Domain)
	}
}

// TestStoreSetCookieOmitsSecureWhenConfiguredInsecure covers AC-008.13.
func TestStoreSetCookieOmitsSecureWhenConfiguredInsecure(t *testing.T) {
	t.Parallel()

	cfg := testCookieConfig()
	cfg.CookieSecure = false
	store := NewStore(nil, cfg, time.Now)

	rec := httptest.NewRecorder()
	store.SetCookie(rec, "token-value", farFutureSession())

	cookie := resultCookie(t, rec, cfg.CookieName)

	if cookie.Secure {
		t.Error("Secure = true, want false when CookieSecure is false")
	}
}

// TestStoreClearCookieExpiresImmediately covers AC-008.15.
func TestStoreClearCookieExpiresImmediately(t *testing.T) {
	t.Parallel()

	cfg := testCookieConfig()
	store := NewStore(nil, cfg, time.Now)

	rec := httptest.NewRecorder()
	store.ClearCookie(rec)

	cookie := resultCookie(t, rec, cfg.CookieName)

	if cookie.Value != "" {
		t.Errorf("Value = %q, want empty", cookie.Value)
	}

	if cookie.MaxAge > 0 {
		t.Errorf("MaxAge = %d, want zero or negative", cookie.MaxAge)
	}
}

// TestStoreClearCookieMatchesSetCookieAttributes proves that ClearCookie
// reuses SetCookie's Name, Path, Domain, Secure, HttpOnly, and SameSite
// attributes exactly, so a browser is guaranteed to match the clearing
// cookie against the one it is holding: a mismatch on any one of them (a
// different Path in particular) makes a browser store the clear as a second,
// unrelated cookie and leave the original in place. Run once with a
// __Host--prefixed name and CookieSecure true, and once with a non-prefixed
// name and CookieSecure false, since Path and Secure interact with the name
// under AC-008.41's __Host- rule.
func TestStoreClearCookieMatchesSetCookieAttributes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cookieName   string
		cookieSecure bool
	}{
		"host-prefixed name with secure cookies": {
			cookieName:   "__Host-service_session",
			cookieSecure: true,
		},
		"plain name with insecure cookies": {
			cookieName:   "service_session",
			cookieSecure: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := testCookieConfig()
			cfg.CookieName = tt.cookieName
			cfg.CookieSecure = tt.cookieSecure
			store := NewStore(nil, cfg, time.Now)

			setRec := httptest.NewRecorder()
			store.SetCookie(setRec, "token-value", farFutureSession())
			setCookie := resultCookie(t, setRec, cfg.CookieName)

			clearRec := httptest.NewRecorder()
			store.ClearCookie(clearRec)
			clearCookie := resultCookie(t, clearRec, cfg.CookieName)

			if clearCookie.Name != setCookie.Name {
				t.Errorf("cleared Name = %q, want %q", clearCookie.Name, setCookie.Name)
			}

			if clearCookie.Path != setCookie.Path {
				t.Errorf("cleared Path = %q, want %q", clearCookie.Path, setCookie.Path)
			}

			if clearCookie.Domain != setCookie.Domain {
				t.Errorf("cleared Domain = %q, want %q", clearCookie.Domain, setCookie.Domain)
			}

			if clearCookie.Secure != setCookie.Secure {
				t.Errorf("cleared Secure = %v, want %v", clearCookie.Secure, setCookie.Secure)
			}

			if clearCookie.HttpOnly != setCookie.HttpOnly {
				t.Errorf("cleared HttpOnly = %v, want %v", clearCookie.HttpOnly, setCookie.HttpOnly)
			}

			if clearCookie.SameSite != setCookie.SameSite {
				t.Errorf("cleared SameSite = %v, want %v", clearCookie.SameSite, setCookie.SameSite)
			}

			if clearCookie.Value != "" {
				t.Errorf("cleared Value = %q, want empty", clearCookie.Value)
			}

			if clearCookie.MaxAge >= 0 {
				t.Errorf("cleared MaxAge = %d, want negative", clearCookie.MaxAge)
			}
		})
	}
}

// TestStoreTokenFromRequestReturnsCookieValue covers AC-008.11.
func TestStoreTokenFromRequestReturnsCookieValue(t *testing.T) {
	t.Parallel()

	cfg := testCookieConfig()
	store := NewStore(nil, cfg, time.Now)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: "presented-token"})

	if got := store.TokenFromRequest(req); got != "presented-token" {
		t.Errorf("TokenFromRequest() = %q, want %q", got, "presented-token")
	}

	bare := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	if got := store.TokenFromRequest(bare); got != "" {
		t.Errorf("TokenFromRequest() = %q, want empty for a request with no cookie", got)
	}
}

// TestConfigValidate covers AC-008.41.
func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg     Config
		wantErr bool
	}{
		"host prefix without secure fails": {
			cfg: Config{
				CookieName:      DefaultCookieName,
				CookieSecure:    false,
				IdleTimeout:     configtype.Duration(time.Hour),
				AbsoluteTimeout: configtype.Duration(2 * time.Hour),
				CleanupInterval: configtype.Duration(time.Hour),
			},
			wantErr: true,
		},
		"idle exceeds absolute fails": {
			cfg: Config{
				CookieName:      "service_session",
				CookieSecure:    true,
				IdleTimeout:     configtype.Duration(3 * time.Hour),
				AbsoluteTimeout: configtype.Duration(2 * time.Hour),
				CleanupInterval: configtype.Duration(time.Hour),
			},
			wantErr: true,
		},
		"default config is valid": {
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		"non-host cookie without secure is valid": {
			cfg: Config{
				CookieName:      "service_session",
				CookieSecure:    false,
				IdleTimeout:     configtype.Duration(time.Hour),
				AbsoluteTimeout: configtype.Duration(2 * time.Hour),
				CleanupInterval: configtype.Duration(time.Hour),
			},
			wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := tt.cfg
			err := cfg.Validate(t.Context())
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
