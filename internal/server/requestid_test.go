package server

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// hexRequestIDPattern matches a generated identifier: 32 lowercase hexadecimal
// characters.
var hexRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TestRequestIDGeneratedWhenAbsent covers AC-002.6 and AC-002.9.
func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	t.Parallel()

	proxies, err := NewTrustedProxies(DefaultProxyConfig())
	if err != nil {
		t.Fatalf("NewTrustedProxies returned error: %v", err)
	}

	var seen string
	handler := withRequestID(proxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !hexRequestIDPattern.MatchString(seen) {
		t.Errorf("RequestIDFromContext() = %q, want 32 lowercase hex characters", seen)
	}

	if got := rec.Header().Get(RequestIDHeader); got != seen {
		t.Errorf("response header %q = %q, want %q", RequestIDHeader, got, seen)
	}

	var secondSeen string
	handler2 := withRequestID(proxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		secondSeen = RequestIDFromContext(r.Context())
	}))

	req2 := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)

	if secondSeen == seen {
		t.Errorf("two separate requests both got identifier %q, want distinct identifiers", seen)
	}
}

// TestRequestIDAdoptedFromTrustedPeer covers AC-002.7.
func TestRequestIDAdoptedFromTrustedPeer(t *testing.T) {
	t.Parallel()

	proxies, err := NewTrustedProxies(ProxyConfig{TrustedCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("NewTrustedProxies returned error: %v", err)
	}

	const supplied = "edge-abc.123_XYZ"

	var seen string
	handler := withRequestID(proxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Set(RequestIDHeader, supplied)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seen != supplied {
		t.Errorf("RequestIDFromContext() = %q, want %q", seen, supplied)
	}

	if got := rec.Header().Get(RequestIDHeader); got != supplied {
		t.Errorf("response header %q = %q, want %q", RequestIDHeader, got, supplied)
	}
}

// TestRequestIDRejectedFromUntrustedPeer covers AC-002.8.
func TestRequestIDRejectedFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	proxies, err := NewTrustedProxies(DefaultProxyConfig())
	if err != nil {
		t.Fatalf("NewTrustedProxies returned error: %v", err)
	}

	const supplied = "attacker-chosen"

	var seen string
	handler := withRequestID(proxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set(RequestIDHeader, supplied)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seen == supplied {
		t.Errorf("RequestIDFromContext() = %q, want it not to adopt untrusted peer's value", seen)
	}

	if !hexRequestIDPattern.MatchString(seen) {
		t.Errorf("RequestIDFromContext() = %q, want 32 lowercase hex characters", seen)
	}
}

// TestRequestIDRejectsMalformedValue covers AC-002.7.
func TestRequestIDRejectsMalformedValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		supplied string
	}{
		{
			name:     "empty value",
			supplied: "",
		},
		{
			name:     "65 character value",
			supplied: strings.Repeat("a", 65),
		},
		{
			name:     "value containing a space",
			supplied: "has space",
		},
		{
			name:     "value containing a newline",
			supplied: "has\nnewline",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			proxies, err := NewTrustedProxies(ProxyConfig{TrustedCIDRs: []string{"10.0.0.0/8"}})
			if err != nil {
				t.Fatalf("NewTrustedProxies returned error: %v", err)
			}

			var seen string
			handler := withRequestID(proxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = RequestIDFromContext(r.Context())
			}))

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "10.1.2.3:443"
			req.Header.Set(RequestIDHeader, test.supplied)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if seen == test.supplied {
				t.Errorf("RequestIDFromContext() = %q, want it not to adopt malformed value", seen)
			}

			if !hexRequestIDPattern.MatchString(seen) {
				t.Errorf("RequestIDFromContext() = %q, want 32 lowercase hex characters", seen)
			}
		})
	}
}
