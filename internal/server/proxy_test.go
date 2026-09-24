package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTrustedProxiesClientIP covers AC-002.10 and AC-002.11.
func TestTrustedProxiesClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		trustedCIDRs []string
		remoteAddr   string
		forwardedFor string
		setForwarded bool
		wantClientIP string
	}{
		{
			name:         "nothing trusted",
			trustedCIDRs: nil,
			remoteAddr:   "203.0.113.7:54321",
			forwardedFor: "198.51.100.9",
			setForwarded: true,
			wantClientIP: "203.0.113.7",
		},
		{
			name:         "trusted single hop",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "198.51.100.9",
			setForwarded: true,
			wantClientIP: "198.51.100.9",
		},
		{
			name:         "trusted two hops",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "198.51.100.9, 10.4.5.6",
			setForwarded: true,
			wantClientIP: "198.51.100.9",
		},
		{
			name:         "spoofed chain",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "1.2.3.4, 198.51.100.9",
			setForwarded: true,
			wantClientIP: "198.51.100.9",
		},
		{
			name:         "header absent",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			setForwarded: false,
			wantClientIP: "10.1.2.3",
		},
		{
			name:         "IPv6 peer",
			trustedCIDRs: []string{"2001:db8::/32"},
			remoteAddr:   "[2001:db8::1]:443",
			forwardedFor: "198.51.100.9",
			setForwarded: true,
			wantClientIP: "198.51.100.9",
		},
		{
			// The client is itself inside the trusted range, so the walk would
			// otherwise continue past the malformed hop into entries the client
			// supplied. The malformed hop has to stop it.
			name:         "unparseable hop ends the walk",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "203.0.113.1, unknown, 10.9.9.9",
			setForwarded: true,
			wantClientIP: "10.1.2.3",
		},
		{
			name:         "chain entirely of trusted proxies falls back to the peer",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "10.4.5.6, 10.7.8.9",
			setForwarded: true,
			wantClientIP: "10.1.2.3",
		},
		{
			name:         "IPv4-mapped IPv6 entry is compared unmapped",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "10.1.2.3:443",
			forwardedFor: "::ffff:198.51.100.9",
			setForwarded: true,
			wantClientIP: "198.51.100.9",
		},
		{
			name:         "unparseable remote",
			trustedCIDRs: []string{"10.0.0.0/8"},
			remoteAddr:   "@",
			forwardedFor: "198.51.100.9",
			setForwarded: true,
			wantClientIP: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			proxies, err := NewTrustedProxies(ProxyConfig{TrustedCIDRs: test.trustedCIDRs})
			if err != nil {
				t.Fatalf("NewTrustedProxies returned error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = test.remoteAddr

			if test.setForwarded {
				req.Header.Set(forwardedForHeader, test.forwardedFor)
			}

			if got := proxies.ClientIP(req); got != test.wantClientIP {
				t.Errorf("ClientIP() = %q, want %q", got, test.wantClientIP)
			}
		})
	}
}

// TestNewTrustedProxiesRejectsInvalidCIDR covers AC-001.2.
// TestNewTrustedProxiesRejectsInvalidCIDR verifies that a malformed CIDR entry
// fails configuration rather than being silently dropped, since a typo in a
// trust boundary must stop the process, not silently narrow it.
func TestNewTrustedProxiesRejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	_, err := NewTrustedProxies(ProxyConfig{TrustedCIDRs: []string{"10.0.0.0/8", "not-a-cidr"}})
	if err == nil {
		t.Fatal("NewTrustedProxies returned nil error for an invalid CIDR entry")
	}

	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("error %q does not mention the offending entry %q", err.Error(), "not-a-cidr")
	}
}

// TestProxyConfigValidateAcceptsWhatTheParserAccepts covers AC-002.10.
func TestProxyConfigValidateAcceptsWhatTheParserAccepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cidrs      []string
		wantFailed bool
	}{
		{name: "nothing trusted", cidrs: nil},
		{name: "one network", cidrs: []string{"10.0.0.0/8"}},
		{name: "an empty entry a trailing comma leaves behind", cidrs: []string{"10.0.0.0/8", ""}},
		{name: "an entry that is not a network", cidrs: []string{"10.0.0.1"}, wantFailed: true},
		{name: "a bad entry after a good one", cidrs: []string{"10.0.0.0/8", "nope"}, wantFailed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := ProxyConfig{TrustedCIDRs: tt.cidrs}

			// Validate exists to fail at startup rather than on the first
			// request, so it must agree with the parser exactly: a value it
			// accepts and the parser rejects would crash a running process.
			_, parseErr := NewTrustedProxies(cfg)
			validateErr := cfg.Validate(t.Context())

			if (validateErr != nil) != tt.wantFailed {
				t.Errorf("Validate() error = %v, wantFailed = %v", validateErr, tt.wantFailed)
			}

			if (parseErr != nil) != (validateErr != nil) {
				t.Errorf("NewTrustedProxies() error = %v but Validate() error = %v, want them to agree", parseErr, validateErr)
			}
		})
	}
}
