package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// forwardedForHeader carries the chain of addresses a request passed through,
// leftmost first.
const forwardedForHeader = "X-Forwarded-For"

// ProxyConfig describes which peers may supply request metadata on a client's
// behalf.
type ProxyConfig struct {
	// TrustedCIDRs lists the networks whose X-Forwarded-For and X-Request-Id
	// headers are believed. It is empty by default, which trusts nothing: an
	// unconfigured deployment must not be one that can be lied to.
	//
	// The entries are checked by Validate rather than by a tag; see there.
	TrustedCIDRs []string `env:"TRUSTED_CIDRS, overwrite" json:"trusted_cidrs"`
}

// Validate rejects a trusted-proxy list this package cannot parse.
//
// It is the custom validation hook internal/config runs on this struct once
// struct-tag validation has passed, and it defers to NewTrustedProxies rather
// than restating the rules as a tag. What starts the process is then exactly
// what the request path will parse, empty entries included. A dive,cidr tag
// instead refused a list written as "10.0.0.0/8," while the only parser it
// guarded accepted it: a second, stricter definition of a valid list, failing
// a deployment over a comma that changes nothing.
func (c *ProxyConfig) Validate(_ context.Context) error {
	_, err := NewTrustedProxies(*c)

	return err
}

// DefaultProxyConfig returns the configuration that trusts no peer.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{TrustedCIDRs: nil}
}

// TrustedProxies decides whether a peer is a reverse proxy whose forwarded
// request metadata may be believed.
//
// Its zero value trusts nothing, and every method is safe to call on it, so a
// caller that has not configured proxies still gets correct, conservative
// answers.
type TrustedProxies struct {
	networks []netip.Prefix
}

// NewTrustedProxies parses cfg's CIDR list into a TrustedProxies. An entry that
// does not parse is an error rather than a skipped line: a typo in a trust
// boundary must stop the process, not silently narrow it.
func NewTrustedProxies(cfg ProxyConfig) (TrustedProxies, error) {
	networks := make([]netip.Prefix, 0, len(cfg.TrustedCIDRs))

	for _, entry := range cfg.TrustedCIDRs {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("parsing trusted proxy CIDR %q: %w", trimmed, err)
		}

		networks = append(networks, prefix.Masked())
	}

	return TrustedProxies{networks: networks}, nil
}

// TrustsPeer reports whether the connection r arrived on came from a trusted
// proxy. Only that immediate peer is consulted, because it is the only address
// in the request that this process observed rather than was told.
func (t TrustedProxies) TrustsPeer(r *http.Request) bool {
	addr, ok := peerAddr(r)
	if !ok {
		return false
	}

	return t.trusts(addr)
}

// ClientIP returns the address to attribute r to, as a string.
//
// From an untrusted peer it is the peer itself, and X-Forwarded-For is ignored
// entirely. From a trusted peer the header is walked right to left and the
// first address that is not itself a trusted proxy is returned: entries further
// left are progressively less verifiable, and the leftmost is whatever the
// original client chose to send. A hop that does not parse ends the walk, and
// the peer is returned, because an uninterpretable hop is the point past which
// nothing is verifiable.
func (t TrustedProxies) ClientIP(r *http.Request) string {
	peer, ok := peerAddr(r)
	if !ok {
		return ""
	}

	if !t.trusts(peer) {
		return peer.String()
	}

	forwarded := forwardedFor(r)

	for _, addr := range slices.Backward(forwarded) {
		// An entry this process cannot parse ends the walk. Everything further
		// left is separated from the trusted boundary by a hop of unknown
		// provenance, so continuing would mean attributing the request to a
		// value the client was free to choose.
		if !addr.IsValid() {
			break
		}

		if !t.trusts(addr) {
			return addr.String()
		}
	}

	return peer.String()
}

// trusts reports whether addr falls inside any configured network.
func (t TrustedProxies) trusts(addr netip.Addr) bool {
	for _, network := range t.networks {
		if network.Contains(addr) {
			return true
		}
	}

	return false
}

// peerAddr returns the address of the connection r arrived on, reporting false
// when RemoteAddr is not an address this process can parse, as happens on a
// unix socket or a synthetic request in a test.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr.Unmap(), true
}

// forwardedFor returns the addresses in r's X-Forwarded-For headers, in header
// order. An entry that does not parse is kept as the zero netip.Addr rather
// than dropped, so that a caller walking the chain can see that a hop was
// present and uninterpretable instead of silently closing the gap it left.
func forwardedFor(r *http.Request) []netip.Addr {
	values := r.Header.Values(forwardedForHeader)
	addrs := make([]netip.Addr, 0, len(values))

	for _, value := range values {
		for entry := range strings.SplitSeq(value, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(entry))
			if err != nil {
				addrs = append(addrs, netip.Addr{})

				continue
			}

			addrs = append(addrs, addr.Unmap())
		}
	}

	return addrs
}
