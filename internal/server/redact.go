package server

import (
	"context"
	"net/http"
	"path"
	"strings"
)

// requestMetaContextKey is the context key a request's requestMeta is stored
// under. It is an unexported empty struct type, which is what makes collision
// with another package's key impossible.
type requestMetaContextKey struct{}

// requestMeta carries per-request state that a handler deep in the middleware
// chain can set and that the access log, WriteError, and the panic recovery
// handler can read once control returns to them. It is installed once, by
// value's own pointer shared across every clone of the request context that
// follows, which is what lets it survive a downstream r.WithContext call that
// would otherwise leave an outer middleware holding a *http.Request the mux
// never touched.
type requestMeta struct {
	// redactedPath is the redacted form withInvitePathRedaction substituted
	// for an invite path, copied in when the requestMeta is created, and left
	// empty for a request whose path carries no invite token.
	redactedPath string
	// pattern is the route ServeMux matched, recorded by withRoutePattern
	// once the mux has run. It is read instead of a middleware's own
	// r.Pattern because a middleware between withRequestLogging and the mux
	// that clones the request with r.WithContext, such as
	// auth.Service.Authenticate or withHandlerTimeout, hands the mux a
	// different *http.Request than the one withRequestLogging is still
	// holding, and ServeMux sets Pattern only on the instance that actually
	// reaches it.
	pattern string
}

// contextWithRequestMeta returns a copy of ctx carrying a fresh, mutable
// requestMeta. It is called once per request, by the outermost logging
// middleware, so that anything the request reaches afterward can record state
// this package's logging sites read back once the handler returns. When
// withInvitePathRedaction redacted the request's path, the redacted form is
// copied in here, so LoggedPath finds it on every request derived from ctx,
// including the one a route handler receives after withRoutePattern has put
// the real path back.
func contextWithRequestMeta(ctx context.Context) context.Context {
	meta := &requestMeta{}

	if original, ok := ctx.Value(originalPathContextKey{}).(originalPath); ok {
		meta.redactedPath = original.redacted
	}

	return context.WithValue(ctx, requestMetaContextKey{}, meta)
}

// requestMetaFromContext returns the requestMeta installed in ctx, or nil when
// none was installed.
func requestMetaFromContext(ctx context.Context) *requestMeta {
	meta, _ := ctx.Value(requestMetaContextKey{}).(*requestMeta)

	return meta
}

// LoggedPath returns the path a log entry about r should carry: the redacted
// form withInvitePathRedaction recorded for a request under /i/, or
// r.URL.Path for any other request. A log line anywhere in the chain,
// including inside a route handler where r.URL.Path has already been
// restored to the real one, uses this rather than r.URL.Path so that an
// invite token never reaches a log.
func LoggedPath(r *http.Request) string {
	if meta := requestMetaFromContext(r.Context()); meta != nil && meta.redactedPath != "" {
		return meta.redactedPath
	}

	return r.URL.Path
}

// matchedRoute returns the route ServeMux matched for r: the pattern
// withRoutePattern recorded in the shared requestMeta, or r.Pattern itself
// when no requestMeta was installed or nothing recorded into it, which is
// the case for a caller that exercises a bare mux without NewMux's own
// wrapping.
func matchedRoute(r *http.Request) string {
	if meta := requestMetaFromContext(r.Context()); meta != nil && meta.pattern != "" {
		return meta.pattern
	}

	return r.Pattern
}

// invitePathPrefix is the path prefix whose next segment is a bearer
// invite token. Every request under it is redacted, whether or not it
// matches a route, since a request that misses the route carries the token
// just the same.
const invitePathPrefix = "/i/"

// redactedInvitePath is what an invite path is replaced with for everything
// that observes the request outside the mux.
const redactedInvitePath = "/i/{token}"

// redactedInviteQRPath replaces an invite path ending in ".png", keeping the
// QR-image and landing requests distinguishable in logs and traces.
const redactedInviteQRPath = "/i/{token}.png"

// originalPathContextKey is the context key an originalPath is stored under.
type originalPathContextKey struct{}

// originalPath is the real path of a request withInvitePathRedaction
// redacted, kept so that withRoutePattern can hand the mux the path the
// client actually sent, together with the redacted form that replaced it.
type originalPath struct {
	path     string
	rawPath  string
	redacted string
}

// withInvitePathRedaction is the outermost layer NewMux builds, outside the
// HTTP instrumentation. For a request whose path.Clean'd path starts with
// /i/, it passes next a copy whose URL.Path is the redacted form and whose
// URL.RawPath is empty, and records the original in the request context. The
// prefix is matched on the cleaned path, not the raw one, so a non-canonical
// path that only becomes /i/<token> after cleaning -- a leading double
// slash, a "." or ".." segment, or one hidden behind percent-encoding --
// is redacted just the same as the canonical form; ServeMux would clean and
// route (or redirect) it identically, so treating it differently here would
// leave the token to leak on a path a client can send today. It sits outside
// tracing because otelhttp records url.path when the span starts, where a
// sampler or span processor sees it, and it sits outside every other layer so
// that a request answered before the mux -- a 503 from the in-flight limit, a
// cross-site rejection -- or one the mux does not route to the invite
// handler, logs and traces the redacted form too. withRoutePattern restores
// the original immediately before the mux, so routing and r.PathValue see
// the real token.
//
// The caller's *http.Request is never modified: the copy has its own URL.
func withInvitePathRedaction(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleaned := cleanedInvitePath(r)
		if cleaned == "" {
			next.ServeHTTP(w, r)

			return
		}

		original := originalPath{path: r.URL.Path, rawPath: r.URL.RawPath, redacted: redactInvitePath(cleaned)}

		ctx := context.WithValue(r.Context(), originalPathContextKey{}, original)

		next.ServeHTTP(w, withURLPath(ctx, r, original.redacted, ""))
	})
}

// cleanedInvitePath returns path.Clean applied to r's path when the result
// starts with invitePathPrefix, and "" when neither the cleaned decoded path
// nor the cleaned escaped path does. Checking both is what catches a token
// hidden behind a percent-encoded segment whose decoded and escaped forms
// disagree, without either check on its own having to be trusted alone.
func cleanedInvitePath(r *http.Request) string {
	if cleaned := path.Clean(r.URL.Path); strings.HasPrefix(cleaned, invitePathPrefix) {
		return cleaned
	}

	if cleaned := path.Clean(r.URL.EscapedPath()); strings.HasPrefix(cleaned, invitePathPrefix) {
		return cleaned
	}

	return ""
}

// withOriginalPath returns r with the path withInvitePathRedaction replaced
// put back, or r itself when the path was never redacted.
func withOriginalPath(r *http.Request) *http.Request {
	original, ok := r.Context().Value(originalPathContextKey{}).(originalPath)
	if !ok {
		return r
	}

	return withURLPath(r.Context(), r, original.path, original.rawPath)
}

// withURLPath returns a shallow copy of r carrying ctx, with a URL of its own
// whose Path and RawPath are urlPath and rawPath. Neither r nor r.URL is
// modified.
func withURLPath(ctx context.Context, r *http.Request, urlPath, rawPath string) *http.Request {
	copied := r.WithContext(ctx)
	copiedURL := *r.URL
	copiedURL.Path = urlPath
	copiedURL.RawPath = rawPath
	copied.URL = &copiedURL

	return copied
}

// redactInvitePath returns the redacted form of an invite path: the QR-image
// form when urlPath ends in ".png", and the landing form otherwise.
func redactInvitePath(urlPath string) string {
	if strings.HasSuffix(urlPath, ".png") {
		return redactedInviteQRPath
	}

	return redactedInvitePath
}
