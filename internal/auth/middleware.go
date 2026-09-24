package auth

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
)

// healthProbePath and readinessProbePath are the two operational endpoints
// Authenticate must answer without resolving a session for: a liveness or
// readiness probe carries no session of its own to attach, and if it did
// carry a stray cookie, resolving it would make a database outage answer a
// probe with 503 instead of reporting the process itself as up. They are
// hardcoded rather than imported from internal/server, which does not
// export them.
const healthProbePath = "/healthz"
const readinessProbePath = "/readyz"

// Authenticate resolves the session cookie a request carries and attaches the
// authenticated subject to its context. A request with no cookie, or with one
// that no longer resolves, continues unauthenticated rather than being
// rejected, so a public route stays public; RequireAuthentication is what
// rejects. See healthProbePath's doc comment for why /healthz and /readyz
// skip session resolution entirely.
func (s *Service) Authenticate(sessions *session.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthProbePath || r.URL.Path == readinessProbePath {
			next.ServeHTTP(w, r)

			return
		}

		token := sessions.TokenFromRequest(r)
		if token == "" {
			next.ServeHTTP(w, r)

			return
		}

		sess, err := sessions.Lookup(r.Context(), token)
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				sessions.ClearCookie(w)
				next.ServeHTTP(w, r)

				return
			}

			s.logger.Error("auth: resolving session", zap.Error(err))
			server.WriteError(w, r, s.logger, &server.ClientError{
				Status:  http.StatusServiceUnavailable,
				Code:    server.ErrorCodeUnavailable,
				Message: "service unavailable",
				Err:     err,
			})

			return
		}

		if reissueErr := sessions.ReissueCookie(r.Context(), w, token, sess); reissueErr != nil {
			s.logger.Warn("auth: reissuing session cookie", zap.Error(reissueErr))
		}

		subject, err := s.Subject(r.Context(), sess.UserID, sess.PublicID)
		if err != nil {
			s.logger.Error("auth: resolving subject", zap.Error(err))
			server.WriteError(w, r, s.logger, &server.ClientError{
				Status:  http.StatusServiceUnavailable,
				Code:    server.ErrorCodeUnavailable,
				Message: "service unavailable",
				Err:     err,
			})

			return
		}

		next.ServeHTTP(w, r.WithContext(authz.WithSubject(r.Context(), subject)))
	})
}

// RequireAuthentication rejects a request that carries no authenticated
// subject with 401.
func RequireAuthentication(logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.SubjectFromContext(r.Context()); !ok {
			server.WriteError(w, r, logger, &server.ClientError{
				Status:  http.StatusUnauthorized,
				Code:    server.ErrorCodeUnauthenticated,
				Message: "authentication required",
			})

			return
		}

		next.ServeHTTP(w, r)
	})
}

// RejectCrossSite rejects a state-changing request that a browser indicates
// came from another site. publicOrigin is the origin this service is reached
// at. cookieName is the configured session cookie name
// (session.Config.CookieName), which the process wiring passes in; the check
// applies only when the request is not GET, HEAD, or OPTIONS and carries a
// cookie by that name (an empty value still counts as carried, since an
// attacker can set an empty cookie as easily as a real one).
func RejectCrossSite(publicOrigin, cookieName string, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)

			return
		}

		if _, err := r.Cookie(cookieName); err != nil {
			next.ServeHTTP(w, r)

			return
		}

		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		origin := r.Header.Get("Origin")

		if crossSiteAllowed(secFetchSite, origin, publicOrigin) {
			next.ServeHTTP(w, r)

			return
		}

		rejectCrossSite(w, r, logger)
	})
}

// RejectCrossSiteAlways rejects a state-changing request that a browser
// indicates came from another site, whether or not it carries a session
// cookie. It exists for the routes that complete a login or a signup: those
// requests arrive before any session exists, so RejectCrossSite's cookie gate
// would wave them through, and a forged one would sign the victim in to an
// account the attacker controls.
func RejectCrossSiteAlways(publicOrigin string, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)

			return
		}

		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		origin := r.Header.Get("Origin")

		if crossSiteAllowed(secFetchSite, origin, publicOrigin) {
			next.ServeHTTP(w, r)

			return
		}

		rejectCrossSite(w, r, logger)
	})
}

// RejectCrossSiteNavigation rejects a request that a browser positively
// signals as cross-site, checked on every method rather than exempting GET,
// HEAD, and OPTIONS the way RejectCrossSite does. It exists for a
// state-changing route that must nonetheless remain a GET, such as the
// identity-link start route: that route redirects the browser to an
// identity provider, so it cannot be turned into a POST, and RejectCrossSite's
// safe-method exemption would let a forged top-level navigation straight
// through. Unlike crossSiteAllowed, the absence of both Sec-Fetch-Site and
// Origin passes rather than rejects: a top-level navigation carries no
// Sec-Fetch-Site-and-Origin guarantee the way a fetch does, so their joint
// absence here is not by itself evidence of forgery, and every current
// browser sends Sec-Fetch-Site regardless. See AC-008.18.
func RejectCrossSiteNavigation(publicOrigin string, logger *zap.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		if secFetchSite != "" {
			if secFetchSite == "same-origin" || secFetchSite == "none" {
				next.ServeHTTP(w, r)

				return
			}

			rejectCrossSite(w, r, logger)

			return
		}

		origin := r.Header.Get("Origin")
		if origin != "" && origin != publicOrigin {
			rejectCrossSite(w, r, logger)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// rejectCrossSite writes the single warn line and the 403 response shared by
// RejectCrossSite and RejectCrossSiteAlways once a request has been decided
// to be a cross-site forgery.
func rejectCrossSite(w http.ResponseWriter, r *http.Request, logger *zap.Logger) {
	logger.Warn("auth: rejecting cross-site request",
		zap.String("method", r.Method),
		zap.String("path", server.LoggedPath(r)),
		zap.String("sec_fetch_site", r.Header.Get("Sec-Fetch-Site")),
		zap.String("origin", r.Header.Get("Origin")),
	)

	server.WriteError(w, r, logger, &server.ClientError{
		Status:  http.StatusForbidden,
		Code:    server.ErrorCodeCrossSite,
		Message: "cross-site request rejected",
	})
}

// isSafeMethod reports whether method is one RejectCrossSite never applies
// to because it cannot change state.
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// crossSiteAllowed decides whether a state-changing request that carries the
// session cookie is same-site enough to proceed. Sec-Fetch-Site, when
// present, is authoritative and is consulted first; only its absence falls
// back to Origin, and the absence of both is refused rather than allowed.
func crossSiteAllowed(secFetchSite, origin, publicOrigin string) bool {
	if secFetchSite != "" {
		return secFetchSite == "same-origin" || secFetchSite == "none"
	}

	if origin != "" {
		return origin == publicOrigin
	}

	return false
}
