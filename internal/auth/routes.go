package auth

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// RouteDeps carries the collaborators the routes need beyond the Service
// itself.
type RouteDeps struct {
	// Sessions issues, resolves, and revokes sessions, and sets and clears
	// the session cookie.
	Sessions *session.Store
	// Providers resolves an OpenID Connect provider key and runs its login
	// ceremony. A nil Providers, or one with no configured keys, means the
	// two OIDC routes are not registered.
	Providers *oidc.Registry
	// Passkeys runs the WebAuthn registration and assertion ceremonies. A
	// nil Passkeys means the four WebAuthn routes and the two credential
	// self-service routes are not registered.
	Passkeys *passkey.Service
	// Codes issues and verifies emailed one-time codes. A nil Codes means
	// the two OTP routes are not registered.
	Codes *otp.Service
	// Users reads and writes accounts, for the routes that render or list
	// them.
	Users *user.Repository
	// Roles reads and writes role assignments, for the routes that report
	// or change them.
	Roles *authz.Repository
	// Limiter bounds how often a client IP may reach an authentication
	// route.
	Limiter *ratelimit.Limiter
	// Proxies resolves the client IP a request is attributed to, honoring
	// only a configured trusted proxy's forwarded header.
	Proxies server.TrustedProxies
	// Logger is where every route logs failures a caller must not see.
	Logger *zap.Logger
	// PublicOrigin is this service's normalized public origin, for example
	// "https://app.example.com". RejectCrossSiteAlways compares a
	// state-changing request's Origin header against it, and it is not
	// itself part of the route table in design.md's "Interfaces" section.
	PublicOrigin string
	// CookieSecure reports whether the OIDC binding cookie carries the
	// Secure attribute and, correspondingly, which of the two cookie names
	// it is set under. It should agree with the session cookie's own
	// session.Config.CookieSecure.
	CookieSecure bool
	// Credentials reads and writes registered WebAuthn credentials. It backs
	// the two credential self-service routes, which are registered whether
	// or not Passkeys is configured, so it must be non-nil even when
	// WebAuthn is disabled.
	Credentials *passkey.Repository
	// FlowTTL is the OIDC binding cookie's lifetime, equal to
	// SERVICE_AUTH_FLOW_TTL.
	FlowTTL time.Duration
}

// auditDetailRouteKey names the audit.Detail field a rate-limit refusal's
// audit event carries the matched route pattern under.
const auditDetailRouteKey = "route"

// hasProviders reports whether at least one OIDC provider is configured, so
// the two OIDC routes are registered only when a login through one of them is
// actually possible.
func hasProviders(registry *oidc.Registry) bool {
	return registry != nil && len(registry.Keys()) > 0
}

// rateLimited wraps next so that a request is refused with 429 once the
// caller, keyed by ratelimit.KeyForIP(deps.Proxies.ClientIP(r)), exceeds the
// configured rate. The first refusal in a run records
// audit.ActionRateLimited with subject "anonymous:ip"; later refusals in the
// same run answer 429 without recording another event (AC-008.88).
func (s *Service) rateLimited(deps RouteDeps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := deps.Proxies.ClientIP(r)

		decision := deps.Limiter.Decide(ratelimit.KeyForIP(clientIP))
		if !decision.Allowed {
			if decision.FirstRefusal {
				s.recordAudit(r.Context(), audit.ActionRateLimited, nil, "anonymous:ip", audit.OutcomeFailure,
					clientIP, server.RequestIDFromContext(r.Context()), s.auditDetail(map[string]any{auditDetailRouteKey: r.Pattern}))
			}

			server.WriteError(w, r, deps.Logger, rateLimitedError())

			return
		}

		next.ServeHTTP(w, r)
	})
}

// authed wraps next in RequireAuthentication using deps' logger.
func authed(deps RouteDeps, next http.Handler) http.Handler {
	return RequireAuthentication(deps.Logger, next)
}

// handlerFunc adapts a (Service, RouteDeps)-aware function to http.Handler,
// so each route registration below reads as one line naming its handler
// rather than a repeated closure.
func (s *Service) handlerFunc(deps RouteDeps, h func(*Service, http.ResponseWriter, *http.Request, RouteDeps)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(s, w, r, deps)
	})
}

// Routes registers the authentication and account routes on mux under
// /api/v1/. A method whose configuration disables it contributes no routes at
// all, so a disabled method answers 404 rather than advertising itself. The
// four /api/v1/auth/webauthn/* routes are gated on deps.Passkeys, the two OIDC
// routes and the identity link route are gated on deps.Providers, and the two
// OTP routes are gated on deps.Codes; every other route registered here,
// including the two credential self-service routes, is always registered.
func (s *Service) Routes(mux *http.ServeMux, deps RouteDeps) {
	mux.Handle("GET /api/v1/auth/providers", s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleProviders)))

	if hasProviders(deps.Providers) {
		mux.Handle("GET /api/v1/auth/oidc/{provider}/start", s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleOIDCStart)))
		mux.Handle("GET /api/v1/auth/oidc/{provider}/callback", s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleOIDCCallback)))
		mux.Handle("GET /api/v1/me/identities/{provider}/link/start",
			authed(deps, RejectCrossSiteNavigation(deps.PublicOrigin, deps.Logger, s.handlerFunc(deps, (*Service).handleMeIdentitiesLinkStart))))
	}

	if deps.Passkeys != nil {
		mux.Handle("POST /api/v1/auth/webauthn/register/start",
			s.rateLimited(deps, authed(deps, s.handlerFunc(deps, (*Service).handleWebAuthnRegisterStart))))
		mux.Handle("POST /api/v1/auth/webauthn/register/finish",
			s.rateLimited(deps, authed(deps, s.handlerFunc(deps, (*Service).handleWebAuthnRegisterFinish))))
		mux.Handle("POST /api/v1/auth/webauthn/login/start",
			s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleWebAuthnLoginStart)))
		mux.Handle("POST /api/v1/auth/webauthn/login/finish",
			s.rateLimited(deps, RejectCrossSiteAlways(deps.PublicOrigin, deps.Logger, s.handlerFunc(deps, (*Service).handleWebAuthnLoginFinish))))
	}

	mux.Handle("GET /api/v1/me/credentials", authed(deps, s.handlerFunc(deps, (*Service).handleMeCredentials)))
	mux.Handle("DELETE /api/v1/me/credentials/{id}", authed(deps, s.handlerFunc(deps, (*Service).handleMeCredentialsDelete)))

	if deps.Codes != nil {
		mux.Handle("POST /api/v1/auth/otp/start", s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleOTPStart)))
		mux.Handle("POST /api/v1/auth/otp/verify",
			s.rateLimited(deps, RejectCrossSiteAlways(deps.PublicOrigin, deps.Logger, s.handlerFunc(deps, (*Service).handleOTPVerify))))
	}

	mux.Handle("POST /api/v1/auth/logout", s.handlerFunc(deps, (*Service).handleLogout))

	mux.Handle("GET /api/v1/me", authed(deps, s.handlerFunc(deps, (*Service).handleMe)))
	mux.Handle("PATCH /api/v1/me", authed(deps, s.handlerFunc(deps, (*Service).handleMePatch)))
	mux.Handle("DELETE /api/v1/me", authed(deps, s.handlerFunc(deps, (*Service).handleMeDelete)))
	mux.Handle("GET /api/v1/me/sessions", authed(deps, s.handlerFunc(deps, (*Service).handleMeSessions)))
	mux.Handle("DELETE /api/v1/me/sessions", authed(deps, s.handlerFunc(deps, (*Service).handleMeSessionsDeleteAll)))
	mux.Handle("DELETE /api/v1/me/sessions/{id}", authed(deps, s.handlerFunc(deps, (*Service).handleMeSessionsDelete)))
	mux.Handle("GET /api/v1/me/identities", authed(deps, s.handlerFunc(deps, (*Service).handleMeIdentities)))
	mux.Handle("DELETE /api/v1/me/identities/{id}", authed(deps, s.handlerFunc(deps, (*Service).handleMeIdentitiesDelete)))

	mux.Handle("GET /api/v1/admin/users",
		authed(deps, authz.RequirePermission(authz.PermissionUserRead, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsers))))
	mux.Handle("PATCH /api/v1/admin/users/{id}/roles",
		authed(deps, authz.RequirePermission(authz.PermissionUserRoleGrant, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsersRoles))))
	mux.Handle("PATCH /api/v1/admin/users/{id}/status",
		authed(deps, authz.RequirePermission(authz.PermissionUserWrite, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsersStatus))))
	mux.Handle("DELETE /api/v1/admin/users/{id}/sessions",
		authed(deps, authz.RequirePermission(authz.PermissionSessionRevokeAny, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsersSessions))))
	mux.Handle("GET /api/v1/admin/audit",
		authed(deps, authz.RequirePermission(authz.PermissionAuditRead, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminAudit))))

	mux.Handle("POST /api/v1/invites",
		authed(deps, authz.RequirePermission(authz.PermissionInviteCreate, deps.Logger)(s.handlerFunc(deps, (*Service).handleInvitesCreate))))
	mux.Handle("GET /api/v1/invites", authed(deps, s.handlerFunc(deps, (*Service).handleInvitesList)))
	mux.Handle("GET /api/v1/invites/{id}", authed(deps, s.handlerFunc(deps, (*Service).handleInvitesGet)))
	mux.Handle("DELETE /api/v1/invites/{id}", authed(deps, s.handlerFunc(deps, (*Service).handleInvitesDelete)))

	// GET /i/{file} serves both the "GET /i/{token}" and
	// "GET /i/{token}.png" routes named in design.md's "Interfaces" section
	// from one registration: see
	// handleInviteRedeem's doc comment for why Go's ServeMux cannot register
	// the two literal patterns side by side. The path carries a bearer
	// token; server.NewMux redacts every path under /i/ before anything logs
	// or traces it, so this route needs no redaction of its own.
	mux.Handle("GET /i/{file}", s.rateLimited(deps, s.handlerFunc(deps, (*Service).handleInviteRedeem)))

	mux.Handle("POST /api/v1/admin/users/{id}/approve",
		authed(deps, authz.RequirePermission(authz.PermissionUserApprove, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsersApprove))))
	mux.Handle("POST /api/v1/admin/users/{id}/reject",
		authed(deps, authz.RequirePermission(authz.PermissionUserApprove, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminUsersReject))))
	mux.Handle("GET /api/v1/admin/settings",
		authed(deps, authz.RequirePermission(authz.PermissionSettingsManage, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminSettingsGet))))
	mux.Handle("PATCH /api/v1/admin/settings",
		authed(deps, authz.RequirePermission(authz.PermissionSettingsManage, deps.Logger)(s.handlerFunc(deps, (*Service).handleAdminSettingsPatch))))
}
