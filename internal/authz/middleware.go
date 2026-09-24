package authz

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// RequirePermission returns middleware that rejects a request whose
// authenticated subject does not hold the named permission. It answers 401
// when there is no subject at all and 403 when there is one without the
// permission, so an unauthenticated caller is told to authenticate rather than
// that it is forbidden.
//
// It is not a substitute for scoping a query to the resource's owner. A route
// that returns a user-owned resource still filters by owner; the permission
// only widens which owners a caller may see.
func RequirePermission(permission string, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject, ok := SubjectFromContext(r.Context())
			if !ok {
				server.WriteError(w, r, logger, &server.ClientError{
					Status:  http.StatusUnauthorized,
					Code:    server.ErrorCodeUnauthenticated,
					Message: "authentication required",
				})

				return
			}

			if !subject.HasPermission(permission) {
				logger.Warn("permission denied",
					zap.String("user_id", subject.UserID.String()),
					zap.String("permission", permission),
					zap.String("path", server.LoggedPath(r)),
				)
				server.WriteError(w, r, logger, &server.ClientError{
					Status:  http.StatusForbidden,
					Code:    server.ErrorCodeForbidden,
					Message: "permission denied",
				})

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
