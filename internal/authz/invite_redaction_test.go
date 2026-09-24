package authz

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// redactionTestToken is the invite token the test in this file puts in a
// request path. Any log field carrying it is a leak.
const redactionTestToken = "perm1ssionINVITEsecret"

// TestInviteTokenNotLoggedByPermissionDenial covers AC-008.87: a request to
// a /i/<token> path that RequirePermission denies inside server.NewMux's
// chain leaves the token out of the permission-denied warn line and every
// other log entry.
func TestInviteTokenNotLoggedByPermissionDenial(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	subject := Subject{UserID: uuid.New(), SessionPublicID: uuid.New(), Permissions: nil}
	withSubject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithSubject(r.Context(), subject)))
		})
	}

	api := func(mux *http.ServeMux) {
		mux.Handle("GET /i/{file}", RequirePermission("invite.read", logger)(recordingHandler(new(bool))))
	}

	mux := server.NewMux(server.DefaultConfig(), server.TrustedProxies{}, server.NewReadiness(), logger,
		server.Telemetry{}, http.NotFoundHandler(), api, withSubject)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/i/"+redactionTestToken, http.NoBody))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	if len(logs.FilterMessage("permission denied").All()) != 1 {
		t.Fatal("want exactly one permission-denied warn line")
	}

	for _, entry := range logs.All() {
		for key, value := range entry.ContextMap() {
			if s, ok := value.(string); ok && strings.Contains(s, redactionTestToken) {
				t.Errorf("%q entry field %q = %q contains the invite token", entry.Message, key, s)
			}
		}
	}
}
