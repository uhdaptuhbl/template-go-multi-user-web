package server

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/buildinfo"
)

// versionPath is the endpoint reporting the running build, named as a constant
// because the route registration and the test that asserts the application
// listener does not carry it have to agree on it.
const versionPath = "/version"

// ProcessInfo identifies the running process: the build it came from and when
// it started.
//
// Start time is passed in rather than read from a clock inside the handler, so
// that what the endpoint reports is fixed at process start and a test can
// assert it exactly.
type ProcessInfo struct {
	// Build is the identity stamped into the binary at link time.
	Build buildinfo.Info
	// Started is when the process began running.
	Started time.Time
}

// versionResponse is the body returned by the version endpoint. Its keys match
// the fields of the start-up log entry, so an operator reading either one is
// looking at the same names.
type versionResponse struct {
	// Version is the release identifier, normally from git describe.
	Version string `json:"version"`
	// Commit is the short hash the build came from.
	Commit string `json:"commit"`
	// BuildDate is when the binary was built, in RFC 3339.
	BuildDate string `json:"build_date"`
	// GoVersion is the toolchain the binary was compiled with.
	GoVersion string `json:"go_version"`
	// StartedAt is when the process began running, in RFC 3339 and UTC.
	StartedAt string `json:"started_at"`
}

// newVersionHandler reports the running build and when the process started.
//
// It answers what the start-up log entry already said, which is the point: that
// line is gone once logs rotate, and the build_info metric requires scraping an
// exposition format to read one value by eye. The build date in particular
// reaches an operator no other way.
//
// It belongs on the administrative listener only. Naming the exact release a
// process is running tells anyone who asks which vulnerabilities to try against
// it, so this sits behind the loopback-bound port with the profiling endpoints
// rather than on the port that serves users.
func newVersionHandler(process ProcessInfo, logger *zap.Logger) http.Handler {
	// Captured once at construction: none of these values can change while the
	// process runs, so the handler consults neither a clock nor the runtime on
	// the request path.
	body := versionResponse{
		Version:   process.Build.Version,
		Commit:    process.Build.Commit,
		BuildDate: process.Build.Date,
		GoVersion: buildinfo.GoVersion(),
		// Normalised to UTC, so two instances in different zones report
		// timestamps that can be compared without parsing offsets.
		StartedAt: process.Started.UTC().Format(time.RFC3339),
	}

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, logger, http.StatusOK, body)
	})
}
