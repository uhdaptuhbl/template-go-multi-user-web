package buildinfo

import (
	"runtime"

	"go.uber.org/zap"
)

// Unknown is reported for a value the build did not stamp, which is what an
// ordinary "go build" with no linker flags produces.
const Unknown = "unknown"

// Info identifies the build a process is running.
type Info struct {
	// Version is the release identifier, normally from git describe.
	Version string
	// Commit is the short hash the build came from.
	Commit string
	// Date is the build timestamp in RFC 3339, which keeps two builds of the
	// same commit distinguishable.
	Date string
}

// GoVersion reports the Go toolchain version the running binary was built with.
//
// It is read from the runtime rather than stamped at link time, so it is
// correct even for a build that passed no linker flags at all. It lives here so
// that the start-up log entry, the build_info metric, and the version endpoint
// all answer from one place.
func GoVersion() string {
	return runtime.Version()
}

// Fields renders the build identity as structured log fields, including the Go
// toolchain version, which is part of what produced the binary and is not
// otherwise recoverable from a running process's logs.
func (i Info) Fields() []zap.Field {
	return []zap.Field{
		zap.String("version", i.Version),
		zap.String("commit", i.Commit),
		zap.String("build_date", i.Date),
		zap.String("go_version", GoVersion()),
	}
}

// Log writes one entry naming the build. It runs as early as the logger exists,
// so that the first line of any log stream answers what is running.
func (i Info) Log(logger *zap.Logger) {
	logger.Info("build information", i.Fields()...)
}
