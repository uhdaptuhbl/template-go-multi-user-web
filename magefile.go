//go:build mage

// Command magefile defines this project's build, test, and release targets.
//
// Targets are run with "go tool mage <target>", which needs no global install:
// the mage version is pinned by the tool directive in go.mod.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// binaryName is the name of the built executable.
const binaryName = "service"

// outputDir is where built binaries are written. It is gitignored.
const outputDir = "bin"

// imageName is the local tag applied to the container image.
const imageName = "service"

// coverageFile is where the coverage profile is written.
const coverageFile = "coverage.out"

// buildArgFlag passes one build argument to "docker build".
const buildArgFlag = "--build-arg"

// Default is the target run when mage is invoked with no arguments.
var Default = Build

// Build compiles the server into bin/service with version information stamped
// into the binary.
func Build() error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return fmt.Errorf("creating output directory %s: %w", outputDir, err)
	}

	output := filepath.Join(outputDir, binaryName)

	if err := sh.RunV("go", "build", "-trimpath", "-ldflags", ldflags(), "-o", output, "./cmd/service"); err != nil {
		return fmt.Errorf("building %s: %w", output, err)
	}

	return nil
}

// Test runs the unit test suite.
func Test() error {
	if err := sh.RunV("go", "test", "./..."); err != nil {
		return fmt.Errorf("running tests: %w", err)
	}

	return nil
}

// Race runs the unit test suite under the race detector, which is the form CI
// gates on.
func Race() error {
	if err := sh.RunV("go", "test", "-race", "./..."); err != nil {
		return fmt.Errorf("running tests under the race detector: %w", err)
	}

	return nil
}

// Integration runs the build-tagged integration suite.
func Integration() error {
	if err := sh.RunV("go", "test", "-race", "-tags=integration", "./..."); err != nil {
		return fmt.Errorf("running integration tests: %w", err)
	}

	return nil
}

// Lint runs golangci-lint against the configuration at the repository root,
// at the version the tool directive in go.mod pins, so that a local run and CI
// cannot disagree about which linter they ran. The integration suite is linted
// separately because its build tag excludes it from the default run. That pass
// covers every package: integration-tagged files live well beyond one or two
// directories, and a list of them goes stale the day a new one is added.
func Lint() error {
	if err := sh.RunV("go", "tool", "golangci-lint", "run"); err != nil {
		return fmt.Errorf("running golangci-lint: %w", err)
	}

	if err := sh.RunV("go", "tool", "golangci-lint", "run", "--build-tags=integration", "./..."); err != nil {
		return fmt.Errorf("running golangci-lint on the integration suite: %w", err)
	}

	return nil
}

// Cover runs the test suite with coverage and reports the per-function summary.
func Cover() error {
	if err := sh.RunV("go", "test", "-coverprofile="+coverageFile, "./..."); err != nil {
		return fmt.Errorf("running tests with coverage: %w", err)
	}

	if err := sh.RunV("go", "tool", "cover", "-func="+coverageFile); err != nil {
		return fmt.Errorf("summarising coverage: %w", err)
	}

	return nil
}

// Vuln scans dependencies and the standard library for known vulnerabilities.
//
// Run through the tool directive in go.mod rather than `go run ...@latest`,
// so a contributor and CI scan with the same version and an upstream release
// cannot turn a passing build red without a commit. Bumping it is a
// Dependabot pull request, like every other dependency.
func Vuln() error {
	if err := sh.RunV("go", "tool", "govulncheck", "./..."); err != nil {
		return fmt.Errorf("running govulncheck: %w", err)
	}

	return nil
}

// envExampleFile is the committed template a working .env is copied from.
const envExampleFile = ".env.example"

// envFile is the gitignored working configuration a developer edits.
const envFile = ".env"

// Bootstrap prepares a fresh clone: it downloads the module requirements,
// materialises the pinned tools, copies .env.example to .env when there is no
// .env yet, and runs the lint and unit gates once so the checkout is known
// good before any change is made to it.
//
// Every step is idempotent, so running it again on a working checkout is
// harmless. The .env copy is the one step that touches a file a developer
// owns, and it refuses to overwrite one that already exists.
func Bootstrap() error {
	if err := sh.RunV("go", "mod", "download"); err != nil {
		return fmt.Errorf("downloading module requirements: %w", err)
	}

	// Materialises every tool directive in go.mod, so the first lint or
	// vulnerability scan does not pay for a build nobody asked for and a
	// machine with no network later still has them.
	if err := sh.RunV("go", "install", "tool"); err != nil {
		return fmt.Errorf("installing the pinned tools: %w", err)
	}

	if err := copyEnvExample(); err != nil {
		return err
	}

	mg.Deps(Lint, Test)

	return nil
}

// copyEnvExample copies .env.example to .env unless .env already exists.
//
// An existing .env is a developer's own configuration and may hold a
// credential, so it is never overwritten. O_EXCL rather than a prior Stat
// makes that promise the filesystem's rather than this function's: a check
// followed by a write leaves a window in which something else creates the
// file and has it truncated out from under it. The new file is 0600 for the
// same reason: what goes into it is a credential often enough.
func copyEnvExample() error {
	contents, err := os.ReadFile(envExampleFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", envExampleFile, err)
	}

	file, err := os.OpenFile(envFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("creating %s: %w", envFile, err)
	}

	_, writeErr := file.Write(contents)
	closeErr := file.Close()

	if joinErr := errors.Join(writeErr, closeErr); joinErr != nil {
		return fmt.Errorf("writing %s: %w", envFile, joinErr)
	}

	return nil
}

// Tidy prunes and refreshes the module requirements.
func Tidy() error {
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return fmt.Errorf("tidying the module: %w", err)
	}

	return nil
}

// Docker builds the container image, passing the same version information the
// Build target stamps in.
func Docker() error {
	args := []string{
		"build",
		buildArgFlag, "VERSION=" + version(),
		buildArgFlag, "COMMIT=" + commit(),
		buildArgFlag, "BUILD_DATE=" + buildDate(),
		"-t", imageName + ":" + version(),
		"-t", imageName + ":latest",
		".",
	}

	if err := sh.RunV("docker", args...); err != nil {
		return fmt.Errorf("building the container image: %w", err)
	}

	return nil
}

// Run builds and starts the server with the current working configuration.
func Run() error {
	mg.Deps(Build)

	if err := sh.RunV(filepath.Join(outputDir, binaryName)); err != nil {
		return fmt.Errorf("running %s: %w", binaryName, err)
	}

	return nil
}

// ReleaseCheck validates .goreleaser.yaml without building anything. CI runs
// the same command, so a release configuration that no longer validates fails
// on the pull request that broke it rather than on the next tag.
func ReleaseCheck() error {
	if err := sh.RunV("goreleaser", "check"); err != nil {
		return fmt.Errorf("checking the release configuration: %w", err)
	}

	return nil
}

// Snapshot builds both release architectures and their container images
// locally, publishing, signing, and tagging nothing. It is the rehearsal to
// run before pushing a version tag, because the release workflow's first
// chance to fail is otherwise on the tag itself.
//
// Snapshot images carry a platform suffix rather than forming one manifest:
// buildx cannot load a multi-platform manifest into the local daemon.
func Snapshot() error {
	if err := sh.RunV("goreleaser", "release", "--snapshot", "--clean"); err != nil {
		return fmt.Errorf("building a release snapshot: %w", err)
	}

	return nil
}

// Clean removes build and coverage output.
func Clean() error {
	if err := os.RemoveAll(outputDir); err != nil {
		return fmt.Errorf("removing %s: %w", outputDir, err)
	}

	if err := os.Remove(coverageFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", coverageFile, err)
	}

	return nil
}

// ldflags builds the linker flags that stamp build information into the binary.
func ldflags() string {
	return strings.Join([]string{
		"-s", "-w",
		"-X", "main.version=" + version(),
		"-X", "main.commit=" + commit(),
		"-X", "main.buildDate=" + buildDate(),
	}, " ")
}

// version reports the build's version from git, falling back to "dev" outside a
// repository or before the first tag.
func version() string {
	described, err := sh.Output("git", "describe", "--tags", "--always", "--dirty")
	if err != nil || described == "" {
		return "dev"
	}

	return described
}

// commit reports the short commit hash being built, falling back to "unknown"
// outside a repository.
func commit() string {
	hash, err := sh.Output("git", "rev-parse", "--short", "HEAD")
	if err != nil || hash == "" {
		return "unknown"
	}

	return hash
}

// buildDate reports the build timestamp in UTC, which keeps two builds of the
// same commit distinguishable.
func buildDate() string {
	return time.Now().UTC().Format(time.RFC3339)
}
