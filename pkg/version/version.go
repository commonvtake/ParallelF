// Package version exposes build metadata injected at link time with
// -ldflags "-X github.com/commonvtake/parallelf/pkg/version.Version=...".
package version

var (
	// Version is the release version or "dev" for local builds.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
)
