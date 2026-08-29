// Package version exposes build identity for every AegisOps binary.
//
// The values are injected at link time by the Makefile:
//
//	-ldflags "-X github.com/bishal05das/aegisops-ai/internal/version.Version=..."
//
// Build identity is not cosmetic here. Every audit log entry and every executed
// remediation records the exact binary that produced it, so that a postmortem
// can answer "which build decided to restart that container".
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Injected via -ldflags. Defaults describe an un-stamped local `go build`.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Info is the immutable build identity of the running process.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	Dirty     bool   `json:"dirty"`
}

// Get assembles the build identity, falling back to Go's embedded VCS stamps
// when the Makefile's ldflags were not applied (e.g. a bare `go run ./...`).
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "none" && s.Value != "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.BuildDate == "unknown" && s.Value != "" {
				info.BuildDate = s.Value
			}
		case "vcs.modified":
			info.Dirty = s.Value == "true"
		}
	}
	return info
}

// Short renders a single-line identity suitable for log preambles.
func (i Info) Short() string {
	commit := i.Commit
	if len(commit) > 8 {
		commit = commit[:8]
	}
	dirty := ""
	if i.Dirty {
		dirty = "+dirty"
	}
	return fmt.Sprintf("%s (%s%s) %s %s", i.Version, commit, dirty, i.GoVersion, i.Platform)
}

// String implements fmt.Stringer.
func (i Info) String() string { return i.Short() }
