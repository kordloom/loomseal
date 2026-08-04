package cmd

import (
	"runtime/debug"
	"strings"
)

// version is injected at release time with
// -ldflags "-X github.com/kordloom/loomseal/cmd.version=0.1.0". It is empty in every build that
// does not go through the release workflow, which includes go install.
var version string

// devVersion is what a binary built from a working tree reports, where no module version exists.
const devVersion = "0.0.0-dev"

// Version returns the version this binary reports. A release build carries an injected value. A
// go install of a published version carries no injection, so the module version Go records in
// the binary is used instead, which keeps an installed verifier from reporting a dev build.
func Version() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return devVersion
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}
