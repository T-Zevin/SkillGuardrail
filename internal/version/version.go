package version

import (
	"runtime/debug"
	"strings"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type metadata struct {
	version string
	commit  string
	date    string
}

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	resolved := resolve(metadata{version: Version, commit: Commit, date: Date}, info)
	Version = resolved.version
	Commit = resolved.commit
	Date = resolved.date
}

func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}

func resolve(current metadata, info *debug.BuildInfo) metadata {
	if fallback(current.version, "dev") {
		if moduleVersion := normalizeModuleVersion(info.Main.Version); moduleVersion != "" {
			current.version = moduleVersion
		}
	}

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if fallback(current.commit, "none") && setting.Value != "" {
				current.commit = setting.Value
			}
		case "vcs.time":
			if fallback(current.date, "unknown") && setting.Value != "" {
				current.date = setting.Value
			}
		}
	}

	return current
}

func fallback(value, placeholder string) bool {
	return value == "" || value == placeholder
}

func normalizeModuleVersion(value string) string {
	if value == "" || value == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(value, "v")
}
