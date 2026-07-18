package version

import (
	"runtime/debug"
	"testing"
)

func TestResolveUsesModuleBuildInfoAsFallback(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.time", Value: "2026-07-19T00:00:00Z"},
		},
	}

	got := resolve(metadata{version: "dev", commit: "none", date: "unknown"}, info)
	if got.version != "1.2.3" {
		t.Fatalf("version = %q, want %q", got.version, "1.2.3")
	}
	if got.commit != "0123456789abcdef" {
		t.Fatalf("commit = %q, want %q", got.commit, "0123456789abcdef")
	}
	if got.date != "2026-07-19T00:00:00Z" {
		t.Fatalf("date = %q, want %q", got.date, "2026-07-19T00:00:00Z")
	}
}

func TestResolvePrefersLinkerMetadata(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "build-info-commit"},
			{Key: "vcs.time", Value: "build-info-date"},
		},
	}
	want := metadata{version: "1.2.3", commit: "linker-commit", date: "linker-date"}

	got := resolve(want, info)
	if got != want {
		t.Fatalf("resolve() = %#v, want linker metadata %#v", got, want)
	}
}

func TestResolveIgnoresDevelopmentModuleVersion(t *testing.T) {
	got := resolve(
		metadata{version: "dev", commit: "none", date: "unknown"},
		&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
	)
	if got.version != "dev" {
		t.Fatalf("version = %q, want %q", got.version, "dev")
	}
}
