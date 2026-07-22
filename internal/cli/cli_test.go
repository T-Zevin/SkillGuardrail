package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSafeAndMaliciousExitCodes(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want int
	}{
		{"safe", filepath.Join("..", "..", "testdata", "safe-skill"), ExitOK},
		{"malicious", filepath.Join("..", "..", "testdata", "malicious-skill"), ExitPolicy},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run([]string{"scan", test.path, "--no-color"}, &stdout, &stderr)
			if got != test.want {
				t.Fatalf("exit=%d want=%d\nstdout:\n%s\nstderr:\n%s", got, test.want, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "VERDICT") {
				t.Fatalf("missing report: %s", stdout.String())
			}
		})
	}
}

func TestScanJSONWithFlagAfterSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", filepath.Join("..", "..", "testdata", "safe-skill"), "--format", "json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("not JSON report: %s", stdout.String())
	}
}

func TestScanChineseFlagAfterSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", filepath.Join("..", "..", "testdata", "safe-skill"), "-cn", "--no-color"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "扫描摘要") {
		t.Fatalf("not Chinese report: %s", stdout.String())
	}
}

func TestScanSafeWithFailOnInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", filepath.Join("..", "..", "testdata", "safe-skill"), "--fail-on", "info", "--no-color"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestIncompleteScanAlwaysReturnsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", filepath.Join("..", "..", "testdata", "safe-skill"), "--max-files", "1", "--fail-on", "critical", "--no-color"}, &stdout, &stderr)
	if code != ExitError {
		t.Fatalf("exit=%d want=%d\nstdout=%s\nstderr=%s", code, ExitError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "<unavailable: incomplete scan>") {
		t.Fatalf("report did not explain missing fingerprint: %s", stdout.String())
	}
}

func TestInterspersedPreservesOptionTerminator(t *testing.T) {
	got := interspersed([]string{"--", "-safe-skill"}, nil)
	want := []string{"--", "-safe-skill"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("interspersed=%q want=%q", got, want)
	}
}

func TestInstallNeedsExplicitYes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"install", filepath.Join("..", "..", "testdata", "safe-skill"), "--dir", t.TempDir(), "--no-color"}, &stdout, &stderr)
	if code != ExitCancelled {
		t.Fatalf("exit=%d want=%d stderr=%s", code, ExitCancelled, stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"wat"}, &stdout, &stderr); code != ExitError {
		t.Fatalf("exit=%d", code)
	}
}
