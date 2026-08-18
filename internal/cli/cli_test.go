package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
	"github.com/T-Zevin/SkillGuardrail/internal/policy"
	"github.com/T-Zevin/SkillGuardrail/internal/scanner"
	"github.com/T-Zevin/SkillGuardrail/internal/source"
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

func TestScanSelectedSubdirectory(t *testing.T) {
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "literature-review")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: literature-review\ndescription: Review literature from public sources.\n---\n"
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", root, "--path", "skills/literature-review", "--no-color"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "SCOPE") || !strings.Contains(stdout.String(), "skills/literature-review") {
		t.Fatalf("selected scope missing from report: %s", stdout.String())
	}
}

func TestScanSelectedManifestUsesContainingSkillDirectory(t *testing.T) {
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "literature-review")
	if err := os.MkdirAll(filepath.Join(skill, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: literature-review\ndescription: Review literature from public sources.\n---\n"
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "scripts", "helper.py"), []byte("print('review')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", root, "--path", "skills/literature-review/SKILL.md", "--no-color"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"SCOPE", "skills/literature-review", "FILES", "2 ("} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("report missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestScanBaselineAcceptsMediumFinding(t *testing.T) {
	root := t.TempDir()
	content := "---\nname: literature-search\ndescription: Query a documented public API.\n---\n\ncurl https://api.crossref.org/works\n"
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := source.Resolve(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Cleanup()
	resolvedScan, err := scanner.Scan(context.Background(), resolved.Root, resolved.Source, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvedScan.Findings) == 0 || resolvedScan.Findings[0].Severity != model.SeverityMedium {
		t.Fatalf("expected medium network finding, got %#v", resolvedScan.Findings)
	}
	baseline := policy.Baseline{
		SchemaVersion: "skillguardrail-baseline/v1", SourceFingerprint: resolvedScan.Fingerprint,
		AcceptedFindings: []policy.AcceptedFinding{{
			Key: resolvedScan.Findings[0].Key, Reason: "Documented public Crossref lookup", ExpiresAt: "2030-01-01T00:00:00Z",
		}},
	}
	data, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".skillguardrail-baseline.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"scan", root, "--baseline", path, "--no-color"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit=%d stderr=%s report=%s", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"VERDICT  PASS", "ACCEPTED", "Documented public Crossref lookup"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("report missing %q:\n%s", want, stdout.String())
		}
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
