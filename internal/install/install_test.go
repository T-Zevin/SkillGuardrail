package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
	"github.com/T-Zevin/SkillGuardrail/internal/scanner"
)

func TestInstallVerifyAndDetectChange(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	stateDir := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyWithState(result.Path, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Valid {
		t.Fatalf("fresh installation is invalid: %#v", verification)
	}
	if err := os.WriteFile(filepath.Join(result.Path, "changed.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	verification, err = VerifyWithState(result.Path, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || len(verification.ChangedFiles) == 0 {
		t.Fatal("expected a changed file to invalidate the receipt")
	}
}

func TestInstallCreatesMissingTargetRoot(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "new", "skills")
	result, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: privateTempDir(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	canonicalTarget, err := canonicalPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != filepath.Join(canonicalTarget, "safe-summary") {
		t.Fatalf("installed path = %q", result.Path)
	}
}

func TestInstallRejectsGroupWritableTargetRoot(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: privateTempDir(t),
	}); err == nil {
		t.Fatal("group-writable target root was accepted")
	}
}

func TestInstallRejectsInsecureStateRoot(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateRoot,
	}); err == nil {
		t.Fatal("insecure authoritative state root was accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "safe-summary")); !os.IsNotExist(err) {
		t.Fatalf("installation crossed discovery boundary before state rejection: %v", err)
	}
}

func TestInstallRejectsGroupWritablePackageEntry(t *testing.T) {
	requireGuardedOperations(t)
	root := t.TempDir()
	skill := []byte("---\nname: unsafe-mode\ndescription: Test unsafe source permissions.\n---\n\nSafe text.\n")
	manifest := filepath.Join(root, "SKILL.md")
	if err := os.WriteFile(manifest, skill, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatal(err)
	}
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), root, report, Options{
		Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: privateTempDir(t),
	}); err == nil {
		t.Fatal("group-writable package entry was accepted")
	}
}

func TestReplaceUsesUniquePrivateBackupContainer(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "skills")
	stateRoot := privateTempDir(t)
	if _, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateRoot,
	}); err != nil {
		t.Fatal(err)
	}
	legacyBackup := filepath.Join(parent, ".skillguardrail-backups")
	if err := os.Symlink(t.TempDir(), legacyBackup); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	result, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateRoot, Replace: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(result.BackupPath) == legacyBackup || filepath.Base(filepath.Dir(result.BackupPath)) == ".skillguardrail-backups" {
		t.Fatalf("replacement used the predictable legacy backup hierarchy: %s", result.BackupPath)
	}
	if info, err := os.Lstat(result.BackupPath); err != nil || !info.IsDir() {
		t.Fatalf("private backup was not preserved: %v", err)
	}
}

func TestVerifyDoesNotTrustPackageManifest(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(result.ReceiptPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWithState(result.Path, stateDir); err == nil {
		t.Fatal("package-local manifest was accepted without the authoritative external receipt")
	}
}

func TestVerifyDetectsPackageManifestTampering(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Path, LockFileName), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyWithState(result.Path, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || len(verification.ChangedFiles) == 0 {
		t.Fatalf("tampered package manifest was not detected: %#v", verification)
	}
}

func TestVerifyDetectsPackageManifestSymlink(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(result.Path, LockFileName)
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(result.ReceiptPath, manifest); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	verification, err := VerifyWithState(result.Path, stateDir)
	if err != nil {
		return
	}
	if verification.Valid {
		t.Fatal("package manifest symlink was accepted")
	}
}

func TestVerifyReportsPermissionDrift(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	skillFile := filepath.Join(result.Path, "SKILL.md")
	if err := os.Chmod(skillFile, 0o700); err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyWithState(result.Path, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Valid || len(verification.ChangedFiles) == 0 || verification.ChangedFiles[0] != "SKILL.md" {
		t.Fatalf("permission drift not attributed to SKILL.md: %#v", verification)
	}
}

func TestVerifyRejectsInsecureInstallationParent(t *testing.T) {
	requireGuardedOperations(t)
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	stateRoot := privateTempDir(t)
	result, err := Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: stateRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWithState(result.Path, stateRoot); err == nil {
		t.Fatal("verification accepted a group-writable installation parent")
	}
}

func TestInstallRejectsPolicyViolation(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "malicious-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: t.TempDir()}); err == nil {
		t.Fatal("expected malicious fixture to be denied")
	}
}

func TestInstallRejectsAccumulatedBlockVerdict(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 7; index++ {
		report.Findings = append(report.Findings, model.Finding{
			RuleID: "SG-TEST-MEDIUM", Title: "Synthetic review item", Severity: model.SeverityMedium,
			Category: "test", Location: model.Location{Path: "SKILL.md", Line: index + 1},
		})
	}
	report.Finalize()
	if report.Verdict != model.VerdictBlock || report.Highest != model.SeverityMedium {
		t.Fatalf("fixture verdict=%s highest=%s", report.Verdict, report.Highest)
	}
	if _, err := Install(context.Background(), root, report, Options{Directory: t.TempDir(), AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: t.TempDir()}); err == nil {
		t.Fatal("expected accumulated block verdict to be denied")
	}
}

func TestTargetRootOverride(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "skills")
	got, err := TargetRoot("", dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := canonicalPath(dir)
	if got != want {
		t.Fatalf("root = %q, want %q", got, want)
	}
}

func TestAuthoritativeStateMustBeOutsideDiscoveryDirectory(t *testing.T) {
	target := t.TempDir()
	installed := filepath.Join(target, "safe-summary")
	if _, err := authoritativeReceiptPath(installed, filepath.Join(target, ".state")); err == nil {
		t.Fatal("state directory inside the agent discovery directory was accepted")
	}
}

func TestReceiptSizeBudgetMatchesVerificationLimit(t *testing.T) {
	if err := validateReceiptSize(make([]byte, maxReceiptBytes)); err != nil {
		t.Fatalf("receipt at limit was rejected: %v", err)
	}
	if err := validateReceiptSize(make([]byte, maxReceiptBytes+1)); err == nil {
		t.Fatal("receipt above verification limit was accepted")
	}
}

func TestAuthoritativeReceiptReplacementCleansPrevious(t *testing.T) {
	requireGuardedOperations(t)
	directory, err := canonicalPath(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "receipt.json")
	if err := writeAuthoritativeReceipt(context.Background(), destination, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthoritativeReceipt(context.Background(), destination, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new\n" {
		t.Fatalf("receipt content = %q", data)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "receipt.json" {
		t.Fatalf("stale receipt files remain: %#v", entries)
	}
}

func TestRestorePreviousReceipt(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "receipt.json")
	previous := filepath.Join(directory, "receipt.previous")
	if err := os.WriteFile(destination, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("post-promotion validation failed")
	if err := restorePreviousReceipt(destination, previous, sentinel); !errors.Is(err, sentinel) {
		t.Fatalf("restore error = %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("restored receipt = %q", data)
	}
	if _, err := os.Lstat(previous); !os.IsNotExist(err) {
		t.Fatalf("previous receipt still exists: %v", err)
	}
}

func requireGuardedOperations(t *testing.T) {
	t.Helper()
	if err := platformGuardedOperationsAvailable(); err != nil {
		t.Skip(err)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
