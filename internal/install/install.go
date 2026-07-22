package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
	"github.com/T-Zevin/SkillGuardrail/internal/scanner"
)

const LockFileName = ".skillguardrail.lock"

const (
	maxReceiptBytes  = 1 << 20
	maxDigestEntries = 5001
	maxDigestBytes   = 50 << 20
)

var validSkillName = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var validSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var validCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var validMode = regexp.MustCompile(`^[0-7]{4}$`)

type Options struct {
	Target      string
	Directory   string
	AllowedRisk model.Severity
	Replace     bool
	ToolVersion string
	StateDir    string
}

type Result struct {
	Path        string         `json:"path"`
	BackupPath  string         `json:"backup_path,omitempty"`
	ReceiptPath string         `json:"receipt_path"`
	Lock        model.LockFile `json:"lock"`
}

type Verification struct {
	Path                string         `json:"path"`
	Valid               bool           `json:"valid"`
	ExpectedFingerprint string         `json:"expected_fingerprint"`
	ActualFingerprint   string         `json:"actual_fingerprint"`
	ChangedFiles        []string       `json:"changed_files,omitempty"`
	Lock                model.LockFile `json:"lock"`
}

func TargetRoot(target, override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return canonicalPath(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "codex":
		if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
			return canonicalPath(filepath.Join(codexHome, "skills"))
		}
		return canonicalPath(filepath.Join(home, ".codex", "skills"))
	case "claude", "claude-code":
		return canonicalPath(filepath.Join(home, ".claude", "skills"))
	case "cursor":
		return canonicalPath(filepath.Join(home, ".cursor", "skills"))
	case "gemini", "gemini-cli":
		return canonicalPath(filepath.Join(home, ".gemini", "skills"))
	case "openclaw":
		return canonicalPath(filepath.Join(home, ".openclaw", "skills"))
	default:
		return "", errors.New("target is required (codex, claude, cursor, gemini, or openclaw), unless --dir is set")
	}
}

func Install(ctx context.Context, root string, report model.ScanReport, options Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := platformGuardedOperationsAvailable(); err != nil {
		return Result{}, err
	}
	if options.AllowedRisk == "" {
		options.AllowedRisk = model.SeverityMedium
	}
	if err := report.CheckInstallPolicy(options.AllowedRisk); err != nil {
		return Result{}, fmt.Errorf("reviewed package policy denies installation: %w", err)
	}
	name := strings.TrimSpace(report.Metadata.Name)
	if len(name) < 1 || len(name) > 64 || !validSkillName.MatchString(name) {
		return Result{}, errors.New("SKILL.md must declare a 1-64 character lowercase hyphenated name before installation")
	}
	if report.Metadata.Description == "" || len(report.Metadata.Description) > 1024 {
		return Result{}, errors.New("SKILL.md must declare a description between 1 and 1024 characters before installation")
	}
	before, err := scanner.Fingerprint(root)
	if err != nil {
		return Result{}, fmt.Errorf("verify source before installation: %w", err)
	}
	if before != report.Fingerprint {
		return Result{}, errors.New("source changed after scanning; scan it again before installation")
	}

	targetRoot, err := TargetRoot(options.Target, options.Directory)
	if err != nil {
		return Result{}, err
	}
	if err := ensureOwnedDirectory(ctx, targetRoot, 0o755, false); err != nil {
		return Result{}, fmt.Errorf("prepare target root: %w", err)
	}

	stageParent := filepath.Dir(targetRoot)
	if err := validateStagingParent(ctx, stageParent); err != nil {
		return Result{}, fmt.Errorf("validate staging parent: %w", err)
	}
	stageContainer, err := os.MkdirTemp(stageParent, ".skillguardrail-stage-")
	if err != nil {
		return Result{}, fmt.Errorf("create same-filesystem staging directory: %w", err)
	}
	defer os.RemoveAll(stageContainer)
	if err := os.Chmod(stageContainer, 0o700); err != nil {
		return Result{}, fmt.Errorf("secure staging directory: %w", err)
	}
	if err := platformHardenPathACL(ctx, stageContainer); err != nil {
		return Result{}, fmt.Errorf("harden staging directory ACL: %w", err)
	}
	if err := validateOwnedDirectory(ctx, stageContainer, true); err != nil {
		return Result{}, fmt.Errorf("validate staging directory ACL: %w", err)
	}
	stageSkill := filepath.Join(stageContainer, name)
	if err := copySkillTree(ctx, root, stageSkill); err != nil {
		return Result{}, fmt.Errorf("copy reviewed package into staging: %w", err)
	}
	if err := platformHardenTreeACL(ctx, stageContainer); err != nil {
		return Result{}, err
	}
	if err := platformVerifyTreeACL(ctx, stageContainer); err != nil {
		return Result{}, fmt.Errorf("validate staged package ACLs: %w", err)
	}
	if err := validateOwnedTree(ctx, stageContainer); err != nil {
		return Result{}, fmt.Errorf("validate staged package ownership and permissions: %w", err)
	}
	after, err := scanner.Fingerprint(root)
	if err != nil {
		return Result{}, fmt.Errorf("verify source after staging: %w", err)
	}
	if after != report.Fingerprint {
		return Result{}, errors.New("source changed while staging; installation aborted")
	}

	stageReport, err := scanner.Scan(ctx, stageSkill, report.Source, options.ToolVersion)
	if err != nil {
		return Result{}, fmt.Errorf("rescan staged package: %w", err)
	}
	if err := stageReport.CheckInstallPolicy(options.AllowedRisk); err != nil {
		return Result{}, fmt.Errorf("staged package policy denies installation: %w", err)
	}
	if stageReport.Fingerprint != report.Fingerprint {
		return Result{}, errors.New("staged package fingerprint differs from the reviewed package; installation aborted")
	}
	files, err := digestTree(stageSkill)
	if err != nil {
		return Result{}, fmt.Errorf("hash staged files: %w", err)
	}
	destination := filepath.Join(targetRoot, name)
	if err := ensureNoSymlinkAncestors(destination); err != nil {
		return Result{}, err
	}
	receiptPath, err := authoritativeReceiptPath(destination, options.StateDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve authoritative receipt: %w", err)
	}
	if err := prepareReceiptDirectory(ctx, filepath.Dir(receiptPath)); err != nil {
		return Result{}, fmt.Errorf("prepare authoritative receipt directory: %w", err)
	}
	lock := model.LockFile{
		SchemaVersion:    model.SchemaVersion,
		ToolVersion:      options.ToolVersion,
		RulePack:         "builtin-v1",
		InstalledAt:      time.Now().UTC(),
		InstalledPath:    destination,
		Source:           report.Source,
		SkillName:        name,
		Fingerprint:      stageReport.Fingerprint,
		RiskScore:        stageReport.RiskScore,
		RiskScoreMeaning: stageReport.RiskScoreMeaning,
		SafetyClaim:      stageReport.SafetyClaim,
		Verdict:          stageReport.Verdict,
		Capabilities:     stageReport.Capabilities,
		Findings:         stageReport.Findings,
		Files:            files,
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("encode installation receipt: %w", err)
	}
	lockBytes = append(lockBytes, '\n')
	if err := validateReceiptSize(lockBytes); err != nil {
		return Result{}, fmt.Errorf("installation policy denies unmanageable receipt: %w", err)
	}
	localReceiptPath := filepath.Join(stageSkill, LockFileName)
	if err := os.WriteFile(localReceiptPath, lockBytes, 0o600); err != nil {
		return Result{}, fmt.Errorf("write installation receipt: %w", err)
	}
	if err := platformHardenPathACL(ctx, localReceiptPath); err != nil {
		return Result{}, fmt.Errorf("harden package receipt ACL: %w", err)
	}
	if err := platformVerifyTreeACL(ctx, stageContainer); err != nil {
		return Result{}, fmt.Errorf("validate final staged package ACLs: %w", err)
	}
	if err := validateOwnedTree(ctx, stageContainer); err != nil {
		return Result{}, fmt.Errorf("validate final staged package ownership and permissions: %w", err)
	}

	result := Result{Path: destination, ReceiptPath: receiptPath, Lock: lock}
	if _, err := os.Lstat(destination); err == nil {
		if !options.Replace {
			return Result{}, fmt.Errorf("destination already exists: %s (use --replace to create a backup and replace it)", destination)
		}
		backupContainer, err := os.MkdirTemp(stageParent, ".skillguardrail-backup-")
		if err != nil {
			return Result{}, fmt.Errorf("create private backup container: %w", err)
		}
		defer os.Remove(backupContainer)
		if err := os.Chmod(backupContainer, 0o700); err != nil {
			return Result{}, fmt.Errorf("secure backup container: %w", err)
		}
		if err := platformHardenPathACL(ctx, backupContainer); err != nil {
			return Result{}, fmt.Errorf("harden backup container ACL: %w", err)
		}
		if err := validateOwnedDirectory(ctx, backupContainer, true); err != nil {
			return Result{}, fmt.Errorf("validate backup container: %w", err)
		}
		backup := filepath.Join(backupContainer, name)
		if err := os.Rename(destination, backup); err != nil {
			return Result{}, fmt.Errorf("backup existing skill: %w", err)
		}
		result.BackupPath = backup
		if err := os.Rename(stageSkill, destination); err != nil {
			if restoreErr := os.Rename(backup, destination); restoreErr != nil {
				return Result{}, fmt.Errorf("atomically install staged skill: %v; restore previous installation: %w", err, restoreErr)
			}
			_ = os.Remove(backupContainer)
			return Result{}, fmt.Errorf("atomically install staged skill: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect destination: %w", err)
	} else if err := os.Rename(stageSkill, destination); err != nil {
		return Result{}, fmt.Errorf("atomically install staged skill: %w", err)
	}
	if err := platformVerifyTreeACL(ctx, destination); err != nil {
		rollbackErr := rollbackInstalledDestination(destination, stageSkill, result.BackupPath)
		if rollbackErr != nil {
			return Result{}, fmt.Errorf("validate installed skill ACLs: %v; installation rollback also failed: %w", err, rollbackErr)
		}
		removeEmptyBackupContainer(result.BackupPath)
		return Result{}, fmt.Errorf("validate installed skill ACLs (installation rolled back): %w", err)
	}
	if err := validateOwnedTree(ctx, destination); err != nil {
		rollbackErr := rollbackInstalledDestination(destination, stageSkill, result.BackupPath)
		if rollbackErr != nil {
			return Result{}, fmt.Errorf("validate installed skill ownership and permissions: %v; installation rollback also failed: %w", err, rollbackErr)
		}
		removeEmptyBackupContainer(result.BackupPath)
		return Result{}, fmt.Errorf("validate installed skill ownership and permissions (installation rolled back): %w", err)
	}
	if err := writeAuthoritativeReceipt(ctx, receiptPath, lockBytes); err != nil {
		rollbackErr := rollbackInstalledDestination(destination, stageSkill, result.BackupPath)
		if rollbackErr != nil {
			return Result{}, fmt.Errorf("write authoritative receipt: %v; installation rollback also failed: %w", err, rollbackErr)
		}
		removeEmptyBackupContainer(result.BackupPath)
		return Result{}, fmt.Errorf("write authoritative receipt (installation rolled back): %w", err)
	}
	return result, nil
}

func validateReceiptSize(data []byte) error {
	if int64(len(data)) > maxReceiptBytes {
		return fmt.Errorf("encoded authoritative receipt exceeds %d bytes", maxReceiptBytes)
	}
	return nil
}

func Verify(path string) (Verification, error) {
	return VerifyWithState(path, "")
}

func VerifyWithState(path, stateDir string) (Verification, error) {
	if err := platformGuardedOperationsAvailable(); err != nil {
		return Verification{}, err
	}
	ctx := context.Background()
	rawAbs, err := filepath.Abs(path)
	if err != nil {
		return Verification{}, err
	}
	if info, err := os.Lstat(rawAbs); err != nil {
		return Verification{}, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return Verification{}, errors.New("verification path may not be a symbolic link")
	}
	abs, err := canonicalPath(rawAbs)
	if err != nil {
		return Verification{}, err
	}
	if err := ensureNoSymlinkAncestors(abs); err != nil {
		return Verification{}, err
	}
	if err := validateOwnedDirectory(ctx, filepath.Dir(abs), false); err != nil {
		return Verification{}, fmt.Errorf("validate installation parent: %w", err)
	}
	if err := platformVerifyTreeACL(ctx, abs); err != nil {
		return Verification{}, fmt.Errorf("validate installed skill ACLs: %w", err)
	}
	if err := validateOwnedTree(ctx, abs); err != nil {
		return Verification{}, fmt.Errorf("validate installed skill ownership and permissions: %w", err)
	}
	receiptPath, err := authoritativeReceiptPath(abs, stateDir)
	if err != nil {
		return Verification{}, fmt.Errorf("resolve authoritative receipt: %w", err)
	}
	if err := ensureNoSymlinkAncestors(receiptPath); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative receipt path: %w", err)
	}
	receiptDirectory := filepath.Dir(receiptPath)
	stateRoot := filepath.Dir(receiptDirectory)
	if err := validateOwnedDirectory(ctx, stateRoot, true); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative state root: %w", err)
	}
	if err := validateOwnedDirectory(ctx, receiptDirectory, true); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative receipt directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(receiptDirectory); err != nil {
			return Verification{}, fmt.Errorf("inspect authoritative receipt directory: %w", err)
		} else if info.Mode().Perm()&0o077 != 0 {
			return Verification{}, errors.New("authoritative receipt directory is accessible to group or other users")
		}
	}
	if err := platformVerifyPathOwner(receiptPath, false); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative receipt owner: %w", err)
	}
	if err := platformVerifyACLPaths(ctx, receiptDirectory, receiptPath); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative receipt ACLs: %w", err)
	}
	data, err := readRegularLimitedFile(receiptPath, maxReceiptBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Verification{}, errors.New("authoritative receipt not found; this directory is not a verified SkillGuardrail installation")
		}
		return Verification{}, fmt.Errorf("read authoritative receipt: %w", err)
	}
	var lock model.LockFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return Verification{}, fmt.Errorf("decode authoritative receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verification{}, errors.New("decode authoritative receipt: trailing JSON data")
	}
	if err := validateLock(lock, abs); err != nil {
		return Verification{}, fmt.Errorf("validate authoritative receipt: %w", err)
	}
	actual, err := scanner.Fingerprint(abs)
	if err != nil {
		return Verification{}, fmt.Errorf("fingerprint installed skill: %w", err)
	}
	currentFiles, err := digestTree(abs)
	if err != nil {
		return Verification{}, fmt.Errorf("hash installed files: %w", err)
	}
	changed := compareDigests(lock.Files, currentFiles)
	localManifest, manifestErr := readRegularLimitedFile(filepath.Join(abs, LockFileName), maxReceiptBytes)
	if manifestErr != nil || !bytes.Equal(localManifest, data) {
		changed = append(changed, LockFileName)
		sort.Strings(changed)
	}
	return Verification{
		Path: abs, Valid: actual == lock.Fingerprint && len(changed) == 0,
		ExpectedFingerprint: lock.Fingerprint, ActualFingerprint: actual,
		ChangedFiles: changed, Lock: lock,
	}, nil
}

func authoritativeReceiptPath(installedPath, override string) (string, error) {
	abs, err := canonicalPath(installedPath)
	if err != nil {
		return "", err
	}
	name := filepath.Base(abs)
	if !validSkillName.MatchString(name) {
		return "", errors.New("installed skill path must end in a lowercase hyphenated skill name")
	}
	root := strings.TrimSpace(override)
	if root == "" {
		root = strings.TrimSpace(os.Getenv("SKILLGUARDRAIL_STATE_HOME"))
	}
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user configuration directory: %w", err)
		}
		root = filepath.Join(config, "SkillGuardrail", "receipts")
	}
	root, err = canonicalPath(root)
	if err != nil {
		return "", err
	}
	if rel, err := filepath.Rel(filepath.Dir(abs), root); err != nil {
		return "", err
	} else if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", errors.New("authoritative state directory must be outside the agent skill discovery directory")
	}
	targetKey := model.ShortHash(filepath.Dir(abs))
	return filepath.Join(root, targetKey, name+".json"), nil
}

func prepareReceiptDirectory(ctx context.Context, directory string) error {
	stateRoot := filepath.Dir(directory)
	if err := ensureOwnedDirectory(ctx, stateRoot, 0o700, true); err != nil {
		return fmt.Errorf("prepare state root: %w", err)
	}
	if err := ensureOwnedDirectory(ctx, directory, 0o700, true); err != nil {
		return fmt.Errorf("prepare receipt directory: %w", err)
	}
	return nil
}

func writeAuthoritativeReceipt(ctx context.Context, destination string, data []byte) error {
	directory := filepath.Dir(destination)
	file, err := os.CreateTemp(directory, ".receipt-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := platformHardenPathACL(ctx, temporary); err != nil {
		_ = file.Close()
		return err
	}
	if err := platformVerifyPathOwner(temporary, false); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	previous := ""
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("existing authoritative receipt is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing authoritative receipt is accessible to group or other users")
		}
		if err := platformVerifyPathOwner(destination, false); err != nil {
			return fmt.Errorf("validate existing authoritative receipt owner: %w", err)
		}
		if err := platformVerifyACLPaths(ctx, destination); err != nil {
			return fmt.Errorf("validate existing authoritative receipt ACL: %w", err)
		}
		previous = destination + ".previous-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := os.Rename(destination, previous); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		if previous != "" {
			if restoreErr := os.Rename(previous, destination); restoreErr != nil {
				return fmt.Errorf("promote new receipt: %v; restore previous receipt: %w", err, restoreErr)
			}
		}
		return err
	}
	validationErr := validateOwnedDirectory(ctx, directory, true)
	if validationErr == nil {
		validationErr = platformVerifyPathOwner(destination, false)
	}
	if validationErr == nil {
		validationErr = platformVerifyACLPaths(ctx, directory, destination)
	}
	if validationErr != nil {
		return restorePreviousReceipt(destination, previous, validationErr)
	}
	if previous != "" {
		_ = os.Remove(previous)
	}
	return nil
}

func restorePreviousReceipt(destination, previous string, validationErr error) error {
	removeErr := os.Remove(destination)
	if previous != "" && removeErr == nil {
		removeErr = os.Rename(previous, destination)
	}
	if removeErr != nil {
		return fmt.Errorf("validate new receipt: %v; restore previous receipt: %w", validationErr, removeErr)
	}
	return fmt.Errorf("validate new receipt: %w", validationErr)
}

func rollbackInstalledDestination(destination, stageSkill, backup string) error {
	if err := os.Rename(destination, stageSkill); err != nil {
		if backup != "" {
			return fmt.Errorf("move failed installation out of discovery directory; previous installation remains at %s: %w", backup, err)
		}
		return fmt.Errorf("move failed installation out of discovery directory: %w", err)
	}
	if backup != "" {
		if err := os.Rename(backup, destination); err != nil {
			return fmt.Errorf("restore previous installation from %s: %w", backup, err)
		}
	}
	return nil
}

func removeEmptyBackupContainer(backup string) {
	if backup != "" {
		_ = os.Remove(filepath.Dir(backup))
	}
}

func readRegularLimitedFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("file changed while opening")
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file is accessible to group or other users")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func validateLock(lock model.LockFile, installedPath string) error {
	if lock.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported schema version %q", lock.SchemaVersion)
	}
	if lock.ToolVersion == "" || len(lock.ToolVersion) > 128 || lock.RulePack == "" || len(lock.RulePack) > 128 {
		return errors.New("invalid tool or rule-pack identifier")
	}
	if lock.InstalledAt.IsZero() || lock.InstalledAt.After(time.Now().UTC().Add(10*time.Minute)) {
		return errors.New("invalid installation time")
	}
	if lock.InstalledPath != installedPath || filepath.Base(installedPath) != lock.SkillName || !validSkillName.MatchString(lock.SkillName) {
		return errors.New("receipt is not bound to this installed path and skill name")
	}
	if !validSHA256.MatchString(lock.Fingerprint) || lock.RiskScore < 0 || lock.RiskScore > 100 {
		return errors.New("invalid fingerprint or risk score")
	}
	if lock.Verdict != model.VerdictPass && lock.Verdict != model.VerdictReview {
		return errors.New("authoritative receipt contains a verdict that may not be installed")
	}
	if lock.Source.Kind != "local" && lock.Source.Kind != "github" {
		return errors.New("invalid source kind")
	}
	if len(lock.Source.Input) > 8192 || len(lock.Source.Resolved) > 8192 || len(lock.Source.Repository) > 512 {
		return errors.New("source provenance field is too large")
	}
	if lock.Source.Commit != "" && !validCommit.MatchString(lock.Source.Commit) {
		return errors.New("invalid source commit")
	}
	if lock.Source.ArchiveSHA256 != "" && !validSHA256.MatchString(lock.Source.ArchiveSHA256) {
		return errors.New("invalid archive digest")
	}
	if lock.Source.Kind == "github" && (lock.Source.Repository == "" || lock.Source.Resolved == "" || !validCommit.MatchString(lock.Source.Commit) || !validSHA256.MatchString(lock.Source.ArchiveSHA256)) {
		return errors.New("incomplete GitHub source provenance")
	}
	if lock.Source.Kind == "local" && lock.Source.Resolved == "" {
		return errors.New("incomplete local source provenance")
	}
	for _, finding := range lock.Findings {
		if finding.RuleID == "" || len(finding.RuleID) > 128 {
			return errors.New("invalid recorded finding")
		}
		if _, err := model.ParseSeverity(string(finding.Severity)); err != nil {
			return errors.New("invalid recorded finding severity")
		}
		if finding.Location.Path == "" || len(finding.Location.Path) > 4096 || finding.Location.Line < 0 || finding.Location.Column < 0 {
			return errors.New("invalid recorded finding location")
		}
	}
	for _, capability := range lock.Capabilities {
		if capability.Name == "" || len(capability.Name) > 256 {
			return errors.New("invalid recorded capability")
		}
		if _, err := model.ParseSeverity(string(capability.Risk)); err != nil {
			return errors.New("invalid recorded capability risk")
		}
	}
	recomputed := model.ScanReport{Findings: append([]model.Finding(nil), lock.Findings...)}
	recomputed.Finalize()
	if recomputed.RiskScore != lock.RiskScore || recomputed.Verdict != lock.Verdict {
		return errors.New("receipt risk score or verdict is inconsistent with its findings")
	}
	if len(lock.Files) == 0 || len(lock.Files) > maxDigestEntries {
		return errors.New("invalid receipt entry count")
	}
	seen := map[string]bool{}
	var totalSize int64
	for _, entry := range lock.Files {
		if seen[entry.Path] {
			return fmt.Errorf("duplicate receipt path %q", entry.Path)
		}
		seen[entry.Path] = true
		if entry.Path != "." && (entry.Path == "" || strings.Contains(entry.Path, "\\") || pathpkg.IsAbs(entry.Path) || pathpkg.Clean(entry.Path) != entry.Path || entry.Path == ".." || strings.HasPrefix(entry.Path, "../")) {
			return fmt.Errorf("invalid receipt path %q", entry.Path)
		}
		if entry.Path == LockFileName || strings.HasSuffix(entry.Path, "/"+LockFileName) {
			return errors.New("package manifest may not certify itself")
		}
		if !validMode.MatchString(entry.Mode) {
			return fmt.Errorf("invalid mode for %q", entry.Path)
		}
		switch entry.Type {
		case "directory":
			if entry.SHA256 != "" || entry.Size != 0 {
				return fmt.Errorf("invalid directory digest for %q", entry.Path)
			}
		case "file":
			if !validSHA256.MatchString(entry.SHA256) || entry.Size < 0 || entry.Size > maxDigestBytes {
				return fmt.Errorf("invalid file digest for %q", entry.Path)
			}
			totalSize += entry.Size
			if totalSize > maxDigestBytes {
				return errors.New("receipt file sizes exceed the verification budget")
			}
		default:
			return fmt.Errorf("invalid entry type for %q", entry.Path)
		}
		if entry.Path == "." && entry.Type != "directory" {
			return errors.New("receipt root entry is not a directory")
		}
	}
	if root, ok := seen["."]; !ok || !root {
		return errors.New("receipt does not contain the installed root directory")
	}
	return nil
}

func canonicalPath(value string) (string, error) {
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(abs)
	suffix := []string{}
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return abs, nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func ResolveVerificationPath(nameOrPath, target, directory string) (string, error) {
	if info, err := os.Lstat(nameOrPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("verification path may not be a symbolic link")
		}
		return filepath.Abs(nameOrPath)
	}
	if !validSkillName.MatchString(nameOrPath) {
		return "", errors.New("verify expects an existing path or a lowercase skill name")
	}
	root, err := TargetRoot(target, directory)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, nameOrPath), nil
}

func copySkillTree(ctx context.Context, sourceRoot, destinationRoot string) error {
	return filepath.WalkDir(sourceRoot, func(sourcePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil {
			return err
		}
		if rel == "." {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if err := os.Mkdir(destinationRoot, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(destinationRoot, info.Mode().Perm())
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == ".venv") {
			return filepath.SkipDir
		}
		if entry.Name() == LockFileName {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("refusing non-regular entry %q", rel)
		}
		destination := filepath.Join(destinationRoot, rel)
		if info.IsDir() {
			if err := os.Mkdir(destination, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(destination, info.Mode().Perm())
		}
		input, err := os.Open(sourcePath)
		if err != nil {
			return err
		}
		openedInfo, err := input.Stat()
		if err != nil {
			_ = input.Close()
			return err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
			_ = input.Close()
			return fmt.Errorf("source entry changed while opening %q", rel)
		}
		mode := info.Mode().Perm()
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.CopyN(output, input, info.Size())
		inputErr := input.Close()
		outputErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputErr != nil {
			return inputErr
		}
		if outputErr != nil {
			return outputErr
		}
		return os.Chmod(destination, mode)
	})
}

func ensureNoSymlinkAncestors(value string) error {
	abs, err := filepath.Abs(value)
	if err != nil {
		return err
	}
	current := filepath.Clean(abs)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing path with symbolic-link component: %s", current)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func validateStagingParent(ctx context.Context, path string) error {
	return validateDirectoryHierarchy(ctx, path)
}

func ensureOwnedDirectory(ctx context.Context, path string, mode os.FileMode, private bool) error {
	if err := ensureNoSymlinkAncestors(path); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		ancestor, ancestorErr := nearestExistingDirectory(path)
		if ancestorErr != nil {
			return ancestorErr
		}
		if err := validateDirectoryHierarchy(ctx, ancestor); err != nil {
			return fmt.Errorf("validate existing parent hierarchy: %w", err)
		}
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		if err := ensureNoSymlinkAncestors(path); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := platformHardenPathACL(ctx, path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return validateOwnedDirectory(ctx, path, private)
}

func validateOwnedDirectory(ctx context.Context, path string, private bool) error {
	if err := ensureNoSymlinkAncestors(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if parent != filepath.Clean(path) {
		if err := validateDirectoryHierarchy(ctx, parent); err != nil {
			return fmt.Errorf("validate parent hierarchy: %w", err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if err := platformVerifyPathOwner(path, false); err != nil {
		return err
	}
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	if info.Mode().Perm()&mask != 0 {
		if private {
			return errors.New("private directory is accessible to group or other users")
		}
		return errors.New("directory is writable by group or other users")
	}
	return platformVerifyACLPaths(ctx, path)
}

func validateDirectoryHierarchy(ctx context.Context, path string) error {
	if err := ensureNoSymlinkAncestors(path); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	paths := []string{}
	current := filepath.Clean(abs)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("directory hierarchy component is not a directory: %s", current)
		}
		if err := platformVerifyPathOwner(current, true); err != nil {
			return fmt.Errorf("untrusted directory owner at %s: %w", current, err)
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("directory hierarchy component is writable by group or other users without sticky protection: %s", current)
		}
		paths = append(paths, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return platformVerifyBoundaryACLPaths(ctx, paths...)
}

func nearestExistingDirectory(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("existing path component is not a directory: %s", current)
			}
			return current, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("no existing directory ancestor")
		}
		current = parent
	}
}

func validateOwnedTree(ctx context.Context, root string) error {
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxDigestEntries+2 {
			return fmt.Errorf("installed tree exceeds ownership-check entry limit (limit=%d)", maxDigestEntries+2)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("refusing non-regular installed-tree entry %q", path)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("installed-tree entry is writable by group or other users: %s", path)
		}
		if err := platformVerifyPathOwner(path, false); err != nil {
			return fmt.Errorf("validate installed-tree owner for %s: %w", path, err)
		}
		return nil
	})
}

func digestTree(root string) ([]model.FileDigest, error) {
	result := []model.FileDigest{}
	entries := 0
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(rel) == LockFileName {
			return nil
		}
		entries++
		if entries > maxDigestEntries {
			return fmt.Errorf("installed tree exceeds %d entries", maxDigestEntries)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := fmt.Sprintf("%04o", info.Mode().Perm())
		if info.IsDir() {
			result = append(result, model.FileDigest{Path: filepath.ToSlash(rel), Type: "directory", Mode: mode})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular installed entry %q", rel)
		}
		if info.Size() < 0 || info.Size() > maxDigestBytes || total+info.Size() > maxDigestBytes {
			return fmt.Errorf("installed tree exceeds %d bytes", maxDigestBytes)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		openedInfo, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = file.Close()
			return fmt.Errorf("installed entry changed while opening %q", rel)
		}
		hash := sha256.New()
		written, copyErr := io.CopyN(hash, file, info.Size())
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		total += written
		result = append(result, model.FileDigest{
			Path: filepath.ToSlash(rel), Type: "file", Mode: mode,
			SHA256: hex.EncodeToString(hash.Sum(nil)), Size: info.Size(),
		})
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, err
}

func compareDigests(expected, actual []model.FileDigest) []string {
	expectedMap := map[string]model.FileDigest{}
	actualMap := map[string]model.FileDigest{}
	for _, item := range expected {
		expectedMap[item.Path] = item
	}
	for _, item := range actual {
		actualMap[item.Path] = item
	}
	changed := []string{}
	for path, want := range expectedMap {
		got, ok := actualMap[path]
		if !ok || got.Type != want.Type || got.Mode != want.Mode || got.SHA256 != want.SHA256 || got.Size != want.Size {
			changed = append(changed, path)
		}
	}
	for path := range actualMap {
		if _, ok := expectedMap[path]; !ok {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}
