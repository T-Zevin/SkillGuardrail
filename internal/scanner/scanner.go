// Package scanner performs a deterministic, offline security review of an
// Agent Skill directory. It never executes files and never follows symlinks.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

const (
	defaultMaxFiles     = 5_000
	defaultMaxFileSize  = int64(2 << 20)  // 2 MiB
	defaultMaxTotalSize = int64(20 << 20) // 20 MiB

	// Findings are attacker-controlled output. Keep both a package-wide ceiling
	// and a per-rule/per-path ceiling so repeated indicators cannot amplify a
	// bounded input into an unbounded report.
	maxRetainedFindings       = 512
	maxFindingsPerRuleAndPath = 16
)

var errByteLimitExceeded = errors.New("byte limit exceeded")

// Config bounds the amount of untrusted input the scanner will inspect.
// Ignored directories are skipped by name at any depth.
type Config struct {
	MaxFiles      int
	MaxFileSize   int64
	MaxTotalSize  int64
	IncludeHidden bool
	IgnoreDirs    []string
}

// DefaultConfig returns conservative limits suitable for an Agent Skill.
// Hidden files are included because a malicious package can hide payloads in
// dotfiles; known dependency and VCS directories are still excluded.
func DefaultConfig() Config {
	return Config{
		MaxFiles:      defaultMaxFiles,
		MaxFileSize:   defaultMaxFileSize,
		MaxTotalSize:  defaultMaxTotalSize,
		IncludeHidden: true,
		IgnoreDirs:    []string{".git", "node_modules", ".venv"},
	}
}

// Scanner is safe for concurrent use. Its configuration is immutable after
// construction.
type Scanner struct {
	config  Config
	ignored map[string]struct{}
}

// New constructs a scanner. Non-positive limits receive safe defaults.
func New(config Config) *Scanner {
	if config.MaxFiles <= 0 {
		config.MaxFiles = defaultMaxFiles
	}
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = defaultMaxFileSize
	}
	if config.MaxTotalSize <= 0 {
		config.MaxTotalSize = defaultMaxTotalSize
	}
	if len(config.IgnoreDirs) == 0 {
		config.IgnoreDirs = []string{".git", "node_modules", ".venv"}
	}
	ignored := make(map[string]struct{}, len(config.IgnoreDirs))
	for _, name := range config.IgnoreDirs {
		name = strings.TrimSpace(name)
		if name != "" && name != "." && !strings.ContainsAny(name, `/\\`) {
			ignored[name] = struct{}{}
		}
	}
	return &Scanner{config: config, ignored: ignored}
}

// Scan uses DefaultConfig. Call New when custom resource limits are needed.
func Scan(ctx context.Context, root string, source model.SourceInfo, toolVersion string) (model.ScanReport, error) {
	return New(DefaultConfig()).Scan(ctx, root, source, toolVersion)
}

// Scan recursively inspects root without executing content or following links.
func (s *Scanner) Scan(ctx context.Context, root string, source model.SourceInfo, toolVersion string) (model.ScanReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return model.ScanReport{}, fmt.Errorf("resolve scan root: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		return model.ScanReport{}, fmt.Errorf("open scan root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.ScanReport{}, errors.New("scan root must not be a symbolic link")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return model.ScanReport{}, fmt.Errorf("scan root is not a directory or regular file: %s", absRoot)
	}

	report := model.NewReport(toolVersion, source, absRoot)
	state := scanState{
		root: absRoot, rootIsFile: !info.IsDir(), report: &report,
		findingCounts: map[string]int{}, manifestData: map[string][]byte{}, findingLimitIndex: -1,
	}

	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if state.halted {
			return fs.SkipAll
		}
		if walkErr != nil {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-FILE-005", "Unreadable path", "file-safety", model.SeverityHigh,
				"The scanner could not inspect part of the package.", walkErr.Error(), "Ensure every packaged file is readable, then scan again.", "high")
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path != absRoot && s.skipEntry(absRoot, path, entry) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path != absRoot || state.rootIsFile {
			state.entriesSeen++
		}
		if state.entriesSeen > s.config.MaxFiles {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-LIMIT-001", "Package entry limit exceeded", "scan-integrity", model.SeverityHigh,
				"The package contains more files or directories than the configured scan limit.", fmt.Sprintf("limit=%d", s.config.MaxFiles),
				"Remove generated dependencies or raise the limit and scan the complete package.", "high")
			state.halted = true
			return fs.SkipAll
		}
		if entry.IsDir() {
			return nil
		}

		entryInfo, err := entry.Info()
		if err != nil {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-FILE-005", "Unreadable file metadata", "file-safety", model.SeverityHigh,
				"The scanner could not inspect file metadata.", err.Error(), "Fix file permissions and scan again.", "high")
			return nil
		}
		report.FilesScanned++

		if entryInfo.Mode()&os.ModeSymlink != 0 {
			s.inspectSymlink(&state, path)
			return nil
		}
		if !entryInfo.Mode().IsRegular() {
			state.addFileFinding(path, 0, "SG-FILE-006", "Special filesystem entry", "file-safety", model.SeverityHigh,
				"Device, socket, or other special entries are not valid portable Skill content.", entryInfo.Mode().String(),
				"Remove the special entry and package only regular files.", "high")
			return nil
		}
		if entryInfo.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			state.addFileFinding(path, 0, "SG-FILE-007", "Privileged executable bit", "file-safety", model.SeverityCritical,
				"The file has a setuid or setgid bit that can change execution privileges.", entryInfo.Mode().String(),
				"Remove privileged permission bits and review the file provenance.", "high")
		}

		state.totalSize += entryInfo.Size()
		if state.totalSize > s.config.MaxTotalSize {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-LIMIT-002", "Package size limit exceeded", "scan-integrity", model.SeverityHigh,
				"The complete package could not be content-scanned within the configured byte limit.",
				fmt.Sprintf("limit=%d bytes", s.config.MaxTotalSize), "Remove generated artifacts or raise the limit and scan again.", "high")
			state.halted = true
			return fs.SkipAll
		}
		if entryInfo.Size() > s.config.MaxFileSize {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-FILE-001", "Oversized file", "file-safety", model.SeverityHigh,
				"The file is too large for content inspection and may conceal a payload.",
				fmt.Sprintf("size=%d bytes; limit=%d bytes", entryInfo.Size(), s.config.MaxFileSize),
				"Remove generated or opaque content, or explicitly raise the scan limit.", "high")
			return nil
		}

		data, err := readFileWithContext(ctx, path, s.config.MaxFileSize)
		if err != nil {
			state.incomplete = true
			if errors.Is(err, errByteLimitExceeded) {
				state.addFileFinding(path, 0, "SG-FILE-001", "File grew beyond inspection limit", "file-safety", model.SeverityHigh,
					"The file exceeded the configured limit while it was being read and may be changing concurrently.",
					fmt.Sprintf("limit=%d bytes", s.config.MaxFileSize), "Stop concurrent writers, reduce the file size, and scan again.", "high")
				return nil
			}
			state.addFileFinding(path, 0, "SG-FILE-005", "Unreadable file", "file-safety", model.SeverityHigh,
				"The scanner could not read this file.", err.Error(), "Fix file permissions and scan again.", "high")
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		state.totalSize += int64(len(data)) - entryInfo.Size()
		if state.totalSize > s.config.MaxTotalSize {
			state.incomplete = true
			state.addFileFinding(path, 0, "SG-LIMIT-002", "Package size limit exceeded", "scan-integrity", model.SeverityHigh,
				"The package grew while it was being scanned and exceeded the configured byte limit.",
				fmt.Sprintf("limit=%d bytes", s.config.MaxTotalSize), "Stop concurrent writers or raise the limit and scan the complete package again.", "high")
			state.halted = true
			return fs.SkipAll
		}
		report.BytesScanned += int64(len(data))
		if isManifestCandidate(absRoot, path, state.rootIsFile) {
			state.manifestData[path] = data
		}
		if binaryKind, binary := classifyBinary(path, data); binary {
			severity := model.SeverityMedium
			title := "Opaque binary file"
			if binaryKind == "media" {
				severity = model.SeverityLow
				title = "Opaque media asset"
			} else if binaryKind == "archive" {
				severity = model.SeverityHigh
				title = "Nested archive"
			} else if binaryKind == "executable" {
				severity = model.SeverityHigh
				title = "Embedded executable"
			}
			state.addFileFinding(path, 0, "SG-FILE-002", title, "binary-content", severity,
				"Binary content cannot be meaningfully reviewed as Skill instructions or source code.", binaryKind,
				"Remove the binary or publish reproducible source and verified checksums.", "high")
			return nil
		}

		return state.inspectText(ctx, path, data)
	})
	if err != nil {
		return report, fmt.Errorf("walk skill package: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("walk skill package: %w", err)
	}

	if metadataPath := findSkillFile(absRoot, state.rootIsFile); metadataPath != "" {
		if data, ok := state.manifestData[metadataPath]; ok {
			metadata, parseErr := parseSkillMetadata(ctx, data)
			if parseErr != nil {
				return report, fmt.Errorf("parse SKILL.md metadata: %w", parseErr)
			}
			report.Metadata = metadata
		}
		metadataRel := state.relative(metadataPath)
		if report.Metadata.Name == "" {
			state.addFinding(model.Finding{
				RuleID: "SG-MAN-001", Title: "Missing skill name", Description: "The SKILL.md frontmatter must declare a portable skill name.",
				Severity: model.SeverityHigh, Category: "manifest", Confidence: "high", Location: model.Location{Path: metadataRel, Line: 1},
				Recommendation: "Add a lowercase, hyphenated name between 1 and 64 characters.",
			})
		}
		if report.Metadata.Description == "" {
			state.addFinding(model.Finding{
				RuleID: "SG-MAN-002", Title: "Missing skill description", Description: "The SKILL.md frontmatter must describe when and why the skill is used.",
				Severity: model.SeverityHigh, Category: "manifest", Confidence: "high", Location: model.Location{Path: metadataRel, Line: 1},
				Recommendation: "Add a clear description between 1 and 1024 characters.",
			})
		}
	} else {
		state.addFinding(model.Finding{
			RuleID: "SG-MAN-003", Title: "SKILL.md not found", Description: "The package is not a portable Agent Skill without a root SKILL.md manifest.",
			Severity: model.SeverityHigh, Category: "manifest", Confidence: "high", Location: model.Location{Path: "."},
			Recommendation: "Add a valid root SKILL.md before installation.",
		})
	}
	if !state.incomplete {
		fingerprint, fingerprintErr := s.fingerprint(ctx, absRoot)
		if fingerprintErr != nil {
			return report, fmt.Errorf("fingerprint skill package: %w", fingerprintErr)
		}
		report.Fingerprint = fingerprint
	}
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("scan skill package: %w", err)
	}
	sortFindings(report.Findings)
	report.Capabilities = buildCapabilities(report.Findings)
	report.Finalize()
	return report, nil
}

type scanState struct {
	root              string
	rootIsFile        bool
	report            *model.ScanReport
	entriesSeen       int
	totalSize         int64
	halted            bool
	incomplete        bool
	findingCounts     map[string]int
	findingTotal      int
	findingLimitIndex int
	manifestData      map[string][]byte
}

func (s *Scanner) skipDirectory(name string) bool {
	_, ok := s.ignored[name]
	return ok
}

func (s *Scanner) skipEntry(root, path string, entry fs.DirEntry) bool {
	if entry.IsDir() && s.skipDirectory(entry.Name()) {
		return true
	}
	if !s.config.IncludeHidden && strings.HasPrefix(entry.Name(), ".") {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel == ".skillguardrail.lock" || rel == "skillguardrail.lock"
}

func (s *Scanner) inspectSymlink(state *scanState, path string) {
	target, err := os.Readlink(path)
	if err != nil {
		state.addFileFinding(path, 0, "SG-FILE-003", "Unreadable symbolic link", "file-safety", model.SeverityHigh,
			"The link target could not be verified.", err.Error(), "Remove symbolic links from the package.", "high")
		return
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(path), resolved)
	}
	resolved = filepath.Clean(resolved)
	severity := model.SeverityMedium
	title := "Symbolic link in package"
	description := "Symbolic links can make installed content differ from the reviewed package."
	if !pathWithin(state.root, resolved, state.rootIsFile) {
		severity = model.SeverityHigh
		title = "Symbolic link escapes package"
		description = "The symbolic link points outside the reviewed Skill root."
	}
	state.addFileFinding(path, 0, "SG-FILE-003", title, "file-safety", severity, description,
		"target="+target, "Replace the link with a regular, reviewable file.", "high")
}

func pathWithin(root, candidate string, rootIsFile bool) bool {
	if rootIsFile {
		return filepath.Clean(root) == filepath.Clean(candidate)
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (state *scanState) inspectText(ctx context.Context, path string, data []byte) error {
	rel := state.relative(path)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), len(data)+1)
	lineNo := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNo++
		line := scanner.Text()
		for _, rule := range contentRules {
			if err := ctx.Err(); err != nil {
				return err
			}
			if evidence, ok := rule.match(line); ok {
				state.addFinding(model.Finding{
					RuleID: rule.id, Title: rule.title, Description: rule.description,
					Severity: rule.severity, Category: rule.category, Confidence: rule.confidence,
					Location: model.Location{Path: rel, Line: lineNo, Column: firstColumn(line, evidence)},
					Evidence: sanitizeEvidence(evidence), Recommendation: rule.recommendation,
				})
				if state.halted {
					return nil
				}
			}
		}
		if evidence, ok := suspiciousUnicode(line); ok {
			state.addFinding(model.Finding{
				RuleID: "SG-OBF-004", Title: "Invisible or bidirectional Unicode", Description: "Invisible control characters can disguise instructions or code.",
				Severity: model.SeverityHigh, Category: "obfuscation", Confidence: "high",
				Location:       model.Location{Path: rel, Line: lineNo, Column: firstColumn(line, evidence)},
				Evidence:       fmt.Sprintf("Unicode control character %U", []rune(evidence)[0]),
				Recommendation: "Remove invisible controls and review the line in a Unicode-aware editor.",
			})
			if state.halted {
				return nil
			}
		}
		if matchesSensitiveEgressChain(line) {
			state.addFinding(model.Finding{
				RuleID: "SG-CHAIN-001", Title: "Sensitive data exfiltration chain", Description: "A single operation combines sensitive local data access with outbound transfer.",
				Severity: model.SeverityCritical, Category: "behavior-chain", Confidence: "high",
				Location:       model.Location{Path: rel, Line: lineNo},
				Evidence:       sanitizeEvidence(line),
				Recommendation: "Remove the transfer and redesign the skill so sensitive data never leaves the machine without explicit, scoped approval.",
			})
			if state.halted {
				return nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

func (state *scanState) addFileFinding(path string, line int, id, title, category string, severity model.Severity, description, evidence, recommendation, confidence string) {
	state.addFinding(model.Finding{
		RuleID: id, Title: title, Description: description, Severity: severity, Category: category, Confidence: confidence,
		Location: model.Location{Path: state.relative(path), Line: line}, Evidence: sanitizeEvidence(evidence), Recommendation: recommendation,
	})
}

func (state *scanState) addFinding(finding model.Finding) {
	key := finding.RuleID + "\x00" + finding.Location.Path
	if state.findingTotal >= maxRetainedFindings || state.findingCounts[key] >= maxFindingsPerRuleAndPath {
		state.noteFindingLimit(finding)
		return
	}
	state.report.Findings = append(state.report.Findings, finding)
	state.findingCounts[key]++
	state.findingTotal++
}

func (state *scanState) noteFindingLimit(suppressed model.Finding) {
	state.incomplete = true
	state.halted = true
	if state.findingLimitIndex >= 0 {
		if suppressed.Severity.Rank() > state.report.Findings[state.findingLimitIndex].Severity.Rank() {
			state.report.Findings[state.findingLimitIndex].Severity = suppressed.Severity
		}
		return
	}
	severity := model.SeverityHigh
	if suppressed.Severity == model.SeverityCritical {
		severity = model.SeverityCritical
	}
	state.report.Findings = append(state.report.Findings, model.Finding{
		RuleID: "SG-LIMIT-003", Title: "Finding retention limit exceeded",
		Description: "Repeated or excessive indicators were suppressed to keep the report and scanner memory bounded.",
		Severity:    severity, Category: "scan-integrity", Confidence: "high",
		Location:       suppressed.Location,
		Evidence:       fmt.Sprintf("retained=%d; global-limit=%d; per-rule-path-limit=%d", state.findingTotal, maxRetainedFindings, maxFindingsPerRuleAndPath),
		Recommendation: "Remove repeated generated content and rescan the complete, reviewable package.",
	})
	state.findingLimitIndex = len(state.report.Findings) - 1
}

func (state *scanState) relative(path string) string {
	if state.rootIsFile {
		return filepath.Base(path)
	}
	rel, err := filepath.Rel(state.root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func firstColumn(line, evidence string) int {
	idx := strings.Index(line, evidence)
	if idx < 0 {
		return 0
	}
	return utf8.RuneCountInString(line[:idx]) + 1
}

func classifyBinary(path string, data []byte) (string, bool) {
	if executableMagic(data) {
		return "executable", true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".jar", ".wasm", ".dmg", ".pkg":
		return "executable", true
	case ".pyc":
		return "executable", true
	case ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar":
		return "archive", true
	case ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp":
		return "media", true
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if bytes.IndexByte(sample, 0) >= 0 || !utf8.Valid(sample) {
		return "opaque", true
	}
	return "", false
}

func executableMagic(data []byte) bool {
	if len(data) >= 4 {
		if bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) || bytes.Equal(data[:4], []byte{0x00, 'a', 's', 'm'}) {
			return true
		}
		magic := [][4]byte{{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe}, {0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}}
		for _, candidate := range magic {
			if bytes.Equal(data[:4], candidate[:]) {
				return true
			}
		}
	}
	return len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
}

func findSkillFile(root string, rootIsFile bool) string {
	if rootIsFile {
		if strings.EqualFold(filepath.Base(root), "SKILL.md") {
			return root
		}
		return ""
	}
	for _, name := range []string{"SKILL.md", "skill.md"} {
		path := filepath.Join(root, name)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func isManifestCandidate(root, path string, rootIsFile bool) bool {
	if rootIsFile {
		return filepath.Clean(root) == filepath.Clean(path) && strings.EqualFold(filepath.Base(path), "SKILL.md")
	}
	if filepath.Clean(filepath.Dir(path)) != filepath.Clean(root) {
		return false
	}
	name := filepath.Base(path)
	return name == "SKILL.md" || name == "skill.md"
}

func parseSkillMetadata(ctx context.Context, data []byte) (model.SkillMetadata, error) {
	var metadata model.SkillMetadata
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "---" {
		return metadata, scanner.Err()
	}
	var listKey string
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return metadata, err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "---" {
			break
		}
		if strings.HasPrefix(line, "-") && listKey == "allowed-tools" {
			value := trimYAMLScalar(strings.TrimSpace(strings.TrimPrefix(line, "-")))
			if value != "" {
				metadata.AllowedTools = append(metadata.AllowedTools, value)
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = trimYAMLScalar(strings.TrimSpace(value))
		listKey = key
		switch key {
		case "name":
			metadata.Name = value
		case "description":
			metadata.Description = value
		case "license":
			metadata.License = value
		case "compatibility":
			metadata.Compatibility = value
		case "allowed-tools", "allowed_tools":
			listKey = "allowed-tools"
			if value != "" {
				value = strings.Trim(value, "[]")
				for _, item := range strings.Split(value, ",") {
					item = trimYAMLScalar(strings.TrimSpace(item))
					if item != "" {
						metadata.AllowedTools = append(metadata.AllowedTools, item)
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return metadata, err
	}
	return metadata, ctx.Err()
}

func trimYAMLScalar(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		value = value[1 : len(value)-1]
	}
	return strings.TrimSpace(value)
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.RuleID < b.RuleID
	})
}

var capabilityForCategory = map[string]struct {
	name string
	risk model.Severity
}{
	"prompt-injection":     {"prompt-manipulation", model.SeverityHigh},
	"dangerous-execution":  {"shell-execution", model.SeverityHigh},
	"credential-access":    {"credential-access", model.SeverityHigh},
	"network-exfiltration": {"network-access", model.SeverityHigh},
	"obfuscation":          {"obfuscated-execution", model.SeverityHigh},
	"persistence":          {"persistence", model.SeverityCritical},
	"binary-content":       {"embedded-binary", model.SeverityHigh},
}

func buildCapabilities(findings []model.Finding) []model.Capability {
	byName := map[string]*model.Capability{}
	order := []string{}
	for _, finding := range findings {
		spec, ok := capabilityForCategory[finding.Category]
		if !ok {
			continue
		}
		capability, exists := byName[spec.name]
		if !exists {
			capability = &model.Capability{Name: spec.name, Risk: spec.risk}
			byName[spec.name] = capability
			order = append(order, spec.name)
		}
		capability.Evidence = append(capability.Evidence, finding.Location)
	}
	sort.Strings(order)
	result := make([]model.Capability, 0, len(order))
	for _, name := range order {
		result = append(result, *byName[name])
	}
	return result
}

// Fingerprint computes a bounded, stable SHA-256 using the same default file
// selection and resource limits as Scan. Symlinks are not followed.
func Fingerprint(root string) (string, error) {
	return New(DefaultConfig()).fingerprint(context.Background(), root)
}

func (s *Scanner) fingerprint(ctx context.Context, root string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return "", err
	}
	rootIsFile := !rootInfo.IsDir()
	hash := sha256.New()
	entriesSeen := 0
	var totalSize int64
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if path != absRoot && s.skipEntry(absRoot, path, entry) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path != absRoot || rootIsFile {
			entriesSeen++
		}
		if entriesSeen > s.config.MaxFiles {
			return fmt.Errorf("package entry limit exceeded while fingerprinting (limit=%d)", s.config.MaxFiles)
		}
		rel := "."
		if path != absRoot {
			rel, err = filepath.Rel(absRoot, path)
			if err != nil {
				return err
			}
		} else if rootIsFile {
			rel = filepath.Base(absRoot)
		}
		rel = filepath.ToSlash(rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, rel+"\x00"+info.Mode().String()+"\x00")
		if entry.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_, _ = io.WriteString(hash, target+"\x00")
			return nil
		}
		if info.Mode().IsRegular() {
			if info.Size() > s.config.MaxTotalSize-totalSize {
				return fmt.Errorf("package size limit exceeded while fingerprinting (limit=%d bytes)", s.config.MaxTotalSize)
			}
			if info.Size() > s.config.MaxFileSize {
				return fmt.Errorf("file %q exceeds fingerprint size limit (%d bytes)", rel, s.config.MaxFileSize)
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			remainingTotal := s.config.MaxTotalSize - totalSize
			copyLimit := s.config.MaxFileSize
			if remainingTotal < copyLimit {
				copyLimit = remainingTotal
			}
			copied, copyErr := copyWithContext(ctx, hash, file, copyLimit)
			closeErr := file.Close()
			if copyErr != nil {
				if errors.Is(copyErr, errByteLimitExceeded) {
					return fmt.Errorf("file %q grew beyond fingerprint byte budget: %w", rel, copyErr)
				}
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			totalSize += copied
			_, _ = io.WriteString(hash, "\x00")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readFileWithContext(ctx context.Context, path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	_, copyErr := copyWithContext(ctx, &buffer, file, limit)
	closeErr := file.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return buffer.Bytes(), nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if int64(read) > limit-total {
				return total, errByteLimitExceeded
			}
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
			total += int64(written)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}
