package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func ParseSeverity(value string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(value)))
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return s, nil
	default:
		return "", fmt.Errorf("unknown severity %q (want info, low, medium, high, or critical)", value)
	}
}

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

type Verdict string

const (
	VerdictPass     Verdict = "pass"
	VerdictReview   Verdict = "review"
	VerdictBlock    Verdict = "block"
	VerdictCritical Verdict = "critical"
)

type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Finding struct {
	RuleID         string   `json:"rule_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Confidence     string   `json:"confidence,omitempty"`
	Location       Location `json:"location"`
	Evidence       string   `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type Capability struct {
	Name     string     `json:"name"`
	Risk     Severity   `json:"risk"`
	Evidence []Location `json:"evidence,omitempty"`
}

type SkillMetadata struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	License       string   `json:"license,omitempty"`
	Compatibility string   `json:"compatibility,omitempty"`
	AllowedTools  []string `json:"allowed_tools,omitempty"`
}

type SourceInfo struct {
	Input         string `json:"input"`
	Kind          string `json:"kind"`
	Resolved      string `json:"resolved,omitempty"`
	Repository    string `json:"repository,omitempty"`
	Commit        string `json:"commit,omitempty"`
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
}

type ScanReport struct {
	SchemaVersion    string         `json:"schema_version"`
	Tool             string         `json:"tool"`
	ToolVersion      string         `json:"tool_version"`
	ScannedAt        time.Time      `json:"scanned_at"`
	Source           SourceInfo     `json:"source"`
	Root             string         `json:"root"`
	Metadata         SkillMetadata  `json:"metadata"`
	FilesScanned     int            `json:"files_scanned"`
	FilesAnalyzed    int            `json:"files_analyzed"`
	UninspectedFiles int            `json:"uninspected_files,omitempty"`
	BytesScanned     int64          `json:"bytes_scanned"`
	Fingerprint      string         `json:"fingerprint"`
	RiskScore        int            `json:"risk_score"`
	Highest          Severity       `json:"highest_severity"`
	Verdict          Verdict        `json:"verdict"`
	Findings         []Finding      `json:"findings"`
	Capabilities     []Capability   `json:"capabilities"`
	Stats            map[string]int `json:"stats"`
}

func NewReport(version string, source SourceInfo, root string) ScanReport {
	return ScanReport{
		SchemaVersion: SchemaVersion,
		Tool:          "SkillGuardrail",
		ToolVersion:   version,
		ScannedAt:     time.Now().UTC(),
		Source:        source,
		Root:          root,
		Highest:       SeverityInfo,
		Verdict:       VerdictPass,
		Findings:      []Finding{},
		Capabilities:  []Capability{},
		Stats:         map[string]int{},
	}
}

func (r *ScanReport) Finalize() {
	weights := map[Severity]int{
		SeverityInfo: 0, SeverityLow: 2, SeverityMedium: 8,
		SeverityHigh: 20, SeverityCritical: 40,
	}
	r.RiskScore = 0
	r.Highest = SeverityInfo
	r.Stats = map[string]int{}
	for _, finding := range r.Findings {
		r.RiskScore += weights[finding.Severity]
		r.Stats[string(finding.Severity)]++
		if finding.Severity.Rank() > r.Highest.Rank() {
			r.Highest = finding.Severity
		}
	}
	if r.RiskScore > 100 {
		r.RiskScore = 100
	}
	switch {
	case r.Highest == SeverityCritical:
		r.Verdict = VerdictCritical
	case r.Highest == SeverityHigh || r.RiskScore >= 50:
		r.Verdict = VerdictBlock
	case r.Highest == SeverityMedium || r.RiskScore >= 15:
		r.Verdict = VerdictReview
	default:
		r.Verdict = VerdictPass
	}
}

// CheckInstallPolicy is the single fail-closed installation decision used for
// both the reviewed source and the staged copy. Block and critical verdicts,
// missing fingerprints, and severities above the explicit review allowance
// cannot cross the agent discovery boundary.
func (r ScanReport) CheckInstallPolicy(maxReview Severity) error {
	if maxReview == "" {
		maxReview = SeverityMedium
	}
	if maxReview.Rank() > SeverityMedium.Rank() {
		return errors.New("installation review allowance may not exceed medium")
	}
	if r.Fingerprint == "" || !sha256Pattern.MatchString(r.Fingerprint) {
		return errors.New("scan has no valid complete-package fingerprint")
	}
	if r.Verdict == VerdictCritical || r.Verdict == VerdictBlock {
		return fmt.Errorf("%s verdict is non-overridable for installation", r.Verdict)
	}
	if r.Highest.Rank() > maxReview.Rank() {
		return fmt.Errorf("%s finding exceeds the permitted review severity %s", r.Highest, maxReview)
	}
	return nil
}

func ShortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:8])
}

type LockFile struct {
	SchemaVersion string       `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	RulePack      string       `json:"rule_pack"`
	InstalledAt   time.Time    `json:"installed_at"`
	InstalledPath string       `json:"installed_path"`
	Source        SourceInfo   `json:"source"`
	SkillName     string       `json:"skill_name"`
	Fingerprint   string       `json:"fingerprint"`
	RiskScore     int          `json:"risk_score"`
	Verdict       Verdict      `json:"verdict"`
	Capabilities  []Capability `json:"capabilities"`
	Findings      []Finding    `json:"findings"`
	Files         []FileDigest `json:"files"`
}

type FileDigest struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
