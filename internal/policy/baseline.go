// Package policy applies auditable, source-bound local review decisions.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

const baselineSchemaVersion = "skillguardrail-baseline/v1"

type Baseline struct {
	SchemaVersion     string            `json:"schema_version"`
	SourceFingerprint string            `json:"source_fingerprint"`
	AcceptedFindings  []AcceptedFinding `json:"accepted_findings"`
}

type AcceptedFinding struct {
	Key       string `json:"finding_key"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// LoadBaseline opens a local JSON baseline. A baseline is deliberately data,
// not executable policy code, and is tied to one complete package fingerprint.
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("decode baseline JSON: %w", err)
	}
	if baseline.SchemaVersion != baselineSchemaVersion {
		return Baseline{}, fmt.Errorf("unsupported baseline schema %q (want %q)", baseline.SchemaVersion, baselineSchemaVersion)
	}
	if len(baseline.SourceFingerprint) != 64 {
		return Baseline{}, errors.New("baseline source_fingerprint must be a SHA-256 fingerprint")
	}
	for index, finding := range baseline.AcceptedFindings {
		if len(finding.Key) != 64 {
			return Baseline{}, fmt.Errorf("accepted_findings[%d].finding_key must be a SHA-256 fingerprint", index)
		}
		if strings.TrimSpace(finding.Reason) == "" {
			return Baseline{}, fmt.Errorf("accepted_findings[%d].reason is required", index)
		}
		if finding.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, finding.ExpiresAt); err != nil {
				return Baseline{}, fmt.Errorf("accepted_findings[%d].expires_at must be RFC 3339: %w", index, err)
			}
		}
	}
	return baseline, nil
}

// ApplyBaseline keeps every raw finding in the report but excludes an exact,
// still-valid, source-bound accepted finding from its verdict and score. High
// and critical findings remain non-suppressible installation blockers.
func ApplyBaseline(report *model.ScanReport, baseline Baseline, path string, now time.Time) {
	if report == nil {
		return
	}
	report.Baseline = model.BaselineStatus{
		Path:              path,
		SourceFingerprint: baseline.SourceFingerprint,
	}
	if report.Fingerprint == "" || report.Fingerprint != baseline.SourceFingerprint {
		report.Baseline.State = "source-mismatch"
		return
	}

	entries := make(map[string]AcceptedFinding, len(baseline.AcceptedFindings))
	for _, entry := range baseline.AcceptedFindings {
		entries[entry.Key] = entry
	}
	for index := range report.Findings {
		finding := &report.Findings[index]
		finding.Key = model.FindingKey(*finding)
		entry, ok := entries[finding.Key]
		if !ok {
			continue
		}
		if entry.ExpiresAt != "" {
			expires, _ := time.Parse(time.RFC3339, entry.ExpiresAt)
			if !expires.After(now) {
				report.Baseline.ExpiredEntries++
				continue
			}
		}
		if finding.Severity.Rank() >= model.SeverityHigh.Rank() {
			report.Baseline.NonSuppressibleMatches++
			continue
		}
		finding.Disposition = model.FindingAccepted
		finding.AcceptanceReason = entry.Reason
		report.Baseline.AcceptedFindings++
	}
	report.Baseline.State = "applied"
	report.Finalize()
}
