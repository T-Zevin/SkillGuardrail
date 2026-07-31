package policy

import (
	"testing"
	"time"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

func reportWithFinding(severity model.Severity) model.ScanReport {
	report := model.NewReport("test", model.SourceInfo{Input: "fixture", Kind: "local"}, "fixture")
	report.Fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	report.Findings = []model.Finding{{
		RuleID: "SG-NET-004", Title: "Outbound network access", Severity: severity,
		Category: "network-exfiltration", Location: model.Location{Path: "SKILL.md", Line: 9},
		Evidence: "curl https://example.test",
	}}
	report.Finalize()
	return report
}

func TestApplyBaselineAcceptsExactMediumFinding(t *testing.T) {
	report := reportWithFinding(model.SeverityMedium)
	baseline := Baseline{
		SchemaVersion: baselineSchemaVersion, SourceFingerprint: report.Fingerprint,
		AcceptedFindings: []AcceptedFinding{{Key: report.Findings[0].Key, Reason: "Documented public API", ExpiresAt: "2030-01-01T00:00:00Z"}},
	}
	ApplyBaseline(&report, baseline, "test.json", time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC))
	if report.Verdict != model.VerdictPass || !report.Findings[0].IsAccepted() {
		t.Fatalf("report = %#v", report)
	}
	if report.Baseline.State != "applied" || report.Baseline.AcceptedFindings != 1 {
		t.Fatalf("baseline = %#v", report.Baseline)
	}
}

func TestApplyBaselineNeverAcceptsHighFinding(t *testing.T) {
	report := reportWithFinding(model.SeverityHigh)
	baseline := Baseline{
		SchemaVersion: baselineSchemaVersion, SourceFingerprint: report.Fingerprint,
		AcceptedFindings: []AcceptedFinding{{Key: report.Findings[0].Key, Reason: "Must not work", ExpiresAt: "2030-01-01T00:00:00Z"}},
	}
	ApplyBaseline(&report, baseline, "test.json", time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC))
	if report.Verdict != model.VerdictBlock || report.Findings[0].IsAccepted() {
		t.Fatalf("high finding was suppressible: %#v", report)
	}
	if report.Baseline.NonSuppressibleMatches != 1 {
		t.Fatalf("baseline = %#v", report.Baseline)
	}
}

func TestApplyBaselineRejectsChangedPackage(t *testing.T) {
	report := reportWithFinding(model.SeverityMedium)
	baseline := Baseline{SchemaVersion: baselineSchemaVersion, SourceFingerprint: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	ApplyBaseline(&report, baseline, "test.json", time.Now())
	if report.Baseline.State != "source-mismatch" || report.Findings[0].IsAccepted() {
		t.Fatalf("baseline = %#v finding = %#v", report.Baseline, report.Findings[0])
	}
}
