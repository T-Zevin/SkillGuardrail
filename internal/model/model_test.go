package model

import (
	"strings"
	"testing"
)

func TestCheckInstallPolicy(t *testing.T) {
	validFingerprint := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		report  ScanReport
		allowed Severity
		wantErr bool
	}{
		{"pass", ScanReport{Fingerprint: validFingerprint, Highest: SeverityInfo, Verdict: VerdictPass}, SeverityMedium, false},
		{"review", ScanReport{Fingerprint: validFingerprint, Highest: SeverityMedium, Verdict: VerdictReview}, SeverityMedium, false},
		{"block", ScanReport{Fingerprint: validFingerprint, Highest: SeverityMedium, Verdict: VerdictBlock}, SeverityMedium, true},
		{"critical", ScanReport{Fingerprint: validFingerprint, Highest: SeverityCritical, Verdict: VerdictCritical}, SeverityMedium, true},
		{"missing fingerprint", ScanReport{Highest: SeverityInfo, Verdict: VerdictPass}, SeverityMedium, true},
		{"severity above allowance", ScanReport{Fingerprint: validFingerprint, Highest: SeverityMedium, Verdict: VerdictReview}, SeverityLow, true},
		{"invalid broad allowance", ScanReport{Fingerprint: validFingerprint, Highest: SeverityInfo, Verdict: VerdictPass}, SeverityHigh, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.report.CheckInstallPolicy(test.allowed)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestFinalizeKeepsSafetyClaimExplicit(t *testing.T) {
	report := NewReport("test", SourceInfo{Kind: "local"}, "/tmp/skill")
	report.Finalize()
	if report.RiskScore != 0 {
		t.Fatalf("clean report signal score = %d, want 0 detected signals", report.RiskScore)
	}
	if report.SafetyClaim != SafetyClaimNotProvenSafe {
		t.Fatalf("safety claim = %q, want %q", report.SafetyClaim, SafetyClaimNotProvenSafe)
	}
}

func TestFinalizeDeduplicatesRepeatedRuleSignals(t *testing.T) {
	report := NewReport("test", SourceInfo{Kind: "local"}, "/tmp/skill")
	report.Findings = []Finding{
		{RuleID: "SG-NET-004", Severity: SeverityMedium},
		{RuleID: "SG-NET-004", Severity: SeverityMedium},
		{RuleID: "SG-CRED-002", Severity: SeverityMedium},
	}
	report.Finalize()
	if report.RiskScore != 16 {
		t.Fatalf("deduplicated risk score = %d, want 16", report.RiskScore)
	}
	if report.Verdict != VerdictReview {
		t.Fatalf("verdict = %s, want review", report.Verdict)
	}
}
