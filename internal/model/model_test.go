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
