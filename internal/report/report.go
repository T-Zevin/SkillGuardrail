package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

func ParseFormat(value string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(value)))
	switch f {
	case FormatText, FormatJSON, FormatSARIF:
		return f, nil
	default:
		return "", fmt.Errorf("unknown report format %q (want text, json, or sarif)", value)
	}
}

func Write(w io.Writer, scan model.ScanReport, format Format, color bool) error {
	switch format {
	case FormatText:
		return writeText(w, scan, color)
	case FormatJSON:
		return writeJSON(w, scan)
	case FormatSARIF:
		return writeSARIF(w, scan)
	default:
		return errors.New("unsupported report format")
	}
}

func writeJSON(w io.Writer, scan model.ScanReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(scan)
}

func writeText(w io.Writer, scan model.ScanReport, color bool) error {
	paint := func(code, value string) string {
		if !color {
			return value
		}
		return "\x1b[" + code + "m" + value + "\x1b[0m"
	}
	verdictColor := "32"
	switch scan.Verdict {
	case model.VerdictReview:
		verdictColor = "33"
	case model.VerdictBlock, model.VerdictCritical:
		verdictColor = "31"
	}
	if _, err := fmt.Fprintf(w, "SkillGuardrail %s\n\n", scan.ToolVersion); err != nil {
		return err
	}
	fingerprint := scan.Fingerprint
	if fingerprint == "" {
		fingerprint = "<unavailable: incomplete scan>"
	}
	if _, err := fmt.Fprintf(w, "VERDICT  %s\nRISK     %d/100\nSOURCE   %s\nFILES    %d (%d bytes)\nHASH     %s\n",
		paint("1;"+verdictColor, strings.ToUpper(string(scan.Verdict))),
		scan.RiskScore, SafeText(scan.Source.Input), scan.FilesScanned, scan.BytesScanned, fingerprint); err != nil {
		return err
	}
	if scan.Metadata.Name != "" {
		if _, err := fmt.Fprintf(w, "SKILL    %s\n", SafeText(scan.Metadata.Name)); err != nil {
			return err
		}
	}
	if len(scan.Capabilities) > 0 {
		if _, err := fmt.Fprintln(w, "\nCAPABILITIES"); err != nil {
			return err
		}
		for _, capability := range scan.Capabilities {
			if _, err := fmt.Fprintf(w, "  %-10s %s\n", strings.ToUpper(string(capability.Risk)), SafeText(capability.Name)); err != nil {
				return err
			}
		}
	}
	if len(scan.Findings) == 0 {
		_, err := fmt.Fprintln(w, "\nNo findings. Static analysis cannot prove a skill is safe; review its requested capabilities before installation.")
		return err
	}

	findings := append([]model.Finding(nil), scan.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() == findings[j].Severity.Rank() {
			if findings[i].Location.Path == findings[j].Location.Path {
				return findings[i].Location.Line < findings[j].Location.Line
			}
			return findings[i].Location.Path < findings[j].Location.Path
		}
		return findings[i].Severity.Rank() > findings[j].Severity.Rank()
	})
	if _, err := fmt.Fprintf(w, "\nFINDINGS (%d)\n", len(findings)); err != nil {
		return err
	}
	for _, finding := range findings {
		location := SafeText(finding.Location.Path)
		if finding.Location.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Location.Line)
		}
		severityColor := "36"
		switch finding.Severity {
		case model.SeverityMedium:
			severityColor = "33"
		case model.SeverityHigh, model.SeverityCritical:
			severityColor = "31"
		}
		if _, err := fmt.Fprintf(w, "\n%s %s  %s\n  %s\n",
			paint("1;"+severityColor, "["+strings.ToUpper(string(finding.Severity))+"]"),
			SafeText(finding.RuleID), SafeText(finding.Title), location); err != nil {
			return err
		}
		if finding.Description != "" {
			if _, err := fmt.Fprintf(w, "  %s\n", SafeText(finding.Description)); err != nil {
				return err
			}
		}
		if finding.Evidence != "" {
			if _, err := fmt.Fprintf(w, "  Evidence: %s\n", SafeText(finding.Evidence)); err != nil {
				return err
			}
		}
		if finding.Recommendation != "" {
			if _, err := fmt.Fprintf(w, "  Fix: %s\n", SafeText(finding.Recommendation)); err != nil {
				return err
			}
		}
	}
	return nil
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription map[string]any `json:"shortDescription"`
	Help             map[string]any `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    map[string]any  `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation map[string]any `json:"physicalLocation"`
}

func writeSARIF(w io.Writer, scan model.ScanReport) error {
	ruleIndex := map[string]model.Finding{}
	for _, finding := range scan.Findings {
		ruleIndex[finding.RuleID] = finding
	}
	ids := make([]string, 0, len(ruleIndex))
	for id := range ruleIndex {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		finding := ruleIndex[id]
		rules = append(rules, sarifRule{
			ID: id, Name: finding.Title,
			ShortDescription: map[string]any{"text": finding.Description},
			Help:             map[string]any{"text": finding.Recommendation},
			Properties:       map[string]any{"category": finding.Category, "severity": finding.Severity},
		})
	}
	results := make([]sarifResult, 0, len(scan.Findings))
	for _, finding := range scan.Findings {
		level := "note"
		if finding.Severity == model.SeverityMedium {
			level = "warning"
		} else if finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityCritical {
			level = "error"
		}
		region := map[string]any{}
		if finding.Location.Line > 0 {
			region["startLine"] = finding.Location.Line
		}
		physical := map[string]any{
			"artifactLocation": map[string]any{"uri": filepathToSlash(finding.Location.Path)},
		}
		if len(region) > 0 {
			physical["region"] = region
		}
		results = append(results, sarifResult{
			RuleID:     finding.RuleID,
			Level:      level,
			Message:    map[string]any{"text": finding.Title + ": " + finding.Description},
			Locations:  []sarifLocation{{PhysicalLocation: physical}},
			Properties: map[string]any{"evidence": finding.Evidence, "confidence": finding.Confidence},
		})
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "SkillGuardrail", Version: scan.ToolVersion,
				InformationURI: "https://github.com/T-Zevin/SkillGuardrail", Rules: rules,
			}},
			Results:    results,
			Properties: map[string]any{"riskScore": scan.RiskScore, "verdict": scan.Verdict, "fingerprint": scan.Fingerprint},
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(log)
}

func filepathToSlash(value string) string {
	return strings.ReplaceAll(value, "\\", "/")
}

// SafeText makes attacker-controlled strings inert in terminal reports.
func SafeText(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if (unicode.IsControl(r) && r != '\t') || unicode.Is(unicode.Cf, r) {
			if r <= 0xffff {
				fmt.Fprintf(&builder, "\\u%04X", r)
			} else {
				fmt.Fprintf(&builder, "\\U%08X", r)
			}
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
