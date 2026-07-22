package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// Language controls human-readable text reports. Machine-readable JSON and
// SARIF reports intentionally keep their stable English schema and fields.
type Language string

const (
	LanguageEnglish Language = "en"
	LanguageChinese Language = "zh-CN"
)

func ParseLanguage(value string) (Language, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "en", "en-us", "english":
		return LanguageEnglish, nil
	case "zh", "zh-cn", "zh-hans", "简体中文", "中文":
		return LanguageChinese, nil
	default:
		return "", fmt.Errorf("unknown language %q (want en or zh-CN)", value)
	}
}

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
	return WriteLocalized(w, scan, format, color, LanguageEnglish)
}

// WriteLocalized writes a report using the requested human-readable language.
// JSON and SARIF remain language-neutral so downstream automation is stable.
func WriteLocalized(w io.Writer, scan model.ScanReport, format Format, color bool, language Language) error {
	switch format {
	case FormatText:
		return writeText(w, scan, color, language)
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

func writeText(w io.Writer, scan model.ScanReport, color bool, language Language) error {
	if language != LanguageChinese {
		language = LanguageEnglish
	}
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
	t := textFor(language)
	if _, err := fmt.Fprintf(w, "SkillGuardrail %s\n\n", scan.ToolVersion); err != nil {
		return err
	}
	fingerprint := scan.Fingerprint
	if fingerprint == "" {
		fingerprint = "<unavailable: incomplete scan>"
	}
	// Keep a compact status line for shell users while the tables below make
	// the report easier to scan visually.
	verdictLabel := localizedVerdict(scan.Verdict, language)
	statusEmoji := verdictEmoji(scan.Verdict)
	if language == LanguageChinese {
		if _, err := fmt.Fprintf(w, "🛡️ 判定  %s %s  |  已知信号 %d/100\n", paint("1;"+verdictColor, verdictLabel), statusEmoji, scan.RiskScore); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(w, "🛡️ VERDICT  %s %s  |  KNOWN SIGNALS %d/100\n",
		paint("1;"+verdictColor, verdictLabel), statusEmoji, scan.RiskScore); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n%s\n", safetyBoundary(language, scan)); err != nil {
		return err
	}
	coverage := fmt.Sprintf("%d/%d", scan.FilesAnalyzed, scan.FilesScanned)
	if scan.UninspectedFiles > 0 {
		if language == LanguageChinese {
			coverage += fmt.Sprintf("（%d 个文件未进行内容分析）", scan.UninspectedFiles)
		} else {
			coverage += fmt.Sprintf(" (%d uninspected)", scan.UninspectedFiles)
		}
	}
	rows := [][]string{
		{t.summaryVerdict, verdictLabel},
		{t.summaryRisk, fmt.Sprintf("%d/100", scan.RiskScore)},
		{t.summaryScore, scoreBar(scan.RiskScore)},
		{t.summarySafetyClaim, safetyClaim(language)},
		{t.summaryHighest, localizedSeverity(scan.Highest, language)},
		{t.summarySource, truncate(SafeText(scan.Source.Input), 96)},
		{t.summaryFiles, fmt.Sprintf("%d (%s)", scan.FilesScanned, formatBytes(scan.BytesScanned))},
		{t.summaryCoverage, coverage},
		{t.summaryFingerprint, fingerprint},
	}
	if scan.Metadata.Name != "" {
		rows = append(rows, []string{t.summarySkill, SafeText(scan.Metadata.Name)})
	}
	if err := writeTable(w, t.summaryTitle, []string{t.field, t.value}, rows); err != nil {
		return err
	}
	if err := writeTable(w, t.verdictLevelsTitle, []string{t.level, t.meaning}, verdictRows(language)); err != nil {
		return err
	}
	if err := writeArchitecture(w, scan.Root, t.architectureTitle, scan.Source.Input); err != nil {
		return err
	}
	if len(scan.Capabilities) > 0 {
		capRows := make([][]string, 0, len(scan.Capabilities))
		for _, capability := range scan.Capabilities {
			capRows = append(capRows, []string{localizedSeverity(capability.Risk, language), SafeText(capability.Name)})
		}
		if err := writeTable(w, t.capabilitiesTitle, []string{t.severity, t.capability}, capRows); err != nil {
			return err
		}
	}
	if len(scan.Findings) == 0 {
		_, err := fmt.Fprintf(w, "\n%s\n", t.noFindings)
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
	findingRows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		location := SafeText(finding.Location.Path)
		if finding.Location.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Location.Line)
		}
		localized := localizeFinding(finding, language)
		findingRows = append(findingRows, []string{
			localizedSeverity(finding.Severity, language), SafeText(finding.RuleID), truncate(location, 64), truncate(localized.Title, 72),
		})
	}
	if err := writeTable(w, fmt.Sprintf("%s (%d)", t.findingsTitle, len(findings)), []string{t.severity, t.rule, t.location, t.title}, findingRows); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n%s\n", t.detailsTitle); err != nil {
		return err
	}
	for index, finding := range findings {
		location := SafeText(finding.Location.Path)
		if finding.Location.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Location.Line)
		}
		localized := localizeFinding(finding, language)
		severityColor := "36"
		switch finding.Severity {
		case model.SeverityMedium:
			severityColor = "33"
		case model.SeverityHigh, model.SeverityCritical:
			severityColor = "31"
		}
		if _, err := fmt.Fprintf(w, "\n%d. %s %s  %s\n  %s\n",
			index+1,
			paint("1;"+severityColor, "["+localizedSeverity(finding.Severity, language)+"]"),
			SafeText(finding.RuleID), SafeText(localized.Title), location); err != nil {
			return err
		}
		if localized.Description != "" {
			if _, err := fmt.Fprintf(w, "  %s\n", SafeText(localized.Description)); err != nil {
				return err
			}
		}
		if finding.Evidence != "" {
			if _, err := fmt.Fprintf(w, "  %s: %s\n", t.evidence, SafeText(finding.Evidence)); err != nil {
				return err
			}
		}
		if localized.Recommendation != "" {
			if _, err := fmt.Fprintf(w, "  %s: %s\n", t.fix, SafeText(localized.Recommendation)); err != nil {
				return err
			}
		}
	}
	return nil
}

type reportText struct {
	summaryTitle, field, value, summaryVerdict, summaryRisk, summaryScore, summarySafetyClaim, summaryHighest, summarySource, summaryFiles, summaryCoverage, summaryFingerprint, summarySkill string
	verdictLevelsTitle, level, meaning, architectureTitle, capabilitiesTitle, severity, capability, findingsTitle, rule, location, title, detailsTitle, evidence, fix, noFindings             string
}

func textFor(language Language) reportText {
	if language == LanguageChinese {
		return reportText{
			summaryTitle: "📊 扫描摘要", field: "字段", value: "值", summaryVerdict: "判定", summaryRisk: "已知信号", summaryScore: "信号条", summarySafetyClaim: "安全结论", summaryHighest: "最高级别", summarySource: "来源", summaryFiles: "文件", summaryCoverage: "内容覆盖", summaryFingerprint: "指纹", summarySkill: "Skill",
			verdictLevelsTitle: "🧭 判定等级", level: "等级", meaning: "含义",
			architectureTitle: "🌳 项目结构",
			capabilitiesTitle: "🧩 能力清单", severity: "级别", capability: "能力", findingsTitle: "🔎 发现", rule: "规则", location: "位置", title: "标题", detailsTitle: "发现详情", evidence: "证据", fix: "建议",
			noFindings: "未发现已知规则命中。这个结果不是零风险证明，请仍然复核来源、能力和未分析内容。",
		}
	}
	return reportText{
		summaryTitle: "📊 SUMMARY", field: "FIELD", value: "VALUE", summaryVerdict: "VERDICT", summaryRisk: "KNOWN SIGNALS", summaryScore: "SIGNAL BAR", summarySafetyClaim: "SAFETY CLAIM", summaryHighest: "HIGHEST", summarySource: "SOURCE", summaryFiles: "FILES", summaryCoverage: "CONTENT COVERAGE", summaryFingerprint: "FINGERPRINT", summarySkill: "SKILL",
		verdictLevelsTitle: "🧭 VERDICT LEVELS", level: "LEVEL", meaning: "MEANING",
		architectureTitle: "🌳 PROJECT ARCHITECTURE",
		capabilitiesTitle: "🧩 CAPABILITIES", severity: "SEVERITY", capability: "CAPABILITY", findingsTitle: "🔎 FINDINGS", rule: "RULE", location: "LOCATION", title: "TITLE", detailsTitle: "DETAILS", evidence: "Evidence", fix: "Fix",
		noFindings: "No known rule matches. This is not a zero-risk claim; review provenance, capabilities, and uninspected content before installation.",
	}
}

func verdictRows(language Language) [][]string {
	if language == LanguageChinese {
		return [][]string{
			{"通过", "未发现已知阻断信号；不代表零风险，仍应复核 Skill 的能力和来源。"},
			{"需复核", "存在中风险信号，需要人工确认后再决定。"},
			{"阻断", "存在高风险信号或风险阈值已达到，默认拒绝安装。"},
			{"严重", "发现严重行为链或完整性问题，始终拒绝安装。"},
		}
	}
	return [][]string{
		{"PASS", "No known blocking signal detected; this is not a zero-risk claim. Review capabilities and provenance."},
		{"REVIEW", "Medium-risk signal requires a human decision."},
		{"BLOCK", "High-risk signal or threshold reached; installation is refused by default."},
		{"CRITICAL", "Critical behavior chain or integrity failure; installation is always refused."},
	}
}

func writeArchitecture(w io.Writer, root, title, input string) error {
	lines := architectureTree(root, 80, 4, architectureDisplayName(input, root))
	if len(lines) <= 1 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\n%s\n", title); err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
			return err
		}
	}
	return nil
}

func architectureTree(root string, maxEntries, maxDepth int, displayName string) []string {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || maxEntries < 1 {
		return nil
	}
	name := displayName
	if name == "" {
		name = filepath.Base(filepath.Clean(root))
	}
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "project"
	}
	lines := []string{SafeText(name) + "/"}
	omitted := 0
	var walk func(string, string, int)
	walk = func(dir, prefix string, depth int) {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			return
		}
		for index, entry := range entries {
			if entry.Name() == ".git" {
				continue
			}
			if len(lines) >= maxEntries {
				omitted++
				continue
			}
			last := index == len(entries)-1
			branch := "├── "
			nextPrefix := prefix + "│   "
			if last {
				branch = "└── "
				nextPrefix = prefix + "    "
			}
			name := SafeText(entry.Name())
			isDir := entry.IsDir()
			if isDir {
				name += "/"
			}
			lines = append(lines, prefix+branch+name)
			if isDir && depth < maxDepth {
				walk(filepath.Join(dir, entry.Name()), nextPrefix, depth+1)
			}
		}
	}
	walk(root, "", 1)
	if omitted > 0 {
		lines = append(lines, fmt.Sprintf("└── … (%d more entries)", omitted))
	}
	return lines
}

func architectureDisplayName(input, root string) string {
	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(strings.TrimSuffix(input, "/")), ".git"), "\\")
	if strings.EqualFold(name, "SKILL.md") || name == "." || name == "/" || name == "" {
		name = filepath.Base(filepath.Clean(root))
	}
	return SafeText(name)
}

func formatBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	if value < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(value)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(value)/(1024*1024))
}

func localizedVerdict(verdict model.Verdict, language Language) string {
	if language == LanguageChinese {
		switch verdict {
		case model.VerdictPass:
			return "通过"
		case model.VerdictReview:
			return "需复核"
		case model.VerdictBlock:
			return "阻断"
		case model.VerdictCritical:
			return "严重"
		}
	}
	return strings.ToUpper(string(verdict))
}

func localizedSeverity(severity model.Severity, language Language) string {
	if language == LanguageChinese {
		switch severity {
		case model.SeverityInfo:
			return "信息"
		case model.SeverityLow:
			return "低"
		case model.SeverityMedium:
			return "中"
		case model.SeverityHigh:
			return "高"
		case model.SeverityCritical:
			return "严重"
		}
	}
	return strings.ToUpper(string(severity))
}

func safetyClaim(language Language) string {
	if language == LanguageChinese {
		return "未证明安全（静态规则扫描）"
	}
	return "NOT PROVEN SAFE (STATIC RULE SCAN)"
}

func safetyBoundary(language Language, scan model.ScanReport) string {
	if language == LanguageChinese {
		message := "⚠️ 安全边界：评分只代表已发现的不同规则信号，不是风险概率；“通过”不等于零风险或安全证明。"
		if scan.UninspectedFiles > 0 {
			message += fmt.Sprintf("仍有 %d 个文件未进行完整内容分析。", scan.UninspectedFiles)
		}
		return message
	}
	message := "⚠️ SAFETY BOUNDARY: the score counts distinct detected rule signals, not the probability of compromise; PASS is not zero risk or a safety certificate."
	if scan.UninspectedFiles > 0 {
		message += fmt.Sprintf(" %d file(s) did not receive complete content analysis.", scan.UninspectedFiles)
	}
	return message
}

func scoreBar(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	const width = 20
	filled := (score*width + 99) / 100
	if score == 0 {
		filled = 0
	}
	return fmt.Sprintf("%s%s %d/100", strings.Repeat("█", filled), strings.Repeat("░", width-filled), score)
}

func verdictEmoji(verdict model.Verdict) string {
	switch verdict {
	case model.VerdictPass:
		return "✅"
	case model.VerdictReview:
		return "⚠️"
	case model.VerdictBlock:
		return "⛔"
	case model.VerdictCritical:
		return "🚨"
	default:
		return "🔎"
	}
}

func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max-1]) + "…"
}

func writeTable(w io.Writer, title string, headers []string, rows [][]string) error {
	if _, err := fmt.Fprintf(w, "\n%s\n", title); err != nil {
		return err
	}
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = textWidth(header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && textWidth(cell) > widths[i] {
				widths[i] = textWidth(cell)
			}
		}
	}
	border := func() string {
		parts := make([]string, len(widths))
		for i, width := range widths {
			parts[i] = strings.Repeat("-", width+2)
		}
		return "+" + strings.Join(parts, "+") + "+\n"
	}
	row := func(values []string) string {
		cells := make([]string, len(widths))
		for i, width := range widths {
			value := ""
			if i < len(values) {
				value = values[i]
			}
			cells[i] = " " + value + strings.Repeat(" ", width-textWidth(value)+1)
		}
		return "|" + strings.Join(cells, "|") + "|\n"
	}
	if _, err := io.WriteString(w, border()); err != nil {
		return err
	}
	if _, err := io.WriteString(w, row(headers)); err != nil {
		return err
	}
	if _, err := io.WriteString(w, border()); err != nil {
		return err
	}
	for _, values := range rows {
		if _, err := io.WriteString(w, row(values)); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, border())
	return err
}

// textWidth is a small terminal-width approximation for table alignment. It
// treats common East Asian wide characters as two columns without adding a
// dependency just for presentation formatting.
func textWidth(value string) int {
	width := 0
	for _, r := range value {
		if unicode.In(r, unicode.Han, unicode.Hangul, unicode.Hiragana, unicode.Katakana) {
			width += 2
		} else {
			width++
		}
	}
	return width
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
			Properties: map[string]any{"riskScore": scan.RiskScore, "riskScoreMeaning": model.RiskScoreMeaningDetectedSignals, "safetyClaim": safetyClaim(LanguageEnglish), "verdict": scan.Verdict, "fingerprint": scan.Fingerprint},
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
