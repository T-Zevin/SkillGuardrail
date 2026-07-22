package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

func sampleReport() model.ScanReport {
	r := model.NewReport("test", model.SourceInfo{Input: "fixture", Kind: "local"}, "/tmp/fixture")
	r.FilesScanned = 1
	r.BytesScanned = 42
	r.Fingerprint = "abc123"
	r.Findings = append(r.Findings, model.Finding{
		RuleID: "SG-EXEC-002", Title: "Destructive filesystem command", Description: "The command can recursively or forcefully destroy files or storage.",
		Severity: model.SeverityHigh, Category: "command-execution",
		Location: model.Location{Path: "SKILL.md", Line: 7}, Evidence: "rm -rf", Recommendation: "Remove destructive commands.",
	})
	r.Finalize()
	return r
}

func TestTextReport(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, sampleReport(), FormatText, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"VERDICT  BLOCK", "SG-EXEC-002", "SKILL.md:7", "SUMMARY", "FINDINGS"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report missing %q:\n%s", want, out.String())
		}
	}
}

func TestChineseTextReport(t *testing.T) {
	var out bytes.Buffer
	if err := WriteLocalized(&out, sampleReport(), FormatText, false, LanguageChinese); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"判定  阻断", "扫描摘要", "判定", "发现", "高", "破坏性文件系统命令", "命令可能递归或强制删除文件或存储。", "建议"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("Chinese report missing %q:\n%s", want, out.String())
		}
	}
}

func TestParseLanguage(t *testing.T) {
	for _, value := range []string{"en", "zh", "zh-CN", "中文"} {
		if _, err := ParseLanguage(value); err != nil {
			t.Fatalf("ParseLanguage(%q): %v", value, err)
		}
	}
	if _, err := ParseLanguage("fr"); err == nil {
		t.Fatal("ParseLanguage accepted unsupported language")
	}
}

func TestJSONAndSARIFAreValid(t *testing.T) {
	for _, format := range []Format{FormatJSON, FormatSARIF} {
		var out bytes.Buffer
		if err := Write(&out, sampleReport(), format, false); err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatalf("%s output is not JSON: %v", format, err)
		}
	}
}

func TestSafeTextEscapesTerminalControls(t *testing.T) {
	got := SafeText("safe\x1b[31m\nnext\u202ehidden\u200b")
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\n') {
		t.Fatalf("control characters were not escaped: %q", got)
	}
	if !strings.Contains(got, `\u001B`) || !strings.Contains(got, `\u000A`) || !strings.Contains(got, `\u202E`) || !strings.Contains(got, `\u200B`) {
		t.Fatalf("escaped form missing: %q", got)
	}
}
