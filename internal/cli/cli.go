package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/T-Zevin/SkillGuardrail/internal/install"
	"github.com/T-Zevin/SkillGuardrail/internal/model"
	"github.com/T-Zevin/SkillGuardrail/internal/progress"
	"github.com/T-Zevin/SkillGuardrail/internal/report"
	"github.com/T-Zevin/SkillGuardrail/internal/scanner"
	"github.com/T-Zevin/SkillGuardrail/internal/source"
	"github.com/T-Zevin/SkillGuardrail/internal/version"
)

const (
	ExitOK        = 0
	ExitPolicy    = 1
	ExitError     = 2
	ExitCancelled = 3
)

type progressLabels struct {
	resolve       string
	scan          string
	report        string
	policy        string
	install       string
	installed     string
	discover      string
	completed     string
	sourceFailed  string
	scanFailed    string
	reportFailed  string
	incomplete    string
	blocked       string
	waiting       string
	installFailed string
}

func labelsFor(language report.Language) progressLabels {
	if language == report.LanguageChinese {
		return progressLabels{
			resolve: "获取并隔离来源", scan: "扫描隔离包", report: "整理报告与完整性指纹",
			policy: "检查安装策略", install: "原子安装并写入收据", installed: "安装完成", discover: "发现唯一 Skill 子目录", completed: "扫描完成",
			sourceFailed: "获取来源失败", scanFailed: "扫描失败", reportFailed: "报告生成失败",
			incomplete: "扫描不完整", blocked: "扫描完成，安装被阻断", waiting: "扫描完成，等待确认",
			installFailed: "安装失败",
		}
	}
	return progressLabels{
		resolve: "Resolving and quarantining source", scan: "Scanning quarantined package", report: "Preparing report and fingerprint",
		policy: "Checking install policy", install: "Installing atomically and writing receipt", installed: "Installation complete", discover: "Found the only nested Skill", completed: "Scan complete",
		sourceFailed: "Source resolution failed", scanFailed: "Scan failed", reportFailed: "Report generation failed",
		incomplete: "Scan incomplete", blocked: "Scan complete; installation blocked", waiting: "Scan complete; awaiting confirmation",
		installFailed: "Installation failed",
	}
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeRootHelp(stdout)
		return ExitOK
	}
	switch args[0] {
	case "help", "--help", "-h":
		writeRootHelp(stdout)
		return ExitOK
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "SkillGuardrail %s\n", version.String())
		return ExitOK
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "skillguardrail: unknown command %q\n\n", args[0])
		writeRootHelp(stderr)
		return ExitError
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	formatValue := flags.String("format", "text", "report format: text, json, or sarif")
	chinese := flags.Bool("cn", false, "render the human-readable report in Simplified Chinese")
	output := flags.String("output", "", "write the report to a file")
	failOnValue := flags.String("fail-on", "medium", "return exit 1 at this severity or higher")
	timeout := flags.Duration("timeout", 10*time.Minute, "maximum fetch and scan duration")
	noColor := flags.Bool("no-color", false, "disable ANSI color")
	maxFiles := flags.Int("max-files", 5000, "maximum number of package entries")
	maxFileSize := flags.Int64("max-file-size", 2<<20, "maximum bytes scanned per file")
	maxTotalSize := flags.Int64("max-total-size", 20<<20, "maximum total bytes scanned")
	sourceDefaults := source.DefaultLimits()
	maxArchiveSize := flags.Int64("max-archive-size", sourceDefaults.MaxArchiveBytes, "maximum compressed GitHub archive bytes")
	maxExtractSize := flags.Int64("max-extract-size", sourceDefaults.MaxExtractBytes, "maximum extracted source bytes")
	maxUncompressedSize := flags.Int64("max-uncompressed-size", sourceDefaults.MaxUncompressedBytes, "maximum uncompressed archive bytes")
	maxSourceEntries := flags.Int("max-source-entries", sourceDefaults.MaxExtractFiles, "maximum entries copied from a source archive")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillguardrail scan SOURCE [options]")
		fmt.Fprint(stderr, "\nSOURCE may be a local skill directory, SKILL.md, or public GitHub repository URL.\n\n")
		flags.PrintDefaults()
	}
	args = interspersed(args, map[string]bool{"cn": true, "no-color": true})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitError
	}
	format, err := report.ParseFormat(*formatValue)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail:", report.SafeText(err.Error()))
		return ExitError
	}
	language := report.LanguageEnglish
	if *chinese {
		language = report.LanguageChinese
	}
	failOn, err := model.ParseSeverity(*failOnValue)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail:", report.SafeText(err.Error()))
		return ExitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	labels := labelsFor(language)
	showProgress := format == report.FormatText && *output == "" && progress.EnabledForTerminal(stderr)
	indicator := progress.New(stderr, showProgress)
	indicator.Start(5, labels.resolve)
	resolved, err := source.ResolveWithLimits(ctx, flags.Arg(0), source.Limits{
		MaxArchiveBytes: *maxArchiveSize, MaxExtractBytes: *maxExtractSize,
		MaxUncompressedBytes: *maxUncompressedSize, MaxExtractFiles: *maxSourceEntries,
	})
	if err != nil {
		indicator.Fail(labels.sourceFailed)
		fmt.Fprintln(stderr, "skillguardrail: source:", report.SafeText(sourceErrorMessage(err, *timeout)))
		return ExitError
	}
	defer resolved.Cleanup()
	indicator.Set(45, labels.scan)
	config := scanner.DefaultConfig()
	config.MaxFiles = *maxFiles
	config.MaxFileSize = *maxFileSize
	config.MaxTotalSize = *maxTotalSize
	engine := scanner.New(config)
	if selectedRoot, selected, selectErr := engine.SelectSkillRoot(resolved.Root); selectErr != nil {
		indicator.Fail(labels.scanFailed)
		fmt.Fprintln(stderr, "skillguardrail: discover skill root:", report.SafeText(selectErr.Error()))
		return ExitError
	} else if selected {
		resolved.Root = selectedRoot
		indicator.Set(35, labels.discover)
	}
	scan, err := engine.Scan(ctx, resolved.Root, resolved.Source, version.Version)
	if err != nil {
		indicator.Fail(labels.scanFailed)
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete:", report.SafeText(err.Error()))
		return ExitError
	}
	indicator.Set(88, labels.report)
	incomplete := scan.Fingerprint == ""
	if incomplete {
		indicator.Fail(labels.incomplete)
	} else {
		indicator.Finish(labels.completed)
	}
	w, closeOutput, err := reportWriter(*output, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: output:", report.SafeText(err.Error()))
		return ExitError
	}
	if closeOutput != nil {
		defer closeOutput()
	}
	color := format == report.FormatText && *output == "" && !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != ""
	if err := report.WriteLocalized(w, scan, format, color, language); err != nil {
		fmt.Fprintln(stderr, "skillguardrail: write report:", report.SafeText(err.Error()))
		return ExitError
	}
	if incomplete {
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete: no complete-package fingerprint was produced")
		return ExitError
	}
	if len(scan.Findings) > 0 && scan.Highest.Rank() >= failOn.Rank() {
		return ExitPolicy
	}
	return ExitOK
}

func runInstall(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "agent target: codex, claude, cursor, gemini, or openclaw")
	directory := flags.String("dir", "", "custom skill discovery directory")
	allowedValue := flags.String("allow-risk", "medium", "maximum review severity: info, low, or medium (block/critical are never allowed)")
	chinese := flags.Bool("cn", false, "render the human-readable report in Simplified Chinese")
	timeout := flags.Duration("timeout", 15*time.Minute, "maximum fetch, scan, and install duration")
	yes := flags.Bool("yes", false, "confirm the non-interactive installation")
	replace := flags.Bool("replace", false, "back up and atomically replace an existing skill")
	stateDir := flags.String("state-dir", "", "private directory for authoritative receipts (advanced)")
	noColor := flags.Bool("no-color", false, "disable ANSI color")
	sourceDefaults := source.DefaultLimits()
	maxArchiveSize := flags.Int64("max-archive-size", sourceDefaults.MaxArchiveBytes, "maximum compressed GitHub archive bytes")
	maxExtractSize := flags.Int64("max-extract-size", sourceDefaults.MaxExtractBytes, "maximum extracted source bytes")
	maxUncompressedSize := flags.Int64("max-uncompressed-size", sourceDefaults.MaxUncompressedBytes, "maximum uncompressed archive bytes")
	maxSourceEntries := flags.Int("max-source-entries", sourceDefaults.MaxExtractFiles, "maximum entries copied from a source archive")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillguardrail install SOURCE --target AGENT --yes [options]")
		fmt.Fprint(stderr, "\nThe source is scanned in quarantine before any agent directory is modified.\n\n")
		flags.PrintDefaults()
	}
	args = interspersed(args, map[string]bool{"cn": true, "yes": true, "replace": true, "no-color": true})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitError
	}
	allowed, err := model.ParseSeverity(*allowedValue)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail:", report.SafeText(err.Error()))
		return ExitError
	}
	language := report.LanguageEnglish
	if *chinese {
		language = report.LanguageChinese
	}
	if allowed.Rank() > model.SeverityMedium.Rank() {
		fmt.Fprintln(stderr, "skillguardrail: --allow-risk may be info, low, or medium; block verdicts require a future rule-specific policy")
		return ExitError
	}
	if *directory == "" && *target == "" {
		fmt.Fprintln(stderr, "skillguardrail: install requires --target or --dir")
		return ExitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	labels := labelsFor(language)
	showProgress := progress.EnabledForTerminal(stderr)
	indicator := progress.New(stderr, showProgress)
	indicator.Start(5, labels.resolve)
	resolved, err := source.ResolveWithLimits(ctx, flags.Arg(0), source.Limits{
		MaxArchiveBytes: *maxArchiveSize, MaxExtractBytes: *maxExtractSize,
		MaxUncompressedBytes: *maxUncompressedSize, MaxExtractFiles: *maxSourceEntries,
	})
	if err != nil {
		indicator.Fail(labels.sourceFailed)
		fmt.Fprintln(stderr, "skillguardrail: source:", report.SafeText(sourceErrorMessage(err, *timeout)))
		return ExitError
	}
	defer resolved.Cleanup()
	engine := scanner.New(scanner.DefaultConfig())
	if selectedRoot, selected, selectErr := engine.SelectSkillRoot(resolved.Root); selectErr != nil {
		indicator.Fail(labels.scanFailed)
		fmt.Fprintln(stderr, "skillguardrail: discover skill root:", report.SafeText(selectErr.Error()))
		return ExitError
	} else if selected {
		resolved.Root = selectedRoot
		indicator.Set(35, labels.discover)
	}
	indicator.Set(45, labels.scan)
	scan, err := engine.Scan(ctx, resolved.Root, resolved.Source, version.Version)
	if err != nil {
		indicator.Fail(labels.scanFailed)
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete:", report.SafeText(err.Error()))
		return ExitError
	}
	indicator.Set(78, labels.report)
	color := !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != ""
	if err := report.WriteLocalized(stdout, scan, report.FormatText, color, language); err != nil {
		indicator.Fail(labels.reportFailed)
		fmt.Fprintln(stderr, "skillguardrail: write report:", report.SafeText(err.Error()))
		return ExitError
	}
	indicator.Set(88, labels.policy)
	if scan.Fingerprint == "" {
		indicator.Fail(labels.incomplete)
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete: no complete-package fingerprint was produced; no files changed")
		return ExitError
	}
	if err := scan.CheckInstallPolicy(allowed); err != nil {
		indicator.Finish(labels.blocked)
		fmt.Fprintf(stderr, "skillguardrail: installation denied: %s\n", report.SafeText(err.Error()))
		return ExitPolicy
	}
	if !*yes {
		indicator.Finish(labels.waiting)
		fmt.Fprintln(stderr, "skillguardrail: no files changed; review the report and rerun with --yes to install")
		return ExitCancelled
	}
	indicator.Set(92, labels.install)
	result, err := install.Install(ctx, resolved.Root, scan, install.Options{
		Target: *target, Directory: *directory, AllowedRisk: allowed,
		Replace: *replace, ToolVersion: version.Version, StateDir: *stateDir,
	})
	if err != nil {
		indicator.Fail(labels.installFailed)
		if strings.Contains(err.Error(), "policy denies") || strings.Contains(err.Error(), "never be overridden") || strings.Contains(err.Error(), "violates policy") || strings.Contains(err.Error(), "non-overridable") {
			fmt.Fprintln(stderr, "skillguardrail: installation denied:", report.SafeText(err.Error()))
			return ExitPolicy
		}
		fmt.Fprintln(stderr, "skillguardrail: install:", report.SafeText(err.Error()))
		return ExitError
	}
	indicator.Finish(labels.installed)
	fmt.Fprintf(stdout, "\nINSTALLED %s\nRECEIPT   %s\nMANIFEST  %s\n", report.SafeText(result.Path), report.SafeText(result.ReceiptPath), report.SafeText(filepath.Join(result.Path, install.LockFileName)))
	if result.BackupPath != "" {
		fmt.Fprintf(stdout, "BACKUP    %s\n", report.SafeText(result.BackupPath))
	}
	return ExitOK
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "agent target when verifying by skill name")
	directory := flags.String("dir", "", "custom skill discovery directory")
	formatValue := flags.String("format", "text", "report format: text or json")
	stateDir := flags.String("state-dir", "", "private directory containing authoritative receipts (advanced)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillguardrail verify PATH\n   or: skillguardrail verify NAME --target AGENT")
		fmt.Fprint(stderr, "\nVerification compares the installed tree with its path-bound external authoritative receipt.\n\n")
		flags.PrintDefaults()
	}
	args = interspersed(args, nil)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitError
	}
	if *formatValue != "text" && *formatValue != "json" {
		fmt.Fprintln(stderr, "skillguardrail: verify format must be text or json")
		return ExitError
	}
	path, err := install.ResolveVerificationPath(flags.Arg(0), *target, *directory)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: verify path:", report.SafeText(err.Error()))
		return ExitError
	}
	verification, err := install.VerifyWithState(path, *stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: verify:", report.SafeText(err.Error()))
		return ExitError
	}
	if *formatValue == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(verification); err != nil {
			fmt.Fprintln(stderr, "skillguardrail: write verification:", report.SafeText(err.Error()))
			return ExitError
		}
	} else if verification.Valid {
		fmt.Fprintf(stdout, "VERIFIED  %s\nHASH      %s\nSOURCE    %s\n", report.SafeText(verification.Path), verification.ActualFingerprint, report.SafeText(verification.Lock.Source.Input))
	} else {
		fmt.Fprintf(stdout, "CHANGED   %s\nEXPECTED  %s\nACTUAL    %s\n", report.SafeText(verification.Path), verification.ExpectedFingerprint, verification.ActualFingerprint)
		for _, changed := range verification.ChangedFiles {
			fmt.Fprintf(stdout, "  - %s\n", report.SafeText(changed))
		}
	}
	if !verification.Valid {
		return ExitPolicy
	}
	return ExitOK
}

func reportWriter(path string, fallback io.Writer) (io.Writer, func() error, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return fallback, nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}

func interspersed(args []string, boolFlags map[string]bool) []string {
	flags := []string{}
	positionals := []string{}
	terminated := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			terminated = true
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			name := strings.TrimLeft(arg, "-")
			if before, _, ok := strings.Cut(name, "="); ok {
				name = before
				continue
			}
			if boolFlags != nil && boolFlags[name] {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if terminated {
		result := append(flags, "--")
		return append(result, positionals...)
	}
	return append(flags, positionals...)
}

func sourceErrorMessage(err error, timeout time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("%s; increase --timeout (current limit %s)", err, timeout)
	}
	return err.Error()
}

func writeRootHelp(w io.Writer) {
	fmt.Fprintln(w, `SkillGuardrail — pre-install security guardrails for Agent Skills

Usage:
  skillguardrail <command> [options]

Commands:
  scan       Inspect a local or public GitHub skill without executing it
  install    Scan, approve, receipt, and atomically install a skill
  verify     Detect changes to a SkillGuardrail-managed installation
  version    Print build version information

Run "skillguardrail <command> --help" for command-specific options.`)
}
