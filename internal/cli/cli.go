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
	output := flags.String("output", "", "write the report to a file")
	failOnValue := flags.String("fail-on", "medium", "return exit 1 at this severity or higher")
	timeout := flags.Duration("timeout", 45*time.Second, "maximum fetch and scan duration")
	noColor := flags.Bool("no-color", false, "disable ANSI color")
	maxFiles := flags.Int("max-files", 5000, "maximum number of package entries")
	maxFileSize := flags.Int64("max-file-size", 2<<20, "maximum bytes scanned per file")
	maxTotalSize := flags.Int64("max-total-size", 20<<20, "maximum total bytes scanned")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillguardrail scan SOURCE [options]")
		fmt.Fprint(stderr, "\nSOURCE may be a local skill directory, SKILL.md, or public GitHub repository URL.\n\n")
		flags.PrintDefaults()
	}
	args = interspersed(args, map[string]bool{"no-color": true})
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
	failOn, err := model.ParseSeverity(*failOnValue)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail:", report.SafeText(err.Error()))
		return ExitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	resolved, err := source.Resolve(ctx, flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: source:", report.SafeText(err.Error()))
		return ExitError
	}
	defer resolved.Cleanup()
	config := scanner.DefaultConfig()
	config.MaxFiles = *maxFiles
	config.MaxFileSize = *maxFileSize
	config.MaxTotalSize = *maxTotalSize
	scan, err := scanner.New(config).Scan(ctx, resolved.Root, resolved.Source, version.Version)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete:", report.SafeText(err.Error()))
		return ExitError
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
	if err := report.Write(w, scan, format, color); err != nil {
		fmt.Fprintln(stderr, "skillguardrail: write report:", report.SafeText(err.Error()))
		return ExitError
	}
	if scan.Fingerprint == "" {
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
	timeout := flags.Duration("timeout", 60*time.Second, "maximum fetch, scan, and install duration")
	yes := flags.Bool("yes", false, "confirm the non-interactive installation")
	replace := flags.Bool("replace", false, "back up and atomically replace an existing skill")
	stateDir := flags.String("state-dir", "", "private directory for authoritative receipts (advanced)")
	noColor := flags.Bool("no-color", false, "disable ANSI color")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillguardrail install SOURCE --target AGENT --yes [options]")
		fmt.Fprint(stderr, "\nThe source is scanned in quarantine before any agent directory is modified.\n\n")
		flags.PrintDefaults()
	}
	args = interspersed(args, map[string]bool{"yes": true, "replace": true, "no-color": true})
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
	resolved, err := source.Resolve(ctx, flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: source:", report.SafeText(err.Error()))
		return ExitError
	}
	defer resolved.Cleanup()
	scan, err := scanner.Scan(ctx, resolved.Root, resolved.Source, version.Version)
	if err != nil {
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete:", report.SafeText(err.Error()))
		return ExitError
	}
	color := !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != ""
	if err := report.Write(stdout, scan, report.FormatText, color); err != nil {
		fmt.Fprintln(stderr, "skillguardrail: write report:", report.SafeText(err.Error()))
		return ExitError
	}
	if scan.Fingerprint == "" {
		fmt.Fprintln(stderr, "skillguardrail: scan incomplete: no complete-package fingerprint was produced; no files changed")
		return ExitError
	}
	if err := scan.CheckInstallPolicy(allowed); err != nil {
		fmt.Fprintf(stderr, "skillguardrail: installation denied: %s\n", report.SafeText(err.Error()))
		return ExitPolicy
	}
	if !*yes {
		fmt.Fprintln(stderr, "skillguardrail: no files changed; review the report and rerun with --yes to install")
		return ExitCancelled
	}
	result, err := install.Install(ctx, resolved.Root, scan, install.Options{
		Target: *target, Directory: *directory, AllowedRisk: allowed,
		Replace: *replace, ToolVersion: version.Version, StateDir: *stateDir,
	})
	if err != nil {
		if strings.Contains(err.Error(), "policy denies") || strings.Contains(err.Error(), "never be overridden") || strings.Contains(err.Error(), "violates policy") || strings.Contains(err.Error(), "non-overridable") {
			fmt.Fprintln(stderr, "skillguardrail: installation denied:", report.SafeText(err.Error()))
			return ExitPolicy
		}
		fmt.Fprintln(stderr, "skillguardrail: install:", report.SafeText(err.Error()))
		return ExitError
	}
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
