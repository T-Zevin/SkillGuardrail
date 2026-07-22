<h1 align="center">SkillGuardrail</h1>

<p align="center">
  <a href="README.md">简体中文</a> · English
</p>

<p align="center">
  <a href="https://github.com/T-Zevin/SkillGuardrail/actions/workflows/ci.yml"><img alt="Build" src="https://github.com/T-Zevin/SkillGuardrail/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/releases"><img alt="Release" src="https://img.shields.io/github/v/release/T-Zevin/SkillGuardrail?display_name=tag&amp;sort=semver"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/T-Zevin/SkillGuardrail/total"></a>
  <a href="go.mod"><img alt="Go Version" src="https://img.shields.io/github/go-mod/go-version/T-Zevin/SkillGuardrail?logo=go"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/T-Zevin/SkillGuardrail"></a>
  <a href="#platform-support"><img alt="Platforms" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-5c6ac4"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/commits/main"><img alt="Last Commit" src="https://img.shields.io/github/last-commit/T-Zevin/SkillGuardrail"></a>
</p>

![SkillGuardrail — security guardrails for Agent Skills](assets/skillguardrail-hero.png)

**Scan before your agent reads. Install only what you trust.**

SkillGuardrail is an open-source pre-install security scanner and guarded installer for Agent Skills. It puts untrusted skill packages through a quarantine, static-analysis, policy, and verification workflow before they reach an agent's skill discovery directory.

It is designed for portable `SKILL.md` packages used with Codex, Claude Code, Cursor, Gemini CLI, OpenClaw, and other Agent Skills-compatible tools.

> [!IMPORTANT]
> SkillGuardrail is an early security tool. Static analysis can reduce risk, but it cannot prove that a skill is safe. Review findings, keep agents sandboxed, grant the least privilege possible, and treat unknown publishers as untrusted.

| **Quarantine first** | **Policy, not just scores** | **Verifiable installs** |
|:---|:---|:---|
| Inspect untrusted packages without running their code. | Turn findings and capability chains into an enforceable verdict. | Bind installs to source commits, fingerprints, and external receipts. |

## Table of contents

- [Why SkillGuardrail?](#why-skillguardrail)
- [What it checks](#what-it-checks)
- [Install](#install)
  - [Homebrew](#homebrew)
  - [Go](#go)
  - [Release binaries](#release-binaries)
  - [Platform support](#platform-support)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Verdicts](#verdicts)
- [Exit codes](#exit-codes)
- [Security model](#security-model)
- [Automation](#automation)
- [Project status](#project-status)
- [Related work](#related-work)
- [Contributing](#contributing)
- [License](#license)

## Why SkillGuardrail?

Installing a skill is not the same as copying an ordinary Markdown file. A skill can introduce instructions, executable scripts, dependencies, network access, and references to external content into an agent's trust boundary.

SkillGuardrail makes that boundary explicit:

```text
untrusted source
      │
      ▼
quarantine ──► static scan ──► capability analysis ──► policy verdict
                                                          │
                                    blocked ◄─────────────┼─────────────► approved
                                                                                │
                                                                                ▼
                                                        atomic install + external receipt
                                                                                │
                                                                                ▼
                                                                      later verification
```

Unlike scan-only tools, SkillGuardrail binds the decision to an immutable source commit and exact package fingerprint, requires the staged fingerprint to match, installs atomically, and stores a path-bound authoritative receipt outside the Skill directory so package-local metadata cannot certify itself.

## What it checks

SkillGuardrail looks for individual indicators and dangerous combinations across the complete skill directory:

- prompt injection, instruction override, and concealed directives;
- catalog injection in `name` or `description`, which an agent may load before the full skill;
- access to secrets, credentials, environment variables, and sensitive files;
- network egress, remote downloads, metadata endpoints, and external instructions;
- shell execution, `eval`, persistence, destructive writes, and system modification;
- obfuscation such as zero-width or bidirectional Unicode, Base64, and long encoded payloads;
- install-time package hooks, remote-script execution, archives, and unexpected binaries;
- capability chains such as **sensitive read + network egress** or **decode + execute**.

Reports include rule IDs, severity, evidence locations, an inferred capability inventory, a detected-rule-signal score, a policy verdict, and a reproducible package fingerprint. The score is not a probability of compromise: `0` means that the enabled rules did not match a known signal, not that residual risk is zero. Every report carries the explicit claim `not-proven-safe`. Portable and platform-specific metadata such as `allowed-tools` is retained for human review without assuming that every ecosystem shares one permission schema. Text, JSON, and SARIF output are available. See the [built-in rule catalog](docs/rules.md).

## Install

### Homebrew

Install through the SHA-256-pinned Homebrew formula:

```bash
brew install T-Zevin/tap/skillguardrail
```

To update an existing installation:

```bash
brew update
brew upgrade T-Zevin/tap/skillguardrail
```

### Go

Go 1.23 or newer is required when installing from source:

```bash
go install github.com/T-Zevin/SkillGuardrail/cmd/skillguardrail@latest
```

This path derives the tool version from Go module build information. Official release archives additionally embed the resolved tag commit and build time.

### Release binaries

Download the archive for your platform from [GitHub Releases](https://github.com/T-Zevin/SkillGuardrail/releases), then verify it against `checksums.txt` before placing the binary on your `PATH`.

### Platform support

Scanning and report generation are supported on macOS, Linux, and Windows. Guarded `install` and `verify` are enabled on macOS and Linux, where SkillGuardrail removes and verifies extended/POSIX ACLs in addition to checking ordinary permission modes. They also fail closed when the filesystem cannot prove ACL absence. Guarded operations are disabled on other platforms in the initial release; Windows users can still scan a package and then install reviewed files manually.

On macOS, the guarded operations call only the fixed system utilities `/bin/chmod` and `/bin/ls` for ACL handling. SkillGuardrail never invokes a package-provided executable, script, interpreter, or install hook.

## Quick start

Scan a local skill without installing it:

```bash
skillguardrail scan ./my-skill
```

Scan a public GitHub repository. Remote content is resolved to an immutable commit before analysis:

```bash
skillguardrail scan https://github.com/example/useful-skill
```

If a repository has no root `SKILL.md` but contains exactly one nested Skill,
SkillGuardrail automatically scans that Skill directory. Repositories with
multiple nested Skills remain at the repository root so you can review the
candidate list before selecting one.

Interactive terminal scans show a staged progress bar while the source is
resolved, quarantined, and analyzed. Progress is written to stderr and is
automatically disabled for JSON/SARIF output, redirected logs, and other
non-interactive writers.

The default `scan` timeout is 20 minutes (15 minutes for `install`) because
public GitHub archives can be slow through proxies or rate-limited networks.
Interactive terminals show downloaded/total archive bytes. If a transfer is
interrupted, SkillGuardrail clears the incomplete quarantine archive and makes
a bounded number of fresh attempts. Use `--timeout 25m` for a particularly
slow connection.

Remote acquisition has bounded defaults: 64 MiB for the compressed GitHub
archive, 128 MiB for extracted files, 160 MiB for the uncompressed tar stream,
and 10,000 source entries. These limits prevent untrusted archives from
exhausting disk or memory while covering ordinary multi-skill repositories.
For a larger repository, raise them explicitly within the built-in hard
ceilings with `--max-archive-size`, `--max-extract-size`,
`--max-uncompressed-size`, and `--max-source-entries`.

Large resources are still included in the package fingerprint even when they
exceed the text-analysis budget. The report separates detected rule signals
from content coverage and lists files that received metadata/hash review only.
An apparently clean result is therefore a bounded static-analysis result, not
a safety certificate or a zero-risk guarantee.

Public GitHub HTTPS repositories are supported. A root Skill or a repository
with exactly one nested Skill can be scanned directly; multiple nested Skills
are reported for explicit selection.

Request machine-readable output:

```bash
skillguardrail scan ./my-skill --format json
```

Human-readable reports are English by default. Add `-cn` to switch to
Simplified Chinese. The table layout, risk bar, architecture tree, and
translated rule explanations apply to text output; JSON and SARIF keep their
stable machine-readable fields:

```bash
skillguardrail scan ./my-skill -cn
```

Terminal colors are enabled automatically when supported. Add `--no-color`
only for plain-text logs or CI output.

Produce SARIF for GitHub code scanning or another compatible consumer:

```bash
skillguardrail scan ./my-skill --format sarif --output skillguardrail.sarif
```

Guarded installation scans first and refuses disallowed findings before writing into the selected agent's skill directory:

```bash
skillguardrail install https://github.com/example/useful-skill --target codex --yes
```

`--yes` records an explicit non-interactive installation decision; it never overrides a `block` or `critical` verdict. `--allow-risk` is limited to review-level severities (`info`, `low`, or `medium`). Omit `--yes` when you only want the command to explain the required approval without changing the destination.

The target and authoritative state roots must be owned by the current user and must not be writable by another user. A private `--state-dir` must not grant group/other access (use mode `0700` on Unix). `--replace` keeps the previous Skill in a unique private backup container and prints its path after a successful replacement.

Verify an installed skill against its recorded source and fingerprint:

```bash
skillguardrail verify my-skill --target codex
skillguardrail verify ~/.codex/skills/my-skill
```

See the options supported by your build:

```bash
skillguardrail --help
skillguardrail scan --help
skillguardrail install --help
```

## Command reference

Use `skillguardrail <command> --help` for the complete option list in the installed build. The primary Chinese README contains the detailed parameter reference; the main defaults are summarized below.

| Command | Required input | Primary options |
| --- | --- | --- |
| `scan SOURCE` | local directory, `SKILL.md`, or public GitHub repository | `-cn`, `--format text\|json\|sarif`, `--output PATH`, `--fail-on`, `--timeout 20m`, `--no-color` |
| `install SOURCE` | source plus `--target AGENT` or `--dir PATH` | `--yes`, `--allow-risk info\|low\|medium`, `--replace`, `--state-dir PATH`, `--timeout 15m` |
| `verify PATH` | installed path, or a name with `--target` / `--dir` | `--format text\|json`, `--state-dir PATH` |

`scan` also accepts bounded content-analysis controls: `--max-files 10000`, `--max-file-size 8388608`, and `--max-total-size 67108864`. Both `scan` and `install` accept GitHub archive controls: `--max-archive-size 67108864`, `--max-extract-size 134217728`, `--max-uncompressed-size 167772160`, and `--max-source-entries 10000`.

## Verdicts

| Verdict | Meaning | Default action |
| --- | --- | --- |
| `pass` | No known blocking signal was detected; this is not a zero-risk claim | Continue only after reviewing capabilities and provenance |
| `review` | Medium-risk behavior or accumulated risk needs review | Require an explicit decision |
| `block` | A high-risk finding or risk threshold was reached | Always refuse installation in `0.x` |
| `critical` | A critical behavior chain or invariant violation was detected | Always refuse |

A `pass` verdict means only that the enabled rules did not identify a known blocking signal. It is not a safety certificate, a probability estimate, or a zero-risk guarantee.

## Exit codes

SkillGuardrail is intended to work in local scripts and CI:

| Code | Meaning |
| ---: | --- |
| `0` | Command completed and policy allowed the result |
| `1` | Findings require review or block the requested operation |
| `2` | Usage, source, I/O, or internal error; the scan is incomplete |
| `3` | The operation was cancelled or requires an explicit `--yes` |

Incomplete scans fail closed for installation.

## Security model

Remote packages are downloaded into a private quarantine directory, and local packages are copied into a bounded private snapshot before inspection. SkillGuardrail does not execute skill scripts or invoke their interpreters during inspection. Installation occurs only after a complete scan and matching staging fingerprint.

The authoritative receipt is stored in a private per-user SkillGuardrail state directory outside the agent's Skill discovery tree; the installed `.skillguardrail.lock` is an inspectable mirror, not the source of trust. The receipt is bound to the canonical installation path and records entry types, modes, sizes, and hashes. Guarded operations validate directory ownership and parent replacement boundaries, and reject residual filesystem ACLs that could grant access beyond those recorded modes. `SKILLGUARDRAIL_STATE_HOME` or `--state-dir` can relocate this state for backup or controlled automation, but the directory must remain private and outside the Skill discovery directory.

This is local drift detection, not publisher attestation. A process running as the same user that can rewrite both the installed Skill and SkillGuardrail's external state can forge local history; signed provenance and OS-backed keys are future hardening areas.

The detailed trust boundaries, attacker capabilities, archive defenses, known limitations, and non-goals are documented in [the threat model](docs/threat-model.md).

SkillGuardrail follows the portable [`SKILL.md` specification](https://agentskills.io/specification) where possible and treats platform-specific metadata as optional input. Its rule taxonomy is intended to remain mappable to public work such as the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/); this does not imply certification or endorsement by either project.

## Automation

JSON and SARIF reports are suitable for policy checks, CI artifacts, code-scanning ingestion, and downstream integrations:

```bash
skillguardrail scan ./my-skill --format json > skillguardrail-report.json
```

Treat the JSON as untrusted data when rendering evidence in another system. Evidence is truncated and should never be executed.

## Project status

SkillGuardrail is under active development. The initial release focuses on a trustworthy local CLI, deterministic static rules, guarded installation, verification, JSON, and SARIF. Planned areas include signed rule bundles, additional source providers, organization policy packs, deeper language-aware analysis, and editor or agent integrations.

## Related work

SkillGuardrail is an independent implementation informed by the public threat models and detection ideas in [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector), [Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner), the [Agent Skills specification](https://agentskills.io/specification), and the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/). Its focus is the secure acquisition-to-installation transaction and subsequent drift verification. No endorsement by those projects is implied.

## Contributing

Security rules are most useful when they are explainable and backed by benign and malicious fixtures. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

To report a vulnerability in SkillGuardrail itself, follow [SECURITY.md](SECURITY.md). Do not submit a public issue containing an exploit or undisclosed vulnerable skill.

## License

Licensed under the [Apache License 2.0](LICENSE).
