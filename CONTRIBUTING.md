# Contributing to SkillGuardrail

Thank you for helping make Agent Skills safer. Small, focused pull requests with clear tests are the easiest to review.

## Before you start

- Use a public issue for ordinary bugs, features, and rule proposals.
- Follow [SECURITY.md](SECURITY.md) for vulnerabilities or unpublished evasions.
- Do not add a dependency or network call without explaining why the standard library is insufficient.
- Never add live malware, real credentials, or code that contacts an external service to test fixtures.

## Development setup

SkillGuardrail requires Go 1.23 or newer.

```bash
git clone https://github.com/T-Zevin/SkillGuardrail.git
cd SkillGuardrail
go test ./...
go run ./cmd/skillguardrail version
```

Before opening a pull request, run:

```bash
gofmt -w cmd internal
go vet ./...
go test -race ./...
go build ./cmd/skillguardrail
```

Or run the same checks with `make check`.

Do not commit the locally built binary.

## Pull-request expectations

A pull request should:

1. explain the security or user problem it solves;
2. describe trust-boundary changes and failure behavior;
3. include tests for the expected path and at least one hostile input;
4. preserve deterministic, offline scanning unless the change explicitly affects source retrieval;
5. update user-facing documentation and JSON schema notes when applicable;
6. avoid drive-by formatting or unrelated refactors.

All pull requests must pass formatting, `go vet`, tests with the race detector, and a clean build on supported platforms.

## Adding or changing a detection rule

Every rule must be understandable to the person deciding whether to install a skill. Include:

- a stable rule ID and category;
- severity and confidence justified by likely impact;
- a concise title and evidence that points to a file and line;
- a practical recommendation;
- a malicious or suspicious fixture that should match;
- a benign near-match that must not match;
- tests for common encoding, path, and case variants when relevant.

Prefer behavioral or structural signals over a long list of isolated keywords. If a rule is noisy, lower its confidence or combine it with capabilities instead of assigning an unjustified high severity.

Evidence must be bounded, escaped for terminal output, and free of secrets. A detector must never evaluate, import, source, or execute the content it analyzes.

## Security invariants

Changes must preserve these invariants:

- untrusted content is not executed during scanning;
- remote source identity is resolved before download;
- redirects and archive extraction cannot escape the approved boundary;
- scanning is complete before an agent discovery directory is modified;
- block and critical verdicts cannot be overridden by the `0.x` installer;
- incomplete scans fail closed for installation;
- installation cannot traverse a symlink-controlled path;
- the staged fingerprint must match the fingerprint shown for approval;
- verification trusts only the path-bound external receipt, not the package-local manifest, and is based on content and permissions rather than modification timestamps.

If a change intentionally revises an invariant, update [docs/threat-model.md](docs/threat-model.md) and call it out prominently in the pull request.

## Commit and review hygiene

Write imperative commit subjects, keep generated artifacts out of source commits, and rebase or merge the latest default branch before final review. By contributing, you agree that your contribution is licensed under the Apache License 2.0.
