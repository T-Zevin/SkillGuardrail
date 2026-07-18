## Purpose

Describe the user or security problem and the smallest change that solves it.

## Security impact

Describe any trust-boundary, parser, source-retrieval, policy, installation, or verification change. Write “none” only after checking the threat model.

## Verification

List the tests and commands you ran.

## Checklist

- [ ] I added or updated tests, including a hostile or failure-path case where relevant.
- [ ] I ran `gofmt`, `go vet ./...`, and `go test -race ./...`.
- [ ] The scanner does not execute, import, or source untrusted content.
- [ ] New evidence is bounded, escaped, and does not expose secrets.
- [ ] I updated the README, JSON schema notes, or threat model when behavior changed.
- [ ] I did not add live malware, credentials, private data, or unrelated changes.
