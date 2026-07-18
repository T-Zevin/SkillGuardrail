# SkillGuardrail threat model

Status: initial threat model for the `0.x` CLI. This document is a security design contract, not a claim that software is defect-free.

## 1. Purpose

SkillGuardrail reduces the risk of moving an untrusted Agent Skill into a directory that Codex, Claude Code, Cursor, Gemini CLI, OpenClaw, or another agent may discover and read.

The protected decision is:

> Given these exact source bytes and this policy, should this skill be allowed to cross into an agent's skill discovery boundary?

The CLI provides evidence for that decision, enforces non-overridable safety invariants, records what was installed, and later detects drift. It does not establish that the skill's publisher is trustworthy or that every possible agent interpretation is safe.

## 2. Assets

The primary assets are:

- credentials, tokens, SSH keys, cloud metadata, and user data available to an agent;
- integrity and confidentiality of the workstation and project repositories;
- integrity of agent instructions, tool policy, and approval boundaries;
- the agent skill discovery directories;
- provenance and content integrity of an installed skill;
- the user's attention and ability to make an informed installation decision;
- availability of the scanner and host system.

## 3. Actors and trust assumptions

### Trusted for the initial model

- the local SkillGuardrail binary and its embedded rules;
- the private external receipt state, until an attacker gains same-user write access to it;
- the operating system kernel, Go runtime, and cryptographic primitives;
- the user who chooses policy and approves review-level findings;
- a correctly configured HTTPS trust store;
- the destination directory selected by the user, before untrusted content is introduced.

### Untrusted

- repository owners, contributors, release authors, and compromised accounts;
- `SKILL.md`, scripts, configuration, archives, binaries, names, paths, and metadata;
- redirects, HTTP response metadata, repository names, branches, and tags;
- terminal control characters and data included in reports;
- lock files or installed content after an attacker gains local write access;
- URLs and path arguments supplied to the CLI.

A GitHub account, star count, familiar organization name, license, or clean README is not a trust signal sufficient to skip scanning.

## 4. Trust boundaries and data flow

```text
[CLI arguments]
       │ validate
       ▼
[source resolver] ──HTTPS──► [GitHub]
       │ immutable commit + bounded archive
       │ or bounded local snapshot
       ▼
[0700 quarantine directory]
       │ safe extraction; no execution
       ▼
[parsers + static rules + capability graph]
       │
       ├──► [escaped human report]
       ├──► [versioned JSON report]
       └──► [policy engine]
                    │
             block/review/pass
                    │ approved only
                    ▼
         [atomic destination install]
                    │
                    ▼
       [package manifest mirror]
                    │
                    └──► [path-bound authoritative receipt outside Skill tree]
```

The most important boundary is between quarantine and the agent discovery directory. No untrusted package file may cross that boundary before a complete scan and an allowed policy decision.

## 5. Attacker goals

An attacker may attempt to:

1. cause SkillGuardrail itself to execute code while inspecting content;
2. evade a rule through encoding, splitting, indirection, generated content, or cross-file behavior;
3. read secrets and exfiltrate them when the agent later uses the skill;
4. override system or user instructions, suppress approval, or solicit excessive permissions;
5. exploit archive extraction, paths, links, races, or redirects to write outside quarantine or destination;
6. replace a scanned branch, tag, archive, or dependency between review and installation;
7. exhaust memory, disk, CPU, terminal, or parser resources;
8. forge a report, fingerprint, lock record, or reassuring package metadata;
9. modify an installed skill after approval without detection;
10. exploit ambiguity across platforms, Unicode normalization, or case-insensitive filesystems.

## 6. Detection model

Static findings are grouped into these families:

| Family | Examples |
| --- | --- |
| `SG-MANIFEST` | specification errors, misleading metadata, suspicious `allowed-tools` when present, scan coverage gaps |
| `SG-PROMPT` | instruction override, catalog injection in `name` or `description`, hidden instructions, attempts to bypass approval |
| `SG-SECRETS` | credentials, sensitive environment variables, key and configuration paths |
| `SG-NET` | network egress, downloads, URL shorteners, metadata or loopback endpoints |
| `SG-EXEC` | shell or interpreter execution, dynamic evaluation, persistence, destructive writes |
| `SG-OBF` | bidirectional or zero-width Unicode, encoded payloads, high-entropy blobs |
| `SG-SUPPLY` | remote scripts, external instructions, unpinned dependencies, binaries, archives |

SkillGuardrail also derives capabilities such as:

- `sensitive_read`
- `network_egress`
- `external_instruction`
- `dynamic_exec`
- `system_write`
- `destructive_write`
- `persistence`

The portable Agent Skills specification requires `name` and `description`; fields such as `allowed-tools` are optional or platform-specific. SkillGuardrail therefore infers capabilities from package content rather than assuming that every skill contains a complete permission manifest. Declaration-to-behavior checks apply only when a relevant field is present. Because agents may load `name` and `description` into a startup catalog before reading the full skill, those fields receive prompt-injection and overly broad activation checks as part of the pre-load boundary.

Capabilities matter in combination. For example, a networking helper and a credential reader may each have legitimate uses in isolation, while `sensitive_read + network_egress` is a critical exfiltration chain. Other critical chains include `external_instruction + dynamic_exec`, `decode + execute`, and `system_write + execute`.

## 7. Policy model

| Highest effective risk | Verdict | Installation policy |
| --- | --- | --- |
| Critical | `critical` | Hard block; no override |
| High | `block` | Hard block in the `0.x` policy; no severity-wide override |
| Medium | `review` | Require an explicit user decision |
| Low or informational | `pass` with warnings | Allow while preserving findings in the report |

Accumulated lower-severity findings may raise the verdict. Parser failures, resource-limit violations, unsupported content required for coverage, and other incomplete scans fail closed for installation.

## 8. Source retrieval controls

The initial remote-source boundary supports public HTTPS GitHub sources. The intended controls are:

- accept only recognized HTTPS GitHub URL forms;
- resolve a branch or tag to a full commit SHA before download;
- download an archive associated with that immutable identity;
- enforce redirect count, HTTPS scheme, exact GitHub host allowlists, time, and byte limits;
- reject redirects or DNS results that reach loopback, link-local, private, multicast, or reserved networks;
- never forward credentials to a redirected host;
- create quarantine with owner-only permissions;
- never invoke `git`, a shell, package manager, language interpreter, or package-provided executable.

Local sources are copied into a fresh owner-only quarantine snapshot before parsing. The snapshot rejects links and special entries, applies entry, depth, and byte limits, excludes known dependency/VCS directories, normalizes file permissions, and verifies the opened file identity before copying. Scanning and installation operate on this private snapshot rather than the caller-controlled original path.

The resolved repository and commit are included in reports and lock metadata. A mutable URL remains useful provenance, but the content fingerprint is the final identity used for verification.

## 9. Archive and filesystem controls

Archive entries and local directories are hostile. Extraction and installation should enforce:

- maximum compressed bytes, expanded bytes, file count, individual file size, path depth, and compression ratio;
- clean relative paths only; reject absolute, drive-qualified, parent-traversal, NUL-containing, and reserved paths;
- reject symbolic links, hard links, device nodes, sockets, FIFOs, and unsupported entry types;
- detect case-folding path collisions; Unicode-normalization collision detection remains planned;
- avoid following links in every destination path component;
- use a fresh staging directory on the destination filesystem and an atomic rename;
- refuse an existing destination unless the user selected an explicit, safely implemented replacement mode;
- require the staged fingerprint to equal the fingerprint shown for approval;
- write package metadata only for the bytes that were actually installed;
- store the authoritative receipt outside the agent discovery tree with owner-only access.
- on supported guarded-install platforms, remove inherited/extended ACLs from staged content and reject residual ACLs on the installed tree and authoritative receipt paths.
- require every staged and installed entry to remain owned by the current user and not writable by group or other users.
- require guarded-operation roots to be owned by the current user, validate current-user/root-owned parent boundaries, and reject group/other-writable replacement paths unless sticky-directory semantics under a trusted owner protect the unique staging entry.
- create replacement backups in unique owner-private containers rather than a predictable shared hierarchy.

Temporary data should be removed after completion. Cleanup failure is reported without following attacker-controlled links.

## 10. Report and terminal safety

Reports contain attacker-controlled names and evidence. Human output must escape control characters, avoid terminal hyperlinks from untrusted input, and bound each evidence excerpt. JSON output uses a versioned schema and valid encoding.

The scanner must not print detected secret values in full. Downstream consumers are responsible for treating JSON fields as data rather than HTML, shell, Markdown, or code.

## 11. Verification

Guarded installation stores an authoritative receipt in a private per-user state directory outside the installed Skill tree and writes `.skillguardrail.lock` inside the Skill only as an inspectable mirror. The authoritative record is bound to the canonical target path and records, at minimum:

- schema and SkillGuardrail versions;
- resolved source and commit when applicable;
- installation time and skill name;
- deterministic content fingerprint;
- risk score, verdict, and detected capabilities;
- entry types and permission modes, file-by-file SHA-256 digests, and the findings accepted at installation time.

`verify` loads only the external authoritative receipt, validates its schema and path binding, recomputes content identity rather than trusting modification times, and compares the package-local manifest with the authoritative bytes. It reports additions, removals, content changes, permission changes, or manifest changes and fails when the external receipt is absent, malformed, insecurely permissioned, or inconsistent with the destination.

The initial guarded installer and verifier are available on macOS and Linux, where SkillGuardrail can fail closed while checking extended or POSIX ACL state. A filesystem response that says ACL inspection is unsupported is not treated as proof that an ACL is absent. Scan-only operation remains available on Windows and other compiled targets. On macOS, ACL handling uses fixed absolute paths to the operating system's `chmod` and `ls` utilities with a minimal fixed environment; package-controlled commands are never executed.

The receipt is not a cryptographic publisher signature. Separation prevents an untrusted package from arriving with a self-signed receipt and detects changes confined to the Skill directory. A process running with the same user identity that can rewrite both the installed Skill and SkillGuardrail's external state, or an attacker who can replace the scanner binary, is outside this protection.

## 12. Known limitations and non-goals

SkillGuardrail does not:

- prove semantic safety or eliminate false positives and false negatives;
- safely execute a skill to observe runtime behavior;
- replace an OS sandbox, agent permission controls, human review, endpoint security, or backups;
- validate a publisher's real-world identity from a GitHub account;
- guarantee the safety of content fetched by the skill after installation;
- analyze every binary format or recover all behavior hidden by encryption or custom encoding;
- currently detect every Unicode-normalization path collision (case-fold collisions are rejected);
- prevent a privileged or same-user local attacker from replacing the scanner, rules, destination, and external receipt state together;
- guarantee race-free destination replacement against a malicious process concurrently mutating paths with the same user identity;
- make a previously scanned mutable branch safe without re-resolution and re-scan.
- provide guarded installation or receipt verification on platforms where the initial release cannot validate filesystem ACL state; scan-only use remains available there.

An allowed verdict is evidence about the scanned bytes under the enabled rules. It is never a blanket endorsement of the repository, publisher, future versions, or runtime environment.

## 13. Security test strategy

Security-sensitive changes should include tests for:

- benign and malicious rule fixtures, including near-matches;
- encoded, split, mixed-case, Unicode, and cross-file variants;
- archive traversal, links, special files, collisions, and decompression limits;
- redirect, host-validation, timeout, and size-limit behavior;
- destination symlink races and existing-path handling where testable;
- deterministic fingerprints and drift detection;
- control-character escaping and bounded evidence;
- fail-closed behavior after every partial failure.

Fuzzing is especially valuable for URL parsing, archive paths, manifest parsing, evidence extraction, and fingerprint traversal.

## 14. Updating this model

Update this document whenever a change adds a source provider, parser, executable integration, rule-update channel, privileged destination, remote service, or new override path. Pull requests should explicitly describe any change to trust assumptions or security invariants.
