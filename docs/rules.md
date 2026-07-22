# Built-in rule catalog

This catalog documents the deterministic rules shipped in the initial `builtin-v1` rule pack. Rule matches are evidence for review, not proof of malicious intent. Critical behavior chains and incomplete scan boundaries fail closed for installation.

## Package and manifest integrity

| Rule | Default severity | Meaning |
| --- | --- | --- |
| `SG-MAN-001` | High | `SKILL.md` does not declare a name |
| `SG-MAN-002` | High | `SKILL.md` does not declare a description |
| `SG-MAN-003` | High | A root `SKILL.md` is missing |
| `SG-MAN-004` | Informational | No root `SKILL.md` is present, but nested Skill manifests indicate a multi-skill repository |
| `SG-LIMIT-001` | High | The package exceeds the configured entry limit; files and directories both count |
| `SG-LIMIT-002` | Info | The package exceeds the content-analysis byte budget; remaining files are fingerprinted and structurally reviewed without text rules. |
| `SG-LIMIT-003` | High/Critical | Finding retention exceeded the package-wide or per-rule/per-path limit; additional evidence was suppressed |
| `SG-FILE-001` | Info | A file exceeds the text-analysis budget. Its metadata and full-package fingerprint are still checked, while content rules are skipped for that file. |
| `SG-FILE-002` | Info/Medium/High | The package embeds opaque, native-library, nested archive, or executable binary content. Native libraries and common document resources are contextual findings; common presentation assets (PNG/JPEG/SVG), `.DS_Store`, `.xlsx`, and generated `__pycache__/*.pyc` files are retained in the fingerprint and architecture tree but do not create a finding by default. |
| `SG-FILE-003` | Medium/High | A symbolic link is present or escapes the package |
| `SG-FILE-005` | High | A path or file could not be inspected |
| `SG-FILE-006` | High | A device, socket, FIFO, or special entry is present |
| `SG-FILE-007` | Critical | A file carries setuid or setgid permission bits |

Scanning and fingerprinting use the same configured path selection and resource budgets. The default `MaxFiles` budget counts both files and directories after ignored paths are excluded. Findings retain at most 512 entries per package and 16 entries for one rule on one path. If an entry, byte, per-file, or finding-retention boundary prevents complete inspection, the scan fails closed and does not emit an installable package fingerprint.

Remote archives are also rejected before scanning when they contain traversal paths, absolute paths, links, special entries, case-folding collisions, excessive depth, too many entries, too many bytes, or an excessive compression ratio.

## Prompt and agent-control rules

| Rule | Severity | Meaning |
| --- | --- | --- |
| `SG-PI-001` | High | Overrides system, developer, or previous instructions |
| `SG-PI-002` | High | Conceals actions or instructions from the user |
| `SG-PI-003` | High | Impersonates a privileged role or disables policy |
| `SG-PI-004` | High | Modifies agent identity, memory, policy, or settings files |
| `SG-PI-005` | High | Retrieves and follows mutable external instructions |

## Execution, credentials, and network

| Rule | Severity | Meaning |
| --- | --- | --- |
| `SG-EXEC-001` | Critical | Pipes remotely fetched content to an interpreter |
| `SG-EXEC-002` | Critical | Uses destructive recursive filesystem or disk commands |
| `SG-EXEC-003` | High | Dynamically evaluates encoded or constructed commands |
| `SG-EXEC-004` | Critical | Disables host malware, quarantine, firewall, or policy controls |
| `SG-EXEC-005` | High | Uses dynamic process or shell execution APIs |
| `SG-EXEC-006` | High | Requests privilege escalation or broad ownership/permission changes |
| `SG-CRED-001` | High | Accesses credential, key, browser, cloud, or identity stores |
| `SG-CRED-002` | Medium | References environment variables commonly containing secrets |
| `SG-CRED-003` | Critical | Contacts a link-local cloud metadata credential endpoint |
| `SG-CRED-004` | High | Reads or enumerates dotenv files |
| `SG-CRED-005` | Medium | Loads dotenv content into a process environment |
| `SG-NET-001` | High | Uploads local data to a remote endpoint |
| `SG-NET-002` | High | Uses a raw socket or remote-copy channel |
| `SG-NET-003` | High | Embeds a webhook receiver endpoint |
| `SG-NET-004` | Medium | Performs general outbound network access |
| `SG-NET-005` | High | Instructs the agent to transmit sensitive or collected data |

## Obfuscation, persistence, and supply chain

| Rule | Severity | Meaning |
| --- | --- | --- |
| `SG-OBF-001` | Critical | Decodes a payload and pipes it to execution |
| `SG-OBF-002` | High | Reconstructs executable content from encoded data |
| `SG-OBF-003` | Medium | Contains a long Base64-like blob |
| `SG-OBF-004` | High | Contains invisible or bidirectional Unicode controls |
| `SG-PERSIST-001` | Critical | Creates a scheduled or background persistence mechanism |
| `SG-PERSIST-002` | High | Modifies login, autorun, shell startup, or SSH authorization files |
| `SG-SUPPLY-001` | High | Defines a package-manager lifecycle hook |

## Behavior correlation

| Rule | Severity | Meaning |
| --- | --- | --- |
| `SG-CHAIN-001` | Critical | A single operation combines sensitive local data access with outbound transfer |

Correlation is intentionally conservative. SkillGuardrail does not upgrade unrelated keywords found in different files into a critical chain. This reduces the package-wide co-occurrence false positives common in simple regex scanners.

## Evidence handling

Evidence excerpts are bounded, known secret formats are redacted, and terminal control characters are escaped. JSON and SARIF consumers must still treat every path and evidence field as attacker-controlled data.
