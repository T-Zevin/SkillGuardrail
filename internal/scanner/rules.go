package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

type rule struct {
	id             string
	title          string
	description    string
	category       string
	severity       model.Severity
	confidence     string
	recommendation string
	patterns       []*regexp.Regexp
}

func (r rule) match(line string) (string, bool) {
	for _, pattern := range r.patterns {
		if loc := pattern.FindStringIndex(line); loc != nil {
			return line[loc[0]:loc[1]], true
		}
	}
	return "", false
}

func regexps(expressions ...string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(expressions))
	for _, expression := range expressions {
		result = append(result, regexp.MustCompile(expression))
	}
	return result
}

var contentRules = []rule{
	{
		id: "SG-PI-001", title: "Instruction hierarchy override", category: "prompt-injection", severity: model.SeverityHigh, confidence: "high",
		description:    "The content tells the agent to ignore or override higher-priority instructions.",
		recommendation: "Remove instruction-hierarchy overrides and state the Skill's task directly.",
		patterns: regexps(
			`(?i)\b(?:ignore|disregard|forget|override)\b.{0,48}\b(?:previous|prior|system|developer|original|higher[- ]priority)\b.{0,24}\b(?:instruction|prompt|message|rule)s?\b`,
			`(?:忽略|无视|覆盖|忘记).{0,24}(?:之前|以上|系统|开发者|原有|更高优先级).{0,16}(?:指令|提示词|消息|规则)`,
		),
	},
	{
		id: "SG-PI-002", title: "Concealment instruction", category: "prompt-injection", severity: model.SeverityHigh, confidence: "high",
		description:    "The content asks the agent to conceal actions or instructions from the user.",
		recommendation: "Remove concealment requirements and make every side effect explicit to the user.",
		patterns: regexps(
			`(?i)\b(?:do not|don't|never)\b.{0,24}\b(?:tell|show|reveal|mention|inform|warn)\b.{0,24}\b(?:user|operator|human)\b`,
			`(?i)\b(?:hide|conceal)\b.{0,32}\b(?:from (?:the )?(?:user|operator)|your actions?|these instructions?)\b`,
			`(?:不要|不得|无需).{0,16}(?:告诉|告知|展示|透露|提醒).{0,12}(?:用户|操作者|人类)`,
		),
	},
	{
		id: "SG-PI-003", title: "Role or policy impersonation", category: "prompt-injection", severity: model.SeverityHigh, confidence: "medium",
		description:    "The Skill attempts to introduce privileged role text or disable safety policy.",
		recommendation: "Remove role impersonation and safety-bypass language.",
		patterns: regexps(
			`(?i)<\/?(?:system|developer|assistant)>`,
			`(?i)\b(?:you are now|act as)\b.{0,32}\b(?:system|developer|administrator|root)\b`,
			`(?i)\b(?:bypass|disable|circumvent)\b.{0,32}\b(?:safety|policy|guardrail|restriction|sandbox)s?\b`,
			`(?:绕过|禁用|规避).{0,24}(?:安全|策略|护栏|限制|沙箱)`,
		),
	},
	{
		id: "SG-PI-004", title: "Agent control-file modification", category: "prompt-injection", severity: model.SeverityHigh, confidence: "high",
		description:    "The Skill attempts to persist instructions in an agent identity, memory, policy, or settings file.",
		recommendation: "Do not modify agent control files; return proposed changes for explicit user review instead.",
		patterns: regexps(
			`(?i)\b(?:write|modify|append|overwrite|update|edit|create)\b.{0,80}\b(?:AGENTS\.md|MEMORY\.md|SOUL\.md|CLAUDE\.md|\.codex[/\\]|\.claude[/\\])`,
			`(?i)(?:>>?|tee\s+(?:-a\s+)?)\s*[^\n]*(?:AGENTS\.md|MEMORY\.md|SOUL\.md|CLAUDE\.md|\.codex[/\\]|\.claude[/\\])`,
		),
	},
	{
		id: "SG-PI-005", title: "Mutable external instructions", category: "prompt-injection", severity: model.SeverityHigh, confidence: "medium",
		description:    "The Skill tells the agent to retrieve and follow instructions that can change outside the reviewed package.",
		recommendation: "Vendor required instructions into the package and pin them by a reviewed content hash.",
		patterns: regexps(
			`(?i)\b(?:fetch|download|read|load|follow|obey|execute)\b.{0,80}\b(?:instructions?|prompt|rules?|commands?)\b.{0,120}https?://`,
			`(?i)https?://[^\s)'\"]+.{0,120}\b(?:follow|obey|execute)\b.{0,60}\b(?:instructions?|commands?)\b`,
		),
	},
	{
		id: "SG-EXEC-001", title: "Remote content piped to an interpreter", category: "dangerous-execution", severity: model.SeverityCritical, confidence: "high",
		description:    "Network-fetched content is executed without a review boundary.",
		recommendation: "Download to quarantine, verify an immutable checksum, inspect the file, then execute only with explicit approval.",
		patterns: regexps(
			`(?i)\b(?:curl|wget)\b[^\n|;]{0,240}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|fish|python(?:3)?|perl|ruby|powershell|pwsh)\b`,
			`(?i)\b(?:iwr|invoke-webrequest)\b[^\n|;]{0,200}\|\s*(?:iex|invoke-expression)\b`,
		),
	},
	{
		id: "SG-EXEC-002", title: "Destructive filesystem command", category: "dangerous-execution", severity: model.SeverityCritical, confidence: "high",
		description:    "The command can recursively or forcefully destroy files or storage.",
		recommendation: "Remove destructive commands or constrain them to an explicit, validated temporary directory.",
		patterns: regexps(
			`(?i)(?:^|[;&|]\s*)rm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force)\b`,
			`(?i)\bremove-item\b[^\n]{0,160}(?:-recurse[^\n]{0,80}-force|-force[^\n]{0,80}-recurse)`,
			`(?i)\b(?:mkfs(?:\.[a-z0-9]+)?|format-volume|diskutil\s+erase|dd\s+if=)\b`,
			`(?i)\b(?:del|rmdir)\b[^\n]{0,80}(?:/s[^\n]{0,30}/q|/q[^\n]{0,30}/s)`,
		),
	},
	{
		id: "SG-EXEC-003", title: "Dynamic or encoded command execution", category: "dangerous-execution", severity: model.SeverityHigh, confidence: "high",
		description:    "Dynamic command evaluation makes the executed behavior difficult to review.",
		recommendation: "Use a fixed command with an argument array and validate every external input.",
		patterns: regexps(
			`(?i)(?:^|[;&|]\s*)eval\s+`,
			`(?i)\b(?:iex|invoke-expression)\b`,
			`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}(?:-encodedcommand|-enc\s)`,
			`(?i)\b(?:bash|sh|zsh|cmd(?:\.exe)?|powershell|pwsh)\b\s+(?:-c|/c)\s+`,
		),
	},
	{
		id: "SG-EXEC-004", title: "Security controls disabled", category: "dangerous-execution", severity: model.SeverityCritical, confidence: "high",
		description:    "The command weakens operating-system malware, quarantine, or policy enforcement.",
		recommendation: "Do not disable host security controls; use a constrained sandbox for testing.",
		patterns: regexps(
			`(?i)\bspctl\b[^\n]{0,80}--master-disable`,
			`(?i)\bxattr\b[^\n]{0,80}(?:-d|-r)[^\n]{0,80}com\.apple\.quarantine`,
			`(?i)\bset-mppreference\b[^\n]{0,160}-disablerealtimemonitoring\s+\$?true`,
			`(?i)\b(?:ufw\s+disable|setenforce\s+0)\b`,
		),
	},
	{
		id: "SG-EXEC-005", title: "Dynamic process execution API", category: "dangerous-execution", severity: model.SeverityHigh, confidence: "medium",
		description:    "The source uses an API that can evaluate code or invoke a command shell dynamically.",
		recommendation: "Use fixed executables with argument arrays, validate inputs, and avoid shell evaluation.",
		patterns: regexps(
			`(?i)\b(?:eval|exec)\s*\(`,
			`(?i)\bos\.system\s*\(`,
			`(?i)\bsubprocess\.[a-z_]+\s*\([^\n]{0,200}\bshell\s*=\s*True`,
			`(?i)\b(?:child_process\.)?exec(?:Sync)?\s*\(`,
		),
	},
	{
		id: "SG-EXEC-006", title: "Privilege or ownership modification", category: "dangerous-execution", severity: model.SeverityHigh, confidence: "medium",
		description:    "The command requests elevated privileges or broadly weakens filesystem permissions.",
		recommendation: "Avoid privilege elevation; constrain permission changes to a validated package-owned path.",
		patterns: regexps(
			`(?i)(?:^|[;&|]\s*)sudo\s+`,
			`(?i)\bchmod\b[^\n]{0,80}(?:777|a\+rwx|-R)\b`,
			`(?i)\bchown\b[^\n]{0,80}(?:-[a-z]*r|--recursive)\b`,
			`(?i)\btakeown\b[^\n]{0,100}/r\b`,
		),
	},
	{
		id: "SG-CRED-001", title: "Sensitive credential store access", category: "credential-access", severity: model.SeverityHigh, confidence: "high",
		description:    "The Skill references a credential, key, token, browser, or cloud-identity store.",
		recommendation: "Use narrowly scoped credentials passed explicitly at runtime; never inspect unrelated user secrets.",
		patterns: regexps(
			`(?i)(?:~|\$\{?HOME\}?|/home/[^/\s]+|/Users/[^/\s]+)[/\\]\.(?:ssh|aws|config[/\\](?:gcloud|gh)|kube)(?:[/\\]|\b)`,
			`(?i)\b(?:id_rsa|id_ed25519|\.aws[/\\]credentials|\.kube[/\\]config|\.npmrc|\.pypirc|/etc/shadow)\b`,
			`(?i)\b(?:security\s+find-(?:generic|internet)-password|cmdkey\s+/list|credentialmanager|keychain)\b`,
			`(?i)(?:login data|cookies\.sqlite|key4\.db|logins\.json)`,
		),
	},
	{
		id: "SG-CRED-002", title: "Secret environment variable access", category: "credential-access", severity: model.SeverityMedium, confidence: "medium",
		description:    "The Skill references an environment variable commonly used to hold a secret.",
		recommendation: "Declare the required secret, scope it narrowly, and never print or transmit its value.",
		patterns: regexps(
			`(?i)\b(?:GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|NPM_TOKEN)\b`,
			`(?i)(?:process\.env|os\.environ|getenv\s*\()[^\n]{0,80}(?:token|secret|password|api[_-]?key)`,
		),
	},
	{
		id: "SG-CRED-003", title: "Cloud metadata credential endpoint", category: "credential-access", severity: model.SeverityCritical, confidence: "high",
		description:    "The link-local cloud metadata service can expose workload identity credentials.",
		recommendation: "Remove metadata-service access unless it is the explicit, documented purpose and is protected against credential disclosure.",
		patterns:       regexps(`(?:169\.254\.169\.254|metadata\.google\.internal)`),
	},
	{
		id: "SG-CRED-004", title: "Environment file access", category: "credential-access", severity: model.SeverityHigh, confidence: "medium",
		description:    "The Skill reads or enumerates dotenv files, which commonly contain application secrets.",
		recommendation: "Request only a named, scoped value and never read unrelated dotenv files.",
		patterns: regexps(
			`(?i)(?:cat|type|get-content|readfile|open\s*\()[^\n]{0,100}(?:^|[/\\])\.env(?:\.[A-Za-z0-9_-]+)?\b`,
			`(?i)\b(?:glob|find|rg|grep)\b[^\n]{0,120}\b\.env\b`,
		),
	},
	{
		id: "SG-CRED-005", title: "Environment-file loader", category: "credential-access", severity: model.SeverityMedium, confidence: "medium",
		description:    "Environment files commonly contain API keys, passwords, and service credentials.",
		recommendation: "Request only named, scoped variables and never enumerate or transmit an environment file.",
		patterns: regexps(
			`(?i)\b(?:cat|type|get-content|source|open|readfile|read_to_string)\b[^\n]{0,100}[/\\]?\.env(?:\.[a-z0-9_-]+)?\b`,
			`(?i)\bdotenv(?:\.config)?\s*\(`,
		),
	},
	{
		id: "SG-NET-001", title: "Outbound data upload", category: "network-exfiltration", severity: model.SeverityHigh, confidence: "high",
		description:    "The command sends local data to a remote endpoint.",
		recommendation: "Remove the upload or require explicit destination approval and disclose exactly what data leaves the machine.",
		patterns: regexps(
			`(?i)\bcurl\b[^\n]{0,260}(?:--data(?:-ascii|-binary|-raw|-urlencode)?\b|--form\b|-F\s|--upload-file\b|-T\s)`,
			`(?i)\bwget\b[^\n]{0,240}--post-(?:data|file)\b`,
			`(?i)\b(?:requests|httpx)\s*\.\s*post\s*\(`,
			`(?i)\b(?:invoke-restmethod|invoke-webrequest)\b[^\n]{0,200}-method\s+(?:post|put|patch)\b`,
			`(?i)\bfetch\s*\([^\n]{0,260}\bmethod\s*:\s*['\"](?:POST|PUT|PATCH)['\"]`,
		),
	},
	{
		id: "SG-NET-002", title: "Raw network or remote-copy channel", category: "network-exfiltration", severity: model.SeverityHigh, confidence: "medium",
		description:    "Raw sockets or remote-copy tools can transfer local data outside normal API boundaries.",
		recommendation: "Document and constrain the destination, protocol, and exact files transferred, or remove the behavior.",
		patterns: regexps(
			`(?i)(?:^|[;&|]\s*)(?:nc|ncat|netcat)\s+`,
			`(?i)\bscp\b[^\n]{0,200}\s[^\s]+@[^\s:]+:`,
			`(?i)\brsync\b[^\n]{0,200}(?:ssh|[^\s]+@[^\s:]+:)`,
		),
	},
	{
		id: "SG-NET-003", title: "Webhook endpoint", category: "network-exfiltration", severity: model.SeverityHigh, confidence: "high",
		description:    "Webhook endpoints are frequently used to receive exfiltrated data.",
		recommendation: "Remove embedded webhooks and use a user-approved, documented endpoint.",
		patterns:       regexps(`(?i)https?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|webhook\.site)/[^\s)'\"]+`),
	},
	{
		id: "SG-NET-004", title: "Outbound network access", category: "network-exfiltration", severity: model.SeverityMedium, confidence: "medium",
		description:    "The Skill can contact an external network endpoint.",
		recommendation: "Document the required hosts, data sent, and reason for network access; prefer immutable pinned content.",
		patterns: regexps(
			`(?i)\b(?:curl|wget)\b[^\n]{0,240}https?://`,
			`(?i)\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|delete)\s*\(`,
			`(?i)\b(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(`,
			`(?i)\b(?:invoke-webrequest|invoke-restmethod)\b`,
		),
	},
	{
		id: "SG-NET-005", title: "Instruction to transmit sensitive data", category: "network-exfiltration", severity: model.SeverityHigh, confidence: "medium",
		description:    "The natural-language instructions direct the agent to send local or sensitive data to a remote endpoint.",
		recommendation: "Remove data transmission or require explicit approval after showing the destination and exact payload.",
		patterns: regexps(
			`(?i)\b(?:send|upload|transmit|exfiltrate|post)\b.{0,100}\b(?:credential|secret|token|private key|environment variable|collected data|local file)s?\b.{0,80}https?://`,
			`(?i)\b(?:credential|secret|token|private key|environment variable|collected data|local file)s?\b.{0,100}\b(?:send|upload|transmit|exfiltrate|post)\b.{0,80}https?://`,
			`(?i)\b(?:send|upload|transmit|post)\s+(?:it|them|the data|the result)\b.{0,80}https?://`,
			`(?:发送|上传|传输|外传).{0,40}(?:凭据|密钥|令牌|环境变量|收集的数据|本地文件).{0,50}https?://`,
		),
	},
	{
		id: "SG-OBF-001", title: "Decoded payload piped to execution", category: "obfuscation", severity: model.SeverityCritical, confidence: "high",
		description:    "Encoded content is decoded and executed without becoming reviewable source.",
		recommendation: "Commit the decoded source as plain text and inspect it before execution.",
		patterns: regexps(
			`(?i)\bbase64\b[^\n|]{0,80}(?:-d|--decode)[^\n|]{0,80}\|\s*(?:bash|sh|zsh|python(?:3)?|perl|ruby|powershell|pwsh)\b`,
			`(?i)\bxxd\b[^\n|]{0,80}-r[^\n|]{0,80}\|\s*(?:bash|sh|zsh|python(?:3)?)\b`,
		),
	},
	{
		id: "SG-OBF-002", title: "Encoded script reconstruction", category: "obfuscation", severity: model.SeverityHigh, confidence: "high",
		description:    "The code reconstructs executable content from an encoded representation.",
		recommendation: "Replace encoded payloads with auditable source code.",
		patterns: regexps(
			`(?i)\[convert\]::frombase64string\s*\(`,
			`(?i)\b(?:atob|fromcharcode|b64decode|decodebytes)\s*\(`,
			`(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}`,
		),
	},
	{
		id: "SG-OBF-003", title: "Long encoded blob", category: "obfuscation", severity: model.SeverityMedium, confidence: "medium",
		description:    "A long Base64-like blob may conceal instructions, code, or data.",
		recommendation: "Store reviewable source or data in its decoded form and document its provenance.",
		patterns:       regexps(`(?:[A-Za-z0-9+/]{160,}={0,2})`),
	},
	{
		id: "SG-PERSIST-001", title: "Scheduled persistence", category: "persistence", severity: model.SeverityCritical, confidence: "high",
		description:    "The Skill creates or enables a recurring background task.",
		recommendation: "Remove persistence; Agent Skills should run only when explicitly invoked.",
		patterns: regexps(
			`(?i)\bcrontab\b`,
			`(?i)\b(?:schtasks)(?:\.exe)?\b[^\n]{0,100}/create\b`,
			`(?i)\bsystemctl\b[^\n]{0,100}\benable\b`,
			`(?i)\b(?:launchctl)\b[^\n]{0,120}\b(?:load|bootstrap|enable)\b`,
		),
	},
	{
		id: "SG-PERSIST-002", title: "Startup configuration modification", category: "persistence", severity: model.SeverityHigh, confidence: "medium",
		description:    "The content targets a login, shell startup, autorun, or SSH authorization file.",
		recommendation: "Do not modify startup or authorization files; keep setup explicit and reversible.",
		patterns: regexps(
			`(?i)(?:>>?|tee\s+(?:-a\s+)?)\s*(?:~|\$\{?HOME\}?)[/\\]\.(?:bashrc|zshrc|profile|bash_profile|config[/\\]fish[/\\]config\.fish)\b`,
			`(?i)(?:>>?|tee\s+(?:-a\s+)?)\s*(?:~|\$\{?HOME\}?)[/\\]\.ssh[/\\]authorized_keys\b`,
			`(?i)\breg\s+add\b[^\n]{0,200}\\(?:run|runonce)\b`,
			`(?i)(?:Library[/\\]LaunchAgents|/etc/(?:cron\.|systemd/))`,
		),
	},
	{
		id: "SG-SUPPLY-001", title: "Package-manager lifecycle hook", category: "supply-chain", severity: model.SeverityHigh, confidence: "high",
		description:    "An install-time lifecycle hook can execute before the package has been reviewed.",
		recommendation: "Remove lifecycle hooks from Skill packages and make every setup step explicit and optional.",
		patterns: regexps(
			`(?i)[\"'](?:preinstall|postinstall|prepare)[\"']\s*:`,
			`(?i)\bsetup\.py\b[^\n]{0,80}\b(?:cmdclass|install)\b`,
		),
	},
}

func suspiciousUnicode(line string) (string, bool) {
	for _, r := range line {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff',
			'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
			'\u2066', '\u2067', '\u2068', '\u2069':
			return string(r), true
		}
	}
	return "", false
}

var evidenceSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+`),
	regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{12,}|gh[opusr]_[A-Za-z0-9_]{12,})\b`),
}

func sanitizeEvidence(evidence string) string {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return ""
	}
	evidence = evidenceSecretPatterns[0].ReplaceAllString(evidence, `${1}<redacted>`)
	evidence = evidenceSecretPatterns[1].ReplaceAllString(evidence, `<redacted-token>`)
	evidence = escapeControls(evidence)
	runes := []rune(evidence)
	if len(runes) > 240 {
		evidence = string(runes[:240]) + "…"
	}
	return evidence
}

func escapeControls(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) && r != '\t' {
			fmt.Fprintf(&builder, "\\u%04X", r)
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

var (
	chainSensitive = regexp.MustCompile(`(?i)(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|(?:^|[/\\])\.env\b|os\.environ|process\.env|printenv\b)`)
	chainEgress    = regexp.MustCompile(`(?i)(?:curl\b[^\n]{0,260}(?:--data|--form|-F\s|--upload-file|-T\s)|requests\.post\s*\(|fetch\s*\([^\n]{0,220}method\s*:\s*[\"']POST|\b(?:nc|ncat|netcat|scp)\b)`)
)

func matchesSensitiveEgressChain(line string) bool {
	return chainSensitive.MatchString(line) && chainEgress.MatchString(line)
}
