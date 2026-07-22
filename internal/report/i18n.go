package report

import "github.com/T-Zevin/SkillGuardrail/internal/model"

type findingText struct {
	Title, Description, Recommendation string
}

// Rule IDs remain the stable cross-language identifier. These translations
// are deliberately kept in the reporting layer so JSON/SARIF schemas and
// scanner logic do not change when human-facing wording evolves.
var chineseFindingText = map[string]findingText{
	"SG-PI-001":      {"覆盖指令层级", "内容要求代理忽略或覆盖更高优先级的指令。", "删除指令层级覆盖内容，直接说明 Skill 的任务。"},
	"SG-PI-002":      {"隐藏行为指令", "内容要求代理向用户隐藏操作或指令。", "删除隐藏要求，向用户明确披露所有副作用。"},
	"SG-PI-003":      {"冒充角色或策略", "Skill 试图引入特权角色文本或关闭安全策略。", "删除角色冒充和绕过安全机制的内容。"},
	"SG-PI-004":      {"修改代理控制文件", "Skill 试图修改代理身份、记忆、策略或设置文件。", "不要修改代理控制文件，将变更交给用户明确审核。"},
	"SG-PI-005":      {"引用可变外部指令", "Skill 要求获取并执行包外可变化的指令。", "将必要指令固定在包内，并绑定经过审核的内容哈希。"},
	"SG-EXEC-001":    {"远程内容直接交给解释器", "网络获取的内容未经审核边界就被执行。", "先下载到隔离区、校验固定哈希并审核，再在明确批准后执行。"},
	"SG-EXEC-002":    {"破坏性文件系统命令", "命令可能递归或强制删除文件或存储。", "删除破坏性命令，或限制到经过校验的临时目录。"},
	"SG-EXEC-003":    {"动态或编码命令执行", "动态求值使实际执行行为难以审核。", "使用固定命令和参数数组，并校验所有外部输入。"},
	"SG-EXEC-004":    {"关闭安全控制", "命令会削弱操作系统的恶意软件、隔离或策略防护。", "不要关闭主机安全控制，测试时使用受限沙箱。"},
	"SG-EXEC-005":    {"动态进程执行 API", "源码使用了可动态求值或调用命令 Shell 的 API。", "使用固定可执行文件和参数数组，避免 Shell 求值。"},
	"SG-EXEC-006":    {"修改权限或所有权", "命令请求提权或大范围削弱文件权限。", "避免提权，将权限变更限制在已校验的包路径内。"},
	"SG-CRED-001":    {"访问敏感凭据存储", "Skill 引用了凭据、密钥、令牌、浏览器或云身份存储。", "只使用运行时显式传入的最小权限凭据，不读取无关秘密。"},
	"SG-CRED-002":    {"读取秘密环境变量", "Skill 引用了常用于保存秘密的环境变量。", "声明并限制所需秘密，绝不打印或传输其值。"},
	"SG-CRED-003":    {"云元数据凭据端点", "链路本地云元数据服务可能暴露工作负载身份凭据。", "移除元数据服务访问，除非它是明确记录且受保护的用途。"},
	"SG-CRED-004":    {"读取环境文件", "Skill 读取了通常包含应用秘密的 dotenv 文件。", "只请求命名且受限的值，不读取无关环境文件。"},
	"SG-CRED-005":    {"加载环境文件", "环境文件通常包含 API 密钥、密码和服务凭据。", "只请求命名变量，不枚举或传输整个环境文件。"},
	"SG-NET-001":     {"向外部上传数据", "命令会将本地数据发送到远程端点。", "删除上传行为，或明确展示目的地和具体载荷后再请求批准。"},
	"SG-NET-002":     {"原始网络或远程复制通道", "原始套接字或远程复制工具可能绕过常规 API 边界传输数据。", "记录并限制目的地、协议和传输文件，或移除该行为。"},
	"SG-NET-003":     {"Webhook 端点", "Webhook 端点经常被用于接收外传数据。", "删除内嵌 Webhook，改用用户批准且有文档的端点。"},
	"SG-NET-004":     {"外发网络访问", "Skill 可以连接外部网络端点。", "记录所需主机、发送数据和网络原因，优先使用固定内容。"},
	"SG-NET-005":     {"要求传输敏感数据", "自然语言指令要求将本地或敏感数据发送到远程端点。", "移除传输行为，或展示目的地和载荷后请求明确批准。"},
	"SG-OBF-001":     {"解码后直接执行载荷", "编码内容被解码并执行，未形成可审核的源码。", "提交解码后的明文源码，审核后再执行。"},
	"SG-OBF-002":     {"重建编码脚本", "代码从编码表示中重建可执行内容。", "用可审计的明文源码替换编码载荷。"},
	"SG-OBF-003":     {"长编码数据块", "长 Base64 样式数据块可能隐藏指令、代码或数据。", "保存可审核的解码内容，并记录其来源。"},
	"SG-OBF-005":     {"Base64 解码", "源码正在解码 Base64 内容；结果可能是普通数据，也可能是编码载荷。", "确认解码结果是预期数据，且不会交给动态执行器。"},
	"SG-PERSIST-001": {"计划任务持久化", "Skill 创建或启用了周期性后台任务。", "移除持久化行为，Skill 只应在明确调用时运行。"},
	"SG-PERSIST-002": {"修改启动配置", "内容指向登录、Shell 启动、自动运行或 SSH 授权文件。", "不要修改启动或授权文件，保持设置明确且可逆。"},
	"SG-SUPPLY-001":  {"包管理器生命周期钩子", "安装时生命周期钩子可能在审核前执行。", "移除生命周期钩子，让每一步设置都显式且可选。"},
	"SG-MAN-001":     {"缺少 Skill 名称", "SKILL.md frontmatter 必须声明可移植的 Skill 名称。", "在根目录 SKILL.md 的 frontmatter 中补充 name。"},
	"SG-MAN-002":     {"缺少 Skill 描述", "SKILL.md frontmatter 必须说明 Skill 的使用时机和用途。", "在根目录 SKILL.md 的 frontmatter 中补充 description。"},
	"SG-MAN-003":     {"缺少 SKILL.md", "没有根目录 SKILL.md 时，该包不是可移植的 Agent Skill。", "在待安装包根目录提供有效的 SKILL.md。"},
	"SG-MAN-004":     {"多 Skill 仓库", "仓库没有根目录 SKILL.md，但发现了嵌套的 Skill 清单；安装前应分别扫描子 Skill。", "扫描并安装包含自身 SKILL.md 的单个子目录。"},
	"SG-FILE-001":    {"跳过内容分析", "文件超过文本分析预算，但仍会检查其元数据并纳入完整包指纹。", "复核文件来源和校验和；如需源码分析，可提高 --max-file-size。"},
	"SG-FILE-003":    {"无法读取的文件系统对象", "文件系统对象无法被安全读取。", "修复权限或移除无法审核的对象。"},
	"SG-FILE-005":    {"无法读取的路径", "路径或文件元数据无法被安全读取。", "修复权限或移除无法审核的路径。"},
	"SG-FILE-006":    {"特殊文件系统对象", "包中包含普通文件和目录之外的特殊文件系统对象。", "移除特殊对象，仅发布可审核的普通文件。"},
	"SG-FILE-007":    {"带特权位的可执行文件", "文件带有可能改变执行权限的特权位。", "移除特权位，并重新审核可执行文件来源。"},
	"SG-LIMIT-002":   {"达到内容分析预算", "包体积超过内容分析预算，但剩余文件仍会纳入指纹和结构检查。", "复核剩余文件来源，或提高 --max-total-size 进行更深度分析。"},
}

var chineseDynamicTitles = map[string]map[string]string{
	"SG-FILE-002": {
		"Embedded executable":       "嵌入式可执行文件",
		"Native library dependency": "原生库依赖",
		"Opaque binary file":        "不透明二进制文件",
		"Opaque media asset":        "不透明媒体资源",
		"Opaque archive":            "不透明归档文件",
	},
}

func localizeFinding(finding model.Finding, language Language) findingText {
	result := findingText{Title: finding.Title, Description: finding.Description, Recommendation: finding.Recommendation}
	if language != LanguageChinese {
		return result
	}
	if localized, ok := chineseFindingText[finding.RuleID]; ok {
		return localized
	}
	if titles, ok := chineseDynamicTitles[finding.RuleID]; ok {
		if title, exists := titles[finding.Title]; exists {
			result.Title = title
		}
		result.Description = "二进制或媒体内容无法像 Skill 指令和源码一样被有效审核。"
		result.Recommendation = "移除该文件，或发布可复现的源码和经过验证的校验和。"
	}
	return result
}
