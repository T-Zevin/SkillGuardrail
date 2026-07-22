<h1 align="center">SkillGuardrail</h1>

<p align="center">
  简体中文 · <a href="README.en.md">English</a>
</p>

<p align="center">
  <a href="https://github.com/T-Zevin/SkillGuardrail/actions/workflows/ci.yml"><img alt="构建" src="https://github.com/T-Zevin/SkillGuardrail/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/releases"><img alt="版本" src="https://img.shields.io/github/v/release/T-Zevin/SkillGuardrail?display_name=tag&amp;sort=semver"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/releases"><img alt="下载量" src="https://img.shields.io/github/downloads/T-Zevin/SkillGuardrail/total"></a>
  <a href="go.mod"><img alt="Go 版本" src="https://img.shields.io/github/go-mod/go-version/T-Zevin/SkillGuardrail?logo=go"></a>
  <a href="LICENSE"><img alt="许可证" src="https://img.shields.io/github/license/T-Zevin/SkillGuardrail"></a>
  <a href="#平台支持"><img alt="平台" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-5c6ac4"></a>
  <a href="https://github.com/T-Zevin/SkillGuardrail/commits/main"><img alt="最近提交" src="https://img.shields.io/github/last-commit/T-Zevin/SkillGuardrail"></a>
</p>

![SkillGuardrail：Agent Skills 安全护栏](assets/skillguardrail-hero.png)

**在 Agent 读取之前先扫描，只安装你真正信任的 Skill。**

SkillGuardrail 是一个开源的 Agent Skills 安装前安全扫描器和受控安装工具。它把公开 GitHub 包下载到私有隔离区，并把本地目录复制成有资源上限的私有快照；完成确定性静态检查、能力推断和策略判定，得到明确批准后才写入 Codex、Claude Code、Cursor、Gemini CLI 或 OpenClaw 的 Skill 目录。

> SkillGuardrail 只能降低风险，不能证明一个 Skill 绝对安全。请继续使用最小权限、Agent 沙箱和人工复核。

| **先隔离** | **不止打分，更能执行策略** | **安装结果可验证** |
|:---|:---|:---|
| 在不运行包内代码的前提下检查不可信 Skill。 | 将风险发现与能力链转化为明确、可执行的判定。 | 用来源 commit、内容指纹和外部 receipt 绑定安装结果。 |

## 目录

- [核心区别](#核心区别)
- [安装](#安装)
  - [平台支持](#平台支持)
- [使用](#使用)
- [命令与参数说明](#命令与参数说明)
- [判定与退出码](#判定与退出码)
- [相关工作](#相关工作)
- [许可证](#许可证)

## 核心区别

它不只是输出一份扫描分数，还覆盖完整安装事务：

```text
不可信来源 → 隔离获取 → 静态扫描 → 风险判定 → 明确批准
                                              ↓
                                  原子安装 + 文件级 receipt
                                              ↓
                                         后续篡改验证
```

- GitHub 可变分支先解析成不可变 commit；
- 仅从 GitHub 官方 API 和 codeload 获取公开仓库；
- 安全解包，拒绝路径穿越、软硬链接、特殊文件、大小写碰撞和压缩炸弹；
- 扫描过程中不执行 Skill 脚本、解释器、包管理器或安装钩子；
- 检查 Prompt Injection、敏感凭据访问、外传、危险命令、持久化、混淆、二进制和供应链风险；
- 安装前再次扫描 staging 内容，随后在同一文件系统原子切换；
- 权威 receipt 保存在 Skill 目录之外的私有状态目录，并绑定规范化安装路径；包内 `.skillguardrail.lock` 只是便于查看的镜像，不能给自己背书；
- receipt 记录来源 commit、归档哈希、包指纹、条目类型与权限、逐文件 SHA-256、风险发现和能力清单；
- `verify` 可以发现安装后的新增、删除和修改。

## 安装

使用 Go 1.23 或更高版本：

```bash
go install github.com/T-Zevin/SkillGuardrail/cmd/skillguardrail@latest
```

通过该方式安装时，工具版本来自 Go 模块构建信息；官方 Release 归档还会写入标签对应的提交和构建时间。

发布版本可从 [GitHub Releases](https://github.com/T-Zevin/SkillGuardrail/releases) 下载，并使用 `checksums.txt` 校验。

通过 Homebrew 安装：

```bash
brew install T-Zevin/tap/skillguardrail
```

已安装旧版本时更新：

```bash
brew update
brew upgrade T-Zevin/tap/skillguardrail
```

### 平台支持

macOS、Linux 和 Windows 均支持扫描及报告输出。受控 `install` 和 `verify` 初版仅在 macOS 与 Linux 启用：除普通权限位外，工具还会清除并验证扩展 ACL/POSIX ACL；如果文件系统无法证明 ACL 不存在，也会默认拒绝。其他平台不会启用受控操作，但 Windows 用户仍可先扫描，再手动安装已复核文件。

macOS 上的受控操作只会为 ACL 处理调用固定系统工具 `/bin/chmod` 和 `/bin/ls`，不会调用 Skill 自带的可执行文件、脚本、解释器或安装钩子。

## 使用

扫描本地 Skill：

```bash
skillguardrail scan ./my-skill
```

扫描公开 GitHub 仓库：

```bash
skillguardrail scan https://github.com/example/useful-skill
```

如果仓库根目录没有 `SKILL.md`，但只包含一个嵌套 Skill，SkillGuardrail 会自动选择该 Skill 目录进行扫描。若仓库包含多个嵌套 Skill，则保留仓库级扫描结果，避免在没有用户确认时自动选错安装对象。

在交互式终端中，扫描会显示阶段进度条，提示当前处于来源解析、隔离获取或静态分析阶段。进度信息写入 stderr；JSON、SARIF、重定向日志和其他非交互输出不会被进度内容污染。

默认 `scan` 超时为 20 分钟，`install` 为 15 分钟，因为公共 GitHub 归档在代理或受限网络下可能较慢。下载时终端会显示归档的已下载/总量；传输中断后会清空不完整的临时归档并有限重试。网络特别慢时可显式使用 `--timeout 25m`。

远程来源默认有明确边界：GitHub 压缩归档 64 MiB、解包后文件总量 128 MiB、tar 未压缩流 160 MiB、来源条目 10,000 个。这些限制用于防止不可信归档耗尽磁盘或内存，同时覆盖常见的多 Skill 仓库。更大的仓库可以在内置硬上限内显式提高 `--max-archive-size`、`--max-extract-size`、`--max-uncompressed-size` 和 `--max-source-entries`。

超过文本分析预算的大文件仍会纳入完整包指纹；报告会把已知规则信号评分、扫描状态和内容覆盖率分开，并列出仅完成元数据/哈希检查的文件。评分不是被攻陷概率；`0` 只代表当前规则没有命中已知信号，不代表剩余风险为零。每份报告都会标注 `not-proven-safe`（未证明安全）。看起来干净的结果只是有边界的静态分析结果，不是安全证明。

输出 JSON 或 SARIF：

```bash
skillguardrail scan ./my-skill --format json
skillguardrail scan ./my-skill --format sarif --output skillguardrail.sarif
```

文本报告默认使用英文；加上 `-cn` 后切换为简体中文，并会以摘要表、评分条、项目结构树、能力表和发现表展示结果：

```bash
skillguardrail scan ./my-skill -cn
```

`-cn` 只影响人类可读的文本输出；JSON 和 SARIF 保持稳定的机器可读字段，适合 CI 和下游脚本。
终端支持颜色时默认会启用颜色；只有在日志或 CI 需要纯文本时才添加 `--no-color`。

扫描通过后安装到 Codex：

```bash
skillguardrail install https://github.com/example/useful-skill --target codex --yes
```

目标目录和权威状态根目录必须归当前用户所有，且不能让其他用户写入。自定义 `--state-dir` 在 Unix 上应使用 `0700` 权限。使用 `--replace` 时，旧 Skill 会保存在唯一的私有备份目录，成功后命令会输出具体路径。

验证已安装内容是否变化：

```bash
skillguardrail verify my-skill --target codex
skillguardrail verify ~/.codex/skills/my-skill
```

默认权威 receipt 位于当前用户的 SkillGuardrail 配置状态目录。受控操作会验证目录所有者与父目录替换边界，并拒绝未清除的文件系统 ACL，避免出现 receipt 未记录的额外访问权限。备份或自动化场景可通过 `SKILLGUARDRAIL_STATE_HOME` 或安装、验证命令的 `--state-dir` 指定其他位置，但它必须保持私有并位于 Agent 的 Skill 发现目录之外。该机制用于发现本地漂移，并不是发布者签名；若同一用户权限下的进程可以同时改写 Skill 和外部状态目录，它仍可伪造本地历史。

远程源支持公开 GitHub HTTPS 仓库。仓库根目录有 Skill，或只有一个嵌套 Skill 时可以直接扫描；多个嵌套 Skill 会保留仓库级结果，等待用户明确选择。

## 命令与参数说明

所有命令都可使用 `skillguardrail <command> --help` 查看运行版本的完整帮助。`SOURCE` 可以是本地 Skill 目录、本地 `SKILL.md`，或公开 GitHub 仓库根 URL；远程仓库只接受 `https://github.com/OWNER/REPO` 形式。

### `scan SOURCE`：只扫描，不写入 Agent 目录

```bash
skillguardrail scan SOURCE [options]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-cn` | 关闭 | 将人类可读文本报告切换为简体中文；JSON/SARIF 字段保持不变。 |
| `--format text\|json\|sarif` | `text` | 选择报告格式。`json` 与 `sarif` 适用于 CI 或后续脚本。 |
| `--output PATH` | 标准输出 | 将报告写入文件；使用 `-` 保持标准输出。写入文件时不显示交互进度条。 |
| `--fail-on info\|low\|medium\|high\|critical` | `medium` | 发现达到该级别的信号时返回退出码 `1`。例如仅希望 High/critical 退出失败，可设为 `--fail-on high`。 |
| `--timeout DURATION` | `20m` | 获取和扫描的总时间上限，如 `--timeout 25m`。 |
| `--no-color` | 关闭 | 禁用 ANSI 颜色，适合日志、CI 或纯文本文件。 |

**内容分析边界**：这些参数控制本地扫描量；超过边界的文件仍会纳入包指纹和结构检查，但不会完成完整文本分析。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--max-files N` | `10000` | 包内最多扫描的条目数。 |
| `--max-file-size BYTES` | `8388608`（8 MiB） | 单个文件可进行内容分析的最大字节数。 |
| `--max-total-size BYTES` | `67108864`（64 MiB） | 所有内容分析文件合计的最大字节数。 |

**GitHub 来源边界**：用于限制下载和解包阶段，防止不可信 archive 耗尽资源。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--max-archive-size BYTES` | `67108864`（64 MiB） | 下载的压缩 GitHub archive 最大大小。 |
| `--max-extract-size BYTES` | `134217728`（128 MiB） | 解包并复制到隔离区的文件总大小上限。 |
| `--max-uncompressed-size BYTES` | `167772160`（160 MiB） | tar 解压数据流最大大小。 |
| `--max-source-entries N` | `10000` | archive 最多允许的来源条目数。 |

### `install SOURCE`：扫描、人工批准后受控安装

```bash
skillguardrail install SOURCE --target codex --yes [options]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--target codex\|claude\|cursor\|gemini\|openclaw` | 无 | 选择内置 Agent Skill 目录；与 `--dir` 至少提供一个。 |
| `--dir PATH` | 无 | 指定自定义的 Skill 发现目录。 |
| `--yes` | 关闭 | 必填确认项；没有它只会显示报告，不会写入文件。 |
| `--allow-risk info\|low\|medium` | `medium` | 允许安装的最高复核级别；`block` 与 `critical` 永远不能绕过。 |
| `--replace` | 关闭 | 安全备份并原子替换同名已安装 Skill。 |
| `--state-dir PATH` | 工具默认私有状态目录 | 保存权威 receipt 的私有目录；Unix 上应为 `0700`，且位于 Agent Skill 目录之外。 |
| `-cn`、`--no-color`、`--timeout DURATION` | — | 分别控制中文报告、颜色和总时间上限（安装默认 `15m`）。 |
| `--max-archive-size`、`--max-extract-size`、`--max-uncompressed-size`、`--max-source-entries` | 同 `scan` | 调整 GitHub 获取和隔离阶段的资源边界。 |

### `verify PATH`：验证受控安装后是否被篡改

```bash
skillguardrail verify PATH [options]
skillguardrail verify NAME --target codex [options]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--target AGENT` | 无 | 当第一个位置参数是安装名称而不是路径时，用于定位内置 Agent 的 Skill 目录。 |
| `--dir PATH` | 无 | 使用自定义 Skill 目录定位安装名称。 |
| `--format text\|json` | `text` | 输出人类可读结果或机器可读 JSON。 |
| `--state-dir PATH` | 工具默认私有状态目录 | 指定保存权威 receipt 的状态目录，必须与安装时一致。 |

### 其他命令

```bash
skillguardrail --help
skillguardrail scan --help
skillguardrail install --help
skillguardrail verify --help
skillguardrail version
```

## 判定与退出码

| 判定 | 默认行为 |
| --- | --- |
| `pass` | 未发现已知阻断信号；不代表零风险，仍需复核来源和能力 |
| `review` | 存在 Medium 风险，需要明确决定 |
| `block` | 存在 High 风险或累计风险达到阈值，禁止安装 |
| `critical` | 关键行为链或安全边界破坏，禁止覆盖 |

| 退出码 | 含义 |
| ---: | --- |
| `0` | 策略允许或命令成功 |
| `1` | 需要复核或策略拒绝 |
| `2` | 参数、获取、解析、扫描或 I/O 失败，结果不完整 |
| `3` | 操作取消或缺少明确的 `--yes` |

规则目录见 [docs/rules.md](docs/rules.md)，安全边界与已知限制见 [docs/threat-model.md](docs/threat-model.md)。

## 相关工作

项目设计参考了 [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)、[Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner)、[Agent Skills 规范](https://agentskills.io/specification)和 [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)，代码与安全安装事务为独立实现，不代表上述项目对 SkillGuardrail 的认证或背书。

## 许可证

[Apache License 2.0](LICENSE)
