# Lawyer Assistance

[English](README.en.md)

Lawyer Assistance 是一款面向 Windows x86_64 的本地优先法律辅助工作台。它把公开法律检索、案件材料整理、引用核验、文书与图示成果、隐私审批，以及受控的 MCP/模型调用整合在同一个桌面应用中。

当前版本：`0.4.0-beta.2`

> [!WARNING]
> 当前版本是技术预发布版。现有 Windows 安装包未进行 Authenticode 签名，不具备受信任发布者身份；生产 OCR 与自动更新尚未启用。请仅从项目 Releases 下载文件，并在安装前核对 SHA-256 与随附 manifest。
>
> 源代码仓库当前公开。公开访问源码或下载文件不代表安装包已经签名，也不会自动启用 updater、取得 OCR 资格或完成正式发布验收。

## 主要能力

- **本地法律检索**：随应用提供只读法律数据库，支持法律、条文、历史版本、效力区间和关联关系检索；不需要模型即可使用。
- **普通聊天**：无需创建案件即可直接使用所选 BYOK Provider。输入区持续提示内容将发送到模型供应商；只发送当前消息、同一普通会话的有界历史和本次显式选择的普通附件正文，不读取案件工作区或 Vault。
- **案件工作台**：在本地管理案件、材料、当事人、事实、证据、争点、法律依据和相互关系。“材料与脱敏”负责导入、提取、人工复核和批准，“案件工作”承载案件助理、研究、文书与图谱工作。
- **隐私批准链**：案件材料先在应用内提取、识别、别名化和人工复核，只有不可变的明确批准版本才能进入指定用途；目的、目标、模型、有效期和撤销状态均会再次校验。
- **案件助理**：每次只使用用户在当前案件明确勾选的 approved/current 脱敏版本和已确认案件数据；后端在 Provider transport 前重新核验归属、版本、风险和撤销状态，输出先进入待确认状态。
- **21-tool approved MCP**：独立的 `approved_case_workspace` profile 精确包含 5 个公开法律工具、10 个 opaque-ID-only 案件/成果工具和 6 个批准图示工具。它默认关闭，仅在应用资格有效并签发短期 session/ticket 后按最小权限开放。
- **公开/合成图示**：`diagram_authoring` profile 提供 5 个公开法律工具和 6 个图示工具，仅允许合成或公开数据。其本地 HTML bundle 为明文，禁止用于真实案件；真实批准案件图示必须走 approved MCP 的加密成果链。
- **BYOK 模型接入**：用户自行提供 Provider API Key。应用支持 DeepSeek，以及 Qwen、SiliconFlow、Volcengine Ark 和自定义 OpenAI-compatible endpoint；密钥保存在 Windows Credential Manager，不写入普通配置文件。
- **宿主集成**：提供 WorkBuddy、Codex 和 OpenCode 的 public-only 集成，以及默认禁用、资格门控的 approved workspace 集成。

## 当前发布边界

| 项目 | `0.4.0-beta.2` 状态 |
| --- | --- |
| Windows x86_64 桌面应用 | 技术预发布 |
| 安装包 | NSIS，当前未签名 |
| 本地法律检索与案件工作台 | 可用 |
| BYOK 普通聊天与案件助理 | 已实现；调用所选 Provider 时会联网，案件助理仅使用明确选择的已批准材料 |
| 隐私批准链与 approved MCP | 已实现；默认关闭并严格资格门控 |
| `diagram_authoring` | 仅限合成/公开数据 |
| 生产 OCR | 未启用；扫描件/纯图像 PDF 不应视为已支持 |
| 自动更新 | 未启用；请手动检查 Releases |

本项目不是律师替代品，也不保证检索结果、模型输出或生成文书适用于具体案件。重要结论应由具备相应资质的专业人员核对原文、效力状态和案件事实。

## 下载与安装

### 系统要求

- Windows x86_64
- 足够的磁盘空间用于应用、随附法律数据库和本地工作数据
- 使用 BYOK Provider 时需要网络；纯本地法律检索不依赖 Provider

### 下载

前往 [GitHub Releases](https://github.com/shilittle/Lawyer-Assistance/releases)，下载与 `0.4.0-beta.2` 对应的以下文件：

- `Lawyer.Assistance_0.4.0-beta.2_windows-x86_64-unsigned-setup.exe`
- 同名 `.sha256`
- 同名 `.manifest.json`

如果 Releases 中不存在这些精确资产，请不要使用来源不明或被重新命名的安装包。当前预发布版不会生成可用的 updater `.sig` 或 `latest.json`。

### 校验

在 PowerShell 中计算安装包哈希：

```powershell
Get-FileHash `
  .\Lawyer.Assistance_0.4.0-beta.2_windows-x86_64-unsigned-setup.exe `
  -Algorithm SHA256
```

将结果与 `.sha256` 文件比较，并确认 manifest 中：

- `version` 为 `0.4.0-beta.2`
- `signed` 为 `false`
- `updaterArtifactGenerated` 为 `false`

校验通过后运行安装包。它采用当前用户安装模式。由于安装包尚未签名，Windows 可能显示未知发布者提示；请先确认文件名、来源和哈希，不要绕过来源不明文件的安全警告。

## 快速开始

1. 启动 Lawyer Assistance，在法律检索页搜索法律名称、关键词或条号。
2. 打开条文详情，核对来源、版本、效力区间和关联法规。
3. 如需普通模型对话，先在“设置 → Provider 与凭据”创建 BYOK Provider，再打开“助理”。无需创建案件；输入区会持续显示 Provider 外发提示。普通附件必须由用户在本次请求中显式选择，且不得包含未脱敏案件材料。
4. 如需案件整理，新建案件后进入“案件工作台 → 材料与脱敏”，完成本地提取、脱敏、人工复核和批准。可靠文本层可本地提取；当前不要依赖生产 OCR 处理扫描件。
5. 进入“案件工作台 → 案件工作”，为本次请求明确勾选当前案件的已批准脱敏版本，再使用案件助理；撤销或失效后必须重新选择。
6. OCR 配置、组件和资格位于“设置 → 本地处理环境与 OCR 组件”；本地 MCP、自动化出站批准和 Approved MCP 位于“设置 → MCP 与自动化”；应用更新、诊断、生命周期和五组件备份位于“设置 → 版本、备份与诊断”。
7. 如需外部宿主访问公开法律，使用默认的 `public_law_only` MCP：

```text
lawyer-assistance-mcp --privacy-profile public_law_only stdio
```

该 profile 必须精确列出以下 5 个只读工具：

```text
system_status
legal_search
legal_get_article
legal_get_versions
legal_get_relations
```

案件数据不得通过 public-only 集成发送。`approved_case_workspace` 只能由应用在完成材料批准、当前资格检查和最小权限授权后签发；宿主任务仅使用 opaque ID，不粘贴或附加案件正文。

## 文档导航

- [用户文档中心](docs/README.md)
- [完整快速开始](docs/getting-started.md)
- [当前发布状态](docs/release-status.md)
- [用户安全与隐私指南](docs/security-and-privacy.md)
- [法律数据集与运行时数据库](docs/data/legal-corpus.md)
- [贡献指南](CONTRIBUTING.md)
- [安全问题报告](SECURITY.md)
- [版本说明](RELEASE_NOTES.md)
- [MCP 总览](docs/mcp/README.md)
- [MCP 安装与运行](docs/mcp/installation.md)
- [approved case workspace](docs/mcp/approved-case-workspace.md)
- [MCP 安全与隐私边界](docs/mcp/security-and-privacy.md)
- [兼容性矩阵](docs/mcp/compatibility-matrix.md)
- [图示架构](docs/diagrams/architecture.md)
- [图示示例](docs/diagrams/examples.md)
- [WorkBuddy 集成](integrations/workbuddy/README.md)
- [Codex 集成](integrations/codex/README.md)
- [OpenCode 集成](integrations/opencode/README.md)
- [仓库目录指南](docs/development/repository-layout.md)

## 开发与构建

### 环境

- Windows 与 MSVC Rust toolchain
- Node.js `>=24`
- pnpm `>=11`（仓库声明 `pnpm@11.7.0`）
- Python 3

安装依赖：

```powershell
pnpm install
```

常用检查与前端构建：

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features --offline -- -D warnings
cargo test --locked --workspace --offline
pnpm lint
pnpm test
pnpm build
```

构建独立 MCP：

```powershell
cargo build --locked -p legal-mcp --bin lawyer-assistance-mcp
```

构建明确标记为未签名的 Windows 技术安装包：

```powershell
pnpm --filter @lawyer-assistance/desktop release:installer:unsigned
```

正式桌面构建需要生成并校验：

```text
apps/desktop/src-tauri/resources/legal_core.sqlite
data/generated/legal_core_distribution_manifest.json
```

大型法律数据库是生成/发布资源，不作为普通 Git blob 提交。构建还会校验许可证、第三方 notices、前端产物，以及打包 MCP sibling 与应用之间的哈希绑定。完整开发约束见 [目录指南](docs/development/repository-layout.md) 和 [MCP 开发文档](docs/mcp/development-and-testing.md)。

## 安全与隐私

- **本地优先不等于永不联网**：法律检索、案件存储和大部分工作台能力在本地运行；BYOK Provider 请求会发送到用户选择的第三方服务。
- **普通聊天不读取案件材料**：普通聊天只发送用户输入、同一普通会话的有界历史和本次显式选择的普通附件正文。案件文件应先进入“案件工作台 → 材料与脱敏”，不得把普通附件当作案件材料绕过复核。
- **案件助理与自动化分离**：案件助理使用当前案件的 approved-only 投影和已确认数据；MCP 与自动化继续使用独立的 publication、qualification、grant、ticket 和撤销边界。
- **批准不是通用授权**：材料被本地标记为 approved 后，仍需绑定精确目标、用途、模型、版本、有效期和撤销状态。
- **public MCP 不含案件能力**：默认 profile 只有 5 个公开法律只读工具。
- **approved MCP 最小授权**：21-tool profile 的非公开能力按 `read`、`write`、`diagram_read`、`diagram_write` 分组，任何缺失、过期、撤销或不匹配状态均 fail closed。
- **不要把原始案件材料粘贴到外部宿主**：WorkBuddy、Codex、OpenCode 或其他模型宿主可能在集成规则加载前处理附件或首条消息；规则无法撤回已经发生的披露。
- **凭据保护**：Provider Key 使用 Windows Credential Manager；应用只向前端返回配置状态或掩码。
- **网络边界**：MCP HTTP 默认仅允许 loopback。不要把明文非 loopback 监听作为生产入口。
- **本地保护的可移植性**：部分加密状态使用 Windows DPAPI CurrentUser 绑定，复制文件并不会转移资格或授权。

发现安全问题时，请避免在公开 issue 中附加真实案件材料、凭据、数据库或日志原文；仅提交最小化、脱敏且可复现的信息。

## 许可证

源代码采用 [MIT License](LICENSE)。

应用随附的第三方组件、法律数据和来源材料可能适用各自的许可、使用条款与署名要求。详见：

- [第三方 notices](apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt)
- [数据来源说明](apps/desktop/src-tauri/resources/DATA_SOURCES.md)
