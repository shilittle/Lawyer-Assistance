# 仓库结构与目录规范

本文档说明代码、数据、测试、宿主集成、模板和生成文件的稳定位置。新增目录、移动代码或增加新功能前，请先检查本规范。

## 仓库原则

- 前端保持轻量：`apps/desktop/src` 只放 UI、视图状态和 typed IPC client。
- 业务逻辑放在 Rust crates 中。
- 所有 Tauri command 都必须在 Rust 和 TypeScript 两侧有明确类型。
- 领域概念放在 `crates/domain`，不要在前端重复定义业务结构。
- SQLite 连接和迁移放在 `crates/database`。
- 检索排序、版本过滤和法律关系查询放在 `crates/retrieval`。
- Provider 请求、模型适配和凭据访问放在 `crates/providers`。
- 引用解析、校验和来源映射放在 `crates/citations`。
- 助理能力契约、结构化 Artifact 校验与纯渲染放在 `crates/assistant`。
- 闭合图示 schema、固定模板和确定性渲染放在 `crates/diagrams`。
- 本地文件格式检测、限额和确定性提取放在 `crates/file-ingest`。
- 本地 OCR/材料处理、worker 协议、进程树与隔离编排放在 `crates/material-processing`。
- Privacy store、项目/隐私身份绑定、Vault、批准投影、出站分类、生命周期和备份契约放在 `crates/privacy`。
- UI 与协议无关的应用编排、写入审计和文件边界放在 `crates/legal-services`。
- MCP schema、stdio/Streamable HTTP 传输和 CLI 适配放在 `crates/legal-mcp`。
- Tauri 不得启动 sidecar；桌面设置页只可在用户手动启动或显式保存自动启动后，
  在进程内监听 loopback HTTP。独立 `lawyer-assistance-mcp serve` 继续服务于
  外部宿主和网络部署。仍禁止为产品运行时新增 Python/Node、本地模型或
  embedding runtime。
- 禁止提交构建产物、包缓存、前端 bundle、`target` 或 `node_modules`。

## 根目录

```text
.
+-- apps/
|   +-- desktop/
+-- crates/
|   +-- assistant/
|   +-- citations/
|   +-- database/
|   +-- diagrams/
|   +-- domain/
|   +-- file-ingest/
|   +-- legal-mcp/
|   +-- legal-services/
|   +-- material-processing/
|   +-- privacy/
|   +-- providers/
|   +-- retrieval/
+-- integrations/
|   +-- workbuddy/
|   +-- codex/
|   +-- opencode/
+-- docs/
+-- .github/
+-- .cargo/
+-- Cargo.toml
+-- package.json
+-- pnpm-workspace.yaml
+-- README.md
```

根目录文件只处理 workspace 级事务：

- `Cargo.toml`：Rust workspace 成员和共享依赖版本。
- `package.json`：workspace 脚本入口。
- `pnpm-workspace.yaml`：pnpm workspace 包范围和依赖构建策略。
- `.cargo/config.toml`：Windows x86_64 target 配置。
- `.github/workflows/`：CI。
- `README.md`：项目入口、命令和文档链接。

`integrations/` 只保存宿主配置、可安装 Skill、Agent 指引和离线示例校验；
不得在三个宿主目录维护分叉的 MCP 实现或不同工具 schema。

## 前端目录：`apps/desktop/src`

前端职责：

- 渲染 UI。
- 管理视图状态。
- 调用 typed IPC client。
- 展示 Rust 返回的 typed response。

前端禁止：

- 执行 SQLite 查询。
- 构造任意 SQL。
- 调用模型 API。
- 在初次提交后访问完整 API Key。
- 校验法律引用。
- 直接生成或落盘 PDF（前端只提交 typed IPC 请求，Markdown/PDF 渲染由受测模块完成）。
- 把本地 dev server 当作产品架构的一部分。

当前前端边界：

```text
apps/desktop/src/
+-- app/
|   +-- AppErrorBoundary.tsx
|   +-- AppRouter.tsx
|   +-- AppShell.tsx
|   +-- navigationGuards.ts
|   +-- routes.ts
|   +-- views.ts
+-- features/
|   +-- assistant/
|   +-- artifacts/
|   +-- cases/
|   +-- legal-library/
|   +-- privacy/
|   +-- settings/
|       +-- automation/
|       +-- local-processing/
|       +-- maintenance/
|       +-- providers/
+-- ipc/
|   +-- assistant/
|   +-- case/
|   +-- case-assistant/
|   +-- document/
|   +-- graph/
|   +-- health/
|   +-- legal/
|   +-- mcp/
|   +-- privacy/
|   +-- provider/
|   +-- release/
+-- App.tsx
+-- main.tsx
+-- styles.css
```

放置规则：

- `app/`：仅放 typed route、顶层产品导航、标题、错误边界、导航/关窗保护和 workspace slot 映射；当前顶层固定为助理、案件工作台、法律库、设置。
- `features/assistant/`：conversation-first 普通聊天工作区、显式普通附件和持续 Provider 外发提示。它只调用 `start_interactive_assistant_run`，不得读取案件、Privacy、Vault 或 MCP 状态。
- `features/artifacts/`：Research/Document/Map Artifact 预览、版本编辑、导出、案件绑定及 proposal 审阅。
- `features/cases/`：案件工作台的概览、材料与脱敏、案件工作、成果，以及只使用 approved-only 投影的案件助理。案件助理只调用 `start_case_assistant_run`。
- `features/privacy/`：保留案件材料和维护页面共享的 review、risk、lifecycle 与样式模块；它不再拥有顶层 `PrivacyWorkspace` 或 `settings:privacy` 产品路由。
- `features/settings/providers/`：Provider profile 和凭据设置。
- `features/settings/local-processing/`：Privacy/OCR 配置、MinerU 组件管理和资格控制的唯一设置 owner；typed route 为 `settings:local-processing`。
- `features/settings/automation/`：本地 MCP、自动化出站批准和 Approved MCP 的唯一设置 owner；三类 activity 独立聚合。
- `features/settings/maintenance/`：应用更新/诊断与 Privacy 生命周期、映射、清理和五组件备份/恢复的高级维护 owner。
- `features/legal-library/`：本地法律检索和兼容引用问答；不得把旧 Provider redirect 恢复为普通聊天或案件工作的 fallback。
- `ipc/<group>/`：Tauri command 的 TypeScript 类型和 typed client。
- UI 状态可放在 feature 邻近 hooks/state 模块；持久化业务状态只由 Rust 和 SQLite 管理。
- 共享前端视图类型必须来自 typed IPC 契约或与其严格镜像。

IPC 规则：

- UI 组件调用 `searchLaws()`、`healthCheck()` 这类本地 wrapper。
- 只有 `src/ipc/` 下的文件可以 import `@tauri-apps/api/core` 的 `invoke`。

## Tauri 目录：`apps/desktop/src-tauri`

Tauri 层职责：

- 注册窗口。
- 注册 commands。
- 初始化 app state。
- 解析应用路径。
- 打包资源。

推荐结构：

```text
apps/desktop/src-tauri/
+-- capabilities/
+-- icons/
+-- resources/
|   +-- legal_core.sqlite
+-- src/
|   +-- commands/
|   +-- state.rs
|   +-- lib.rs
|   +-- main.rs
+-- build.rs
+-- Cargo.toml
+-- tauri.conf.json
```

放置规则：

- `src/lib.rs`：app builder、setup、command 注册。
- `src/main.rs`：二进制入口。
- `src/state.rs`：共享 Rust app state。
- `src/commands/`：薄 command handler，只做 IPC 到 crate 调用的转换。
- `resources/legal_core.sqlite`：随应用打包的核心法律数据库。
- `capabilities/`：Tauri 权限定义。
- `icons/`：Windows 应用图标。

Command 规则：

- Command 必须尽量薄，重逻辑放到 crates。
- Command 返回 typed struct，不返回临时拼出来的 JSON。
- 只有 provider 扩展参数这类明确需要动态字段的地方可以使用受控 `serde_json::Value`。
- Command 必须把内部错误转换成稳定 IPC error shape。

## Rust Crates

### `crates/domain`

负责共享业务词汇：

- health response
- law document
- law version
- law article
- case project
- fact
- evidence
- provider profile
- citation source
- graph node / edge

规则：

- 不放 SQLite 连接代码。
- 不放 HTTP client 代码。
- 不依赖 Tauri。
- 跨 IPC 的类型必须可序列化。

### `crates/database`

负责 SQLite 访问：

- 连接打开。
- PRAGMA 设置。
- 迁移。
- 事务 helper。
- 路径 helper。
- schema 校验。

规则：

- `legal_core.sqlite` 只读打开。
- `user.sqlite` 可写，并由迁移管理。
- API Key 永远不放这里。
- 测试使用临时 SQLite 文件。

### `crates/retrieval`

负责法律检索行为：

- 标题检索。
- 法条全文检索。
- BM25 排序。
- 按日期过滤有效版本。
- 版本和关系遍历。
- 检索结果结构化。

规则：

- 可以依赖 `database` 和 `domain`。
- 对外暴露领域函数，不向前端暴露 SQL。
- 使用 fixture 数据库测试检索行为。

### `crates/providers`

负责模型供应商和凭据：

- 凭据存储接口。
- Windows Credential Manager 实现。
- Provider Profile。
- OpenAI-compatible adapter。
- 供应商差异参数转换。
- 流式解析。
- 测试连接。

规则：

- 完整 API Key 不离开该 crate，除非作为出站 Authorization header。
- Debug 和日志必须脱敏。
- 测试使用进程内 mock transport。
- CI 不调用真实收费 API。

### `crates/citations`

负责来源身份和引用校验：

- `[SRC:...]` 解析。
- 引用 ID 生成。
- 引用校验。
- 来源到法律、版本、法条、段落的映射。
- 不支持引用的报告。

规则：

- 模型输出默认不可信。
- 展示给用户的每个法律引用都必须映射到本地数据。
- 无效引用处理必须确定、可测试。

### `crates/assistant`

负责与 Provider 无关的有界助理契约：

- 十项受控能力的名称、权限、预算和确认要求。
- `DocumentSpec`、`MapSpec`、`CaseChangeSpec` 及闭合响应 envelope。
- 结构化输出验证、Document Markdown/DOCX 和 Map JSON/摘要渲染。

规则：

- 不访问 Tauri、SQLite、Credential Manager、网络或用户文件路径。
- 所有模型结构都拒绝未知字段，并在数量、文本、引用、节点和边上失败关闭。
- 模型产生的数据只能经 Tauri 编排层显式分派，不能自行选择任意 command。

### `crates/file-ingest`

负责 PDF、DOCX、UTF-8 TXT 和 Markdown 的确定性文件检测与文本提取：

- basename、扩展名、magic/容器一致性和 SHA-256。
- 原始大小、PDF 页数、DOCX entry/解压/压缩比、正文和 locator 上限。
- 宏、脚本、嵌入对象、ZIP 穿越、加密或无文本文件的明确拒绝。

规则：

- crate 只接收安全 basename 与 bytes，不接收任意本地路径。
- 不记录正文或 parser 内部细节；稳定错误不得回显敏感文件内容。
- 旧 `.doc` 和批量压缩包不在当前支持范围。视觉 OCR 的资格、worker、网络隔离和运行编排由 `material-processing` 与 Privacy/Tauri 受信边界负责，不得塞入本 crate 的普通提取路径。

### `crates/diagrams`

负责闭合图示 schema、固定模板、确定性渲染、更新和导出描述符校验。

规则：

- 合成/公开图示与 approved-case 图示共用受测 schema 和渲染核心，但使用不同存储与授权边界。
- 不接受脚本、外部资源、任意 HTML、路径或 URI。
- approved-case HTML 只能由受控 work-product 服务加密保存。

### `crates/material-processing`

负责本地材料处理和 MinerU worker 编排，包括原生/视觉路由、worker 协议、运行时配置、进程树、网络隔离、输出校验和安全派生导出。

规则：

- 不提供 HTTP、SSH、云 OCR 或远程模型回退。
- 真实视觉 OCR 只有在当前组件、运行时、模型、防火墙和资格 tuple 全部有效时才能运行。
- worker 输入输出、页数、几何、置信度、文件集和临时目录均执行有界校验与清理。

### `crates/privacy`

负责 Privacy store、ProjectId 与 PrivacyCaseId 的审计型一对一绑定、Vault、脱敏 finding/risk/review、approved-only 投影、receipt、qualification、MCP ticket、egress classification、生命周期和五组件备份契约。

规则：

- `ProjectId` 与严格 `PrivacyCaseId` 只能通过可信后端持久化绑定解析；前端不得生成或猜测 Privacy 身份。
- raw、pending、approved、interactive user content 和 secret 分类不得互相降级。
- binding、risk、selection、lifecycle 和迁移证据保持 append-preserving；安全关键冲突必须 fail closed。
- 任何案件正文恢复都通过受限 loader/service，不向前端、MCP handler 或普通日志暴露 Vault 路径、原文或密钥。

### `crates/legal-services`

负责 Tauri 与 MCP 共用的应用服务：数据库身份检查、受限检索、确定性引用
校验、案件 proposal/apply、revision CAS、写入审计、文书生成和受限原子导出。

规则：

- 不依赖 Tauri、Windows、HTTP 或 MCP。
- 所有公开请求、响应和错误均有显式 `schemaVersion`。
- 写操作必须在 `BEGIN IMMEDIATE` 事务中完成业务变更与审计，冲突不得覆盖。
- 文件路径必须 canonicalize，并限制在配置的 allowed roots/output root 内。

### `crates/legal-mcp`

负责同一工具注册表的 stdio 与 Streamable HTTP 暴露、MCP 注解、结构化输出、
请求限额、Origin/Host/Bearer 校验和敏感日志脱敏。

规则：

- 只调用 `legal-services`，不得调用 Tauri IPC 或复制法律业务逻辑。
- stdout 在 stdio 模式下只输出 MCP 消息；诊断仅写 stderr。
- HTTP 默认 loopback，非 loopback 没有显式认证时拒绝启动。
- WorkBuddy、Codex、OpenCode 差异仅留在 `integrations/` 配置与工作流中。

## 未来可增加的 Crates

只有当新边界足够稳定，并且继续塞进现有 crate 会变得臃肿时，才新增 crate。

可能的未来 crates：

- `case_analysis`：案件事实、证据缺口、结构化模型结果。
- `documents`：Markdown 预览、模板渲染、PDF 导出。
- `credentials`：如果凭据管理超出 provider 范围再拆。
- `diagnostics`：崩溃日志和诊断信息。

不要为了长期设想创建空 crate。只有阶段任务真正需要代码和测试时再加。

## 数据和生成资产

未来推荐结构：

```text
data/
+-- schema/
+-- migrations/
+-- sources/
+-- build/
+-- generated/
```

规则：

- `data/schema/`：纳入版本控制的 schema 定义。
- `data/migrations/`：纳入版本控制的迁移文件。
- `data/sources/`：来源元数据和小型人工 fixture。
- `data/build/`：开发侧构建脚本和临时输出。
- `data/generated/`：生成的法律数据库资产。
- 开发侧数据准备可以使用 Python，但 Python 不能成为打包应用的运行时。
- 大型生成数据库是否提交必须经过明确发布决策。

## 样例数据和正式数据边界

必须严格区分三类数据：

- fixture/sample 数据：只用于测试、UI 闭环或开发演示。
- generated 数据：由构建流水线生成，等待审计的候选正式数据。
- packaged 数据：已通过审计并随应用打包的 `legal_core.sqlite`。

放置规则：

- fixture/sample 数据只能放在 `tests/fixtures/`、crate-local test fixture 目录或明确命名为 fixture 的测试目录。
- fixture/sample 文件名必须包含 `fixture`、`sample` 或 `test`，避免被误认为正式数据库。
- `data/sources/` 保存真实数据来源清单、范围说明和来源元数据。
- `data/build/` 保存开发侧数据构建脚本。
- `data/generated/` 保存生成出来、尚未打包的数据库候选产物。
- `apps/desktop/src-tauri/resources/legal_core.sqlite` 只能放已通过数据审计的 packaged 数据库。

禁止：

- 把测试 fixture 复制成 `apps/desktop/src-tauri/resources/legal_core.sqlite` 后声称阶段完成。
- 在正式 `legal_core.sqlite` 中混入 `sample`、`demo`、`fixture`、`test` 数据。
- 没有 `coverage.md`、source manifest 和构建报告就声称真实法律库完成。
- 用少量人工条目代替声明范围内的真实法律数据。

正式 `legal_core.sqlite` 至少应能追溯：

- 数据范围声明。
- 来源清单 hash。
- 构建时间。
- schema 版本。
- 文档、版本、法条、FTS、关系的数量统计。
- 缺失来源、重复 ID、无效关系端点等审计结果。

## Prompts 和 Templates

未来推荐结构：

```text
prompts/
+-- common_constraints.md
+-- query_rewrite.md
+-- cited_answer.md
+-- fact_extraction.md
+-- evidence_gap.md
+-- document_draft.md

templates/
+-- complaint/
+-- defence/
+-- evidence_list/
+-- research_report/
+-- lawyer_letter/
```

规则：

- Prompt 跟随应用版本和法律库快照一起版本化。
- 涉及法律结论的 Prompt 必须要求来源约束。
- Template 定义必填字段和输出结构。
- Template 渲染由 Rust 完成。

## 测试目录

未来推荐结构：

```text
tests/
+-- fixtures/
+-- retrieval_cases/
+-- provider_contracts/
+-- citation_cases/
+-- golden_documents/
```

规则：

- crate 内部单元测试放在对应 Rust 模块旁边。
- 跨 crate 集成 fixture 放在根 `tests/`。
- Provider 测试使用 mock transport，不调用真实 API。
- 文书测试比较结构或稳定生成资产，不比较完整模型自然语言。
- 检索测试使用小型 fixture 数据库。

## 新增 Tauri Command 流程

必须完成：

1. 在合适 crate 中定义 Rust request 和 response 类型。
2. 在 `apps/desktop/src-tauri/src/commands/` 增加 command handler。
3. 在 `src-tauri/src/lib.rs` 注册 command。
4. 在 `apps/desktop/src/ipc/<group>/` 增加 TypeScript request 和 response 类型。
5. 增加 typed IPC client wrapper。
6. 为 command 邻近逻辑增加 Rust 测试。
7. 对有格式化或展示逻辑的前端增加测试。
8. 运行完整验证命令。

命名：

- Rust command：`snake_case`。
- TypeScript wrapper：`camelCase`。
- 请求类型：`<CommandName>Request`。
- 响应类型：`<CommandName>Response`。

## 新增 SQLite 行为流程

必须完成：

1. 新增或更新 schema / migration 文件。
2. 增加 Rust 迁移测试。
3. 在 `database` 增加查询函数，或在 `retrieval` 增加检索函数。
4. 返回 typed domain result。
5. 只通过领域 command 暴露给前端。
6. 增加 fixture 测试。

禁止：

- 前端 SQL。
- 用用户输入拼接 SQL 字符串。
- 没有测试的 schema 变更。
- API Key 字段。

## 新增 Provider 行为流程

必须完成：

1. 增加 typed provider option。
2. 在 `providers` 中增加 request shaping。
3. 增加日志和 Debug 脱敏。
4. 增加进程内 mock transport 测试。
5. 只通过 typed IPC 增加 UI 字段。

禁止：

- API Key 保存到 app config。
- 完整 Key 返回给前端。
- 打印 Authorization header。
- 在 CI 调真实付费 API。

## 生成文件和忽略文件

默认忽略：

- `target/`
- `node_modules/`
- `apps/desktop/frontend-dist/`（由 Vite 创建并在每次构建前完整清理，不保留占位文件）
- `apps/desktop/src-tauri/gen/`
- 日志和临时文件

如果生成文件必须作为源码资产提交，先在对应 PR 或文档中说明原因。

## 阶段退出清单

一个阶段完成前必须满足：

- 文档反映新增行为。
- Commands 和 IPC 类型明确。
- Rust 逻辑有测试。
- 前端如有数据转换或展示逻辑，应有测试。
- 没有新增被禁止的运行时依赖。
- Secrets 不写入普通文件、SQLite、日志或前端存储。
- 完整验证命令全部通过。
