# Lawyer Assistance 应用信息架构与工作流重构计划

计划文档路径：

`docs/plans/2026-07-29-app-information-architecture-and-workflow-rebuild.md`

## 1. 重构目标

本轮重构解决以下根本问题：

1. 普通聊天必须能够在未创建案件、未上传案件文件、未执行脱敏审批的情况下直接使用。
2. 普通聊天应醒目说明请求将发送到模型供应商服务器，并明确提醒不得发送敏感案件材料。
3. 脱敏从“设置与维护”迁入“案件工作台”，成为案件材料管理中的独立专注页面。
4. 案件材料处理与案件分析分离：

   * “材料与脱敏”负责文件导入、提取、OCR、脱敏、人工复核和批准。
   * “案件工作”负责事实、证据、争点、法律依据、问答、文书和图示。
5. 真实案件原件不得被普通助手或案件助手自动读取。
6. 案件助手只使用用户明确选择的已批准脱敏版本和已确认案件数据。
7. MCP 和外部自动化继续执行精确授权、opaque ID、ticket、grant、撤销和 fail-closed 规则。
8. `App.tsx` 退化为应用装配层，不再承载全部业务状态和工作流。

## 2. 非目标

本轮不做以下事项：

* 不重写现有 Provider adapter 和凭据存储。
* 不降低 MCP approved workspace 的安全边界。
* 不删除现有脱敏、Vault、receipt、risk review 和 protected work-product 能力。
* 不在第一阶段重新设计全部文书和示意图模板。
* 不用一个新的巨型组件替换现有 `App.tsx`。
* 不通过把用户自由文本伪装成 `ProductPublic` 来绕过类型系统。

## 3. 目标信息架构

### 3.1 顶层导航

固定为：

* 助手
* 案件工作台
* 法律库
* 设置

### 3.2 助手

助手包含：

* 会话列表；
* 普通聊天；
* Provider 选择；
* 显式聊天附件；
* 公开法律来源；
* 成果预览。

聊天输入区持续显示以下提示：

> 内容将通过 API 发送至所选模型供应商服务器。请勿输入或上传未脱敏的案件材料。案件文件请先到“案件工作台 → 材料与脱敏”处理。

普通聊天不得：

* 自动打开案件原件；
* 自动读取 Vault；
* 自动加入案件材料；
* 强制跳转脱敏页面；
* 要求 Provider task receipt；
* 要求用户填写 reviewer、TTL 或 task binding。

### 3.3 案件工作台

案件工作台内部固定为：

* 概览
* 材料与脱敏
* 案件工作
* 成果

“材料与脱敏”包含：

* 案件材料列表；
* 导入文件；
* 本地提取或 OCR 状态；
* 自动脱敏草稿；
* 人工复核；
* approved generation 列表；
* 撤销和版本历史；
* 本地安全导出。

“案件工作”包含：

* 当事人；
* 事实；
* 证据；
* 事实—证据关联；
* 法律争点；
* 法律依据；
* 待核实事项；
* 案件助理。

案件助理只允许选择当前案件的 approved generation，不显示或读取 raw generation。

### 3.4 设置

设置只包含：

* 模型服务与凭据；
* 本地处理环境与 OCR 组件；
* MCP 与自动化；
* 版本、备份与诊断。

脱敏正文、人工复核和具体案件材料不得出现在设置页。

## 4. 信任与出站模型

定义三种互不混用的执行模式：

### `interactive_chat`

用途：普通聊天。

允许用户自由文本和用户显式选择的聊天附件。

要求：

* UI 持续显示 Provider 外发提示；
* 请求保存发送范围审计；
* 不读取案件 Vault；
* 不要求 redaction receipt；
* 不使用 `ApprovedCase` authority；
* 不将其错误标记为 `ProductPublic`。

新增显式分类与 authority，例如：

* `DataClassification::InteractiveUserProvided`
* `ChatRequestAuthority::InteractiveUserContent`

该分类允许普通 Provider transport，但不能访问任何案件材料服务。

### `interactive_case_work`

用途：案件页面内的交互式工作。

允许：

* 当前案件确认数据；
* 用户明确选择的 approved generation；
* 当前本地法律来源。

禁止：

* raw material；
* redaction draft；
* revoked generation；
* 非当前案件 generation；
* 自动扩大来源范围。

该模式不得把 task-specific Provider Approval Panel 暴露为每次问答的必经 UI。

### `approved_automation`

用途：MCP、WorkBuddy、Codex、OpenCode 和其他自动化宿主。

继续要求：

* opaque IDs；
* approved source refs；
* clean-task gate；
* grants；
* exact ticket；
* destination/purpose binding；
* optimistic concurrency；
* revoke-aware fail closed；
* protected work-product sink。

## 5. 领域模型

建立统一案件材料生命周期：

```text
raw_local
  → extracted_local
  → redaction_draft
  → human_reviewed
  → approved_generation
  → revoked
```

核心实体至少包括：

### `CaseMaterial`

* materialId
* projectId
* displayName
* mediaType
* sourceSha256
* vaultObjectId
* vaultObjectVersion
* extractionStatus
* createdAt
* deletedAt

### `RedactionGeneration`

* redactionId
* materialId
* projectId
* generationNumber
* extractionSha256
* redactedContentSha256
* reviewState
* riskRevision
* approvedAt
* revokedAt

### `CaseMaterialSelection`

* projectId
* materialId
* redactionId
* purpose
* selectedByUser
* selectedAt

现有 `PrivacyReview.caseId`、`materialId`、Vault object 字段应迁移进入这一统一模型，不另建第三套平行材料系统。

### 5.1 身份绑定决策（2026-07-30）

本计划采用
[`ADR-0001：ProjectId 与 PrivacyCaseId 的持久化一对一绑定`](../adr/0001-project-privacy-case-binding.md)。
这是对 Phase 1 已识别身份冲突的授权消解，不改变本计划的其他目标和阶段边界。

* `ProjectId` 保留现有 `case-...` 形式，继续作为应用案件、材料归属和前端工作流
  的主身份；不得迁移或重写 `projects.project_id` 及其引用。
* `PrivacyCaseId` 保留 `case_` 加 32 位小写十六进制的冻结格式，继续作为 Privacy、
  Vault、签名、approved workspace 和 MCP 隐私边界的身份；不得放宽校验。
* 两者禁止依赖字符串相等、字符串替换、哈希截断或可预测计数器关联。唯一受支持
  的关联是隐私库中审计型、持久化、一对一且默认不可变的绑定。
* 所有以项目为入口的 Privacy/Vault 操作必须在可信后端边界解析绑定，再把严格的
  `PrivacyCaseId` 传入 Vault；前端不得生成、缓存为权威值或猜测
  `PrivacyCaseId`。
* 生命周期校验必须验证
  `binding(ProjectId).privacyCaseId == Vault PrivacyCaseId`，不得继续验证
  `ProjectId == PrivacyCaseId`。
* 历史 Privacy/Vault 数据保留原 `PrivacyCaseId`。只有可信元数据能够无歧义恢复
  关系时才建立绑定；其余记录 fail closed 并进入迁移冲突报告，不得猜测、覆盖或
  静默重绑。
* 绑定迁移只读 `user.sqlite`，只在 Privacy 可写库中写入绑定、审计和迁移结果；
  必须幂等、可恢复、并发安全，且回滚不得修改或删除既有 Vault 数据。
* 绑定与审计的不可变性必须覆盖 SQLite `REPLACE` / upsert 冲突算法；可写连接要
  核验实际 schema、外键和递归触发器，不能只相信同名表或触发器存在。
* 项目删除采用 append-preserving journal：先撤销 Privacy/Vault/approved/work
  lineage 并 tombstone 材料，再删除用户项目。绑定与审计保留，原 `ProjectId`
  永久 retired，不允许同名项目重新绑定或生成第二套 Vault。
* unified material/binding、approved publication 或 work-product lineage 任一存在
  后，只允许恢复一致的五组件应用备份；旧三组件备份不得部分覆盖新模型状态。

## 6. 前端目录重构

目标目录：

```text
apps/desktop/src/
├─ app/
│  ├─ AppShell.tsx
│  ├─ AppRouter.tsx
│  ├─ routes.ts
│  └─ navigationGuards.ts
├─ features/
│  ├─ assistant/
│  │  ├─ AssistantWorkspace.tsx
│  │  ├─ AssistantComposer.tsx
│  │  ├─ ProviderEgressNotice.tsx
│  │  └─ attachments/
│  ├─ cases/
│  │  ├─ CaseWorkspace.tsx
│  │  ├─ CaseNavigation.tsx
│  │  ├─ overview/
│  │  ├─ materials/
│  │  │  ├─ CaseMaterialList.tsx
│  │  │  ├─ RedactionWorkbench.tsx
│  │  │  └─ ApprovedGenerationList.tsx
│  │  ├─ work/
│  │  │  ├─ CaseFactsWorkspace.tsx
│  │  │  ├─ CaseEvidenceWorkspace.tsx
│  │  │  └─ CaseAssistantWorkspace.tsx
│  │  └─ outputs/
│  ├─ legal-library/
│  └─ settings/
│     ├─ providers/
│     ├─ local-processing/
│     ├─ automation/
│     └─ maintenance/
└─ App.tsx
```

`App.tsx` 只负责：

* 根级依赖装配；
* Router；
* AppShell；
* 全局错误边界；
* 窗口关闭保护。

禁止继续向 `App.tsx` 添加案件表单、Provider 表单、QA 状态或 Privacy workflow 状态。

## 7. 后端边界

### 7.1 Assistant

新增独立命令：

* `start_interactive_assistant_run`
* `start_case_assistant_run`

不得继续让一个 command 同时表达：

* 普通聊天；
* 未批准案件；
* 已批准案件；
* MCP 自动化。

`start_interactive_assistant_run`：

* 使用 `InteractiveUserContent` authority；
* 不读取 case workspace；
* 只使用请求中显式附件；
* 保留大小、所有权、SSRF、取消、审计和输出限制。

`start_case_assistant_run`：

* 接收 project ID；
* 接收用户选择的 redaction generation IDs；
* 后端重新验证 generation 当前有效、属于同一案件且未撤销；
* 构造最小案件上下文；
* 不读取 raw Vault object。

### 7.2 Material Service

将材料编排从 Tauri component 中抽出到 Rust service：

* `CaseMaterialService`
* `RedactionReviewService`
* `ApprovedGenerationService`

Tauri commands 只做 typed IPC 转换。

### 7.3 Providers

新增交互式用户内容 authority，禁止复用：

* `ProductPublic`
* `LegalPublic`
* `ApprovedCase`

保留：

* endpoint 校验；
* private network 显式许可；
* credential 隔离；
* 请求和响应限额；
* 日志脱敏。

### 7.4 MCP

`crates/legal-mcp` 与 approved workspace 的硬边界保持不变。

普通 Assistant command 不调用 MCP profile，也不通过 MCP grant 判断是否允许普通聊天。

## 8. 迁移策略

1. 现有 assistant conversation 原样保留。
2. 现有聊天不再跳转 Provider Approval Panel。
3. 已存在且带 `caseId` 的 Privacy Review 自动显示在对应案件的“材料与脱敏”。
4. `caseId = null` 的历史 Privacy Review 进入“未归属本地材料”，允许用户手动归入案件。
5. 现有 `CaseFile` 元数据记录迁移为 `CaseMaterial` 引用；无法解析的记录标记为 legacy reference，不静默删除。
6. 现有 Provider approved outputs 保留在“设置 → MCP 与自动化 → 历史输出”。
7. 原 `PrivacyWorkspace` 拆分后：

   * OCR 配置和组件管理留在设置；
   * Review Workbench 迁入案件材料；
   * Provider Approval 和 Approved MCP 迁入自动化设置；
   * Lifecycle 以材料详情或高级维护形式呈现。

## 9. 实施阶段

### Gate 0：仓库保护

* 保存当前 main 保护分支。
* 保存 v0.3.1 基线保护分支。
* 解决已确认的 Git 历史断裂。
* 禁止使用 `--allow-unrelated-histories` 直接制造最终历史。

### Phase 1：文档与现状测试

只提交：

* 本计划文档；
* 当前错误行为的 characterization tests；
* 页面和 command 依赖图；
* 数据迁移说明。

必须覆盖：

* 普通聊天当前必然跳转；
* 后端当前必然返回 `approved_provider_required`；
* ordinary request 当前携带错误的 ApprovedCase authority；
* Privacy Workbench 当前未传递 caseId；
* Privacy 页面当前聚合全部管理面板。

该阶段不得改变生产行为。

### Phase 2：应用骨架拆分

* 引入 typed route model。
* 将案件、Provider、法律库、Privacy 状态迁出 `App.tsx`。
* 建立新的 Case Workspace 子导航。
* 保持现有功能行为不变。

验收标准：

* `App.tsx` 只承担装配；
* feature 之间只能通过 typed props、route state 或 IPC 协议交互；
* 不新增全局 mutable singleton。

### Phase 3：材料与脱敏迁移

* 将 Privacy Review Workbench 改造成 case-scoped Redaction Workbench。
* 调用 `preparePrivacyMaterial` 时强制传入当前 `ProjectId`；可信后端通过
  ADR-0001 绑定解析或事务性初始化对应 `PrivacyCaseId`，再进入 Privacy/Vault。
* 按案件列出材料、review 和 generation。
* 建立 CaseMaterial 与 RedactionGeneration 绑定。
* 把 OCR 运行环境配置留在设置。

### Phase 4：恢复普通聊天

* 删除前端 always-false public-shell 判断。
* 删除自动跳转 `redirectLegacyEgressToApprovedProvider`。
* 删除按钮“前往脱敏批准”。
* 新增持续可见的 Provider 外发提示。
* 新增 `InteractiveUserContent` authority 和 classification。
* 普通聊天直接走现有 Provider streaming pipeline。
* 普通聊天不得读取案件 workspace。

#### Phase 4 实施澄清（2026-07-31）

本节只收窄 Phase 4 的实现契约，不改变 Phase 5 的案件助手或 Phase 6 的 MCP
边界：

* 新命令 `start_interactive_assistant_run` 使用独立、无 `intent` 的闭合 IPC：
  `runId`、`conversationId`、`providerId`、`prompt`、显式
  `attachmentIds` 和可选 `budget`。请求拒绝 `projectId`、`caseId`、
  `privacyCaseId`、redaction generation、receipt、authority、classification、
  artifact/regeneration 和 MCP 字段；authority 与 classification 只能由可信后端构造。
* 旧 `start_assistant_run` 在 Phase 7 清理前继续 fail closed，不能借 Phase 4
  恢复旧的 legal/file/document/map/case 多意图执行计划。Phase 5 只通过独立
  `start_case_assistant_run` 恢复案件能力。
* 案件绑定会话可以继续承载普通聊天，但 `projectId` 仅是保留的会话容器元数据：
  普通聊天不得以其分支、查询或构造上下文，不读取 Case Workspace、CaseMaterial、
  Privacy、Vault、approved generation 或 MCP 服务，也不把该标识写入 Provider
  请求或发送范围审计。
* 自动携带的历史只包括同一会话中 `intent = interactive_chat` 且已成功运行的、
  成对的 user/assistant 文本消息，并继续受 24 条与 32 KiB 上限约束。旧多意图、
  案件、artifact、source、proposal 和 automation lineage 保留显示但不得自动重发；
  畸形 interactive lineage 必须 fail closed。
* 附件正文只允许从本次请求显式列出的、属于当前会话且本地提取成功的附件定点读取；
  未选择和跨会话附件不得枚举或发送。发送给模型的正文不包含本地路径、附件 ID
  或原始文件名，持久化前在同一 immediate transaction 中复核附件哈希、提取状态
  和模型可见正文哈希，防止 TOCTOU。普通附件不得自动登记为 CaseMaterial。
* `InteractiveUserContent` 精确映射到 `InteractiveUserProvided`。只有该 authority
  可以把用户主动输入的正文发送到 External Provider 或显式配置的 Verified Local
  Provider；不得发送到 External MCP Host。ProductPublic、LegalPublic、
  ApprovedCase、raw/pending case 和 Secret 的既有残留检测、receipt 与拒绝规则
  保持不变。
* 每次 Provider dispatch 使用 `assistant.interactive_chat` capability 写入
  `user.sqlite` 的 agent-run/tool-call 审计链。审计只保存 classification、
  conversation/显式 attachment 标识、内容哈希、字节数、条数、截断计数和 Provider
  快照，不保存 raw prompt、历史正文、附件正文、路径或案件标识；不修改 Privacy/Vault
  审计库 schema。
* 普通聊天使用现有 Provider streaming、取消、credential 隔离、SSRF/private-network
  许可、请求/响应额度和错误脱敏机制。输出作为普通文本消息持久化，不创建 artifact、
  proposal、citation report 或案件成果。
* 输入框附近始终显示：
  `内容将通过 API 发送至所选模型供应商服务器。请勿输入或上传未脱敏的案件材料。案件文件请先到“案件工作台 → 材料与脱敏”处理。`
  选择附件时还必须显示将发送正文的文件名、类型和大小，但不得显示或传递本地路径。

### Phase 5：案件工作页

* 创建独立 Case Assistant。
* 只允许选择当前案件 approved generations。
* 后端重新验证 generation 归属、状态和版本。
* 案件分析、文书和图示成果回写前继续要求用户确认。
* 撤销 generation 后，新的案件请求不得继续使用。

### Phase 6：自动化边界归位

* Provider Approval Panel 改名并迁入“自动化出站批准”。
* Approved MCP Panel 迁入“设置 → MCP 与自动化”。
* 普通聊天不再加载这些面板。
* WorkBuddy/Codex/OpenCode 继续使用严格 approved workspace。

### Phase 7：清理与产品验收

* 删除旧 Privacy 大页面。
* 删除 compatibility redirect 代码。
* 删除失效的 approvedProviderTaskRequest handoff。
* 更新用户文档、截图和发布说明。
* 运行完整 Rust、TypeScript、integration、MCP 和迁移测试。

## 10. 必须通过的端到端验收

### 普通聊天

1. 新安装应用。
2. 只配置一个 Provider。
3. 不创建案件。
4. 新建会话。
5. 输入“合同解除的一般条件是什么？”
6. 点击发送。
7. 页面不得跳转。
8. 应正常流式返回回答。
9. 输入框附近始终显示供应商服务器外发提示。

### 普通附件

1. 在普通聊天显式选择一个 TXT/PDF。
2. 页面明确显示该附件正文将发送到所选 Provider。
3. 用户可直接发送或取消。
4. 不强制进入脱敏页面。
5. 不得自动把附件登记为案件材料。

### 案件脱敏

1. 创建案件。
2. 打开“材料与脱敏”。
3. 添加文件。
4. 完成本地提取、自动脱敏、人工复核和批准。
5. 批准版本出现在当前案件材料列表。
6. 设置页不得显示该文件正文。

### 案件工作

1. 打开“案件工作”。
2. 选择已批准版本。
3. 发起案件问答。
4. Provider 只收到所选脱敏版本和确认案件数据。
5. 后端不得读取原件。
6. 撤销 generation 后再次发送必须失败并要求重新选择材料。

### MCP

1. 未批准原件进入 MCP 时在 transport 前失败。
2. Approved generation 必须匹配 publication、grant 和 ticket。
3. 来源撤销后 update/export 失败。
4. MCP 的严格边界不得因普通聊天放宽而改变。

## 11. 提交与 PR 规则

* 第一提交必须是 docs-only。
* 每个 Phase 使用独立分支和独立 PR。
* 不允许将导航重构、数据库迁移、普通聊天恢复和 MCP 修改塞入一个 PR。
* 每个 PR 必须附：

  * 影响范围；
  * 数据迁移；
  * 安全边界变化；
  * 测试证据；
  * UI 截图；
  * 回滚方法。
* 未完成端到端验收前，不得发布正式 v0.4。
