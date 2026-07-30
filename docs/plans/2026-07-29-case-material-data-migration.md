# 案件材料统一模型数据迁移说明（Phase 1）

本文档是 `docs/plans/2026-07-29-app-information-architecture-and-workflow-rebuild.md` 的 Phase 1 数据迁移设计。本文只描述后续实现必须遵守的契约，不创建数据库表、不执行迁移，也不表示 `CaseMaterial`、`RedactionGeneration` 或 `CaseMaterialSelection` 已经存在。

## 1. 目标与边界

后续阶段需要把当前分散的材料身份统一为三个逻辑实体：

- `CaseMaterial`：原始材料、Vault 精确对象版本、案件归属和处理状态的唯一身份。
- `RedactionGeneration`：同一材料的一次脱敏审阅代次；批准后内容不可原地改写。
- `CaseMaterialSelection`：用户为某个案件用途显式选择的、当时仍有效的批准代次。

迁移只统一身份和索引，不移动或解密导出原件，不重新生成脱敏内容，不改变 receipt、mapping、approved workspace、MCP grant/ticket 或 work-product 的安全语义。

以下操作不属于本迁移：

- 不把 `case_files.storage_reference` 当作可信路径并读取文件。
- 不把 `attachments.content_blob` 自动复制到 Vault。
- 不把 `CaseFile` 自动视为已脱敏或已批准材料。
- 不因“引用无法解析”“案件不存在”或“数据冲突”删除任何源记录。
- 不把 approved workspace 的 `document_version` 混同为脱敏 `generationNumber`。
- 不将迁移失败降级为 legacy 原始内容可读；失败记录只能被隔离并显式展示。

## 2. 已核对的当前存储

以下名称来自当前代码，均为迁移输入，不是目标模型。

### 2.1 案件数据库

`crates/database/src/lib.rs` 当前将案件数据库放在：

```text
<app_local_data_dir>/user.sqlite
```

当前 `USER_SCHEMA_VERSION` 为 `10`，canonical marker 为
`v10-operation-audit-20260717`。

与本迁移直接相关的表为：

```text
projects(
  project_id, title, case_type, status, opened_on, summary,
  created_at, updated_at
)

case_files(
  file_id, project_id, title, file_type, storage_reference,
  summary, created_at
)

attachments(
  attachment_id, project_id, original_name, extension,
  detected_mime, sha256, size_bytes, content_blob,
  extraction_status, extracted_text, segments_json,
  error_code, created_at
)
```

`case_files.project_id` 外键到 `projects.project_id`，当前为
`ON DELETE CASCADE`。`CaseFile` 的 Rust 类型位于
`crates/domain/src/case.rs`，字段名与上表一致。

`case_files.storage_reference` 不是统一的 Vault 引用。当前代码明确兼容：

- attachment 本身的 `attachment_id`；
- `attachment:<id>` 规范引用；
- 历史 double-prefix `attachment:attachment:<id>`；
- 空字符串或其他历史自由文本。

因此，任何不能唯一解析为同案件 `attachments` 行的值都必须保留为
legacy reference，不能猜测为路径、Vault object 或 approved generation。

### 2.2 隐私工作流数据库

`apps/desktop/src-tauri/src/privacy_workflow.rs` 当前使用：

```text
<app_local_data_dir>/privacy/privacy-workflow.sqlite
```

`crates/privacy/src/store.rs` 的当前 `PRIVACY_STORE_SCHEMA_VERSION` 为 `5`。
主要迁移输入如下：

```text
privacy_materials(
  material_id, project_id, attachment_id,
  source_sha256, source_name_sha256, media_type, page_count,
  state, created_at, updated_at
)

privacy_redactions(
  redaction_id, material_id,
  generation_number, generation_status,
  extraction_sha256, redacted_content_sha256,
  approved_payload_sha256,
  policy_id, policy_version, detector_version,
  unresolved_high_risk_count, review_state,
  risk_revision, approved_at, revocation_state, revoked_at,
  row_version,
  protected_review_blob, protection_scheme,
  reviewed_by_sha256, created_at, reviewed_at
)

privacy_risk_review_revisions(
  redaction_id, revision, state_sha256, risk_sha256,
  hard_gate_sha256, action_code, reason_codes_json,
  protected_state_blob, protection_scheme,
  previous_revision_hash, revision_hash, created_at
)

case_material_selections(
  selection_id, project_id, material_id, redaction_id, purpose,
  selected_by_user, selected_at,
  selected_generation_number, selected_approved_payload_sha256,
  selected_risk_revision, deselected_at, invalidated_at,
  invalidation_reason, row_version
)
```

`privacy_risk_review_revisions` 已是 append-only hash chain。迁移后的
`riskRevision` 必须是该 `redaction_id` 的已验证最大 `revision`，不能按行数重算，
也不能丢弃 `previous_revision_hash` / `revision_hash` 证据。

当前 Vault 导入流程把 `VaultImportBinding.object_id` 写入
`privacy_materials.attachment_id`。该列在这条路径上不是
`user.sqlite.attachments.attachment_id`，迁移器不得用同名列直接跨库 join；
可信 Vault 绑定只能取自下述 `privacy_vault_material_refs`。

当前前端 `PrivacyReview` 位于
`apps/desktop/src/ipc/privacy/types.ts`。其 `caseId`、
`vaultObjectId`、`vaultObjectVersion` 均可为 `null`。
后端对应 `PrivacyReviewView` 和加密落盘的 `StoredReviewPayload` 位于
`apps/desktop/src-tauri/src/privacy_workflow.rs`。`StoredReviewPayload` 内含：

- `material_id`、`redaction_id`；
- 可空 `case_id`、`vault_object_id`、`vault_object_version`、
  `vault_isolation`；
- `source_display_name`；
- source、extraction、suggested-redacted hashes；
- processing/media/page/backend 信息；
- 原文、脱敏页、canary 和 review summary。

该 payload 以 `privacy_redactions.protected_review_blob` 保存，当前保护方案是
`windows_dpapi_current_user_v1`。敏感文件名目前不应从该 blob 明文复制到普通索引。

### 2.3 Vault 精确绑定

Vault 根目录当前为：

```text
<app_local_data_dir>/case-vault-v2/
  vault-state.sqlite
  objects/
  keys/
  .staging/
  .quarantine/
```

`apps/desktop/src-tauri/src/privacy_workflow/vault_broker.rs` 在
`privacy-workflow.sqlite` 中另有：

```text
privacy_vault_material_refs(
  material_id, case_id, object_id, object_version,
  source_sha256, envelope_sha256, content_bytes,
  retention_expires_at_unix, retention_policy_revision,
  bound_at_unix, import_state, failure_code,
  created_at, updated_at
)
```

其中 `(object_id, object_version)` 唯一，`material_id` 是主键。
Vault 本体的 `object_journal` 以 `(object_id, version)` 为主键，并同时绑定
`case_id`、object kind、state、envelope hash 和内容长度。

Vault 身份始终是精确四元组：

```text
(case_id, object_id, object_version, source_sha256)
```

迁移不得仅凭 `object_id` 或文件名恢复引用。四元组任一项冲突都必须 fail closed。

### 2.4 Approved workspace 不是脱敏代次表

批准发布物当前位于：

```text
<app_local_data_dir>/privacy/approved-mcp/approved-generations/
  workspace-state.sqlite
  cases/<case_id>/approved/<publication_id>/...
```

`publication_journal` 保存 `case_id`、`material_id`、
`document_version`、`publication_id`、manifest/content hashes、
state、`revoked_at_unix`、`revocation_epoch` 和 `lifecycle_binding_id`。
发布时 `lifecycle_binding_id` 是 App-local `redaction_id`。

因此可通过 `publication_journal.lifecycle_binding_id =
privacy_redactions.redaction_id` 验证发布物来源，但：

- `document_version` 是 approved workspace 发布版本；
- `generationNumber` 是同一材料在 App 内的脱敏审阅代次；
- receipt 的 `revoked_at_unix` 只撤销该 receipt；
- publication 的撤销只撤销该发布物；
- 材料或脱敏代次的撤销才使新的案件工作请求全面失效。

这四种版本/撤销状态不得相互覆盖或推断。

## 3. 当前身份不一致与正式决策

当前案件 UI 在 `apps/desktop/src/App.tsx` 使用
`case-<base36 time>-<random>` 形式创建 `projectId`。
隐私 vNext `CaseId`（`crates/privacy/src/vnext.rs`）则严格要求
`case_` 加 32 位小写十六进制。

另外，`PrivacyReviewWorkbench.tsx` 当前调用
`preparePrivacyMaterial({ customTerms })`，未传 `caseId`；后端
`prepare_selected_material_with_qualification` 会为缺失值生成新的
`case_<32 hex>`，而不是查找当前 `projects` 行。

2026-07-30 已正式选择方案 B，详见
[`ADR-0001：ProjectId 与 PrivacyCaseId 的持久化一对一绑定`](../adr/0001-project-privacy-case-binding.md)。
后续实现必须把两种身份视为不同类型：

1. `ProjectId` 保留 `case-...`，是 `user.sqlite`、案件归属、CaseMaterial 和前端
   工作流的身份；迁移不得修改该值或任何源表。
2. `PrivacyCaseId` 保留 `case_<32 lowercase hex>`，是 Privacy、Vault、签名、
   approved workspace 和 MCP 隐私边界的身份；不得放宽其格式。
3. 两者只能通过 Privacy 可写库内审计型、一对一、默认不可变的持久化绑定关联。
   禁止依赖字符串相等、临时字符串转换、哈希截断或可预测计数器。

历史迁移必须区分：

1. `StoredReviewPayload.case_id = null`：历史未归属本地材料。
2. `case_id` 非空且可通过既有绑定或可信跨库 provenance 无歧义恢复唯一
   `ProjectId`：保留该 `PrivacyCaseId` 并幂等建立绑定。
3. `case_id` 非空但不能唯一恢复项目：包括当前旧 UI 产生的匿名
   `case_<32 hex>`；必须迁移为“未归属”，同时保留 `legacyCaseId`，
   不能创建幽灵案件，也不能按标题、排列顺序或字符串相似度自动绑定。
4. 项目尚无任何 Privacy/Vault 状态且没有绑定：可以在事务内用安全随机源生成
   新的 `PrivacyCaseId` 并创建唯一绑定。

用户后续手动归入案件时，服务必须执行一次明确的归属操作并记录审计；不能改写
Vault 内既有 `case_id`。如果归属涉及 Vault case identity 变化，应创建新的受控
Vault revision/binding，而不是只更新数据库字符串。

归属命令必须由后端重新验证目标项目仍存在且未退休、现有双向绑定、材料与所有
generation 的身份一致性，以及任何 Vault 四元组。操作需要事务性或 journaled，
同一请求重试只能得到同一结果，并发归属到不同项目必须 fail closed；前端只提交
用户选择的 `ProjectId`，不得提交或生成权威 `PrivacyCaseId`。

## 4. 目标逻辑模型与物理落盘原则

为避免第三套平行材料系统，后续实现应演进现有
`privacy_materials` / `privacy_redactions` 作为统一模型的物理 backing，
而不是长期维护一组独立 shadow `case_materials` /
`redaction_generations` 表。Rust/IPC 暴露逻辑名称
`CaseMaterial` / `RedactionGeneration`；物理表是否在最终清理阶段改名，
不影响本迁移契约。

只有 `CaseMaterialSelection`、ADR-0001 身份绑定及其审计表，以及迁移
ledger/legacy-reference 辅助表是新增数据。
`user.sqlite.case_files` 在兼容期保留为源与旧 UI 投影，不能继续成为第二个材料
真实性来源。

### 4.0 `ProjectPrivacyCaseBinding`

绑定物理落盘在 `privacy-workflow.sqlite`，不写入迁移源 `user.sqlite`。逻辑字段
至少包括：

```text
projectId
privacyCaseId
bindingVersion
creationSource
creationAuditId
migrationId              nullable
createdAt
updatedAt
```

数据库必须分别唯一约束 `projectId` 与 `privacyCaseId`，并校验非空、
`bindingVersion > 0` 和严格的 Privacy CaseId 格式。绑定身份列在 v1 中不可更新；
任何未来重绑都必须是独立、显式、受控且可审计的迁移，不得使用普通 UPDATE。

绑定服务必须提供以下唯一解析边界：

* 由 `ProjectId` 查询现有 `PrivacyCaseId`；
* 在明确允许初始化的生命周期点，以 `BEGIN IMMEDIATE` 等等价写锁事务执行
  “查询或安全随机创建”；
* 由 `PrivacyCaseId` 反查 `ProjectId`；
* 校验给定身份对是否为当前合法绑定；
* 以稳定错误区分 `unbound`、`invalid_project_id`、`invalid_privacy_case_id`、
  `binding_conflict`、`ambiguous_legacy_binding` 和 `binding_store_failed`。

新 `PrivacyCaseId` 必须由操作系统安全随机源生成并满足
`case_[0-9a-f]{32}`；不得使用 `ProjectId` 的哈希截断、字符串替换或计数器。
同一项目的并发首次创建只能提交一个绑定；竞争者必须读取并返回已提交的同一
绑定，不能生成第二套 Vault。

### 4.1 `CaseMaterial`

目标逻辑字段至少包括：

```text
materialId
projectId                 nullable
legacyCaseId              nullable, migration evidence only
displayName               App 解密后返回
displayNameSha256
mediaType                 nullable only for unresolved legacy reference
sourceSha256              nullable only for unresolved legacy reference
sourceKind                vault | local_review | user_attachment | legacy_reference
vaultObjectId             nullable
vaultObjectVersion        nullable
vaultEnvelopeSha256       nullable
vaultContentBytes         nullable
extractionStatus
migrationStatus           ready | unassigned | legacy_reference | blocked
rowVersion
createdAt
updatedAt
deletedAt                 nullable
```

`displayName` 应以 DPAPI-protected blob 落盘；普通索引只保存 hash。对现有
Privacy Review，从通过身份校验的 `StoredReviewPayload.source_display_name`
迁移。对 `CaseFile`，展示名取既有 `case_files.title`，原
`attachments.original_name` 只作为受保护 provenance 保留，不能覆盖用户标题。

Vault 字段在逻辑上来自 `privacy_vault_material_refs`，不应复制成可漂移的第二份
权威值。统一服务可以 join 投影这些字段；若最终为了查询增加缓存列，写入必须与
Vault ref 在同一隐私库事务内完成，并用约束保证全空或全非空。

`deletedAt` 是统一目录的 tombstone。迁移过程永远不设置它。后续显式硬删除仍须先
撤销 selection、generation、receipt/publication/work-product，并遵守 legal hold
和现有 cleanup journal；不能依靠外键 cascade 作为用户不可见的业务操作。

### 4.2 `RedactionGeneration`

目标逻辑字段至少包括：

```text
redactionId
materialId
projectId                 从 CaseMaterial 投影，不是独立可写副本
generationNumber
extractionSha256
redactedContentSha256
approvedPayloadSha256     nullable until approved
reviewState
riskRevision
policyId / policyVersion
detectorVersion
approvedAt                nullable
revocationState
revokedAt                 nullable; legacy time unknown时仍不可使用
rowVersion
createdAt
```

迁移时复用既有 `redaction_id`，因为 mapping、receipt、
`privacy_approved_outputs` 和 approved publication 的
`lifecycle_binding_id` 都精确绑定该值。格式异常的历史 ID 标记
`legacy_id` 并只读，不得生成新 ID 后悄悄断开旧关系。

`generationNumber` 的首次分配规则为：

```text
同一 material_id 内按 (privacy_redactions.created_at, redaction_id) 升序，
从 1 开始分配。
```

分配结果写入 ledger 后不可重算。迁移期间新建代次必须在写锁下使用
`MAX(generationNumber) + 1`；重复运行读取既有分配。时间戳相同由
`redaction_id` 稳定打破平局。

批准前，pending review 可以继续通过现有 optimistic hash 与 append-only risk
revision 更新同一代次。批准后以下值构成不可变内容身份：

```text
(materialId, redactionId, generationNumber,
 sourceSha256, extractionSha256,
 redactedContentSha256, approvedPayloadSha256,
 policyId, policyVersion, detectorVersion, riskRevision)
```

任何内容变更都必须创建新的 `RedactionGeneration`；不得递增
`vaultObjectVersion` 来表示脱敏变更，也不得改写已批准行。

当前 schema 允许 `review_state='revoked'`，但没有对应的可靠撤销时间列。遇到这类
历史行，应迁移为 `revocationState='revoked_legacy_time_unknown'` 且
`revokedAt=null`。`null` 不能解释为有效；有效性由 revocation state 决定。
同理，不得把 publication 或 receipt 的撤销时间伪装成 generation 撤销时间。

### 4.3 `CaseMaterialSelection`

当前没有可安全推断的案件工作选择。MCP publish approval、receipt 和
`publication_journal` 都不是用户在 `interactive_case_work` 中的选择，因此迁移后
该表初始为空。

建议新增 append-preserving 表，至少保存：

```text
selectionId
projectId
materialId
redactionId
purpose
selectedByUser            必须为 true
selectedAt
selectedGenerationNumber
selectedApprovedPayloadSha256
selectedRiskRevision
deselectedAt              nullable
invalidatedAt             nullable
invalidationReason        nullable
rowVersion
```

每个 `(projectId, materialId, purpose)` 最多一个 active selection。替换选择时先将
旧行写为 deselected，再插入新行，不覆盖历史。generation 撤销、材料删除或重新归属
只会使 selection invalid，不会删除 selection。

### 4.4 Phase 5 approved-only 投影与案件助手 lineage

Privacy schema v5 已建立 unified generation、selection、binding 和迁移 ledger，
但现有 `protected_review_blob` 同时包含原文与建议脱敏文。它不能作为案件助手的
运行时批准正文来源。Phase 5 将 Privacy schema 升级为 v6，并在现有
`privacy_redactions` 上增加以下列：

```text
approved_payload_schema_version       nullable
protected_approved_payload_blob       nullable
approved_payload_protection_scheme    nullable
approved_risk_revision_hash           nullable
```

这些列是 `RedactionGeneration` 的 approved-only 受保护投影，不是第三套材料表。
投影明文是 canonical `ApprovedPayload` v1：

```text
{
  schemaVersion,
  sourceSha256,
  extractionSha256,
  mediaType,
  pages: [{ pageNumber, text }]
}
```

投影不得包含 original text、文件名、locator、span、canary、案件身份、Vault 或
attachment ID、路径。继续复用 `approved_payload_sha256` 校验 canonical 明文字节，
`approved_risk_revision_hash` 精确绑定生成批准时已完整验证的 risk chain head。
四列必须全空或全完整；`review_state='approved'` 且 `generation_status='ready'` 的
行必须具有完整投影、`risk_revision > 0`、零 high-risk finding 和合法 chain head。
历史损坏行保留全部源数据但标为 blocked，不得伪造投影。

新批准必须在同一事务内写入完整 review blob、approved-only 投影、批准状态、
risk revision/head 和 row version。批准后投影、批准 hash 和 risk head 不可原地
改写。安全关键 trigger 必须阻止 UPDATE、DELETE 及 `INSERT OR REPLACE`/upsert
冲突算法绕过；risk revision 和 selection 的 append-preserving 触发器同样必须覆盖
delete/replace。可写连接应比较 canonical trigger SQL、foreign keys 和
`recursive_triggers` 配置，不只检查对象同名存在。

新增专用 approved-only loader，其 SQL 只能选择投影与必要公开索引列，不能选择
`protected_review_blob`。loader 必须严格解析并 canonical 重编码，逐字节核对 payload、
source/extraction/redacted hashes、media/page、generation、完整 risk chain/head、
project binding 和 revocation 状态。使用合法投影但旧 full blob 已损坏时仍应成功，
用于证明运行时未读取原文；投影缺失或损坏时禁止 fallback 到旧 blob。

Phase 5 同时把 user database 升级为下一 canonical schema：

- `conversations` 增加后端权威的 `assistant | case_work` 范围；所有既有会话迁移为
  `assistant`，不得按历史 `project_id` 或 intent 推断；
- 新增 append-preserving `case_assistant_pending_outputs` 与精确 source snapshot
  lineage，保存 opaque project/conversation/run/generation 标识、版本/hash、
  output kind/hash/version、workspace base digest、状态与确认审计，不保存
  `PrivacyCaseId`、原文、路径或 Provider 正文副本；
- 未确认 output 不绑定案件 artifact、不进入 Case Outputs。确认在 user database
  事务中执行 workspace CAS 和一次性状态转换；Privacy generation/selection 在进入
  事务前及应用前分别重新验证。

`CaseMaterialSelection` 的固定 purpose 为 `interactive_case_work`。每次
`start_case_assistant_run` 只处理请求显式列出的 generation IDs，并在写锁事务内
幂等追加/替换对应选择；其他 active selection 只用于 UI 恢复，不自动扩大本次来源。
selection 创建、批准正文读取、Provider socket write 和 pending output 确认四个时点
都必须重新验证当前项目绑定、generation snapshot、risk head 与撤销状态。

#### v5→v6 受控 backfill

使用固定 migration id `approved-case-projection-v1`，复用现有 append-preserving
migration ledger/events，执行顺序固定为：

1. 在 operation gate 下只读预检 Privacy v5 schema、完整 risk chains、源 manifest
   和 projection source fingerprint。
2. 创建并验证包含 user database、Privacy database、Vault、approved generations
   和 work-products 的五组件一致性备份；在首次 schema 写入前再次比较 fingerprint。
3. 只增加 nullable projection 列和临时批准阻断 trigger。v1–v4 输入必须先明确升级
   到中间版本 v5，不能因全局版本常量变为 6 而提前写 v6 metadata。
4. 对每个 ready approved generation，仅在迁移进程内解密旧 full blob，验证
   material/redaction/project/Vault 身份、所有公开 hash、page count、canary/residual
   和完整 risk chain；从 `suggested_redacted_text` 构造 canonical approved payload，
   核对既有 approved hash 后以 DPAPI 写入安全投影和精确 risk head，并在同一事务
   写完成 ledger。
5. 无效行保留旧 blob、主键和全部 provenance，追加 blocked result 并使 active
   selection invalid；pending、stale、revoked、non-approved 行不生成投影。
6. 所有 ready approved 行均已验证或稳定 blocked 后，安装最终安全 trigger、验证
   schema/manifest，再写 Privacy schema version 6 并清除 upgrade-required 状态。

fingerprint 排除本迁移自身写入的投影/status/row-version 列，并通过持久化源 manifest
支持 schema-prep、单行 backfill、finalize 任一崩溃点幂等恢复。迁移不得改写
`user.sqlite`、旧 `protected_review_blob`、源主键或 Vault/approved/work-product
内容。

approved-only 投影会扩大 Privacy database。v5 迁移源继续受 96 MiB 旧上限约束；
Phase 5 将 raw Privacy database、portable/envelope、application backup 和 restore
的相关上限成套提升到 256 MiB，并在任何 schema 写入前预估迁移后文件大小。单个
canonical approved payload 继续受 16 MiB 上限约束；预计超过 256 MiB 时稳定阻断并
保留五组件备份和源库，不允许产生无法被应用备份覆盖的部分 v6 状态。

投影仍位于 Privacy database，因此备份格式保持五组件 V3，不增加第六组件。
application backup 必须按 migration id 路由独立的 source fingerprint，允许
`approved-case-projection-v1`，并支持恢复 Privacy v5 后重新执行受备份保护的迁移。
任一 projection、selection 或 pending-output lineage 存在后，三组件或单数据库恢复
必须在暂存前和首次组件替换前再次 fail closed。

## 5. 源数据映射

### 5.1 Privacy material/review

每个 `privacy_materials.material_id` 产生一个 `CaseMaterial`。迁移程序必须解密并
校验其关联的每个 `protected_review_blob`：

- payload schema version 受支持；
- payload `material_id` / `redaction_id` 与索引行一致；
- payload extraction/redacted hashes 与 `privacy_redactions` 一致；
- payload `source_sha256` 与 `privacy_materials.source_sha256` 一致；
- page count 与 pages 数量一致；
- 同一 material 的多个 payload 对 case、source、display name 和 Vault tuple
  不得互相冲突。

每个 `privacy_redactions.redaction_id` 产生一个 `RedactionGeneration`。
`riskRevision` 取已验证 hash chain 的最大 revision。`reviewed_at` 只在可解析且
`review_state='approved'` 时映射为 `approvedAt`；批准行缺少
`approved_payload_sha256`、仍有 high-risk finding 或 risk chain 断裂时，整代次
标为 `blocked`。

Vault-backed material 还必须同时满足：

- payload `case_id` 与 `privacy_vault_material_refs.case_id` 一致且均为合法
  `PrivacyCaseId`；
- `privacy_materials.project_id` 为逻辑 `ProjectId`，其持久化绑定解析结果必须与
  上述 `PrivacyCaseId` 一致；不得再比较两种 ID 的字符串；
- object id/version 与 payload 一致；
- source/envelope hashes、content length 合法；
- Vault `object_journal` 中精确对象是 committed 且 case identity 一致；
- `import_state` 未撤销。

普通迁移巡检不把原件明文写入日志。需要内容完整性复核时，只在 Vault broker 内
读取并比较 SHA-256，使用后清零；错误只输出稳定 error code。

### 5.2 `caseId = null` 与孤立非空 `caseId`

`caseId = null`：

- `projectId = null`；
- `migrationStatus = unassigned`；
- 保留原 material/redaction identity；
- 不创建 selection；
- 不得出现在任何案件助手、approved automation 或 MCP source list。

非空但无法通过既有绑定或可信 provenance 唯一恢复 `ProjectId` 的 `caseId`
使用同一规则，并额外保存 `legacyCaseId`。只有绑定验证或无歧义可信恢复通过时
才可自动归属；名称、顺序、字符串相似度和单独文件名/hash 均不足以建立绑定。

### 5.3 `CaseFile`

每个 `case_files.file_id` 都必须得到一条迁移 ledger 结果：

1. 唯一解析到同一 `project_id` 的 `attachments` 行：
   创建或链接 `sourceKind=user_attachment` 的 CaseMaterial reference，使用
   attachment 的 `sha256`、`detected_mime` 和 `extraction_status`，但不复制
   `content_blob`，且状态仍是 raw/unapproved。
2. 引用解析到其他案件、多个候选或 attachment ownership 为未知：
   创建 `migrationStatus=blocked` 的 legacy reference。
3. 空值、自由文本、疑似路径或找不到 attachment：
   创建 `migrationStatus=legacy_reference` 的记录，原值以 DPAPI protection 保存，
   同时保存 `storage_reference_sha256` 用于幂等校验。

只有同时满足以下条件时，CaseFile 才能复用已有 Privacy `CaseMaterial`：

- project exact match；
- source SHA-256 exact match；
- 候选恰好一个；
- 候选的 Vault/source binding 完整通过；
- ledger 中不存在另一个冲突来源。

不能只按文件名、`file_id == material_id`、大小、summary 或 hash 跨案件合并。
歧义时保留两个 material 及其 provenance，等待用户显式合并。

## 6. 幂等迁移协议

迁移使用固定 migration id，例如
`case-material-unification-v1`，并在隐私库保存 append-preserving ledger：

```text
(migration_id, source_store, source_table, source_key)
  UNIQUE

source_fingerprint
target_material_id
target_redaction_id        nullable
assigned_generation_number nullable
result_state               migrated | legacy_reference | blocked
error_code                 nullable
started_at / completed_at
```

`source_fingerprint` 是规范编码后的 SHA-256：

- Privacy 行：相关公开列、protected blob ciphertext hash、Vault ref 列；
- CaseFile：全部 CaseFile 列，加上成功解析的 attachment metadata；
- 不把明文文件名、路径、原文或 `content_blob` 写入 ledger。

CaseFile-only material ID 必须可重复生成，例如：

```text
mat_ + first_32_hex(
  SHA256("case-material-migration-v1\0" +
         workspace_instance_id + "\0user.sqlite\0case_files\0" + file_id)
)
```

既有 Privacy `material_id` 原样复用。若确定性 ID 已存在但 provenance fingerprint
不同，迁移立即冲突失败，不能添加随机后缀。

重复运行规则：

- fingerprint 相同且 target invariants 仍成立：no-op；
- fingerprint 改变：标记 `source_changed`，重新读取并在 optimistic check 下升级，
  不覆盖另一个来源；
- 上次 `blocked`：重新验证后可追加 resolution 事件，不能改写历史错误；
- crash 在 target commit 前：无完成 ledger，安全重跑；
- crash 在 target commit 后：同事务内已有完成 ledger，安全 no-op。

迁移完成后的受控生命周期操作不得破坏上述幂等协议：

- migration ledger 与 resolution event 永不因 retention cleanup、项目删除或用户
  删除材料而删除或改写；
- retention cleanup 物理移除某个 redaction 后，target invariant 只有在同一
  `redaction_id` 的 cleanup candidate 已为 `removed`、父 cleanup journal 已为
  `committed`，且 journal 哈希链、候选计数和完成计数全部验证通过时，才可把该
  target 缺失解释为受控终态；证据缺失、被替换或被篡改仍须
  `case_material_migration_target_mismatch`；
- 被 source ledger 引用的 material identity 必须保留为已撤销/已删除 tombstone，
  同时清除到期的受保护展示元数据；不得依赖外键 cascade 删除 provenance；
- 项目删除完成后，迁移器必须验证 completed deletion journal、精确 scope、
  material/generation tombstone、Vault ref 撤销和原绑定。验证通过的记录保持原
  `projectId`、`PrivacyCaseId`、`sourceKind` 与 Vault 四元组并 no-op；不得因
  `user.sqlite` 中项目已删除而把历史记录重新投影成未归属或覆盖 provenance。

`user.sqlite` 与 `privacy-workflow.sqlite` 是不同数据库。迁移在 App operation gate 下
以只读 snapshot 打开 `user.sqlite`，只在隐私库写 target + ledger。因为源记录不被
修改，不需要伪造跨库原子提交；若 snapshot 结束前源 fingerprint 改变，本批次回滚。

只读 snapshot 必须使用操作系统/SQLite 只读打开方式并启用 `query_only`，在同一
deferred read transaction 中固定 schema、project manifest 和逻辑内容。不能只依赖
调用约定；测试注入写 SQL 必须得到 `SQLITE_READONLY`，且迁移前后源文件 bytes、
schema version 与逻辑 manifest 均保持一致。

身份绑定 backfill 使用独立固定 migration id
`project-privacy-case-binding-v1`，并遵循：

1. 读取已存在绑定并验证双向唯一性。
2. 只读扫描项目、CaseFile/attachment provenance 与 Privacy/Vault 精确元数据。
3. 所有可信候选一致指向同一身份对时，保留原 `PrivacyCaseId` 并在同一事务写入
   绑定、创建审计事件和完成 ledger。
4. 项目无任何 Privacy/Vault 状态时，可安全随机创建新 `PrivacyCaseId`。
5. 任一端出现多个候选、Vault 四元组冲突或来源不完整时，写结构化 blocked
   migration result；不得创建替代绑定掩盖问题。
6. fingerprint 相同的重复运行为 no-op；中断后重跑从未完成 ledger 继续。
7. 迁移前后比较 `user.sqlite` 文件 hash、schema、项目主键 manifest 和
   `PRAGMA data_version`，任何源写入迹象都使迁移失败。

## 7. 分阶段上线与读兼容

### A. 预检与快照

- 阻止第二实例和材料/隐私写入。
- 校验 `user.sqlite` schema version/marker、Privacy schema version、
  `PRAGMA integrity_check`、`foreign_key_check`。
- 校验 Vault isolation、workspace instance id 和 pending cleanup 状态。
- 创建当前五组件一致性应用备份：user database、privacy database、Vault、
  approved generations、work-products。
- 任一预检失败则不创建 target 行。

### B. Schema 演进与 backfill

- 通过 privacy schema version migration 演进现有 backing tables并创建 selection、
  legacy-reference 与 ledger。
- 先迁 Privacy material/redaction，再迁 CaseFile references。
- 每批事务后执行 invariants；错误行进入 `blocked`，源记录保持不变。
- `blocked` 行可以在 UI 的迁移问题列表显示，但不得进入可用材料列表。

### C. Shadow read

- 旧 API 仍从当前表/payload 返回结果。
- 新服务同时构造统一模型并比较 identity、hash、state。
- 任何安全相关 mismatch 均返回稳定错误，不回退读取 raw、Vault 或 CaseFile 路径。
- 只有 ledger terminal 且未 blocked 的行可进入新 UI shadow list。

### D. Target-primary read / compatible write

- 新材料写入直接建立统一 material + generation，并继续维护现有 receipt、
  lifecycle 和 Vault refs。
- 旧 command 如仍启用，只能调用同一个 service，不得单独写一套状态。
- 读 target 缺失时，只能在 migration ledger 明确为“尚未迁移”时走旧只读兼容；
  fingerprint mismatch、blocked、revoked、stale 均禁止 fallback。

### E. Cutover 与清理

- `pending=0`、所有非 blocked 行核对通过后才可切换 UI。
- `case_files`、旧字段和 protected payload 继续保留至少一个发布周期。
- 删除旧字段/兼容读是独立的后续迁移和独立 PR，必须再次备份并提供用户确认。
- 本 Phase 1 以及首次 backfill 均不执行源表 `DELETE`、Vault cleanup 或文件删除。

## 8. 使用时的 fail-closed 判定

`CaseMaterialSelection` 只能创建或使用于同时满足以下条件的记录：

1. `CaseMaterial.projectId == request.projectId`，且项目仍存在；需要 Vault 的操作
   还必须验证
   `binding(request.projectId).privacyCaseId == vaultRef.caseId`。
2. material 未 deleted/revoked/blocked，source identity 完整。
3. generation 属于该 material，`reviewState == approved`。
4. `approvedPayloadSha256` 存在且与受保护 payload 重算值一致。
5. 当前 risk revision 等于 selection 绑定 revision，hash chain 完整，
   unresolved P0/P1 为零。
6. generation 未撤销；selection 未 deselect/invalidated。
7. 若操作需要 Vault source，精确 Vault 四元组重新验证成功。
8. 若操作是 approved automation/MCP，还必须独立验证当前 publication、
   receipt、grant、ticket、destination/purpose、hash 和 revocation epoch。

案件助手只读取经上述验证的 approved payload，不读取 raw Vault source、
`protected_review_blob` 中的 original pages 或 `attachments.content_blob`。

以下情况一律阻断而不是猜测：

- DPAPI blob 无法解密或 schema 不支持；
- public row 与 protected payload 不一致；
- project/case/material/redaction 任一归属冲突；
- Vault ref 缺列、版本错误、object 不可用或 hash 不一致；
- approved state 与 approved hash/risk state 矛盾；
- generation number 重复；
- legacy reference 无法解析；
- selection 指向旧 risk revision 或已撤销发布物。

## 9. 回滚

### Cutover 前

关闭 feature flag 即可恢复旧读路径。新增 target/ledger 数据保留，不删除、不降
schema version。随后修复迁移器并幂等重跑。

### Cutover 后但尚无 target-only 数据

可以回到 compatible-read 版本；仍保留 target 数据用于核对。不得通过 SQL drop
table 或复制单个数据库“回滚”。

### 已有 selection 或新模型写入后

旧二进制可能因较高 Privacy schema version 拒绝启动；此时唯一受支持的数据回滚是
恢复 A 阶段创建的完整五组件应用备份，并与对应应用版本一起恢复。不能只恢复
`user.sqlite` 或 `privacy-workflow.sqlite`，否则 Vault、approved publication 与
work-product revocation 状态可能分叉。

同样地，旧三组件备份只对尚无 unified material/binding、approved publication 和
work-product lineage 的切换前状态保持读兼容。一旦任一 lineage 存在，恢复服务
必须在暂存前以及首次组件替换前各检查一次并拒绝三组件恢复，防止检查与应用之间
新增状态造成部分回滚。

恢复前后都必须保留迁移报告。恢复动作不得删除用户原始外部文件；现有
`delete_review` 的显式、hash-checked、legal-hold-aware 删除流程不属于迁移回滚。

## 10. 验证查询与验收不变量

以下为实现阶段的代表性检查；跨库离线检查应将数据库以只读别名
`userdb`、`privacydb`、`approveddb` ATTACH，生产服务仍通过受限 repository API。

### 当前源库结构完整

```sql
PRAGMA integrity_check;
PRAGMA foreign_key_check;

SELECT r.redaction_id
FROM privacy_redactions r
LEFT JOIN privacy_materials m ON m.material_id = r.material_id
WHERE m.material_id IS NULL;
```

预期：`integrity_check = ok`，另两项无行。

### 当前 Vault 索引没有公开列冲突

```sql
SELECT v.material_id
FROM privacy_vault_material_refs v
JOIN privacy_materials m ON m.material_id = v.material_id
WHERE v.source_sha256 <> m.source_sha256
   OR v.object_version <= 0
   OR v.import_state NOT IN
      ('vault_committed','review_ready','processing_failed','revoked');
```

预期：无行。payload/Vault 四元组与实际对象内容仍必须由应用 validator 校验，
不能仅依赖 SQL。

### 隐私 case 是否对应真实项目

```sql
SELECT m.material_id, m.project_id, v.case_id AS privacy_case_id
FROM privacydb.privacy_materials m
LEFT JOIN userdb.projects p ON p.project_id = m.project_id
LEFT JOIN privacydb.project_privacy_case_bindings b
  ON b.project_id = m.project_id
LEFT JOIN privacydb.privacy_vault_material_refs v
  ON v.material_id = m.material_id
WHERE m.project_id IS NOT NULL
  AND (
    p.project_id IS NULL
    OR b.project_id IS NULL
    OR b.privacy_case_id <> v.case_id
  );
```

预期：无行。无法通过绑定恢复的历史行不是可自动归属案件；迁移后必须是
`projectId=null` 且保留 `legacyCaseId`。

### 身份绑定是一对一且格式严格

```sql
SELECT project_id
FROM privacydb.project_privacy_case_bindings
GROUP BY project_id
HAVING COUNT(*) <> 1;

SELECT privacy_case_id
FROM privacydb.project_privacy_case_bindings
GROUP BY privacy_case_id
HAVING COUNT(*) <> 1;

SELECT project_id, privacy_case_id
FROM privacydb.project_privacy_case_bindings
WHERE length(project_id) = 0
   OR length(privacy_case_id) <> 37
   OR substr(privacy_case_id, 1, 5) <> 'case_'
   OR substr(privacy_case_id, 6) GLOB '*[^0-9a-f]*';
```

预期：均无行。应用层还必须用 `PrivacyCaseId` parser 复核格式，SQL 约束不能代替
强类型边界。

### CaseFile 引用覆盖

```sql
SELECT cf.file_id
FROM userdb.case_files cf
LEFT JOIN privacydb.case_material_migration_ledger l
  ON l.migration_id = 'case-material-unification-v1'
 AND l.source_store = 'user.sqlite'
 AND l.source_table = 'case_files'
 AND l.source_key = cf.file_id
WHERE l.source_key IS NULL
   OR l.result_state NOT IN ('migrated','legacy_reference','blocked');
```

切换 target-primary 前预期：无行。`blocked` 可以存在，但必须可见、不可用且有稳定
error code。

### Generation 编号唯一且连续

```sql
SELECT material_id, generation_number, COUNT(*)
FROM privacy_redactions
GROUP BY material_id, generation_number
HAVING COUNT(*) <> 1;
```

预期：无行。另按 material 比较 `MIN=1`、`MAX=COUNT(*)`；编号一旦分配后重跑不变。

### Selection 不跨案件且不引用未批准代次

```sql
SELECT s.selection_id
FROM case_material_selections s
JOIN privacy_materials m ON m.material_id = s.material_id
JOIN privacy_redactions r ON r.redaction_id = s.redaction_id
WHERE r.material_id <> s.material_id
   OR m.project_id IS NULL
   OR m.project_id <> s.project_id
   OR r.review_state <> 'approved'
   OR r.approved_payload_sha256 IS NULL
   OR m.deleted_at IS NOT NULL;
```

预期：无行。active selection 还必须通过应用层 risk/hash/revocation 复核。

### 不静默删除

迁移前后必须记录并比较：

- `projects`、`case_files`、`attachments` 行数与主键/hash manifest；
- `privacy_materials`、`privacy_redactions`、risk revisions、receipts 行数；
- Vault committed object manifest；
- approved `publication_journal` 和 work-product manifest。

首次 backfill 的源表主键集合必须完全相同。任何减少都使迁移失败并触发完整备份
恢复；不能以“已迁入新表”为理由接受源记录减少。

## 11. Phase 1 交付判定

本文档完成后，Phase 1 对数据迁移的结论是：

- 当前 schema 与存储路径已明确；
- `ProjectId` 与 `PrivacyCaseId` 通过 ADR-0001 的持久化一对一绑定解析，不再假设
  字符串相等；
- `caseId=null`、匿名非空 case、CaseFile legacy reference 均有无损去向；
- ID、generation、hash、risk revision、Vault version 和 publication version
  的语义互不混用；
- 迁移具备可重入 ledger、分阶段读兼容、fail-closed 边界和完整备份回滚；
- 首次迁移不删除任何源数据库行、Vault object、attachment blob 或外部文件；
- 只有用户显式选择且运行时重新验证通过的 approved generation 才能进入案件助手。
