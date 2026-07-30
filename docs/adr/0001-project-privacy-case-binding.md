# ADR-0001：ProjectId 与 PrivacyCaseId 的持久化一对一绑定

- 状态：Accepted
- 决策日期：2026-07-30
- 适用版本：v0.4.0 起
- 关联计划：
  - `docs/plans/2026-07-29-app-information-architecture-and-workflow-rebuild.md`
  - `docs/plans/2026-07-29-case-material-data-migration.md`

## 背景

应用案件使用 `case-...` 形式的 `ProjectId`，Privacy vNext、Vault、签名、
approved workspace 与 MCP 隐私边界使用严格的
`case_[0-9a-f]{32}` `PrivacyCaseId`。当前代码曾把两者当作同一字符串：
前端传入现有 `ProjectId` 会被 Privacy parser 拒绝；不传则会生成与项目无关联的
匿名 `PrivacyCaseId`。

全量改写 `ProjectId` 会触及 `projects` 及大量外键、审计和历史成果，并违反
`user.sqlite` 只读迁移边界。放宽 `PrivacyCaseId` 会破坏冻结的 Vault 与签名身份
规范。因此采用显式持久化绑定。

## 决策

### 两种身份各自保留

`ProjectId`：

* 保留现有 `case-...` 值和语义；
* 是案件、项目、CaseMaterial 归属和前端工作流的主身份；
* 不迁移、不重写 `projects.project_id` 或其引用。

`PrivacyCaseId`：

* 保留 `case_` 加 32 位小写十六进制的严格格式；
* 是 Privacy、Vault、加密 AAD、签名、approved workspace 和 MCP 隐私边界身份；
* 不放宽 parser，不接受 `ProjectId`。

两者不得通过字符串相等、替换、哈希截断、顺序或可预测计数器关联。唯一受支持的
关联是 `privacy-workflow.sqlite` 中一对一、审计型、默认不可变的持久化绑定。

### 持久化模型

绑定表逻辑名为 `project_privacy_case_bindings`，至少保存：

```text
project_id              PRIMARY KEY, NOT NULL
privacy_case_id         UNIQUE, NOT NULL, strict case_[0-9a-f]{32}
binding_version         positive integer
creation_source         constrained enum
creation_audit_id       non-empty
migration_id            nullable
created_at
updated_at
```

创建审计使用 append-only 事件或等价审计记录，至少绑定
`project_id`、`privacy_case_id`、`binding_version`、来源、操作 ID、结果和时间。
数据库和应用层同时校验双向唯一性与 Privacy ID 格式。

v1 不允许普通更新改变任一身份列。发现同一端已绑定另一身份时返回
`binding_conflict`，不得覆盖、删除后重建或静默修复。

SQLite 的冲突算法也不得成为绕过路径。绑定与创建审计必须同时拒绝普通
`UPDATE`、`DELETE`、`INSERT OR REPLACE` 以及会改写身份的
`ON CONFLICT DO UPDATE`。每个可写连接必须启用并核验外键与递归触发器，
初始化时还要验证实际 schema/trigger 契约；同名弱表、缺失保护触发器或被替换为
空操作的触发器都必须使应用 fail closed，而不是继续运行。

### 解析服务

可信后端提供唯一的身份解析边界：

```text
resolve(ProjectId) -> PrivacyCaseId | unbound
resolve_or_create(ProjectId, lifecycle_context) -> PrivacyCaseId
reverse_resolve(PrivacyCaseId) -> ProjectId | unbound
validate_pair(ProjectId, PrivacyCaseId) -> valid | binding error
```

错误至少区分：

* `invalid_project_id`
* `invalid_privacy_case_id`
* `project_privacy_case_unbound`
* `project_privacy_case_conflict`
* `ambiguous_legacy_binding`
* `project_privacy_case_store_failed`

以项目为入口的 Tauri command 接收强类型或明确封装的 `ProjectId`。只有可信后端
可以解析绑定并把 `PrivacyCaseId` 传入 Privacy/Vault。前端不得生成或推导
`PrivacyCaseId`。

### 创建与并发

只在明确允许初始化的生命周期点创建绑定。创建使用单个写事务和立即写锁：

1. 查询项目现有绑定；
2. 若存在，验证并返回；
3. 若不存在，使用操作系统安全随机源生成 `case_[0-9a-f]{32}`；
4. 在同一事务写绑定、创建审计以及必要初始化状态；
5. 提交前重新依赖数据库双向唯一约束。

并发竞争者若发现另一个事务已为同一项目提交绑定，必须读取并返回该同一值；若
另一端发生冲突则 fail closed。不得产生第二个绑定或第二套 Vault。

### 生命周期与安全校验

生命周期代码不再比较 `ProjectId == PrivacyCaseId`，而是验证：

```text
binding(ProjectId).privacyCaseId == VaultRef.caseId
```

Vault 内部仍只接受严格 `PrivacyCaseId`，并继续验证完整
`(privacyCaseId, objectId, objectVersion, sourceSha256)` 四元组。MCP、receipt、
publication、ticket、grant、签名、撤销 epoch 和 protected work-product 边界不因
本 ADR 放宽。

删除项目是跨 `user.sqlite`、Privacy、Vault、approved publication 与 work-product
边界的可恢复生命周期操作，不是删除绑定的理由。删除必须先持久化
append-preserving journal，在 Privacy/Vault 侧完成撤销和材料 tombstone，再把
用户项目删除作为最后一个业务提交，并允许启动时幂等续作。原绑定、创建审计和
删除 journal 永久保留；已删除的 `ProjectId` 视为 retired，不得通过重新创建同名
项目、删除后插入绑定或生成新 `PrivacyCaseId` 使其复活。

### 历史迁移

迁移只读扫描 `user.sqlite`，只写 Privacy 可写库：

1. 校验已存在绑定；
2. 扫描项目与可信 Privacy/Vault provenance；
3. 既有绑定，或完整可信元数据无歧义指向唯一身份对时，保留原
   `PrivacyCaseId` 并幂等写入绑定；
4. 项目无任何 Privacy/Vault 状态时，可安全随机创建绑定；
5. 多候选、跨项目冲突、Vault 四元组冲突或证据不足时写结构化 blocked 结果；
6. 不按名称、顺序、字符串相似度、单独文件名或单独 hash 猜测；
7. 重跑读取已完成 ledger；中断只重试未完成事务；
8. 迁移前后验证 `user.sqlite` 未被写入。

历史 Vault object、payload、publication 和 work product 保留原
`PrivacyCaseId`。无法无歧义关联的记录保持未归属并保留 `legacyCaseId`。

未归属记录只能经用户明确发起、后端审计的归属命令处理。该命令必须重新验证目标
项目、既有双向绑定、材料/generation 身份和 Vault 四元组，并在单一事务或可恢复
journal 边界内完成；重复请求只能返回同一结果，并发冲突必须 fail closed。
不得用单纯改写 `project_id` 或 `case_id` 把既有 Vault 对象移动到另一身份。
需要改变 Vault case identity 时必须创建受控的新 revision/ref，并保留原始
`PrivacyCaseId` 与完整审计链。

### 回滚

绑定 schema 与 ledger 是 append-preserving 数据，不通过 drop table 或改写 Vault
回滚。切换前可关闭 target-primary 读并保留绑定供核对；已有新模型写入后只能使用
计划规定的五组件一致性备份与对应应用版本恢复。任何回滚都不得修改或删除既有
Vault object。

旧版三组件备份仅允许用于尚未产生 unified material/binding、approved publication
或 work-product lineage 的切换前历史状态。一旦存在任一上述状态，恢复入口在暂存
前和首次组件替换前都必须再次拒绝三组件恢复；不得用旧备份部分覆盖五组件状态。

## 影响

优点：

* 保留全部既有项目 ID 和 Privacy/Vault 安全格式；
* 避免跨 19 张项目身份表的破坏性重写；
* 支持重启、升级、崩溃恢复、并发和审计；
* 明确消除字符串相等假设。

代价：

* 所有跨案件/Privacy 边界必须调用解析服务；
* 迁移和生命周期校验需要同时处理两种强类型身份；
* 历史匿名 Privacy 数据可能保持 fail-closed 未归属，等待显式处理。

## 被否决方案

* 全量迁移 `ProjectId` 为 `case_<32hex>`：影响面大，违反只读源库和历史兼容边界。
* 放宽 Privacy `CaseId`：破坏冻结的 Vault、签名和 MCP 身份规范。
* 运行时字符串转换或哈希映射：不可审计、不可恢复，并违反随机 ID 与禁止推导要求。
