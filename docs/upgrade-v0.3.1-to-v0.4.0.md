# 从 v0.3.1 升级到 v0.4.0

本指南适用于由官方 `v0.3.1` 数据结构产生、且仍保持原始 user schema 10 与 Privacy schema 1
形态的本地工作区。升级器只接受经过完整结构、业务数据与来源证明验证的 exact v0.3.1 profile；
无法唯一认证的数据库、手工修改过的 schema、混合版本目录或不完整恢复状态都会停止升级，而不会
猜测来源或继续写入。

当前仓库中的 v0.4.0 仍处在正式发布验收流程中。只有正式签名、发布资产、CI、干净机器与
服务端回读门禁全部通过后，才应把对应安装包视为稳定版。

## 升级前

1. 完全退出 v0.3.1，确认没有仍在运行的 Lawyer Assistance 或 MCP 进程。
2. 保留整个 v0.3.1 应用数据目录，不要单独复制、编辑或替换其中的 SQLite、Privacy 或恢复文件。
3. 使用同一 Windows 用户启动 v0.4.0。升级与恢复证据由 Windows CurrentUser 保护，不能由另一
   用户代为生成或应用。
4. 不要预先创建 Vault、approved workspace 或 work-products 目录。exact v0.3.1 的后三个目标
   组件必须原本不存在。

## 首次升级

v0.4.0 在普通启动初始化之前识别 exact v0.3.1 profile。写入任何源数据前，它会先创建并认证
五槽原态恢复点：user v10 与 Privacy v1 为 present，Vault、Approved 和 WorkProducts 为 absent。
随后按冻结顺序创建目标组件、迁移 Privacy、建立审计型一对一 `ProjectId ↔ PrivacyCaseId` 绑定、
迁移材料与投影，最后才在一个事务中把 user schema 10 升到 11。

升级期间不要终止、复制或编辑应用数据目录。若进程意外结束，重新启动同一 v0.4.0；启动仲裁器会
根据已经认证的 receipt 和五槽实态，从唯一安全阶段继续或恢复，不会运行 SQL down-migration，也
不会只恢复一个数据库。

升级完成后应检查：

- 原项目、会话、消息和 Privacy 复核数据仍可读取；
- 项目与 Privacy 案件之间的绑定由后端持久保存，前端不显示、生成或推导权威 Privacy CaseId；
- Vault、approved workspace 与 work-products 已按目标 schema 建立；
- 重启不会产生第二条绑定、第二份材料、第二个 generation 或第二条 terminal receipt。

exact v0.3.1 本地复核可能没有可恢复的源显示名或 Privacy CaseId。此类材料会明确保持未归属，
直到用户手动归入项目；应用可以显示经过认证的“旧版名称不可用”占位，但不会用哈希伪造旧文件名，
也不会据此猜测绑定。

## 显式恢复到 v0.3.1

完整恢复是维护操作，不是普通 `.lavbackup` restore。它只在已完成升级并重新认证当前五槽后可用。
在 v0.4.0 的维护界面中选择恢复，并逐字输入：

```text
恢复到 v0.3.1 并退出当前应用
```

前端只发送该确认短语；它不会发送路径、lineage、Privacy CaseId、凭据或备份 bytes。后端先创建
当前 v0.4.0 五组件 Safety 备份与四项凭据归档，再关闭新的 MCP/standalone 准入、排空现有操作、
撤销 active standalone session，并在全部写屏障内完成最终复证。正式恢复 marker 安装后，应用
只请求受控重启，不会重新开放当前会话中的业务写入。

下一次启动是 recovery-only：普通 manager、UI、maintenance 与后台任务都不会初始化。恢复器以
固定顺序交换五个物理槽，提交前的失败会使用已认证 abort intent 恢复完整 v0.4.0；提交后的失败
只会继续清理，不能反向暴露混合状态。完成报告安装并认证后，应用以成功状态退出。

此时 user 数据库恢复为原态 bundle 中的 schema 10 bytes，Privacy 恢复为 schema 1 bytes，Vault、
Approved、WorkProducts 目标组件和四项 v0.4.0 凭据均不存在。原态 V2、当前 Safety V3、凭据归档、
commit/abort/report 与迁移报告会保留在审计命名空间；它们不是后续升级的 terminal marker。

## 恢复后与再次升级

1. 显式启动 v0.3.1，确认原项目、会话、消息和 Privacy 复核数据可以读取，然后正常退出。
2. 以后需要返回 v0.4.0 时，再显式启动同一 v0.4.0。它会重新识别 exact v0.3.1 profile，建立新的
   lineage，并执行完整升级。
3. 再次重启 v0.4.0，确认升级终态保持幂等。

不要把 migration-only 原态 bundle 交给普通 V3 restore；普通 restore 必须拒绝 old schema 与
migration-only identity。不要移动、重命名或手工删除任何 pending、incoming、rollback、cleanup
或 audit 文件。若启动返回恢复或来源认证错误，请保留整个应用数据目录和匿名错误码，停止写入，
再按受控支持流程检查；不要通过编辑数据库或删除 marker 绕过失败关闭。
