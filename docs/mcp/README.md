# Lawyer Assistance MCP

当前默认 MCP 生产契约是隐私收紧后的 `public_law_only`，只提供五个公开法律只读工具：

- `system_status`
- `legal_search`
- `legal_get_article`
- `legal_get_versions`
- `legal_get_relations`

默认 stdio 与 Streamable HTTP 必须列出相同的五项；宿主看到多一项或少一项都应拒绝连接。仓库中的 WorkBuddy、Codex 和 OpenCode 默认示例均按此契约配置。

`redacted_case` 是实验 profile，只在五项基础上增加需要精确活动票据的 `citation_validate`。当前 App 尚不能签发绑定该用途、目标和请求字节的正向票据，因此生产集成仍固定使用公开五项。没有票据、密钥、持久化状态或 Windows 保护能力时，第六项调用 fail-closed。

`approved_case_workspace` 是独立资格门禁 profile，`tools/list` 精确列出公开五项、十个 opaque-ID-only 案件/成果工具和六个批准图示工具，共 21 项。其生产 handler、App 签票和 standalone session 已实现；仓库静态资产仍默认禁用。policy v2 的 16 个非公开 grants 分为 `read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`，旧 read/write 不静默扩权，旧 session 必须撤销重建。只有当前 App 已资格化、已发布精确批准 generation、并签发匹配 session/ticket 时才执行。缺失、过期、撤销、漂移或不匹配返回 `PROFILE_NOT_QUALIFIED` 或更具体的匿名错误；工具可发现不等于已授权。

`diagram_authoring` 是另一个永久仅限合成/公开数据的 profile；它生成明文本地 HTML bundle，不能处理真实案件。批准案件图示只走 `approved_case_workspace`：render/update 发布加密 protected HTML，export 只返回 descriptor metadata，不返回 path、URI 或 HTML。

旧的 `case_get_state`、patch、任意材料导入、缺口分析、文书生成和路径导出能力在所有 profile 中仍隐藏且不可调用。

应用内普通聊天、案件助理和 MCP/自动化是三个独立边界：普通聊天通过 `start_interactive_assistant_run` 发送用户主动提供的非案件内容；案件助理通过 `start_case_assistant_run` 只发送本次明确选择的 approved-only 投影和最小已确认案件数据；自动化 Provider 与 Approved MCP 位于“设置 → MCP 与自动化”，继续使用独立资格和精确授权。普通聊天的恢复不增加任何 MCP 工具，也不允许 `CASE_RAW` 或 `CASE_REDACTED_PENDING` 进入 `ExternalMcpHost`。旧多意图入口已经物理删除；任何绕过当前闭合入口的裸案件请求仍在网络前 fail closed。

## 文档

- [架构与信任边界](architecture.md)
- [工具与 profile 契约](tools.md)
- [批准案件工作区 profile](approved-case-workspace.md)
- [安装与运行](installation.md)
- [安全与隐私](security-and-privacy.md)
- [数据库与版本](database-and-versioning.md)
- [开发与测试](development-and-testing.md)
- [兼容性矩阵](compatibility-matrix.md)
- [打包、迁移与回滚](packaging-and-migration.md)

早期文档和历史验收曾记录固定 12 工具的案件闭环；那是历史证据，已经被本隐私收紧契约取代，不是当前可用能力。历史正文不应被解释为重新启用依据。
