# Lawyer Assistance MCP

当前生产契约是隐私收紧后的 `public_law_only`，只提供五个公开法律只读工具：

- `system_status`
- `legal_search`
- `legal_get_article`
- `legal_get_versions`
- `legal_get_relations`

stdio 与 Streamable HTTP 必须列出相同的五项；宿主看到多一项或少一项都应拒绝连接。仓库中的 WorkBuddy、Codex 和 OpenCode 示例均按此契约配置。

`redacted_case` 是实验 profile，只在五项基础上增加需要精确活动票据的 `citation_validate`。当前 App 尚不能签发绑定该用途、目标和请求字节的正向票据，因此生产集成仍固定使用公开五项。没有票据、密钥、持久化状态或 Windows 保护能力时，第六项调用 fail-closed。

案件读取、案件写入、材料导入、缺口分析、文书生成和文书导出工具在两个 profile 中都隐藏且不可调用。Provider 路径同样没有案件批准票据正向集成；案件数据在请求序列化前被拒绝。

## 文档

- [架构与信任边界](architecture.md)
- [工具与 profile 契约](tools.md)
- [安装与运行](installation.md)
- [安全与隐私](security-and-privacy.md)
- [数据库与版本](database-and-versioning.md)
- [开发与测试](development-and-testing.md)
- [兼容性矩阵](compatibility-matrix.md)
- [打包、迁移与回滚](packaging-and-migration.md)

早期文档和历史验收曾记录固定 12 工具的案件闭环；那是历史证据，已经被本隐私收紧契约取代，不是当前可用能力。历史正文不应被解释为重新启用依据。