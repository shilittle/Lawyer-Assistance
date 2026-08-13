# Lawyer Assistance 文档

Lawyer Assistance 是面向 Windows x86_64 的本地法律辅助应用。它提供离线公开法律检索、无需案件即可使用的普通聊天、案件材料与脱敏、approved-only 案件助理、法律图示、成果管理与加密备份。默认数据边界是本地处理；普通聊天、案件工作和 approved automation 使用互不混用的出站边界，任何 Provider 或宿主集成都必须经过明确配置和对应授权。

当前版本为 `0.4.0-beta.2`，定位为未签名技术预发布。它不是已完成 Authenticode、自动更新、生产 OCR 和完整归档数据交付验收的正式版本。开始使用前请先阅读[当前发布状态](release-status.md)。

源代码仓库当前公开。公开可见性只说明源码和已实际发布的文件可供检查，并不建立可信 Windows publisher、可用 updater 签名、OCR 资格、干净机器验收或正式发布状态。

## 用户文档

- [快速开始](getting-started.md)：安装、普通聊天与附件、材料与脱敏、案件助理、BYOK Provider、MCP、OCR 与备份。
- [安全与隐私](security-and-privacy.md)：普通聊天、案件工作、自动化三种出站边界，以及本地数据、OCR、宿主集成和备份规则。
- [当前发布状态](release-status.md)：`0.4.0-beta.2` 已实现能力、默认禁用项和正式发布门槛。
- [从 v0.3.1 升级到 v0.4.0](upgrade-v0.3.1-to-v0.4.0.md)：exact profile 自动升级、完整五槽恢复、旧版重开与再次升级。
- [English documentation](README.en.md)

## 功能参考

- [MCP 概览](mcp/README.md)
- [MCP 安装与运行](mcp/installation.md)
- [MCP 工具与 profile 契约](mcp/tools.md)
- [批准案件工作区](mcp/approved-case-workspace.md)
- [图示系统架构](diagrams/architecture.md)
- [图示系统安全模型](diagrams/security-model.md)
- [隐私工作区与 MCP 边界](privacy-vnext/WORKSPACE_AND_MCP.md)
- [隐私运维说明](privacy-vnext/OPERATIONS.md)：本地处理、案件材料、案件助理、自动化和维护入口。
- [法律数据集与运行时数据库](data/legal-corpus.md)
- [仓库结构与目录规范](development/repository-layout.md)
- [Windows 发布签名](development/release-signing.md)

## 宿主集成

仓库提供 WorkBuddy、Codex 和 OpenCode 的功能性集成示例。默认集成都固定为不含案件数据的 `public_law_only`；批准案件工作区使用独立、默认禁用且需要 App 当前授权的配置。

- [WorkBuddy](../integrations/workbuddy/README.md)
- [Codex](../integrations/codex/README.md)
- [OpenCode](../integrations/opencode/README.md)

## 法律与数据说明

应用内容仅用于辅助检索和律师复核，不替代对现行官方文本、案件事实和专业判断的核验。应用包使用经过验证的 `runtime-slim-v1` 运行时法律库；完整归档数据库不随技术预发布包提供。数据来源和版本身份以仓库中的 source manifest、distribution manifest 和应用内版本信息为准。

- [数据来源清单](../data/sources/source_manifest.md)
- [发布说明](../RELEASE_NOTES.md)
- [许可证](../LICENSE)
