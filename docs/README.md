# Lawyer Assistance 文档

当前版本 `0.4.0` 是本机 Web 重构版本：Rust server 提供业务和 HTTP/MCP 接口，`apps/web` 提供无需构建的普通 HTML/CSS/JavaScript 界面。产品首要目标是 TXT/DOCX 脱敏和本地法律检索。

## 用户文档

- [快速开始](getting-started.md)：启动服务、导入材料、复核、导出和使用 MCP。
- [安全与隐私](security-and-privacy.md)：数据存储、云辅助授权、会话和 MCP 边界。
- [法律数据与运行时数据库](data/legal-corpus.md)：来源、发行清单和审计命令。
- [Web API 文档](web/README.md)：若该目录已生成，记录 HTTP 请求和响应契约。
- [MCP 文档](mcp/README.md)：公开法律和 `privacy_workspace` 工具、传输和安全说明。

## 开发文档

- [仓库结构](development/repository-layout.md)
- [贡献指南](../CONTRIBUTING.md)
- [安全政策](../SECURITY.md)

## 支持范围

当前只支持 TXT、DOCX、公开法律检索、简单模板、Provider 对话和指定的 MCP 工具。PDF、图片、扫描件 OCR、原件版式保留、复杂案件工作台、法律图谱和自动办案流程不在首版范围。没有 Tauri 安装器、签名/updater 发布链或 OCR 运行时。

## 数据和许可证

运行时只读法律库与许可证位于 `data/runtime/`。法律数据来源和构建/审计工具保留在 `data/sources/`、`data/build/`；这些工具不应在应用运行期间写入用户数据目录。
