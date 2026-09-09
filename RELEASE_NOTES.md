# Lawyer Assistance v1.0.0：Web 大版本发布 / Web Major Release

Lawyer Assistance v1.0.0 是面向 Windows 本机单用户场景的 Web 大版本。它由 Rust 后台服务、普通 HTML WebUI 和可独立调用的 MCP 程序组成，首要用途是材料脱敏和本地法律检索。

## 下载与运行

下载 GitHub Release 资产 `Lawyer-Assistance_1.0.0_windows-x86_64-portable.zip`，并核对同名 `.zip.sha256`。解压后：

1. 双击 `Lawyer-Assistance.vbs` 启动服务；脚本通过 `wscript.exe` 隐藏窗口运行 `lawyer-assistance.exe serve --open --port 8877`。
2. 浏览器访问 `http://127.0.0.1:8877`。默认工作区为 `%LOCALAPPDATA%\LawyerAssistanceWeb`。
3. 双击 `Stop-Lawyer-Assistance.vbs` 优雅停止服务，也可执行 `lawyer-assistance.exe stop`。停止命令验证当前用户的加密连接描述符、loopback 会话和 CSRF 请求，只停止匹配的本机 server，不调用任意进程终止器。

ZIP 包含两个 release 可执行文件、运行时法律库及许可 notices、当前使用文档、MCP 配置示例、隐藏窗口启动/停止脚本，以及 `MANIFEST.sha256`、`portable.manifest.json`。它是未签名的 Windows x86_64 便携产物，不包含安装器、签名文件、自动更新器或 updater 资源。

## 主要能力

- **材料脱敏**：批量导入 TXT/DOCX，提取正文和表格，进行规则与词典识别、稳定别名替换、残留检查、人工复核和不可变结果发布；支持 TXT、Markdown、重建 DOCX 与批量 ZIP 导出。
- **法律检索**：使用只读 `legal_core.sqlite` 查询法律、条文、历史版本、效力日期、关联法规和收藏。
- **轻量业务**：六类固定模板、引用复制和简单 Provider 对话。对话上下文只能来自用户主动输入以及明确选择的法条和有效脱敏结果。
- **MCP**：`public_law_only` 固定提供 5 个公开法律工具；`privacy_workspace` 共提供 8 个工具，即这 5 个公开工具加上 `privacy_workspace.submit`、`privacy_workspace.status`、`privacy_workspace.read_result`。私有工具只能通过已授权的本机后台读取已发布脱敏文本。

## Breaking changes

- Tauri 桌面入口、窗口/IPC、WebView2、安装器、签名、updater 和旧资格发布链已从 v1.0.0 发布路径移除；使用本机 server、浏览器和 VBS 启动/停止脚本。
- 工作区使用全新目录 `%LOCALAPPDATA%\LawyerAssistanceWeb`。旧 Tauri 案件、材料、映射、授权和其他用户数据保持原样，不读取、不迁移、不覆盖。
- `approved_case_workspace`、`redacted_case`、`diagram_authoring` profile 已停用并返回 `profile_disabled`，不会静默映射到 `privacy_workspace`。
- 首版输入范围为 TXT 和 DOCX；PDF、图片、扫描件 OCR、原件版式保留、复杂案件管理、法律图谱和自动办案流程不在 v1.0.0 范围内。OCR 只保留扩展接口，不安装或发布 OCR 运行时。

## 验证与已知边界

发布验证覆盖 Rust 全工作区、WebUI、Python 打包与集成用例，以及原生凭据并发读写；测试命令见 [开发与测试](docs/mcp/development-and-testing.md)，核心重构的既有验收见 [Web 验收记录](docs/web/validation.md)。MCP 验证覆盖公开 5 工具、私有 8 工具及 HTTP/stdio 调用边界。

疑难云辅助使用可控模拟服务完成自动化验证，本次公开发布未完成真实 Provider 联调；真实凭据和测试材料不会随包提供。合成材料上的通过率、误报和漏检统计用于回归检查，不能作为真实案件精度保证。法律数据仍需结合官方现行文本、案件事实和律师复核。

## 文档

- [快速开始](docs/getting-started.md)
- [安全与隐私](docs/security-and-privacy.md)
- [MCP 工具与协议](docs/mcp/README.md)
- [Web 核心功能与运行边界](docs/web/README.md)
- [法律数据与运行时数据库](docs/data/legal-corpus.md)
