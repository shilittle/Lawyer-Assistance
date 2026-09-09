# Changelog

本文件记录 Lawyer Assistance 的用户可见变化。

## [1.0.0] - 2026-09-09

### Added

- Rust `lawyer-assistance` 本机后台服务，提供 loopback HTTP API、会话认证、任务恢复和嵌入式静态 WebUI。
- 普通 HTML/CSS/JavaScript WebUI，直接嵌入 server 二进制，不依赖 Tauri、WebView2 或前端开发服务器。
- TXT/DOCX 导入、正文和表格提取、规则与词典识别、稳定别名、替换、残留检查、复核、撤销，以及 TXT/Markdown/重建 DOCX/ZIP 导出。
- 本地只读法律检索、条文详情、历史版本、效力日期、关联法规和收藏。
- `privacy_workspace` MCP 的 `submit`、`status`、`read_result` 三个工作区工具，同时保留公开法律五工具；私有 profile 共八个工具。
- Windows 无窗口 `Lawyer-Assistance.vbs` 启动器、认证 `Stop-Lawyer-Assistance.vbs` 停止器，以及包含运行时法律库和当前文档的 x86_64 便携 ZIP 打包流程。

### Changed

- 工作区数据使用 `%LOCALAPPDATA%\LawyerAssistanceWeb`；旧 Tauri 案件、材料、映射、授权和其他用户数据保持不变，不读取、不迁移、不覆盖。
- MCP public/private profile 共用本机后台的业务边界；`approved_case_workspace`、`redacted_case` 和 `diagram_authoring` 明确停用，不兼容映射。
- 版本与结果流程支持任务恢复、取消、重试、冲突复核、结果撤销和有效版本检查。

### Breaking changes

- Tauri 窗口、IPC、WebView2、安装器、签名、updater 和旧资格发布链不再属于 v1.0.0 运行或发布路径。
- 首版输入限定 TXT 和 DOCX；PDF、图片、扫描件 OCR、原件版式保留、复杂案件工作台、法律图谱和自动办案流程没有入口。OCR 仅保留扩展接口，不安装或发布运行时。
- 公开法律 MCP 固定为五个工具；`privacy_workspace` 固定为八个工具。停用的旧 profile 返回 `profile_disabled`。

### Security and release boundaries

- Provider 密钥保存后读回校验，无法读取或内容不一致时明确返回保存失败。
- 原始材料、映射、凭据和用户数据不进入便携包、日志、公开 MCP 或未经授权的 Provider；MCP 私有结果只返回已发布脱敏文本。
- 便携包未签名，不提供安装器或自动更新器；发布资产须通过 ZIP SHA-256 和包内 manifest 校验。
- 本次公开发布未完成真实 Provider 联调；疑难云辅助和自动化回归使用可控模拟服务。合成材料的通过率、误报和漏检统计用于回归验证，不构成真实案件精度保证。
