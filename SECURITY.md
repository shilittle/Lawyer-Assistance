# 安全政策 / Security Policy

## 当前支持边界

当前维护版本为 `1.0.0`，产品是本机 loopback Rust 服务和纯 HTML WebUI。GitHub Release 提供未签名的 Windows 便携 ZIP；项目不提供 Tauri 安装器、自动更新或 OCR 资格发布链。请使用包内 `MANIFEST.sha256`、同名 `.zip.sha256` 和法律库发行清单核对完整性；公开发布不表示产物已通过 Windows 代码签名。

用户数据默认存放在 `%LOCALAPPDATA%\LawyerAssistanceWeb`。旧 Tauri 数据目录不迁移。原件、映射和私密正文只由后台工作区处理；WebUI 会话 token 与 MCP client token 分开，loopback 请求检查 Host/Origin、CSRF 和不缓存响应。

## 报告安全问题

优先使用 GitHub 的 **Security → Report a vulnerability** 私密入口。不要在公开 Issue、PR、日志或截图中提交：

- 真实案件、客户或当事人信息；
- 原始 TXT/DOCX、脱敏映射、OCR 内容或法律数据库副本；
- API key、token、证书、私钥、session、MCP client token；
- 能识别个人、机构或本机环境的完整路径和原始日志。

报告应包含最小化的合成复现、版本/commit、预期行为、实际行为和影响范围。若私密入口不可用，请先创建不含漏洞细节和敏感数据的普通 Issue，请求维护者提供安全联系方式。

## 数据边界

- TXT/DOCX 导入、识别、替换、残留检查和导出默认在本地运行。
- 云辅助只能由用户针对具体材料版本、Provider、模型和用途明确授权；模型返回的是候选片段，本地必须验证其存在后才可替换。
- 未通过提取完整性、冲突处理、别名一致性或残留扫描的材料不得发布，也不能经 MCP 读取。
- `public_law_only` 只读取公开法律库，不接触工作区；`privacy_workspace` 只返回任务状态和已发布脱敏文本，不提供原文、映射、原始文件名或磁盘路径。
- 路径输入只接受配置收件目录下的相对路径；符号链接、越界路径、源文件变化和过期/撤销结果必须失败关闭。
- 错误、日志和 manifest 不得包含正文、映射、token 或完整本机路径。

## English

The maintained version is `1.0.0`, a local loopback Rust server with a plain HTML WebUI. GitHub Releases provides an unsigned Windows portable ZIP. There is no Tauri installer, automatic-update channel, or OCR qualification release chain. Verify `MANIFEST.sha256`, the adjacent `.zip.sha256`, and the legal distribution manifest. Public availability does not imply Windows code signing.

User data defaults to `%LOCALAPPDATA%\LawyerAssistanceWeb`; the old Tauri data directory is not migrated. Original material, mappings, and private text stay in the backend workspace. Browser sessions and MCP client tokens are separate, and loopback requests enforce Host/Origin, CSRF, and no-store responses.

Use GitHub's private **Security → Report a vulnerability** flow. Never include real case data, source documents, redaction mappings, OCR text, database copies, credentials, private keys, session descriptors, client tokens, identifying paths, or raw logs in a public report. Provide a minimal synthetic reproduction, version/commit, expected and actual behavior, and impact.

TXT/DOCX extraction, detection, replacement, residual scanning, and export are local by default. Cloud assistance requires explicit authorization bound to the exact material version, Provider, model, and purpose; candidate spans are locally verified before replacement. Only complete, conflict-free, alias-consistent, residual-clean versions are published. The public MCP never accesses the private workspace, and `privacy_workspace` returns only task status and published redacted text.
