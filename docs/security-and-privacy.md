# 安全与隐私

## 数据分层

- **公开法律数据**：`data/runtime/legal_core.sqlite` 只读打开，公开 MCP 和 WebUI 法律检索只访问它。
- **用户工作区**：默认位于 `%LOCALAPPDATA%\LawyerAssistanceWeb`，保存分组、任务、提取结果、脱敏版本、词典、Provider 状态、收藏和会话。旧 Tauri 数据目录不迁移。
- **原始/私密材料**：原件、映射和未发布正文由后端工作区保护；日志、错误和 MCP 不返回它们。
- **浏览器会话**：登录 bootstrap 只用于本机首次登录；之后使用 HttpOnly 会话 cookie 和 CSRF token。响应 `Cache-Control: no-store`，Host/Origin 不匹配请求被拒绝。

## 脱敏外发边界

TXT/DOCX 提取、识别、替换、残留扫描和导出默认本地完成。云辅助必须明确绑定材料版本、Provider、模型和用途；发送的是提取文本，模型返回的只是候选片段，本地检查候选确实出现在原文后才执行替换。未授权、撤销、版本漂移、路径越界、提取不完整或残留扫描失败都会阻断发送/发布。

Provider 对话不会自动读取原始材料，只能使用用户当前消息和明确选中的有效脱敏结果。不要把原始案件正文粘贴进普通聊天、浏览器、搜索引擎或其他 MCP。

## MCP 边界

- `public_law_only` 固定五个公开法律只读工具，不打开工作区数据库。
- `privacy_workspace` 的三个脱敏工具共用后台业务，但独立使用客户端 bearer token；客户端只能绑定指定材料组和收件目录。
- `privacy_workspace.submit` 只接受收件目录下相对路径，并重新检查符号链接、越界、文件变化和幂等键。
- `privacy_workspace.status` 返回任务状态和匿名安全原因码；`read_result` 只分页返回当前有效的脱敏文本。
- 待复核、失败、取消、撤销和过期结果不可读；不会提供原文、映射、原始文件名、磁盘路径、人工批准或云授权工具。
- 旧 `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` profile 明确停用。

## 运行和报告

便携包只写入 `%LOCALAPPDATA%\LawyerAssistanceWeb`，启动器通过隐藏 `wscript.exe` 启动或停止 server；停止器只调用经过会话和 CSRF 认证的 loopback API，不结束任意进程。包不包含用户数据、凭据、签名私钥或 updater。使用包内 `MANIFEST.sha256`、`.zip.sha256` 和法律库发行清单核对完整性。

报告安全问题时只使用合成数据，避免上传真实材料、映射、凭据、路径和日志原文；入口见仓库根目录 [SECURITY.md](../SECURITY.md)。
