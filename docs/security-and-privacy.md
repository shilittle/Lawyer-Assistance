# 安全与隐私

## 数据分层

- **公开法律数据**：`data/runtime/legal_core.sqlite` 与同目录的 `judicial_cases.sqlite` 均只读打开；法条检索和案例检索分别访问各自数据库。
- **用户工作区**：默认位于 `%LOCALAPPDATA%\LawyerAssistanceWeb`，保存分组、任务、提取结果、脱敏版本、词典、Provider 状态、收藏和会话。旧 Tauri 数据目录不迁移。
- **原始/私密材料**：原件、映射和未发布正文由后端工作区保护；日志、错误和 MCP 不返回它们。
- **浏览器会话**：登录 bootstrap 只用于本机首次登录；之后使用 HttpOnly 会话 cookie 和 CSRF token。响应 `Cache-Control: no-store`，Host/Origin 不匹配请求被拒绝。

## 脱敏外发边界

配置 AI 模型后，后台以视觉 OCR、模型实体定位、本地精确替换和残留检查处理材料。国内官方预设默认允许发送用户所选原文；自定义地址需确认归属和发送设置，地址变更后重新判断。未信任供应商只能使用有效脱敏材料引用，不能直接接收原件和上传附件。

AI 搜索、写作和会话只读取用户选中的材料与附件。每轮重新校验供应商、材料版本和结果有效性；撤销或材料变化后阻止后续发送。发送到服务商的既有请求无法撤回。材料中的伪造指令只作为内容，不获得工具或配置权限。

AI 可调用的工具仅为本地只读法律、版本、关联法规与官方案例检索。引用标识和引文由数据库校验，模型不能向案例库写入内容。没有模型配置时仍可使用原有本地 TXT/DOCX 流程，处理方式明确显示。详见 [升级说明](web/ai-upgrade.md)。

## MCP 边界

- `public_law_only` 固定七个公开法律只读工具，其中 `legal_search_cases`、`legal_get_case` 只读已校验的最高人民法院案例 sidecar，不打开工作区数据库。
- `privacy_workspace` 的三个脱敏工具共用后台业务，但独立使用客户端 bearer token；客户端只能绑定指定材料组和收件目录。
- `privacy_workspace.submit` 只接受收件目录下相对路径，并重新检查符号链接、越界、文件变化和幂等键。
- `privacy_workspace.status` 返回任务状态和匿名安全原因码；`read_result` 只分页返回当前有效的脱敏文本。
- 待复核、失败、取消、撤销和过期结果不可读；不会提供原文、映射、原始文件名、磁盘路径、人工批准或云授权工具。
- 旧 `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` profile 明确停用。

## 运行和报告

便携包只写入 `%LOCALAPPDATA%\LawyerAssistanceWeb`，启动器通过隐藏 `wscript.exe` 启动或停止 server；停止器只调用经过会话和 CSRF 认证的 loopback API，不结束任意进程。包不包含用户数据、凭据、签名私钥或 updater。使用包内 `MANIFEST.sha256`、`.zip.sha256`、法律库发行清单和案例发行 manifest 核对完整性。

报告安全问题时只使用合成数据，避免上传真实材料、映射、凭据、路径和日志原文；入口见仓库根目录 [SECURITY.md](../SECURITY.md)。
