# Web 重构：核心功能与运行边界

本版面向 Windows 本机单用户。日常运行只需要 `lawyer-assistance.exe` 和可选的法律库；静态 HTML/CSS/JavaScript 编译进可执行文件。不需要 Tauri、WebView2、Node、前端开发服务器或 OCR 环境。

## 核心流程

1. 新建材料分组，可先录入已确认敏感词和别名。
2. 批量导入 TXT/DOCX。每批最多 100 个文件、合计 100 MiB，单文件最多 20 MiB。
3. 后台提取、检测、替换并独立扫描残留。规则和已确认词典可自动发布；仅有语义模型候选时等待本批次云授权或人工复核。
4. 云辅助只发送授权材料版本的完整提取文本。Provider、模型、目标地址、用途及有效期都参与授权绑定，返回候选必须与原文精确对应。撤销阻止后续发送并取消进行中的请求；已发送给服务商的文本无法撤回。
5. 复核可添加词典、调整别名或排除非确定性误报。修改词典使整个分组的旧结果失效并重新处理；替换源文件保留材料 ID，同时递增版本。
6. 通过检查后生成不可变结果，支持 TXT、Markdown、重建 DOCX 和批量 ZIP。ZIP 附 `report.json`，未完成材料不进入成功文件列表。

TXT 使用严格解码，支持 UTF-8、GB18030 和 UTF-16；编码错误可更换编码后重新上传。DOCX 检查正文与表格；含图片、修订、附属文本或暂不支持的结构时阻断发布，不静默丢弃这些内容。首版不支持 PDF/图片、OCR 或原件版式保留。

## 状态与持久化

| 状态 | 操作 |
| --- | --- |
| `queued` / `running` | 后台处理，可取消；关闭浏览器后继续 |
| `awaiting_consent` | 在 WebUI 授权本批次云辅助，或人工处理 |
| `needs_review` | 修正检测、补充词典、重新处理 |
| `ready` | 可导出并由授权 MCP 客户端读取 |
| `failed` | 查看安全原因码，重试或替换文件 |
| `cancelled` / `revoked` | 禁止读取对应结果；取消任务可重试，撤销材料可替换源文件后重新处理 |

批次有可用和失败材料时返回 `partial`。相同请求 ID 和同样文件不会重复建任务；更换内容复用相同请求 ID 会报冲突。结果有效期为 30 天，过期结果不可读取，可通过任务重试生成新版本。

默认工作区是 `%LOCALAPPDATA%\LawyerAssistanceWeb`。后台独占 `workspace.lock`；SQLite 记录包含分组、源文件、任务、检测证据、输出版本、词典、授权、收藏与会话。所有业务对象以 Windows DPAPI 分块加密，密文绑定记录类型、ID 和块位置。Provider API Key 保存于 Windows Credential Manager。不要将该目录当作可跨 Windows 用户直接复制的数据包。

重启会恢复本地未完成任务。已经占用云发送授权的中断任务进入复核，避免重放原文请求。旧桌面数据目录不读取、不修改、不迁移。

## 程序结构

| 路径 | 职责 |
| --- | --- |
| `crates/privacy-text` | 严格提取入口、统一检测与替换、源/输出范围证据、残留扫描、重建导出 |
| `crates/workspace-service` | 工作区锁、加密持久化、任务、版本、授权、分组和附带业务 |
| `apps/server` | 本机会话、Host/Origin/CSRF 边界、HTTP API、静态页面和 MCP HTTP 挂载 |
| `apps/web` | 材料脱敏、法律检索、模板、对话、设置五个普通页面 |
| `crates/legal-mcp` | 公开法律工具、脱敏三工具及连接后台的 stdio 适配 |
| `data/runtime` | 独立的只读法律库和来源/许可文件 |

替换证据记录原文 UTF-8 字节范围、输出范围、实体、别名、原文摘要和输出摘要。发布及读取均验证证据；MCP 只接收分页脱敏正文，不接收检测映射。

## MCP 与附带功能

`public_law_only` 的五个工具和参数契约保持不变，独立 stdio 不打开私密工作区。`privacy_workspace` 在五工具上增加 `submit`、`status`、`read_result`。HTTP 地址为 `http://127.0.0.1:8877/mcp`，脱敏 stdio 通过该后台的受认证 API 访问业务，后台未运行时明确失败。旧 profile 明确停用。详见 [MCP 文档](../mcp/README.md)。

每个脱敏客户端在 WebUI 配置一个分组和独立收件目录。MCP 提交相对路径；后台锁定父目录身份、拒绝链接及越界，并检查文件句柄的最终路径和读取期间变化。WebUI 登录会话和 MCP token 分离，浏览器写操作需要 CSRF，敏感响应不缓存。

法律检索保留来源、条号、版本、效力日期、关联法规、收藏及引用复制，不进行自动联网采集。六类模板使用独立表单，填写内容仅在本地生成和导出。AI 对话只发送用户输入、可见会话历史及明确选择的法条/有效脱敏结果；流式输出可取消，无自主工具执行权限。历史所依据的脱敏结果撤销后，包含该上下文的会话也不能继续向模型发送。

## 验证

[本次验收记录](validation.md) 列出实际执行的测试、浏览器与 MCP 验证，以及未进行真实 Provider 联调的边界。

[合成回归说明](redaction-quality.md) 明确区分确定性规则、人工词典覆盖和模拟云候选，不将合成样例描述为真实案件精度。

```powershell
cargo test --locked --workspace --all-targets --all-features -j 1 -- --test-threads=4
cargo clippy --locked --workspace --all-targets --all-features -j 1 -- -D warnings
pnpm test
python -m unittest scripts.test_package_portable scripts.test_generate_third_party_notices
```

集成测试只使用临时工作区、合成材料与本机模拟 Provider。真实 Provider 联调未包含在这些自动化结论中。
