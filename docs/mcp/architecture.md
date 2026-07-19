# 架构与信任边界

## 组件

- `crates/legal-services`：共享法律检索与历史案件/文书服务实现。服务代码存在不等于 MCP 对外开放。
- `crates/legal-mcp`：配置、stdio/HTTP、profile 工具注册表、适配器、票据门和结果隐私扫描。
- `crates/privacy`：分类、脱敏、DPAPI 保护、精确票据与本地审计基础。
- `crates/material-processing`：本地 PDF 质量判断、原生文本提取、实验 MinerU runner 协议和安全 PDF 重建。
- Windows Tauri App：本地材料准备、人工复核、批准和安全导出；目前不向 MCP/Provider 签发案件外发票据。

`legal-mcp` 不依赖 Tauri IPC、WebView 或 Node/Python 运行时。它可以复用 `legal-services` 的公开法律查询，但 registry 与 adapter 必须在进入服务前按 profile 拒绝未开放工具。

## 当前请求路径

1. 宿主启动或连接 MCP，并声明/核验 `public_law_only`。
2. stdio 或 HTTP 传输完成帧、认证、Host/Origin、大小、超时和并发检查。
3. profile registry 只列出精确五个公开法律工具；adapter 对隐藏工具再次拒绝，不能只依赖 `tools/list` 隐藏。
4. 法律服务只读查询 `legal_core.sqlite`。
5. `content` 和 `structuredContent` 两个通道都经过残留扫描，再返回公开法律结果。

`redacted_case` 只在第 3 步多列出 `citation_validate`，并在调用服务前验证精确活动票据。票据绑定完整请求字节、固定目的地 `lawyer-assistance-mcp:redacted_case`、固定用途、内容/策略/探测器 provenance、密钥版本和短 TTL，并核对持久化撤销状态。当前 App 没有该签发用途，所以这条路径没有生产正向调用。

案件状态、案件变更、材料导入、缺口分析、文书生成和导出在两个 profile 中均不进入 registry，也必须被 adapter 拒绝。不能用内部共享服务仍存在这些 DTO 或实现来推断对外可用。

## 信任边界

1. **宿主与 Provider。** 宿主可能在 Skill/Agent/prompt 加载前已经发送首条消息或附件。MCP 无法阻止、撤回或证明删除这次披露。生产任务因此不得把任何案件材料放入 WorkBuddy、Codex、OpenCode 或其他外部模型上下文。
2. **分类与票据。** `CASE_RAW`、`CASE_REDACTED_PENDING`、待复核和仅标签 approved 都不能外发。App 本地批准只证明本地工件状态，不自动满足 MCP/Provider 的目的地与用途绑定。
3. **协议。** 传输拒绝未知字段、错误 schema、超限请求、未授权 HTTP、非法 Host/Origin 和超时；错误不回显秘密或路径。
4. **服务。** 法律库只读打开；public-only 调用不读取案件文件、材料根或输出根。
5. **结果。** 两个 MCP 结果通道、日志和错误分别执行隐私控制；任何一层失败都 fail-closed。

## PDF 与 OCR 路径

带可靠文本层的本地 PDF 可原生提取并在 App 内脱敏。实验 MinerU runner 具备本地进程协议、超时/取消和禁用远程环境的基础，但 App 当前传入 `None`，没有认证 worker、模型哈希、GPU 隔离或端到端完整性证明。因此扫描/视觉 PDF 不进入下游复核或外发，必须 fail-closed；不存在 SSH/云 OCR 回退。

## 演进规则

工具名和顺序以 Rust profile 常量与 `integrations/tool-catalog.json` 为共同发布门禁。新增任何案件或文书能力必须先完成 App 正向签票、逐字节请求绑定、目的地实例隔离、撤销/过期、重放防护、宿主数据保留审计和端到端红队测试；在此之前不得通过文档或配置“预告可用”。

早期固定 12 工具架构和相关验收是历史记录，已被本 profile 架构取代。