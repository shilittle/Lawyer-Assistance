# 架构与信任边界

## 组件

- `crates/legal-services`：共享法律检索与历史案件/文书服务实现。服务代码存在不等于 MCP 对外开放。
- `crates/legal-mcp`：配置、stdio/HTTP、profile 工具注册表、适配器、票据门和结果隐私扫描。
- `crates/privacy`：分类、脱敏、DPAPI 保护、精确票据与本地审计基础。
- `crates/material-processing`：本地 PDF 质量判断、原生文本提取、受资格门禁的 MinerU runner/进程隔离协议，以及安全 PDF/DOCX/TXT/Markdown 重建。
- Windows Tauri App：本地材料准备、人工复核、批准、安全导出、资格持久化，并为精确 approved MCP session/call 与 approved Provider purpose 签发后端保护的授权。

`legal-mcp` 不依赖 Tauri IPC、WebView 或 Node/Python 运行时。它可以复用 `legal-services` 的公开法律查询，但 registry 与 adapter 必须在进入服务前按 profile 拒绝未开放工具。

## 当前请求路径

默认生产路径仍为：

1. 宿主启动或连接 MCP，并声明/核验 `public_law_only`。
2. stdio 或 HTTP 传输完成帧、认证、Host/Origin、大小、超时和并发检查。
3. profile registry 只列出精确五个公开法律工具；adapter 对隐藏工具再次拒绝，不能只依赖 `tools/list` 隐藏。
4. 法律服务只读查询 `legal_core.sqlite`。
5. `content` 和 `structuredContent` 两个通道都经过残留扫描，再返回公开法律结果。

`redacted_case` 只在第 3 步多列出 `citation_validate`，并在调用服务前验证精确活动票据。票据绑定完整请求字节、固定目的地 `lawyer-assistance-mcp:redacted_case`、固定用途、内容/策略/探测器 provenance、密钥版本和短 TTL，并核对持久化撤销状态。当前 App 没有该签发用途，所以这条路径没有生产正向调用。

`approved_case_workspace` 在第 3 步列出十个额外 ID-only 案件 schema 和六个批准图示 schema，因此总面为 21 项。formal release 先构建 exact MCP sibling 并把其 SHA-256 编译进 App；adapter 验证 paired-binary trust anchor、当前 App qualification、DPAPI/Credential Manager policy-v2 standalone session 和逐调用 ticket，再由真实 backend 校验 immutable manifest、签名、内容哈希、scope/purpose、撤销和残留扫描；写入只允许 immutable work-product generation。16 个非公开 grants 分为 `read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`，旧 read/write 集合不扩展。未资格化仍返回 `PROFILE_NOT_QUALIFIED`，但不存在统一无条件 stub。宿主不能传路径，也不能直接访问工作区目录。

图示存在两个不可互换的数据面。`diagram_authoring` 直接使用本地 `DiagramService`，永久只接收合成/公开数据并生成明文 HTML bundle / artifact reference。真实批准案件使用 approved backend：来源引用先按当前 generation 和撤销状态核验，render/update 的确定性 HTML 只进入加密 protected work-product store，export 只返回签名 descriptor metadata。approved schema 和响应都不接受或返回 path、URI、HTML。

旧案件状态、案件变更、任意材料导入、缺口分析、文书生成和路径导出在所有 profile 中均不进入 registry，也必须被 adapter 拒绝。不能用内部共享服务仍存在这些 DTO 或实现来推断对外可用。

## 信任边界

1. **宿主与 Provider。** 宿主可能在 Skill/Agent/prompt 加载前已经发送首条消息或附件。MCP 无法阻止、撤回或证明删除这次披露。原件、待复核内容、粘贴、附件和路径永远不得进入宿主；已批准正文只可在独立干净 approved task 中由当前 `case_read_approved_material` 直接响应取得。
2. **分类与票据。** `CASE_RAW`、`CASE_REDACTED_PENDING`、待复核和仅标签 approved 都不能外发。App 本地批准只证明本地工件状态，不自动满足 MCP/Provider 的目的地与用途绑定。
3. **协议。** 传输拒绝未知字段、错误 schema、超限请求、未授权 HTTP、非法 Host/Origin 和超时；错误不回显秘密或路径。
4. **服务。** 法律库只读打开；public-only 调用不读取案件文件、材料根或输出根。
5. **结果。** 两个 MCP 结果通道、日志和错误分别执行隐私控制；任何一层失败都 fail-closed。批准 diagram export 只是 metadata descriptor，不能转换成宿主文件访问。

## PDF 与 OCR 路径

带可靠文本层的本地 PDF 原生提取；需要视觉解析的页面在当前签名资格有效时由 App 传入受信本地 MinerU runner。完整 worker/config/runtime/model inventory、Windows Firewall ActiveStore、启动前后身份、进程树、页完整性与输出边界均复核。final installed component path 还受 259 UTF-16 code units 上限约束，以避开当前原生依赖的长路径导入缺陷。资格缺失或漂移时扫描/视觉 PDF fail closed；不存在 SSH/云 OCR/模型下载回退。

历史候选组件及 direct-worker synthetic diagnostics 仅是工程证据，永久禁止发布。
最终 v4 仍须从固定源码确定性重建、显式审批、签名、短根安装/remeasure、GPU probe
并完成 App Firewall/Job/canary/restart 资格。历史 hash、宿主权限或组件下载均不能
进入 `qualified` 分支；官方 Release URL 可达也不等于自动下载或生产资格成立。

## 演进规则

工具名和顺序以 Rust profile 常量与两个 integration catalog 为共同发布门禁。approved
path 已完成 App 正向签票、逐字节请求绑定、目的地实例隔离、撤销/过期与防重放；
集成 debug sibling 已完成 exact 21-tool、六个 diagram 工具、stdio/HTTP case + diagram
正负向 E2E，并验证四组 policy-v2 grants。每个正式 release sibling 仍须重新测量与
复跑。后续新增能力同样必须先完成生产 handler、票据、存储、UI、正负向 E2E 和数据
保留审计，不能用文档或配置代替。

早期固定 12 工具架构和相关验收是历史记录，已被本 profile 架构取代。
