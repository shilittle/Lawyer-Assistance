# 安全与隐私

## 当前强制边界

所有来自案件工作区、案件材料、Vault 或宿主案件任务的原件、附件、粘贴文本、OCR、截图、文件名或路径、当事人及关联人信息、案号、联系方式、地址、证件或账户、签名印章、事实、证据、草稿、摘要、翻译和派生内容一律视为 `CASE_RAW`。`CASE_REDACTED_PENDING`、待复核内容，以及仅有 `CASE_REDACTED_APPROVED` 标签、文件名或口头声明的内容同样不得进入宿主、MCP 或未经批准的 Provider。

应用内普通聊天可以发送用户主动输入的非案件文本，以及本次显式选择、属于当前普通会话且本地提取成功的非案件附件正文；后端将其构造为 `InteractiveUserProvided`，不是公开数据。该能力不适用于案件文件、宿主附件或来源不明的内容。无法确认是否包含案件或客户信息时，必须按 `CASE_RAW` 处理并回到“案件工作台 → 材料与脱敏”。

App 内的本地批准产物并不自动获得 MCP/Provider 外发资格。案件助理只使用本次明确选择的 approved-only 投影和最小已确认案件数据；批准 MCP 和自动化 Provider 正向链则继续要求当前资格、精确 generation、目的地/实例、工具或固定用途、canonical request/payload、短期有效期、撤销 epoch 和防重放全部匹配。三者不能互相借用 authority、receipt、grant 或 ticket。默认 public-only 宿主集成仍只允许不含案件事实的公开法律检索。用户同意、紧急情况、宽泛的宿主权限、其他 prompt 或宿主文件读取不能替代这些技术证据。

## 宿主在规则加载前的披露

WorkBuddy、Codex、OpenCode 或其他宿主可能在 Skill/Agent/prompt 规则加载前就把首条消息或附件发给所选模型。MCP 和仓库内 prompt 无法阻止或撤回已经发生的宿主披露，也不能证明原件未上传、未发送、未记录、未保留、已删除或已召回。

一旦任务已经或可能包含案件原文，宿主应停止所有工具调用和派生处理，只建议用户删除附件与任务、清理可访问历史/记忆/日志、核对 Provider 保留策略，并回到 Lawyer Assistance App 本地处理。后续停止不能保证清除既有副本。

## MCP profile

- `public_law_only` 默认只公开五个法律只读工具，不读取案件材料。
- `redacted_case` 仅增加 receipt-gated `citation_validate`。其票据必须精确绑定请求字节、目标、用途、来源/抽取/脱敏/批准哈希、策略与探测器版本、密钥版本和短 TTL，并通过持久化活动/撤销状态核验。
- `diagram_authoring` 永久只允许合成/公开数据。其本地 HTML bundle 是明文并使用 artifact reference；真实、待复核或批准案件内容不得进入该 profile。
- `approved_case_workspace` 的 `tools/list` 精确为 21 项：公开五项、十个最小 ID-only 案件工具和六个批准图示工具；有效 App 资格、policy-v2 standalone session 和逐调用 ticket 存在时执行真实 handler，其他状态 fail closed。资格化前还必须证明 sibling SHA-256 精确等于正式构建时编译进 App 的配对 release hash；仅同名、相同版本输出或仿真 canary 不能建立二进制信任。只有当前 `case_read_approved_material` 直接响应且响应本身为 `CASE_REDACTED_APPROVED` 才可能成为宿主正文来源。
- 16 个非公开 session grants 精确分为 `read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`。旧 read/write 不含 diagram 权限；没有 `diagram_read` 时通用 metadata/list/read/manifest-export 不可见或拒绝 `legal_diagram`，通用 write/update 不能伪造图示；policy v2 之前的 session 必须撤销并重建，不能迁移或静默扩权。
- 批准图示输入 schema 与 runtime 都使用闭合 metadata allowlist，并递归拒绝路径、文件名、URI、UNC、盘符与遍历编码。`diagram.render` / `diagram.update` 只发布加密 protected `text/html` work product，manifest 额外绑定 canonical Spec SHA-256 和单调来源血缘；`diagram.export` 只返回签名 descriptor metadata。来源撤销、parent Spec/content/hash/version/ticket 不匹配时 fail closed。
- 实验 `redacted_case/citation_validate` 的旧引证用途仍没有 App 生产签发入口；不得把批准工作区 ticket、本地材料页或导出票据改名后复用。默认宿主继续使用 `public_law_only`，案件宿主必须使用独立 approved package 和 App-issued session。
- 三类批准宿主资产默认禁用。Skill、用户同意或客户端白名单不能替代后端 manifest、撤销、哈希、残留扫描、隔离和 Provider 资格。
- 旧案件状态/patch、任意材料导入、缺口分析、文书生成和路径导出工具在所有 profile 中隐藏；新 work-product 只能通过精确的 case write/update 或 approved diagram render/update 业务工具写入。
- 原件已进入任务时必须停止并新建干净任务；Skill 不能撤回加载前披露。

`CASE_RAW` 和 `CASE_REDACTED_PENDING` 指向 `ExternalMcpHost` 时必须返回 `classification_forbidden`，且 transport 保持零调用。拒绝审计只保存分类、内容 hash、字节数和拒绝原因，不保存正文或 destination 明文。普通聊天允许 `InteractiveUserProvided` 到所选 Provider，不改变这条 MCP 负向边界。

## Provider 边界

Provider transport 在序列化前要求明确数据分类，并区分三个闭合入口：

- 普通聊天只通过 `start_interactive_assistant_run` 发送 `InteractiveUserProvided`。请求只接受 run、普通会话、Provider、prompt、本次显式附件和可选预算；authority/classification 由可信后端构造，不接受 project、Privacy、generation、receipt、MCP 或客户端声明的 authority/classification。
- 案件助理只通过 `start_case_assistant_run` 发送 `CaseRedactedApproved`。每次请求明确列出当前案件 generation，后端从 approved-only 投影恢复正文并在 socket write 前重验归属、版本、risk 和撤销；不读取原件、完整 review blob、普通聊天附件或 MCP 授权。
- 自动化 Provider 在“设置 → MCP 与自动化 → 自动化出站批准”执行固定任务。Rust 从受保护存储恢复批准 payload 和 receipt，重验 Provider/endpoint/model/固定用途/策略/探测器/OCR provenance/generation/期限/撤销，再发送并保护输出。

普通聊天不得伪装成公开法律或 `ProductPublic`，案件助理不得降级为普通聊天，自动化 receipt 也不得替代案件助理的显式选择。旧多意图入口和裸案件 `ChatRequest` 仍必须在读取凭据、持久化或网络调用前 fail closed。

## PDF、OCR 与 MinerU

本地带可靠文本层的 PDF 走原生文本提取。`auto_local` 与 `force_local` 已把 App 摄取接到固定本地 MinerU worker，但只在 worker/config/runtime/model 全量受信、Windows Firewall 出站规则经 ActiveStore 复核、合成 canary 和当前环境签名资格有效时运行。启动前后身份、进程树、页数/页序/尺寸/bbox/置信度/输出边界均校验；任一失败即拒绝。扫描、手写、印章或低清内容没有远程 MinerU、SSH、云 OCR、模型下载或外部上传回退。

## 传输与秘密

stdio 的 stdout 只承载 MCP 帧，诊断写 stderr。HTTP 默认只监听 loopback；即使配置 Bearer，也拒绝直接非 loopback 明文监听。生产跨机入口保持服务 loopback，并在受控 TLS 反向代理上实施认证、Host/Origin 限制和网络策略。

Bearer 只从环境变量、受限令牌文件或系统凭据读取，不写入仓库、Skill、对话或截图。发布配置不得启用 `--dangerously-allow-insecure-non-loopback-http`、`dangerously_allow_insecure_non_loopback_http` 或 `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`；这些诊断逃生开关不能替代 TLS。

## 日志与保留

日志只记录请求标识、公开工具名、耗时、结果类别和安全计数，不记录 Authorization、案件正文、OCR 文本、路径、票据或密钥。MCP 侧日志脱敏不约束宿主或 Provider 的保留行为；部署前必须分别核对它们的日志、训练、人工访问和删除政策。
