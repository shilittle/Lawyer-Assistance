# 安全与隐私

## 当前强制边界

所有案件原件、附件、粘贴文本、OCR、截图、文件名或路径、当事人及关联人信息、案号、联系方式、地址、证件或账户、签名印章、事实、证据、草稿、摘要、翻译和派生内容一律视为 `CASE_RAW`。`CASE_REDACTED_PENDING`、待复核内容，以及仅有 `CASE_REDACTED_APPROVED` 标签、文件名或口头声明的内容同样不得进入宿主、MCP、Provider、网络或文件工具。

App 内的本地批准产物并不自动获得 MCP/Provider 外发资格。批准 MCP 和批准 Provider 的正向链已分别实现，但每次使用仍要求当前资格、精确 generation、目的地/实例、工具或固定用途、canonical request/payload、短期有效期、撤销 epoch 和防重放全部匹配。默认 public-only 集成仍只允许不含案件事实的公开法律检索。用户同意、紧急情况、Full Access、其他 prompt 或宿主文件读取不能替代这些技术证据。

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

## Provider 边界

Provider transport 在序列化前要求明确数据分类。公开路径只放行代码内固定、且不插入用户内容的公开法律或产品请求；旧助理入口的全部用户自由文本（包括表面上不含个人信息的法律问题）以及旧案件分析、法律文书入口都必须在读取凭据、持久化或网络调用前 fail closed，并转入 Approved Provider 固定任务。独立批准路径从 Rust 受保护存储恢复逐字节批准正文和回执，重验 Provider/endpoint/model/固定用途/策略/探测器/OCR provenance/generation/期限/撤销，再发送并保护输出。前端标签、意图字段、空会话或裸 `ChatRequest` 不能构造该类型，也不能证明公开来源。

## PDF、OCR 与 MinerU

本地带可靠文本层的 PDF 走原生文本提取。`auto_local` 与 `force_local` 已把 App 摄取接到固定本地 MinerU worker，但只在 worker/config/runtime/model 全量受信、Windows Firewall 出站规则经 ActiveStore 复核、合成 canary 和当前环境签名资格有效时运行。启动前后身份、进程树、页数/页序/尺寸/bbox/置信度/输出边界均校验；任一失败即拒绝。扫描、手写、印章或低清内容没有远程 MinerU、SSH、云 OCR、模型下载或外部上传回退。

## 传输与秘密

stdio 的 stdout 只承载 MCP 帧，诊断写 stderr。HTTP 默认只监听 loopback；即使配置 Bearer，也拒绝直接非 loopback 明文监听。生产跨机入口保持服务 loopback，并在受控 TLS 反向代理上实施认证、Host/Origin 限制和网络策略。

Bearer 只从环境变量、受限令牌文件或系统凭据读取，不写入仓库、Skill、对话或截图。发布配置不得启用 `--dangerously-allow-insecure-non-loopback-http`、`dangerously_allow_insecure_non_loopback_http` 或 `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`；这些诊断逃生开关不能替代 TLS。

## 日志与保留

日志只记录请求标识、公开工具名、耗时、结果类别和安全计数，不记录 Authorization、案件正文、OCR 文本、路径、票据或密钥。MCP 侧日志脱敏不约束宿主或 Provider 的保留行为；部署前必须分别核对它们的日志、训练、人工访问和删除政策。
