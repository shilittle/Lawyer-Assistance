# 安全与隐私

## 安全模型概览

Lawyer Assistance 默认在本地处理法律库、案件资料、脱敏状态、成果和备份。应用把“内容位于本地”“内容已人工批准”“允许发送给某个目的地”视为三件不同的事。用户同意、提示词、宿主权限或文件名不能替代后端资格、签名状态、授权范围和防重放检查。

该安全模型降低误外发和越权访问风险，但不替代律师复核、组织制度、终端安全、Provider 合同或备份管理。

## 产品能力归属

四个顶层区域职责相互独立：

- **助理**：负责无案件前提的普通 Provider 会话和本次显式选择的普通附件；输入区持续提示内容将发送到 Provider 服务器，并警告不得输入或上传未脱敏案件材料。
- **案件**：负责概览、**材料与脱敏**、案件工作和成果。案件材料、提取正文、脱敏草稿、人工复核、approved generation、撤销和版本历史只属于材料与脱敏。
- **法律资料库**：负责离线公开法律检索、版本、效力、关联与来源复核。
- **设置**：只承载 **Provider 服务与凭据**、**本地处理环境与 OCR 组件**、**MCP 与自动化**、**版本、备份与诊断**四个 owner；不显示案件正文或人工脱敏工作台。

## 数据分类

- **公开法律数据**：可以进入默认公开法律检索流程。
- **交互式用户内容**：用户在普通聊天中主动输入的文本，以及在本次请求中显式选择、属于当前普通会话且本地提取成功的非案件附件正文。它可以发送给所选 Provider，但不是公开数据，也不能访问案件材料服务。
- **原始案件数据**：客户、案件、材料、附件、OCR 文本以及可识别的派生事实；默认只在本地处理。
- **待复核脱敏数据**：尚未完成精确人工复核，仍按原始案件数据处理。
- **已批准 generation**：由 App 对不可变内容、范围和来源完成签名批准；仍不自动获得任意外发权限。
- **受保护成果**：经受控流程生成并保存的 work product 或批准案件图示。

## 本地存储

应用使用只读运行时法律库和本地可写用户数据。案件、审批、Vault、映射和成果通过 Rust 后端管理，不由前端任意读取数据库。API Key 使用 Windows Credential Manager；普通配置、日志和前端状态只保存必要的非秘密信息或掩码状态。

受保护 work product 使用认证加密、版本化 manifest 和完成记录。旧式明文内容、文件集异常、哈希不匹配、来源撤销或额外残留都会失败关闭。

应用 `ProjectId` 与权威 Privacy/Vault `PrivacyCaseId` 属于不同身份域。可信后端维护审计型、持久化、不可变的一对一绑定，不使用字符串替换、哈希截断或可预测计数器推导关系。前端不得生成、猜测、作为权威缓存或接收权威 `PrivacyCaseId`。历史关联无法无歧义恢复时必须 fail closed；删除项目后仍保留绑定与审计历史，已退役的 `ProjectId` 不得重新绑定到另一 Privacy case。参见 [ADR-0001](adr/0001-project-privacy-case-binding.md)。

## Provider 外发

Lawyer Assistance 使用 BYOK Provider，并把三种执行模式保持为独立数据通道：

- **普通聊天 `interactive_chat`**：无需案件或脱敏批准。只发送用户当前输入、同一普通会话的有界成功文本历史，以及本次显式选择且复核所有权、提取状态和正文 hash 的普通附件正文。输入区持续显示 Provider 外发提示；请求不读取案件工作区、CaseMaterial、Privacy、Vault、approved generation 或 MCP 状态，也不携带案件标识。
- **案件工作 `interactive_case_work`**：只在“案件工作台 → 案件工作”的案件助理中使用。每次发送只接受用户本次明确选择的当前案件 approved/current generation；后端从 approved-only 投影恢复正文，加入最小已确认案件数据，并在 Provider socket write 前重验项目绑定、generation/version、risk head 和撤销状态。响应经过完整有界缓冲和残留扫描后才显示，并先保存为待确认输出。
- **批准自动化 `approved_automation`**：Provider 固定任务和 Approved MCP 位于“设置 → MCP 与自动化”，继续要求独立 qualification、精确 publication/receipt、目的地/用途、grant、ticket、短期有效期、撤销和防重放。它不是普通聊天或案件助理的必经页面。

三种模式不能互相降级或借用 authority。普通聊天不得伪装成 `ProductPublic`；案件助理不得回退到普通聊天；自动化授权不得被案件助理复用。旧式裸案件请求仍在序列化和网络发送前失败。Provider 响应、审计和错误继续执行有界、无正文日志和脱敏规则。

Provider 可能有自己的日志、训练、保留、人员访问和区域政策。使用前必须由部署方审查；应用不能撤回已被外部服务接收的数据。

## MCP profile 隔离

- `public_law_only` 固定为五个公开法律只读工具，不读取案件、Vault、批准材料或成果。
- `diagram_authoring` 只允许纯合成或公开数据，生成明文本地 HTML，不能作为真实案件的降级通道。
- `approved_case_workspace` 固定发现 21 个工具，但发现不等于授权。16 个非公开工具还需要当前 App 资格、standalone session、明确 grant 和精确逐调用 ticket。
- 案件读写 grants 与图示读写 grants 分离，旧 session 不会静默获得图示权限。

批准 profile 不接受任意路径、文件名、URI、附件、粘贴原文、命令、shell 片段或 raw OCR。案件成果只通过受控 work-product 和 approved diagram 接口保存。

普通聊天允许交互式用户内容发送给用户选择的 Provider，不会放宽 MCP：`CaseRaw` 或 `CaseRedactedPending` 指向 `ExternalMcpHost` 时仍必须在 transport 前返回 `classification_forbidden`，且拒绝审计不得保存正文或 destination 明文。

## WorkBuddy、Codex 与 OpenCode

默认宿主 package 只支持 `public_law_only`。批准案件 package 必须单独安装、默认禁用，并从只含 opaque ID 的新任务开始。

Skill 或 Agent 规则可能晚于宿主发送第一条消息或附件。如果案件内容在规则加载前已经进入任务，宿主或其 Provider 可能已经接收。此时应停止调用，删除受污染的任务和附件，按宿主与 Provider 控制清理可访问历史、记忆和日志，并新建干净任务。应用和 Skill 不能证明外部副本已删除。

## 文件导入与 OCR

案件 PDF、DOCX、UTF-8 TXT 和 Markdown 应从“案件工作台 → 材料与脱敏”导入，并在本地进行格式、大小、结构和内容检查。可靠文本层可以本地解析；视觉页只能进入已经完成当前资格的本地 MinerU。具体案件正文、人工复核、approved generation、撤销和版本历史不得出现在设置页。

OCR 配置、组件管理、信任、防火墙隔离和资格控制位于“设置 → 本地处理环境与 OCR 组件”。组件下载与案件处理是两条独立通道；组件管理 API 不接收案件 ID、材料路径、正文或 Provider 凭据。

生产 OCR 资格要求精确组件、worker、配置、模型和运行时清单，Windows Firewall 出站隔离，进程树约束，固定合成 canary，重启复核以及漂移、撤销和到期失效。`0.4.0` 源码候选实现了这条验证链，但在最终 MinerU 资产、签名、GPU/driver 和干净机证据完成前不得宣称已取得生产资格；系统不提供 SSH、云 OCR、远程模型下载或静默回退。

## 图示安全

图示输入采用闭合 Schema、固定模板和确定性本地渲染。渲染器拒绝任意脚本、外部资源、危险 HTML、位置泄漏和超限图。批准案件图示绑定来源 lineage、规范哈希、HTML 哈希和加密 work-product manifest；导出接口只返回 descriptor metadata。

## 备份、删除与日志

`.lavbackup` 使用认证加密覆盖用户数据库、隐私状态、加密 Vault、批准工作区和加密成果。备份文件本身仍是敏感资产，应放在访问受控的位置。

应用更新、诊断、Privacy 生命周期和五组件备份位于“设置 → 版本、备份与诊断”。更新/诊断与生命周期 mutation 使用独立活动状态并互相禁用；任一写入进行时都会阻止导航和关窗。

应用尽量只记录稳定错误码、版本和无内容诊断。不要在日志、截图或支持工单中放入正文、密钥、路径、映射或 session 信息。撤销、逻辑删除和密钥销毁不能保证 SSD 单元、操作系统历史、外部备份、宿主缓存或已披露云副本被取证擦除。

## 法律与运行限制

- 法律库和模型输出只用于辅助研究与复核，不构成法律意见。
- 引用、版本、效力、案件事实和最终文书必须由专业人员复核。
- 只有正式 Release 中通过 Authenticode、RFC3161 与服务端回读的 exact installer 才有已验证的 Windows publisher 身份；源码候选或未签名产物没有。
- 源代码仓库当前公开，但公开源码或可下载资产不能证明 Authenticode 签名、updater 就绪、OCR 资格或干净机器发布验收。
- updater 代码和验证链已实现，但在 installer-bound 签名、`latest.json`、发布提升与最终端点复验完成前不得称自动更新可用。
- 完整归档数据库不随桌面 App Release 提供。
- 最终生产 OCR 资格尚待真实资产与机器证据；扫描或视觉 PDF 在当前资格无效时必须保持阻断。

当前限制和发布门槛见[当前发布状态](release-status.md)。
