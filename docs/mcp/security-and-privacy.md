# 安全与隐私

## 当前强制边界

所有案件原件、附件、粘贴文本、OCR、截图、文件名或路径、当事人及关联人信息、案号、联系方式、地址、证件或账户、签名印章、事实、证据、草稿、摘要、翻译和派生内容一律视为 `CASE_RAW`。`CASE_REDACTED_PENDING`、待复核内容，以及仅有 `CASE_REDACTED_APPROVED` 标签、文件名或口头声明的内容同样不得进入宿主、MCP、Provider、网络或文件工具。

App 内的本地批准产物并不自动获得 MCP/Provider 外发资格。当前 App→MCP citation receipt 正向签发链和 App→Provider 案件票据链都未实现，因此生产只允许不含任何案件事实的公开法律检索。用户同意、紧急情况、Full Access、其他 prompt 或宿主文件读取不能替代精确活动票据。

## 宿主在规则加载前的披露

WorkBuddy、Codex、OpenCode 或其他宿主可能在 Skill/Agent/prompt 规则加载前就把首条消息或附件发给所选模型。MCP 和仓库内 prompt 无法阻止或撤回已经发生的宿主披露，也不能证明原件未上传、未发送、未记录、未保留、已删除或已召回。

一旦任务已经或可能包含案件原文，宿主应停止所有工具调用和派生处理，只建议用户删除附件与任务、清理可访问历史/记忆/日志、核对 Provider 保留策略，并回到 Lawyer Assistance App 本地处理。后续停止不能保证清除既有副本。

## MCP profile

- `public_law_only` 默认只公开五个法律只读工具，不读取案件材料。
- `redacted_case` 仅增加 receipt-gated `citation_validate`。其票据必须精确绑定请求字节、目标、用途、来源/抽取/脱敏/批准哈希、策略与探测器版本、密钥版本和短 TTL，并通过持久化活动/撤销状态核验。
- `approved_case_workspace` 列出十个最小 ID-only 案件工具；当前资格未建立，案件执行返回 `PROFILE_NOT_QUALIFIED`。只有当前 `case_read_approved_material` 直接响应且响应本身为 `CASE_REDACTED_APPROVED` 才可能成为宿主正文来源。
- 当前 App 不能签发上述 MCP 引证用途票据。因此生产宿主固定使用 `public_law_only`；不得把本地材料页或导出票据改名后复用。
- 三类批准宿主资产默认禁用。Skill、用户同意或客户端白名单不能替代后端 manifest、撤销、哈希、残留扫描、隔离和 Provider 资格。
- 旧案件状态/patch、任意材料导入、缺口分析、文书生成和路径导出工具在所有 profile 中隐藏；新 work-product 只能通过精确的 write/update 业务工具写入。
- 原件已进入任务时必须停止并新建干净任务；Skill 不能撤回加载前披露。

## Provider 边界

Provider transport 在序列化前要求明确数据分类，只放行公开法律或产品公开数据。旧的案件助手、案件分析和法律文书请求被标记为 `CASE_RAW` 并 fail-closed；目前没有把 App 的逐字节批准结果和精确活动票据接到 Provider 请求上的正向路径。不得声称案件 Provider 发送可用。

## PDF、OCR 与 MinerU

本地带可靠文本层的 PDF 可以走原生文本提取和本地脱敏。仓库存在实验性的本地 MinerU runner/protocol，但 App 当前向材料处理传入 `None`，尚未接入经过认证的本地 worker、模型完整性、GPU 隔离与可验证输出链。扫描件、手写页、印章/图像承载文字或其他视觉 PDF 在认证完成前必须 fail-closed；不得回退到远程 MinerU、SSH、云 OCR 或外部上传。

## 传输与秘密

stdio 的 stdout 只承载 MCP 帧，诊断写 stderr。HTTP 默认只监听 loopback；即使配置 Bearer，也拒绝直接非 loopback 明文监听。生产跨机入口保持服务 loopback，并在受控 TLS 反向代理上实施认证、Host/Origin 限制和网络策略。

Bearer 只从环境变量、受限令牌文件或系统凭据读取，不写入仓库、Skill、对话或截图。发布配置不得启用 `--dangerously-allow-insecure-non-loopback-http`、`dangerously_allow_insecure_non_loopback_http` 或 `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`；这些诊断逃生开关不能替代 TLS。

## 日志与保留

日志只记录请求标识、公开工具名、耗时、结果类别和安全计数，不记录 Authorization、案件正文、OCR 文本、路径、票据或密钥。MCP 侧日志脱敏不约束宿主或 Provider 的保留行为；部署前必须分别核对它们的日志、训练、人工访问和删除政策。