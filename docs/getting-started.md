# 快速开始

## 1. 使用前确认

`0.4.0-beta.2` 面向 Windows x86_64，当前定位为未签名技术预发布：

- 安装程序没有已验证的 Windows 发布者身份，可能触发 SmartScreen 或安全软件提示。
- 当前没有可用的自动更新发布链；升级应使用项目提供并核验过的完整新包。
- 生产扫描件 OCR 尚未取得资格。没有在 App 中看到全部当前资格门通过时，不要用它处理扫描或视觉 PDF。
- 技术预发布包使用 `runtime-slim-v1` 法律库，不包含完整归档数据库。

下载或接收安装包时，应同时核对版本、文件名、SHA-256 和随包 manifest。不要把 CI fixture、调试程序或历史 OCR 组件当作产品资产。

## 2. 首次启动

1. 启动 Lawyer Assistance，确认版本显示为 `0.4.0-beta.2`。
2. 打开应用健康或版本信息，确认运行时法律库已加载。
3. 阅读隐私提示，确认应用的数据保留和外发边界符合当前工作要求。
4. 如需使用模型 Provider，打开“设置 → Provider 与凭据”，创建自己的 Provider 配置并保存 API Key。密钥由 Windows Credential Manager 管理，前端只显示掩码状态。
5. 在使用案件、Provider、MCP 或 OCR 前，分别检查对应的资格和授权状态。一个能力通过不代表其他能力自动通过。

## 3. 公开法律检索

公开法律检索可以离线读取运行时法律库，用于：

- 检索法律和条文；
- 查看版本及效力信息；
- 查看法律关系和来源引用；
- 为公开法律问题准备带来源的研究材料。

检索结果需要律师结合官方现行文本和具体事实复核。运行时精简库服务于应用查询，不是完整归档审计库的替代品。

## 4. 普通聊天与普通附件

普通聊天不要求先创建案件、上传案件文件或取得脱敏批准：

1. 打开“助理”，新建普通会话并选择已保存的 Provider。
2. 在“普通聊天消息”中输入问题。输入区附近会持续显示：内容将通过 API 发送至所选模型供应商服务器，请勿输入或上传未脱敏案件材料。
3. 直接发送时，应用只使用当前消息和同一普通会话内有界的成功文本历史，不读取 Case Workspace、CaseMaterial、Privacy、Vault、approved generation 或 MCP 状态。
4. 如需普通附件，必须在本次请求中显式选择支持的 TXT/PDF 等文件。页面会列出将发送正文的文件名、类型和大小；用户可以发送或取消。
5. 普通附件不会自动登记为案件材料，也不会强制跳转到脱敏页面。附件若属于真实案件、包含客户信息或无法确认范围，不得从普通聊天发送，应改到“案件工作台 → 材料与脱敏”处理。

普通聊天经 `interactive_chat` 边界发送用户主动提供的内容。它不是公开法律数据，也不会被伪装成 `ProductPublic`；请求仍受 Provider endpoint、凭据隔离、SSRF/private-network 许可、大小、取消、审计、响应限额和错误脱敏约束。

## 5. 案件工作区

案件工作区内部固定分为“概览”“材料与脱敏”“案件工作”和“成果”。建议按以下顺序使用：

1. 创建案件并录入必要的结构化信息。
2. 打开“案件工作台 → 材料与脱敏”，导入 PDF、DOCX、UTF-8 TXT 或 Markdown。
3. 检查本地提取结果、敏感信息发现和别名映射；正文、复核和版本历史只在当前案件材料页显示，不进入设置页。
4. 人工复核脱敏范围，只批准确实需要进入后续流程的不可变 generation。
5. 打开“案件工作台 → 案件工作”，创建独立案件助理会话，为本次请求明确勾选当前案件的 approved/current generation，并选择输出类型。
6. 案件助理只发送本次选择的 approved-only 投影、最小已确认案件数据、同一案件工作会话的有界历史和当前指令，不读取原件、Vault 对象、路径、普通聊天附件或 MCP 授权。
7. 模型输出先保存为待确认状态。只有单独确认并再次通过来源、版本、撤销和 workspace CAS 校验后，才会写入案件或成果。
8. generation 被撤销、删除、阻断或变旧后，刷新会清除失效选择；新的请求必须停止并提示“请重新选择材料”。

本地批准不等于允许把正文粘贴到普通聊天、普通附件、浏览器、其他 MCP 或任意 Provider。案件助理、自动化出站批准和 approved MCP 各自重新验证精确 generation、目的地、用途和当前状态，不能互相借用授权。

## 6. BYOK Provider

Lawyer Assistance 采用 BYOK（自带密钥）方式连接兼容 Provider：

- 由用户提供 Provider 账户和 API Key；
- API Key 不写入普通配置、日志或数据库正文；
- 普通聊天只发送用户输入、同一普通会话的有界文本历史和本次显式选择的普通附件正文；
- 案件助理只发送本次明确选择的 approved-only 投影和最小已确认案件数据；
- “设置 → MCP 与自动化 → 自动化出站批准”保留固定任务、单次批准、派发和历史输出，服务于 `approved_automation`，不是普通聊天或案件助理的必经页面；
- 每种模式都在后端独立构造 authority/classification，并在发送前核对 Provider、endpoint、model、用途、来源范围和当前撤销状态。

Provider 是外部服务。使用前请核对其数据保留、访问控制、区域和计费政策。不要把本地批准理解为对所有 Provider 的通用许可。

## 7. MCP 与宿主集成

Lawyer Assistance 提供四个不同的 MCP profile：

| Profile | 工具数 | 用途 |
|---|---:|---|
| `public_law_only` | 5 | 默认公开法律只读检索，不含案件数据 |
| `redacted_case` | 6 | 兼容实验 profile；当前 App 不提供其正向用途票据 |
| `diagram_authoring` | 11 | 只处理纯合成或公开数据，生成本地明文图示 bundle |
| `approved_case_workspace` | 21 | 经 App 资格、session、grant 和逐调用 ticket 约束的批准案件工作区 |

WorkBuddy、Codex 和 OpenCode 的默认示例使用 `public_law_only`。应用内的本地 MCP、自动化出站批准和 Approved MCP 位于“设置 → MCP 与自动化”，但三者保持独立 activity 和授权边界。批准案件配置是独立、默认禁用的 Windows stdio 配置。使用批准工作区时：

1. 从 App 创建当前 standalone session。
2. 新建只含 opaque ID 的干净宿主任务。
3. 不粘贴、不附加、不从宿主文件系统读取案件正文。
4. 只信当前任务中 `case_read_approved_material` 的直接响应。
5. 只通过受控 work-product 或 approved diagram 工具保存成果，并复读精确版本。

## 8. 法律图示

- `diagram_authoring` 只允许纯合成或公开法律数据。它的 HTML 是本地明文制品，不能承载真实案件内容。
- 真实批准案件图示只能使用 `approved_case_workspace`。
- 批准案件的 `diagram.render` 和 `diagram.update` 保存加密的受保护 HTML work product。
- `diagram.export` 只返回经过验证的 descriptor metadata，不返回 HTML、文件路径或 URI。

## 9. OCR

可靠原生文本层可以由本地解析器处理。扫描或视觉 PDF 只有在 App 显示当前 worker、模型、组件完整性、Windows Firewall 隔离、合成 canary 和环境复测全部通过时，才可进入本地 MinerU。

OCR 配置、组件导入/安装/回滚/卸载、信任、防火墙隔离和资格运行统一位于“设置 → 本地处理环境与 OCR 组件”。配置草稿、组件 mutation 和资格 mutation 相互隔离；任一写入进行时不得并行启动另一类写入。

当前技术预发布没有取得生产 OCR 资格。不得用历史组件、GPU 诊断、用户同意或远程 OCR 代替资格门；失败时应用应阻断，而不是静默上传或远程回退。

## 10. 备份与恢复

“设置 → 版本、备份与诊断”同时承载应用更新/诊断和 Privacy 生命周期维护，但两类 mutation 互相禁用。该页面提供本地、认证加密的 `.lavbackup` 备份，覆盖用户数据库、隐私状态、加密 Vault、批准工作区和加密 work products；另有用于隐私维护的 `.lavprivacy` 格式。

- 备份前结束正在进行的写入并使用应用提供的导出入口。
- 把备份保存在受控位置，不要上传到未经批准的云盘、聊天或工单。
- 恢复后检查案件、Vault、批准 generation、work products 和授权状态。
- 备份与逻辑删除不等于对 SSD、外部副本、宿主缓存或云端历史的取证级擦除。

## 11. 遇到阻断时

`PROFILE_NOT_QUALIFIED`、过期、撤销、重放、完整性或残留扫描错误都表示对应案件或自动化流程必须停止。不要降级到普通聊天、普通附件、粘贴、文件路径、浏览器、远程 OCR、其他 MCP 或另一个 Provider。普通聊天自己的非案件内容不受 MCP 资格控制，但绝不能被用来绕过案件材料边界。

进一步信息请参阅[安全与隐私](security-and-privacy.md)和[当前发布状态](release-status.md)。
