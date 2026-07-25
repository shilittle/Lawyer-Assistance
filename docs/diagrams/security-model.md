# 图示系统安全模型

## 受保护对象与攻击面

系统保护原始案件材料、批准 publication、个人与企业敏感信息、来源位置、访问凭据、work-product 密文与签名 manifest、法律分析状态以及宿主既有隐私承诺。攻击面包括恶意或误生成的 DiagramSpec、提示注入文本、超大图、路径/URI 泄露、伪造来源绑定、ticket 重放、授权撤销竞态、并发覆盖、明文落盘和制品被当作主动网页执行。

## 数据准入：profile 是硬边界

| 数据 | 唯一允许的 profile | 持久化 |
|---|---|---|
| 纯合成或公开数据 | `diagram_authoring` | 明文 `artifact.diagram.json` + `artifact.html`，可返回 `artifact_uri` |
| 真实批准案件 | `approved_case_workspace` | encrypted protected `text/html` work product，响应不返回正文或位置 |

`diagram_authoring` 固定为 11 tools 且永久 synthetic/public-only。它没有 Privacy 批准链，也不能以“本地”“已脱敏”“仅测试”等标签承载真实案件；误用会把 Spec 与 HTML 明文写入 output root。

`approved_case_workspace` 固定为 21 tools，是真实批准案件唯一图示路径。请求必须引用当前可读的 `material_id` / `publication_id`，Spec 来源必须与 publication 精确绑定；仅有文件名、模型声明或旧 receipt 不能扩大 CASE_RAW 范围。

外部模型计费测试只能使用纯虚构 fixtures。确定性渲染和自动回归不调用 Provider。2026-07-21 的历史 DeepSeek opt-in QA 证据保留在 `acceptance-2026-07-21.md`；它不改变当前 profile 边界，也不能被当作真实案件互操作证据。

## 一次性授权与最小权限

批准案件调用由 App 对规范化业务请求签发一次性 access ticket。绑定至少覆盖 profile、工具名/目的、canonical request hash、案件，以及适用时的 work product 和版本；ticket 由宿主内部注入，不出现在模型可见 host schema、日志或业务响应中。请求被修改、ticket 被复用、过期、撤销 epoch 变化或目标不匹配时均 fail closed。

图示授权独立于原有案件授权：

- `diagram_read`：`diagram.list_templates`、`diagram.get_schema`、`diagram.validate`、`diagram.export`。
- `diagram_write`：`diagram.render`、`diagram.update`。

既有 `read` 仍只包含 8 个案件读取工具，既有 `write` 仍只包含 2 个案件 work-product 写工具。策略升级不会把 6 个图示工具静默加入旧会话；没有 `diagram_read` 时通用 metadata/list/read/manifest-export 会过滤或拒绝 `legal_diagram`，通用 write/update 也不能创建或改写图示。App 必须显式授予新组。

## 批准来源与位置隔离

批准案件的 `diagram.get_schema` 返回 DiagramSpec 的受限投影：

- Source 禁止 path、`file_name`、`uri`、`attachment`，并移除 `file`、`file_page`、`attachment`、`uri` 来源种类。
- Source `id` 与必填 `artifact_id` 必须是 `pub_` 加 32 位小写十六进制不透明 ID，且与 `source_approved_refs` 中当前 publication 精确匹配。
- provenance 的 `source_file_ids` 只允许相同的 `pub_...` ID，不是文件 ID 或路径。
- `locator` 只能表达页、段、表等非位置语义；闭合 metadata allowlist 与递归字符串扫描拒绝任意反斜杠、盘符、UNC、URI scheme、绝对/相对/遍历路径、常见文件名和换键编码。仅响应 diagnostic 的 `path` 可返回净化且字段段受限的 JSON Pointer；approved Spec/patch 输入没有 JSON Pointer 例外。

批准请求不得携带文件系统位置，也不能让 MCP 根据客户端文本打开文件。来源撤销后，依赖该 publication 的 validate/render/update/export 均不能继续；尤其是已准备的一次性 ticket 不会冻结或绕过撤销状态。

## 模型—渲染隔离

模型只影响 DiagramSpec 数据。模板 ID、节点类型、关系、状态、字段长度、集合数量、metadata 深度和布局提示均为封闭集合。固定渲染器生成 HTML、SVG、CSS、JS 和坐标，用户文本按 HTML 文本、属性或 JSON 上下文转义。

固定 HTML 外壳必须满足：

- CSP 为 `default-src 'none'`，脚本和样式只允许渲染器写入的固定 nonce；输入无法控制 nonce、标签或 CSP。
- 不使用 `innerHTML` 注入用户文本，不使用 `eval`、`Function` 或动态 import。
- 不提供表单、fetch/XHR、WebSocket、自动导航、远程字体或远程图片。
- 用户字段不能进入 style、事件处理器、SVG path 或 CSS selector。

在批准通道中，渲染只在内存中完成，随后把 HTML 字节交给 Privacy protected work-product publisher；不会调用 `DiagramService` 的明文制品存储。

## 资源与拒绝服务

DiagramSpec Schema 限制 500 节点、1200 边、100 组、1000 来源及各字段长度。两条通道另有不同边界：

- `diagram_authoring`：MCP 工具 envelope 4 MiB、规范化 Spec 4 MiB、明文 HTML 12 MiB。
- `approved_case_workspace`：规范化业务请求最多 256 KiB，render/update 的 protected HTML 最多 1 MiB。

所有批准请求在业务反序列化与执行前检查 256 KiB 上限；HTML 在发布前检查 1 MiB 上限。超过 100 节点时仍会隐藏弱边、折叠低重要性节点并显示性能提示，但降噪不能替代最小必要数据范围。

## 制品机密性与完整性

### 合成/公开通道

`DiagramService` 以规范化 Spec（含模板版本）计算内容地址，把 `artifact.diagram.json` 和 `artifact.html` 在 staging 目录完成后作为 sibling bundle 原子提交。render/update/export 重新验证 output root、diagram root 与父链身份并拒绝 symlink/junction/reparse；export 和 URI update 会验证 canonical Spec、URI/spec hash、领域语义，并固定重渲染逐字节比对 HTML。

这些保障解决完整性，不提供机密性；文件是明文，因此只允许合成/公开数据。

### 批准案件通道

render/update 发布 `task_type=legal_diagram`、`content_media_type=text/html` 的 encrypted protected work product。manifest 绑定案件、来源批准引用、内容 hash、canonical `diagram_spec_sha256`、字节数、版本、父版本、作者工具和状态；只有专用 `diagram.render` / `diagram.update` author tool 能创建该组合。响应仅包含不透明 work-product 标识、版本、hash、统计和净化诊断。

update 必须：

1. 在当前授权下读取并验证指定 protected parent；
2. 要求 `expected_spec_hash` 与 parent manifest 中的 `diagram_spec_sha256` 精确一致；
3. 对调用方提交的完整 `base_spec` 计算 canonical hash，要求同一 `expected_spec_hash`，再固定重渲染并与解密后的 parent 内容逐字节比对；
4. 应用有限 patch；
5. 重新执行来源闭合绑定、残留扫描和完整校验，并要求新来源集合等于 parent 来源与更新后 Spec 来源的并集，保持撤销血缘单调；
6. 发布同一 work product 的下一加密版本。

export 读取并验证 protected 内容及 signed manifest，只返回 `case_id`、`work_product_id`、`version`、`format`、`mime_type`、`byte_len`、`html_sha256` 与 `manifest_sha256`。它不返回 HTML、manifest 正文、path、filename、URI，也不打开 GUI。

## 日志、诊断与模型可见输出

日志只保留工具名、版本、耗时、输入/输出字节数、诊断计数和不可逆请求标识，不记录标题、节点、边、来源正文、ticket、URI 查询或凭据。反序列化错误返回稳定 code 和闭集白名单净化的 JSON Pointer；到达任意 metadata 键时路径截断在 `/metadata`。语义诊断经过模型可见结果隐私扫描。

批准响应不得包含受保护 HTML、原始 Spec、来源路径、文件名、attachment、URI 或 access ticket。list/get-schema 的批准投影也不返回内置虚构示例正文，避免把非案件内容误作当前已批准来源。

## 安全测试门禁

发布前至少覆盖：

- 两个 profile 的固定工具数（11/21）与 profile 隔离；
- 旧 `read`/`write` grant 不扩权，新 `diagram_read` 4 tools / `diagram_write` 2 tools 精确授权；
- 缺失、篡改、重放或目标不匹配 ticket 在执行前拒绝且不产生 work product；
- 路径、文件名、URI、attachment、错误 publication 绑定和残留敏感数据拒绝；
- render/update 确实生成 encrypted protected `text/html`，且响应不含 HTML 或位置；
- 父内容不匹配、陈旧 hash/版本、来源撤销和 manifest 篡改 fail closed；
- 256 KiB 请求、1 MiB protected HTML 以及 DiagramSpec 集合上限；
- 脚本/属性/SVG/MathML/双重编码/危险 URL/控制字符/双向文本注入；
- 合成/公开 sibling bundle 的路径逃逸、reparse 替换、原子性与逐字节重验证。

## 已知剩余风险

最严重的操作风险是把真实案件误路由到 `diagram_authoring`，因为该通道按设计明文落盘并返回 URI；调用方必须以 profile 和 grant 硬门禁防止降级。单文件 HTML 仍依赖固定内联运行时、严格 CSP、上下文转义和禁用动态代码。即使低于所有上限，单张图也可能包含过多已批准上下文；应按争点拆图，并让每次 `source_approved_refs` 保持最小集合。第一阶段只承诺 HTML，不提供 SVG/PNG/PDF 对外导出。
