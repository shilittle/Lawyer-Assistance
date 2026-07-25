# WorkBuddy 图示生成协议

## 先选数据通道

WorkBuddy 在接触图示内容前必须确定数据等级，且整个任务不能降级换道：

| 数据范围 | profile | 允许结果 |
|---|---|---|
| 完全虚构或可公开处理的数据 | `diagram_authoring` | 本地明文 Spec/HTML sibling bundle 与 `artifact_uri` |
| 由 Privacy 正向链为当前材料版本、目的和工具明确批准的数据 | `approved_case_workspace` | encrypted protected HTML work product 与不透明 descriptor metadata |

`diagram_authoring` 永久 synthetic/public-only。真实案件即使已经“隐藏姓名”“仅在本机”“由用户同意”，也不得进入该 profile，因为它会明文写入 `artifact.diagram.json` 与 `artifact.html`。真实批准案件只能使用 `approved_case_workspace`。

案件材料、附件、粘贴、OCR/远程 OCR、截图及其摘要、翻译和派生事实在批准前均按 `CASE_RAW` 处理。若无法确认范围，立即停止，不读取、复制、摘要、转换、保存或通过诊断回显，也不交给 Provider、网络、browser/search、远程 OCR、其他 MCP/Skill、memory、subagent、连接器、自动化、专家或团队。

## 职责分工

WorkBuddy 负责选择模板、提取实体与关系、区分主张/支持/争议/未知、绑定来源并生成 DiagramSpec。固定 MCP 实现负责 profile、grant、逐次 ticket、来源授权、Schema/语义校验、模板布局、安全渲染和制品发布。

WorkBuddy 不生成 HTML/CSS/JS，不提交坐标，不创造关系，不把 `supported` 提升为 `established`，不自行构造 `case_` / `mat_` / `pub_` / `wp_` ID，不读取或复用 access ticket。

## 批准案件标准工作流

1. 在 App 中建立 `approved_case_workspace` 会话。只检查图示时授予 `diagram_read`；需要生成或修订时显式增加 `diagram_write`。旧 `read`/`write` 不包含图示能力。
2. 调用 `diagram.list_templates` 与 `diagram.get_schema`。批准通道只返回模板元数据和受限 Schema，不返回内置虚构示例正文。
3. 从当前批准材料取得 `material_id` / `publication_id`，构造最小的 `source_approved_refs`。
4. 生成完整 Spec。每个 Source 的 `id` 与必填 `artifact_id` 必须等于相应 `pub_...`；禁止 path、`file_name`、`uri`、`attachment`，locator 只保留页/段/表等非位置定位。provenance 的 `source_file_ids` 也只写 `pub_...`。
5. 调用 `diagram.validate`。MCP 会重新解析当前来源授权、核对精确 publication 绑定并做残留敏感数据扫描；逐条修复 error，保留 warning 和结论边界。
6. 调用 `diagram.render`，提供 `status` 与全新的 `idempotency_key`。保存返回的 `work_product_id`、版本、spec hash、HTML hash 和 manifest 相关 metadata；不要寻找 URI 或路径。
7. WorkBuddy 在当前批准会话内安全保留用于本次图示的结构化 `base_spec`。局部修改时调用 `diagram.update`，同时提供该完整基线、`work_product_id`、`expected_parent_version`、`expected_spec_hash`、来源引用、patch、状态与新的幂等键。
8. 需要交付描述时调用 `diagram.export`。它只返回经 signed manifest 绑定的 verified descriptor metadata；protected HTML 的实际消费必须经 Privacy work-product 服务和当前授权完成。

每次业务调用的 access ticket 由 App 对规范化请求及目标签发并由宿主内部注入。WorkBuddy 看不到 ticket，也不得要求用户粘贴 ticket。来源在 render 后被撤销时，后续 update/export 必须失败；不要改用 `diagram_authoring` 绕过。

## 合成/公开数据标准工作流

1. 明确记录数据完全虚构或来自公开来源，无现实客户主体。
2. 在 `diagram_authoring` 调用 `diagram.list_templates` / `diagram.get_schema`；该通道可以返回内置虚构示例。
3. 生成完整 Spec 并调用 `diagram.validate`。
4. 调用 `diagram.render`，保存 `artifact_uri` 与 spec hash。
5. 局部修改时以 `artifact_uri` 或 `base_spec` 为基线调用 `diagram.update`；hash 冲突后获取最新基线再分析。
6. 调用 `diagram.export` 重新验证 sibling Spec/HTML，只使用 `html` 格式。

一旦任务混入非公开案件材料，停止该工作流并重新走 Privacy 批准链；不能把已有明文制品“升级”为 protected work product 来补救边界违规。

## 六类调用

| 调用 | `diagram_authoring` | `approved_case_workspace` | grant |
|---|---|---|---|
| `diagram.list_templates` | 返回模板与虚构示例 | 只返回模板元数据 | `diagram_read` |
| `diagram.get_schema` | 完整 DiagramSpec v1 | 禁 path/filename/URI/attachment 的受限投影 | `diagram_read` |
| `diagram.validate` | `spec` | `case_id` + `source_approved_refs` + `spec` | `diagram_read` |
| `diagram.render` | 写明文 sibling bundle，返回 URI | 加 `status`/幂等键，发布 ≤1 MiB encrypted protected HTML | `diagram_write` |
| `diagram.update` | URI 或 base Spec + hash + patch | protected parent/version + 完整 base Spec + 来源 + hash + patch | `diagram_write` |
| `diagram.export` | URI → 明文制品描述符 | case/work-product/version → signed-manifest 绑定 metadata | `diagram_read` |

批准案件的每个规范化业务请求不得超过 256 KiB。响应中若出现批准案件 HTML、path、filename、URI、attachment 或 ticket，应视为边界失败并停止消费。

## 模板选择

- 比较规范层级：`legal_hierarchy_v1`。
- 展示争点到要件、规则和后果的推导：`legal_application_chain_v1`。
- 展示冲突、废止、替代和优先适用：`legal_conflict_priority_v1`。
- 展示当事人、股权、控制、合同、劳动或担保关系：`case_party_relationship_v1`。
- 展示争点、事实、证据、规则和缺失信息：`case_issue_evidence_law_v1`。
- 展示多笔付款、账户路径或资金回流：`case_money_flow_v1`。
- 展示事件顺序、程序节点或陈述时间冲突：`case_timeline_v1`。

一个案件可以生成多张最小图；不要为了塞进单图而混用错误的 diagram type。跨图关联使用批准 publication ID 和稳定业务 ID，不发明新边关系。

## 质量规则

- 将不同主体的陈述建成独立事实或事件节点，并保留 `alleged`、`disputed`、`contradicted`、`unknown`。
- 证据节点写明原件性、核验情况、证明对象、相对方意见和缺陷；“有材料”不等于“事实成立”。
- 法律规范写明版本、条款和已批准/公开来源；无法核实时标记未核验，不能补造引用。
- 资金边保留方向、金额、币种、日期和凭证；疑似回流单独呈现。
- 时间冲突用两个节点和 `conflicts_in_time_with`，不选择性覆盖。
- 缺材料时新增 `missing_information`，并在摘要中说明结论边界。

## 失败与恢复

Schema 或模板版本不兼容时停止。未知关系改用注册表中准确关系，只有确实无法表达时才使用会产生 warning 的 `related_to`。陈旧 parent/version/hash 冲突应在当前授权下取得最新版本并逐项重放。ticket、grant、profile、来源绑定、残留扫描、撤销或 descriptor 验证失败都不能通过拆分请求、改写工具名、移除 provenance、复用幂等键或降级到明文 profile 绕过。
