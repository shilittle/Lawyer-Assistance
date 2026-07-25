# 纯虚构样例目录

所有样例均为工程测试 fixtures，无现实对应主体、案件、账户、法律规范或法律效力。它们只属于 `diagram_authoring` 的 synthetic/public 基线，不得把字段替换为生产材料后直接提交外部模型或真实案件 profile。真实材料必须先成为当前调用可验证、范围覆盖本次材料版本/目的/图示工具的 Privacy 批准 publication，再按 `approved_case_workspace` 的受限 Schema 从零构造最小 Spec。

## Profile 消费边界

- `diagram_authoring` 的 `diagram.list_templates` 可以返回七个注册表主样例的完整内容；render/update 会把 Spec 与 HTML 明文写入本地 sibling bundle，并返回 `artifact_uri`。
- `approved_case_workspace` 的 list/get-schema 只返回模板元数据与受限 Schema，不返回任何内置样例正文。客户端不得把本目录 fixture 误当作当前案件来源。
- 把样例的结构模式用于批准案件时，必须删除 path、`file_name`、`uri`、`attachment`，把每个 Source 的 `id` 和 `artifact_id` 替换为当前 `source_approved_refs` 中精确匹配的 `pub_...`，并让 provenance 的 `source_file_ids` 使用同一 publication ID。
- 真实批准案件只能发布最多 1 MiB 的 encrypted protected `text/html` work product；不得把真实数据写入本目录、测试快照、明文 `artifact.diagram.json` / `artifact.html` 或文档示例。

## 注册表主样例

| 文件 | 模板 | 主要覆盖 |
|---|---|---|
| `legal_hierarchy_v1.json` | `legal_hierarchy_v1` | 虚构规范层级、授权方向 |
| `legal_application_chain_v1.json` | `legal_application_chain_v1` | 虚构民间借贷规则、要件、后果 |
| `legal_conflict_priority_v1.json` | `legal_conflict_priority_v1` | 冲突、替代、优先适用 |
| `case_party_relationship_v1.json` | `case_party_relationship_v1` | 股权与间接控制 |
| `case_issue_evidence_law_v1.json` | `case_issue_evidence_law_v1` | 买卖合同、证据不足、待补信息 |
| `case_money_flow_v1.json` | `case_money_flow_v1` | 多笔转账与同日回流 |
| `case_timeline_v1.json` | `case_timeline_v1` | 两种交付日期陈述及时间矛盾 |

上述文件名由模板注册表引用，不可随意改名。

## 补充情景样例

| 文件 | 场景 |
|---|---|
| `case-party-multi-guarantee-fictional.json` | 多个保证人和抵押提供方 |
| `case-issue-evidence-loan-fictional.json` | 民间借贷款项性质、双方主张、证据范围与待补材料 |
| `case-issue-evidence-labor-fictional.json` | 劳动关系、工资、门禁和加班待补证 |
| `case-money-flow-sales-fictional.json` | 买卖合同分期付款与争议尾款 |
| `case-timeline-labor-dispute-fictional.json` | 劳动争议履行、解除、仲裁与程序时间轴 |
| `legal-application-general-special-exception-fictional.json` | 同一法律领域的一般规则、特别规则、例外与适用结论 |

## 兼容性回归样例

为覆盖同一模板的不同结构，仓库还保留七份纯虚构回归变体：

- `legal-hierarchy-fictional.json`
- `legal-application-chain-fictional-loan.json`
- `legal-conflict-priority-fictional.json`
- `case-party-equity-control-fictional.json`
- `case-issue-evidence-sales-insufficient-fictional.json`
- `case-money-flow-loan-backflow-fictional.json`
- `case-timeline-conflict-fictional.json`

因此第一阶段共提供且固定校验 20 份样例；`all_examples` 测试会遍历全部 JSON，并断言精确数量，而不仅校验七个注册表默认文件。七个注册表默认文件另由 `examples_contract` 逐一核对模板描述符中的样例路径。

## 校验要求

样例变更后必须执行 JSON 解析、DiagramSpec Schema、完整语义/模板校验和确定性渲染。允许为了展示不确定性保留 warning，但不能保留 error。所有金额使用十进制定点字符串和 ISO 4217 币种，所有时间事件携带可核验的日期字段，所有关键节点与边的 `source_refs` 必须闭合。样例门禁证明 synthetic/public 契约，不替代批准 profile 的 publication 绑定、256 KiB 请求、残留扫描、protected work-product 和撤销测试。
