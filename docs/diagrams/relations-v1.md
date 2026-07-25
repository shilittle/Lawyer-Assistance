# DiagramSpec v1 关系注册表

方向写作 `source → target`。除 `related_to` 外禁止发明关系。模板注册表还会收紧每个关系可出现的图类型。

| relation | 中文 | 允许的 source → target | 语义 |
|---|---|---|---|
| `supports` | 支持 | evidence/rule/fact → fact/issue/claim/conclusion | 前者支持后者，不等于已确认 |
| `contradicts` | 反驳 | evidence/fact → fact/claim/defense | 前者与后者冲突 |
| `proves` | 证明对象 | evidence → fact/event/amount | 证据拟证明的对象 |
| `alleges` | 主张 | party/claim → fact/issue | 主体或请求提出但未确认的陈述 |
| `admits` | 自认 | party/defense → fact | 对事实明确承认 |
| `disputes` | 争议 | party/defense → fact/issue/claim | 明确争议 |
| `raises` | 提出争点 | claim/defense/party → issue | 形成争议焦点 |
| `applies_to` | 适用于 | rule/law/principle → issue/fact/relationship/subject | 规范适用对象 |
| `requires` | 要求满足 | rule/claim → element/evidence/fact | 构成或证明条件 |
| `leads_to` | 导致 | fact/element/rule/event → consequence/conclusion/event | 条件满足后的后果 |
| `based_on` | 基于 | claim/defense/conclusion → rule/fact/evidence | 分析或主张依据 |
| `involves` | 涉及 | issue/event/relationship → party/amount | 业务参与对象 |
| `occurred_before` | 先于 | event/procedure → event/procedure | 时间先后 |
| `occurred_after` | 后于 | event/procedure → event/procedure | 时间先后 |
| `same_event_as` | 同一事件 | event/procedure ↔ event/procedure | 不同陈述指向同一事件 |
| `conflicts_in_time_with` | 时间冲突 | event/procedure ↔ event/procedure | 时间陈述矛盾 |
| `paid_to` | 支付给 | party → party | 资金方向，须关联 amount 或边金额 metadata |
| `transferred_to` | 转给 | party/account/amount → party/account/amount | 转账或权利移转 |
| `owes` | 负有债务 | party → party/amount | 债务方向 |
| `guarantees` | 担保 | party/relationship → party/amount/relationship | 担保对象 |
| `controls` | 控制 | party → party | 实际或协议控制 |
| `owns` | 持有 | party → party/amount | 股权/财产权持有 |
| `represents` | 代理 | party → party | 代理方向 |
| `employs` | 雇佣 | party → party | 用人单位到劳动者 |
| `contracts_with` | 订约 | party ↔ party | 合同相对关系 |
| `related_party_of` | 关联主体 | party ↔ party | 有明确依据的关联主体 |
| `superior_to` | 效力高于 | legal norm → legal norm | 上位规范到下位规范 |
| `authorized_by` | 依据授权 | lower norm → higher norm | 被授权规范到授权依据 |
| `implements` | 实施细化 | lower/specific norm → higher/general norm | 实施性规范到被实施规范 |
| `references` | 引用 | legal norm/rule → legal norm/rule | 前者引用后者 |
| `supplements` | 补充 | legal norm/rule → legal norm/rule | 前者补充后者 |
| `interprets` | 解释 | interpretation/rule → legal norm/rule | 解释文件到被解释规范 |
| `exception_to` | 构成例外 | exception/rule → general rule | 特别例外到一般规则 |
| `limits` | 限制 | rule/norm → rule/norm/subject | 前者限制后者范围 |
| `conflicts_with` | 规范冲突 | norm/rule ↔ norm/rule | 规范内容存在冲突 |
| `repeals` | 废止 | newer norm → older norm | 废止行为方向 |
| `amends` | 修改 | newer norm → older/versioned norm | 修改行为方向 |
| `replaces` | 替代 | newer norm → older norm | 替代方向 |
| `applies_before` | 优先适用 | norm/rule → norm/rule | 冲突时前者优先 |
| `contains` | 包含 | law/group → rule/article/node | 结构包含 |
| `belongs_to` | 属于 | node → group/law/relationship | 结构归属 |
| `related_to` | 其他关联 | any → any | 兜底；每次产生 warning |

## 校验原则

- 法律层级只比较可识别的效力层级；低位规范 `superior_to` 高位规范是 error。
- `authorized_by` 与 `implements` 的方向不得反写；需要反向展示时由渲染器画回边，不改变数据语义。
- `paid_to`/`transferred_to` 必须有方向、金额/币种/日期以及凭证来源；缺失字段至少 warning，核心资金图可升级为 error。
- `supports` 只表达支持强度，不改变事实状态。
- 对称关系在注册表中标记为 symmetric，但仍保存明确 source/target，渲染器使用双向视觉标记。
- 自环只允许 `same_event_as` 的兼容迁移场景并产生 warning；其他自环是 error。
