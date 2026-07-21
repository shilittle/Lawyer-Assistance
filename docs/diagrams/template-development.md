# 图示模板开发指南

## 模板清单

| template_id | diagram_type | 核心问题 | 推荐布局 |
|---|---|---|---|
| `legal_hierarchy_v1` | `legal_hierarchy` | 规范效力层级 | top-down |
| `legal_application_chain_v1` | `legal_application_chain` | 规则、要件与后果 | left-right |
| `legal_conflict_priority_v1` | `legal_conflict_priority` | 规范冲突与优先顺序 | left-right 对照 |
| `case_party_relationship_v1` | `case_party_relationship` | 当事人、股权、控制与担保 | 中心/分层 |
| `case_issue_evidence_law_v1` | `case_issue_evidence_law` | 争点、事实、证据与规则 | 争点分栏 |
| `case_money_flow_v1` | `case_money_flow` | 款项方向、金额、日期与回流 | 有向流 |
| `case_timeline_v1` | `case_timeline` | 事件顺序、程序和日期冲突 | timeline |

## 描述符要求

每个模板描述符固定声明模板 ID、语义版本 `1.0.0`、中文名、适用场景、对应 diagram type、必需节点类型、允许关系、布局策略及仓库样例路径。模板只能收紧公共 DiagramSpec，不能添加未入 Schema 的私有字段。

新增模板前应先回答：它是否表达新的法律分析问题，而不是只改变颜色或排版；现有节点和关系是否足够；来源与不确定性如何呈现；大图如何分组和降噪。仅视觉差异应作为固定渲染策略或有限显示选项处理。

## 七模板语义检查

- 层级图：`superior_to` 必须从高位规范指向低位规范；`authorized_by` 从被授权规范指向授权依据。
- 适用链：至少表达争点、规则/要件和后果；`requires` 指向必要条件，`leads_to` 指向后果或结论。
- 冲突图：冲突和优先关系必须分开保存；`conflicts_with` 不等同于 `applies_before`。
- 主体图：控制、持有、担保、债务和代理方向必须按关系注册表保存；名称不能代替主体 ID。
- 争点图：证据通过 `proves` 或 `supports` 指向事实/争点，规则通过 `applies_to` 指向争点；证据弱点和待补材料不能被隐藏。
- 资金图：每条核心资金边应有金额、币种、日期和凭证来源；回流必须作为反向流单独保存，不能净额抵销后丢失路径。
- 时间图：事件应有日期或日期区间；相互矛盾的陈述使用独立节点和 `conflicts_in_time_with`，不能由模型任选一个覆盖另一个。

## 开发步骤

1. 在公共 Schema 和关系注册表可表达的前提下定义模板描述符。
2. 为有效最小图、复杂图和每类拒绝场景编写测试。
3. 实现稳定排序、固定间距和可预测的边路由；禁止读取随机数、网络或系统区域设置。
4. 增加至少一个纯虚构样例，确保标题、来源和 provenance 明示其测试属性。
5. 为模板增加安全快照、窄屏/打印检查和 20/100/500 节点性能样本。
6. 更新模板清单、WorkBuddy 参考资料与迁移说明。

## 设计禁区

- 不接收任意 CSS、JS、HTML、SVG path 或绝对坐标。
- 不为某个客户或案件扩展自由文本 relation。
- 不以颜色作为唯一状态信号；文字、形状或图例必须同步表达。
- 不在布局阶段改变节点状态、删除争议证据或合并不同来源的事实。
- 不把 URL 当作自动抓取指令；来源 URI 只展示并通过协议白名单校验。

## 验收清单

模板需要通过描述符唯一性、图类型匹配、允许节点/关系、来源完整性、稳定字节输出、键盘可达、打印可读、注入载荷、节点上限和退化布局测试。任何语义变化都必须提升模板版本并给出迁移策略。
