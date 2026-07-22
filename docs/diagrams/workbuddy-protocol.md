# WorkBuddy 图示生成协议

## 不可覆盖的 CASE_RAW 边界

进入图示作者流程的数据只允许来自三类范围：完全虚构的测试数据、可公开处理的材料，或由 Privacy 正向链为本次材料版本、目的和图示工具明确授权且可由当前调用逐字节核验的数据。仅有“已处理”“已隐藏姓名”等文字标签不构成批准。宿主在 Skill 运行前已经取得的材料仍可能越过提示词边界，因此生产开放必须依赖可验证的正向批准凭据，而不是模型自述。

案件材料、附件、粘贴、OCR/远程 OCR、截图及其摘要、翻译和派生事实在批准前均按 `CASE_RAW` 处理。若无法确认数据范围，立即停止且不调用任何工具；不要读取、复制、摘要、转换、保存或通过诊断回显未知材料，也不得交给 Provider、网络、browser/search、远程 OCR、其他 MCP/Skill、memory、subagent、连接器、自动化、专家或团队。DeepSeek 等计费测试只使用 `crates/diagrams/examples/` 的纯虚构样例，密钥从系统凭据存储读取，不写入请求样例、日志或 Git。

## 职责分工

WorkBuddy 负责选择模板、提取实体与关系、区分主张/支持/争议/未知、绑定来源并生成 DiagramSpec。MCP 负责边界校验、模板布局、安全渲染、内容寻址和制品存储。WorkBuddy 不生成 HTML/CSS/JS，不提交坐标，不创造关系，不把 `supported` 提升为 `established`。

## 标准工作流

1. 确认数据范围和授权；为虚构测试写明“无现实对应主体”。
2. 调用 `diagram.list_templates`，依据核心问题选择一个模板。
3. 调用 `diagram.get_schema` 取得当前契约和模板约束。
4. 生成完整 Spec；每项关键事实、证据、法律规范和资金记录绑定来源。
5. 调用 `diagram.validate`。逐条修复 error；向用户保留 warning 和不确定性。
6. 调用 `diagram.render`，保存返回的 URI 和 spec hash。
7. 局部修改时调用 `diagram.update`；hash 冲突后重新基于最新版本分析。
8. 需要交付时调用 `diagram.export`，第一阶段仅使用 HTML。

## 六类调用

| 调用 | 目的 | 继续条件 |
|---|---|---|
| `diagram.list_templates` | 发现能力 | 找到与问题匹配的已注册模板 |
| `diagram.get_schema` | 读取契约 | 版本与模板均受支持 |
| `diagram.validate` | 获取结构/语义诊断 | error 为零；warning 已保留或解释 |
| `diagram.render` | 生成确定性制品 | 返回受支持 URI 和 spec hash |
| `diagram.update` | 并发安全局部更新 | `expected_spec_hash` 与基线一致 |
| `diagram.export` | 物化交付文件 | 格式为 `html`，制品已登记 |

## 模板选择

- 比较规范层级：`legal_hierarchy_v1`。
- 展示争点到要件、规则和后果的推导：`legal_application_chain_v1`。
- 展示冲突、废止、替代和优先适用：`legal_conflict_priority_v1`。
- 展示当事人、股权、控制、合同、劳动或担保关系：`case_party_relationship_v1`。
- 展示争点、事实、证据、规则和缺失信息：`case_issue_evidence_law_v1`。
- 展示多笔付款、账户路径或资金回流：`case_money_flow_v1`。
- 展示事件顺序、程序节点或陈述时间冲突：`case_timeline_v1`。

一个案件可以生成多张图；不要为了放入单张图而混用错误的 diagram type。跨图关联在第一阶段用来源和稳定业务 ID 说明，不发明新边关系。

## 质量规则

- 将不同主体的陈述建成独立事实或事件节点，并保留 `alleged`、`disputed`、`contradicted`、`unknown`。
- 证据节点写明原件性、核验情况、证明对象、相对方意见和缺陷；“有材料”不等于“事实成立”。
- 法律规范写明版本、条款和官方来源；无法核实时标记未核验，不能补造引用。
- 资金边保留方向、金额、币种、日期和凭证；疑似回流单独呈现。
- 时间冲突用两个节点和 `conflicts_in_time_with`；不要选择性覆盖。
- 缺材料时新增 `missing_information`，并在摘要中说明结论边界。

## 失败与恢复

Schema 或模板版本不兼容时停止；未知关系改用注册表中准确关系，只有确实无法表达时才使用会产生 warning 的 `related_to`。更新冲突应重新取得最新基线，逐项重放变更。任何 profile、数据范围或来源授权失败都不能通过拆分请求、改写工具名或移除 provenance 绕过。
