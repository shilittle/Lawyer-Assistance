# 模板与调用示例

## 模板选择

- 规范层级：`legal_hierarchy_v1`
- 规则—要件—后果：`legal_application_chain_v1`
- 规范冲突与优先：`legal_conflict_priority_v1`
- 主体、股权、控制与担保：`case_party_relationship_v1`
- 争点、证据、规则与缺口：`case_issue_evidence_law_v1`
- 多笔付款、账户路径与回流：`case_money_flow_v1`
- 事件顺序与时间矛盾：`case_timeline_v1`

仓库 `crates/diagrams/examples/` 提供纯虚构样例，覆盖民间借贷、买卖合同、劳动争议、股权控制、多方担保、多笔转账/回流、时间矛盾和证据不足。

## 六个必备场景的完整 fixture

| 场景 | 可直接加载或组合参照的完整 Spec |
|---|---|
| 民间借贷争点—证据—法律图 | `crates/diagrams/examples/case-issue-evidence-loan-fictional.json` |
| 多主体资金流与回流 | `crates/diagrams/examples/case-money-flow-loan-backflow-fictional.json` |
| 公司股权与实际控制 | `crates/diagrams/examples/case-party-equity-control-fictional.json` |
| 劳动争议时间轴 | `crates/diagrams/examples/case-timeline-labor-dispute-fictional.json` |
| 同领域上下位规范 | `crates/diagrams/examples/legal-hierarchy-fictional.json` |
| 一般规则、特别规则与例外 | `crates/diagrams/examples/legal-application-general-special-exception-fictional.json` |

调用时读取整个 JSON 对象作为 `spec`，不得把文件路径或尖括号占位字符串提交给 MCP。所有文件均为纯虚构测试数据。

## 六类最小调用

```json
{"name":"diagram.list_templates","arguments":{"schema_version":1}}
```

```json
{"name":"diagram.get_schema","arguments":{"schema_version":1,"template_id":"case_money_flow_v1"}}
```

```json
{"name":"diagram.validate","arguments":{"schema_version":1,"spec":"<完整 DiagramSpec 对象>"}}
```

```json
{"name":"diagram.render","arguments":{"schema_version":1,"spec":"<同一份已校验对象>"}}
```

```json
{"name":"diagram.update","arguments":{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expected_spec_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","patch":{"summary":"补充虚构流水回流说明"}}}
```

```json
{"name":"diagram.export","arguments":{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","format":"html"}}
```

尖括号字符串只表示文档占位。实际 `spec` 必须是完整 JSON 对象，不能提交占位字符串。

上面的 64 位十六进制仅用于展示合法格式；实际调用必须使用前一次 `render`/`update` 返回的 `artifact_uri` 和 `spec_hash`，不得自行构造。

## 质量示例

时间冲突应建立“陈述甲日期”和“陈述乙日期”两个事件节点，并用 `conflicts_in_time_with` 连接。证据不足应保留现有证据的缺陷，再增加 `missing_information`。多笔转账应逐笔保存金额、币种、日期和凭证来源；同日回流另建反向资金记录。这样图示能表达不确定性，而不是制造一个看似确定的故事。
