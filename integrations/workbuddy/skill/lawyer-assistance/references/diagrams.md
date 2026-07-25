# 图示规范入口

当前 `lawyer-assistance` Skill 只用于公开法律研究，不应在该 Skill 中生成案件图。纯虚构或公开材料图示可改用独立 `lawyer-diagrams` Skill 与显式启用的 `diagram_authoring` profile；真实案件即使已有可信本地批准链，也只能使用 `lawyer-assistance-approved-workspace` Skill 与 `approved_case_workspace` profile。

公开规范入口：

- `docs/diagrams/diagram-spec-v1.md`：DiagramSpec 数据契约。
- `docs/diagrams/relations-v1.md`：关系方向与语义。
- `docs/diagrams/architecture.md`：组件、信任边界和数据流。
- `docs/diagrams/template-development.md`：七模板及扩展规则。
- `docs/diagrams/mcp-tools.md`：六个 MCP 工具。
- `docs/diagrams/workbuddy-protocol.md`：WorkBuddy 调用协议。
- `docs/diagrams/security-model.md`：安全模型。
- `docs/diagrams/testing.md`：测试和验收。
- `docs/diagrams/extension-and-versioning.md`：扩展与版本迁移。

`CASE_RAW` 数据边界优先于图示请求。真实案件材料、附件或派生事实绝不进入会明文生成 `artifact.diagram.json`/`artifact.html` 的 `diagram_authoring`，批准标签也不能改变该路由。approved workspace 的图示工具只接受当前批准来源引用并发布加密 protected work product。DeepSeek 等外部模型计费测试仅使用 `crates/diagrams/examples/` 中明确标为虚构的样例。
