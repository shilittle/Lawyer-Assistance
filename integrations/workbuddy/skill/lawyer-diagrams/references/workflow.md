# 工作流与六类调用

## 执行顺序

1. 确认数据为纯虚构、公开，或当前调用可逐字节验证且范围覆盖本次材料版本、目的和图示工具的 Privacy 批准产物。
2. `diagram.list_templates({"schema_version":1})`：发现七个可用模板。
3. `diagram.get_schema({"schema_version":1,"template_id":"..."})`：读取公共 Schema 与模板约束。
4. 生成完整 Spec；Spec 内的 `schema_version` 是字符串 `"1.0"`。
5. `diagram.validate({"schema_version":1,"spec":{...}})`：修复 error，保留并说明 warning。
6. `diagram.render({"schema_version":1,"spec":{...}})`：生成内容寻址 HTML，保存 URI 和 spec hash。
7. `diagram.update`：提供 `artifact_uri` 或 `base_spec`、`expected_spec_hash` 与有限 patch。
8. `diagram.export({"schema_version":1,"artifact_uri":"...","format":"html"})`：物化交付。

六个工具分别承担能力发现、契约读取、校验、渲染、并发安全更新和 HTML 导出。不得跳过能力发现直接猜测模板，也不得在校验失败后直接渲染。

## 状态与来源

- `alleged`：一方主张，尚未确认。
- `supported`：有材料支持，仍不等于事实成立。
- `disputed` / `contradicted`：存在明确争议或矛盾材料。
- `established`：只有可信确认依据充分时使用。
- `unknown`：信息缺失或无法判断。

每个关键节点和边都应通过 `source_refs` 回指 `sources`。来源定位要足以由人复核，但不得把本机绝对路径或秘密写入 Spec。缺证据时使用 `missing_information`，不补造事实、日期、条文或凭证。

## 更新冲突

`expected_spec_hash` 不匹配表示基线已变化。停止当前写入，获取最新版本并检查每项变更是否仍适用，然后用新 hash 重试。不要去掉 hash、改为整图覆盖或反复提交旧 patch。
