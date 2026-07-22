# 图示 MCP 工具协议

## 共同封装

所有请求使用 snake_case，拒绝未知字段。MCP 请求的 `schema_version` 固定为整数 `1`；`spec.schema_version` 固定为字符串 `"1.0"`。工具只在显式启用的 `diagram_authoring` profile 中注册。

模型可见响应应保持小而稳定：返回版本、诊断、统计、spec hash 和 `lawyer-assistance://diagrams/...` URI，不返回绝对路径、凭据或规范全文日志。error 表示不能继续渲染；warning 表示需要用户注意但不必然阻止操作。

## 六个工具

### `diagram.list_templates`

请求：`{"schema_version":1}`。返回七个模板描述符及版本。客户端必须以此为能力发现来源，不能硬编码尚未协商的模板。

### `diagram.get_schema`

请求：`{"schema_version":1}`，可附 `template_id`。返回公共 DiagramSpec Schema；给定模板时同时返回模板约束摘要。未知模板或版本应明确拒绝。

### `diagram.validate`

请求：`{"schema_version":1,"spec":{...}}`。执行结构、引用、关系、模板和安全边界校验。成功不代表事实真实或法律判断正确；它只说明规范可被本版本处理。

### `diagram.render`

请求：`{"schema_version":1,"spec":{...}}`。先完整校验，再通过固定模板生成内容寻址 HTML。相同输入必须幂等；已有相同制品时可直接复用。

### `diagram.update`

请求必须提供 `expected_spec_hash`，并在 `artifact_uri` 与 `base_spec` 中二选一作为基线，再提供有限 patch。patch 只允许修改标题、摘要、布局提示、显示选项，或 upsert/remove 节点、边、组和来源。删除仍被引用的对象、并发 hash 不一致或试图修改模板代码都会失败。

### `diagram.export`

请求：`{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/<64位小写十六进制>","format":"html"}`。第一阶段格式只允许 `html`；工具读取同目录 sibling Spec，核对 URI/spec hash 与规范化字节，用固定渲染器重渲染并逐字节比对已存 HTML，全部通过后才返回不可变描述。孤儿、换绑或任一侧篡改均 fail closed；工具不联网、不打开 GUI。

## 调用示例

```json
{"name":"diagram.list_templates","arguments":{"schema_version":1}}
```

```json
{"name":"diagram.get_schema","arguments":{"schema_version":1,"template_id":"case_timeline_v1"}}
```

```json
{"name":"diagram.validate","arguments":{"schema_version":1,"spec":{"schema_version":"1.0","diagram_type":"case_timeline","template_id":"case_timeline_v1"}}}
```

上例省略了 Spec 必填字段，仅用于说明 envelope；实际请求必须提交完整对象。

```json
{"name":"diagram.render","arguments":{"schema_version":1,"spec":"<完整 DiagramSpec 对象>"}}
```

```json
{"name":"diagram.update","arguments":{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expected_spec_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","patch":{"title":"修订后的虚构示意图"}}}
```

```json
{"name":"diagram.export","arguments":{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","format":"html"}}

以上十六进制值仅展示合法格式；真实调用必须复用 `render`/`update` 返回值。
```

## 错误处理

客户端应按诊断路径修复 Spec，而不是移除安全字段或降低校验级别。hash 冲突时重新获取基线并重放仍然适用的变更；版本不兼容时停止并请求能力协商；profile 拒绝时不得改名重试或借用其他工具绕过门禁。
