# 图示 MCP 工具协议

## 两条不可混用的执行通道

六个图示工具名在两个 profile 中复用，但输入、输出和制品边界不同。客户端必须先按数据等级选择 profile，不能把一种通道的请求或返回值带到另一种通道。

| profile | 固定工具总数 | 图示用途 | 制品与返回边界 |
|---|---:|---|---|
| `diagram_authoring` | 11（5 个公开法律工具 + 6 个图示工具） | 永久只允许纯合成或公开数据 | `DiagramService` 在本地明文写入 sibling `artifact.diagram.json` 与 `artifact.html`，返回 `lawyer-assistance://diagrams/...` `artifact_uri` |
| `approved_case_workspace` | 21（5 个公开法律工具 + 10 个批准案件工具 + 6 个图示工具） | 真实批准案件的唯一图示路径 | `render`/`update` 只发布最多 1 MiB 的加密 protected `text/html` work product；响应不含 HTML、路径、文件名或 URI |

所有请求使用 snake_case、拒绝未知字段。MCP envelope 的 `schema_version` 固定为整数 `1`；`spec.schema_version` 固定为字符串 `"1.0"`。error 表示不能继续，warning 表示需保留并向用户解释的不确定性。

`approved_case_workspace` 的业务请求上限为 256 KiB。App 为每次实际调用签发与 profile、工具、规范化请求 hash、案件、目标对象及版本绑定的一次性 access ticket；该 ticket 由宿主注入，不属于模型可见的 host schema，也不能由客户端自行填写或复用。

## 六个工具

### `diagram.list_templates`

- `diagram_authoring`：请求 `{"schema_version":1}`，返回七个模板描述符及完整内置虚构示例。
- `approved_case_workspace`：请求相同，但只返回模板元数据，不返回内置示例内容。

该工具属于 `diagram_read`，不读取案件正文。

### `diagram.get_schema`

请求 `{"schema_version":1}`，可附 `template_id`。公开通道返回完整冻结 DiagramSpec Schema；批准案件通道返回受限投影：来源不得包含 path、`file_name`、`uri` 或 `attachment`，来源 ID 与 `artifact_id` 必须使用当前批准 publication 的 `pub_...` 不透明标识。

该工具属于 `diagram_read`，不读取案件正文。

### `diagram.validate`

- `diagram_authoring`：`{"schema_version":1,"spec":{...}}`。
- `approved_case_workspace`：`{"schema_version":1,"case_id":"case_...","source_approved_refs":[{"material_id":"mat_...","publication_id":"pub_..."}],"spec":{...}}`。

批准通道先验证一次性 ticket、当前可读的批准来源版本、Spec 与 publication 的精确绑定及残留敏感数据扫描，再执行结构、引用、关系、模板和安全校验。成功只表示当前版本可处理该 Spec，不证明事实真实或法律结论正确。该工具属于 `diagram_read`，不写 work product。

### `diagram.render`

- `diagram_authoring`：`{"schema_version":1,"spec":{...}}`。固定模板确定性渲染，明文写入内容寻址的 Spec/HTML sibling bundle，并返回 URI、hash 和统计。
- `approved_case_workspace`：在 `validate` 请求字段外再提供 `status`（`draft`/`final`）与 `idempotency_key`。固定渲染器在内存中生成 HTML，随后以 `task_type=legal_diagram`、`content_media_type=text/html` 发布加密 protected work product；HTML 最大 1 MiB。

批准通道只返回不透明 `work_product_id`、版本、manifest/内容 hash、字节数、spec hash、统计和净化后的诊断，不返回 HTML、文件系统位置或 `artifact_uri`。该工具属于 `diagram_write`。

### `diagram.update`

- `diagram_authoring`：提供 `expected_spec_hash`，在 `artifact_uri` 与 `base_spec` 中二选一作为基线，再提交有限 patch；成功后写入新的明文内容寻址 sibling bundle。
- `approved_case_workspace`：必须提供 `case_id`、`work_product_id`、`expected_parent_version`、`source_approved_refs`、完整 `base_spec`、`expected_spec_hash`、有限 `patch`、`status` 与 `idempotency_key`。

批准通道会读取并解密指定 protected parent，要求 `expected_spec_hash` 同时匹配 parent manifest 的 canonical Spec hash 与调用方 `base_spec` hash，再重渲染并逐字节核对父内容。应用有限 patch 后，重新验证闭合来源集合、残留扫描和单调来源血缘，最后发布同一 work product 的下一加密版本。删除历史来源依赖、加入无关 envelope 来源、删除仍被引用对象、父版本/hash 不一致、来源被撤销、试图携带位置字段或修改模板代码都 fail closed。该工具属于 `diagram_write`。

### `diagram.export`

- `diagram_authoring`：`{"schema_version":1,"artifact_uri":"lawyer-assistance://diagrams/<64-hex>","format":"html"}`。读取 sibling Spec，核对 URI/spec hash，固定重渲染并逐字节比对已存 HTML，成功后返回明文制品描述符。
- `approved_case_workspace`：`{"schema_version":1,"case_id":"case_...","work_product_id":"wp_...","version":2,"format":"html"}`。读取并验证指定加密 work product、当前来源授权和 signed manifest，只返回绑定该 manifest 的 verified descriptor metadata：案件、work product、版本、格式、MIME、字节数、HTML hash 与 manifest hash。

批准通道绝不返回 HTML、manifest 正文、路径、文件名或 URI，也不负责打开 GUI 或复制文件。该工具属于 `diagram_read`。

## 批准案件授权组

授权策略将图示能力独立分组，避免既有会话静默扩权：

| grant group | 图示工具 |
|---|---|
| `diagram_read` | `diagram.list_templates`、`diagram.get_schema`、`diagram.validate`、`diagram.export` |
| `diagram_write` | `diagram.render`、`diagram.update` |

既有 `read` 仍只授予 8 个案件读取工具，既有 `write` 仍只授予 2 个案件 work-product 写工具；它们不会隐式获得任何图示工具，也不能通过通用 list/read/export/write/update 旁路访问或伪造 `legal_diagram`。需要图示能力的 App 会话必须显式勾选相应新组，最小权限场景可只授予 `diagram_read`。

## 最小调用示例

纯合成/公开数据可使用：

```json
{"name":"diagram.render","arguments":{"schema_version":1,"spec":"<完整的纯合成或公开 DiagramSpec>"}}
```

真实批准案件的渲染形状为：

```json
{
  "name": "diagram.render",
  "arguments": {
    "schema_version": 1,
    "case_id": "case_0123456789abcdef0123456789abcdef",
    "source_approved_refs": [
      {
        "material_id": "mat_0123456789abcdef0123456789abcdef",
        "publication_id": "pub_0123456789abcdef0123456789abcdef"
      }
    ],
    "spec": "<不含路径、文件名、URI、附件字段的完整 DiagramSpec>",
    "status": "draft",
    "idempotency_key": "idem_0123456789abcdef0123456789abcdef"
  }
}
```

示例 ID 仅展示合法形状。真实调用必须使用 App 当前会话提供的不透明 ID 和来源批准引用；不得自行构造、猜测或跨版本复用。

## 错误处理

客户端应按诊断 code 与净化后的 JSON Pointer 修复 Spec，不得移除来源绑定、安全字段或降低校验级别。并发冲突时重新读取已授权的最新 protected 版本再重放仍适用的变更；来源撤销、ticket 失效、profile 拒绝或 descriptor 验证失败时立即停止。不得拆分请求、改名重试、转用 `diagram_authoring`、借用旧 `read`/`write` 授权或把批准案件内容降级写入明文制品。
