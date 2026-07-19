# 工具与隐私 profile 契约

机器权威位于 `crates/legal-mcp/src/registry.rs`。所有发布配置和宿主白名单必须与 `integrations/tool-catalog.json` 的 `public_law_only` 五项完全一致。

## Profile

| Profile | `tools/list` | 生产状态 |
|---|---|---|
| `public_law_only` | 五个公开法律只读工具 | 默认且唯一获准的生产 profile |
| `redacted_case` | 公开五项 + receipt-gated `citation_validate` | 实验；App 无法签发该用途票据，生产不可用 |

`redacted_case` 的第六项要求活动、未撤销、未过期的精确票据。票据必须绑定完整请求字节、固定 MCP 目标、固定用途、策略/探测器/内容哈希、密钥版本和短 TTL；材料页或本地导出票据不能复用。当前 App 没有这条签发路径，所以没有生产正向调用。

以下案件能力在两个 profile 中都隐藏并拒绝调用：`case_get_state`、`case_propose_patch`、`case_apply_patch`、`case_analyze_gaps`、`document_generate`、`document_export`。材料导入也不可用；不得用文件、命令、浏览器、Provider 或其他 MCP 工具重建这些流程。

## 通用规则

所有输入都是 snake_case JSON object，必须包含整数 `schema_version: 1`，并拒绝未知字段。所有公开五项均为：

- `readOnlyHint: true`
- `destructiveHint: false`
- `idempotentHint: true`
- `openWorldHint: false`

成功响应使用版本化 envelope；错误和日志不得回显令牌、客户文本、数据库路径或本地文件路径。MCP 的 `content` 与 `structuredContent` 两个结果通道都执行隐私残留检查。

## 五个生产工具

### `system_status`

输入只有 `schema_version`。返回法律库、用户库和 schema 的安全状态，不返回配置路径。宿主只在 `ready` 时继续。

### `legal_search`

按公开关键词、法域和可选公开基准日期检索法律。历史日期字段是 `case_date`，但生产 public-only 调用不得从真实案件材料提取该日期。返回候选法律/条文、版本信息和安全摘要。

### `legal_get_article`

按公开条文标识读取指定版本的条文。宿主必须保留效力区间和数据库缺口，不能把现行条文冒充历史适用文本。

### `legal_get_versions`

读取公开法律文件的版本与生效区间。版本缺失或日期冲突必须显式呈现为缺口。

### `legal_get_relations`

读取公开法律文件之间的引用、替代和关联。关系仅是继续核查的索引，不能替代关联条文原文和版本检查。

## 实验第六项

`citation_validate` 只在显式 `redacted_case` profile 中出现，并对每次调用先核验精确活动票据。它不开放案件状态、材料或文书能力，也不证明模型陈述已获得语义支持。由于 App 尚不能签发该 MCP 用途票据，当前生产宿主不得配置或期待这一项。