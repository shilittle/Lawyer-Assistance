# 工具与隐私 profile 契约

机器权威位于 `crates/legal-mcp/src/registry.rs`。默认发布配置和宿主白名单必须与 `integrations/tool-catalog.json` 的 `public_law_only` 五项完全一致；资格门禁资产必须与 `integrations/tool-catalog.approved-case-workspace.json` 的 21 项完全一致，二者不能混用。

## Profile

| Profile | `tools/list` | 生产状态 |
|---|---|---|
| `public_law_only` | 五个公开法律只读工具 | 默认且唯一获准的生产 profile |
| `redacted_case` | 公开五项 + receipt-gated `citation_validate` | 实验；App 无法签发该用途票据，生产不可用 |
| `diagram_authoring` | 公开五项 + 六个明文本地图示工具 | 永久仅合成/公开数据；不得处理真实批准案件 |
| `approved_case_workspace` | 公开五项 + 十个 ID-only 批准材料/成果工具 + 六个批准图示工具，共 21 项 | 真实 handler；仅当前 App 资格 + policy-v2 standalone session + 精确一次性 ticket 有效时执行，静态宿主资产默认禁用 |

`redacted_case` 的第六项要求活动、未撤销、未过期的精确票据。票据必须绑定完整请求字节、固定 MCP 目标、固定用途、策略/探测器/内容哈希、密钥版本和短 TTL；材料页或本地导出票据不能复用。当前 App 没有这条签发路径，所以没有生产正向调用。

`approved_case_workspace` 的 16 个非公开工具仅处理签名批准 generation、匿名 work-product 和固定公开图示模板/schema。正文只可由当前 `case_read_approved_material` 直接响应提供；普通成果只可通过 `case_write_work_product` 或 `case_update_work_product` 写回，图示成果只可通过 `diagram.render` 或 `diagram.update` 写入加密 protected HTML。`diagram.export` 只返回签名 descriptor metadata，不返回 HTML、路径或 URI。formal App 在构建时内置 exact paired MCP sibling SHA-256；运行时还复测 sibling path/file identity/version/behavior。无该 compile-time anchor 的 development App、同名替换 binary、静态 host allowlist 或用户同意均不能取得 qualification。完整契约见[批准案件工作区 profile](approved-case-workspace.md)。

policy v2 的 session grants 精确为 `read` 八项、`write` 两项、`diagram_read` 四项和 `diagram_write` 两项。原有 `read` / `write` 不包含任何图示工具，升级不会静默扩权；没有 `diagram_read` 时通用案件读取接口不显示或返回 `legal_diagram`，通用写入接口也不能创建或更新它。旧 session 必须撤销并重建。

以下旧宽泛能力在所有 profile 中都隐藏并拒绝调用：`case_get_state`、`case_propose_patch`、`case_apply_patch`、`case_analyze_gaps`、`document_generate`、`document_export`。任意路径材料导入也不可用；不得用文件、命令、浏览器、Provider 或其他 MCP 工具重建这些流程。

## 通用规则

所有输入都是 snake_case JSON object，必须包含整数 `schema_version: 1`，并拒绝未知字段。所有公开五项均为：

- `readOnlyHint: true`
- `destructiveHint: false`
- `idempotentHint: true`
- `openWorldHint: false`

成功响应使用版本化 envelope；错误和日志不得回显令牌、客户文本、数据库路径或本地文件路径。MCP 的 `content` 与 `structuredContent` 两个结果通道都执行隐私残留检查。

`public_law_only` 与 `approved_case_workspace` 是不同的数据面，不是同一 profile 的“开关强弱”：public 五项不能读取 approved material/work product/Vault；approved 16 项也不能接受任意路径、附件、粘贴原文或 raw OCR。`diagram_authoring` 的明文本地 bundle 契约也不能用作批准案件的降级路径。较早 15-tool actual-binary stdio/HTTP 合成 E2E 只证明当时的 handler/transport/auth chain；2026-07-24 已完成集成后 21-tool debug sibling 的 stdio/HTTP 合成复跑，最终 release sibling 仍须重新测量、签名并复跑。当前机器 OCR 四项资格仍为 `false`，MCP E2E 不等于真实扫描案件获准处理。

## 六个图示工具的双重契约

六个工具名在 `diagram_authoring` 与 `approved_case_workspace` 中相同，但 schema、存储和授权边界不同：

- `diagram.list_templates`、`diagram.get_schema`：只返回固定模板/schema 信息。
- `diagram.validate`：批准 profile 还要求当前可读的精确 approved source references。
- `diagram.render`、`diagram.update`：批准 profile 的输入为闭合、无位置字段的 Spec/patch，source 集合精确绑定，输出只发布带 canonical Spec hash 与来源血缘的加密 protected `text/html` work-product version；synthetic/public profile 才生成明文本地 bundle。
- `diagram.export`：批准 profile 只返回 verified descriptor metadata，无 path、URI 或 HTML；synthetic/public profile 返回本地 artifact descriptor。

宿主必须按 profile 校验 schema，不能把 `diagram_authoring` 的 `artifact_uri` 请求或响应带入批准案件会话。

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
