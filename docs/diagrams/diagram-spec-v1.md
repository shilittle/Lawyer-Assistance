# DiagramSpec v1 数据契约

本文件与 `crates/diagrams/schema/diagram-spec-v1.schema.json`、Rust 类型和模板注册表共同构成冻结基础契约。发生冲突时以通过测试的机器 Schema 与 Rust 枚举为准，文档必须在同一提交同步修正。

同一 v1 数据模型有两个 MCP 投影，不能把基础 Schema 的位置字段理解为批准案件许可：

| profile | Schema 投影 | 允许数据 |
|---|---|---|
| `diagram_authoring` | 完整基础 Schema | 永久仅纯合成/公开数据；允许产生明文 Spec/HTML 与 `artifact_uri` |
| `approved_case_workspace` | 由 `diagram.get_schema` 返回的受限投影，并叠加当前 publication 精确绑定与残留扫描 | 真实批准案件的唯一图示路径；禁止 path、filename、URI、attachment |

受限投影不是新的 DiagramSpec 版本；它是在相同 `schema_version="1.0"` 上按 profile 收紧准入。因此客户端必须使用当前 profile 的 `diagram.get_schema`，不得缓存另一 profile 的 Schema 代用。

## 版本与标识

- `schema_version` 固定为字符串 `1.0`；MCP envelope 的 `schema_version` 是整数 `1`，两者不能混用。
- `template_id` 必须来自七模板注册表且与 `diagram_type` 匹配。
- ID 使用 1–96 个 ASCII 字符，首字符为字母或数字，后续只允许字母、数字、`_`、`-`、`.`、`:`。
- 节点、边、组、来源分别唯一；节点和边 ID 还必须共同唯一。

## 顶层对象

| 字段 | 类型 | 限制 |
|---|---|---|
| `schema_version` | string | `1.0` |
| `diagram_type` | enum | 七类业务图 |
| `template_id` | enum | 七模板 |
| `title` | string | 1–256 字符 |
| `summary` | string | 0–4096 字符 |
| `nodes` | array | 1–500 |
| `edges` | array | 0–1200 |
| `groups` | array | 0–100 |
| `sources` | array | 0–1000 |
| `layout_hints` | object | 仅有限提示 |
| `display_options` | object | 仅固定布尔/枚举选项 |
| `provenance` | object | 必填生成和版本边界 |

## 节点

必填字段：`id`、`type`、`label`、`details`、`status`、`importance`、`source_refs`、`tags`、`metadata`。`subtype`、`short_label` 可空。

节点类型冻结为：

`party`、`account`、`event`、`legal_relationship`、`fact`、`issue`、`evidence`、`rule`、`claim`、`defense`、`amount`、`procedure`、`law`、`regulation`、`supervisory_regulation`、`judicial_interpretation`、`department_rule`、`local_regulation`、`local_government_rule`、`normative_document`、`guiding_case`、`legal_principle`、`element`、`legal_consequence`、`exception_rule`、`application_conclusion`、`missing_information`。

事实状态冻结为：`alleged`、`admitted`、`supported`、`disputed`、`contradicted`、`established`、`unsupported`、`unknown`。其他实体可使用：`active`、`inactive`、`pending`、`completed`、`effective`、`repealed`、`expired`、`not_yet_effective`、`uncertain`、`not_applicable`。

`supported` 不会被系统自动提升为 `established`。`established` 且仍存在严重争议会产生 error 或 warning（取决于矛盾证据是否明确）。

`importance`：`critical`、`high`、`normal`、`low`。

领域 `metadata` 使用固定键而非模板自定义 Schema：

- Evidence：`evidence_name`、`evidence_type`、`submitted_by`、`formed_on`、`source_file`、`locator`、`proves`、`authenticity`、`legality`、`relevance`、`is_original`、`examined`、`opponent_view`、`probative_value`、`supports_facts`、`contradicts_facts`、`defects`、`human_confirmation`。
- Legal norm：`full_name`、`short_name`、`issuing_authority`、`document_number`、`authority_level`、`published_on`、`effective_from`、`effective_to`、`validity_status`、`jurisdiction`、`applicable_subjects`、`article`、`paragraph`、`item`、`version`、`official_source`、`quoted_text`、`verified_by`。
- Amount：`amount`（十进制定点字符串）、`currency`（ISO 4217）、`date`、`purpose`、`voucher_source_ref`。
- Event/Procedure：`date`、`date_start`、`date_end`、`date_precision`、`sequence`、`limitation_deadline`、`statement_variant`。
- Party：`role`、`organization_type`、`ownership_percent`、`human_confirmation`。

## 边

必填字段：`id`、`source`、`target`、`relation`、`label`、`strength`、`source_refs`、`metadata`。`source`/`target` 必须指向节点；方向是语义的一部分。

`strength`：`conclusive`、`strong`、`moderate`、`weak`、`unknown`。关系权威定义见 `relations-v1.md`。`related_to` 是唯一兜底关系，每次使用产生 warning；占边数超过 10% 产生额外 warning。

## 组

组包含 `id`、`label`、`node_ids`、可空 `parent_group_id`、`collapsed_by_default`、`source_refs`。组不能循环嵌套；同一节点可进入多个语义组，但模板可限制。

## 来源：基础契约

必填：`id`、`kind`、`title`、`locator`、`verification_status`。可选：`artifact_id`、`uri`、`file_name`、`page`、`paragraph`、`table`、`attachment`、`law_document`、`law_version`、`article`、`quote`、`content_hash`。

`kind`：`file`、`file_page`、`paragraph`、`table`、`attachment`、`law`、`case_record`、`artifact`、`uri`、`model_analysis`、`human_input`。`verification_status`：`original_material`、`model_extracted`、`model_analyzed`、`database_verified`、`human_confirmed`、`unverified`。

文件来源至少提供 `artifact_id` 或 `file_name`，并提供页/段/表/附件之一或明确 `locator`。法律来源必须提供 `law_document`、`law_version`、`article`（适用时）和官方 `uri` 或内部 `artifact_id`。URI 只展示，不自动访问。

上述位置能力只属于 `diagram_authoring` 的纯合成/公开基础契约。它不会授予文件读取能力，但写出的 `artifact.diagram.json` 与 `artifact.html` 是明文，绝不能承载真实案件。

## 批准案件来源投影

`approved_case_workspace` 对 Source 和 provenance 施加额外的机器 Schema 与运行时约束：

- Source 不允许 `uri`、`file_name`、`attachment`，`kind` 不允许 `file`、`file_page`、`attachment`、`uri`。
- Source `id` 与必填 `artifact_id` 都必须是 `pub_` 加 32 位小写十六进制的不透明 publication ID。
- 每个 Spec Source 必须精确匹配 envelope 的 `source_approved_refs[].publication_id`；不得多报未批准来源，也不得以文件名、路径或摘要替代 publication。
- provenance 的 `source_file_ids` 只允许上述 `pub_...`，此字段在批准投影中实际表示来源 publication 绑定，不是本地文件 ID。
- `locator` 可以表达页、段、表、条款等非位置定位，但不得包含 path、filename、URI 或 attachment 引用；节点 metadata、标题、摘要等其他字段也不得换键编码这些位置数据。
- Spec 必须至少包含一个当前批准来源；来源撤销、版本不再可读、publication 不匹配或 residual scan 发现未批准敏感残留时，validate/render/update/export 都 fail closed。

批准 envelope 另带不属于 DiagramSpec 的 `case_id` 与 `source_approved_refs`：

```json
{
  "case_id": "case_0123456789abcdef0123456789abcdef",
  "source_approved_refs": [
    {
      "material_id": "mat_0123456789abcdef0123456789abcdef",
      "publication_id": "pub_0123456789abcdef0123456789abcdef"
    }
  ]
}
```

这些引用由 App/Privacy 链提供，不能由模型根据内容推断或自行构造。

## 布局与显示

`layout_hints` 只允许：`direction`（`top_down`/`left_right`/`radial`/`timeline`）、`preferred_root_ids`、`group_by`、`max_initial_nodes`、`timeline_lane`。不得提交坐标、样式或脚本。

`display_options` 只允许：`theme`（`light`/`dark`/`auto`）、`show_legend`、`show_sources`、`hide_weak_edges`、`collapse_low_importance`、`print_page_size`（`a4_landscape`/`a4_portrait`）。

## provenance

必填：`generated_by`、`generated_at`（RFC 3339）、`diagram_spec_version`（`1.0`）、`template_version`（`1.0.0`）、`source_file_ids`、`human_confirmed`、`model_content_scope`、`deterministic_content_scope`。可选：`parent_spec_hash`、`change_summary`。

`generated_by`：`workbuddy`、`codex`、`local_model`、`human`、`importer`。`model_content_scope` 必须说明模型只负责提取/分析数据；`deterministic_content_scope` 必须说明 HTML/CSS/JS/布局来自 MCP 固定模板。

## 局部更新

patch 只能更新 `title`、`summary`、`layout_hints`、`display_options`，或 upsert/remove 节点、边、组、来源。应用前检查 `expected_spec_hash`；删除仍被引用的对象会失败。更新后对完整新 Spec 重新执行 Schema、语义和模板校验并生成新 hash；不允许 patch 模板脚本或关系注册表。

两个 profile 的基线不同：

- `diagram_authoring` 可以用 `artifact_uri` 或 `base_spec` 二选一定位明文基线。
- `approved_case_workspace` 不接受 `artifact_uri`。调用方必须提供 `case_id`、`work_product_id`、`expected_parent_version`、完整受限 `base_spec`、`expected_spec_hash`、当前 `source_approved_refs`、patch、状态和幂等键。服务先解密 protected parent，并把 `base_spec` 固定重渲染后与 parent HTML 逐字节比对，再应用 patch。

批准业务请求最大 256 KiB；render/update 产生的 HTML 最大 1 MiB，并且只作为 encrypted protected `text/html` work product 发布。export 只返回 signed manifest 绑定的 verified descriptor metadata，不返回 HTML、Spec、path、filename、URI 或 attachment。

## 兼容性

v1 读取器拒绝未知主版本。新增可选枚举或字段必须发布新 minor Schema 并显式协商；删除/改义字段或关系必须升级主版本。按 profile 收紧字段、来源绑定和大小上限不扩大基础契约，不允许客户端退回完整 Schema 绕过。旧 MapSpec 迁移默认状态为 `unknown`，来源无法映射时产生 warning，不推断法律确认状态；包含真实案件位置字段的旧 Spec 不能直接迁入批准 profile，必须从当前批准 publication 重新构造。
