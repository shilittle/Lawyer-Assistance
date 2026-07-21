# DiagramSpec v1 数据契约

本文件与 `crates/diagrams/schema/diagram-spec-v1.schema.json`、Rust 类型和模板注册表共同构成冻结契约。发生冲突时以通过测试的机器 Schema 与 Rust 枚举为准，文档必须在同一提交同步修正。

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

## 来源

必填：`id`、`kind`、`title`、`locator`、`verification_status`。可选：`artifact_id`、`uri`、`file_name`、`page`、`paragraph`、`table`、`attachment`、`law_document`、`law_version`、`article`、`quote`、`content_hash`。

`kind`：`file`、`file_page`、`paragraph`、`table`、`attachment`、`law`、`case_record`、`artifact`、`uri`、`model_analysis`、`human_input`。`verification_status`：`original_material`、`model_extracted`、`model_analyzed`、`database_verified`、`human_confirmed`、`unverified`。

文件来源至少提供 `artifact_id` 或 `file_name`，并提供页/段/表/附件之一或明确 `locator`。法律来源必须提供 `law_document`、`law_version`、`article`（适用时）和官方 `uri` 或内部 `artifact_id`。URI 只展示，不自动访问。

## 布局与显示

`layout_hints` 只允许：`direction`（`top_down`/`left_right`/`radial`/`timeline`）、`preferred_root_ids`、`group_by`、`max_initial_nodes`、`timeline_lane`。不得提交坐标、样式或脚本。

`display_options` 只允许：`theme`（`light`/`dark`/`auto`）、`show_legend`、`show_sources`、`hide_weak_edges`、`collapse_low_importance`、`print_page_size`（`a4_landscape`/`a4_portrait`）。

## provenance

必填：`generated_by`、`generated_at`（RFC 3339）、`diagram_spec_version`（`1.0`）、`template_version`（`1.0.0`）、`source_file_ids`、`human_confirmed`、`model_content_scope`、`deterministic_content_scope`。可选：`parent_spec_hash`、`change_summary`。

`generated_by`：`workbuddy`、`codex`、`local_model`、`human`、`importer`。`model_content_scope` 必须说明模型只负责提取/分析数据；`deterministic_content_scope` 必须说明 HTML/CSS/JS/布局来自 MCP 固定模板。

## 局部更新

patch 只能更新 `title`、`summary`、`layout_hints`、`display_options`，或 upsert/remove 节点、边、组、来源。应用前检查 `expected_spec_hash`；删除仍被引用的对象会失败。更新后对完整新 Spec 重新执行 Schema、语义和模板校验并生成新 hash；不允许 patch 模板脚本或关系注册表。

## 兼容性

v1 读取器拒绝未知主版本。新增可选枚举或字段必须发布新 minor Schema 并显式协商；删除/改义字段或关系必须升级主版本。旧 MapSpec 迁移默认状态为 `unknown`，来源无法映射时产生 warning，不推断法律确认状态。
