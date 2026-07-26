# 批准案件工作区 profile

`approved_case_workspace` 是独立的资格门禁 profile，不改变默认 `public_law_only`。它的 `tools/list` 精确包含现有五个公开法律工具、十个最小案件工作区工具和六个批准案件图示工具，共 21 项。正式构建先把固定 sibling MCP 的 SHA-256 作为配对信任锚编译进同批 App；没有该信任锚的开发 App，或仅仿冒名称、版本和 canary 行为的替换程序，都不能取得资格。生产 handler、App 精确签票、持久化防重放和 standalone session 已实现；只有当前机器的 App 资格、批准 generation、session grant 和逐调用 ticket 全部有效时才执行。其他状态返回 `PROFILE_NOT_QUALIFIED` 或更具体的匿名错误；工具可发现、配置已启用或用户同意都不等于授权。

## 十个案件工具

1. `case_list`
2. `case_get_public_metadata`
3. `case_list_approved_materials`
4. `case_read_approved_material`
5. `case_search_approved_materials`
6. `case_list_work_products`
7. `case_read_work_product`
8. `case_write_work_product`
9. `case_update_work_product`
10. `case_export_work_product_manifest`

这些工具不恢复旧的 `case_get_state`、patch、任意材料导入、文书生成或路径导出接口。案件 schema 只接受严格的 opaque ID、版本、游标、任务类型、批准来源引用、幂等键和脱敏正文，不接受绝对/相对路径、文件名、URI、目录、glob、命令、shell 或自由元数据。

## 六个批准案件图示工具

1. `diagram.list_templates`
2. `diagram.get_schema`
3. `diagram.validate`
4. `diagram.render`
5. `diagram.update`
6. `diagram.export`

真实批准案件图示只能走本 profile。approved Spec/patch 使用闭合 schema 和 metadata allowlist，所有输入字符串都拒绝 URI、盘符、UNC、绝对/相对/遍历路径和文件名编码；source、provenance 与实际引用必须和请求 envelope 精确闭合。`diagram.render` 和 `diagram.update` 只把确定性 HTML 发布为加密 protected work-product version，并在 manifest 中绑定 canonical Spec SHA-256；update 同时核对 parent manifest Spec hash、调用方 base Spec hash、parent HTML、版本和来源血缘。正文不会作为明文 bundle 落盘或返回宿主；`diagram.export` 只返回与签名 manifest 绑定的 descriptor metadata，不返回 HTML、路径或 URI。

独立 `diagram_authoring` profile 永久只允许合成或公开数据。它生成的本地 HTML bundle 是明文，并使用本地 artifact reference；不得把该 profile、其 `artifact_uri` 契约或其输出目录用于真实、待复核或已批准案件材料。

## Policy v2 与 session grants

policy v2 把 16 个非公开工具分为四个显式 grant group：

- `read`：原有八个案件只读工具。
- `write`：原有两个案件写入/更新工具。
- `diagram_read`：`diagram.list_templates`、`diagram.get_schema`、`diagram.validate`、`diagram.export`。
- `diagram_write`：`diagram.render`、`diagram.update`。

五个公开法律工具不计入这 16 个 session grants。旧 `read` / `write` 的精确集合保持不变，不会因为升级而静默获得任何图示能力：没有 `diagram_read` 时，通用 metadata/list/read/manifest-export 会过滤或拒绝 `legal_diagram`，通用 write/update 也不能创建或改写图示。所有 policy v2 之前创建的 standalone session 都必须在 App 中撤销并重新创建；旧 descriptor、credential 或 replay journal 不能迁移成 v2 权限。

## 宿主信任契约

- 正文只能来自当前干净任务中刚完成的 `case_read_approved_material` 直接响应，且该响应本身携带 `CASE_REDACTED_APPROVED` 和精确匹配的 opaque ID。
- `case_list`、公开元数据、材料列表和搜索结果只用于定位 ID；标签、搜索片段、旧响应、附件、粘贴、宿主文件、路径或 memory 都不是批准证据。
- 遇到 `PROFILE_NOT_QUALIFIED`、撤销、过期、ID/签名/哈希/残留扫描失败时停止，不得降级到文件、浏览器、其他 MCP、其他 Skill、远程 OCR 或其他 Provider。
- 案件成果只能通过 `case_write_work_product`、`case_update_work_product` 或批准图示的 `diagram.render` / `diagram.update` 写回，保持匿名占位符并绑定精确批准来源。两种 export 都只返回描述信息，不是宿主文件、路径或正文导出授权。
- 原件、OCR 中间结果、待复核内容、映射、真实文件名和路径不得进入宿主或 Provider。

如果原件、粘贴正文、附件或真实路径已经进入任务，宿主必须停止所有案件工具和派生处理，要求删除受污染任务/附件并新建仅含 opaque ID 的干净任务。Skill 不能撤回其加载前已经发生的披露，也不能替代后端校验、ACL、网络隔离和 Provider 治理。

## 集成与校验

三类宿主的独立、默认禁用资产位于：

- `integrations/workbuddy/skill/lawyer-assistance-approved-workspace`
- `integrations/codex/skill/lawyer-assistance-approved-workspace`
- `integrations/opencode/agents/lawyer-assistance-approved-workspace.md`

机器目录为 `integrations/tool-catalog.approved-case-workspace.json`，必须精确列出 21 项。运行 `python integrations/validate_approved_workspace_examples.py` 校验批准 profile；继续单独运行 `python integrations/validate_examples.py` 校验 public-only 默认面，不能用前者替代后者。

App 操作顺序是：人工批准并发布 generation → 运行 approved MCP 资格 → 选择最小
policy-v2 grant groups 并创建只显示 `srv_…` 的 standalone session → 在干净任务中按
opaque ID 读取 → case write/update 或 approved diagram render/update → 立即精确版本
reread → 撤销 session/generation。静态宿主只允许精确 Windows stdio 参数；HTTP
acceptance 凭据留在 App broker，不分发到模板。集成后的 21-tool debug sibling 已完成
stdio/HTTP 合成 E2E；每个正式 release sibling 仍须重新测量并复跑。详见
[`../privacy-vnext/OPERATIONS.md`](../privacy-vnext/OPERATIONS.md)。
