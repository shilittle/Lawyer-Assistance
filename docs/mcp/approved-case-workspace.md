# 批准案件工作区 profile

`approved_case_workspace` 是独立的资格门禁 profile，不改变默认 `public_law_only`。它公开现有五个公开法律工具和十个最小案件工作区工具，共 15 项。正式构建先把固定 sibling MCP 的 SHA-256 作为配对信任锚编译进同批 App；没有该信任锚的开发 App，或仅仿冒名称、版本和 canary 行为的替换程序，都不能取得资格。生产 handler、App 精确签票、持久化防重放和 standalone session 已实现；只有当前机器的 App 资格、批准 generation、session 和逐调用 ticket 全部有效时才执行。其他状态返回 `PROFILE_NOT_QUALIFIED` 或更具体的匿名错误；工具可发现、配置已启用或用户同意都不等于授权。

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

## 宿主信任契约

- 正文只能来自当前干净任务中刚完成的 `case_read_approved_material` 直接响应，且该响应本身携带 `CASE_REDACTED_APPROVED` 和精确匹配的 opaque ID。
- `case_list`、公开元数据、材料列表和搜索结果只用于定位 ID；标签、搜索片段、旧响应、附件、粘贴、宿主文件、路径或 memory 都不是批准证据。
- 遇到 `PROFILE_NOT_QUALIFIED`、撤销、过期、ID/签名/哈希/残留扫描失败时停止，不得降级到文件、浏览器、其他 MCP、其他 Skill、远程 OCR 或其他 Provider。
- 案件成果只能通过 `case_write_work_product` 或 `case_update_work_product` 写回，保持匿名占位符并绑定精确批准来源。manifest 导出不是宿主文件导出授权。
- 原件、OCR 中间结果、待复核内容、映射、真实文件名和路径不得进入宿主或 Provider。

如果原件、粘贴正文、附件或真实路径已经进入任务，宿主必须停止所有案件工具和派生处理，要求删除受污染任务/附件并新建仅含 opaque ID 的干净任务。Skill 不能撤回其加载前已经发生的披露，也不能替代后端校验、ACL、网络隔离和 Provider 治理。

## 集成与校验

三类宿主的独立、默认禁用资产位于：

- `integrations/workbuddy/skill/lawyer-assistance-approved-workspace`
- `integrations/codex/skill/lawyer-assistance-approved-workspace`
- `integrations/opencode/agents/lawyer-assistance-approved-workspace.md`

机器目录为 `integrations/tool-catalog.approved-case-workspace.json`。运行 `python integrations/validate_approved_workspace_examples.py` 校验批准 profile；继续单独运行 `python integrations/validate_examples.py` 校验 public-only 默认面，不能用前者替代后者。

App 操作顺序是：人工批准并发布 generation → 运行 approved MCP 资格 → 创建只显示 `srv_…` 的 standalone session → 在干净任务中按 opaque ID 读取 → write/update → 立即精确版本 reread → 撤销 session/generation。静态宿主只允许精确 Windows stdio 参数；HTTP acceptance 凭据留在 App broker，不分发到模板。详见 [`../privacy-vnext/OPERATIONS.md`](../privacy-vnext/OPERATIONS.md)。
