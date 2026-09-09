---
name: lawyer-assistance
description: 通过五工具 public_law_only MCP 检索中国公开法律。只处理不含客户、案件或原始材料的公开法律问题。
---

# Lawyer Assistance

仅用于公开法律检索。不得把案件原文、客户信息、文件、路径、映射、令牌或私有工作区数据交给宿主或工具。

确认 `tools/list` 精确列出五项公开工具：`system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations`。先检查状态，再核对效力日期、版本和条文来源。明确法律库缺口，不把检索结果表述为个案结论。

脱敏工作区是单独配置的 `privacy_workspace`，只读取后台发布的脱敏结果。
