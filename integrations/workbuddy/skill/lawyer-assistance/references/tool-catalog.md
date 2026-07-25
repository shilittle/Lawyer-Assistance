# 工具目录

`public_law_only` 只允许以下五个工具，顺序必须与 MCP `tools/list` 一致。它们全部为只读、幂等、封闭世界工具：`readOnlyHint: true`、`destructiveHint: false`、`idempotentHint: true`、`openWorldHint: false`。

| 工具 | 用途 |
|---|---|
| `system_status` | 检查本地公开法律库、schema 和 profile 状态 |
| `legal_search` | 按公开关键词、法域和日期检索法律 |
| `legal_get_article` | 读取指定公开法律版本的具体条文 |
| `legal_get_versions` | 查询公开法律的版本和生效区间 |
| `legal_get_relations` | 查询公开条文之间的引用、替代和关联关系 |

所有调用都显式传入 `schema_version: 1`。历史检索日期字段为 `case_date`（`YYYY-MM-DD`）；这里只能填写公开研究基准日期，不能填写从真实案件材料得出的日期。

本 public-only 连接器的工具列表出现任何额外项时立即停用。案件材料、案件状态、个案引证、写入和导出能力在此 package 刻意不可用；独立 approved package 使用另一个精确 21 工具 catalog 和 App-issued session。不得借助附件、粘贴、宿主文件、命令、网络、其他 MCP/Skill、memory 或 subagent 重建或桥接流程。
