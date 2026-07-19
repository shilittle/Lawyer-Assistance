# 公开法律研究流程

1. 确认问题不含客户、案件、附件、路径、当事人或派生事实；否则立即停止。
2. 用 `system_status` 核对本地法律库和 `public_law_only` profile。
3. 把问题收敛为公开法律名称、法域、主题和公开基准日期。
4. 用 `legal_search` 找候选；用 `legal_get_versions` 核对日期对应版本；用 `legal_get_article` 读取条文；必要时用 `legal_get_relations` 查公开关联。
5. 交叉核对名称、条号和效力区间。数据库缺失目标版本时明确说明缺口，不猜测。
6. 只输出公开法律研究结论，并提醒其不是针对具体案件的法律意见。

必须停止：工具列表不是精确五项、profile 不是 `public_law_only`、法律库 degraded、日期或法域不足、问题含真实案件事实，或任何输入属于 `CASE_RAW`、`CASE_REDACTED_PENDING`、待复核/仅标签批准内容。

当前没有安全的 App→MCP citation receipt 正向链，因而没有案件导入、案件分析、个案引证核验、文书生成、写入或导出工作流。