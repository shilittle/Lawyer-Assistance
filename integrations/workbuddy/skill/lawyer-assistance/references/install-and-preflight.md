# 连接器安装与预检

## 安装

- Windows/macOS/Linux stdio：选择 `assets/connectors` 中的平台示例，替换绝对路径。启动参数必须保留 `--privacy-profile public_law_only`。
- Streamable HTTP：使用 `http.bearer.json`，服务仅监听 `127.0.0.1`，令牌只从 `LAWYER_ASSISTANCE_MCP_TOKEN` 读取。生产网络入口必须由受控 TLS 反向代理提供。
- 不得在发布配置中加入 `--dangerously-allow-insecure-non-loopback-http`、`dangerously_allow_insecure_non_loopback_http` 或 `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`；这些危险开关不能替代 TLS。

## 每次任务的预检

1. 在读取用户内容前先判断任务是否可能包含案件、客户、附件或派生事实；若是，按 `RAW_DATA_ALREADY_DISCLOSED_TO_HOST` 停止且不调用工具。
2. 确认连接器只列出 `system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations`。列表不精确匹配就停用。
3. 调用 `system_status`，只在法律库 ready、schema 兼容且 profile 为 `public_law_only` 时继续。
4. 仅允许公开法律名称、公开条号、公开法域和公开研究日期进入工具参数。

`CASE_RAW`、`CASE_REDACTED_PENDING`、待复核内容、仅有 `CASE_REDACTED_APPROVED` 标签的内容，以及 App 产物本身都不能进入 WorkBuddy。当前 App→MCP citation receipt 正向链未实现，案件材料流程安全禁用。