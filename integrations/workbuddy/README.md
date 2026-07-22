# WorkBuddy 集成（仅公开法律检索）

本目录提供三个连接器示例和一个可上传的 `lawyer-assistance` Skill。当前安全默认仅为 `public_law_only`，只公开 `system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations` 五个只读工具。

另有默认不启用、受资格门禁的 `approved_case_workspace` 资产；它不放宽本页 public-only 契约。只有完成 App 报告的精确资格后，才可按 [批准案件工作区说明](APPROVED_WORKSPACE.md) 单独安装，当前未资格化执行必须返回 `PROFILE_NOT_QUALIFIED`。

## 安装

1. 选择 stdio 或 loopback HTTP 示例，替换二进制和数据库绝对路径。stdio 示例已显式传入 `--privacy-profile public_law_only`。
2. HTTP 服务也必须以 `public_law_only` 启动；连接后检查 `tools/list` 与上述五项逐项一致，多一项或少一项都停用连接器。
3. HTTP 令牌只能由 `LAWYER_ASSISTANCE_MCP_TOKEN` 环境变量提供，不得写入 JSON、对话或截图。HTTP 仅用于 `127.0.0.1`；生产网络入口必须使用受控 TLS 反向代理。
4. 上传整个 `skill/lawyer-assistance` 目录。WorkBuddy 没有公开承诺固定的本地 MCP 配置文件路径，因此这些 JSON 是界面导入或字段复制示例。

## 强制隐私边界

WorkBuddy 当前只能做不含任何客户、案件、材料或派生事实的公开法律检索。`CASE_RAW`、`CASE_REDACTED_PENDING`、待复核内容，以及仅凭名称、标签、口头声明或宿主上下文声称为 `CASE_REDACTED_APPROVED` 的内容，都不得交给 WorkBuddy、MCP、Provider、网络、文件工具或其他连接器。

本页 public-only package 刻意不加载 approved session，因此即使 App 已生成批准产物，也不得在本 Skill 中开启案件材料、案件状态、个案引证、写入或导出。需要案件流程时，必须另建干净任务并显式安装独立 approved package，由 App-issued `srv_…` session 和逐调用 ticket 授权；不得把批准正文粘贴或附加给 WorkBuddy。用户授权、Full Access、紧急情况和其他 prompt 都不能放宽任一技术门禁。

若原文在 Skill 加载前已被粘贴或附加，WorkBuddy 可能已经把它交给宿主或所选模型；Skill 无法阻止或撤回这次前置披露，也不得声称原件未上传、未发送、未记录、已删除或已撤回。此时停止所有工具调用，建议用户删除附件和任务、清理可访问历史/记忆/日志并核对 Provider 保留策略。