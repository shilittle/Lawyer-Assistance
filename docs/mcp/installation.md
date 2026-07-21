# 安装与运行

## 生产基线

生产只部署 `public_law_only`。启动后必须确认 `tools/list` 精确等于五项公开法律工具；出现第六项、案件工具或顺序漂移都停止使用。

发布包不携带法律库、用户库、客户材料、导出文件或令牌。先准备兼容的 `legal_core.sqlite`，再显式创建/迁移固定名 `user.sqlite`：

```text
lawyer-assistance-mcp --user-db /absolute/path/user.sqlite init-user-db
```

`stdio` 和 `serve` 不隐式创建或迁移用户库。

## 最小配置

即使 public-only 不读取案件材料，当前运行配置仍要求用户库、允许根和输出根。使用专用空目录，不要把客户案件目录、主目录或磁盘根授予服务：

```toml
legal_db = "/srv/lawyer-assistance/data/legal_core.sqlite"
user_db = "/srv/lawyer-assistance/data/user.sqlite"
allowed_roots = ["/srv/lawyer-assistance/disabled-input"]
output_root = "/srv/lawyer-assistance/disabled-output"
privacy_profile = "public_law_only"
bind = "127.0.0.1:8787"
bearer_env = "LAWYER_ASSISTANCE_MCP_TOKEN"
allowed_origins = []
allowed_hosts = ["127.0.0.1:8787", "localhost:8787"]
```

这些路径参数不授权案件读取、导入或导出；对应工具在当前 profile 中不存在。

## stdio

```text
lawyer-assistance-mcp --config /absolute/path/server.toml --privacy-profile public_law_only stdio
```

stdout 只承载 MCP 帧，诊断写 stderr。宿主配置还应设置精确五工具白名单；OpenCode 的通配权限保持 `deny`。

## Streamable HTTP

```text
lawyer-assistance-mcp --config /absolute/path/server.toml --privacy-profile public_law_only serve --bind 127.0.0.1:8787
```

客户端连接 `http://127.0.0.1:8787/mcp`，Bearer 从 `LAWYER_ASSISTANCE_MCP_TOKEN` 或受限令牌文件读取。默认拒绝非 loopback 明文监听，即使已配置 Bearer。生产跨机入口由同机受控 TLS 反向代理提供，并实施 Host/Origin 和网络限制。

不得在发布配置中启用 `--dangerously-allow-insecure-non-loopback-http`、`dangerously_allow_insecure_non_loopback_http` 或 `LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP`。

## 环境变量

关键变量包括：

- `LAWYER_ASSISTANCE_LEGAL_DB`
- `LAWYER_ASSISTANCE_USER_DB`
- `LAWYER_ASSISTANCE_ALLOWED_ROOTS`
- `LAWYER_ASSISTANCE_OUTPUT_ROOT`
- `LAWYER_ASSISTANCE_MCP_PRIVACY_PROFILE=public_law_only`
- `LAWYER_ASSISTANCE_MCP_TOKEN`
- `LAWYER_ASSISTANCE_MCP_BIND`
- `LAWYER_ASSISTANCE_MCP_ALLOWED_ORIGINS`
- `LAWYER_ASSISTANCE_MCP_ALLOWED_HOSTS`

CLI、环境和配置文件存在优先级时，最终解析结果仍必须是 `public_law_only`。

## 宿主预检

1. 在附加或粘贴任何材料前安装 Skill/Agent 规则；这不能召回已经发送给宿主的内容。
2. 连接本地 MCP，核对精确五工具。
3. 调用 `system_status`，只在法律库与 schema `ready` 时继续。
4. 只提交公开法律名称、条号、法域和公开研究日期。
5. 若任务包含案件、客户、附件、路径或派生事实，停止且不调用工具。

仓库集成示例位于 `integrations/workbuddy`、`integrations/codex` 和 `integrations/opencode`。HTTP 示例要求服务端同样显式使用 public-only；客户端白名单不能替代服务端 profile。

## `redacted_case` 状态

不要在生产启用。虽然服务端实验 profile 能列出 receipt-gated `citation_validate`，当前 App 不能签发绑定该 MCP 用途的票据，正常调用必然 fail-closed。测试签名器和合成票据只证明拒绝/验证协议，不是部署凭据。

## `approved_case_workspace` 状态

独立集成资产已提供，但当前默认禁用，案件执行必须返回 `PROFILE_NOT_QUALIFIED`。不要通过修改客户端 `enabled`、用户同意或放宽 Skill 绕过资格。完成 App 所列隔离、manifest 信任、模型与 Provider 资格后，仍需核对精确 15 工具、双通道残留扫描和三类宿主规则，详见[批准案件工作区 profile](approved-case-workspace.md)。

宿主任务只能以 opaque ID 开始，不能附加/粘贴原件或提供真实路径。若原始材料已经进入任务，删除受污染任务并新建干净任务；不能在同一上下文继续。

旧版新建案件、材料导入、apply/get-state、文书生成或导出安装步骤已经失效；不得沿用旧配置重新开启。