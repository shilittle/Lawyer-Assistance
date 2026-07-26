# 安装与运行

## 生产基线

默认生产部署 `public_law_only`。启动后必须确认 `tools/list` 精确等于五项公开法律工具；出现第六项、案件工具或顺序漂移都停止使用。案件工作仅使用后文独立的 App-qualified approved stdio package，不能修改默认配置获得。

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

## `diagram_authoring` 状态

该 profile 永久只用于合成或公开材料的本地图示编写。它在公开五工具之外列出六个 `diagram.*` 工具，并生成明文 HTML bundle / 本地 artifact reference。不要为它提供 approved session，不要把真实、待复核或批准案件正文、来源引用或派生内容交给它。真实批准案件图示必须使用下节的 `approved_case_workspace`。

## `approved_case_workspace` 状态

独立集成资产已提供并默认禁用。approved MCP policy v2 是 breaking boundary：先停止旧 approved host，在 App 中撤销所有旧 standalone session，再完成材料人工批准/发布、approved MCP 资格，并按最小权限选择 `read`（8）、`write`（2）、`diagram_read`（4）和/或 `diagram_write`（2）创建新 session。旧 `read` / `write` 不会获得图示权限。只把显示的 `srv_…` ID 写入精确 Windows stdio 模板：

```text
lawyer-assistance-mcp --privacy-profile approved_case_workspace --approved-session-id <APP_ISSUED_SERVER_ID> stdio
```

只使用 formal App 随包发布的 paired MCP sibling。release 构建先测量该 sibling 并把 SHA-256 编译进 App；普通未绑定 development App、复制来的同名 executable、版本/canary 模仿或任意其他 binary 不能取得 qualification。不要添加 config、数据库/根/路径、环境、Bearer、bind/origin 或 HTTP 参数，也不要通过修改 `enabled`、用户同意或放宽 Skill 绕过资格。缺失或失效的 paired hash/qualification/session/ticket 必须 `PROFILE_NOT_QUALIFIED` 或具体匿名失败；有效状态执行真实 handler。核对精确 21 工具、四组 v2 grants、双通道残留扫描和三类宿主规则，详见[批准案件工作区 profile](approved-case-workspace.md)。

批准图示的 `diagram.render` / `diagram.update` 只发布加密 protected HTML work-product version；`diagram.export` 只返回 verified descriptor metadata，不返回 HTML、路径或 URI。若宿主尝试使用 `artifact_uri`、输出目录或 `diagram_authoring` 明文 bundle，立即停止。

宿主任务只能以 opaque ID 开始，不能附加/粘贴原件或提供真实路径。若原始材料已经进入任务，删除受污染任务并新建干净任务；不能在同一上下文继续。

旧版新建案件、材料导入、apply/get-state、文书生成或导出安装步骤已经失效；不得沿用旧配置重新开启。

## 本地 MinerU component

MinerU component 不随 Git 源码或普通 MCP ZIP 内置。历史候选组件永久禁止发布或改名
复用。最终 v4 必须从固定源码确定性重建、显式审批、签名、短根安装/remeasure 和
GPU probe 后，才可进入 App Firewall/Job qualification。

只能从项目官方 Release 下载完整 catalog、`.minisig`、descriptor 与全部 parts 后
本地导入；不得向 App/catalog 注入 GitHub token。必须验证 detached Minisign、每个
part 的 exact size/SHA-256 和 package/manifest/provenance hash，再通过 App
component manager 安装。final installed tree 中任何路径超过 259 UTF-16 code units
都会以 `component_runtime_path_too_long` fail closed。

组件安装或 direct-worker diagnostics 均不授权真实案件 OCR。在 App 后端全部生产
资格都变为当前有效之前，只能处理可靠原生文本层；扫描/视觉 PDF 必须阻断，不能转发
远程 OCR。

## 签名发布状态

正式签名发布要求外部 Authenticode 证书和 updater 私钥/密码；这些凭据不存储在仓库
中。缺少任一凭据时只能生成明确命名的 unsigned technical prerelease，不能冒充
trusted-publisher build，也不能发布 updater metadata。稳定流程见
[`docs/development/release-signing.md`](../development/release-signing.md)。
