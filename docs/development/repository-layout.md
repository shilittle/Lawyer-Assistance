# 仓库结构与运行边界

当前仓库的产品入口是 Rust server + 纯 HTML WebUI + MCP。不要把已删除的 Tauri 桌面层或前端开发服务器重新作为运行时依赖。

```text
apps/
  server/                 # lawyer-assistance CLI、HTTP 路由、嵌入 WebUI
  web/                    # index.html、app.js、api.js、styles.css、Node tests
crates/
  workspace-service/     # 工作区、任务、材料、结果、导出、Provider、MCP backend
  file-ingest/           # TXT/DOCX 检测与提取
  privacy-text/          # 识别、替换、残留检查和文本导出
  legal-services/        # 只读法律库查询
  legal-mcp/             # public_law_only/privacy_workspace MCP transport
  domain/ providers/ ... # 共享领域类型和模型适配
data/
  runtime/               # 随便携包分发的只读 legal_core.sqlite、许可证和 notices
  sources/ schema/ build/ # 法律数据来源、结构和构建/审计工具
scripts/
  package_portable.py    # Windows unsigned portable ZIP
  test_package_portable.py
docs/mcp/                # MCP 契约（独立文档）
```

## Server

`apps/server/src/main.rs` 的 `lawyer-assistance` CLI 支持 `serve` 和 `login`。服务只绑定 `127.0.0.1`，默认端口 `8877`，默认数据目录 `%LOCALAPPDATA%\LawyerAssistanceWeb`。启动器传入绝对的 `--legal-db`，也可显式传入 `--data-dir`。`login` 只读取服务保存的本机连接描述并重新打开浏览器。

`apps/server/src/lib.rs` 暴露 HTTP API、会话、CSRF、Host/Origin 检查、静态 WebUI 和 MCP 私有代理。业务写入集中在 `crates/workspace-service`，HTTP handler 不直接操作 SQLite 文件。

## WebUI

`apps/web` 不使用 React、Tauri、bundler 或开发服务器。Rust server 通过 `include_str!` 嵌入四个静态文件；浏览器只调用 `/api/v1`。前端不得读取 SQLite、调用 Provider、保存凭据或实现脱敏安全规则。

## 数据和发布

便携打包只复制两个 release exe、`data/runtime` 运行时资源、README 和 `Lawyer-Assistance.vbs`。打包前核对 `data/generated/legal_core_distribution_manifest.json`。不复制工作区、用户数据库、密钥、`target` 之外的构建缓存或旧桌面资源。

当前发布路径不包含 Tauri、安装器、签名/updater 或 OCR 运行时。旧桌面目录如果仍出现在历史 Git 对象中，不代表它属于当前产品入口。

## 测试

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
pnpm check
pnpm test
python -m unittest scripts.test_package_portable -v
```

所有测试只使用合成数据和临时目录。真实案件、Provider key、用户数据库和 `data/runtime/legal_core.sqlite` 的用户副本不得进入测试输出或日志。

## English

The product entrypoint is a Rust server, a plain embedded WebUI, and MCP. `apps/server` owns the `lawyer-assistance` CLI and HTTP routes; `apps/web` contains static HTML/CSS/JavaScript; `crates/workspace-service` owns business writes; `crates/file-ingest` and `crates/privacy-text` implement extraction/redaction; `crates/legal-services` reads the legal database; and `crates/legal-mcp` exposes public/privacy MCP transports.

The server binds loopback, defaults to port `8877` and `%LOCALAPPDATA%\LawyerAssistanceWeb`, and embeds the WebUI with `include_str!`. The portable package copies only the two release executables, `data/runtime` resources, README files, and a hidden-window VBS launcher. It does not contain a user workspace, credentials, installer, updater, Tauri runtime, or OCR runtime.
