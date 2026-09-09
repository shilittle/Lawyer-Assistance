# 贡献指南 / Contributing

Lawyer Assistance 的当前产品由 Rust server、纯 HTML WebUI 和 MCP 组成。贡献应围绕材料脱敏、法律检索、服务 API、MCP 契约和可验证的操作逻辑展开。

## 基本规则

- 只使用合成、公开且许可明确的数据；不得提交真实案件材料、客户信息、凭据、用户数据库、原始 OCR 内容或本机绝对路径。
- 不引入 Tauri、WebView2、前端开发服务器、安装器、updater 或 OCR 运行时。WebUI 必须继续通过 `include_str!` 嵌入 Rust server。
- `public_law_only` 始终只包含五个公开法律只读工具；`privacy_workspace` 只能返回后台已发布的脱敏状态或文本，不能扩展为原文、映射或路径读取。
- Provider、MCP 和导出边界由后端统一校验。前端不得直接访问 SQLite、调用 Provider API、保存 API key 或自行实现脱敏规则。
- 旧 Tauri 数据目录不迁移、不覆盖。测试用例应使用临时目录，不依赖 `%LOCALAPPDATA%\LawyerAssistanceWeb` 中的用户数据。
- 不提交 `target/`、`node_modules/`、`dist/`、release secret、生成的完整数据库或构建临时目录。

## 开发环境与检查

需要 Windows/MSVC Rust stable、Node.js `>=24`、pnpm `>=11` 和 Python 3：

```powershell
pnpm install
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
pnpm check
pnpm test
```

后端 release 构建：

```powershell
cargo build --release --locked -p lawyer-assistance-server --bin lawyer-assistance
cargo build --release --locked -p legal-mcp --bin lawyer-assistance-mcp
```

便携包脚本会校验两个二进制、运行时法律库大小/SHA-256/source manifest hash、许可证和 notices：

```powershell
python -m unittest scripts.test_package_portable -v
python scripts/package_portable.py --skip-build
```

涉及浏览器操作、API 契约、MCP 或脱敏边界的变更，应补充相应的 Node/Rust smoke test。测试可以验证合成数据的行为，不能把合成通过率表述为真实案件的召回率或误报率。

## 代码放置

- `apps/server`：CLI、loopback HTTP 路由、会话/CSRF 和静态 WebUI 嵌入。
- `apps/web`：无构建步骤的 HTML、CSS、JavaScript 和浏览器单元/smoke 测试。
- `crates/workspace-service`：工作区、任务、材料、脱敏版本、导出、Provider 会话和 MCP 私有后台业务。
- `crates/file-ingest`、`crates/privacy-text`：TXT/DOCX 提取、检测、替换、残留检查和导出。
- `crates/legal-services`、`crates/legal-mcp`：法律库查询与公共/隐私 MCP 契约。
- `data/runtime`：随便携包分发的只读法律库和许可证；`data/build` 保留为法律数据来源审计/构建工具，不在产品启动时写入用户目录。

## 提交与 PR

每个提交保持单一目的，说明用户可见行为、数据边界、运行命令和已运行检查。失败或未运行的验证必须明确写出。PR、Issue 和 CI 日志不得包含 secret、真实案件正文、原始路径或映射。

## English

The current product is a Rust server, a plain HTML WebUI, and MCP. Keep changes focused on redaction, legal research, service APIs, MCP contracts, and deterministic operations.

- Use only synthetic/public licensed data. Never commit real case material, credentials, user databases, raw OCR, or identifying absolute paths.
- Do not reintroduce Tauri, WebView2, a frontend dev server, installers, updaters, or an OCR runtime. The WebUI remains embedded in the Rust server.
- Keep `public_law_only` at exactly five read-only public-law tools. `privacy_workspace` may expose only published redaction status/text and never original text, mappings, or paths.
- The backend owns SQLite, Provider, and redaction boundaries. The frontend must not call Provider APIs or persist API keys.
- Never migrate or overwrite the old Tauri data directory. Use temporary synthetic workspaces in tests.

Run `cargo fmt`, workspace clippy/tests, `pnpm check`, `pnpm test`, and `python -m unittest scripts.test_package_portable -v` for relevant changes. List all commands and limitations in the PR.
