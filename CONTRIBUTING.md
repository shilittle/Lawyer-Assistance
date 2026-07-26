# 贡献指南 / Contributing

感谢参与 Lawyer Assistance。提交代码或文档前，请先阅读
[`docs/security-and-privacy.md`](docs/security-and-privacy.md)。

## 基本规则

- 只使用合成、公开且许可明确的数据。不要提交真实案件、客户材料、凭据、本机数据库、
  OCR 中间产物或绝对个人路径。
- 保持默认 `public_law_only` 精确为五个公开法律只读工具。
- 不得通过文档、prompt、Skill、宿主权限或测试开关绕过 App qualification、批准
  generation、session grant、逐调用 ticket、来源撤销和 residual scan。
- 功能性 WorkBuddy、Codex、OpenCode 集成属于产品接口；新增或修改工具时必须同步
  validators、catalog 和安全说明。
- 不要提交生成数据库、`target/`、`node_modules/`、release secrets 或构建临时目录。

## 开发环境

- Windows + MSVC Rust toolchain
- Node.js `>=24`
- pnpm `>=11`（项目锁定 `pnpm@11.7.0`）
- Python 3

```powershell
pnpm install
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features --offline -- -D warnings
cargo test --locked --workspace --offline
pnpm lint
pnpm test
pnpm build
```

涉及 MCP、隐私或打包的变更还应运行对应 validators、真实 sibling 合成 E2E 和资源
校验。不得用真实 Provider 计费调用替代本地自动测试。

## 提交与 PR

- 每个提交保持单一目的，说明用户影响和安全边界。
- PR 应列出已运行的测试、已知限制和未运行原因。
- 不要在 PR、Issue 或 CI 日志中粘贴 secret 或真实案件内容。

## English

Use only synthetic, public, properly licensed data. Never commit real case
material, credentials, local databases, OCR intermediates, or identifying
absolute paths. Preserve the five-tool `public_law_only` default and all
qualification, approval, session, ticket, revocation, and residual-scan gates.

Keep changes focused, list the checks you ran, and state known limitations.
Functional WorkBuddy, Codex, and OpenCode integrations are product interfaces;
tool changes must update their validators, catalogs, and security guidance.
