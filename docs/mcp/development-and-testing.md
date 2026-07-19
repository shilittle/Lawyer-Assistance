# 开发与测试

## 代码边界

- `crates/legal-services`：共享法律服务和历史内部案件/文书实现。
- `crates/legal-mcp`：profile registry、adapter 二次拒绝、receipt gate、stdio/HTTP 和结果隐私扫描。
- `crates/privacy`：分类、脱敏、DPAPI、票据与本地审计。
- `crates/material-processing`：原生 PDF、实验本地 MinerU runner 和安全 PDF 重建。
- `integrations`：三类宿主的 public-only 五工具配置、Skill/Agent 和验证器。

共享服务里存在案件函数不构成 MCP API；测试必须证明它们从 registry 和 adapter 两层均不可达。

## 常用门禁

```text
cargo fmt --all -- --check
cargo clippy -p legal-mcp --all-targets -- -D warnings
cargo test -p legal-mcp
cargo test -p privacy -p material-processing -p providers -p file-ingest -p legal-services
python integrations/validate_examples.py
python -m unittest integrations.test_validate_examples
```

桌面端变更还运行其 Rust、TypeScript、Vitest 与 ESLint 门禁。

## 必测契约

1. 默认 profile 是 `public_law_only`，stdio/HTTP 只列出且只调用五个公开法律工具。
2. 五项名称、顺序、schema 和 annotations 与 integration catalog 精确一致。
3. public-only 对 `citation_validate`、所有案件工具和文书工具返回稳定拒绝，且不调用底层服务。
4. `redacted_case` 只增加 `citation_validate`；缺密钥、缺持久化状态、错误/撤销/过期/超 TTL/错用途/错目标/错请求字节/错 provenance 的票据全部 fail-closed。
5. 测试使用的合成签名器和票据不得进入发布配置；当前没有 App 正向签发成功验收。
6. `content` 与 `structuredContent` 均执行敏感残留扫描；日志、错误和快照不含案件 canary、Authorization、票据、密钥或绝对路径。
7. Provider 请求默认分类为 `CASE_RAW`；只有明确 `LEGAL_PUBLIC`/`PRODUCT_PUBLIC` 才能在序列化前通过。旧案件请求必须在发送前失败。
8. 带可靠文本层的 PDF 可原生处理；当 App 未提供本地 OCR runner 时，扫描/视觉 PDF 必须拒绝，不能回退 SSH、云 OCR 或网络。
9. 本地 MinerU runner 测试覆盖参数白名单、清空环境、禁远程、超时、取消和输出边界；这些单测不等于 App/GPU 端到端认证。
10. WorkBuddy/Codex/OpenCode 的第一操作性规则覆盖 `CASE_RAW`、待复核与仅标签 approved，并保留“pre-Skill 披露无法阻止或撤回”的说明。

## 人工宿主验收

只使用无客户数据的公开法律查询：连接、核对精确五工具、`system_status`、法律检索、版本、条文和关系。再验证额外/案件工具不可见，宿主通配权限不放行，错误不泄露内部字段。

不要把真实或“已脱敏”的案件文件用于截图。若要验证 pre-Skill 风险，仅使用明确合成 canary，并按宿主数据保留政策清理。

历史 WorkBuddy 12/12 工具和案件提案验收记录仍可作为当时行为证据，但已被隐私收紧取代，不能作为当前功能验收或回归期望。