# 开发与测试

## 代码边界

- `crates/legal-services`：共享法律服务和历史内部案件/文书实现。
- `crates/legal-mcp`：profile registry、adapter 二次拒绝、receipt gate、stdio/HTTP 和结果隐私扫描。
- `crates/privacy`：分类、脱敏、DPAPI、票据与本地审计。
- `crates/material-processing`：原生 PDF、受资格门禁的本地 MinerU runner/进程隔离，以及安全 PDF/DOCX/TXT/Markdown 重建。
- `integrations`：三类宿主的 public-only 默认资产及独立、默认禁用的 approved-case-workspace 配置、Skill/Agent 和 validator。

共享服务里存在案件函数不构成 MCP API；测试必须证明它们从 registry 和 adapter 两层均不可达。

## 常用门禁

```text
cargo fmt --all -- --check
cargo clippy -p legal-mcp --all-targets -- -D warnings
cargo test -p legal-mcp
cargo test -p privacy -p material-processing -p providers -p file-ingest -p legal-services
cargo test --locked --offline -p lawyer-assistance-desktop mineru_components
python integrations/validate_examples.py
python integrations/validate_approved_workspace_examples.py
python -m unittest integrations.test_validate_examples
python -m unittest integrations.test_validate_approved_workspace_examples
```

桌面端变更还运行其 Rust、TypeScript、Vitest 与 ESLint 门禁。

## 必测契约

1. 默认 profile 是 `public_law_only`，stdio/HTTP 只列出且只调用五个公开法律工具。
2. 五项名称、顺序、schema 和 annotations 与 integration catalog 精确一致。
3. public-only 对 `citation_validate`、所有案件工具和文书工具返回稳定拒绝，且不调用底层服务。
4. `redacted_case` 只增加 `citation_validate`；缺密钥、缺持久化状态、错误/撤销/过期/超 TTL/错用途/错目标/错请求字节/错 provenance 的票据全部 fail-closed。
5. `redacted_case/citation_validate` 的测试签名器和票据不得进入发布配置；approved workspace 必须改用 App 生产签发、DPAPI/Credential Manager session 和实际 binary wire E2E。
6. `content` 与 `structuredContent` 均执行敏感残留扫描；日志、错误和快照不含案件 canary、Authorization、票据、密钥或绝对路径。
7. Provider 公开路径默认把案件请求分类为 `CASE_RAW`；旧案件请求必须在发送前失败且请求数为零。独立 approved 类型必须从后端保护状态恢复、精确绑定并经真实 loopback HTTP 正向测试；前端或裸 `ChatRequest` 不能伪造。
8. 带可靠文本层的 PDF 可原生处理；`auto_local`/`force_local` 仅在完整签名资格有效时提供本地 OCR runner。缺失/漂移时扫描/视觉 PDF 必须拒绝，不能回退 SSH、云 OCR、下载或网络。
9. 本地 MinerU 测试覆盖参数白名单、受控环境、进程树/网络隔离、预后身份、模型全集、超时/取消、页/输出边界、signed sharded package exact hashes 与 final installed path 的 259 UTF-16 gate；单测、component install/re-measure、direct GPU diagnostic 与最终 App/Firewall/Job production E2E 必须分开记录。
10. WorkBuddy/Codex/OpenCode 的第一操作性规则覆盖 `CASE_RAW`、待复核与仅标签 approved，并保留“pre-Skill 披露无法阻止或撤回”的说明。
11. `approved_case_workspace` 精确列出 21 项（公开 5 + 案件 10 + 图示 6）；未资格化调用返回 `PROFILE_NOT_QUALIFIED` 且不回显参数；formal build 必须先测量 paired MCP sibling 并把 SHA-256 编译进 App，缺失/畸形/错 hash/same-name substitution 必须 fail closed；集成后的 actual binary stdio/HTTP 必须完成 case 与 diagram 的正负向 E2E。
12. policy v2 session grants 必须精确为 `read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`；验证旧 read/write 未新增工具、旧 session 被拒绝且必须重建、无对应 diagram grant 时不创建任何 work product。
13. `diagram_authoring` 仅用合成/公开 fixture 验证明文 bundle；approved diagram render/update 必须发布加密 protected HTML，export 只返回 descriptor metadata，schema/响应/错误均不得出现 path、URI 或 HTML，来源撤销后 update/export fail closed。
14. 三类 approved 宿主副本只信当前 approved read 直接响应，搜索/列表只导航 ID，成果只经 case write/update 或 approved diagram render/update 写回，并显式禁止附件/粘贴/宿主文件/浏览器/远程 OCR/其他 MCP 或 Skill/memory/subagent/未批准 Provider。
15. public-only 与 approved validator 独立运行；新增 profile 不改变默认五项及其宿主白名单。

## 人工宿主验收

public-only 验收只使用公开法律查询：连接、核对精确五工具、`system_status`、法律检索、版本、条文和关系。approved 验收另建干净任务，只用合成 opaque ID，核对 21 工具和四组 v2 grants，完成 direct approved read、case write/update、diagram validate/render/update/export、exact-version reread、revoke/replay 失败；断言 protected diagram work product 已加密且 export 无 path/URI/HTML。任何证据都不得泄露正文、路径、session secret 或 ticket。较早的 15-tool actual-binary 证据保留为历史 baseline，但不能替代集成后 21-tool binary 的 stdio/HTTP 复跑。

不要把真实或“已脱敏”的案件文件用于截图。若要验证 pre-Skill 风险，仅使用明确合成 canary，并按宿主数据保留政策清理。

历史 WorkBuddy 12/12 工具和案件提案验收记录仍可作为当时行为证据，但已被隐私收紧取代，不能作为当前功能验收或回归期望。

## 2026-07-22 machine-test ledger boundary

- historical signed self-contained v3 and short-root v5 candidates are permanently excluded from publication; their install/signature results remain diagnostic evidence only;
- direct MinerU 3.4.3/RTX 5090 diagnostics: synthetic two-page, low-resolution and rotated inputs succeeded; unreadable handwriting returned `output_incomplete`;
- long final runtime root failed while identical historical bytes under a short root succeeded; the 259 UTF-16 preflight gate is covered by unit tests;
- the historical installed-tree diagnostic passed, but is neither v4 evidence nor App Firewall/Job qualification;
- v4 provenance source gates and the two builder suites pass 27/27; no final v4 bytes/hash exist before a deterministic rebuild from the final clean source commit, explicit approval, signing, short-root install/remeasure and GPU probe;
- two UAC elevation attempts were cancelled, so Firewall/Job/App production OCR was not qualified and all four machine gates remain `false`.
- because the repository is private, eventual v4 assets require authenticated GitHub download followed by local App import unless the runtime already has private-Release access.

