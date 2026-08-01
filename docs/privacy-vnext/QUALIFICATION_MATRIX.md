# 脱敏系统 vNext 资格与验收矩阵

> 当前公开状态见 [`docs/release-status.md`](../release-status.md)。本文件冻结资格语义、
> 证据要求和未满足行为；任何能力只有精确当前环境证据仍有效时才是 `qualified`。

## 1. 状态定义

- `implemented`：代码和自动化测试存在。
- `enabled`：真实产品路径可达，仍可能只允许人工审批。
- `shadow`：真实计算发生，但自动决策不发布。
- `feature-flagged`：实现完整，默认关闭。
- `qualified`：绑定 exact 环境的证据矩阵达标且未过期/撤销。
- `blocked`：至少一个 hard gate 未通过，后端拒绝。
- `not-run`：测试需要当前环境不具备的硬件、凭据或人工条件。

发布说明必须逐项使用这些词，不得用“支持”混淆实现、启用和资格。

## 2. 历史基线（v0.3.1，非当前行为）

| 能力 | 当前状态 | 证据/限制 |
|---|---|---|
| 本地文本层 PDF/DOCX/TXT/MD 提取 | enabled | 非支持格式 fail closed |
| 确定性脱敏与人工逐页复核 | enabled | alias 仅单会话稳定，未形成 finding/cluster |
| DPAPI review blob | enabled | 不是原件 vault |
| HMAC v1 receipt、TTL/revoke、hash-only audit | enabled | 发布步骤尚非统一原子事务 |
| 安全文本重建 PDF | enabled | 不保留原版式/印章/签名外观 |
| 默认公开法律 MCP 五工具 | enabled | 精确五项，案件路径不可达 |
| 本地 MinerU CLI runner 基础 | implemented | App 未接入，隔离和 manifest trust 未 qualified |
| 真实扫描案件 OCR | blocked | `networkIsolationEnforced=false`；`modelManifestTrustEstablished=false` |
| 自动批准 | blocked | 无 calibration，hard gates 未完整 |
| Approved workspace/MCP | not implemented | 默认 fail closed |

### 2.1 beta.2 当前实现覆盖

| 能力 | 当前实现状态 | 仍需最终验收 |
|---|---|---|
| 本地 MinerU OCR 与资格持久化 | `CODE_COMPLETE` | 历史 v3/v5 candidate 仅保留诊断证据并永久禁止发布；v4 provenance 源码门禁及 27/27 builder tests 已完成，但尚无 final v4 artifact/hash；最终 clean source commit 后仍须确定性重建、显式审批、签名、短根安装、remeasure、GPU probe、firewall/trust/canary/restart/App E2E |
| Approved MCP 十工具与 App ticket/session | `E2E_COMPLETE` | 实际 sibling binary stdio/HTTP 与 compile-time SHA-256 trust anchor 已测；最终合并后对 release-candidate 二进制复跑并记录 artifact hash |
| Approved Provider 正向链 | `E2E_COMPLETE` | 最终合并后复跑 loopback wire 与 network-zero negatives |
| PDF/DOCX/TXT/Markdown 安全派生、encrypted work products、mapping、lifecycle、five-component backup V3 | `CODE_COMPLETE` | 最终构建 App 的选择器、暂存、重启、五组件重开与回滚验收；V2 三组件只读/恢复兼容，V1 fail closed |
| WorkBuddy/Codex/OpenCode approved assets | `CODE_COMPLETE` | validator 复跑；闭源宿主 UI/账号只作为独立环境资格 |
| Windows/GitHub release | `PENDING_FINAL_ACCEPTANCE` | unsigned artifacts、安装/启动 smoke、最终 commit/tag/release；当前发布机缺少 Authenticode certificate/private key 与 updater key/password，最终 updater artifacts 还必须绑定精确 signed installer |

这些状态不能替代下表的资格证据；缺少 exact 环境证据时，生产后端仍 fail closed。
## 3. 资格矩阵

| 域 | 必须证据 | 自动化验收 | 人工/环境验收 | 未满足行为 |
|---|---|---|---|---|
| Vault crypto | CNG AES-256-GCM、随机 nonce、per-case key、DPAPI wrap、AAD | round-trip、篡改、截断、nonce、cross-case/object/version swap、key loss | Windows 支持版本验证 | import/read blocked |
| Vault layout | 本地固定盘、非 reparse/cloud/network、随机对象名、索引排除 | path escape、link/reparse、placeholder、权限回归 | DACL/索引状态检查 | vault blocked |
| Backup/restore | application backup V3 把 user DB、encrypted privacy bundle、ciphertext-only Vault archive、approved-workspace archive、encrypted work-products archive 作为五个独立 AAD/hash/manifest-bound 组件；staged restart transaction；V2 三组件只读/恢复兼容；V1 fail closed | tamper/traversal/hardlink/extra-file/component-or-manifest swap/V1 rejection、V2 compatibility、interruption、session/ticket/qualification invalidation 与五组件 rollback | synthetic App export/verify/stage/restart/open | restore blocked；all five components rollback |
| Service isolation | 独立服务身份与 DACL，或准确 user-boundary-only | 非授权进程读写矩阵 | Windows 服务 SID 检查 | strong profile blocked；可降级显示警告 |
| MinerU component | 签名/受信 key、exact file set/hash/size、final installed path ≤ 259 UTF-16 code units | 增删改文件、回滚、撤销、漂移、过长运行时路径 | 离线包来源审查 | OCR blocked |
| MinerU runtime | worker/Python/MinerU/PyTorch/CUDA/GPU/model/config exact tuple | hello/health/schema/hash/timeout/cancel/kill-tree | 指定 GPU 与驱动 | real OCR blocked |
| Network isolation | 绑定 worker 的 OS 控制与证据 hash | 网络请求 canary、DNS/loopback/代理逃逸 | 防火墙/沙箱状态 | real OCR blocked |
| OCR completeness | 页数/序、尺寸、旋转、page hash、blocks、coverage/confidence/visual risks | 丢页、乱序、越界、非法分数、未知视觉、空白页伪造 | 代表性扫描件目检 | document blocked |
| Finding engine | deterministic rules、字典、cluster、alias ledger、模型 provenance | 实体矩阵、Unicode/OCR 混淆、跨页/跨文档、冲突 | 法律语料抽样 | P0/P1 或 full review |
| Risk/hard gates | 后端唯一计算、政策 hash、17 gates | score 绕过、前端篡改、qualification/policy 漂移 | 政策签署 | automatic blocked |
| Residual scan | 与主检测独立的规则/版本 | canary、破损 placeholder、双通道差异 | 假阴性抽样 | publication/MCP/write blocked |
| Publisher | staging/fsync/rename/current/journal/recovery | 每个 crash point、半发布、TOCTOU、replay | 断电/重启演练 | generation quarantined |
| Manifest verifier | canonical claims、签名、content hash、epoch、scope | 字段重排/重复/未知、签名/正文替换、过期/撤销 | key 生命周期审查 | read blocked |
| MCP schema | public 五项不变；`diagram_authoring` 六项仅 synthetic/public 明文 bundle；approved 总计 21 项（public 5 + case 10 + diagram 6）；formal App 内置 paired MCP SHA-256 | exact tool sets、deny unknown、禁用字段、diagram profile 混用、fuzz、缺失/畸形/错 hash/same-name substitution | 宿主集成；最终 21-tool binary stdio/HTTP 复跑 | profile start/qualification blocked |
| MCP egress | content + structuredContent 独立扫描 | 两通道 canary、错误脱敏、日志扫描 | WorkBuddy 会话抽查 | call blocked |
| Approved session policy | v2；16 non-public grants：`read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`；旧 read/write 集合不扩展 | pre-v2 session、重复/未知 group、错 purpose、无 diagram grant、旧 descriptor/credential/replay reuse | revoke/recreate 与 least-privilege canary | session/call blocked |
| Work products | immutable、OCC、idempotency、source refs、scan；每版本 exact `content.envelope.json` + signed `manifest.json` + `commit.json`；fresh AES-256-GCM key/nonce、DPAPI CurrentUser wrap、完整 AAD；普通成果及 approved diagram HTML 均仅由 scoped `WorkProductService` 鉴权解密；diagram export 仅 metadata | plaintext/legacy `content.bin`、明文 approved diagram bundle、export path/URI/HTML、extra/missing file、tamper、cross-object/version swap、hardlink、overwrite/path escape/stale source/injection | 典型任务验收 | read/write/update/export blocked |
| Skills/host config | 正向来源与全套禁令跨宿主一致 | WorkBuddy/Codex/OpenCode validator | 新任务干净上下文检查 | 案件 skill blocked |
| Installer/update | 组件、策略、数据库迁移和回滚 | clean install/upgrade/rollback/uninstall | Authenticode/SmartScreen | release not qualified |

## 4. OCR 与材料测试集

只使用合成或公开无敏感 fixture，覆盖：

- 原生文本、纯扫描、混合页、横向/旋转、空白页、损坏 PDF、加密 PDF。
- 中文姓名/机构/地址/案号/证件/电话/银行卡/账号、Unicode 与 OCR 混淆。
- 印章、签名、手写、截图、复杂表格、页眉页脚、水印、跨页表格。
- 丢页、重复页、乱序、bbox/polygon 越界、置信度缺失、worker 输出注入。
- DOCX/TXT/Markdown，以及显式拒绝的不支持材料。

测试 fixture 禁止包含真实案件材料、真实身份数据、真实账号或生产密钥。

## 5. 自动批准校准门

automatic 默认关闭。开放前必须有离线、版本化、可重复的校准报告，至少包含分实体、分材料类型、分 OCR 质量的 precision/recall、P0/P1 漏检、confidence calibration、人工复核分歧和样本来源声明。

资格策略必须定义不可放宽的最低值；任一 exact detector/model/worker/policy/calibration 变化后自动批准重新回到 shadow。shadow 只能记录“若自动会如何路由”，实际批准仍由人完成。

## 6. 发布门

候选 release 必须同时满足：

1. Rust 全 workspace、前端 unit/integration、Python worker、MCP host validators 全绿。
2. 零明文日志/临时文件/CI artifact canary 泄漏。
3. clean install、upgrade、rollback、uninstall 和启动恢复通过。
4. 默认 profile 仍精确五项公开工具；新案件 profile 默认关闭。
5. 资格报告、资产 SHA-256、签名状态和所有 `not-run` 项在 release notes 明示。
6. 真实 GPU/OCR、付费 Provider、Authenticode、SmartScreen 等未运行项单列，不得计入普通回归。
7. 不覆盖或移动 v0.3.1 tag、Release 和资产；新版本使用新 tag 且先发布 prerelease。

## 7. 发布与机器资格边界

- 最终 MinerU v4 构件必须绑定固定源码、构建脚本、worker 源码树、runtime
  distributions 与 model revisions，并经过确定性重建、人工审批、签名、短路径安装、
  remeasure、GPU probe 和完整 App Firewall/Job/canary/restart 资格链。
- 历史候选构件和 direct-worker diagnostics 永久不能替代正式 v4 provenance 或当前
  机器资格。
- 只有 App 当前报告的 exact-machine evidence 可以使
  `networkIsolationEnforced`、`modelManifestTrustEstablished`、
  `appAutoEnableAuthorized` 与 `productionCaseOcrAuthorized` 成立。
- 组件安装、catalog 验签、synthetic E2E 或宿主权限不能解释为真实扫描案件 OCR 的
  生产授权，也不能启用自动审批。
- 默认 `public_law_only` 始终只有五个公开法律工具；`diagram_authoring` 的明文 bundle
  永久只处理 synthetic/public 数据；`approved_case_workspace` 的 21-tool 实现只在
  formal App paired-binary hash、当前 qualification、policy-v2 standalone session
  grant 与逐调用 ticket 全部匹配时执行。
