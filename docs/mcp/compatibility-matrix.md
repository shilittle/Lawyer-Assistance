# 兼容性矩阵

## 当前契约

| 项目 | 当前值 | 漂移行为 |
|---|---|---|
| MCP 协议元数据 | `2025-11-25` | 初始化或宿主协商失败，不静默降级 |
| 服务 schema | `1` | `unsupported_schema_version` |
| 法律归档 schema | `4` | 拒绝不兼容法律库 |
| 法律运行时 schema | `1`（存在该元数据时） | 拒绝不兼容法律库 |
| 用户库 schema | `10` | 新版本拒绝降级打开；旧版本只走显式迁移 |
| 默认生产 profile | `public_law_only` | 非精确匹配停止默认部署 |
| 默认生产工具数 | `5` | CI、配置验证和宿主验收失败 |
| 实验 profile | `redacted_case`，工具数 `6` | App 无正向票据签发，生产不可用 |
| 合成/公开图示 profile | `diagram_authoring`，工具数 `11`（公开五项 + 图示六项） | 永久明文本地 bundle；真实、待复核或批准案件数据一律禁止 |
| 条件案件 profile | `approved_case_workspace`，工具数 `21`（公开五项 + 案件十项 + 图示六项） | formal App paired-binary hash + 当前 qualification + policy-v2 standalone session + exact ticket 任一缺失即 fail closed；静态资产默认禁用 |
| Approved session grants | 16 项：`read=8`、`write=2`、`diagram_read=4`、`diagram_write=2` | 旧 read/write 不静默扩权；policy v2 之前的 session 必须撤销并重建 |
| 隐藏旧案件/文书工具 | 全部隐藏 | 不兼容调用稳定拒绝 |

## 平台

| 组件 | Windows x86-64 | Linux x86-64 | macOS Apple silicon | 当前边界 |
|---|---|---|---|---|
| `legal-services` | 本机测试 | 目标支持 | 目标支持 | 跨平台 Rust 服务；首次完整远端矩阵仍是发布门禁 |
| MCP stdio | 本机自动测试 | 目标支持 | 目标支持 | 必须显式/默认解析为 `public_law_only` |
| MCP HTTP `/mcp` | 本机自动测试 | 目标支持 | 目标支持 | loopback + Bearer；生产跨机入口使用 TLS 反向代理 |
| `redacted_case` receipt gate | Windows 合成协议测试 | fail-closed | fail-closed | 依赖 Windows 保护能力；无 App 生产签票链 |
| `diagram_authoring` | synthetic/public 本地图示 | 目标支持 | 目标支持 | 明文 bundle，不是批准案件路径 |
| `approved_case_workspace` | Windows 15-tool baseline actual-binary stdio/HTTP 已测；集成后 21-tool binary 复跑待完成 | fail-closed | fail-closed | 静态宿主只提供 Windows stdio；App broker 的 HTTP 仅用于受控链；不是跨平台已认证声明 |
| Tauri App | Windows 目标 | 不在当前交付范围 | 不在当前交付范围 | App 本地复核/导出不等于 MCP/Provider 外发授权 |
| 本地 MinerU GPU OCR | worker/component 与 synthetic direct-worker diagnostics 已测；production qualification 未取得 | 未认证 | 未认证 | App 已接入 qualified runner；缺少任一当前机器资格时，扫描/视觉 PDF fail-closed |

“目标支持”只表示代码与 workflow 面向该平台；没有成功的目标平台发布矩阵和真实宿主验收，就不能写成“已认证”。

历史 Windows MinerU v3/v5 candidate 的安装与 synthetic-only diagnostic 只作为兼容性诊断，两者永久禁止发布，也不是 production qualification。v4 provenance 源码门禁与 27/27 builder tests 已完成，但最终 clean source commit 后的确定性重建、显式审批、签名、短根安装/remeasure、GPU probe 和 App Firewall/Job qualification 仍待执行，当前没有 final v4 artifact/hash。项目 Release 为 private；未认证客户端不能直接使用 catalog asset URL，最终发布后仍推荐认证下载完整资产集再本地导入。

## 宿主

| 宿主 | 配置资产 | 当前验收要求 |
|---|---|---|
| WorkBuddy | public-only 连接器/Skill；另有默认禁用 Windows approved stdio 连接器/Skill | public 精确五项；approved 精确 21 项、只填 App-issued `srv_…`、按需选择四组 v2 grants、opaque-ID-only 且全套外流禁令生效 |
| Codex | public-only 配置/Skill；另有默认禁用 Windows approved stdio 配置/Skill | public 双重锁定五项；approved 不含 HTTP/path/env/secret，精确 21 项并要求干净任务 |
| OpenCode | public-only配置/Agent；另有默认禁用 Windows approved local 配置/Agent | public 通配 `deny` + 五项 `allow`；approved 只用 App session ID、精确 21 项且禁止 attachment/file/browser/other MCP/memory/subagent |
| 其他 MCP 宿主 | 自行配置 | 只保证服务器协议；必须独立验证工具白名单、日志和 Provider 保留策略 |

任何宿主都可能在 Skill/Agent 生效前上传首条消息或附件。MCP 兼容不表示能阻止、撤回或删除宿主已经披露的数据。

## 历史证据说明

早期 Windows/WorkBuddy 验收曾记录 12/12 工具、案件提案和写入停点；后续验收也曾记录 15-tool approved baseline。当时记录仍是历史事实，未被改写；但它们不是当前 21-tool 兼容性或可用性声明。当前默认复验只接受公开五工具；独立 approved 复验要求十个 ID-only 案件工具、六个批准图示工具及其 App-issued v2 授权，旧案件操作不再执行。

formal Windows release 先构建 exact MCP sibling，再把其 SHA-256 编译进 App。缺失/畸形/错 hash/same-name substitution negatives 已覆盖该 trust anchor；集成后的 21-tool actual binary stdio/HTTP E2E 仍是发布前必跑项。普通未绑定 development App 不具备 approved qualification 能力。
