# 兼容性矩阵

## 当前契约

| 项目 | 当前值 | 漂移行为 |
|---|---|---|
| MCP 协议元数据 | `2025-11-25` | 初始化或宿主协商失败，不静默降级 |
| 服务 schema | `1` | `unsupported_schema_version` |
| 法律归档 schema | `4` | 拒绝不兼容法律库 |
| 法律运行时 schema | `1`（存在该元数据时） | 拒绝不兼容法律库 |
| 用户库 schema | `10` | 新版本拒绝降级打开；旧版本只走显式迁移 |
| 生产 profile | `public_law_only` | 非精确匹配停止部署 |
| 生产工具数 | `5` | CI、配置验证和宿主验收失败 |
| 实验 profile | `redacted_case`，工具数 `6` | App 无正向票据签发，生产不可用 |
| 案件/文书工具 | 全部隐藏 | 不兼容调用稳定拒绝 |

## 平台

| 组件 | Windows x86-64 | Linux x86-64 | macOS Apple silicon | 当前边界 |
|---|---|---|---|---|
| `legal-services` | 本机测试 | 目标支持 | 目标支持 | 跨平台 Rust 服务；首次完整远端矩阵仍是发布门禁 |
| MCP stdio | 本机自动测试 | 目标支持 | 目标支持 | 必须显式/默认解析为 `public_law_only` |
| MCP HTTP `/mcp` | 本机自动测试 | 目标支持 | 目标支持 | loopback + Bearer；生产跨机入口使用 TLS 反向代理 |
| `redacted_case` receipt gate | Windows 合成协议测试 | fail-closed | fail-closed | 依赖 Windows 保护能力；无 App 生产签票链 |
| Tauri App | Windows 目标 | 不在当前交付范围 | 不在当前交付范围 | App 本地复核/导出不等于 MCP/Provider 外发授权 |
| 本地 MinerU GPU OCR | 未完成 App 认证 | 未认证 | 未认证 | runner 存在但 App 传 `None`；扫描/视觉 PDF fail-closed |

“目标支持”只表示代码与 workflow 面向该平台；没有成功的目标平台发布矩阵和真实宿主验收，就不能写成“已认证”。

## 宿主

| 宿主 | 配置资产 | 当前验收要求 |
|---|---|---|
| WorkBuddy | 三份连接器 JSON + 中文 Skill | `tools/list` 精确五项；任务不含案件数据；pre-Skill 披露说明可见 |
| Codex | stdio/HTTP TOML + privacy hardening + Skill | 服务端 profile 与客户端 `enabled_tools` 双重锁定五项 |
| OpenCode | local/remote JSON + Agent/AGENTS | 分享关闭；通配权限 `deny`；仅五项显式 `allow` |
| 其他 MCP 宿主 | 自行配置 | 只保证服务器协议；必须独立验证工具白名单、日志和 Provider 保留策略 |

任何宿主都可能在 Skill/Agent 生效前上传首条消息或附件。MCP 兼容不表示能阻止、撤回或删除宿主已经披露的数据。

## 历史证据说明

早期 Windows/WorkBuddy 验收曾记录 12/12 工具、案件提案和写入停点。当时记录仍是历史事实，未被改写；但它已经被 2026-07-19 隐私收紧取代，不是当前生产兼容性或可用性声明。当前复验只接受公开五工具，旧案件操作不再执行。