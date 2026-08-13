# Changelog

本文件记录面向用户的正式版本变化。历史预发布构建只作为开发与验收事实保留，不作为稳定版本支持线。

## [Unreleased]

### Target: 0.4.0

### Added

- 四个顶层工作区：助理、案件、法律资料库和设置；普通聊天、案件助理与 approved automation/MCP 使用相互独立的执行边界。
- 审计型、一对一、双向唯一的 `ProjectId ↔ PrivacyCaseId` 持久化绑定，以及案件材料归属、保护显示名和迁移证据链。
- exact v0.3.1 自动升级、写入前五槽原态恢复点、recovery-only `apply-and-exit`、旧版重开与再次升级流程。
- `.lavbackup` V3 五组件备份、加密 work-products、approved MCP policy v2/replay journal v2，以及本地 MinerU 组件的签名、隔离和资格链。
- 统一 stable version gate、精确发布资产 allowlist、不可覆盖的 draft 上传和全新目录服务端回读验证。

### Changed

- User 数据库目标 schema 升至 11；Privacy 数据库依次迁移至 schema 5/6，并在最后事务中才提交 User schema 10→11。
- approved case workspace 固定为 21 个工具；旧 approved MCP session 必须撤销并以 policy v2 重建。
- Windows 正式发布只接受 exact `0.4.0`、干净且同步的 `main`、exact-HEAD CI、Authenticode/RFC3161、installer-bound updater 签名与固定资产名。

### Security

- 无法唯一认证的旧数据库、混合版本目录、身份冲突、回放、篡改、残留或不完整恢复状态均失败关闭。
- 真实案件材料仍禁止进入仓库、日志、浏览器/搜索、远程 OCR、云存储或未经批准的 Provider/MCP/自动化上下文。
- 稳定发布的外部凭据、最终 MinerU 资产、clean-machine 和服务端证据必须真实满足；测试 key、占位模型或本机普通 smoke test 不构成替代。
