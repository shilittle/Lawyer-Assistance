# 当前发布状态

## 版本结论

当前目标版本为 `0.4.0`，当前定位是：

> manifest、lockfile、测试 fixture 和当前用户文档使用精确稳定版本号的正式发布候选源码；尚未宣称 GitHub stable/latest Release 已发布。

该结论不否定已经实现的本地法律检索、案件工作区、隐私审批、受保护成果、MCP、升级/回滚和备份能力；它明确区分“版本源已同步为稳定 `0.4.0`”与“外部发布证据已闭合”。后者还需要 exact final `main` CI、真实签名凭据、精确资产与服务端回读、Windows 10/11 clean-machine、updater 端点和 final MinerU 资格。

GitHub 仓库当前为公开仓库。仓库可见性和资产可下载性只属于分发事实，并不等于已建立可信发布者签名、可用自动更新、OCR 资格、干净机器验收或正式发布状态。

## 当前可用能力

| 能力 | 状态 |
|---|---|
| Windows x86_64 桌面应用 | 候选源码已实现；正式资产必须建立可信发布者身份并通过 clean-machine 验收 |
| 四区域信息架构 | 已实现为助理、案件、法律资料库和设置 |
| 普通助理聊天 | 已实现；无需先创建案件，使用用户选择的 BYOK Provider，并持续显示 Provider 服务器外发提示 |
| 显式普通附件 | 已实现；只有当前发送明确选择的附件会贡献本地提取正文，且不会自动登记为案件材料 |
| `runtime-slim-v1` 运行时法律库 | 随应用资源使用；服务于当前查询和引用流程 |
| 本地案件、证据、问题与法律依据管理 | 已实现 |
| PDF、DOCX、UTF-8 TXT、Markdown 本地导入 | 已实现；视觉页受 OCR 资格门限制 |
| 案件 → 材料与脱敏 | 已实现导入、文本层提取、脱敏复核、不可变批准、撤销和版本历史；OCR 仍受门禁且当前未取得生产资格 |
| approved-only 案件助理 | 已在案件工作中实现；每次请求显式选择当前批准 generation，并排除原件和 Vault 对象 |
| 审计型 `ProjectId ↔ PrivacyCaseId` 绑定 | 已实现为后端持久化、不可变的一对一绑定；前端不推导也不接收权威 Privacy 身份 |
| 受保护 work products 与安全派生文件 | 已实现 |
| 五组件认证加密 `.lavbackup` | 已实现 |
| BYOK Provider | 已实现；`interactive_chat`、`interactive_case_work` 和 `approved_automation` 三条通道相互独立 |
| 四个设置 owner | Provider 服务与凭据；本地处理环境与 OCR 组件；MCP 与自动化；版本、备份与诊断 |
| `public_law_only` | 默认五个公开法律只读 MCP 工具 |
| `approved_case_workspace` | 精确 21 工具；默认禁用并受 App 资格、session、grant 和 ticket 约束 |
| `diagram_authoring` | 精确 11 工具；永久仅限纯合成或公开数据 |
| 批准案件图示 | 经 approved workspace 保存为加密受保护 HTML work product |

## 当前工作流边界

- `interactive_chat` 支持不绑定案件的普通消息和显式普通附件。它不能读取案件工作区、Privacy store、Vault、approved generation 或 MCP 授权状态。
- `interactive_case_work` 只允许应用内案件助理使用当前案件中本次显式选择、仍为批准且当前有效的 generation 和已确认案件数据。已撤销、过期、原始、待复核、其他案件或未选择的来源全部 fail closed。
- `approved_automation` 保留独立的外部宿主边界：opaque ID、干净任务控制、qualification、批准来源引用、grant、exact ticket、目的地/用途绑定、撤销校验和受保护成果落点。

三种模式不可互换，任何受阻模式都不得回退到另一种模式。案件正文和人工复核只存在于 **案件 → 材料与脱敏**；设置只承载四个配置与维护 owner。

## 正式资产契约

正式 App Release 使用 tag `v0.4.0`。只有以下 12 项自定义资产完整、名称精确且通过本地及服务端回读验证时，才符合 App/MCP allowlist；GitHub 自动生成的 source archive 不计：

```text
Lawyer.Assistance_0.4.0_x64-setup.exe
Lawyer.Assistance_0.4.0_x64-setup.exe.sha256
Lawyer.Assistance_0.4.0_x64-setup.exe.sig
latest.json
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256
lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip
lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256
lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz
lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256
```

Tauri 本地产物 `Lawyer Assistance_0.4.0_x64-setup.exe` 必须在发布时映射为点号规范名 `Lawyer.Assistance_0.4.0_x64-setup.exe`。App、配对 Windows MCP 和 installer 必须具有有效 Authenticode 与 RFC3161 timestamp；updater `.sig` 必须签署 exact 已签名 installer bytes，`latest.json` 的版本、URL 与 signature 必须逐项匹配。

正式 MinerU 组件使用独立 tag/Release `mineru-components-v0.4.0`，只允许：

- `mineru-component-catalog.json` 与 `mineru-component-catalog.json.minisig`；
- `mineru-component-provenance.json` 与 `mineru-component-provenance.json.minisig`；
- 唯一 descriptor `lawyer-assistance-mineru-0.4.0-windows-x86_64.laocrpkg.laocrparts`；
- descriptor/catalog 精确列出的全部有序 `.partNNNN-of-NNNN`。

分片发布不得同时上传未分片 `.laocrpkg`。历史 v3/v5 candidate、空或占位模型、合成包及未批准的 runtime/model/license/provenance 永久不得进入正式 Release。

## 尚待外部门禁闭合

### Authenticode 与安装包

当前还没有可据此文档确认的正式 Authenticode certificate/private key、可信 RFC3161 时间戳和 Windows publisher 验收证据。候选安装程序不能标记为已签名、正式或生产安装包。

### 自动更新

正式发布需要与仓库内 updater 公钥匹配的私钥和密码，对 exact 已签名 installer bytes 生成 `.sig`，再验证 `latest.json`。在 stable/latest endpoint 的 bytes、version、URL 和 signature 全部通过前，自动更新不得视为可用。

### 生产 OCR

本地 MinerU 代码路径、组件管理和资格门已经实现，但仍缺 final v4 runtime/model revisions、完整 assets、Minisign 私钥、provenance/license/redistribution 人工批准，以及目标 GPU/driver qualification 证据。扫描或视觉 PDF 必须保持 fail-closed；不得改用云 OCR、远程 OCR、SSH 或静默上传。

### 完整归档数据库

桌面应用使用 `runtime-slim-v1` 投影。完整归档数据库 `legal_core_full.sqlite` 不在 App Release 中，也不能由 fixture、运行时投影或同名文件替代。需要完整 coverage 重建和 strict archival/provenance 审计的工作必须使用另行验证的正式归档资源。

### 最终环境验收

正式发布仍需要为 exact final `main` commit 完成：

- 主 CI 与 MCP Linux/Windows/macOS CI 全绿，并从该 exact run 收集跨平台 MCP archive；
- 从干净发布源生成、签名并核验完整 12 项 App/MCP allowlist 和 MinerU 组件资产；
- Windows 10/11 clean-machine 安装、启动、升级、回滚和卸载；
- Authenticode、时间戳、SmartScreen、AV/EDR 与 updater 精确资产验证；
- 最终 MinerU 组件的确定性构建、审批、签名、短路径安装、重测量和 GPU probe；
- App 所有 OCR 隔离、canary、重启、漂移、撤销和到期门禁；
- 最终 release App 与配对 MCP binary 的重新测量和合成 E2E；
- 两个 draft Release 的 exact allowlist、逐文件 SHA-256、签名与本地构建一致；同一 Release 经 prerelease 公网验收后再提升 stable/latest，并完成 latest endpoint 最终复验。

## 可以如何描述本版本

可以使用：

- “Lawyer Assistance `0.4.0` 正式发布候选源码”
- “仓库版本源已同步为精确稳定版本号 `0.4.0`，外部发布门禁仍待闭合”
- “Lawyer Assistance 源代码仓库为公开仓库”
- “提供本地公开法律检索、案件整理、隐私审批、受保护成果和受控 MCP”
- “通过相互独立的执行模式提供无案件前提的普通 Provider 聊天和 approved-only 案件助理”
- “生产 OCR 默认阻断”
- “使用运行时精简法律库，完整归档库不随包提供”

不应使用：

- “`v0.4.0` 已正式发布”“stable/latest 已可用”“生产完整版”或“已完成全部发布验收”
- “已通过生产扫描件 OCR 资格”
- “已签名”或“已建立可信 Windows publisher”
- “支持当前自动更新”
- “安装包包含完整归档数据库”
- “因为仓库或资产公开，所以已经完成签名、updater、OCR 资格或发布验收”
- “已完成 Windows 10/11 clean-machine 全覆盖”

## 用户建议

候选阶段只应使用项目提供并可核验的资产，在隔离的评估环境中处理合成或适当授权的数据。只有同一 `v0.4.0` Release 明确提升为 stable/latest 且上述验证证据闭合后，才按正式发布资产使用。真实案件使用始终必须遵守[安全与隐私](security-and-privacy.md)中的审批、外发和宿主边界；扫描材料在生产 OCR 资格完成前不得进入 OCR 流程。
