# 当前发布状态

## 版本结论

当前目标版本为 `0.4.0-beta.2`，发布定位是：

> 未签名技术预发布，尚未达到正式生产版本或完整版本的发布门槛。

该结论不否定已经实现的本地法律检索、案件工作区、隐私审批、受保护成果、MCP 和备份能力；它表示签名、自动更新、生产 OCR、完整归档资源和最终环境验收仍未完成。

## 当前可用能力

| 能力 | 状态 |
|---|---|
| Windows x86_64 桌面应用 | 已实现；技术预发布尚未建立可信发布者身份 |
| `runtime-slim-v1` 运行时法律库 | 随应用资源使用；服务于当前查询和引用流程 |
| 本地案件、证据、问题与法律依据管理 | 已实现 |
| PDF、DOCX、UTF-8 TXT、Markdown 本地导入 | 已实现；视觉页受 OCR 资格门限制 |
| 脱敏复核、不可变批准 generation、Vault 与映射 | 已实现 |
| 受保护 work products 与安全派生文件 | 已实现 |
| 五组件认证加密 `.lavbackup` | 已实现 |
| BYOK Provider | 已实现；公开与批准案件通道分离 |
| `public_law_only` | 默认五个公开法律只读 MCP 工具 |
| `approved_case_workspace` | 精确 21 工具；默认禁用并受 App 资格、session、grant 和 ticket 约束 |
| `diagram_authoring` | 精确 11 工具；永久仅限纯合成或公开数据 |
| 批准案件图示 | 经 approved workspace 保存为加密受保护 HTML work product |

## 当前未交付或未资格化

### Authenticode 与安装包

当前版本没有完成正式 Authenticode 签名和可信 Windows publisher 验收。未签名安装程序可能触发 SmartScreen、AV 或 EDR 提示，不能标记为已签名或正式生产安装包。

### 自动更新

当前不提供可发布的 installer-bound updater `.sig` 和 `latest.json`。技术预发布不得发布指向未签名安装程序的 updater 元数据。升级需要重新取得并核验完整安装包。

### 生产 OCR

本地 MinerU 代码路径、组件管理和资格门已经实现，但当前版本没有完成最终可发布组件和生产资格。扫描或视觉 PDF 必须保持 fail-closed；不得改用云 OCR、远程 OCR、SSH 或静默上传。

### 完整归档数据库

应用使用 `runtime-slim-v1` 投影。完整归档数据库 `legal_core_full.sqlite` 不在技术预发布包中，也不能由 fixture、运行时投影或同名文件替代。需要完整 coverage 重建和 strict archival/provenance 审计的工作必须使用另行验证的正式归档资源。

### 最终环境验收

正式发布仍需要完成：

- 从干净发布源生成并核验最终 portable、installer 和 MCP 资产；
- Windows 10/11 clean-machine 安装、启动、升级、回滚和卸载；
- Authenticode、时间戳、SmartScreen、AV/EDR 与 updater 精确资产验证；
- 最终 MinerU 组件的确定性构建、审批、签名、短路径安装、重测量和 GPU probe；
- App 所有 OCR 隔离、canary、重启、漂移、撤销和到期门禁；
- 最终 release App 与配对 MCP binary 的重新测量和合成 E2E。

## 可以如何描述本版本

可以使用：

- “Lawyer Assistance `0.4.0-beta.2` 未签名技术预发布”
- “提供本地公开法律检索、案件整理、隐私审批、受保护成果和受控 MCP”
- “生产 OCR 默认阻断”
- “使用运行时精简法律库，完整归档库不随包提供”

不应使用：

- “正式版”“生产完整版”或“已完成全部发布验收”
- “已通过生产扫描件 OCR 资格”
- “已签名”或“已建立可信 Windows publisher”
- “支持当前自动更新”
- “安装包包含完整归档数据库”
- “已完成 Windows 10/11 clean-machine 全覆盖”

## 用户建议

技术预发布只应使用项目提供并可核验的资产，在隔离的评估环境中处理合成或适当授权的数据。真实案件使用必须遵守[安全与隐私](security-and-privacy.md)中的审批、外发和宿主边界；扫描材料在生产 OCR 资格完成前不得进入 OCR 流程。
