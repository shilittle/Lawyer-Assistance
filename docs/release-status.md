# 当前发布状态

## 版本结论

源码版本暂为 `0.4.0`。项目正在从 Tauri 桌面工作台切换为 Rust server + 纯 HTML WebUI + MCP；该版本用于本地技术验证和可复现便携打包，不是已签名 Windows stable 发布。

便携包由 `scripts/package_portable.py` 生成，包含：

```text
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip
Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256
Lawyer-Assistance_0.4.0_windows-x86_64-portable.manifest.json
```

ZIP 内含两个 release exe、`data/runtime/legal_core.sqlite`、`DATA_SOURCES.md`、`LICENSE.txt`、`THIRD_PARTY_NOTICES.txt`、README、`Lawyer-Assistance.vbs`、`Stop-Lawyer-Assistance.vbs`、`MANIFEST.sha256` 和 `portable.manifest.json`。打包前会把数据库文件大小、SHA-256 和 SQLite 内的 `source_manifest_sha256` 与 `data/generated/legal_core_distribution_manifest.json` 对照。

## 可用能力

| 能力 | 状态 |
| --- | --- |
| 本机 server + loopback WebUI | 已实现，默认 `127.0.0.1:8877` |
| TXT/DOCX 脱敏 | 已实现本地提取、识别、替换、复核、残留检查和结果版本 |
| TXT/Markdown/DOCX/ZIP 导出 | 已实现并在导出后复读检查 |
| 本地法律检索 | 使用只读 runtime 数据库 |
| `public_law_only` | 固定五个公开法律工具 |
| `privacy_workspace` | 三个脱敏工具，共用后台并使用独立 client token |
| Provider 云辅助/简单对话 | 需要显式绑定授权；只发送用户允许的提取文本/脱敏结果 |
| PDF、图片、扫描件 OCR | 首版不支持；只保留扩展接口 |
| Tauri、安装器、签名、updater、GitHub 发布 | 已从当前发布路径移除 |

## 数据与兼容性

新数据目录为 `%LOCALAPPDATA%\LawyerAssistanceWeb`。旧 Tauri 数据目录、案件、映射和授权保持原样，不迁移、不自动打开。法律库缺失只影响法律检索；脱敏任务不依赖法律库。

旧 MCP profile `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` 明确返回停用错误，不会兼容映射到 `privacy_workspace`。

## 运行限制

- 便携包和本地 release 构建均为未签名技术产物。
- 没有 installer、Authenticode/RFC3161、`.sig`、`latest.json` 或自动更新链。
- 没有生产 OCR 运行时、GPU 资格或云端 OCR 回退。
- 真实案件材料不应进入仓库、测试 fixture、日志、截图或未授权 Provider/MCP。
