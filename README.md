# Lawyer Assistance

[English](README.en.md)

Lawyer Assistance 是一个 Windows 本机单用户法律工具。它由一个 Rust 后台服务、一个普通 HTML WebUI 和一个可独立运行的 MCP 程序组成，核心工作是材料脱敏和本地法律检索。

当前发布版本为 `1.0.0`，这是 Web 重构后的公开 Web 大版本。Windows 产物为未签名便携包，不提供安装器或自动更新器。

## 能力边界

- **材料脱敏**：导入 TXT、DOCX，提取正文和表格，识别常见个人/机构/联系方式/证件/案号/账户信息，使用同一材料组内稳定别名替换，残留检查通过后生成可用版本。
- **复核和导出**：在 WebUI 中补充敏感词、修改别名、处理疑难项或撤销结果；支持 TXT、Markdown、重建 DOCX 和批量 ZIP 导出。
- **法律检索**：读取只读 `legal_core.sqlite`，支持法律、条文、历史版本、效力日期、关联法规和收藏。
- **轻量工具**：六类固定文书模板、简单 Provider 对话，以及用户明确选择的法条和有效脱敏结果上下文。本次公开发布未完成真实 Provider 联调，验证使用可控模拟服务。
- **MCP**：`public_law_only` 提供五个只读公开法律工具；`privacy_workspace` 提供八个工具（五个公开法律工具，加上提交、状态和结果分页读取三个工作区工具）。

PDF、图片、扫描件 OCR、原件版式保留、复杂案件管理、法律图谱和自动办案流程不属于 v1.0.0。OCR 只保留未来扩展接口，不安装或发布 OCR 运行时。疑难云辅助使用可控模拟服务完成验证，合成材料的通过率、误报和漏检报告用于回归检查，不能作为真实案件精度保证。

## 便携运行

下载 `Lawyer-Assistance_1.0.0_windows-x86_64-portable.zip`。Windows x86_64 便携包包含两个 release 程序、运行时法律库、许可证/第三方 notices、当前文档和 MCP 示例、`Lawyer-Assistance.vbs` 以及 `Stop-Lawyer-Assistance.vbs`。解压后双击启动脚本；脚本通过 `wscript.exe` 隐藏窗口执行：

```powershell
lawyer-assistance.exe serve --open --port 8877 --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" --legal-db "<package>\data\runtime\legal_core.sqlite"
```

用户数据只写入 `%LOCALAPPDATA%\LawyerAssistanceWeb`，不会迁移或覆盖旧 Tauri 工作台数据。启动后浏览器打开 `http://127.0.0.1:8877`。已有服务运行时可执行 `lawyer-assistance.exe login` 重新打开登录页。

停止服务时双击 `Stop-Lawyer-Assistance.vbs`，或运行 `lawyer-assistance.exe stop`。该命令读取当前用户加密连接描述符，通过已认证的本机会话和 CSRF 请求优雅停止当前 server；它不会结束任意进程。

下载后先核对同名 `.zip.sha256`，再阅读包内 `MANIFEST.sha256` 和 `portable.manifest.json`。v1.0.0 公开提供的是未签名本地便携产物，没有安装器、签名文件或 updater 文件。

## 从源码运行

要求 Rust stable/MSVC、Node.js `>=24`、pnpm `>=11` 和 Python 3。前端是嵌入 Rust 二进制的 `apps/web`，无需前端开发服务器：

```powershell
pnpm install
pnpm check
pnpm test
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
pnpm build
```

直接启动后台服务时，必须传入绝对法律库路径；省略 `--data-dir` 时使用 `%LOCALAPPDATA%\LawyerAssistanceWeb`：

```powershell
cargo run --release --locked -p lawyer-assistance-server --bin lawyer-assistance -- serve `
  --open --port 8877 `
  --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" `
  --legal-db "$pwd\data\runtime\legal_core.sqlite"
```

构建便携包（会先编译两个 release 程序）：

```powershell
python scripts/package_portable.py
```

已有 release 程序时只执行资源校验和打包：

```powershell
python scripts/package_portable.py --skip-build
```

该脚本只生成 ZIP、SHA-256 sidecar 和 JSON manifest，不上传 GitHub，不生成安装器、签名、`.sig`、`latest.json` 或 updater 文件。

## MCP

公开法律 MCP 独立使用运行时法律库，不读取用户工作区：

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

公开 profile 固定包含五个工具：`system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations`。`privacy_workspace` profile 共包含八个工具，另有 `privacy_workspace.submit`、`privacy_workspace.status` 和 `privacy_workspace.read_result`。

`privacy_workspace` 通过 WebUI 的“设置”创建客户端 token，由 MCP 代理调用已运行的本机后台。它只能提交配置收件目录中的相对路径、读取任务状态和分页读取已发布脱敏文本；不会返回原文、映射、原始文件名或磁盘路径。旧 `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` profile 已停用，不会兼容映射。

详细参数和协议说明见 [MCP 文档](docs/mcp/README.md)。

## 文档

- [快速开始](docs/getting-started.md)
- [安全与隐私](docs/security-and-privacy.md)
- [法律数据与运行时数据库](docs/data/legal-corpus.md)
- [MCP 文档](docs/mcp/README.md)
- [Web 核心功能与运行边界](docs/web/README.md)
- [Web 重构验收记录](docs/web/validation.md)
- [贡献指南](CONTRIBUTING.md)
- [安全问题报告](SECURITY.md)
- [变更日志](CHANGELOG.md)
- [v1.0.0 发布说明](RELEASE_NOTES.md)

法律数据仅用于辅助检索和律师复核，不能替代对官方现行文本、案件事实和专业意见的核验。

## 许可证

源代码采用 [MIT License](LICENSE)。法律运行时数据库的来源说明、许可和第三方 notices 随包位于 `data/runtime/`，并保留在 [数据来源说明](data/runtime/DATA_SOURCES.md) 和 [法律数据审计文档](docs/data/legal-corpus.md) 中。
