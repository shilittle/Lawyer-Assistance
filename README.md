# Lawyer Assistance

[English](README.en.md)

Lawyer Assistance 是一个 Windows 本机单用户法律工具。它由一个 Rust 后台服务、一个普通 HTML WebUI 和一个可独立运行的 MCP 程序组成，核心工作是材料脱敏和本地法律检索。

当前增量版本为 `1.2.0`，包含 AI 脱敏、完整分页法律检索、AI 法律搜索、文书写作和带法律工具的会话。Windows 未签名便携包、源码和验收资料见 [v1.2.0 发布页](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v1.2.0)。

## 功能

- **材料脱敏**：TXT、DOCX、PDF、PNG、JPEG、WebP；视觉 OCR、本地规则与 LLM 定位查漏结合，同组稳定别名，统一输出纯 TXT，支持批量 ZIP。
- **法律检索**：完整匹配集计数和分页，法律归组与逐条视图，类型、效力、地域、状态和日期筛选；相关性及日期排序，可打开历史版本正文。
- **AI 法律搜索**：读取用户描述、选定材料或附件，自行调整关键词、检索和阅读本地法条、版本及最高法案例，输出经过数据库核验的引用并保存历史，不联网检索法律资料。
- **文书写作**：根据案件撰写六类常用文书及自定义要求，可调用法律工具；预览排版正文，保存版本，默认导出 PDF，也支持真正的 DOCX 和纯 TXT。
- **AI 会话**：自动命名及手动改名，图形化材料选择与附件上传，共用法律工具；后台任务关闭浏览器后继续。
- **模型设置**：常见国内供应商预设、密钥联网获取模型、多选启用，对话、脱敏、写作和 OCR 分别配置。密钥保存在 Windows 凭据管理器。
- **MCP**：`public_law_only` 保持七个只读法律/案例工具；`privacy_workspace` 保持十个工具。私密材料不从公开 MCP 返回。

国内官方预设默认允许发送选定原文，自定义地址需要确认发送策略，其他供应商使用有效脱敏材料。案件材料内的提示内容不获得工具或配置权限。案例库覆盖以来源清单为准，不是全国裁判文书全集。具体流程和旧数据兼容见 [升级说明](docs/web/ai-upgrade.md)。

案例 sidecar 当前包含 759 个主案例/合集：279 个指导案例、61 个参考案例和 419 个典型案例合集，并保留 834 个 TXT 来源条目。典型合集可能包含多个案件，按一篇文章检索，不作为单独案件计数；指导案例 45 保留洛阳市中级人民法院官方转载来源。来源、状态和哈希见 `data/runtime/CASE_DATA_SOURCES.md` 与 `data/generated/judicial_cases_manifest.json`。

## 便携运行

便携包由 `scripts/package_portable.py` 在本地生成，文件名为 `Lawyer-Assistance_1.2.0_windows-x86_64-portable.zip`。当前交付方式是 ZIP、同名 `.zip.sha256` 和包内 JSON 清单一起交付；不表示 GitHub Release 已发布。Windows x86_64 便携包包含两个 release 程序、`legal_core.sqlite` 法律库、`judicial_cases.sqlite` 案例库、案例来源说明和发行清单、许可证/第三方 notices、派生检索索引、Pdfium、Typst、中文字体、当前文档和 MCP 示例、`Lawyer-Assistance.vbs` 以及 `Stop-Lawyer-Assistance.vbs`。解压后双击启动脚本；脚本通过 `wscript.exe` 隐藏窗口执行：

```powershell
lawyer-assistance.exe serve --open --port 8877 --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" --legal-db "<package>\data\runtime\legal_core.sqlite"
```

用户数据只写入 `%LOCALAPPDATA%\LawyerAssistanceWeb`，不会迁移或覆盖旧 Tauri 工作台数据。启动后浏览器打开 `http://127.0.0.1:8877`。已有服务运行时可执行 `lawyer-assistance.exe login` 重新打开登录页。

停止服务时双击 `Stop-Lawyer-Assistance.vbs`，或运行 `lawyer-assistance.exe stop`。该命令读取当前用户加密连接描述符，通过已认证的本机会话和 CSRF 请求优雅停止当前 server；它不会结束任意进程。

拿到 ZIP 后先核对同名 `.zip.sha256`，再阅读包内 `MANIFEST.sha256` 和 `portable.manifest.json`；其中应同时列出法律库和案例库的文件大小、SHA-256、schema、数量和官方来源信息。v1.2.0 交付物为未签名本地便携产物，没有安装器、签名文件或 updater 文件。

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

公开 profile 固定包含七个工具：`system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations`、`legal_search_cases`、`legal_get_case`。`privacy_workspace` profile 共包含十个工具，另有 `privacy_workspace.submit`、`privacy_workspace.status` 和 `privacy_workspace.read_result`。旧五个法律工具的名称、输入和输出契约保持不变；案例库缺失时案例工具明确报告不可用，法条库身份不变。

`privacy_workspace` 通过 WebUI 的“设置”创建客户端 token，由 MCP 代理调用已运行的本机后台。它只能提交配置收件目录中的相对路径、读取任务状态和分页读取已发布脱敏文本；不会返回原文、映射、原始文件名或磁盘路径。旧 `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` profile 已停用，不会兼容映射。

详细参数和协议说明见 [MCP 文档](docs/mcp/README.md)。

## 文档

- [快速开始](docs/getting-started.md)
- [安全与隐私](docs/security-and-privacy.md)
- [法律数据与运行时数据库](docs/data/legal-corpus.md)
- [MCP 文档](docs/mcp/README.md)
- [Web 核心功能与运行边界](docs/web/README.md)
- [AI 增量验收报告](docs/web/ai-validation.md)
- [Web 重构验收记录](docs/web/validation.md)
- [贡献指南](CONTRIBUTING.md)
- [安全问题报告](SECURITY.md)
- [变更日志](CHANGELOG.md)
- [v1.2.0 发布说明](RELEASE_NOTES.md)

法律数据仅用于辅助检索和律师复核，不能替代对官方现行文本、案件事实和专业意见的核验。

## 许可证

源代码采用 [MIT License](LICENSE)。法律运行时数据库的来源说明、许可和第三方 notices 随包位于 `data/runtime/`，并保留在 [法条数据来源说明](data/runtime/DATA_SOURCES.md)、[案例来源说明](data/runtime/CASE_DATA_SOURCES.md) 和 [法律数据审计文档](docs/data/legal-corpus.md) 中。
