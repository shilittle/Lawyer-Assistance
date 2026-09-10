# Changelog

本文件记录 Lawyer Assistance 的用户可见变化。

## [1.2.1] - 2026-09-10（本地修复候选版）

- 文书编辑、保存和导出固定绑定任务及 revision；表单和未提交正文保存为加密草稿，支持页面及浏览器重启恢复。
- 统一轮询订阅，加入有限指数退避；会话材料采用服务器版本清单，移除后取消相关任务并排除依赖历史。
- Web、AI、MCP 共用关键词与版本查询规则；精确条号、三种匹配模式、日期边界及索引降级使用一致的完整结果集合。
- 增加有限页面与计数缓存、加密摘要调度索引、可恢复备份迁移、并发准入和贯通取消；健康状态及日志明确记录故障类别。
- PDF 改由同一程序的内部 worker 逐页处理，文本页本机提取，扫描与混合页按需 OCR；限制子进程内存及累计渲染时间。
- 引用证据绑定法规版本、引文定位、正文哈希、文书 revision 和日期；编辑后失效，待复核导出保留真实核验状态。
- 模型能力可配置，输入和输出有预算；材料与历史按实际选取范围反馈，截断回答不能标为完成。
- 补齐 zune 依赖许可证正文。候选版及验收资料只在本地交付，详情见 `docs/web/audit-1.2.1.md`。

## [1.2.0] - 2026-09-09

- 模型服务增加国内供应商预设、在线模型发现、多选启用及对话、脱敏、写作、OCR 独立默认模型；保留 Windows 凭据管理器。
- 法律检索按完整匹配集计数、筛选和分页，支持法律归组、相关性排序和历史版本正文，新增独立中文检索索引。
- 脱敏接入大模型识别和检查，支持 PDF、图片、DOCX 内嵌图片的视觉 OCR，成品统一为纯 TXT；后台保存处理阶段。
- AI 搜索、文书写作和会话复用本地法律工具，保存检索步骤、经核验的引用、任务与历史；材料通过图形界面选择。
- 文书预览采用安全排版，支持编辑和历史版本，默认导出中文 A4 PDF，另提供真正排版的 DOCX 与纯 TXT。
- 便携包内置 Pdfium、Typst 和中文字体；现有 Web 工作区升级前自动备份，原始法律库和既有案例检索增量保留。
- 此次仅交付本地增量与便携包，不自动发布 GitHub；具体验收证据见 `docs/web/ai-validation.md`。

## [1.1.0] - 2026-09-09

### Added

- 新增最高人民法院案例 sidecar `data/runtime/judicial_cases.sqlite`，重点覆盖发行清单声明的指导案例，并纳入官方参考案例；案例来源说明和 `judicial_cases_manifest.json` 随包提供。
- WebUI 法律检索增加案例模式、指导/参考类型筛选、案例详情和官方来源快捷链接；案例库在本机只读检索，缺失或不兼容时明确显示不可用。
- 新增“AI 理解案例搜索”：用户明确选择已有 Provider 后，仅发送本次输入提取检索词和争点，结果仍由本地真实案例库返回。
- MCP `public_law_only` 增加只读 `legal_search_cases`、`legal_get_case`，公开工具共七项；`privacy_workspace` 共十项。HTTP 和 stdio 均保留旧五个法律工具的输入输出契约。
- 便携包校验案例 manifest 的文件大小、SHA-256、schema、记录数量和最高人民法院官方来源，并发行案例库、来源说明和 manifest。

### Changed

- 默认运行时自动发现与 `legal_core.sqlite` 同目录的 `judicial_cases.sqlite`；法条库文件身份、路径和检索契约保持不变。
- 便携包版本和文档更新为 `1.1.0`；包内仍不包含用户工作区、缓存原文、凭据或 Provider 密钥。

## [1.0.0] - 2026-09-09

### Added

- Rust `lawyer-assistance` 本机后台服务，提供 loopback HTTP API、会话认证、任务恢复和嵌入式静态 WebUI。
- 普通 HTML/CSS/JavaScript WebUI，直接嵌入 server 二进制，不依赖 Tauri、WebView2 或前端开发服务器。
- TXT/DOCX 导入、正文和表格提取、规则与词典识别、稳定别名、替换、残留检查、复核、撤销，以及 TXT/Markdown/重建 DOCX/ZIP 导出。
- 本地只读法律检索、条文详情、历史版本、效力日期、关联法规和收藏。
- `privacy_workspace` MCP 的 `submit`、`status`、`read_result` 三个工作区工具，同时保留公开法律五工具；私有 profile 共八个工具。
- Windows 无窗口 `Lawyer-Assistance.vbs` 启动器、认证 `Stop-Lawyer-Assistance.vbs` 停止器，以及包含运行时法律库和当前文档的 x86_64 便携 ZIP 打包流程。

### Changed

- 工作区数据使用 `%LOCALAPPDATA%\LawyerAssistanceWeb`；旧 Tauri 案件、材料、映射、授权和其他用户数据保持不变，不读取、不迁移、不覆盖。
- MCP public/private profile 共用本机后台的业务边界；`approved_case_workspace`、`redacted_case` 和 `diagram_authoring` 明确停用，不兼容映射。
- 版本与结果流程支持任务恢复、取消、重试、冲突复核、结果撤销和有效版本检查。

### Breaking changes

- Tauri 窗口、IPC、WebView2、安装器、签名、updater 和旧资格发布链不再属于 v1.0.0 运行或发布路径。
- 首版输入限定 TXT 和 DOCX；PDF、图片、扫描件 OCR、原件版式保留、复杂案件工作台、法律图谱和自动办案流程没有入口。OCR 仅保留扩展接口，不安装或发布运行时。
- 公开法律 MCP 固定为五个工具；`privacy_workspace` 固定为八个工具。停用的旧 profile 返回 `profile_disabled`。

### Security and release boundaries

- Provider 密钥保存后读回校验，无法读取或内容不一致时明确返回保存失败。
- 原始材料、映射、凭据和用户数据不进入便携包、日志、公开 MCP 或未经授权的 Provider；MCP 私有结果只返回已发布脱敏文本。
- 便携包未签名，不提供安装器或自动更新器；发布资产须通过 ZIP SHA-256 和包内 manifest 校验。
- 本次公开发布未完成真实 Provider 联调；疑难云辅助和自动化回归使用可控模拟服务。合成材料的通过率、误报和漏检统计用于回归验证，不构成真实案件精度保证。
