# 快速开始

本页对应 v1.2.0。它在 V1.0.0 Web 工作区上增加了模型驱动的材料脱敏、完整分页法律检索、AI 法律搜索、文书写作和带法律工具的 AI 会话。详细升级步骤见[升级说明](web/ai-upgrade.md)，已执行的命令、真实模型调用、案例检索和限制见[AI 增量验收报告](web/ai-validation.md)。当前交付方式是本地 Windows 便携 ZIP、SHA-256 sidecar 和 JSON 清单；本文不表示 GitHub Release 已发布。

## 运行便携包

1. 使用 `scripts/package_portable.py` 生成或取得 `Lawyer-Assistance_1.2.0_windows-x86_64-portable.zip`，在 Windows x86_64 上解压。
2. 核对同名 `.zip.sha256`，再查看包内 `MANIFEST.sha256` 和 `portable.manifest.json`。
3. 双击 `Lawyer-Assistance.vbs`。它通过 `wscript.exe` 隐藏窗口运行 `lawyer-assistance.exe serve --open --port 8877`。
4. 浏览器访问 `http://127.0.0.1:8877`。数据目录默认是 `%LOCALAPPDATA%\LawyerAssistanceWeb`。便携包为未签名产物，不含安装器或自动更新器。

便携包包括法律库 `legal_core.sqlite`、同目录的案例 sidecar `judicial_cases.sqlite`、派生检索索引、案例来源说明和发行清单，以及 Pdfium、Typst、中文字体和 MCP 示例。案例 sidecar 的主案例/合集数为 759：指导案例 279、参考案例 61、典型案例合集 419；来源清单保留 834 个 TXT 来源条目。典型合集可能包含多个案件，仍按一篇 `typical` 文章检索；指导案例 45 保留洛阳市中级人民法院官方转载来源。完整来源和哈希见包内 `CASE_DATA_SOURCES.md` 与 `judicial_cases_manifest.json`。

停止服务时双击 `Stop-Lawyer-Assistance.vbs`，或者执行 `lawyer-assistance.exe stop`。停止请求必须通过当前用户加密连接描述符、loopback 会话和 CSRF 校验；该命令不会调用 `taskkill`。

已有服务运行时，可双击或在 PowerShell 运行 `lawyer-assistance.exe login`。旧 Tauri 数据目录不会被读取、迁移或覆盖。

## 从源码启动

```powershell
pnpm install
cargo run --release --locked -p lawyer-assistance-server --bin lawyer-assistance -- serve `
  --open --port 8877 `
  --data-dir "$env:LOCALAPPDATA\LawyerAssistanceWeb" `
  --legal-db "$pwd\data\runtime\legal_core.sqlite"
```

省略 `--legal-db` 时，server 会依次查找可执行文件旁的 `data/runtime/legal_core.sqlite` 和当前目录下的同名路径；找到法条库后，会在同一 `data/runtime` 目录自动发现 `judicial_cases.sqlite`。法条库缺失只会阻断法条检索，案例 sidecar 缺失只会使案例检索报告不可用，不会改写用户工作区。

## 材料脱敏

1. 在“材料脱敏”中创建材料组并维护组级词典。
2. 选择 TXT、DOCX、PDF、PNG、JPEG 或 WebP 文件，提交导入任务。PDF、图片和 DOCX 内嵌图片通过已配置的云端视觉模型 OCR；TXT 和 DOCX 正文先在本地提取。没有配置模型时，TXT/DOCX 仍可走本地流程，并在任务状态中如实标识。
3. 配置脱敏模型后，系统按“提取或视觉 OCR → 本地预扫描 → LLM 定位 → 本地核验和替换 → LLM 查漏 → 本地残留检查”处理。查看姓名、机构、地址、电话、邮箱、证件、案号和账户等片段；同组实体使用稳定别名。
4. 对待复核片段补充词典、修改别名或标记误报。云辅助必须绑定当前材料版本、Provider、模型和用途；国内官方预设默认允许发送用户选中的原文，自定义地址需要确认，未信任的供应商只能接收有效脱敏材料引用。
5. 只有提取完整、无冲突、别名一致且残留检查通过时，任务才生成不可变的可用结果。失败、待复核或已撤销结果不能从 MCP 读取。
6. 脱敏成品统一保存为 UTF-8 纯 TXT；批量操作可导出 ZIP。原始材料格式和排版不作为脱敏输出格式，导出会重新读取并检查生成文件。

## 法律检索、AI 搜索、文书写作和会话

法律检索默认按法律归组，也可切换为条文平铺。系统对完整匹配集计数后分页，不把结果截断为固定 20 条；支持类型、效力层级、地域、状态、案件日期筛选，以及相关性、效力、公布日期和施行日期排序。历史版本和关联法规默认打开，历史版本正文可分页读取。法条库使用本地只读 runtime 数据库。

切换到案例模式后，可按关键词、指导/参考/典型类型和指导案例编号检索，并打开案例详情及官方来源。案例库只覆盖来源清单声明的最高人民法院官方案例，不是全国裁判文书全集；典型合集按文章保存，不把一篇合集误计为一个单独案件。

AI 法律搜索可读取用户描述、附件或用户图形化选择的已脱敏材料。模型自行整理案情、调整关键词并多轮检索本地法条、版本和最高法案例；不联网搜索法律资料。引用标识和逐字引文由数据库核验，过程保存为历史记录。

“文书写作”根据案件描述、文书类型和其他要求组织正文，可调用同一套本地法律检索工具。生成后自动保存历史；预览显示渲染后的正文，不显示 Markdown 代码。TXT 是纯文本，DOCX 是结构化文档，默认导出 Markdown 渲染后的中文 A4 PDF。

AI 会话首次完整回答后自动生成标题，之后可以手动修改。用户可图形化选择材料并上传附件；会话 AI 可调用本地法律检索和案例工具。已接受的后台任务与浏览器生命周期分离，关闭页面不会取消任务，用户可以显式取消。

## MCP

公开 profile 使用独立程序：

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

它固定暴露七个公开法律只读工具：`system_status`、`legal_search`、`legal_get_article`、`legal_get_versions`、`legal_get_relations`、`legal_search_cases`、`legal_get_case`。其中两个案例工具访问同目录的最高人民法院案例 sidecar。`privacy_workspace` profile 共十个工具，另有 `privacy_workspace.submit`、`privacy_workspace.status` 和 `privacy_workspace.read_result`；要先在“设置”创建客户端 token，再通过已运行的 loopback server 调用。旧五个法律工具的 I/O 契约保持不变；公开 MCP 不读取原文、映射、原始文件名或磁盘路径。

## 限制

- PDF、图片和扫描材料的 OCR 依赖已配置的云端视觉模型；供应商、模型或请求失败时不会伪造 OCR 或发布结果。
- 本地案例库的范围、来源和状态以 `judicial_cases_manifest.json` 与 `CASE_DATA_SOURCES.md` 为准，不代表全国裁判文书全量覆盖。
- AI 搜索、文书写作和会话只使用用户明确选择且符合发送策略的材料；测试材料为独立生成的虚构内容，测试指标不外推为真实案件准确率。
- 便携 ZIP 和源码构建均为未签名技术产物；最终便携包须在交付前完成打包和清单验收，不应称为已发布的 GitHub 安装器、正式 updater 或签名资产。
