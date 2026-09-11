# 当前发布状态

本页对应 v1.2.1。Windows 完整便携包、源码和 SHA-256 校验文件见 [发布页](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v1.2.1)，资产文件名附日期与提交。功能续修与验证边界见[独立复测记录](web/retest-1.2.1.md)，发布构建身份和便携包验证见 Release 附件 `release-validation.json`。

## 版本与交付

源码版本为 `1.2.1`，基于 V1.0.0 Web 工作区，使用 Rust server、纯 HTML WebUI 和 MCP。便携包由 `scripts/package_portable.py` 在本地生成：

```text
Lawyer-Assistance_1.2.1_windows-x86_64-portable.zip
Lawyer-Assistance_1.2.1_windows-x86_64-portable.zip.sha256
Lawyer-Assistance_1.2.1_windows-x86_64-portable.manifest.json
```

ZIP 构建内容包括两个 release 程序、`data/runtime/legal_core.sqlite`、同目录的 `judicial_cases.sqlite`、派生检索索引、`CASE_DATA_SOURCES.md`、案例 `judicial_cases_manifest.json`、Pdfium、Typst、中文字体、许可证/第三方 notices、当前文档、MCP 示例以及 `Lawyer-Assistance.vbs` 和 `Stop-Lawyer-Assistance.vbs`。打包器会核对两个数据库及其清单的大小、SHA-256、schema、数量和官方来源。

便携包与源码构建均为未签名技术产物，不包含安装器、签名文件、`.sig`、`latest.json` 或自动更新器。ZIP、`.zip.sha256` 和 JSON 清单作为一组发布附件提供。

## 可用能力

| 能力 | 状态 |
| --- | --- |
| 本机 server + loopback WebUI | 已实现，默认 `127.0.0.1:8877` |
| LLM 主导的材料脱敏 | 支持本地预扫描、LLM 定位、本地核验替换、LLM 查漏和残留检查 |
| PDF、图片和 DOCX 内嵌图片 | 文本页在隔离 worker 中本机提取，扫描及混合页按需使用已配置的视觉模型 OCR；可选择页/段落范围 |
| 脱敏输出 | 统一保存为 UTF-8 纯 TXT，批量操作可导出 ZIP |
| 本地法律检索 | 完整匹配集计数、法律归组/条文平铺、筛选、相关性和日期排序、分页 |
| 历史版本和关联法规 | 无日期默认当前有效版本；历史范围明确选择，正文支持分页读取 |
| AI 法律搜索 | 根据描述、附件或选定材料检索本地法条、版本和最高法案例，并保存历史 |
| 文书写作 | 模型根据案情写作，可调用本地法律工具；渲染预览、版本保存、纯 TXT/结构化 DOCX/默认 PDF 导出 |
| AI 会话 | 自动命名、手动改名、图形化材料选择、附件和本地法律工具；后台任务独立运行 |
| 模型设置 | 常见供应商预设、联网获取模型列表、多选启用及对话/脱敏/写作/OCR 分别配置 |
| `public_law_only` | 固定七个公开法律工具（含两个案例工具） |
| `privacy_workspace` | 七个公开法律工具加三个脱敏工具，共十个工具并使用独立 client token |

## 案例数据

`judicial_cases.sqlite` 是独立的只读最高人民法院案例 sidecar。当前主案例/合集数为 759：指导案例 279、参考案例 61、典型案例合集 419；来源清单保留 834 个 TXT 来源条目。典型合集可能包含多个案件，按一篇 `case_type=typical` 文章检索，不混入参考案例，也不把 834 个来源条目当成 834 个案件。指导案例 45 的主源保留洛阳市中级人民法院官方转载 URL、来源角色和权威机构。具体来源、哈希、状态和版本见 `data/runtime/CASE_DATA_SOURCES.md` 与 `data/generated/judicial_cases_manifest.json`。

## 升级与兼容

停止旧服务，生成或取得 v1.2.1 便携 ZIP，双击 `Lawyer-Assistance.vbs`。首次打开旧 Web 工作区时，后台会先创建并验证备份，再事务升级；分组、原件、字典、收藏、结果和会话保留。旧 Tauri 工作区不迁移。

停止服务时双击 `Stop-Lawyer-Assistance.vbs` 或执行 `lawyer-assistance.exe stop`；停止请求通过当前用户加密连接描述符、loopback 会话和 CSRF 校验，不会结束任意进程。浏览器关闭不会取消已接受的后台 AI 任务，未知云请求需要用户明确继续。

旧 MCP profile `approved_case_workspace`、`redacted_case` 和 `diagram_authoring` 返回停用错误，不映射到 `privacy_workspace`。原有五个法律工具的名称、输入和输出契约保持不变。

## 运行边界

- 云端视觉 OCR、LLM 脱敏、AI 搜索、文书写作和会话都依赖已配置的 Provider、模型和发送策略；失败、撤销或待复核状态不会自动发布结果。
- 国内官方预设默认允许发送用户选中的原文；自定义地址需要确认，未信任的供应商只能接收有效脱敏材料引用。原件、映射、私密历史和检查点由本机后台保护。
- AI 法律搜索只使用本地法条、版本和最高法案例，不联网检索法律资料；案例库不是全国裁判文书全集。
- 验收使用独立生成的虚构材料；测试指标不外推为真实案件准确率。最终便携包须以打包后的清单和验收结果为准。
