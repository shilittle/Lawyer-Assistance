# 快速开始

## 运行便携包

1. 下载并在 Windows x86_64 上解压 GitHub Release 资产 `Lawyer-Assistance_1.0.0_windows-x86_64-portable.zip`。
2. 使用同名 `.zip.sha256` 校验 ZIP；再查看包内 `MANIFEST.sha256` 和 `portable.manifest.json`。
3. 双击 `Lawyer-Assistance.vbs`。它通过 `wscript.exe` 隐藏窗口运行 `lawyer-assistance.exe serve --open --port 8877`。
4. 浏览器访问 `http://127.0.0.1:8877`。数据目录默认是 `%LOCALAPPDATA%\LawyerAssistanceWeb`。便携包为未签名产物，不含安装器或自动更新器。

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

省略 `--legal-db` 时，server 会依次查找可执行文件旁的 `data/runtime/legal_core.sqlite` 和当前目录下的同名路径。法律库缺失只会阻断法律检索，不会改写用户工作区。

## 材料脱敏

1. 在“材料脱敏”中创建材料组并维护组级词典。
2. 选择 TXT 或 DOCX 文件，提交导入任务。TXT 编码不明时选择编码后重试；不会静默吞掉乱码。DOCX 的正文和表格会提取，图片、嵌入对象、修订或不支持结构会在任务状态中明确标记。
3. 查看识别出的姓名、机构、地址、电话、邮箱、证件、案号和账户等片段。系统为同组实体分配稳定别名，并在本地执行替换和残留检查。
4. 对待复核片段补充词典、修改别名、标记误报，或者为当前材料版本和具体 Provider/模型/用途授权一次云辅助。云辅助只接收提取文本，返回的候选必须由本地验证后才能替换。
5. 提取完整、无冲突、别名一致且残留检查通过时，任务生成不可变可用结果。失败或待复核状态不能从 MCP 读取。
6. 在结果页导出 TXT、Markdown、重建 DOCX，或选择多个可用结果导出 ZIP。导出会重新读取并检查生成文件。

## 法律检索、模板和对话

法律检索支持关键字、法律/条文详情、历史版本、效力日期和关联法规；结果可收藏和复制引用。固定模板从表单生成预览并导出 TXT/Markdown/DOCX。Provider 对话只发送用户主动输入以及明确选择的法条和有效脱敏结果，不自动读取原始材料。本次公开发布未完成真实 Provider 联调，相关验证使用可控模拟服务。

## MCP

公开 profile 使用独立程序：

```powershell
lawyer-assistance-mcp --privacy-profile public_law_only `
  --legal-db "$pwd\data\runtime\legal_core.sqlite" stdio
```

它固定暴露五个公开法律只读工具。`privacy_workspace` profile 共八个工具（五个公开工具加上 submit/status/read_result），要先在“设置”创建客户端 token，再通过已运行的 loopback server 调用；配置收件目录和材料组后，只使用目录下相对路径。该 profile 不会读取原文、映射、原始文件名或磁盘路径。

## 限制

当前不接受 PDF/图片、扫描件 OCR 或原件版式保留。OCR 只保留扩展接口。疑难云辅助使用可控模拟服务验证；合成材料的通过率、误报和漏检报告不能作为真实案件精度保证。不要把便携 ZIP 或源码构建称为签名安装器、正式 updater 或 OCR 资格资产。
