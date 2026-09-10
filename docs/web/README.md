# Web 核心功能与运行边界

当前版本使用 Windows 本地 Rust 服务和嵌入式 HTML/CSS/JavaScript 页面，保留 V1.0.0 Web 工作区。日常使用不需要 Node 或 Python；Pdfium、Typst 与中文字体随便携包提供。

完整流程、供应商原文发送策略、OCR、法律检索、写作、会话及升级备份见 [AI 增量升级说明](ai-upgrade.md)。实际执行的验证结果见 [AI 增量验收报告](ai-validation.md)。

## 本机存储

默认工作区为 `%LOCALAPPDATA%\LawyerAssistanceWeb`，后台独占 `workspace.lock`。业务对象通过 Windows DPAPI 分块加密并绑定记录类型、ID 和位置。API Key 保存于 Windows 凭据管理器。

单份材料上限 20 MiB，每批最多 100 份、合计 100 MiB。结果有效期和撤销检查继续生效。任务可显式取消，浏览器断开不取消后台任务。原件版式不作为脱敏输出保留，成品统一为纯 TXT。

## 权限边界

Web 登录使用 HttpOnly cookie、CSRF、Host/Origin 检查和 no-store 响应。MCP token 与浏览器会话分开。公开 MCP 七个工具只读法律和官方案例库；私密工作区十个工具仅为已授权客户端提交相对收件路径、查询状态和分页读取有效脱敏结果，不返回原文和映射。

## 源码验证

```powershell
cargo test --locked --workspace --all-targets --all-features -- --test-threads=2
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
pnpm test
python -m unittest scripts.test_package_portable
```

[V1.0.0 历史验收](validation.md) 和 [旧合成回归说明](redaction-quality.md) 记录升级前的规则与云辅助行为，不能代替当前版本验收。
