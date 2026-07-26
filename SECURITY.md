# 安全政策 / Security Policy

## 支持版本

当前仅维护最新的 `0.4.x` 技术预发布。请先确认问题能够在最新 Release 或当前 `main`
复现。

## 报告安全问题

请优先使用 GitHub 仓库的 **Security → Report a vulnerability** 私密报告入口。不要在
公开 Issue、Discussion、PR、日志或截图中提交：

- 真实案件、客户或当事人信息；
- 原始文书、OCR 文本、数据库或备份；
- API Key、token、证书、私钥或 session descriptor；
- 能识别个人、机构或本机环境的绝对路径和完整日志。

报告应包含最小化的合成复现、受影响版本、预期/实际行为和影响范围。若无法使用私密
入口，请先创建不含漏洞细节和敏感数据的普通 Issue，请求维护者提供安全联系方式。

## 发布边界

`0.4.0-beta.2` 是未签名技术预发布。未知发布者提示本身不等于漏洞，但被重新命名、
hash 不匹配或来源不明的安装包应视为不可信。生产 OCR 与自动更新当前未启用。

## English

Only the latest `0.4.x` technical prerelease is maintained. Prefer GitHub's
private **Report a vulnerability** flow. Never include real case data, source
documents, OCR text, databases, backups, credentials, private keys, session
descriptors, identifying paths, or raw logs in a public report.

Provide a minimal synthetic reproduction, affected version, expected and actual
behavior, and impact. `0.4.0-beta.2` is an unsigned technical prerelease;
production OCR and automatic updates are not enabled.
