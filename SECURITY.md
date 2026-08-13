# 安全政策 / Security Policy

## 支持版本

当前维护 `0.4.x` 源码与发布候选线。请先确认问题能够在最新已发布 Release、正式发布候选或当前
`main` 复现，并在报告中准确注明所用资产和 commit；不要把候选状态写成已发布 stable。

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

仓库版本源当前为稳定 `0.4.0`，但只有 `v0.4.0` 同一 Release 完成正式签名资产回读、
clean-machine、updater 和 MinerU qualification，并明确提升为 stable/latest 后，才能视为
正式发布。未知或不匹配的发布者、缺失 RFC3161 时间戳、被重新命名、hash/签名不匹配或
来源不明的安装包都应视为不可信；候选阶段不得宣称生产 OCR 或自动更新已经可用。

## English

The current `0.4.x` source and release-candidate line is maintained. Prefer GitHub's
private **Report a vulnerability** flow. Never include real case data, source
documents, OCR text, databases, backups, credentials, private keys, session
descriptors, identifying paths, or raw logs in a public report.

Provide a minimal synthetic reproduction, affected version, expected and actual
behavior, and impact. Repository version sources are fixed at stable `0.4.0`,
but only an official Release that has completed signing, exact-HEAD CI,
server-readback, clean-machine, updater, and final MinerU gates is a stable
release. Do not trust an unknown/mismatched publisher, a missing RFC3161
timestamp, a renamed file, or a hash/signature mismatch. Production OCR and
automatic updates must remain unavailable until their release evidence exists.
