# 打包、迁移与回滚

## 发布包内容

平台发布包包含：

- `lawyer-assistance-mcp` 二进制；
- 许可证和第三方声明；
- `RELEASE_NOTES.md` 与 `docs/mcp/`；
- public-only 的 WorkBuddy/Codex/OpenCode 集成资产；
- `MANIFEST.sha256`。

不得包含 `legal_core.sqlite`、`user.sqlite`、案件材料、OCR 输出、导出文书、Bearer、票据、Credential Manager 内容、机器本地配置或 Provider Key。

实验 MinerU runner 代码不等于发布包内置可用 OCR。当前 App 未连接经过认证的 worker/model；不得随包偷偷下载模型、调用远程服务或把扫描件送出本机。未来若打包本地 GPU worker，必须单独完成模型来源/许可证、哈希、进程隔离、离线网络、更新与回滚审查。

## Profile 固化

发布的 stdio 示例显式传入 `--privacy-profile public_law_only`；Codex 再设置精确五工具 `enabled_tools`，OpenCode 通配权限为 `deny`。HTTP 服务端也必须使用 public-only，并在宿主连接后核对五项。

不要发布启用 `redacted_case` 的默认配置。当前 App 无法签发其 citation 用途票据，生产启用只会造成不可用或误导。案件读写、材料导入、文书生成和导出工具不属于当前发布面。

## 升级

1. 停止 App、stdio 子进程和 HTTP 服务。
2. 备份用户库及 SQLite 辅助文件；另行记录当前二进制与法律数据 manifest。
3. 校验新包的 manifest、签名和平台目标。
4. 显式运行用户库迁移命令；失败则保留原库，不启动新服务。
5. 使用 `public_law_only` 启动，验证 `tools/list` 精确五项和 `system_status` ready。
6. 用无客户数据的公开法律查询完成检索、版本、条文和关系 smoke test。

旧包或宿主配置若仍声明固定 12 工具、案件 proposal/apply、材料导入或文书导出，必须更换；不能通过放宽白名单兼容。

## 回滚

- 停止新服务后恢复与旧二进制匹配的完整数据库备份；不要让旧二进制打开已升级且不兼容的库。
- 恢复旧配置时仍保留 public-only profile 和五工具宿主白名单。
- 轮换可能暴露的 Bearer/Provider 凭据；数据库回滚不会删除宿主或 Provider 已保存的消息。
- App 本地导出文件、备份和文件系统快照不随数据库回滚自动删除。

## 可复现与发布验收

打包器固定成员顺序、时间戳、所有权和权限，并生成逐文件 manifest。可复现哈希、签名、三平台 CI、真实宿主 public-only 验收和干净机安全检查都是发布运营门禁；本地单测不能替代。

早期 0.2.0 文档中的 12 工具包与案件闭环已被隐私 breaking change 取代，仅保留为历史，不得重新发布。