# 打包、迁移与回滚

## 发布包内容

平台发布包包含：

- `lawyer-assistance-mcp` 二进制；
- 许可证和第三方声明；
- `RELEASE_NOTES.md` 与 `docs/mcp/`；
- public-only 的 WorkBuddy/Codex/OpenCode 集成资产；
- `MANIFEST.sha256`。

不得包含 `legal_core.sqlite`、`user.sqlite`、案件材料、OCR 输出、导出文书、Bearer、票据、Credential Manager 内容、机器本地配置或 Provider Key。

App 已接入受约束的本地 MinerU worker、组件管理与资格链，但安装 App 本身不等于 OCR 已获生产授权。只有签名组件目录、固定版本 worker/model、完整性与本机 GPU/运行时检查、Windows Firewall 隔离、合成 canary 和当前环境重测全部通过后，扫描材料才可进入本机 worker；其余状态一律 fail closed。组件包可从项目固定 GitHub Release 下载，但组件管理 API 不接收案件材料，OCR 处理没有 HTTP、SSH、云服务或远程回退。

## Profile 固化

发布的 stdio 示例显式传入 `--privacy-profile public_law_only`；Codex 再设置精确五工具 `enabled_tools`，OpenCode 通配权限为 `deny`。HTTP 服务端也必须使用 public-only，并在宿主连接后核对五项。

不要把实验 `redacted_case` 设为默认配置；App 仍不签发其旧 `citation_validate` 用途票据。`diagram_authoring` 永久只处理合成/公开数据，并生成明文本地 HTML bundle，不能进入批准案件 package。正式案件宿主能力位于独立的 `approved_case_workspace` package：精确五项公开工具、十项 opaque-ID-only 案件/成果工具和六项批准图示工具，共 21 项，并要求当前 App 资格、policy-v2 standalone session、精确 generation 与逐调用 ticket。旧宽泛案件 patch、任意路径材料导入、旧文书生成和路径导出工具不属于发布面。

policy v2 有 16 个非公开 grants：`read=8`、`write=2`、`diagram_read=4`、`diagram_write=2`。旧 read/write 集合保持不变；升级时必须停止旧 host、撤销全部旧 session 并重新创建，不能把旧 descriptor、Credential Manager state 或 replay journal 迁移成新权限。批准 diagram render/update 进入加密 protected HTML work-product store，export 只返回 descriptor metadata，无 path/URI/HTML。

## 升级

1. 停止 App、stdio 子进程和 HTTP 服务。
2. 备份用户库及 SQLite 辅助文件；另行记录当前二进制与法律数据 manifest。
3. 校验新包的 manifest、签名和平台目标。
4. 显式运行用户库迁移命令；失败则保留原库，不启动新服务。
5. 使用 `public_law_only` 启动，验证 `tools/list` 精确五项和 `system_status` ready。
6. 用无客户数据的公开法律查询完成检索、版本、条文和关系 smoke test。
7. 如需 approved profile，重建 policy-v2 session，用合成 opaque ID 核对 21 项和所选 grant group；在发布前用最终 paired binary 复跑 stdio/HTTP 的 case + diagram 正负向 E2E。

旧包或宿主配置若仍声明固定 12 工具、案件 proposal/apply、材料导入或文书导出，必须更换；不能通过放宽白名单兼容。

## 回滚

- 停止新服务后恢复与旧二进制匹配的完整数据库备份；不要让旧二进制打开已升级且不兼容的库。
- 恢复旧配置时仍保留 public-only profile 和五工具宿主白名单。
- 轮换可能暴露的 Bearer/Provider 凭据；数据库回滚不会删除宿主或 Provider 已保存的消息。
- App 本地导出文件、备份和文件系统快照不随数据库回滚自动删除。

## 可复现与发布验收

正式构建先生成固定 MCP sibling（签名版在 Authenticode 签名之后取值），再把该文件的 SHA-256 作为只读信任锚编译进同批 App；无信任锚的普通开发构建不得资格化 approved workspace。运行时仍重验 canonical path、文件身份、SHA-256、版本和 canary。打包器固定成员顺序、时间戳、所有权和权限，并生成逐文件 manifest。可复现哈希、签名、三平台 CI、真实宿主 public-only 验收、集成后 21-tool actual-binary stdio/HTTP 复跑和干净机安全检查都是发布运营门禁；本地单测或历史 15-tool E2E 不能替代。

早期 0.2.0 文档中的 12 工具包与案件闭环已被隐私 breaking change 取代，仅保留为历史，不得重新发布。
