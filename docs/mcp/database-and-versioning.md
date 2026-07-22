# 数据库与版本

## 数据库角色

- `legal_core.sqlite`：只读公开法律数据。`public_law_only` 的检索、条文、版本和关系查询只访问该法律数据边界。
- `user.sqlite`：桌面本地案件数据和运行迁移所需用户库。当前 MCP 配置仍要求兼容用户库，`system_status` 会报告其安全状态，但 public-only 工具不会读取或写入案件状态。
- privacy database 与 encrypted Vault：只由 App native backend/Broker 使用，保存复核、mapping、qualification、lifecycle 与加密案件对象；MCP 不取得数据库路径、Vault root 或解密能力。
- approved workspace/work-product store：只保存不可变已批准 generation、最小公开元数据和脱敏成果。work product 每个版本的 exact file set 是 `content.envelope.json`、签名 `manifest.json` 与 `commit.json`；正文使用 fresh AES-256-GCM key/nonce 加密，数据 key 由 DPAPI CurrentUser 包装。只允许 scoped `WorkProductService` 在 manifest/commit/hash/source/revocation/filesystem/residual 全部通过后鉴权解密；MCP 不取得 Vault、mapping、root 或通用解密能力，旧明文 `content.bin` fail closed。撤销会阻断后续 list/read/update/export。
- 票据/session 状态：实验 `redacted_case` 第六项仍要求其独立票据，但 App 不签发该 legacy purpose。`approved_case_workspace` 使用 App 生产签发的 DPAPI-protected descriptor、Credential Manager session secret、持久化单次 ticket consumption 和 revocation state；密钥不存明文数据库，缺任一条件都拒绝。

当前 schema 兼容值为：法律归档 `4`，法律运行时 `1`（存在该元数据时），用户库 `10`，MCP 服务 schema `1`。

## 启动与迁移

`stdio` 和 `serve` 只验证，不隐式创建或迁移用户库。初始化/升级必须显式执行：

```text
lawyer-assistance-mcp --user-db /absolute/path/user.sqlite init-user-db
```

迁移前备份主文件及 SQLite `-wal`/`-shm` 辅助文件；停止 App/MCP 写入后再复制。新二进制遇到更高未知 schema、损坏库或不匹配发行物时 fail-closed，不覆盖原库。

## Public-only 数据路径

公开五工具不得：

- 读取案件表、材料正文、附件路径或导出记录；
- 写入案件、材料、文书或审计业务记录；
- 把 `user.sqlite` 中的数据拼入公开法律响应；
- 把数据库绝对路径或底层 SQLite 错误返回宿主。

配置中的 `allowed_roots` 与 `output_root` 只是当前运行结构的必填项，不代表案件导入/导出可用。部署应指向专用空目录。

## 法律数据版本

`legal_core.sqlite` 的 dataset name/version、distribution profile、schema 和 manifest hash 必须彼此匹配。历史检索使用公开基准日期选择版本；缺失版本保留为警告或错误，不用现行条文静默填补。

发布包不携带多 GB 法律库。归档全库与运行时投影分别校验，不能把其中一个的大小、哈希或覆盖率冒充另一个。

## 票据、paired binary 与备份

本地 DPAPI 保护意味着受保护 blob 绑定 Windows 用户/机器上下文；复制单个数据库并不自动迁移可用密钥，也不能恢复 approved session。实验票据有短 TTL、撤销状态和目的地/用途绑定；恢复旧数据库不能复活过期、已消费或撤销票据。

formal App 还把 exact paired MCP sibling 的 SHA-256 编译为 trust anchor。运行时只有 sibling path/file identity/hash/version/behavior 与该值及当前 App/workspace/server/transport/epoch 全部匹配，才能持久化 approved-MCP qualification。复制、重命名或用同名 binary 替换数据库旁文件不能迁移该能力；ordinary unbound development App 必须 fail closed。

完整恢复使用新建的 `.lavbackup` V3：它把 `user.sqlite`、encrypted privacy bundle、ciphertext-only encrypted Vault archive、approved-workspace archive 与 encrypted work-products archive 绑定为一个 DPAPI CurrentUser 五组件包，并在重启时作为单一事务安装或全量回滚。V2 三组件包只保留读取/恢复兼容，V1 fail closed。`.lavprivacy` 只是 privacy-database-only 维护格式，不恢复完整应用。成功恢复还会轮换 MCP ticket key 与 qualification revocation epoch，并撤销 authenticated standalone sessions；任何备份都不自动授权 MCP/Provider 外发，恢复后仍须重建当前 qualification/session/ticket。

App 已能为 `approved_case_workspace` 与独立 approved Provider 正向链签发生产授权；它仍不为 legacy `redacted_case/citation_validate` purpose 签票。本地批准/导出记录本身不能开启外发，必须再满足 exact destination/purpose、expiry/revocation 和当前环境绑定。
