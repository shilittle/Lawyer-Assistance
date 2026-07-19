# 数据库与版本

## 数据库角色

- `legal_core.sqlite`：只读公开法律数据。`public_law_only` 的检索、条文、版本和关系查询只访问该法律数据边界。
- `user.sqlite`：桌面本地案件数据和运行迁移所需用户库。当前 MCP 配置仍要求兼容用户库，`system_status` 会报告其安全状态，但 public-only 工具不会读取或写入案件状态。
- 隐私票据状态：实验 `redacted_case` 在执行第六项前需要持久化活动/撤销/provenance 状态和 Windows 保护的签名密钥。密钥不存明文数据库，缺任一条件都拒绝。

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

## 票据与备份

本地 DPAPI 保护意味着受保护 blob 绑定 Windows 用户/机器上下文；复制数据库并不自动迁移可用密钥。备份/恢复文档必须明确这一点。实验票据有短 TTL、撤销状态和目的地/用途绑定；恢复旧数据库不能复活过期或撤销票据。

App 目前没有为 MCP citation 或 Provider 案件发送签发生产票据，因此数据库中存在本地批准/导出记录也不能开启外发。