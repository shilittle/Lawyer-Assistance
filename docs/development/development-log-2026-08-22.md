# 2026-08-14 至 2026-08-22 开发与发布审计日志

状态复核日期：2026-08-22。

## 范围与结论

本日志记录 `0.4.0` 最终候选源码的 exact-HEAD CI、unsigned evaluation prerelease、本机安装与启动测试。结论如下：

- `main` 基线提交 `4fd0d88caef5bca6d874e7f1bc290d604e9b172b` 的主 CI 和 MCP 三平台 CI 已通过。
- GitHub 已发布 `v0.4.0-unsigned-evaluation.1`，其性质是公开、非草稿、非 latest 的未签名评估预发布；它不是正式 `v0.4.0` stable/latest Release。
- exact-HEAD unsigned 安装包已在本机覆盖安装为 `0.4.0`，App 与配对 MCP 的版本和哈希均已复核。
- 安装后的 App 在既有混合预发布 profile 上按设计失败关闭，未创建窗口；未检测到持久化 profile 写入。
- Authenticode、updater、正式 MinerU 资产、Windows 10/11 clean-machine 与目标 GPU 资格门仍未闭合。

## 源码与 CI 基线

日志更新前的仓库和远端 `main` 均指向：

```text
4fd0d88caef5bca6d874e7f1bc290d604e9b172b
```

该提交的可复核 CI 证据：

- [主 CI run 31762817709](https://github.com/shilittle/Lawyer-Assistance/actions/runs/31762817709)：`push` / `main` / exact SHA，Windows x86_64 job 与 42 个步骤全部成功。Rust broad gate、两个 inventory=1 的隔离集成门、真实 approved MCP stdio/HTTP E2E 和 Tauri packaging smoke 均成功。
- [MCP server CI run 31762817760](https://github.com/shilittle/Lawyer-Assistance/actions/runs/31762817760)：Windows x86_64、Linux x86_64 与 macOS ARM64 三个 job 全部成功；三个 Actions artifact 的 provenance 均绑定同一 exact SHA、`0.4.0` 和对应 target。

上述证据只绑定 `4fd0d88…`。本日志或后续任何提交进入 `main` 后，正式发布仍须为新的 exact `main` SHA 重新取得主 CI 与 MCP 三平台 CI 证据。

## 2026-08-14 unsigned evaluation 发布

- Tag：`v0.4.0-unsigned-evaluation.1`
- Annotated tag object：`77c79b94c107c49f623f1dd9cf1e0f6e718c84cb`
- Peeled commit：`4fd0d88caef5bca6d874e7f1bc290d604e9b172b`
- Release：[Lawyer Assistance 0.4.0 unsigned evaluation 1](https://github.com/shilittle/Lawyer-Assistance/releases/tag/v0.4.0-unsigned-evaluation.1)
- 状态：已发布、非草稿、`prerelease=true`、`latest=false`

Release 仅包含三个明确标注为 unsigned evaluation 的资产：

| 资产 | 大小 | GitHub metadata SHA-256 |
|---|---:|---|
| `Lawyer.Assistance_0.4.0_windows-x86_64-unsigned-setup.exe` | 343,787,616 bytes | `a0eb12425285bb798a7ef9c6b249c59b7e23fad9e694730991ab917886412f05` |
| `Lawyer.Assistance_0.4.0_windows-x86_64-unsigned-setup.exe.manifest.json` | 1,622 bytes | `f62d4a7dfcd149ab4db485778f71e3c7ee8b4fe2bb7c9ba31fa2df60b22d58a2` |
| `Lawyer.Assistance_0.4.0_windows-x86_64-unsigned-setup.exe.sha256` | 124 bytes | `c689785250c39b7984dcffaed06378a9c12ee8ce9989178b63bb2fae95f04052` |

安装包的 GitHub metadata digest 与本机构建产物一致。一次全新目录完整下载因网络吞吐在 10 分钟内未完成，因此本日志不把它表述为完整的 fresh-byte 服务端回读。该预发布也不包含 `.sig`、`latest.json`、正式 portable/MCP 12 项 allowlist 或 MinerU 正式资产。

## 构建与本机安装

unsigned 安装包由仓库支持的 `apps/desktop/scripts/build_unsigned_installer_release.ps1` 从 exact 源码构建。首次构建在磁盘与并行编译资源压力下失败；清理 Cargo 构建缓存并将 `CARGO_BUILD_JOBS=1` 后，保持 locked/offline 依赖和原 release profile 的重试成功。没有为通过构建而修改源码、优化级别或工具链。

安装后复核结果：

| 项目 | 结果 |
|---|---|
| HKCU 安装版本 | `0.4.0` |
| App ProductVersion | `0.4.0` |
| App SHA-256 | `f85776fefa1581c8613da8d583eb112ee8b4734287c951466509ea75e39e8cd8` |
| App Authenticode | `NotSigned` |
| MCP `--version` | `lawyer-assistance-mcp 0.4.0`，退出码 0 |
| MCP SHA-256 | `26c15c9782816daa589d2b5713bf9e21bd96cbe9f08d776a015f63f249737ecb` |
| MCP Authenticode | `NotSigned` |

MCP 哈希与 unsigned build manifest 中的配对 MCP 哈希一致。

## 本机启动测试

已安装 App 被启动两次。两次均在约一秒内退出，未产生主窗口；首次观测到退出码 `101`，第二次捕获到相同 Rust panic：

```text
Failed to setup app: error encountered during setup hook: startup action failed:
the exact v0.3.1 source profile proof failed
```

既有本机 profile 为混合预发布状态：User schema 10、Privacy schema 4，并已有 Vault/Approved target state。它既不是升级器唯一接受的 exact v0.3.1 source（要求 Privacy schema 1 且目标状态认证为空），也没有完整的当前版本认证历史。因此只读 startup observer 在普通 manager、UI 或迁移写入前失败关闭。

只读后验审计记录：

- 启动后 production profile 中没有文件或目录的修改时间晚于启动时刻；未出现 WAL/journal、marker、receipt、lineage、backup、staging 或 quarantine 文件。
- 六个核心数据/配置文件和一个 operation lock 的大小、修改时间与启动前记录一致；Credential Manager 相关条目数量也未变化。
- Windows Application/WER 日志没有 App crash、WER report 或残留进程。
- 启动前没有为全部核心文件保存 SHA-256 基线，因此这里只能表述为“未检测到持久化写入”，不能倒推声称启动前后字节级完全相同。当前取得的核心文件哈希作为后续审计基线保留在本地验证记录中。
- 由于 App 未创建窗口，本次没有进行 UI 点击与功能流测试。

不得通过删除、改写或部分迁移该混合 profile 绕过失败关闭。若要继续本机 UI 验收，必须先获得明确授权，再对既有 profile 做可恢复备份与隔离；正式发布验收仍应在干净 Windows 10/11 环境中进行。

## 当前状态与后续门禁

截至 2026-08-22：

- GitHub 仓库公开，`v0.4.0-unsigned-evaluation.1` 仍是唯一 `0.4.0` 评估 Release；没有正式 `v0.4.0` tag 或 stable/latest Release。
- unsigned evaluation 证明构建、分发、安装和混合 profile 失败关闭路径，但不证明可信 Windows publisher、自动更新、正式 OCR、clean-machine 或生产资格。
- 正式发布仍需要有效 Authenticode 私钥与 RFC3161 时间戳、匹配 runtime 公钥的 updater 私钥、完整 12 项 App/MCP 资产、最终 MinerU 签名资产与审批、服务端完整回读、Windows 10/11 clean-machine 和目标 GPU 资格证据。

当前状态的用户向摘要见[当前发布状态](../release-status.md)。
