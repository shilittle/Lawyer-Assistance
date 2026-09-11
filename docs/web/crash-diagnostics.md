# 崩溃专项诊断

本工具只建立本地、限时、可审计的进程证据。它不能把一次受控进程终止解释为原始事故根因，也不能替代 WER 转储或 WinDbg 定位。

## 本地诊断入口

```powershell
.\lawyer-assistance.exe diagnostics --data-dir C:\isolated\diagnostic-check
```

此命令检查这一次命令进程自身的构建身份和日志写入状态，并在指定目录留下开始、阶段和终态记录；它不打开数据库，也不等同于检查已运行的 daemon。正常返回安全 JSON 和退出码 0，日志不可写或记录失败时返回退出码 1。观察实际 daemon 或 worker 时使用下面的 PID 采集器。

## 只读采集

先在独立合成工作区启动待观察的 daemon，取得它实际的 PID 和显式诊断目录。采集器不会自动寻找工作区，因此必须由操作者明确传入目录：

```powershell
python scripts/collect_crash_diagnostics.py `
  --pid 12345 `
  --duration-seconds 30 `
  --interval-ms 250 `
  --diagnostics-dir C:\isolated\diagnostics\process `
  --channel Application `
  --channel Microsoft-Windows-WER-Diag/Operational `
  --output C:\isolated\evidence\crash-12345.json
```

`--pid` 只接受一个已经运行的 Windows PID。采集开始时记录这个 PID 的父进程和当前可见的后代；后续新出现的后代也会被记录。每个身份只保留 PID、父 PID、角色、进程名、开始时间令牌，不保存完整可执行文件路径或命令行。资源曲线只保留工作集和私有提交量。

默认采集 10 秒，最长 600 秒，采样间隔必须在 100–10,000 毫秒之间。窗口结束、目标 PID 消失或 PID 被复用后立即停止；目标在窗口内消失时结果为 `failed`，并带有 `target_exited` 或 `target_pid_reused` 观察项。正常完成的窗口只有在显式诊断目录读到目标自身当前启动的 JSONL、且 Application/WER 查询没有缺失时才会是 `passed`。

输出文件和 stdout 都是同一份 JSON。顶层 `status` 只有四种值：

- `passed`：目标完整经过窗口，安全日志及请求的事件通道都可读。
- `failed`：目标退出、PID 复用、事件 XML/日志损坏或读取过程中发生不可恢复错误。
- `blocked`：目标在采集前不可见、没有权限、事件日志工具不可用，或显式诊断目录不存在/没有目标记录。
- `not_run`：参数非法或使用 `--duration-seconds 0`。

退出码分别为 0、1、2、3。`process_diagnostics.status` 和 `logs.status` 单独记录各自是否缺失；缺少日志不会被写成成功。事件日志只查询 `Application` 与 `Microsoft-Windows-WER-Diag/Operational` 中的 1000/1001，结果只保留事件编号、提供者、级别、时间和是否命中目标 PID/进程名。原始 XML、事件消息、应用路径、模块路径、正文和令牌不会写入证据。

进程 JSONL 只接受固定字段投影：构建提交、EXE 哈希状态、启动关联、PID/父 PID、角色、阶段、操作编号、结果、错误类别、终止意图、原生退出码、回收状态、stderr 丢弃计数、内存和受限 panic 地址。未知字段、未知事件、无关 PID 和不合规字符串会被丢弃；文件超过 256 KiB、单行超过 64 KiB 或出现坏 UTF-8/JSON 时标记 `failed`。采集器不读取 dump、不启用 WER LocalDumps、不安装驻留程序、不自动重启、不上传，也不会修改既有系统配置。

进程 JSONL 中父进程和后代记录只提供上下文，不能单独证明目标进程写过日志。Windows 的进程创建 FILETIME 会转换为 `target_start_unix_ms`；同一 PID 在该时刻以前的旧记录保留为 `target_pid_before_current_start`，但不会计入 `target_event_proof`，因此“只有父进程记录”或“只有 PID 复用前记录”会是 `blocked`。未能读取创建时间令牌时，目标 PID 记录会标为 `target_pid_unverified_start`，仍不会把父子记录当作目标证明。

`--since` 和 `--until` 为 Application/WER 查询以及进程日志设置明确的时间边界；省略 `--since` 时，进程日志仍可读取采集开始前的启动记录，但会按目标创建时间排除旧 PID 记录。不改变当前 PID 的资源采样窗口。时间不完整或上界早于下界会产生 `not_run`，不会扩大查询范围。

## 配对诊断构建

诊断构建要求仓库已经提供：

```toml
[profile.diagnostic]
inherits = "release"
debug = 2
```

这保留现有 release 的优化和 codegen 设置，只为单独的诊断构建打开符号。构建脚本默认使用仓库 `target` 下独立的 `diagnostic` profile（也可用 `--target-dir` 指定独立目录），执行锁定、离线构建，并把匹配的 EXE/PDB 放进一个新的目录：

```powershell
python scripts/build_diagnostic.py `
  --root . `
  --target-dir C:\isolated\cargo-target `
  --output C:\isolated\diagnostic-build-<revision>
```

`diagnostic-build.json` 绑定 Git revision、dirty 状态、Cargo/rustc 版本、`Cargo.lock` 和 `cargo metadata` 哈希、目标/包/profile、EXE/PDB 字节哈希，以及 PE CodeView RSDS 与 PDB Info stream 的 GUID/age。Cargo metadata、构建和工具版本命令各写入独立 JSON 日志，保留命令、退出码、耗时、stdout 和 stderr。脚本先检查源构建产物，再检查复制后的产物；任一配对不一致都失败。PDB 的嵌入源码路径不进入清单，也不能把新 PDB 与旧 EXE 混用。构建目录必须是新目录，已有证据不会覆盖。该脚本须在 `[profile.diagnostic]` 已由仓库构建配置提供后运行；配置缺失时只写入 `blocked` 清单，不会伪造构建产物。

当前工作单只允许在隔离合成工作区或经授权的备份副本上采集。没有原始事故的 PID、操作时间、二进制字节和系统事件时，报告结论应保持 `unconfirmed`；受控内存限制、panic、取消或子进程终止通过，只能证明诊断链和故障隔离有效。

主 EXE 的安全日志保存其 SHA-256 和 CodeView 标识。panic 栈保留模块名、基址、偏移及绑定状态；其他 DLL 的帧标为 `unbound_module`，不能单凭模块名或偏移声称已匹配某个 DLL 版本。运行时资源哈希应与同次采集一并保留，旧程序不能套用新建 PDB。

`exit_source: natural` 表示父进程在主动清理前已观察到退出码，并不表示正常退出或已排除外部终止。取消、超时等由父进程发起的终止会先记录意图，再把随后观察到的退出标为 `after_cleanup`。外部终止须结合采集窗口、系统事件或明确的测试控制记录判断，不能只用一个退出码确定原因。

## 合成环境回归

`scripts/audit_process_diagnostics_native.mjs` 使用独立临时工作区、固定合成 PDF 和本地 mock，验证 14 个诊断门禁。它需要用 `build_document_fault_test.py` 单独构建的测试 EXE、普通生产 EXE，以及通过既有原生预检的本地 Pdfium/公开库副本。`--scope process` 只运行不依赖 PDF 渲染的前 7 项，供 Windows CI 使用。测试程序的故障入口不会进入普通或 diagnostic 构建；不得把测试 EXE 放入交付程序目录。完整既有 43 项门禁仍由 `scripts/audit_validate.py --phase all` 单独记录。
