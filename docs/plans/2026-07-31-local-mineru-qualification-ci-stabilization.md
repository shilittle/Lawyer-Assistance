# Local MinerU qualification CI 稳定化计划

## 1. 状态与目的

本文冻结一个独立于产品 Phase 6 的 CI 前置修订。它只修复 Windows
托管 runner 对本地 PowerShell GPU test double 的非确定性超时，并增强超时诊断与
进程树收敛验证；不改变 Lawyer Assistance 的产品功能、正式资格结论或出站边界。

Phase 6 的前端-only 契约保持不变。Phase 6 PR 必须继续保持 Draft，直到本修订先
独立合入 `main`、合并后 CI 全绿，再把新的 `main` 同步回 Phase 6 分支。

## 2. 触发证据

以下运行都基于没有修改 qualification harness 的代码：

- `main@a7a314b` 的 CI run `30611014721` attempt 1、2 均在
  `Test local MinerU qualification harness` 超时；
- 同一 SHA 的 attempt 3 在同一步骤运行约 196 秒后通过，证明失败不是固定输入或
  Phase 5 业务回归；
- Phase 6 PR run `30614057402` 在同一步骤启动后约 71 秒失败；
- Phase 3、Phase 5 和当前 `main` 的 workflow、qualifier 与 harness Git blob
  完全相同；Phase 5 PR 曾在同一门禁通过；
- 本机用同一套纯 mock 脚本完整通过，没有调用真实 MinerU、真实 GPU、Provider
  或网络。

71 秒的失败严格早于 harness 中任何 MinerU mock 的最小 120 秒预算。当前只有
`Get-GpuMetadata` 对 `nvidia-smi` 进程硬编码 30 秒预算，因此该 fresh runner
失败可以定位到 `gpu_inventory` PowerShell test double，而不是 MinerU OCR
进程。

## 3. 允许范围

本修订只允许修改：

- 本计划文档；
- `scripts/qualify_local_mineru.ps1`；
- `scripts/test_qualify_local_mineru.ps1`。

如实现不需要，不新增 fixture、helper 或 workflow 文件。

明确禁止修改：

- Phase 6 UI、路由、activity、handoff、lazy bundle 或截图；
- Rust 业务逻辑、Privacy、Provider、MCP、IPC、schema、migration；
- 五组件备份/恢复、授权、出站、publication、grant、ticket 或撤销语义；
- 正式 OCR 资格状态、证据 schema 或发布声明；
- CI 的 `continue-on-error`、自动重试、跳过、降级或断言弱化。

本修订不得调用真实 MinerU、真实案件材料、网络 OCR、真实或付费 Provider。

## 4. 冻结实现契约

### 4.1 闭合进程身份

`Resolve-CommandDescriptor` 必须显式产生布尔字段
`IsPowerShellTestDouble`：

- `.exe` 或 `.com` 为 `false`；
- 仅测试使用的 `.ps1` 为 `true`。

不得根据 `PrefixArguments` 数量、runner 环境或调用位置隐式推断。

`Invoke-SanitizedProcess` 必须接收闭合 stage：

- `mineru_ocr`；
- `gpu_inventory`。

stage 只允许进入稳定诊断错误，不得进入 qualification evidence。错误不得包含
路径、命令、参数、设备信息、环境变量、stdout、stderr、hash 或 secret。

### 4.2 有效 timeout

顶层 `TimeoutSeconds` 的默认值 `1800` 和 `[10, 7200]` 边界保持不变。
有效子进程预算由一个无副作用的纯函数计算：

| stage | descriptor | 有效预算 |
|---|---|---|
| `mineru_ocr` | 两种 descriptor | 调用者的 `TimeoutSeconds` |
| `gpu_inventory` | `IsPowerShellTestDouble=false` | 固定 30 秒 |
| `gpu_inventory` | `IsPowerShellTestDouble=true` | `min(TimeoutSeconds, 120)` 秒 |

因此正式 MinerU 和真实 `nvidia-smi.exe` 的既有 1800 秒/30 秒 fail-closed
默认边界不变；只有 PowerShell GPU test double 从隐藏的固定 30 秒改为受顶层
参数约束且最多 120 秒的测试预算。`TimeoutSeconds=7200` 时，GPU test double
也不得占用 runner 两小时。

### 4.3 超时仍必须失败

任何超时都必须：

1. 终止既有进程树；
2. 在一个独立、固定且短的收敛窗口内确认根进程已经退出；
3. 返回包含闭合 stage 的非敏感稳定错误；
4. 不读取、记录或回显被丢弃的 stdout/stderr；
5. 不重试、不忽略、不自动降级，也不产生成功 evidence。

若无法确认进程退出，必须返回独立的非敏感 termination failure，仍视为失败。

### 4.4 Evidence 与迁移

不修改 qualification evidence JSON schema，不写入 stage、process kind、timeout
或本地诊断字段。现有 evidence 不自动重写、不迁移。

evidence 已包含 qualifier 的 `scriptSha256`。旧 evidence 只能证明旧脚本字节，
不能伪装成由新脚本生成；正式验收必须重新运行 qualification。

## 5. 确定性测试

### 5.1 纯 timeout 表

从 PowerShell AST 提取并执行纯 timeout resolver，精确覆盖：

- `mineru_ocr` + 两种 descriptor，输入 `10/120/1800/7200` 均等于输入；
- `gpu_inventory` + `IsPowerShellTestDouble=false`，任一合法输入均为 30 秒；
- `gpu_inventory` + `IsPowerShellTestDouble=true`：
  `10 → 10`、`120 → 120`、`1800 → 120`、`7200 → 120`；
- 未列出的 stage 必须被 `ValidateSet` 拒绝。

AST 还必须断言：

- 只有两个 `Invoke-SanitizedProcess` 调用点；
- 两者分别传固定 `mineru_ocr` / `gpu_inventory`；
- 两者都显式传递顶层 `$TimeoutSeconds`；
- GPU 路径不再出现隐藏的 `-TimeoutMilliseconds 30000`。

### 5.2 超时负向测试

从 AST 提取进程 helper 及其直接依赖，以一个只写自身 PID 后休眠的本地
PowerShell mock 验证：

- `gpu_inventory` + `TimeoutSeconds=10` 在有界时间内失败；
- 错误包含 `stage=gpu_inventory`；
- 错误不包含 test root、mock 路径或 secret；
- 根进程和子进程树均已终止；
- 没有产生 evidence，也没有自动重试。

### 5.3 既有门禁不得减少

保留当前 harness 的全部正负向检查，包括：

- 固定三页合成 canary、24 条精确 OCR 文本、页序、尺寸与 bbox；
- GPU 元数据与选定 CUDA 设备；
- offline/local 环境、secret/path 不继承且不进入 evidence；
- hash、版本、固定 backend/method/language；
- overwrite 拒绝、默认清理、显式 KeepArtifacts；
- bad OCR text 和 bad middle page size 必须拒绝；
- `TimeoutSeconds` 默认值与 `[10, 7200]` 边界；
- evidence 顶层结构没有新增 stage、descriptor 类型或 timeout 诊断字段。

## 6. 验证与合并顺序

1. 新建独立 `codex/ci-mineru-qualification-mock-stability` 分支；
2. 第一提交只包含本文；
3. 实现脚本和测试，不修改 Phase 6 分支；
4. 本机连续运行完整 qualification harness 至少 5 次；
5. 运行 MinerU worker/release builder 测试、PowerShell AST、UTF-8、
   `git diff --check`；
6. 因 qualifier 被桌面 Rust `include_str!`，运行完整 Rust 测试；
7. 独立 PR 的 Windows 主 CI 与三平台 MCP CI 全绿；
8. 对同一 head 独立 rerun 两次且均全绿，不在 workflow 内重试；
9. 合并稳定化 PR，确认 post-merge `main` CI 全绿；
10. 将 Phase 6 两个原提交 rebase 到新的 `main`，以
    `--force-with-lease` 更新 PR；Phase 6 diff 仍只包含冻结的产品范围；
11. Phase 6 PR 全套 CI 通过后才可转 Ready 和合并。

## 7. PR 证据与回滚

专项 PR 继续使用既定六部分说明：

- 影响范围；
- 数据迁移；
- 安全边界；
- 测试证据；
- UI 截图：明确 UI 无变化，并引用 `main` 的现有基线图；
- 回滚方法。

回滚只 revert qualifier 与 harness 实现提交，再按需要 revert 本计划提交。
没有数据库或 evidence migration；不得声称回滚会让新旧 `scriptSha256` 等价。
