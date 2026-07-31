# Rust loopback 测试夹具 CI 稳定化计划

## 1. 状态与目的

本文冻结一个独立于产品 Phase 6 和 MinerU qualification 修订的 CI 前置修订。
它只稳定三处既有 Rust 测试夹具的就绪、存活和关闭生命周期，不改变任何产品运行
逻辑、Provider 出站语义、审批边界或下载行为。

MinerU qualification PR #7 必须保持独立且继续为 Draft。本修订先从
`main@a7a314bc56f6ed0e10aeaea61f1d579c164013ce` 独立合入；随后 PR #7
rebase 到新的 `main`，并从新 head 重新完成同一提交的完整 CI 首跑和两次独立
全量 rerun。

## 2. 触发证据

以下失败所用的 Rust 夹具代码与 Phase 5 合并时相同，且不在 PR #7 的三个修改
路径内：

- `main` CI run `30611014721` attempt 3：
  - `download_tests.rs:96` 的本地 HTTPS Python 子进程在固定 5 秒轮询内没有发布
    端口；
  - `approved_provider_tests.rs:537` 的多任务 loopback Provider 在固定 60 秒
    server lifetime 后出现 Network 失败；
- PR #7 CI run `30620432632`：
  - attempt 1 在 `adapter.rs:2725` 的 approved chat loopback fixture 出现
    Network 失败；
  - attempt 2 同一测试和全部 CI 通过；
  - attempt 3 在完全相同位置再次出现 Network 失败，其他 92 个 Provider 测试
    通过，MinerU qualification 已通过。

本机在移除旧 observation window 后的连续目标测试进一步捕获到一种等价失败：
reqwest 已收到响应，但 fixture 记录的请求为零字节。Windows 上非阻塞 listener
派生的 accepted socket 可继续处于非阻塞模式；旧 helper 在请求字节到达前收到
`WouldBlock` 后就误判读取结束，提前写响应并关闭连接。该行为可表现为 Network、
响应正文截断或零字节请求，必须作为同一夹具生命周期缺陷一并关闭。

这三处均使用 `127.0.0.1:0` 并持续持有已绑定 listener，因此没有证据表明是端口
选择竞争。重复失败指向测试夹具依赖 600 毫秒、150 毫秒、5 秒或 60 秒固定墙钟
窗口，且缺少显式的就绪—存活—关闭所有权协议。

## 3. 允许范围

本修订只允许修改：

- 本计划文档；
- `crates/providers/src/adapter.rs` 的 `#[cfg(test)]` 测试和测试 helper；
- `apps/desktop/src-tauri/src/mineru_components/download_tests.rs`；
- `apps/desktop/src-tauri/src/privacy_workflow/approved_provider_tests.rs`。

明确禁止修改：

- 生产 Provider adapter、transport、DNS、timeout、重试或错误映射；
- Provider qualification、批准票据、一次性消费、出站分类或 canary 断言；
- MinerU 生产下载、组件安装、OCR、GPU 或 qualification 逻辑；
- Privacy、MCP、IPC、schema、migration、备份/恢复或 UI；
- CI workflow、`continue-on-error`、自动重试、测试跳过、全局
  `--test-threads=1` 或断言弱化。

本修订不得调用真实或付费 Provider、真实 MinerU/GPU、网络 OCR或真实案件材料。

## 4. 冻结实现契约

### 4.1 Provider crate approved JSON fixture

`spawn_approved_json_fixture` 必须改为有所有权的测试夹具：

- listener 仍由父线程同步绑定到 `127.0.0.1:0`；
- server 线程通过有界 ready channel 明确声明已进入服务循环；
- 服务存活到测试显式 shutdown，不再使用 600 毫秒 observation window，也不在
  收到首个请求后启动 150 毫秒退出窗口；
- 每个 accepted socket 必须显式切回 blocking，再设置有界 read timeout；不得把
  非阻塞 `WouldBlock` 当作完整 HTTP 请求；
- 正常 finish 返回捕获的请求；`Drop` 也必须发送 shutdown 并 join，保证测试
  panic 时不残留线程；
- 每个请求仍有有界读取 timeout，且不得新增请求重试。

三个既有测试必须继续精确证明：

- approved chat 只产生一个真实 HTTP 请求，授权 replay 在 transport 前失败；
- tampered body 和 expired authorization 都产生零 HTTP 请求；
- wire 中不含 raw canary、手机号、receipt 或额外字段。

正向测试必须在 ready 后故意等待超过旧 600 毫秒窗口再发送，以确定性证明
listener 的存活由显式 shutdown 控制，而不是依赖扩大旧 sleep。

### 4.2 Desktop approved Provider fixture

`spawn_test_server` 必须返回 RAII 测试夹具：

- 使用有界 ready channel；
- 服务到达 `expected_requests` 后可正常结束；
- 在请求未齐时只接受显式 shutdown，不再以固定 60 秒作为正常关闭条件；
- accepted socket 显式切回 blocking，并继续使用有界 request read timeout；
- 正常 finish 返回全部请求；`Drop` 负责 shutdown 和 join；
- 保留精确请求数量、每个固定任务、protected prior readback、零 raw canary 和
  一次性批准断言。

不得增加 Provider 请求重试或放宽产品 transport timeout。

### 4.3 MinerU 本地 HTTPS Python fixture

Python 子进程必须在 spawn 成功后立即进入 RAII guard，再开始等待端口文件：

- 使用有名称的 30 秒测试就绪上限；
- 每次轮询同时检查 `child.try_wait()`，区分“子进程提前退出”和“就绪超时”；
- 任一失败路径都由 guard 执行 kill（如仍存活）和 wait；
- 成功后把同一 child 所有权转移给 `LocalHttpsServer`，其既有 Drop 继续负责
  收敛；
- stdout/stderr 继续丢弃，错误只报告稳定状态类别和退出状态，不得输出临时路径、
  证书、payload、环境变量或 secret。

生产下载 client 的连接 timeout、总 timeout、TLS pinning、完整性检查和清理语义
保持不变。

## 5. 确定性测试与安全断言

实现必须新增或保留以下证据：

1. Provider 正向 loopback 在 ready 后延迟超过旧 600 毫秒仍成功；
2. replay 仍是零额外请求，不允许以 retry 掩盖失败；
3. 两个 Provider 零网络负例在显式 shutdown 后返回空请求；
4. desktop 多任务 fixture 精确接收全部预期请求后退出；
5. desktop 单请求和 prior-output 流程精确计数不变；
6. MinerU 本地 HTTPS 成功下载与 hash 失败清理测试继续通过；
7. 静态审计确认旧 600/150 毫秒和 60 秒 server lifetime 已移除，30 秒只用于
   Python fixture 的就绪上限，两个 Provider accept 分支都显式恢复 blocking；
8. 失败和 panic 路径不得残留测试线程或 Python 子进程。

## 6. 验证与合并顺序

1. 新建独立 `codex/ci-rust-loopback-fixture-stability` 分支；
2. 第一提交只包含本文；
3. 第二提交只包含三个允许的 Rust 测试文件；
4. Provider 目标测试连续运行至少 20 次；
5. 两个 desktop 目标测试各连续运行至少 5 次；
6. 运行 `cargo fmt --all --check`；
7. 运行
   `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`；
8. 完整 `cargo test --locked --workspace --all-targets --all-features`
   连续运行至少 3 次；
9. 独立 PR 的完整 Windows CI 首跑和同一 head 两次独立全量 rerun 均全绿；
10. 合并后确认 `main` CI 全绿；
11. PR #7 rebase 到新 `main`，确认仍只有其冻结的 qualification 三个路径和
    docs-first 提交顺序，再从新 head 重做三次全绿门禁；
12. PR #7 合并后，才继续 rebase Phase 6 两个提交。

MCP 三平台 workflow 如因路径过滤不触发，必须如实记录为不适用，并引用未被本
修订修改的最近 `main` 绿色基线；不得通过无关改动强制触发。

## 7. PR 证据与回滚

专项 PR 必须保留既定六部分说明：

- 影响范围；
- 数据迁移：无；
- 安全边界；
- 测试证据；
- UI 截图：UI 无变化，引用当前 `main` 基线图；
- 回滚方法。

回滚时先 revert 测试夹具实现提交，再按需要 revert 本计划提交。没有数据库、
evidence 或用户数据迁移；回滚不得改写或隐藏既有 CI 失败记录。
