# Approved MCP 真实 HTTP 测试主 CI 隔离修订

> 日期：2026-08-14
>
> 状态：已冻结；作为
> [`v0.4.0` 发布计划](2026-08-01-v0.4.0-upgrade-release-and-publication.md)和
> [`v0.3.1` 真实重启测试隔离修订](2026-08-14-main-ci-v031-restart-test-isolation.md)
> 的第二个窄范围验证修订执行
>
> 触发基线：`main@ec06c14329890bd64a9d8e6c70135d65a569852f`

## 1. 触发证据

exact-main push CI run `31754643101` 的 broad Rust step 保留了完整
`workspace + all-targets + all-features` 覆盖，并只排除已单列的真实重启 parent。结果为：

- desktop lib：`765 passed / 0 failed / 10 ignored / 1 filtered`；
- 唯一失败发生在随后运行的 legal-mcp lib：
  `approved_backend::tests::approved_streamable_http_tcp_reads_writes_rereads_and_rejects_replay`；
- 该测试的 approved work-product 写入期望 HTTP `200`，实际由生产 HTTP deadline 返回
  `504`；legal-mcp lib 总计 `82 passed / 1 failed`，耗时 `84.43s`；
- 同一 lib 同时有三个 approved-backend sibling tests 超过 60 秒；
- 同一 SHA 的 MCP Windows job `94627704949` 已运行同一个 legal-mcp lib，得到
  `83 passed / 0 failed`，该测试明确成功；
- 本地以相同 package/lib/all-features、`--exact --test-threads=1` 连续运行 20 次，
  `20/20` 成功，每次测试体为 `0.39–0.46s`；inventory 精确为 1。

生产 `http.rs` 在读取 body 前取得并发 permit，并以配置的 request deadline 同时约束 body
和 downstream handler。deadline 到期后返回 `504 request_timeout`，后台任务继续持有 permit
直至真实写入结束，避免把未知写入结果错误地标为可重试。该状态机及 5 秒测试配置按设计
工作。本次失败只证明真实 TCP 正向测试在同一 libtest 的重型 sibling load 下超过测试预算，
不能用增大 deadline 或接受 504 来掩盖。

## 2. 允许范围与禁止项

本修订只能修改：

- 本计划文档；
- `.github/workflows/ci.yml`；
- `scripts/test_release_contract.py` 的 workflow 静态回归。

不得修改：

- legal-mcp、HTTP middleware、approved backend、SQLite、ticket 或 work-product 生产代码；
- 测试的 5 秒 server/client deadline；
- 对 `200`、业务 payload、ticket 不回显和 replay fail-closed 的断言；
- retry、rerun、`continue-on-error`、`#[ignore]` 或全 workspace 串行；
- 既有 `v0.3.1` real-restart 独立门禁；
- MCP 三平台 workflow 或资产 provenance。

本计划独立于 2026-07-31 loopback 夹具修订，不改写该历史计划。它处理该修订完成后、
`v0.4.0` exact-main 全量门禁中首次观测到的另一条真实 TCP fixture 调度证据。

## 3. 冻结实现

主 CI broad Rust 命令继续运行完整 workspace、全部 targets 和全部 features，只在该次并行
invocation 中使用两个完整 `--skip`：

1. 已由独立 Gate8 step 补回的 `v0.3.1` real-restart parent；
2. 本计划新增的 approved streamable-HTTP TCP 测试。

两个测试都不是被删除或忽略；broad step 后必须依次存在两个独立硬门禁：

1. `v0.3.1` real-restart inventory=1，随后 exact parent 运行一次；
2. approved HTTP inventory=1，随后以
   `cargo test --locked -p legal-mcp --lib --all-features <完整名> -- --exact --nocapture --test-threads=1`
   运行一次。

approved HTTP step 必须对 inventory 和 exact run 分别检查 native exit code，并对
`<完整名>: test` 做大小写敏感、恰好一项的 cardinality 断言。目标不存在、重复、命令漂移、
返回 504、业务断言失败或进程非零均 fail closed。

三个 steps 合计与原 broad 命令具有相同测试集合；两个真实 integration parents 各执行一次，
其余测试仍按原并行矩阵执行。后续真实 approved MCP binary、notices、frontend 和 Tauri
packaging steps 的顺序及失败语义不变。

## 4. 回归与验收

静态回归必须锁定：

- broad 命令及两个完整 `--skip` 恰好各一次；
- broad、real-restart、approved HTTP 三个 steps 的固定顺序；
- 两个 isolated steps 均有 package/lib/all-features inventory、cardinality=1、exact run 和两次
  `$LASTEXITCODE` 检查；
- `--test-threads=1` 只出现在 isolated steps；
- 相关 step 不含 retry 或 `continue-on-error`。

实现提交前必须通过：

- `python -m unittest scripts.test_release_contract -v`；
- approved HTTP 本地 focused 连续 20 次；
- `git diff --check` 和 workflow YAML 解析；
- 既有 real-restart 本地 inventory=1 与 exact 1/1 证据继续有效。

推送后只接受新 exact main SHA 的证据：

- broad step 成功；
- real-restart inventory=1 且 1/1 成功；
- approved HTTP inventory=1 且 1/1 成功；
- 主 CI 其余全部 steps 成功；
- MCP Windows/Linux/macOS 三平台重新成功，三件制品 provenance 精确绑定新 SHA。

## 5. 提交与回滚

第一提交只包含本计划。第二提交只包含 workflow 与静态回归。回滚时先回滚实现提交，再按需
回滚计划；不得删除或改写 run `31754643101` 的 504 证据，也不得用手工 rerun 代替新的
exact-main closure。
