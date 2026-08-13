# v0.3.1 真实重启测试主 CI 隔离修订

> 日期：2026-08-14
>
> 状态：已冻结；作为
> [`v0.4.0` 升级、回滚与发布冻结计划](2026-08-01-v0.4.0-upgrade-release-and-publication.md)
> 的窄范围验证修订执行
>
> 触发基线：`main@637114b0b16cbdb42cb24e99b8f768e5c4f421fa`

## 1. 目的与证据

本修订只调整一个真实 Windows 跨进程重启测试在主 CI 中的调度方式，不改变产品代码、
生产锁超时、升级/恢复状态机、断言或测试覆盖。

exact-main push CI run `31743334638` 在 `Test Rust` 中得到：

- desktop lib：`765 passed / 1 failed / 10 ignored`；
- 唯一失败：
  `commands::v031_user_upgrade::tests::real_os_process_restart_crosses_gate8_then_loads_terminal_without_raw_key_env`；
- Step 8 子进程返回折叠后的 `UpgradeComplete`，随后 parent 失败；
- 同一 SHA 的独立 exact 运行以 `--test-threads=1` 得到 `1 passed / 0 failed`，耗时
  `174.20s`；
- 同一 Rust 测试代码在此前完整 Windows CI 中通过；触发提交只修改 release
  PowerShell 的 Git fetch-URL 查询，不修改 Rust。

该测试使用 UUID 隔离应用根和 Credential Manager 账户名，但 Windows Provider Store 的
所有操作仍共享固定命名 mutex `Local\\LawyerAssistance.ProviderStore.v1`，生产获取上限为
5 秒。完整 libtest 同时运行多组重型升级、DPAPI 和凭据测试；子进程的
`--test-threads=1` 只约束子进程自身，不能隔离 parent test binary 中的 sibling tests。
因此现有证据高置信指向测试调度下的共享 OS mutex 争用，而不是升级状态机回归。

底层错误在 `ensure_v031_upgrade_complete` 外层被折叠，日志没有直接保留
`WAIT_TIMEOUT`。本修订不把 mutex 竞争描述为百分之百直接观测到的事实，也不通过重跑
掩盖失败；它用确定性的调度隔离同时保留完整覆盖。

## 2. 与既有计划的关系

[`2026-07-31 Rust loopback 测试夹具 CI 稳定化计划`](2026-07-31-rust-loopback-fixture-ci-stabilization.md)
禁止在其专项修订中修改 workflow、跳过测试或全局串行。该历史计划及其证据不得改写。
本修订处理其完成后、`v0.4.0` exact-main 发布门禁中出现的另一条真实跨进程测试，具有
独立证据、独立允许文件和独立提交。

允许修改且只能修改：

- 本计划文档；
- `.github/workflows/ci.yml`；
- `scripts/test_release_contract.py` 中只读 workflow 回归测试。

明确禁止：

- 修改 Rust 生产或测试实现；
- 放宽 `ProviderStoreLock` 的生产 5 秒超时；
- retry、rerun、`continue-on-error`、`#[ignore]` 或弱化断言；
- 给整个 workspace 设置 `--test-threads=1`；
- 删除或条件跳过其他测试、target 或 feature；
- 把一次孤立通过或旧 CI 结果当作新的 exact-main closure。

## 3. 冻结实现

主 CI 的原完整 Rust 测试门拆为两个顺序、独立的 GitHub Actions steps。

第一步仍运行完整 workspace、全部 targets 和全部 features，只从该次并行 invocation 中
排除唯一完整 test name：

```text
cargo test --locked --workspace --all-targets --all-features -- --skip commands::v031_user_upgrade::tests::real_os_process_restart_crosses_gate8_then_loads_terminal_without_raw_key_env
```

第二步只选择 `lawyer-assistance-desktop` lib、全部 package features，并且必须先列举 exact
inventory，严格证明 `<完整名>: test` 恰好出现一次；随后用同一完整名运行一次：

```text
cargo test --locked -p lawyer-assistance-desktop --lib --all-features <完整名> -- --exact --nocapture --test-threads=1
```

inventory 或 exact run 任一非零、测试名缺失/重复、输出格式漂移均 fail closed。两个步骤
合计覆盖原完整矩阵中的全部测试，目标 parent 恰好运行一次；它仍按生产路径启动 Step 8
和 terminal 子进程。第二步不是 retry，因为第一步明确不运行该 parent。

后续 notices、frontend、Tauri packaging 和所有发布门禁保持原顺序与 fail-closed 语义。

## 4. 回归与验收

`scripts/test_release_contract.py` 必须静态验证：

1. broad step 的命令、完整 `--skip` 名称和次数精确；
2. isolated step 位于 broad step 之后；
3. inventory 与 exact run 都使用固定 package、lib、all-features 和完整 test name；
4. inventory 恰好一项的 PowerShell 断言存在；
5. isolated run 恰好使用 `--exact --nocapture --test-threads=1`；
6. 两个 step 均没有 retry、`continue-on-error` 或错误吞噬。

实现提交前必须通过：

- `python -m unittest scripts.test_release_contract -v`；
- `git diff --check`；
- 目标 parent 的本地独立 exact 运行；
- workflow YAML/PowerShell 静态解析。

合并到 `main` 后必须从新 exact SHA 重新取得：

- 主 CI 全部 steps 成功，broad step 与 isolated step 分别成功；
- MCP server CI 的 Windows、Linux、macOS 三矩阵成功；
- 三个平台制品的 commit、版本、target、checksum、manifest 和 provenance 精确回读。

只有新 SHA 的上述证据才能继续 `v0.4.0` 发布顺序。真实 Authenticode、updater 私钥、
MinerU 最终资产、Win10/Win11 干净机和目标 GPU 门禁仍是独立外部门禁；本修订不得把它们
标记为完成。

## 5. 提交与回滚

第一提交只包含本计划。第二提交只包含 workflow 与静态回归测试。回滚时先回滚实现提交，
再按需回滚本计划；不得删除或改写 run `31743334638` 的失败证据。回滚不允许用原并行失败
矩阵的单次 rerun 代替确定性隔离。
