# 图示系统测试与验收

## 测试层次

1. Schema 单元测试：必填字段、未知字段、枚举、长度、数量、metadata 形状和版本。
2. 语义测试：唯一 ID、悬空引用、组循环、来源闭合、关系方向、状态冲突、模板必需类型和领域字段。
3. 渲染测试：七模板专用布局标记、确定性字节、边界裁剪/并行边/自环、CSP、转义、图例、详情、来源可见性、键盘标记、打印和离线性。
4. 服务测试：内容寻址、Spec+HTML sibling bundle 原子提交、重复/并发渲染、patch、hash 冲突、导出重渲染、孤儿/篡改/URI 换绑拒绝，以及初始化后 symlink/junction/reparse 替换和 output root 身份约束。
5. MCP 测试：六工具发现、参数 Schema、profile 可见性/拒绝、错误映射、结果隐私和 URI。
6. 工作区回归：Rust workspace、桌面端 TypeScript/Vitest/ESLint/build 和 integration catalog。

## 固定样例矩阵

`crates/diagrams/examples/` 当前包含 20 份纯虚构样例：七模板各有注册表样例，并覆盖可直接调用的民间借贷争点—证据—法律图、买卖合同、劳动争议、股权控制、多方担保、多笔转账与回流、时间矛盾、证据不足以及一般—特别—例外规则。样例必须可由公共 Schema 读取，且不得出现现实自然人联系方式、证件、账户、案号或客户文件路径。

`all_examples` 遍历全部 JSON，先执行冻结 Draft 2020-12 Schema 的真实运行时验证，再执行 typed 反序列化与完整语义校验；七个注册表样例另核对模板描述符；渲染契约验证七种专用布局、两次渲染字节相等和离线 HTML smoke。快照变更须人工判断属于预期布局升级还是回归。

## 必测反例

- MCP `schema_version` 与 Spec `schema_version` 混用。
- template ID 与 diagram type 不匹配、未知节点/关系/状态。
- 重复 ID、节点/边 ID 冲突、悬空边、悬空来源、循环组。
- `supported` 被无依据提升为 `established`，或已确认事实同时存在强矛盾材料。
- `authorized_by`、`paid_to`、`guarantees`、`occurred_before` 等方向反写。
- 资金记录缺金额、币种、日期或凭证来源；法律来源缺版本或定位。
- 时间陈述互相矛盾却被合并为单节点。
- 删除仍被边、组或来源引用的对象；错误 `expected_spec_hash`。
- 任意 HTML/CSS/JS、危险协议、路径穿越、超限集合和深层 metadata。

## 交互验收

在无网络条件下验证搜索、按类型/状态/争议点/主体筛选、选择节点/边、查看详情与来源、分组折叠、隐藏弱边、折叠低重要性节点、上下游聚焦、逐层展开、缩放、重置和打印。键盘可完成节点与边的核心操作，焦点可见；颜色不是唯一状态信号；窄屏和 A4 横/纵向不截断关键文本。

## 性能目标

规模分级为小型（≤20）、中型（20–100）和大型（>100，硬上限 500）。自动化用 20、100、101、500 节点四档同时执行完整语义校验与 HTML 渲染，并断言 >100 时出现 warning、性能提示、弱边隐藏与低重要性折叠；四档必须在 10 秒宽松防退化门限内完成。2026-07-21 的 release 验收中，四档合计由 Rust test harness 报告为 0.01 秒。该数字是单次功能回归耗时，不等同于统计学 p95 基准；后续若承诺“校验 p95 <100 ms / 100 节点渲染 <250 ms”，仍需独立 benchmark 和环境固化。

性能失败不能通过跳过来源、安全或语义校验规避。

## 建议门禁命令

2026-07-21 第一阶段基线验收执行：

- `cargo test --workspace`：通过（覆盖 `diagrams` 与 `legal-mcp` 新测试）。
- `cargo clippy -p diagrams -p legal-mcp --all-targets -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo test -p diagrams --release --test large_graph -- --nocapture`：通过；20/100/101/500 四档合计 0.01 秒。
- `python integrations/validate_examples.py`：通过。
- `python -m unittest integrations.test_validate_examples`：16 tests 通过。
- `pnpm test`：248 tests 通过。
- `pnpm lint`：通过。
- `pnpm build`：通过。
- `node --check crates/diagrams/src/runtime-enhancements.js`：通过。

2026-07-22 的制品完整性加固后，`crates/diagrams/tests` 有 44 个集成测试用例，新图示 MCP 集成文件另有 3 个用例。新增用例覆盖 sibling Spec/HTML 完整性、目录级原子提交、孤儿、双侧篡改、URI/hash 换绑、并发收敛和初始化后 diagram root reparse/junction 替换。实际复跑结果：`cargo test -p diagrams --locked --offline --no-fail-fast` 为 44 passed；`cargo test -p legal-mcp --locked --offline --no-fail-fast` 为 59 passed、1 个正式法律库 opt-in ignored；`cargo clippy -p diagrams -p legal-mcp --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 均通过；release 大图测试 1/1 通过（0.01 秒）；integration validator 与其单测分别通过，后者为 17/17（新增图示 Skill 禁令退化测试）。上述自动门禁不访问外网、不读取 Provider 凭据，也不产生计费。

## DeepSeek 计费口径

- 自动测试、确定性布局、本地 Schema/语义校验和 HTML 渲染均不调用、也不依赖 DeepSeek。
- 2026-07-21 最终 opt-in QA 另行调用官方 `deepseek-v4-flash` 3 次，输入仅为纯合成法律图数据；usage 为 14、3,409、3,560 tokens，合计 6,983。模型输出得到 10 nodes、9 edges、4 sources 的合成 Spec，本地 Schema 与语义诊断均为 0，随后 MCP `validate/render/export/update` 通过。
- 同日旧应用内两项法律回答和一项案件抽取 ignored 测试在 Provider transport 前被 `CaseRaw` 门禁拒绝，没有网络请求、没有计费，不能算作 DeepSeek 成功调用。
- 密钥未打印、未写文件、未进入制品或版本控制。逐项记录以 `acceptance-2026-07-21.md` 为准。

## 验收证据

发布记录应包含通过的样例数量、七模板覆盖、测试计数、快照变更说明、性能环境/数据、计费 smoke 是否执行及其纯虚构输入声明。失败和忽略项必须说明原因与后续负责人。
