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

规模分级为小型（≤20）、中型（20–100）和大型（>100，硬上限 500）。自动化用
20、100、101、500 节点四档同时执行完整语义校验与 HTML 渲染，并断言 >100 时出现
warning、性能提示、弱边隐藏与低重要性折叠；四档必须在宽松防退化门限内完成。任何
p95 性能承诺都需要独立 benchmark、固定环境和可复现实验，不能由单次单元测试耗时
推导。

性能失败不能通过跳过来源、安全或语义校验规避。

## 建议门禁命令

建议在最终提交上运行：

- `cargo test -p diagrams --locked --offline --no-fail-fast`
- `cargo test -p legal-mcp --locked --offline --no-fail-fast`
- `cargo test -p diagrams --release --test large_graph -- --nocapture`
- `cargo clippy -p diagrams -p legal-mcp --all-targets --locked --offline -- -D warnings`
- `cargo fmt --all -- --check`
- `python integrations/validate_examples.py`
- `python -m unittest integrations.test_validate_examples`
- `pnpm test`
- `pnpm lint`
- `pnpm build`
- `node --check crates/diagrams/src/runtime-enhancements.js`

门禁覆盖 Spec/HTML 完整性、目录级原子提交、孤儿、双侧篡改、URI/hash 换绑、并发
收敛、reparse/junction 替换、大小上限、来源可见性和 profile 授权。普通自动门禁不
访问外网、不读取 Provider 凭据，也不产生计费。

## 外部 Provider 测试

- 自动测试、确定性布局、本地 Schema/语义校验和 HTML 渲染不调用、也不依赖任何
  外部 Provider。
- 付费 Provider smoke test 不是普通发布门禁。确需执行时只能使用纯合成图数据，
  必须显式授权费用，且不得打印、写文件或提交 API 密钥。
- Provider 生成的 Spec 仍须通过同一套本地 Schema、语义、来源和安全验证；模型输出
  不能绕过确定性 renderer 或 profile 边界。

## 验收证据

发布记录应包含通过的样例数量、七模板覆盖、测试计数、快照变更说明、性能环境/数据、计费 smoke 是否执行及其纯虚构输入声明。失败和忽略项必须说明原因与后续负责人。
