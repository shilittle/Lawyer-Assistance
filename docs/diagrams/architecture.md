# 法律与案件示意图系统总体架构

## 目标与不可变边界

系统把法律分析数据转换为可校验、可追溯、可离线查看的确定性 HTML 图示。权威中间表示是 `DiagramSpec 1.0`；模型可以生成或修订结构化数据，但不能生成模板代码、样式、脚本、坐标或未注册关系。关系注册表冻结 42 种关系，`related_to` 是唯一会触发 warning 的兜底关系。

本系统不代替律师判断。节点状态区分“主张”“有材料支持”“有争议”“已确认”和“未知”，`supported` 绝不自动升级为 `established`。数据等级决定执行通道：

- `diagram_authoring` 永久只处理纯合成或公开数据；它不是批准案件能力，也没有升级为真实案件通道的兼容模式。
- `approved_case_workspace` 是真实批准案件唯一允许的图示路径；它继承 Privacy vNext 的逐次请求绑定、当前来源授权、撤销和 encrypted protected work-product 边界。

## 双通道拓扑

```text
纯合成 / 公开数据
  │
  ▼
legal-mcp: diagram_authoring（固定 11 tools）
  │  6 diagram tools
  ▼
DiagramService
  ├─ Schema + 领域语义校验
  ├─ 确定性布局与安全 HTML 渲染
  └─ 明文内容寻址 sibling bundle
       ├─ artifact.diagram.json
       └─ artifact.html
            ▼
lawyer-assistance://diagrams/<artifact-key>

真实批准案件
  │
  ▼
App / standalone approved session
  │  显式 diagram_read / diagram_write grant
  │  一次性、请求 hash/案件/目标/版本绑定 ticket
  ▼
legal-mcp: approved_case_workspace（固定 21 tools）
  │  6 approved diagram adapters；256 KiB request ceiling
  ▼
批准来源解析 + 精确 publication 绑定 + residual scan
  │
  ▼
crates/diagrams 纯校验 / 纯渲染 / hash-bound update
  │  不调用 DiagramService 明文制品存储
  ▼
Privacy protected work-product publisher
  └─ 加密 text/html，最多 1 MiB，signed manifest
       ▼
opaque work_product_id + version + verified descriptor metadata
```

两条通道共享 DiagramSpec、模板注册表、校验器和固定渲染器，不共享制品信任模型。真实案件适配器只调用纯函数生成内存 HTML，再交给 Privacy publisher；不得把 `DiagramService` 的明文 `artifact.diagram.json` / `artifact.html` 存储接到批准案件 profile。

## Profile 与工具组成

| profile | 总数 | 组成 | 图示制品 |
|---|---:|---|---|
| `diagram_authoring` | 11 | 5 个公开法律工具 + 6 个图示工具 | 明文内容寻址 sibling bundle 与 `artifact_uri` |
| `approved_case_workspace` | 21 | 5 个公开法律工具 + 10 个批准案件工具 + 6 个图示工具 | encrypted protected HTML work product |

批准案件的图示授权与既有授权分离：`diagram_read` 授予 list/get-schema/validate/export，`diagram_write` 授予 render/update。原 `read` 和 `write` 工具集合保持原样，不因集成而扩权；没有 `diagram_read` 时，通用 metadata/list/read/manifest-export 会过滤或拒绝 `legal_diagram`，通用 write/update 也不能创建或改写图示。

## 批准案件数据流

1. App 建立 `approved_case_workspace` 会话并显式选择所需 grant group。
2. 客户端用 `diagram.list_templates` / `diagram.get_schema` 发现七模板和批准案件受限 Schema；该通道不返回内置虚构示例正文。
3. 客户端只从当前批准 publication 构造 Spec。`source_approved_refs` 位于工具 envelope；Spec 来源 `id`/`artifact_id` 使用匹配的 `pub_...`。approved schema、metadata allowlist 和递归字符串扫描共同拒绝 path、文件名、URI、UNC、盘符、遍历与 attachment 编码。
4. App 对规范化业务请求签发一次性 ticket；宿主将其注入内部 schema，模型不可见也不能自行提供。
5. `validate` 解析当前可读来源版本，验证 Spec 与 publication 的精确闭合绑定，执行残留敏感数据扫描、Schema、typed、跨引用、关系方向和模板语义校验。
6. `render` 只在内存中确定性生成 HTML，然后以 `legal_diagram` / `text/html` 发布最多 1 MiB 的加密 protected work product；manifest 同时绑定 canonical Spec SHA-256。
7. `update` 先解密并验证指定 parent，要求 `expected_spec_hash` 同时匹配 parent manifest 与调用方 `base_spec` 的 canonical hash，再逐字节核对 parent HTML；patch 后重新验证闭合来源集合，并要求新 manifest 的来源血缘包含全部 parent 来源，禁止删除历史依赖或加入无关来源。
8. `export` 重新验证当前来源授权、protected 内容和 signed manifest，只返回绑定 manifest 的 descriptor metadata，不返回 HTML、manifest 正文、路径或 URI。

任一来源撤销都会使依赖它的后续 update/export fail closed；已有 ticket 也不能越过撤销状态。

## 合成/公开数据流

1. 客户端在 `diagram_authoring` profile 读取带内置虚构示例的模板清单和完整 Schema。
2. `validate` 对纯合成或公开 Spec 执行结构与领域校验。
3. `render` 规范化 Spec、计算 hash、固定布局，并原子写入明文 `artifact.diagram.json` 与 `artifact.html` sibling bundle。
4. `update` 以 `artifact_uri` 或调用方提供的 `base_spec` 为基线，执行 optimistic concurrency patch。
5. `export` 重读 sibling Spec、验证 URI/hash、重渲染并逐字节比对 HTML，再返回明文制品描述符。

该通道的明文文件与 `artifact_uri` 是有意保留的本地公开/合成契约；任何真实案件内容进入该通道都属于边界违规。

## 信任分层

| 层 | 可以影响 | 不可以影响 |
|---|---|---|
| 模型/客户端 | 标题、节点、边、来源、不确定性、有限布局提示和显示选项 | HTML、CSS、JS、CSP、任意网络请求、模板代码、扩大授权范围 |
| App 批准链 | profile、grant、规范化请求、案件、来源、work product 与版本的逐次授权 | 让模型自签 ticket、在撤销后继续、把路径暴露给 MCP |
| Schema/语义校验 | 接受或拒绝数据，给出净化诊断 | 推断案件真相、补造来源 |
| 模板/布局器 | 节点位置、边路由、图例与交互 | 改写事实状态或来源内容 |
| 明文 DiagramService | 仅为合成/公开数据写内容寻址 sibling bundle | 接收真实批准案件 |
| protected publisher | 加密 HTML、版本化、签名 manifest、来源撤销核验 | 返回内容、路径、文件名或 URI 给图示响应 |

## 确定性、交互与大图

- 同一 Spec、模板版本和渲染版本必须产生相同 HTML 字节与 hash；布局升级必须有快照差分和版本说明。
- 节点、边和组通过 `source_refs` 回指来源；引用断裂是错误。批准案件还要求所有来源精确绑定本次 `source_approved_refs`。
- 固定 HTML 提供搜索、筛选、争议点聚焦、弱边隐藏、低重要性节点折叠、分组折叠、上下游展开、缩放/平移、详情/来源侧栏、键盘操作和打印。
- 500 节点、1200 边是 DiagramSpec 契约硬上限；超过 100 节点时初始隐藏弱边、折叠低重要性节点并显示性能提示。批准案件还受 256 KiB 请求和 1 MiB protected HTML 上限约束，通常会更早拒绝过大的上下文。

## 消费边界

公开/合成通道的宿主可以解析 `lawyer-assistance://diagrams/...` 并只读展示本地明文制品。批准案件通道不存在 artifact URI：宿主必须经 Privacy work-product 服务和当前授权读取 protected 内容；MCP `diagram.export` 仅提供 verified descriptor metadata。任何消费者都不能因“展示图示”获得额外材料、路径或授权。
