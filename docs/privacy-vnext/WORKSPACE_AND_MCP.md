# Approved Workspace、Work Products 与 MCP 边界

## 1. 两个物理数据域

`vault` 保存原件、OCR 私有结果、真实实体、mapping、review state 和密钥材料；`workspace` 只保存已批准脱敏材料、最小公开元数据和加密落盘的脱敏 work products。两者使用不同根目录、不同 Broker 能力和不同服务接口。

MCP handler 只能得到 `ApprovedWorkspaceService` 与 scoped `WorkProductService`，不得得到 vault root、workspace root、privacy database、user.sqlite、mapping、任意文件读取能力或通用解密能力。只有 `WorkProductService` 可以在一次受限 read 操作中，对调用指定且已通过全部绑定校验的单个 work product 进行鉴权解密；它没有 Vault、mapping、root 浏览或任意路径能力。

当前若仍在同一 Windows 用户边界内运行，隔离级别必须标记为 `user-boundary-only`。只有独立服务身份、受验证的 DACL 与进程访问测试通过后，才能标记 `strong-service-boundary`。

## 2. Approved generation

每次批准产生不可变 generation：

```text
workspace/<case-id>/approved/<publication-id>/
  content.bin
  manifest.json
  manifest.sig
  public-metadata.json
```

发布事务：

1. 在同一卷的随机 staging 目录写入全部文件。
2. 对 content 做独立 residual scan；计算 content hash。
3. 生成 canonical manifest claims 并签名。
4. 重新读取并验证文件类型、大小、hash、签名、撤销 epoch 和目标 scope。
5. flush 文件与目录，原子 rename 为最终 generation。
6. 最后原子更新受控 current pointer 与 publication journal。
7. 只有 committed journal + valid pointer 才可枚举；半发布目录一律隔离。

不得覆盖已发布 generation。任何正文、finding、mapping、策略、worker/model、资格、目的地或人工修改变化都创建新 document/publication version，并撤销旧读权限。

## 3. VerifiedApprovedMaterial

这是后端私有、不可由 JSON 反序列化构造的能力类型。服务只能在一次读取中完成以下检查后创建它：

- ID 格式和 workspace instance 匹配。
- manifest schema/canonical hash/signature 有效。
- classification 精确等于 `CASE_REDACTED_APPROVED`。
- content 是受控根内普通文件，无 link/reparse/hardlink 逃逸。
- content size/hash 与 manifest 完全一致。
- publication committed、未撤销、未过期、purpose/destination/profile 匹配。
- P0/P1 为零、hard gates hash 有效、资格与策略未失效。
- 独立 MCP egress scan 通过。

验证后仍应以已打开的受控句柄读取，避免先校验后替换。失败只返回匿名错误码。

## 4. Work products

work product 只能写入：

```text
workspace/<case-id>/work-products/<work-product-id>/<version>/
  content.envelope.json
  manifest.json
  commit.json
```

每个 immutable version 的文件集合必须精确等于上述三项：

- `content.envelope.json` 是 canonical JSON 加密 envelope，不是明文正文。每个 generation 都生成新的随机 AES-256-GCM data key 与 nonce，data key 由 Windows DPAPI CurrentUser 包装。
- AES-GCM AAD 绑定 `workspace_instance_id`、case ID、work-product ID、version、signed-manifest SHA-256、content SHA-256、content bytes 与 media type；跨 workspace/case/object/version/manifest/content 调换均无法通过认证。
- `manifest.json` 是 canonical、签名的 work-product manifest；`commit.json` 再绑定 case/work-product/version、manifest hash、content hash 与长度。
- 旧格式明文 `content.bin`、任何额外/缺失文件、非普通文件、symlink/reparse/hardlink、非 canonical/未知字段、签名或 hash 不一致都 fail closed。正文不会以明文文件落盘。

服务端生成 ID 与版本；更新要求 `expected_parent_version` 和 idempotency key。写入必须：

- 引用当前仍有效的 approved material IDs 与 manifest hashes。
- 执行独立 residual scan、placeholder 完整性检查和媒体类型/大小限制。
- 拒绝路径、文件名、URI、外部引用、脚本、宏和活动内容。
- 使用 immutable generation + 原子 current pointer。
- 不得覆盖 approved、vault 或另一个 case。

读取时，scoped `WorkProductService` 先验证 exact file set、固定本地普通文件身份、canonical manifest/commit/envelope、manifest 签名、全部 AAD/ID/version/hash/length/media bindings、当前 approved source refs 与 revocation，再鉴权解密并复算 content hash、执行 residual scan；任一步失败均不返回正文。撤销源材料后，相关 work product 立即失效；当前实现阻断 list/read/update/export，不允许用组织策略把已撤销源降级成“仍可读”。合法保留只影响受控保留/清理，不重新授予 MCP 内容访问能力。

## 5. MCP profiles

### `public_law_only`

默认 profile，继续精确暴露现有五项公开法律工具。任何 vNext 改动不得改变其工具数量、参数 schema 或公开资料边界。

### `approved_case_workspace`

显式启用的新 profile，包含现有五项公开法律工具及以下十项案件工具：

- `case_list`
- `case_get_public_metadata`
- `case_list_approved_materials`
- `case_read_approved_material`
- `case_search_approved_materials`
- `case_list_work_products`
- `case_read_work_product`
- `case_write_work_product`
- `case_update_work_product`
- `case_export_work_product_manifest`

所有参数 `deny_unknown_fields`，只接受严格 opaque ID、受限枚举、页码/limit/cursor、受限搜索串、受限正文和并发版本。禁止 path、filename、URI、URL、directory、glob、command、shell、任意 metadata object 和任意环境选择。

profile 启用门包括：workspace 完整性、manifest verifier、撤销检查、双通道 egress scan、隔离级别政策、资格 tuple 和本地显式设置。默认关闭，不从旧 `redacted_case` 自动迁移。

formal Windows App 与 MCP sibling 是成对发布物：构建流程先生成并测量 exact `lawyer-assistance-mcp.exe`，再把其 SHA-256 编译进 App。approved-MCP qualification 同时核对该 trust anchor、canonical sibling path/file identity、版本、canary 行为、App/workspace/server key/transport 与撤销 epoch。普通未绑定 development App、缺失/畸形 hash、同名替换或只模仿版本/canary 的二进制一律 fail closed。

## 6. MCP 输出与错误

`content` 与 `structuredContent` 两条通道必须分别扫描；仅扫描其中一条即失败。输出只允许：

- 当前调用直接读取且仍有效的批准脱敏正文。
- opaque IDs、安全状态、公开元数据、hash、版本和计数。
- 经验证的脱敏 work product。

禁止输出原路径、原文件名、真实实体、mapping、OCR 私有正文、review draft、receipt secret、签名 key、vault 错误细节和宿主提供的任意附件正文。

错误统一为有限 reason code，例如 `APPROVED_MATERIAL_NOT_AVAILABLE`、`PUBLICATION_STALE`、`WORKSPACE_INTEGRITY_FAILED`、`PROFILE_NOT_QUALIFIED`；不得把底层路径或解析片段拼入 message。

## 7. WorkBuddy 正向流程

唯一允许的案件材料来源是本次调用 `case_read_approved_material` 直接返回且标记 `CASE_REDACTED_APPROVED` 的内容。标签、文件名、用户口头声明、粘贴文本、附件、历史 memory 和其他工具返回都不构成批准证据。

标准流程：

1. `case_list` / `case_list_approved_materials` 取得 opaque ID。
2. `case_read_approved_material` 读取批准材料。
3. 在会话内处理，不尝试恢复占位符真实值。
4. `case_write_work_product` 或 `case_update_work_product` 写回脱敏成果。
5. 需要公开法律资料时只调用既有五项公开工具。

处理案件时严格禁止浏览器、网页搜索、邮件、网盘、任意文件读取、OCR、其他 MCP/Skill、memory、子智能体以及把材料发给未经批准的 Provider。若任务上下文已包含原件或待复核材料，立即停止案件处理并提示用户新建干净任务。

## 8. 配置与验证器

- WorkBuddy、Codex、OpenCode 各宿主均要同步更新主 Skill、引用文件、工具目录和权限配置。
- 保留现有 public-only 验证器；新增独立 approved-profile 验证器，不能通过放宽旧验证器实现。
- CI 对每个宿主检查十项工具精确集合、禁用字段、正向来源措辞、禁止工具措辞和写回路径。
- Skill 只是辅助控制；任何 prompt injection 都不能绕过后端 schema、manifest、ACL 和 egress gate。

## 9. 当前交付状态


