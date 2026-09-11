# 1.2.1 本地接口变更

本文记录审查修复中的兼容约定。本轮实际验收状态见[续修记录](retest-1.2.1.md)，上一轮[逐项报告](audit-1.2.1.md)保留为历史证据。HTTP 路由仍受现有登录、CSRF 与本机访问限制约束。

## 法规检索

`GET /api/v1/legal/search/page` 新增以下查询条件：

| 字段 | 可选值 | 默认与约束 |
| --- | --- | --- |
| `match_mode` | `all`、`any`、`phrase` | 默认 `all`；全部词必须在同一条文候选中命中 |
| `version_scope` | `current`、`as_of`、`all` | 未传日期时默认 `current`；只传日期时推断为 `as_of` |
| `case_date` | `YYYY-MM-DD` | 必须是真实日历日期；显式 `current` 或 `all` 不能同时携带日期 |
| `version_status` | 数据库版本状态 | 与法律文档的 `status` 分开过滤 |

明确法律名与条号执行交集定位，法律名存在歧义时返回 `ambiguities` 供选择。条号支持中文、阿拉伯和全角数字，以及“条之一”等增设条款。默认当前有效范围不把缺少或非法生效日期的版本标为有效；这些记录可在显式扩大版本范围后查看。

响应中的 `appliedQuery` 是实际采用的规范化条件。非空查询的 `totalArticles`、`totalLaws` 在平铺和分组视图中对应同一个命中文章集合。每页最多 100 项；完整计数不意味着在内存中保存完整结果集。派生索引不能确认完整候选时，使用原文 SQL 降级并在 `metrics.indexFallback` 中报告。

ALL 查询在 SQLite 中对词内必要双字及跨词约束一起求交，再探测最多 901 个候选。ANY 按完整词候选求并；候选超过 900、参数预算不足或词不能安全索引时均执行完整原文查询，不截断结果。计数、平铺、分组及分组预览共用保守的 999 参数预算判断，取消与数据库中断不能转为继续扫描。

`metrics.indexFallbackReason` 说明 `index_unavailable`、`unsupported_term`、`candidate_limit` 或 `parameter_limit`。`planMs`、`indexMs`、`countMs`、`pageMs`、`totalMs` 记录本次请求各阶段耗时，另保留锁等待和缓存字节。页面缓存命中时，候选数、索引/计数/分页耗时和 `countCacheHit` 归零；这些字段不能沿用填充缓存时的旧工作量。首次查询键不表示操作系统冷盘，基准脚本单独列出首次键、热页与新页。

条文详情与版本正文接口接受相同的 `version_scope`、`case_date`。默认当前范围不能读取已不在该范围内的历史正文；显式选择历史日期或全部版本后才读取。版本元数据列表不等同于已经选用了该历史正文。

MCP v1 的字段、数量上限和公开输出格式保留，内部使用同一查询计划。AI 工具不能覆盖用户在本次任务中指定的日期、匹配模式和版本范围。

## 文书、草稿与会话

保存和导出文书必须携带固定任务 ID 与期望 revision。保存正文修改产生新版本，旧版本仍可读取。缺少版本的旧写请求返回可识别错误；冲突不覆盖用户输入。

`PUT /api/v1/ai/runs/{id}/content` 接受 `expected_revision`、`content` 和可选的 `case_date`。省略日期表示继承；`null` 表示清空并回到当前版本范围；日期字符串表示切换为该日期范围。改变正文或日期后，新版本的旧引用证据立即失效。

`POST /api/v1/ai/runs/{id}/citations/recheck` 接受 `expected_revision`，只进行来源和引文的机械核对，不调用模型。响应的 `citation_verification` 记录来源及版本 ID、全文哈希、引文定位、查询日期、文书正文哈希和 revision，分别提供来源存在、全文读取、引文匹配和时间核验结果。论证相关性始终需要人工判断。待复核和旧记录文书仍可导出，导出记录保存当时的核验状态，不借用其他版本的通过状态。

写作草稿保存在加密工作区，包含表单和未提交正文的任务版本绑定，采用期望 revision 更新。成功生成不删除草稿，清除需要显式操作。

写作任务响应增加服务器维护的 `document_id`，保存新版本和继续生成均继承该标识；旧记录缺字段时以原任务 ID 兼容读取。`id` 和 `revision` 仍定位固定正文版本，不能用 `document_id` 代替导出版本校验。

新建表单使用 `writing-current` 草稿；文书正文使用 `writing-{document_id}`，草稿 CAS revision 与正文 revision 分别管理。发生 CAS 冲突后，客户端停止旧版本重试，通过现有草稿 PUT 接口保存独立的 `{base_id}-c-{32位小写十六进制随机ID}` 候选（`expected_revision: 0`）。候选写入未获成功确认时，正文仍应显示未保存。

`GET /api/v1/ai/drafts/{base_id}/conflicts?limit=20&cursor=...` 分页返回 `drafts: [{id, revision, updated_at}]`、`next_cursor`、`total`、`corrupt_count`。`limit` 为 1–100，游标只适用于同一基底；列表仅读取索引元数据，正文须通过单份草稿 GET 读取。候选采用远端、合并保存或保留独立草稿均由用户选择；合并时仍携带读取到的 CAS revision，再次冲突不能覆盖任何输入。

会话材料清单在服务器持久化并带 revision。`inherit` 表示沿用服务器清单，`replace` 表示完整替换；替换为空数组表示清空。发送使用 `context/prepare` 返回的清单版本与准备哈希。移除材料会停止依赖该材料的未完成任务，后续上下文排除相应历史轮次；无法可靠归因的旧历史仅保留本地查看。

## 上下文预算

`POST /api/v1/ai/context/estimate` 接受任务请求并返回本地预检，不调用模型。结果包含模型能力配置、输入和预留输出预算、选中的材料范围及省略原因。预检不把尚未解析的文档描述为已经完整读取；处理和每次模型请求仍须通过增量检查。任务响应中的 `context_plan` 记录实际采用范围，敏感正文与模型消息不出现在计划摘要中。

Provider 的 `model_capabilities` 按模型名配置 `context_window_tokens`、`max_output_tokens`、`supports_tools`、`supports_structured_output`、`supports_vision`。未配置容量时采用 16,384 输入和 4,096 输出 token 的保守预算并显示未核实。配置值不等于已经实测服务能力。容量不足返回 `context_budget_exceeded`（HTTP 413）；明确不支持的功能在外发前拒绝。模型响应因长度上限截断时，任务不能标为完成。

能力字段使用 `null`（未知）、`true`（声明支持）、`false`（声明不支持）。保存 Provider 时，省略能力映射或其中某个字段表示保留；显式 `null` 才将该字段改为未知。只修改容量不能清除已有 `false`，旧记录的 `false` 在用户明确更正前仍阻断相应功能。声明来源、时间、配置绑定和待复核状态由服务器记录；改变容量不代表已经实测模型。

兼容字段 `capabilities.verified` 表示输入预算所需的容量配置是否完整，不能作为真实模型测试通过的证据。Provider 的 `capability_metadata` 提供声明来源与 `verification_state`；本轮只使用本地 mock，不将用户声明升级为实测支持。

Provider 配置、能力声明和默认模型选择在同一工作区锁和 SQLite 事务内保存；发送前在锁内读取配置与凭据的一致快照，网络等待不持锁。凭据管理器属于独立存储，写入前持久化发送阻断状态；失败时恢复并核对旧凭据。无法确认恢复时保留阻断，即使重启也不能继续发送，须重新填写并成功保存凭据。

`POST /api/v1/ai/context/inspect` 接受单个来源的 `source_kind`、`source_id` 和材料所需的 `source: original | redacted`。响应只包含格式、`unit_kind`、`unit_count`、`unit_version`、`estimated_input_tokens`、`estimate_basis` 和 `inspection_hash` 等结构信息。PDF 页树在隔离进程中检查；检查不调用 OCR 或模型，不返回正文。

任务请求和会话材料替换接口接受 `context_ranges`。每个已选来源对应一个条目，例如：

```json
{
  "source_kind": "attachment",
  "source_id": "attachment_...",
  "mode": "pages",
  "ranges": [{"start": 2, "end": 4}, {"start": 7, "end": 7}],
  "inspection_hash": "服务器返回的来源绑定标识"
}
```

`mode` 为 `all`、`pages` 或 `paragraphs`。页码和段落编号从 1 开始、包含两端；服务器排序并合并重叠或相邻区间。局部范围为空、倒序、从 0 开始、越界或与来源格式不匹配时拒绝。局部范围须携带当前来源的检查标识；来源版本、内容或范围改变后，旧准备计划失效。未提供范围的旧请求按全部处理，仍受预算限制；最终材料和附件清单都为空时范围也为空。

预检的 `plan_hash` 保持不变；实际处理后新增 `actual_plan_hash`，绑定原始请求范围 `requested_scope`、实际采用范围 `selected_scope`、遗漏和预算账目，历史轮次计入 `history_tokens`。完整估算超过剩余容量时，预检返回 `stage: scope_required` 并说明原因，创建任务返回 HTTP 413。用户可缩小页码或段落范围后重新准备。处理过程中仍有增量预算检查，不能将预算导致的截断结果标为完整完成。

新计划返回 `schema_version: 2`，其实际哈希包含 `requested_scope`。旧 schema 1 记录继续按原投影核验，不因兼容读取补出的空字段改变原哈希。同一材料的原稿和脱敏稿分别按来源版本归集范围。

## PDF 工作进程

发行程序通过内部 `document-worker` 子命令处理 PDF，主服务不加载 Pdfium。文本页在本机读取，扫描页和混合页按需 OCR；页间确认和有限帧避免一次渲染全部页面。Windows 子进程内存上限为 512 MiB，单文件累计渲染期限为 90 秒；等待模型识别的时间不占渲染期限。取消和子进程异常都会终止并回收子进程，错误只返回安全类别。此隔离措施不等于已经查明原始闪退原因。

## 分页与资源状态

材料、任务、会话和分组列表保留原有集合字段，新增 `next_cursor`、`total`、`corrupt_count`。默认每页 50 项，最大 100 项。列表读取加密摘要，材料调度直接领取一条 queued 记录，空闲队列不解密正文。

检索预算为 2 个执行、16 个等待；AI 为 2 个执行、6 个等待；解析为 1 个执行、2 个等待。超额返回 `capacity_exceeded`（HTTP 429）。`health.resources` 返回实际执行、等待和限制计数。取消贯通等待、SQLite 和模型 HTTP；浏览器关闭不会取消已经接受的后台任务。

升级仅处理实际打开的现行工作区，迁移前验证备份，对象、加密摘要与调度元数据同事务更新。损坏对象隔离并报告，不作为空列表或空队列处理。旧历史目录不自动合并或覆盖。


材料任务在独立的受监督执行单元内运行。panic 对应 `task_panicked`，底层中止对应 `task_cancelled`；晚到结果须通过任务版本和终态比较。失败状态写入受阻时，健康状态保持降级，按有界退避重试；不得把存储错误视为空队列或直接领取下一条。

测试构建 feature `document-worker-fault-injection` 仅供隔离验收，正式便携包使用默认构建。它不构成公开 HTTP 或 MCP 接口，生产程序不提供故障命令。测试内存结果必须包含实际申请/触碰及拒绝证据；故障测试通过不表示原始闪退根因已经确认。
