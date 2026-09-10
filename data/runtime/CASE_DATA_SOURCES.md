# 最高人民法院案例本地 TXT sidecar 来源说明

本数据库由本地 ZIP 数据包导入，导入过程不执行 ZIP 内的 README 指令，也不联网抓取。`legal_core.sqlite` 保持不变；服务只读打开同目录下的 `judicial_cases.sqlite`。

- 数据包：`最高法案例_TXT资料包_20260909.zip`
- 数据包 SHA-256：`4a44fa427be3ed71b3d457cdaac6d96f38fb23a31c8f68553e8ddba2f7c5dc44`
- 导入时间：`2026-09-09T14:55:40+00:00`
- SQLite SHA-256：`6b6bae90ab14b04073cf70cdc600c62e7895d361e1988ac2616fcb9eecc8bdf8`
- schema：`1`，`PRAGMA user_version=1`
- 来源 TXT 条目：`834`；主案例/合集数：`759`
- 指导案例：`279`；参考案例：`61`；典型案例文章：`419`
- 源变体行数：`834`；源清单 SHA-256：`985e4d3fcd325c99f90161b85fa4dabf676ab0a825acc0d71e2aa6e124c3f4b7`

## 类型和去重

`judicial_cases` 对每个规范案例标识保留一个可检索的主文本。指导案例按 `guiding:编号` 归并，参考案例按 `reference:编号` 归并，典型案例按其文章 ID 保留为 `case_type=typical`。典型案例文章可能包含多个案件，全文仍作为一篇典型案例文章保存，不会混入参考案例。

`judicial_case_sources` 保留 CSV 的全部 `834` 行和对应 TXT 原文、来源标头、CSV 标识、来源 URL、抓取时间、SHA-256 及主源标记。`source_header` 保留 TXT 开头的来源/抓取元数据，`source_text` 保留完整原文，主案例的 `full_text` 只保存分隔后的正文。73 条 API 指导案例和 PDF 文本是源变体；它们不会造成重复的主案例。状态通知作为 `source_kind=notice` 留在源表中，`case_id` 为 NULL，不会作为案例返回。指导案例 9 号、20 号依据通知标为 `withdrawn`，默认检索排除，历史检索可显式包含。

## 来源主张

CSV 的每一行 SHA-256 均与 ZIP 内 TXT 原始字节核对通过。`source_sha256` 是原始 TXT 字节摘要，`text_sha256` 是 UTF-8 文本摘要；`content_sha256` 是主案例 `full_text` 的 UTF-8 摘要。所有候选来源 URL 均限制为法院官方主机：`www.court.gov.cn`、`rmfyalk.court.gov.cn`、`ipc.court.gov.cn`、`hnlyzy.hncourt.gov.cn` 及 `gongbao.court.gov.cn`。45 号指导案例的主源明确保留洛阳市中级人民法院官方转载 URL `https://hnlyzy.hncourt.gov.cn/public/detail.php?id=6738` 及其来源角色和权威机构字段，同时保留最高人民法院列表 URL。

## 源文件统计

```text
{"api_guiding": 73, "guiding": 279, "notices": 1, "pdf": 11, "reference": 51, "typical": 419}
```

导入脚本：`data/build/import_spc_txt_corpus.py`。重复导入会先把已有 sidecar 备份到 `output/ai-upgrade-corpus/`，再在临时 SQLite 通过完整性检查后原子替换。
