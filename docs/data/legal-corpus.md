# 法律数据与运行时数据库 / Legal corpus and runtime database

Lawyer Assistance 使用公开、可追溯的官方法律来源构建本地只读索引。Web 便携包只包含法条和案例运行时投影，不包含抓取状态、审计原文或完整归档数据库。

## 运行时投影

运行时数据库位于 `data/runtime/legal_core.sqlite`，发行身份由 [`data/generated/legal_core_distribution_manifest.json`](../../data/generated/legal_core_distribution_manifest.json) 固定：

```text
dataset: official-china-legal-core
version: 2026.07.14-stage1c.2
runtime_profile: runtime-slim-v1
size: 1,775,419,392 bytes
sha256: 86574bba91950b194c6530586eebbae31c689a5bd2a485877b3eed6b611f7d3c
source_manifest_sha256: 011551065b404507bce7b2cf542cb3b18da79a14437d094d067e685a438cd9fa
```

实际值以发行清单为准；示例包或 CI fixture 不得替代正式库。便携打包脚本会校验文件大小、SHA-256 和 SQLite `database_metadata.source_manifest_sha256`，不匹配时失败关闭。

## 来源、构建与许可

- 来源清单：[`data/sources/source_manifest.md`](../../data/sources/source_manifest.md)
- 覆盖说明：[`data/sources/coverage.md`](../../data/sources/coverage.md)
- 数据 schema：[`data/schema/legal_core.sql`](../../data/schema/legal_core.sql)
- 运行时许可证/来源说明：[`data/runtime/DATA_SOURCES.md`](../../data/runtime/DATA_SOURCES.md)
- 构建、压缩、严格审计工具：`data/build/`

完整归档库及其 manifest 仅用于数据构建和审计，不随产品包提供，也不作为普通 Git blob。`data/build` 中少数历史默认输出仍可能记录旧桌面路径；这些路径只属于数据构建工具，不影响产品运行时和便携打包路径，后续数据构建迁移由维护者单独处理。

法律文本及来源受官方站点、法律法规和各自许可约束。仓库 MIT 许可证只适用于本项目代码，不重新许可第三方法律文本、字体、模型或外部内容。

## 最高人民法院案例 sidecar

案例运行时文件为 `data/runtime/judicial_cases.sqlite`，与 `legal_core.sqlite` 同目录、独立更新和只读打开。其发行清单为 [`data/generated/judicial_cases_manifest.json`](../../data/generated/judicial_cases_manifest.json)，包内副本为 `data/runtime/judicial_cases_manifest.json`；`CASE_DATA_SOURCES.md` 随案例库发行并记录官方来源、抓取边界、许可和覆盖限制。

打包前必须同时核对案例文件的 `size_bytes`、`sha256`、`schema_version`、`counts` 和官方最高人民法院 `source`。数据库还必须通过 SQLite 完整性检查、`database_metadata.schema_version`/`PRAGMA user_version` 检查以及 `judicial_cases` 表结构检查。案例记录数量以 manifest 为准，文档不硬编码会随官方快照变化的数量。

当前案例范围以清单声明为准，重点覆盖最高人民法院指导案例，并可包含官方参考案例；它不宣称覆盖全国裁判文书全量，也不把模型生成内容写入案例库。案例库缺失或不兼容时，法条库仍保持原有身份和可用性，案例检索应明确报告不可用。

## 本地验证

准备好 `data/runtime/legal_core.sqlite`、`data/runtime/judicial_cases.sqlite` 和对应 manifest 后，可以直接运行便携打包自检（不重新编译）：

```powershell
python -m unittest scripts.test_package_portable -v
python scripts/package_portable.py --skip-build
```

## English

Lawyer Assistance builds local read-only statute and case indexes from traceable official public sources. The Web portable package contains only the runtime projections, not crawler state, audit payloads, or the full archival database.

The runtime file is `data/runtime/legal_core.sqlite`; its identity is fixed by `data/generated/legal_core_distribution_manifest.json`. Packaging verifies its size, SHA-256, and the SQLite `database_metadata.source_manifest_sha256`. The full archive and build/audit state stay outside the product package.

The judicial sidecar is `data/runtime/judicial_cases.sqlite`, discovered beside the statute database and kept independently replaceable. Its source manifest is `data/generated/judicial_cases_manifest.json`, with a packaged copy at `data/runtime/judicial_cases_manifest.json`; `CASE_DATA_SOURCES.md` records the official source and coverage boundary. Packaging verifies its declared size, SHA-256, schema version, record counts, and Supreme People's Court source, plus SQLite integrity, metadata/user schema version, and the `judicial_cases` table shape. Counts come from the manifest so they can follow the official snapshot without stale documentation. The corpus focuses on Supreme People's Court guiding cases and may include official reference cases; it is not a complete national judgment corpus. A missing or incompatible sidecar is reported as unavailable while the statute database identity remains unchanged.

Source coverage, schema, and licensing constraints are documented under `data/sources/`, `data/schema/`, and `data/runtime/`. The MIT license applies to project code only and does not relicense third-party legal text, fonts, models, or other external content.
