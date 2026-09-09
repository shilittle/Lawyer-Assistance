# 法律数据与运行时数据库 / Legal corpus and runtime database

Lawyer Assistance 使用公开、可追溯的官方法律来源构建本地只读索引。Web 便携包只包含运行时投影，不包含抓取状态、审计原文或完整归档数据库。

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

## 本地验证

准备好 `data/runtime/legal_core.sqlite` 后，可以直接运行便携打包自检（不重新编译）：

```powershell
python -m unittest scripts.test_package_portable -v
python scripts/package_portable.py --skip-build
```

## English

Lawyer Assistance builds a local read-only index from traceable official public sources. The Web portable package contains only the runtime projection, not crawler state, audit payloads, or the full archival database.

The runtime file is `data/runtime/legal_core.sqlite`; its identity is fixed by `data/generated/legal_core_distribution_manifest.json`. Packaging verifies its size, SHA-256, and the SQLite `database_metadata.source_manifest_sha256`. The full archive and build/audit state stay outside the product package.

Source coverage, schema, and licensing constraints are documented under `data/sources/`, `data/schema/`, and `data/runtime/`. The MIT license applies to project code only and does not relicense third-party legal text, fonts, models, or other external content.
