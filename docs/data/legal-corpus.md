# 法律数据集与运行时数据库 / Legal corpus and runtime database

Lawyer Assistance 使用公开、可追溯的官方法律来源构建本地只读索引。应用安装包只包含
运行时投影，不包含构建过程中的抓取状态、审计原文或完整归档数据库。

## 两类数据库

### 运行时投影

应用使用 `runtime-slim-v1` 投影：

```text
path: apps/desktop/src-tauri/resources/legal_core.sqlite
size: 1,775,419,392 bytes
sha256: 86574bba91950b194c6530586eebbae31c689a5bd2a485877b3eed6b611f7d3c
```

其身份由 `data/generated/legal_core_distribution_manifest.json` 固定。正式打包脚本会在
编译前重新验证大小、SHA-256、schema、记录数量与 FTS 一致性。

### 完整归档库

完整归档与审计权威由以下 manifest 描述：

```text
path: data/generated/legal_core_full.sqlite
expected size: 4,512,894,976 bytes
expected sha256: 31cf1995cc09f0e3e00f70bfcf20cf67548f1a6362706ccc11d1fd3b2ebc26ac
```

完整归档库不打包进桌面应用，也不作为普通 Git blob 提交。公开源码仓库中的 manifest、
schema、构建器和来源清单用于重建与核验；缺少完整归档库时不得声称完成 strict
archival/provenance audit。

## 来源与许可

- 来源清单：[`data/sources/source_manifest.md`](../../data/sources/source_manifest.md)
- 数据 schema：[`data/schema/legal_core.sql`](../../data/schema/legal_core.sql)
- 运行时分发 manifest：
  [`data/generated/legal_core_distribution_manifest.json`](../../data/generated/legal_core_distribution_manifest.json)
- 完整归档 manifest：
  [`data/generated/legal_core_full_manifest.json`](../../data/generated/legal_core_full_manifest.json)
- 安装包数据说明：
  [`apps/desktop/src-tauri/resources/DATA_SOURCES.md`](../../apps/desktop/src-tauri/resources/DATA_SOURCES.md)

法律文本及其来源受相应官方站点、法律法规与数据许可条件约束。仓库的 MIT 许可证仅适用
于本项目代码，不重新许可第三方法律文本、字体、模型或其他外部内容。

## 验证

在运行时数据库已放置到固定资源路径后执行：

```powershell
python apps\desktop\scripts\verify_legal_resource.py `
  --resource apps\desktop\src-tauri\resources\legal_core.sqlite `
  --manifest data\generated\legal_core_distribution_manifest.json
```

## English

Lawyer Assistance builds its local read-only legal index from traceable public
official sources. The desktop installer contains only the `runtime-slim-v1`
projection. It does not bundle crawler state, audit payloads, or the full
archival database.

The runtime projection is fixed by
`data/generated/legal_core_distribution_manifest.json`; formal packaging
rechecks its size, SHA-256, schema, row counts, and FTS consistency. The full
archive is described by `legal_core_full_manifest.json`, remains outside normal
Git objects and the desktop package, and is required only for strict archival
and provenance audits.

The repository MIT license covers project code only. It does not relicense
third-party legal text, fonts, models, or other external content.
