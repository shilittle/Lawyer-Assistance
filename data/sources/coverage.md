# Legal Core Coverage

Stage 1B pre-normalization build report (historical):
`data/generated/legal_core_build_report.json`

Current Stage 1C reports: `data/generated/stage_1c_history_report.json`,
`data/generated/stage_1c_corpora_report.json`, and
`data/generated/legal_core_strict_audit_report.json`

Archival/audit database: `data/generated/legal_core_full.sqlite`

Bundled runtime projection: `apps/desktop/src-tauri/resources/legal_core.sqlite`

- Archival size/SHA-256: `4512894976` /
  `31cf1995cc09f0e3e00f70bfcf20cf67548f1a6362706ccc11d1fd3b2ebc26ac`
- Runtime size/SHA-256: `1775419392` /
  `86574bba91950b194c6530586eebbae31c689a5bd2a485877b3eed6b611f7d3c`
- Runtime profile: `runtime-slim-v1`

Current declared-source coverage status: `complete`

Overall Stage 1 data/implementation status: `complete_with_declared_exceptions`.
Stage 1 product acceptance was completed on 2026-07-12 using the formal release
database and the recorded offline-process evidence. Stage 1C covers 4,481 normalized official
historical-version families and records all 1,121 unresolved families in
`history_version_exceptions`. The separately sourced guiding-case, typical-case,
and document-template corpora are complete for the declared 2026-07-11 Supreme
People's Court website snapshot.

Stage 1B snapshot generated at: 2026-07-08T12:21:09Z

Stage 1C snapshot finalized at: 2026-07-11T13:48:41Z

Latest archival strict-audit report: 2026-07-12 (complete, zero failures)

Latest runtime compaction verification: 2026-07-13 (complete, zero failures)

## Included Official Sources

| Source id | Source | Official total | Imported raw rows | Imported unique documents | Current text status |
| --- | --- | ---: | ---: | ---: | --- |
| `flk_npc` | 国家法律法规数据库 | 29708 | 29708 | 29689 | Complete: detail and text fetched for all unique documents |
| `gjgzk_gov` / 部门规章 | 国家规章库 | 2663 | 2663 | 2663 | Complete |
| `gjgzk_gov` / 地方政府规章 | 国家规章库 | 7941 | 7941 | 7941 | Complete |

## Included Categories

- 宪法及修正案、法律、行政法规、监察法规、地方性法规、自治条例和单行条例、经济特区法规、浦东新区法规、海南自由贸易港法规、司法解释：来自国家法律法规数据库。
- 现行有效部门规章、地方政府规章：来自国家规章库。

## Current Archival Audit Summary

The counts below describe `legal_core_full.sqlite`, which remains the strict
coverage, provenance, and rebuild authority. They must not be attributed to the
smaller bundled runtime when a listed audit-only table is intentionally omitted.

- `coverage_status = complete`
- `schema_version = 4`
- `law_documents = 34549`
- `law_versions = 40293`
- `law_articles = 1181655`
- `law_articles_fts = 1181655`
- `law_relations = 12141`
- `source_records = 111733`
- `legal_attachments = 88890`
- `ingestion_audit = 42347`
- `guiding_cases = 1302` (278 individual guiding cases, 15 batch notices, 412 typical-case collections, 597 stable per-case records)
- `document_templates = 752`
- `history_version_exceptions = 1121`
- `placeholder_article_count = 0`
- `fixture_demo_marker_hits = 0`

## Bundled Runtime Projection Summary

The verified runtime projection retains every application-visible identity and
lookup surface:

- `law_documents = 34549`
- `law_versions = 40293`
- `law_articles_fts = 1181655`
- `citation_metadata = 1181655`
- `law_relations = 12141`
- `source_records = 111733`
- SQLite integrity `ok`, foreign-key errors `0`

It stores deduplicated article content separately and replaces the archival
`law_articles` storage table with a read-compatible view over compact rows/content; it
also omits raw fetch/audit payloads, attachments,
`history_version_exceptions`, `guiding_cases`, and `document_templates`. Those
omissions reduce the bundled database by 60.66% without dropping an article,
citation, version, relation, or source-record identity used by current commands.

## Not Included In Stage 1

- A full national judgment corpus beyond the declared Supreme People's Court
  guiding/typical-case snapshot.
- Sources, snapshots, and document categories not declared in this file and the
  embedded `source_systems` / `coverage_audit` records.

The archival database is complete for the declared statutory and Supreme
People's Court website source scopes. On 2026-07-11,
the Stage 1C history pass merged 5,744 former version-document rows into 4,481
multi-version laws and generated 5,744 bounded `effective_to` values. It left
1,121 official history families separate because their source dates are missing,
placeholder values, or otherwise ambiguous; no dates were inferred. Those
families are now recorded in a queryable audit table: 1,116 missing/placeholder
date families and 5 duplicate-effective-date families.

Stage 1C history report: `data/generated/stage_1c_history_report.json`

Archival manifest: `data/generated/legal_core_full_manifest.json`

Runtime distribution manifest: `data/generated/legal_core_distribution_manifest.json`

The runtime distribution manifest records its own 1.775 GB hash and the 4.512 GB
archival hash as `archival_source_sha256`. It intentionally remains
`local_snapshot_pending_external_publish` with no download URL. Stage 1 requires
a verified external-install workflow; publishing the artifact and URL is a
Stage 7 release action.

Stage 1C corpora report: `data/generated/stage_1c_corpora_report.json`

## Stage 1B Build Commands

Full WAF-safe build:

```powershell
python data\build\build_legal_core.py --stage all --source all --resume --workers 1 --min-delay 3 --max-delay 8 --stop-on-waf --strict --output data\generated\legal_core_full.sqlite --report data\generated\legal_core_build_report.json
```

Strict audit:

```powershell
python data\build\build_legal_core.py --stage audit --strict --output data\generated\legal_core_full.sqlite --report data\generated\legal_core_strict_audit_report.json
```

Generate and verify the bundled runtime only after the archival database passes
strict audit:

```powershell
python data\build\compact_legal_core.py
python data\build\verify_legal_core_distribution.py --source apps\desktop\src-tauri\resources\legal_core.sqlite
```
