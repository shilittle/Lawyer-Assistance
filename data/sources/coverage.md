# Legal Core Coverage

Build report: `data/generated/legal_core_build_report.json`

Bundled database: `apps/desktop/src-tauri/resources/legal_core.sqlite`

Current declared-source coverage status: `complete`

Overall Stage 1 status: `partial` pending historical-version coverage and the
separately sourced guiding-case, typical-case, and document-template corpora.

Snapshot generated at: 2026-07-08T12:21:09Z

Latest strict audit: 2026-07-08T13:16:47Z

## Included Official Sources

| Source id | Source | Official total | Imported raw rows | Imported unique documents | Current text status |
| --- | --- | ---: | ---: | ---: | --- |
| `flk_npc` | 国家法律法规数据库 | 29708 | 29708 | 29689 | Complete: detail and text fetched for all unique documents |
| `gjgzk_gov` / 部门规章 | 国家规章库 | 2663 | 2663 | 2663 | Complete |
| `gjgzk_gov` / 地方政府规章 | 国家规章库 | 7941 | 7941 | 7941 | Complete |

## Included Categories

- 宪法及修正案、法律、行政法规、监察法规、地方性法规、自治条例和单行条例、经济特区法规、浦东新区法规、海南自由贸易港法规、司法解释：来自国家法律法规数据库。
- 现行有效部门规章、地方政府规章：来自国家规章库。

## Current Audit Summary

- `coverage_status = complete`
- `schema_version = 3`
- `law_documents = 40293`
- `law_versions = 40293`
- `law_articles = 1181655`
- `law_articles_fts = 1181655`
- `law_relations = 26699`
- `source_records = 110276`
- `legal_attachments = 88890`
- `ingestion_audit = 40293`
- `placeholder_article_count = 0`
- `fixture_demo_marker_hits = 0`

## Not Included In Stage 1

- Guiding cases, typical cases, and document templates from separate official sources.

The bundled database is complete for the declared statutory-source subset of
Stage 1B. It must not be described as completing the full Stage 1/MVP data scope
or as including separate full guiding-case, typical-case, or document-template
corpora until those sources are explicitly added and audited. The 2026-07-10
review also found that every current document has exactly one `law_versions`
row and every `effective_to` value is null, so historical-version product
acceptance remains pending even though date-filtering logic is covered by test
fixtures.

## Stage 1B Build Commands

Full WAF-safe build:

```powershell
python data\build\build_legal_core.py --stage all --source all --resume --workers 1 --min-delay 3 --max-delay 8 --stop-on-waf --strict --output apps\desktop\src-tauri\resources\legal_core.sqlite --report data\generated\legal_core_build_report.json
```

Strict audit:

```powershell
python data\build\build_legal_core.py --stage audit --strict --output apps\desktop\src-tauri\resources\legal_core.sqlite --report data\generated\legal_core_strict_audit_report.json
```
