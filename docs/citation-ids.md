# Citation ID Rules

Stage 3 uses stable local source ids in the form:

```text
law:<document_id>:<version_id>:art:<article_order>
```

Rules:

- The id is stored in `citation_metadata.citation_id` inside the bundled `legal_core.sqlite`.
- Citation ids are immutable source identities. Historical-version normalization may reparent `law_versions.document_id` and `law_articles.document_id` to the current canonical document while retaining the original `<document_id>` component in existing citation ids.
- Rust resolves every exact citation id through `citation_metadata`. For a missing paragraph under a retained historical id, the validator treats the historical document component as compatible only when another stored citation for that same version proves the exact `law:<document_id>:<version_id>:art:` prefix. This preserves `ParagraphNotFound` for forged paragraph numbers without accepting a document/version combination that has no stored provenance.
- The frontend may display ids, but only Rust validates and maps them to source text.
- A model answer may cite sources only as `[SRC:<citation_id>]`.
- A citation is valid only when the id exists locally, belongs to the current source-bounded context, and matches the requested case-date effectiveness check.
- Duplicate, malformed, out-of-context, missing, version-mismatched, date-mismatched, and missing-paragraph citations are reported as invalid.
- Answer records store verified citation reports and invalid citation reports; raw model citation strings are not treated as trusted source metadata.
