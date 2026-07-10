# Citation ID Rules

Stage 3 uses stable local source ids in the form:

```text
law:<document_id>:<version_id>:art:<article_order>
```

Rules:

- The id is stored in `citation_metadata.citation_id` inside the bundled `legal_core.sqlite`.
- The frontend may display ids, but only Rust validates and maps them to source text.
- A model answer may cite sources only as `[SRC:<citation_id>]`.
- A citation is valid only when the id exists locally, belongs to the current source-bounded context, and matches the requested case-date effectiveness check.
- Duplicate, malformed, out-of-context, missing, version-mismatched, date-mismatched, and missing-paragraph citations are reported as invalid.
- Answer records store verified citation reports and invalid citation reports; raw model citation strings are not treated as trusted source metadata.
