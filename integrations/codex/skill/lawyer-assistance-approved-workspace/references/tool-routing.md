# Tool routing

The exact `approved_case_workspace` surface contains the five public-law tools followed by:

1. `case_list`
2. `case_get_public_metadata`
3. `case_list_approved_materials`
4. `case_read_approved_material`
5. `case_search_approved_materials`
6. `case_list_work_products`
7. `case_read_work_product`
8. `case_write_work_product`
9. `case_update_work_product`
10. `case_export_work_product_manifest`
11. `diagram.list_templates`
12. `diagram.get_schema`
13. `diagram.validate`
14. `diagram.render`
15. `diagram.update`
16. `diagram.export`

Use list/metadata/search calls only for opaque-ID navigation. Only a direct current-task approved-material read carrying `CASE_REDACTED_APPROVED` supplies case content. Use the public-law tools only on this reviewed server; never route case text to outside search.

Text sinks are `case_write_work_product` and `case_update_work_product`; approved diagram sinks are `diagram.render` and `diagram.update`. All bind exact approved source generations and use immutable/idempotent versioning. Every create/update must be verified through an immediate exact-version `case_read_work_product`; no write response alone is a trusted final result. `diagram.export` returns only verified descriptor metadata bound to the signed work-product manifest. No approved tool accepts a host path, artifact URI, or export destination.

The `read` and `write` groups retain their original ten case grants. Diagram calls require the separate `diagram_read` and `diagram_write` groups, so upgrading a session never silently expands its authority.
