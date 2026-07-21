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

Use list/metadata/search calls only for opaque-ID navigation. Only a direct current-task approved-material read carrying `CASE_REDACTED_APPROVED` supplies case content. Use the public-law tools only on this reviewed server; never route case text to outside search.

The only substantive sinks are `case_write_work_product` and `case_update_work_product`. Both bind approved source references and use immutable/idempotent versioning. No tool accepts a host path or export destination.
