# Tool catalog

The qualification-gated `approved_case_workspace` profile exposes exactly 15 closed-world tools, in this order:

1. `system_status`
2. `legal_search`
3. `legal_get_article`
4. `legal_get_versions`
5. `legal_get_relations`
6. `case_list`
7. `case_get_public_metadata`
8. `case_list_approved_materials`
9. `case_read_approved_material`
10. `case_search_approved_materials`
11. `case_list_work_products`
12. `case_read_work_product`
13. `case_write_work_product`
14. `case_update_work_product`
15. `case_export_work_product_manifest`

The two write tools are non-destructive, idempotent, closed-world mutations and require confirmation. The other tools are read-only. No tool accepts an arbitrary path or destination.

For case content, list, metadata, and search results are navigation only. Only the current direct `case_read_approved_material` response with `CASE_REDACTED_APPROVED` is a content source. Substantive outputs go only to `case_write_work_product` or `case_update_work_product`.
