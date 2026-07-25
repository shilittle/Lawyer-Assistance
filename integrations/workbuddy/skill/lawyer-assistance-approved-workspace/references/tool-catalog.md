# Tool catalog

The qualification-gated `approved_case_workspace` profile advertises exactly 21 closed-world tools, in this order:

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
16. `diagram.list_templates`
17. `diagram.get_schema`
18. `diagram.validate`
19. `diagram.render`
20. `diagram.update`
21. `diagram.export`

The four write tools—`case_write_work_product`, `case_update_work_product`, `diagram.render`, and `diagram.update`—are non-destructive, idempotent, closed-world mutations and require confirmation. The other tools are read-only. No approved-profile tool accepts an arbitrary path, artifact URI, or destination.

The App grants the ten case operations through `read`/`write` and the six diagram operations through separate `diagram_read`/`diagram_write` groups. Advertising a tool in `tools/list` does not grant it; a missing group must fail with `STANDALONE_GRANT_DENIED`.

For case content, list, metadata, and search results are navigation only. Only the current direct `case_read_approved_material` response with `CASE_REDACTED_APPROVED` is a content source. Text outputs go only to `case_write_work_product` or `case_update_work_product`; diagrams go only to `diagram.render` or `diagram.update`, which publish encrypted protected HTML work products. `diagram.export` returns descriptor metadata only.
