# Approved case workflow

1. Confirm a clean task and qualification. If raw content is already present, stop with `CLEAN_TASK_REQUIRED` and call nothing.
2. Use `case_list` and public metadata/list tools only to obtain opaque IDs.
3. Treat `case_search_approved_materials` as navigation only. Read the exact selected generation with `case_read_approved_material`.
4. Continue only if that current response carries `CASE_REDACTED_APPROVED` and matching IDs. Do not merge it with attachments, paste, files, memory, old responses, or outside sources.
5. Preserve every anonymous placeholder while analyzing. Do not infer the mapping.
6. Create a result with `case_write_work_product`, binding the exact source `material_id` and `publication_id`. Update only with `case_update_work_product` using the expected parent version.
7. After each create/update, call `case_read_work_product` with the exact returned ID and version; stop unless the current response matches version, bound source generation, content hash, status, and placeholders.
8. Return only the verified opaque work-product ID, version, status, and safe reason codes in chat.

For an approved case diagram, explicitly require the `diagram_read` and `diagram_write` groups. Build the Spec only from the current direct approved-material reads, bind their exact generations in `source_approved_refs`, call `diagram.validate`, then persist through `diagram.render`. For an in-task revision, provide the exact parent work-product ID/version, base Spec/hash, and bounded patch to `diagram.update`. Immediately verify every returned ID/version with `case_read_work_product`. Use `diagram.export` only to obtain verified descriptor metadata bound to the signed work-product manifest; it never returns HTML, a path, or a URI.

Never use host export or filesystem output. `case_export_work_product_manifest` verifies and returns a manifest only.
