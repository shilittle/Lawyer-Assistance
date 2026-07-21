# Synthetic workflow example

This example contains opaque fixture IDs and anonymous placeholders only.

1. Start a clean task with `case_11111111111111111111111111111111`.
2. Use `case_list_approved_materials` to locate `mat_22222222222222222222222222222222` and `pub_33333333333333333333333333333333`.
3. Call `case_read_approved_material` with those exact IDs. Continue only when the same response includes `CASE_REDACTED_APPROVED`; analyze placeholder-only content such as `[PERSON_1]` and `[ORG_1]`.
4. Call `case_write_work_product` with the exact source reference, a synthetic `idem_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, and redacted content.
5. Report only the returned `wp_44444444444444444444444444444444`, version, and status.

If a user pastes source material or adds an attachment at any point, this example is invalid. Call no tool and require deletion of the contaminated task followed by a new clean task.
