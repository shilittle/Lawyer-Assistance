# Data and result versions (v1.0.0)

The v1.0.0 Web release treats `legal_core.sqlite` as a read-only legal resource. A missing or incompatible legal database does not prevent startup; a legal call reports the availability failure. `system_status` keeps its existing response shape and marks `user_database` unavailable in public mode without opening it.

Private workspace records, originals, mappings, and encrypted content are owned by the local application service under the new Web workspace directory. MCP has no database path, mapping, or original-content API. `privacy_workspace.read_result` returns only the current published result ID supplied by the backend. Revoked, stale, failed, or review-required results are rejected by that backend.
