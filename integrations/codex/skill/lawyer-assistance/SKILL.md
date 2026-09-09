---
name: lawyer-assistance
description: Research public Chinese law through the five-tool public_law_only Lawyer Assistance MCP profile. Use only public legal questions with no client or source material.
---

# Lawyer Assistance

Use this Skill only for public-law research. Do not provide case originals, client information, source files, mappings, token values, or private workspace paths to a host or tool.

Verify that `tools/list` contains exactly `system_status`, `legal_search`, `legal_get_article`, `legal_get_versions`, and `legal_get_relations`. Call `system_status` first, then use version and article tools to cite the applicable public text. Report legal source, effective date, and any unavailable data.

The privacy workspace is configured separately and only returns backend-published redacted results.
