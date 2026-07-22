# 脱敏系统 vNext 核心 Schema 冻结版

## 1. 版本与规范

- Domain schema：lawyer-assistance-privacy-domain-v2
- OCR protocol：la-mineru-worker-v1
- Approved manifest：approved-material-manifest-v2（签名绑定 Vault 原件版本、源文件名哈希、案件词典与映射修订）
- Work product manifest：work-product-manifest-v1
- Canonical encoding：canonical-json-v1

canonical-json-v1 规则：

- UTF-8，无 BOM。
- 对象 key 按 Unicode code point 排序。
- 拒绝重复 key、未知字段、NaN、Infinity 和控制字符。
- 签名 claims 禁止浮点数；置信度使用 0–1,000,000 ppm 整数。
- 数组顺序是语义的一部分；需要无序集合时先排序、去重。
- hash 输入包含固定 domain separator 和一个 NUL 字节，再接 canonical JSON。

## 2. Opaque ID

- workspace_instance_id：ws_ 加 32 个小写十六进制字符。
- case_id：case_ 加 32 个小写十六进制字符。
- material_id：mat_ 加 32 个小写十六进制字符。
- object_id：obj_ 加 32 个小写十六进制字符。
- finding_id：fnd_ 加 32 个小写十六进制字符。
- cluster_id：clu_ 加 32 个小写十六进制字符。
- publication_id：pub_ 加 32 个小写十六进制字符。
- work_product_id：wp_ 加 32 个小写十六进制字符。
- receipt_id：rct_ 加 32 个小写十六进制字符。
- transaction_id：tx_ 加 32 个小写十六进制字符。

所有 ID 由后端生成；MCP 只接受上述精确格式。

## 3. 生命周期

MaterialState：

- imported
- assessing
- extracting_native
- ocr_required
- ocr_running
- extracted
- redacting
- review_required
- approved
- published
- stale
- revoked
- blocked
- failed

PublicationState：

- prepared
- staged
- published
- committed
- rolled_back
- quarantined

ReviewResolution：

- unresolved
- accepted
- modified
- not_sensitive
- cluster_merged
- cluster_split
- revoked

状态改变只由后端命令产生，并写入 hash-chain event log。

## 4. Vault schema

VaultObjectEnvelopeV1：

- schema_version
- workspace_instance_id
- case_id
- object_id
- object_kind
- object_version
- crypto_suite
- key_id
- key_version
- nonce
- aad_schema_version
- ciphertext_size
- ciphertext_sha256
- created_at_unix

AAD 必须绑定：

- domain
- schema_version
- workspace_instance_id
- case_id
- object_id
- object_kind
- object_version
- key_version
- chunk_index
- chunk_count

CaseKeyRecordV1：

- case_id
- key_id
- key_version
- algorithm
- wrap_provider
- wrapped_case_key
- wrap_context_hash
- created_at_unix
- rotated_at_unix
- state

Object kind：

- source_material
- private_metadata
- redaction_map
- review_state
- ocr_result
- private_manifest

原始文件名、原路径、source hash 和真实值只存在于加密 private metadata。

## 5. OCR schema

OcrDocumentV1：

- protocol_version
- document_id
- source_sha256
- input_unmodified_sha256
- page_count
- pages
- provenance
- warnings
- completeness
- output_sha256

OcrPageV1：

- page_index
- width_micropoints
- height_micropoints
- rotation_degrees
- page_image_sha256
- status：ok、verified_blank、blocked
- blocks
- coverage_ppm
- minimum_ocr_confidence_ppm
- mean_ocr_confidence_ppm
- visual_risks
- warnings
- completeness

OcrBlockV1：

- block_id
- block_type
- reading_order
- raw_text_ref
- normalized_text
- bbox
- polygon
- coordinate_system
- ocr_confidence_ppm
- layout_confidence_ppm
- confidence_available
- source_locator
- visual_classification

raw_text_ref 指向 vault 内 private OCR payload；不会进入 MCP 或普通日志。

OcrProvenanceV1：

- worker_version
- worker_sha256
- protocol_version
- python_version
- mineru_version
- pytorch_version
- cuda_runtime_version
- gpu_driver_version
- requested_device
- actual_device
- model_version
- model_manifest_sha256
- config_sha256
- isolation_evidence_id
- isolation_evidence_sha256
- qualification_report_id
- processing_parameters_sha256
- started_at_unix
- duration_ms

## 6. Finding 与 cluster

PrivacyFindingV1：

- finding_id
- case_id
- material_id
- document_version
- page_index
- block_id
- start_offset
- end_offset
- bbox
- polygon
- entity_type
- detector_sources
- detector_versions
- model_versions
- raw_score_ppm
- calibrated_confidence_ppm
- ocr_confidence_ppm
- layout_confidence_ppm
- normalization_evidence
- confusable_evidence
- case_dictionary_match
- cluster_id
- detector_agreement
- severity
- review_priority
- reason_codes
- proposed_replacement
- resolution_state
- human_override
- provenance_hash
- private_value_ref

private_value_ref 只能解析到加密 review payload。

EntityType 至少包含：

- person_name
- organization_name
- case_number
- identity_number
- passport_number
- phone_number
- landline_number
- bank_account
- email_address
- address
- organization_code
- business_license_number
- vehicle_plate
- ip_address
- social_account
- payment_account
- account_name
- contract_number
- tracking_number
- property_certificate_number
- custom

CaseDictionaryEntryV1：

- dictionary_entry_id
- case_id
- entity_type
- private_value_ref
- normalized_value_hash
- cluster_id
- replacement
- aliases_private_ref
- revision
- provenance_hash

同一 case_id 内 replacement 由持久化 alias ledger 分配，不依赖文档遇见顺序。

## 7. 风险模型

FindingSeverity：

- p0_blocking
- p1_high
- p2_medium
- p3_resolved
- informational

PageRiskV1：

- page_index
- p0_count
- p1_count
- p2_count
- p3_count
- ocr_min_ppm
- ocr_mean_ppm
- ocr_p10_ppm
- coverage_ppm
- unknown_long_number_count
- unresolved_entity_counts
- visual_risks
- completeness_passed
- detector_conflict_count
- cluster_inconsistency_count
- visual_review_required
- readiness_score
- reason_codes

DocumentRoute：

- auto_approval_eligible
- quick_review_required
- full_review_required
- blocked

DocumentRiskV1：

- route
- readiness_score
- page_risks
- total_p0
- total_p1
- total_p2
- hard_gate_evaluation_hash
- finding_summary_hash
- policy_id
- policy_version
- policy_sha256
- calibration_evidence_version
- qualification_report_id
- reason_codes

## 8. HardGateEvaluation

每个 gate 是：

- gate_id
- passed
- blocking
- reason_codes
- evidence_hashes

固定 gate：

1. qualified_processing_chain
2. complete_pages_and_order
3. no_p0
4. no_unresolved_p1
5. ocr_thresholds
6. visual_risks_resolved
7. required_dictionary_entities_stable
8. deterministic_high_risk_fields_resolved
9. detector_conflicts_resolved
10. cluster_alias_consistency
11. independent_residual_scan
12. provenance_receiptable
13. calibrated_policy
14. approval_mode_allows_automatic
15. organization_policy_allows_automatic
16. publication_target_fixed
17. exact_worker_model_qualification

readiness_score 不能修改任何 gate 的 passed 值。

## 9. 审批与 manifest

ApprovalMode：

- human
- shadow_human
- automatic

AutoApprovalPolicyMode：

- strict
- balanced
- batch
- shadow
- disabled

ApprovedMaterialManifestV1 unsigned claims：

- schema_version
- classification：CASE_REDACTED_APPROVED
- workspace_instance_id
- case_id
- material_id
- document_version
- publication_id
- content_media_type
- content_sha256
- content_bytes
- source_sha256
- extraction_sha256
- ocr_output_sha256
- finding_summary_hash
- hard_gate_evaluation_hash
- policy_id
- policy_version
- policy_sha256
- detector_versions
- model_versions
- worker_sha256
- model_manifest_sha256
- qualification_report_id
- calibration_evidence_version
- dictionary_revision_hash
- mapping_revision_hash
- approval_mode
- readiness_score
- unresolved_p0
- unresolved_p1
- unresolved_p2
- destination_scope
- purpose
- workspace_isolation_level
- issued_at_unix
- expires_at_unix
- receipt_id
- receipt_nonce
- revocation_epoch

Signed envelope：

- claims
- canonical_claims_sha256
- signing_algorithm
- signing_key_id
- signing_key_version
- signature

manifest 不包含自引用 manifest hash。文件 hash 是 signed envelope bytes 的 SHA-256。

## 10. Work product

WorkProductManifestV1：

- schema_version
- workspace_instance_id
- case_id
- work_product_id
- version
- expected_parent_version
- task_type
- status
- source_approved_refs
- source_manifest_hashes
- content_media_type
- content_sha256
- content_bytes
- placeholder_policy_version
- residual_scan_hash
- author_tool
- author_tool_version
- created_at_unix
- signed_envelope

写入采用 immutable version + optimistic concurrency + idempotency key。

## 11. MCP profile

PublicLawOnly：

- 继续精确五项公开法律工具。

ApprovedCaseWorkspace：

- case_list
- case_get_public_metadata
- case_list_approved_materials
- case_read_approved_material
- case_search_approved_materials
- case_list_work_products
- case_read_work_product
- case_write_work_product
- case_update_work_product
- case_export_work_product_manifest
- 现有五项公开法律工具

所有 request deny_unknown_fields，且 schema 中不得出现 path、filename、URI、glob、directory、URL、command 或自由 metadata object。

## 12. 失效规则

以下任一变化必须提高 revocation_epoch 或产生新 document_version，旧批准不可再读：

- source bytes
- extraction/OCR output
- redacted content
- case dictionary
- mapping/cluster
- detector/model/worker
- model manifest
- risk policy/calibration
- hard-gate evidence
- manifest/content
- destination/purpose/workspace instance
- 人工修改

