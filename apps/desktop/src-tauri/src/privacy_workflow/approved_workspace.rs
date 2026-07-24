use super::*;
use privacy::{
    unprotect_local,
    vnext::Sha256Hex,
    workspace::{APPROVED_MATERIAL_READ_PURPOSE, APPROVED_WORKSPACE_DESTINATION_SCOPE},
    SignedRedactionReceipt,
};
use zeroize::Zeroizing;

pub(crate) struct ApprovedGenerationSource {
    pub redaction_id: String,
    pub case_id: Option<String>,
    pub material_id: String,
    pub source_sha256: String,
    pub source_name_sha256: Sha256Hex,
    pub source_revision_hash: Sha256Hex,
    pub extraction_sha256: String,
    pub redacted_content_sha256: String,
    pub approved_payload_sha256: String,
    pub content_media_type: String,
    pub approved_payload: Vec<u8>,
    pub policy_id: String,
    pub policy_version: u32,
    pub detector_version: String,
    pub processing_version: String,
    pub backend_trace: Vec<BackendTrace>,
    pub summary: RedactionSummary,
    pub dictionary_revision_hash: Sha256Hex,
    pub mapping_revision_hash: Sha256Hex,
    /// Decrypted only while the final workflow gate is held. These values are never serialized
    /// and are zeroized as soon as the publication call returns.
    pub case_dictionary_terms: Zeroizing<Vec<String>>,
    pub source_terms: Zeroizing<Vec<String>>,
    pub raw_canary_terms: Zeroizing<Vec<String>>,
    pub receipt: SignedRedactionReceipt,
}

impl fmt::Debug for ApprovedGenerationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedGenerationSource")
            .field("redaction_id", &self.redaction_id)
            .field("case_id", &self.case_id)
            .field("material_id", &self.material_id)
            .field("source_sha256", &self.source_sha256)
            .field("source_name_sha256", &self.source_name_sha256)
            .field("source_revision_hash", &self.source_revision_hash)
            .field("extraction_sha256", &self.extraction_sha256)
            .field("redacted_content_sha256", &self.redacted_content_sha256)
            .field("approved_payload_sha256", &self.approved_payload_sha256)
            .field("content_media_type", &self.content_media_type)
            .field("approved_payload", &"<redacted-approved-payload>")
            .field("processing_version", &self.processing_version)
            .field("receipt_id", &self.receipt.claims.receipt_id)
            .field("policy_id", &self.policy_id)
            .field("policy_version", &self.policy_version)
            .field("detector_version", &self.detector_version)
            .field("dictionary_revision_hash", &self.dictionary_revision_hash)
            .field("mapping_revision_hash", &self.mapping_revision_hash)
            .field(
                "case_dictionary_term_count",
                &self.case_dictionary_terms.len(),
            )
            .field("source_term_count", &self.source_terms.len())
            .field("raw_canary_term_count", &self.raw_canary_terms.len())
            .finish()
    }
}

impl PrivacyWorkflowManager {
    /// Keep the workflow operation gate held from the final live source and
    /// receipt verification through the caller's publication commit. Any
    /// review edit, deletion, or receipt-revoking deletion must wait until the
    /// publication reaches a terminal result.
    pub(crate) fn with_approved_generation_source_publish<T, E, F>(
        &self,
        redaction_id: &str,
        expected_approved_payload_sha256: &str,
        publish: F,
    ) -> Result<Result<T, E>, PrivacyWorkflowError>
    where
        F: FnOnce(ApprovedGenerationSource) -> Result<T, E>,
    {
        let _gate = self.gate();
        let source = self.load_approved_generation_source_unlocked(
            redaction_id,
            expected_approved_payload_sha256,
        )?;
        Ok(publish(source))
    }

    #[cfg(test)]
    pub(crate) fn load_approved_generation_source(
        &self,
        redaction_id: &str,
        expected_approved_payload_sha256: &str,
    ) -> Result<ApprovedGenerationSource, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.load_approved_generation_source_unlocked(
            redaction_id,
            expected_approved_payload_sha256,
        )
    }

    fn load_approved_generation_source_unlocked(
        &self,
        redaction_id: &str,
        expected_approved_payload_sha256: &str,
    ) -> Result<ApprovedGenerationSource, PrivacyWorkflowError> {
        if !valid_identifier(redaction_id) || !valid_hash(expected_approved_payload_sha256) {
            return Err(PrivacyWorkflowError::new(
                "approved_generation_request_invalid",
                "The approved generation request is invalid.",
            ));
        }

        let connection = self.open_connection()?;
        let loaded = PrivacyStore::load_review_draft(&connection, redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        if loaded.review_state != "approved" || loaded.unresolved_high_risk_count != 0 {
            return Err(PrivacyWorkflowError::new(
                "redaction_not_approved",
                "Only a fully approved local review can be published.",
            ));
        }
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "review_payload_invalid",
                    "The approved local review payload is invalid.",
                )
            })?;
        validate_loaded_review(&loaded, &stored)?;
        let vault_binding = self
            .verify_stored_vault_source(&connection, &stored)?
            .ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "approved_generation_vault_binding_required",
                    "Approved workspace publication requires a live, exact Vault source binding.",
                )
            })?;
        let persisted_source_name_sha256 = connection
            .query_row(
                "SELECT source_name_sha256 FROM privacy_materials WHERE material_id=?1",
                [&loaded.material_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "The source-name binding could not be verified.",
                )
            })?;
        if persisted_source_name_sha256 != sha256_hex(stored.source_display_name.as_bytes()) {
            return Err(PrivacyWorkflowError::new(
                "approved_generation_source_name_mismatch",
                "The protected source-name binding changed; publication is blocked.",
            ));
        }
        let source_name_sha256 = Sha256Hex::parse(persisted_source_name_sha256).map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_generation_source_name_mismatch",
                "The persisted source-name binding is invalid; publication is blocked.",
            )
        })?;

        let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(|| {
            PrivacyWorkflowError::new(
                "approved_generation_case_binding_missing",
                "The approved generation is not bound to a case dictionary.",
            )
        })?)
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_generation_case_binding_invalid",
                "The approved generation case binding is invalid.",
            )
        })?;
        let dictionary =
            case_dictionary_store::load_required_case_dictionary(&connection, self, &case_id)?;
        let risk_state = self.load_risk_state_unlocked(&connection, redaction_id)?;
        verify_dictionary_revision(&risk_state.session, &dictionary)?;
        let now_unix = self.current_unix()?;
        let mapping_revision_hash = current_or_absent_mapping_revision_hash(
            &connection,
            redaction_id,
            &loaded.material_id,
            now_unix,
        )?;

        let mut source_terms = Vec::new();
        let source_name = stored.source_display_name.trim();
        if !source_name.is_empty() {
            source_terms.push(source_name.to_owned());
            if let Some(stem) = Path::new(source_name)
                .file_stem()
                .and_then(|value| value.to_str())
                .map(str::trim)
                .filter(|value| !value.is_empty() && *value != source_name)
            {
                source_terms.push(stem.to_owned());
            }
        }

        let pages = stored
            .pages
            .iter()
            .map(|page| CanonicalRedactedPage {
                page_number: page.page_number,
                text: page.suggested_redacted_text.clone(),
            })
            .collect::<Vec<_>>();
        reject_normalized_canaries(&pages, &stored.forbidden_canaries)?;
        let approved = ApprovedPayload {
            schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
            source_sha256: &stored.source_sha256,
            extraction_sha256: &stored.extraction_sha256,
            media_type: &stored.media_type,
            pages: &pages,
        };
        let approved_payload = serde_json::to_vec(&approved).map_err(|_| {
            PrivacyWorkflowError::new(
                "canonicalization_failed",
                "The approved payload could not be canonicalized.",
            )
        })?;
        let approved_payload_sha256 = sha256_hex(&approved_payload);
        let source_revision_hash = Sha256Hex::parse(sha256_hex(
            format!(
                "privacy-source-revision-binding-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                case_id.as_str(),
                loaded.material_id,
                redaction_id,
                vault_binding.object_id.as_str(),
                vault_binding.object_version,
                stored.source_sha256,
                source_name_sha256.as_str(),
                stored.extraction_sha256,
                approved_payload_sha256,
            )
            .as_bytes(),
        ))
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_generation_source_revision_invalid",
                "The exact Vault source revision binding is invalid.",
            )
        })?;
        let persisted_payload_sha256 = connection
            .query_row(
                "SELECT approved_payload_sha256 FROM privacy_redactions
                 WHERE redaction_id=?1 AND review_state='approved'",
                [redaction_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "The approved payload binding could not be read.",
                )
            })?
            .flatten()
            .ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "redaction_not_approved",
                    "The approved payload binding is unavailable.",
                )
            })?;
        if persisted_payload_sha256 != approved_payload_sha256
            || expected_approved_payload_sha256 != approved_payload_sha256
        {
            return Err(PrivacyWorkflowError::new(
                "approved_payload_mismatch",
                "The approved payload has changed since the human approval.",
            ));
        }

        let destination = DestinationScope {
            kind: DestinationKind::ExternalMcpHost,
            identifier: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
        };
        let destination_hash = sha256_hex(destination.identifier.as_bytes());
        let protected_token = connection
            .query_row(
                "SELECT signed_token FROM privacy_receipts
                 WHERE redaction_id=?1 AND destination_kind='external_mcp_host'
                   AND destination_identifier_sha256=?2 AND purpose=?3
                   AND revoked_at_unix IS NULL
                 ORDER BY issued_at_unix DESC,receipt_id DESC LIMIT 1",
                rusqlite::params![
                    redaction_id,
                    destination_hash,
                    APPROVED_MATERIAL_READ_PURPOSE
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_store_database_error",
                    "The approved workspace receipt could not be read.",
                )
            })?
            .ok_or_else(|| {
                PrivacyWorkflowError::new(
                    "approved_workspace_receipt_required",
                    "A current human approval for the approved MCP workspace is required.",
                )
            })?;
        let token_bytes = unprotect_local(&protected_token).map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_workspace_receipt_invalid",
                "The approved workspace receipt could not be verified.",
            )
        })?;
        let token = std::str::from_utf8(&token_bytes).map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_workspace_receipt_invalid",
                "The approved workspace receipt could not be verified.",
            )
        })?;
        let signer = self.receipt_signer()?;
        let receipt = PrivacyStore::verify_active_receipt_token(
            &connection,
            &signer,
            &ActiveReceiptVerification {
                redaction_id,
                signed_token: token,
                approved_payload: &approved_payload,
                destination: &destination,
                purpose: APPROVED_MATERIAL_READ_PURPOSE,
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        )
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "approved_workspace_receipt_invalid",
                "The approved workspace receipt is expired, revoked, or mismatched.",
            )
        })?;

        Ok(ApprovedGenerationSource {
            redaction_id: redaction_id.to_owned(),
            case_id: stored.case_id,
            material_id: loaded.material_id,
            source_sha256: stored.source_sha256,
            source_name_sha256,
            source_revision_hash,
            extraction_sha256: stored.extraction_sha256,
            redacted_content_sha256: loaded.redacted_content_sha256,
            approved_payload_sha256,
            content_media_type: "application/vnd.lawyer-assistance.approved+json".to_owned(),
            approved_payload,
            processing_version: stored.processing_version,
            backend_trace: stored.backend_trace,
            summary: stored.summary,
            dictionary_revision_hash: dictionary.revision_hash().clone(),
            mapping_revision_hash,
            case_dictionary_terms: Zeroizing::new(dictionary.egress_terms()),
            source_terms: Zeroizing::new(source_terms),
            raw_canary_terms: Zeroizing::new(stored.forbidden_canaries),
            receipt,
            policy_id: loaded.policy_id,
            policy_version: loaded.policy_version,
            detector_version: loaded.detector_version,
        })
    }
}

fn current_or_absent_mapping_revision_hash(
    connection: &Connection,
    redaction_id: &str,
    material_id: &str,
    now_unix: u64,
) -> Result<Sha256Hex, PrivacyWorkflowError> {
    type MappingRevisionRow = (
        String,
        i64,
        i64,
        String,
        Option<i64>,
        i64,
        i64,
        String,
        Option<Vec<u8>>,
    );
    let row: Option<MappingRevisionRow> = connection
        .query_row(
            "SELECT m.mapping_id,m.revision,m.key_version,m.mapping_revision_sha256,
                    m.revoked_at_unix,m.created_at_unix,m.expires_at_unix,k.state,k.protected_key
             FROM privacy_sensitive_mappings m
             JOIN privacy_redactions r ON r.redaction_id=m.redaction_id
             JOIN privacy_mapping_keys k ON k.key_version=m.key_version
             WHERE m.redaction_id=?1 AND r.material_id=?2
             ORDER BY m.revision DESC,m.created_at_unix DESC,m.mapping_id ASC LIMIT 1",
            rusqlite::params![redaction_id, material_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_mapping_revision_query_failed",
                "The encrypted mapping revision could not be queried.",
            )
        })?;
    match row {
        Some((_, _, _, _, Some(_), _, _, _, _)) => Err(PrivacyWorkflowError::new(
            "privacy_mapping_revision_revoked",
            "The encrypted mapping revision has been revoked; republish is blocked.",
        )),
        Some((_, _, _, _, None, _, expires_at_unix, _, _))
            if u64::try_from(expires_at_unix).map_or(true, |expires_at| now_unix >= expires_at) =>
        {
            Err(PrivacyWorkflowError::new(
                "privacy_mapping_revision_expired",
                "The encrypted mapping revision has expired; republish is blocked.",
            ))
        }
        Some((_, _, _, _, None, _, _, state, protected_key))
            if !matches!(state.as_str(), "active" | "retired") || protected_key.is_none() =>
        {
            Err(PrivacyWorkflowError::new(
                "privacy_mapping_key_revoked",
                "The encrypted mapping key is unavailable; republish is blocked.",
            ))
        }
        Some((
            mapping_id,
            revision,
            key_version,
            mapping_content_hash,
            None,
            created_at_unix,
            expires_at_unix,
            _,
            _,
        )) => {
            if !valid_identifier(&mapping_id) {
                return Err(PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping revision identity is invalid.",
                ));
            }
            let revision = u64::try_from(revision).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping revision number is invalid.",
                )
            })?;
            let key_version = u64::try_from(key_version).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping key version is invalid.",
                )
            })?;
            let created_at_unix = u64::try_from(created_at_unix).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping creation time is invalid.",
                )
            })?;
            let expires_at_unix = u64::try_from(expires_at_unix).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping expiry is invalid.",
                )
            })?;
            let mapping_content_hash = Sha256Hex::parse(mapping_content_hash).map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping content hash is invalid.",
                )
            })?;
            if revision == 0 || key_version == 0 || created_at_unix >= expires_at_unix {
                return Err(PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping revision metadata is invalid.",
                ));
            }
            Sha256Hex::parse(sha256_hex(
                format!(
                    "privacy-mapping-revision-binding-v1\0{mapping_id}\0{redaction_id}\0{material_id}\0{revision}\0{key_version}\0{}\0{created_at_unix}\0{expires_at_unix}",
                    mapping_content_hash.as_str(),
                )
                .as_bytes(),
            ))
            .map_err(|_| {
                PrivacyWorkflowError::new(
                    "privacy_mapping_revision_invalid",
                    "The encrypted mapping revision binding is invalid.",
                )
            })
        }
        None => Sha256Hex::parse(sha256_hex(
            format!("privacy-mapping-absence-v1\0{redaction_id}\0{material_id}").as_bytes(),
        ))
        .map_err(|_| {
            PrivacyWorkflowError::new(
                "privacy_mapping_revision_invalid",
                "The absent mapping revision binding is invalid.",
            )
        }),
    }
}
