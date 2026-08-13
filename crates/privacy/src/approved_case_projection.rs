use crate::{
    project_case_binding::{ProjectId, ProjectPrivacyCaseBindingStore},
    protect_local, sha256_hex, unprotect_local, PrivacyStore, PrivacyStoreError,
    LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use uuid::Uuid;

pub const APPROVED_CASE_PAYLOAD_SCHEMA_VERSION: u16 = 1;
pub const INTERACTIVE_CASE_WORK_PURPOSE: &str = "interactive_case_work";
pub const APPROVED_CASE_PROJECTION_MIGRATION_ID: &str = "approved-case-projection-v1";
pub const MAX_APPROVED_CASE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

const APPROVED_PROJECTION_SELECT_SQL: &str = "
    SELECT
        generation.redaction_id,
        generation.material_id,
        generation.generation_number,
        generation.extraction_sha256,
        generation.redacted_content_sha256,
        generation.approved_payload_sha256,
        generation.policy_id,
        generation.policy_version,
        generation.detector_version,
        generation.risk_revision,
        generation.approved_risk_revision_hash,
        generation.row_version,
        generation.approved_payload_schema_version,
        generation.protected_approved_payload_blob,
        generation.approved_payload_protection_scheme,
        material.source_sha256,
        material.media_type,
        material.page_count,
        binding.binding_version
    FROM privacy_redactions AS generation
    JOIN privacy_materials AS material
      ON material.material_id=generation.material_id
    JOIN project_privacy_case_bindings AS binding
      ON binding.project_id=material.project_id
    WHERE generation.redaction_id=?1
      AND material.project_id=?2
      AND material.migration_status='ready'
      AND material.state IN ('approved','outbound_ready')
      AND material.deleted_at IS NULL
      AND generation.generation_status='ready'
      AND generation.review_state='approved'
      AND generation.unresolved_high_risk_count=0
      AND generation.risk_revision > 0
      AND generation.revocation_state='active'
      AND generation.revoked_at IS NULL
      AND generation.approved_payload_schema_version=1
      AND generation.protected_approved_payload_blob IS NOT NULL
      AND generation.approved_payload_protection_scheme=
          'windows_dpapi_current_user_v1'
      AND generation.approved_risk_revision_hash IS NOT NULL
      AND generation.generation_number=(
          SELECT MAX(current_generation.generation_number)
          FROM privacy_redactions AS current_generation
          WHERE current_generation.material_id=generation.material_id
      )
";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCasePageV1 {
    pub page_number: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCasePayloadV1 {
    pub schema_version: u16,
    pub source_sha256: String,
    pub extraction_sha256: String,
    pub media_type: String,
    pub pages: Vec<ApprovedCasePageV1>,
}

impl ApprovedCasePayloadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PrivacyStoreError> {
        validate_payload_shape(self)?;
        serde_json::to_vec(self).map_err(|_| PrivacyStoreError::InvalidInput)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCaseGenerationMetadata {
    pub redaction_generation_id: String,
    pub material_id: String,
    pub generation_number: u64,
    pub media_type: String,
    pub page_count: u32,
    pub approved_at: String,
    pub selected: bool,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovedCaseSourceSnapshot {
    pub project_id: String,
    pub redaction_id: String,
    pub material_id: String,
    pub generation_number: u64,
    pub source_sha256: String,
    pub extraction_sha256: String,
    pub redacted_content_sha256: String,
    pub approved_payload_sha256: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub detector_version: String,
    pub risk_revision: u64,
    pub approved_risk_revision_hash: String,
    pub generation_row_version: u64,
    pub binding_version: u64,
    pub selection_id: String,
    pub selection_row_version: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedCaseProjection {
    pub snapshot: ApprovedCaseSourceSnapshot,
    pub media_type: String,
    pub pages: Vec<ApprovedCasePageV1>,
    pub canonical_payload: Vec<u8>,
}

impl fmt::Debug for ApprovedCaseProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedCaseProjection")
            .field("snapshot", &self.snapshot)
            .field("media_type", &self.media_type)
            .field("pages", &"<approved-redacted-pages>")
            .field("canonical_payload", &"<canonical-approved-payload>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedProjectionBackfill<'a> {
    pub redaction_id: &'a str,
    pub source_fingerprint: &'a str,
    pub approved_payload_plaintext: &'a [u8],
    pub approved_risk_revision_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionRow {
    redaction_id: String,
    material_id: String,
    generation_number: u64,
    extraction_sha256: String,
    redacted_content_sha256: String,
    approved_payload_sha256: String,
    policy_id: String,
    policy_version: u32,
    detector_version: String,
    risk_revision: u64,
    approved_risk_revision_hash: String,
    row_version: u64,
    approved_payload_schema_version: u16,
    protected_approved_payload_blob: Vec<u8>,
    approved_payload_protection_scheme: String,
    source_sha256: String,
    media_type: String,
    page_count: u32,
    binding_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalRedactedContent<'a> {
    schema_version: u16,
    pages: &'a [ApprovedCasePageV1],
}

impl PrivacyStore {
    /// Lists only current, case-bound generations whose approved-only projection
    /// can be fully verified. No PrivacyCaseId or protected review payload leaves
    /// this boundary.
    pub fn list_current_approved_case_generations(
        connection: &Connection,
        project_id: &ProjectId,
    ) -> Result<Vec<ApprovedCaseGenerationMetadata>, PrivacyStoreError> {
        require_project_binding(connection, project_id)?;
        let mut statement = connection
            .prepare(
                "SELECT generation.redaction_id,generation.approved_at,
                        material.protected_display_name,material.display_name_sha256,
                        material.display_name_protection_scheme,
                        EXISTS(
                          SELECT 1 FROM case_material_selections AS selection
                          WHERE selection.project_id=?1
                            AND selection.material_id=material.material_id
                            AND selection.redaction_id=generation.redaction_id
                            AND selection.purpose='interactive_case_work'
                            AND selection.deselected_at IS NULL
                            AND selection.invalidated_at IS NULL
                        )
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE material.project_id=?1
                   AND material.migration_status='ready'
                   AND material.state IN ('approved','outbound_ready')
                   AND material.deleted_at IS NULL
                   AND generation.generation_status='ready'
                   AND generation.review_state='approved'
                   AND generation.revocation_state='active'
                   AND generation.revoked_at IS NULL
                   AND generation.generation_number=(
                       SELECT MAX(current_generation.generation_number)
                       FROM privacy_redactions AS current_generation
                       WHERE current_generation.material_id=generation.material_id
                   )
                 ORDER BY generation.material_id ASC,generation.redaction_id ASC",
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let redaction_ids = statement
            .query_map([project_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .map_err(|_| PrivacyStoreError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PrivacyStoreError::Database)?;
        redaction_ids
            .into_iter()
            .map(
                |(
                    redaction_id,
                    approved_at,
                    protected_display_name,
                    display_name_sha256,
                    display_name_scheme,
                    selected,
                )| {
                    let (row, _, _) =
                        load_verified_projection_core(connection, project_id, &redaction_id)?;
                    let display_name = load_verified_display_name(
                        protected_display_name,
                        display_name_sha256,
                        display_name_scheme,
                    )?;
                    Ok(ApprovedCaseGenerationMetadata {
                        redaction_generation_id: row.redaction_id,
                        material_id: row.material_id,
                        generation_number: row.generation_number,
                        media_type: row.media_type,
                        page_count: row.page_count,
                        approved_at,
                        selected,
                        display_name,
                    })
                },
            )
            .collect()
    }

    /// Validates exactly the caller-supplied generation IDs under an immediate
    /// write lock and append-preserves the user's `interactive_case_work`
    /// selections. Existing active selections for omitted materials are never
    /// added to the returned source set.
    pub fn validate_and_append_case_work_selections(
        connection: &mut Connection,
        project_id: &ProjectId,
        redaction_ids: &[String],
    ) -> Result<Vec<ApprovedCaseProjection>, PrivacyStoreError> {
        validate_requested_generation_ids(redaction_ids)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        require_project_binding(&transaction, project_id)?;

        let mut requested = redaction_ids.to_vec();
        requested.sort();
        let mut loaded = Vec::with_capacity(requested.len());
        let mut material_ids = BTreeSet::new();
        for redaction_id in &requested {
            let (row, payload, canonical_payload) =
                load_verified_projection_core(&transaction, project_id, redaction_id)?;
            if !material_ids.insert(row.material_id.clone()) {
                return Err(PrivacyStoreError::Conflict);
            }
            loaded.push((row, payload, canonical_payload));
        }

        let mut projections = Vec::with_capacity(loaded.len());
        for (row, payload, canonical_payload) in loaded {
            let active = transaction
                .query_row(
                    "SELECT selection_id,redaction_id,selected_generation_number,
                            selected_approved_payload_sha256,selected_risk_revision,row_version
                     FROM case_material_selections
                     WHERE project_id=?1 AND material_id=?2 AND purpose=?3
                       AND deselected_at IS NULL AND invalidated_at IS NULL",
                    params![
                        project_id.as_str(),
                        row.material_id.as_str(),
                        INTERACTIVE_CASE_WORK_PURPOSE
                    ],
                    |selection| {
                        Ok((
                            selection.get::<_, String>(0)?,
                            selection.get::<_, String>(1)?,
                            selection.get::<_, i64>(2)?,
                            selection.get::<_, String>(3)?,
                            selection.get::<_, i64>(4)?,
                            selection.get::<_, i64>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| PrivacyStoreError::Database)?;

            let exact_active = active.as_ref().is_some_and(|active| {
                active.1 == row.redaction_id
                    && u64::try_from(active.2).ok() == Some(row.generation_number)
                    && active.3 == row.approved_payload_sha256
                    && u64::try_from(active.4).ok() == Some(row.risk_revision)
            });
            let (selection_id, selection_row_version) = if exact_active {
                let active = active.ok_or(PrivacyStoreError::Conflict)?;
                (
                    active.0,
                    u64::try_from(active.5).map_err(|_| PrivacyStoreError::Database)?,
                )
            } else {
                if let Some(active) = active {
                    let changed = transaction
                        .execute(
                            "UPDATE case_material_selections
                             SET deselected_at=CURRENT_TIMESTAMP,row_version=row_version+1
                             WHERE selection_id=?1 AND row_version=?2
                               AND deselected_at IS NULL AND invalidated_at IS NULL",
                            params![active.0, active.5],
                        )
                        .map_err(map_constraint)?;
                    if changed != 1 {
                        return Err(PrivacyStoreError::Conflict);
                    }
                }
                let selection_id = format!("sel_{}", Uuid::new_v4().simple());
                transaction
                    .execute(
                        "INSERT INTO case_material_selections(
                            selection_id,project_id,material_id,redaction_id,purpose,
                            selected_by_user,selected_at,selected_generation_number,
                            selected_approved_payload_sha256,selected_risk_revision
                         ) VALUES(?1,?2,?3,?4,?5,1,CURRENT_TIMESTAMP,?6,?7,?8)",
                        params![
                            selection_id,
                            project_id.as_str(),
                            row.material_id,
                            row.redaction_id,
                            INTERACTIVE_CASE_WORK_PURPOSE,
                            sql_u64(row.generation_number)?,
                            row.approved_payload_sha256,
                            sql_u64(row.risk_revision)?,
                        ],
                    )
                    .map_err(map_constraint)?;
                (selection_id, 1)
            };
            projections.push(projection_from_parts(
                project_id,
                row,
                payload,
                canonical_payload,
                selection_id,
                selection_row_version,
            ));
        }
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(projections)
    }

    /// Revalidates exact immutable source and selection snapshots immediately
    /// before transport or confirmation. It never restores omitted active
    /// selections and never reads the legacy full review blob.
    pub fn revalidate_case_work_source_snapshots(
        connection: &Connection,
        project_id: &ProjectId,
        snapshots: &[ApprovedCaseSourceSnapshot],
    ) -> Result<Vec<ApprovedCaseProjection>, PrivacyStoreError> {
        if snapshots.is_empty() || snapshots.len() > 256 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        require_project_binding(connection, project_id)?;
        let mut redaction_ids = BTreeSet::new();
        let mut material_ids = BTreeSet::new();
        let mut projections = Vec::with_capacity(snapshots.len());
        for expected in snapshots {
            if expected.project_id != project_id.as_str()
                || !redaction_ids.insert(expected.redaction_id.clone())
                || !material_ids.insert(expected.material_id.clone())
            {
                return Err(PrivacyStoreError::Conflict);
            }
            let (row, payload, canonical_payload) =
                load_verified_projection_core(connection, project_id, &expected.redaction_id)?;
            let selection = connection
                .query_row(
                    "SELECT row_version
                     FROM case_material_selections
                     WHERE selection_id=?1 AND project_id=?2 AND material_id=?3
                       AND redaction_id=?4 AND purpose=?5
                       AND selected_generation_number=?6
                       AND selected_approved_payload_sha256=?7
                       AND selected_risk_revision=?8
                       AND deselected_at IS NULL AND invalidated_at IS NULL",
                    params![
                        expected.selection_id,
                        project_id.as_str(),
                        expected.material_id,
                        expected.redaction_id,
                        INTERACTIVE_CASE_WORK_PURPOSE,
                        sql_u64(expected.generation_number)?,
                        expected.approved_payload_sha256,
                        sql_u64(expected.risk_revision)?,
                    ],
                    |selection| selection.get::<_, i64>(0),
                )
                .optional()
                .map_err(|_| PrivacyStoreError::Database)?
                .ok_or(PrivacyStoreError::Conflict)?;
            let selection_row_version =
                u64::try_from(selection).map_err(|_| PrivacyStoreError::Database)?;
            let actual = projection_from_parts(
                project_id,
                row,
                payload,
                canonical_payload,
                expected.selection_id.clone(),
                selection_row_version,
            );
            if &actual.snapshot != expected {
                return Err(PrivacyStoreError::Conflict);
            }
            projections.push(actual);
        }
        projections
            .sort_by(|left, right| left.snapshot.redaction_id.cmp(&right.snapshot.redaction_id));
        Ok(projections)
    }

    /// Verifies the complete append-only risk chain and returns the exact head.
    pub fn verify_complete_risk_review_chain(
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<(u64, String), PrivacyStoreError> {
        validate_identifier(redaction_id)?;
        let mut statement = connection
            .prepare(
                "SELECT revision,state_sha256,risk_sha256,hard_gate_sha256,action_code,
                        reason_codes_json,protected_state_blob,protection_scheme,
                        previous_revision_hash,revision_hash
                 FROM privacy_risk_review_revisions
                 WHERE redaction_id=?1
                 ORDER BY revision ASC",
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let mut rows = statement
            .query([redaction_id])
            .map_err(|_| PrivacyStoreError::Database)?;
        let mut expected_revision = 1_u64;
        let mut previous_hash = String::new();
        let mut found = false;
        while let Some(row) = rows.next().map_err(|_| PrivacyStoreError::Database)? {
            found = true;
            let revision = u64::try_from(
                row.get::<_, i64>(0)
                    .map_err(|_| PrivacyStoreError::Database)?,
            )
            .map_err(|_| PrivacyStoreError::Database)?;
            let state_sha256 = row
                .get::<_, String>(1)
                .map_err(|_| PrivacyStoreError::Database)?;
            let risk_sha256 = row
                .get::<_, String>(2)
                .map_err(|_| PrivacyStoreError::Database)?;
            let hard_gate_sha256 = row
                .get::<_, String>(3)
                .map_err(|_| PrivacyStoreError::Database)?;
            let action_code = row
                .get::<_, String>(4)
                .map_err(|_| PrivacyStoreError::Database)?;
            let reason_codes_json = row
                .get::<_, String>(5)
                .map_err(|_| PrivacyStoreError::Database)?;
            let protected_state = row
                .get::<_, Vec<u8>>(6)
                .map_err(|_| PrivacyStoreError::Database)?;
            let protection_scheme = row
                .get::<_, String>(7)
                .map_err(|_| PrivacyStoreError::Database)?;
            let stored_previous_hash = row
                .get::<_, String>(8)
                .map_err(|_| PrivacyStoreError::Database)?;
            let revision_hash = row
                .get::<_, String>(9)
                .map_err(|_| PrivacyStoreError::Database)?;
            let reason_codes: Vec<String> = serde_json::from_str(&reason_codes_json)
                .map_err(|_| PrivacyStoreError::Conflict)?;
            let canonical_reasons =
                serde_json::to_string(&reason_codes).map_err(|_| PrivacyStoreError::Conflict)?;
            if revision != expected_revision
                || protection_scheme != LOCAL_PROTECTION_SCHEME
                || stored_previous_hash != previous_hash
                || canonical_reasons != reason_codes_json
                || !valid_lower_hash(&state_sha256)
                || !valid_lower_hash(&risk_sha256)
                || !valid_lower_hash(&hard_gate_sha256)
                || !valid_lower_hash(&revision_hash)
                || action_code.is_empty()
                || action_code.len() > 128
                || reason_codes.len() > 64
                || reason_codes.iter().collect::<BTreeSet<_>>().len() != reason_codes.len()
                || reason_codes
                    .iter()
                    .any(|reason| validate_identifier(reason).is_err())
            {
                return Err(PrivacyStoreError::Conflict);
            }
            let plaintext =
                unprotect_local(&protected_state).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
            if sha256_hex(&plaintext) != state_sha256 {
                return Err(PrivacyStoreError::Conflict);
            }
            let protected_sha256 = sha256_hex(&protected_state);
            let expected_hash = risk_revision_hash(&RiskRevisionHashInput {
                redaction_id,
                revision,
                state_sha256: &state_sha256,
                risk_sha256: &risk_sha256,
                hard_gate_sha256: &hard_gate_sha256,
                action_code: &action_code,
                reason_codes_json: &reason_codes_json,
                protected_sha256: &protected_sha256,
                previous_revision_hash: &previous_hash,
            });
            if expected_hash != revision_hash {
                return Err(PrivacyStoreError::Conflict);
            }
            previous_hash = revision_hash;
            expected_revision = expected_revision
                .checked_add(1)
                .ok_or(PrivacyStoreError::Conflict)?;
        }
        if !found {
            return Err(PrivacyStoreError::Conflict);
        }
        Ok((expected_revision - 1, previous_hash))
    }

    /// Computes the v5 projection migration source fingerprint without
    /// decrypting the legacy full review blob. Projection, migration-ledger,
    /// generation-status and row-version fields are deliberately excluded so
    /// crash recovery remains idempotent. The v5-optional Vault reference
    /// table is normalized by content, so its absence and the canonical empty
    /// v6 table have the same fingerprint while every stored reference remains
    /// source-bound. Callers must still enforce the exact v5/v6 schema gate.
    pub fn approved_projection_migration_source_fingerprint(
        connection: &Connection,
    ) -> Result<String, PrivacyStoreError> {
        let mut digest = Sha256::new();
        digest.update(b"LawyerAssistance/approved-case-projection-source/v1\0");
        append_table_presence(&mut digest, connection, "project_privacy_case_bindings")?;

        let mut statement = connection
            .prepare(
                "SELECT
                    material.material_id,material.project_id,material.legacy_case_id,
                    material.source_sha256,material.media_type,material.page_count,
                    material.source_kind,material.extraction_status,material.migration_status,
                    material.state,material.deleted_at,
                    generation.redaction_id,generation.generation_number,
                    generation.extraction_sha256,generation.redacted_content_sha256,
                    generation.approved_payload_sha256,generation.policy_id,
                    generation.policy_version,generation.detector_version,
                    generation.unresolved_high_risk_count,generation.review_state,
                    generation.risk_revision,generation.protected_review_blob,
                    generation.protection_scheme,generation.reviewed_by_sha256,
                    generation.approved_at,generation.revocation_state,generation.revoked_at,
                    generation.created_at,generation.reviewed_at
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 ORDER BY material.material_id ASC,generation.generation_number ASC,
                          generation.redaction_id ASC",
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let mut rows = statement
            .query([])
            .map_err(|_| PrivacyStoreError::Database)?;
        while let Some(row) = rows.next().map_err(|_| PrivacyStoreError::Database)? {
            append_len_prefixed(&mut digest, b"generation");
            for index in 0..22 {
                let value = row
                    .get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?;
                append_sql_value(&mut digest, value)?;
            }
            let protected = row
                .get::<_, Vec<u8>>(22)
                .map_err(|_| PrivacyStoreError::Database)?;
            append_len_prefixed(&mut digest, sha256_hex(&protected).as_bytes());
            for index in 23..30 {
                let value = row
                    .get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?;
                append_sql_value(&mut digest, value)?;
            }
        }
        append_risk_source(&mut digest, connection, None)?;
        append_binding_source(&mut digest, connection)?;
        append_vault_source(&mut digest, connection)?;
        Ok(format!("{:x}", digest.finalize()))
    }

    pub fn approved_projection_migration_row_fingerprint(
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<String, PrivacyStoreError> {
        validate_identifier(redaction_id)?;
        let mut digest = Sha256::new();
        digest.update(b"LawyerAssistance/approved-case-projection-row/v1\0");
        let found = connection
            .query_row(
                "SELECT
                    material.material_id,material.project_id,material.source_sha256,
                    material.media_type,material.page_count,material.source_kind,
                    material.extraction_status,material.migration_status,material.state,
                    material.deleted_at,generation.redaction_id,generation.generation_number,
                    generation.extraction_sha256,generation.redacted_content_sha256,
                    generation.approved_payload_sha256,generation.policy_id,
                    generation.policy_version,generation.detector_version,
                    generation.unresolved_high_risk_count,generation.review_state,
                    generation.risk_revision,generation.protected_review_blob,
                    generation.protection_scheme,generation.reviewed_by_sha256,
                    generation.approved_at,generation.revocation_state,generation.revoked_at,
                    generation.created_at,generation.reviewed_at
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.redaction_id=?1",
                [redaction_id],
                |row| {
                    for index in 0..21 {
                        append_sql_value(
                            &mut digest,
                            row.get_ref(index)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        )
                        .map_err(|_| rusqlite::Error::InvalidQuery)?;
                    }
                    let protected = row.get::<_, Vec<u8>>(21)?;
                    append_len_prefixed(&mut digest, sha256_hex(&protected).as_bytes());
                    for index in 22..29 {
                        append_sql_value(
                            &mut digest,
                            row.get_ref(index)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        )
                        .map_err(|_| rusqlite::Error::InvalidQuery)?;
                    }
                    Ok(())
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        if found.is_none() {
            return Err(PrivacyStoreError::Conflict);
        }
        append_risk_source(&mut digest, connection, Some(redaction_id))?;
        Ok(format!("{:x}", digest.finalize()))
    }

    /// Writes one migration projection and its append-only ledger result in one
    /// immediate transaction. The caller must already have established and
    /// revalidated the five-component backup gate.
    pub fn backfill_approved_projection_after_backup(
        connection: &mut Connection,
        input: &ApprovedProjectionBackfill<'_>,
    ) -> Result<(), PrivacyStoreError> {
        validate_identifier(input.redaction_id)?;
        if !valid_lower_hash(input.source_fingerprint)
            || !valid_lower_hash(input.approved_risk_revision_hash)
            || input.approved_payload_plaintext.is_empty()
            || input.approved_payload_plaintext.len() > MAX_APPROVED_CASE_PAYLOAD_BYTES
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let payload = decode_canonical_payload(input.approved_payload_plaintext)?;
        let protected = protect_local(input.approved_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        let row = load_projection_migration_index(&transaction, input.redaction_id)?;
        validate_payload_against_migration_index(&payload, input.approved_payload_plaintext, &row)?;
        let (risk_revision, risk_head) =
            Self::verify_complete_risk_review_chain(&transaction, input.redaction_id)?;
        if risk_revision != row.risk_revision
            || risk_head != input.approved_risk_revision_hash
            || risk_head != row.expected_risk_head
        {
            return Err(PrivacyStoreError::Conflict);
        }
        if let Some(existing) = load_projection_migration_ledger(&transaction, input.redaction_id)?
        {
            if existing
                != (
                    input.source_fingerprint.to_owned(),
                    "migrated".to_owned(),
                    None,
                )
            {
                return Err(PrivacyStoreError::Conflict);
            }
            let (_, existing_payload, canonical) =
                load_verified_projection_core(&transaction, &row.project_id, input.redaction_id)?;
            if existing_payload != payload || canonical != input.approved_payload_plaintext {
                return Err(PrivacyStoreError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)?;
            return Ok(());
        }
        let changed = transaction
            .execute(
                "UPDATE privacy_redactions
                 SET approved_payload_schema_version=?2,
                     protected_approved_payload_blob=?3,
                     approved_payload_protection_scheme=?4,
                     approved_risk_revision_hash=?5,
                     row_version=row_version+1
                 WHERE redaction_id=?1
                   AND generation_status='ready'
                   AND review_state='approved'
                   AND revocation_state='active'
                   AND revoked_at IS NULL
                   AND unresolved_high_risk_count=0
                   AND risk_revision=?6
                   AND approved_payload_sha256=?7
                   AND approved_payload_schema_version IS NULL
                   AND protected_approved_payload_blob IS NULL
                   AND approved_payload_protection_scheme IS NULL
                   AND approved_risk_revision_hash IS NULL",
                params![
                    input.redaction_id,
                    APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                    input.approved_risk_revision_hash,
                    sql_u64(risk_revision)?,
                    row.approved_payload_sha256,
                ],
            )
            .map_err(map_constraint)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        append_projection_migration_ledger(
            &transaction,
            input.redaction_id,
            &row.material_id,
            row.generation_number,
            input.source_fingerprint,
            "migrated",
            None,
        )?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    /// Preserves a corrupt historical source, blocks it from case work, and
    /// append-records a stable migration failure.
    pub fn block_approved_projection_after_backup(
        connection: &mut Connection,
        redaction_id: &str,
        source_fingerprint: &str,
        error_code: &str,
    ) -> Result<(), PrivacyStoreError> {
        validate_identifier(redaction_id)?;
        validate_identifier(error_code)?;
        if !valid_lower_hash(source_fingerprint) {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        if let Some(existing) = load_projection_migration_ledger(&transaction, redaction_id)? {
            if existing
                != (
                    source_fingerprint.to_owned(),
                    "blocked".to_owned(),
                    Some(error_code.to_owned()),
                )
                || !projection_migration_block_target_is_terminal(&transaction, redaction_id)?
            {
                return Err(PrivacyStoreError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)?;
            return Ok(());
        }
        let (material_id, generation_number) =
            load_projection_migration_block_target(&transaction, redaction_id)?;
        transaction
            .execute(
                "UPDATE case_material_selections
                 SET invalidated_at=CURRENT_TIMESTAMP,
                     invalidation_reason='approved_projection_migration_blocked',
                     row_version=row_version+1
                 WHERE redaction_id=?1
                   AND deselected_at IS NULL AND invalidated_at IS NULL",
                [redaction_id],
            )
            .map_err(map_constraint)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_redactions
                 SET generation_status='blocked',row_version=row_version+1
                 WHERE redaction_id=?1 AND generation_status='ready'",
                [redaction_id],
            )
            .map_err(map_constraint)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        append_projection_migration_ledger(
            &transaction,
            redaction_id,
            &material_id,
            generation_number,
            source_fingerprint,
            "blocked",
            Some(error_code),
        )?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    /// Explicitly invalidates active case-work selections for a revoked
    /// generation without deleting selection history.
    pub fn invalidate_case_work_selections_for_generation(
        connection: &Connection,
        redaction_id: &str,
        reason_code: &str,
    ) -> Result<u64, PrivacyStoreError> {
        validate_identifier(redaction_id)?;
        validate_identifier(reason_code)?;
        let changed = connection
            .execute(
                "UPDATE case_material_selections
                 SET invalidated_at=CURRENT_TIMESTAMP,invalidation_reason=?2,
                     row_version=row_version+1
                 WHERE redaction_id=?1 AND purpose=?3
                   AND deselected_at IS NULL AND invalidated_at IS NULL",
                params![redaction_id, reason_code, INTERACTIVE_CASE_WORK_PURPOSE],
            )
            .map_err(map_constraint)?;
        u64::try_from(changed).map_err(|_| PrivacyStoreError::Database)
    }
}

fn load_projection_migration_block_target(
    connection: &Connection,
    redaction_id: &str,
) -> Result<(String, u64), PrivacyStoreError> {
    connection
        .query_row(
            "SELECT material_id,generation_number
             FROM privacy_redactions
             WHERE redaction_id=?1
               AND generation_status='ready'
               AND review_state='approved'
               AND revocation_state='active'
               AND revoked_at IS NULL",
            [redaction_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?
        .ok_or(PrivacyStoreError::Conflict)
        .and_then(|(material_id, generation_number)| {
            Ok((
                material_id,
                u64::try_from(generation_number).map_err(|_| PrivacyStoreError::Database)?,
            ))
        })
}

fn projection_migration_block_target_is_terminal(
    connection: &Connection,
    redaction_id: &str,
) -> Result<bool, PrivacyStoreError> {
    connection
        .query_row(
            "SELECT
                generation.generation_status='blocked'
                AND generation.review_state='approved'
                AND generation.revocation_state='active'
                AND generation.revoked_at IS NULL
                AND generation.approved_payload_schema_version IS NULL
                AND generation.protected_approved_payload_blob IS NULL
                AND generation.approved_payload_protection_scheme IS NULL
                AND generation.approved_risk_revision_hash IS NULL
                AND ledger.target_material_id=generation.material_id
                AND ledger.target_redaction_id=generation.redaction_id
                AND ledger.assigned_generation_number=generation.generation_number
             FROM case_material_migration_ledger AS ledger
             JOIN privacy_redactions AS generation
               ON generation.redaction_id=ledger.source_key
             WHERE ledger.migration_id=?1
               AND ledger.source_store='privacy-workflow.sqlite'
               AND ledger.source_table='privacy_redactions'
               AND ledger.source_key=?2",
            params![APPROVED_CASE_PROJECTION_MIGRATION_ID, redaction_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)
        .map(|matches| matches == Some(true))
}

#[derive(Debug)]
struct ProjectionMigrationIndex {
    material_id: String,
    project_id: ProjectId,
    generation_number: u64,
    source_sha256: String,
    extraction_sha256: String,
    redacted_content_sha256: String,
    approved_payload_sha256: String,
    media_type: String,
    page_count: u32,
    risk_revision: u64,
    expected_risk_head: String,
}

fn load_projection_migration_index(
    connection: &Connection,
    redaction_id: &str,
) -> Result<ProjectionMigrationIndex, PrivacyStoreError> {
    connection
        .query_row(
            "SELECT generation.material_id,material.project_id,
                    generation.generation_number,material.source_sha256,
                    generation.extraction_sha256,generation.redacted_content_sha256,
                    generation.approved_payload_sha256,material.media_type,
                    material.page_count,generation.risk_revision,
                    (
                      SELECT revision_hash
                      FROM privacy_risk_review_revisions
                      WHERE redaction_id=generation.redaction_id
                      ORDER BY revision DESC LIMIT 1
                    )
             FROM privacy_redactions AS generation
             JOIN privacy_materials AS material
               ON material.material_id=generation.material_id
             WHERE generation.redaction_id=?1
               AND generation.generation_status='ready'
               AND generation.review_state='approved'
               AND generation.revocation_state='active'
               AND generation.revoked_at IS NULL",
            [redaction_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?
        .ok_or(PrivacyStoreError::Conflict)
        .and_then(|row| {
            Ok(ProjectionMigrationIndex {
                material_id: row.0,
                project_id: ProjectId::parse(row.1).map_err(|_| PrivacyStoreError::Conflict)?,
                generation_number: u64::try_from(row.2).map_err(|_| PrivacyStoreError::Database)?,
                source_sha256: row.3,
                extraction_sha256: row.4,
                redacted_content_sha256: row.5,
                approved_payload_sha256: row.6,
                media_type: row.7,
                page_count: u32::try_from(row.8).map_err(|_| PrivacyStoreError::Database)?,
                risk_revision: u64::try_from(row.9).map_err(|_| PrivacyStoreError::Database)?,
                expected_risk_head: row.10,
            })
        })
}

fn validate_payload_against_migration_index(
    payload: &ApprovedCasePayloadV1,
    canonical: &[u8],
    row: &ProjectionMigrationIndex,
) -> Result<(), PrivacyStoreError> {
    if payload.source_sha256 != row.source_sha256
        || payload.extraction_sha256 != row.extraction_sha256
        || payload.media_type != row.media_type
        || payload.pages.len() != row.page_count as usize
        || sha256_hex(canonical) != row.approved_payload_sha256
        || redacted_content_sha256(&payload.pages)? != row.redacted_content_sha256
    {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(())
}

fn load_verified_projection_core(
    connection: &Connection,
    project_id: &ProjectId,
    redaction_id: &str,
) -> Result<(ProjectionRow, ApprovedCasePayloadV1, Vec<u8>), PrivacyStoreError> {
    validate_identifier(redaction_id)?;
    require_project_binding(connection, project_id)?;
    let row = connection
        .query_row(
            APPROVED_PROJECTION_SELECT_SQL,
            params![redaction_id, project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                ))
            },
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?
        .ok_or(PrivacyStoreError::NotApproved)?;
    let row = ProjectionRow {
        redaction_id: row.0,
        material_id: row.1,
        generation_number: u64::try_from(row.2).map_err(|_| PrivacyStoreError::Database)?,
        extraction_sha256: row.3,
        redacted_content_sha256: row.4,
        approved_payload_sha256: row.5,
        policy_id: row.6,
        policy_version: u32::try_from(row.7).map_err(|_| PrivacyStoreError::Database)?,
        detector_version: row.8,
        risk_revision: u64::try_from(row.9).map_err(|_| PrivacyStoreError::Database)?,
        approved_risk_revision_hash: row.10,
        row_version: u64::try_from(row.11).map_err(|_| PrivacyStoreError::Database)?,
        approved_payload_schema_version: u16::try_from(row.12)
            .map_err(|_| PrivacyStoreError::Database)?,
        protected_approved_payload_blob: row.13,
        approved_payload_protection_scheme: row.14,
        source_sha256: row.15,
        media_type: row.16,
        page_count: u32::try_from(row.17).map_err(|_| PrivacyStoreError::Database)?,
        binding_version: u64::try_from(row.18).map_err(|_| PrivacyStoreError::Database)?,
    };
    if row.approved_payload_schema_version != APPROVED_CASE_PAYLOAD_SCHEMA_VERSION
        || row.approved_payload_protection_scheme != LOCAL_PROTECTION_SCHEME
        || !valid_lower_hash(&row.source_sha256)
        || !valid_lower_hash(&row.extraction_sha256)
        || !valid_lower_hash(&row.redacted_content_sha256)
        || !valid_lower_hash(&row.approved_payload_sha256)
        || !valid_lower_hash(&row.approved_risk_revision_hash)
        || row.policy_version == 0
        || row.binding_version == 0
    {
        return Err(PrivacyStoreError::Conflict);
    }
    let plaintext = unprotect_local(&row.protected_approved_payload_blob)
        .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
    let payload = decode_canonical_payload(&plaintext)?;
    if payload.schema_version != row.approved_payload_schema_version
        || payload.source_sha256 != row.source_sha256
        || payload.extraction_sha256 != row.extraction_sha256
        || payload.media_type != row.media_type
        || payload.pages.len() != row.page_count as usize
        || sha256_hex(&plaintext) != row.approved_payload_sha256
        || redacted_content_sha256(&payload.pages)? != row.redacted_content_sha256
    {
        return Err(PrivacyStoreError::Conflict);
    }
    let (risk_revision, risk_head) =
        PrivacyStore::verify_complete_risk_review_chain(connection, redaction_id)?;
    if risk_revision != row.risk_revision || risk_head != row.approved_risk_revision_hash {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok((row, payload, plaintext))
}

fn projection_from_parts(
    project_id: &ProjectId,
    row: ProjectionRow,
    payload: ApprovedCasePayloadV1,
    canonical_payload: Vec<u8>,
    selection_id: String,
    selection_row_version: u64,
) -> ApprovedCaseProjection {
    ApprovedCaseProjection {
        snapshot: ApprovedCaseSourceSnapshot {
            project_id: project_id.as_str().to_owned(),
            redaction_id: row.redaction_id,
            material_id: row.material_id,
            generation_number: row.generation_number,
            source_sha256: row.source_sha256,
            extraction_sha256: row.extraction_sha256,
            redacted_content_sha256: row.redacted_content_sha256,
            approved_payload_sha256: row.approved_payload_sha256,
            policy_id: row.policy_id,
            policy_version: row.policy_version,
            detector_version: row.detector_version,
            risk_revision: row.risk_revision,
            approved_risk_revision_hash: row.approved_risk_revision_hash,
            generation_row_version: row.row_version,
            binding_version: row.binding_version,
            selection_id,
            selection_row_version,
        },
        media_type: payload.media_type,
        pages: payload.pages,
        canonical_payload,
    }
}

fn validate_requested_generation_ids(redaction_ids: &[String]) -> Result<(), PrivacyStoreError> {
    if redaction_ids.is_empty() || redaction_ids.len() > 256 {
        return Err(PrivacyStoreError::InvalidInput);
    }
    let mut unique = BTreeSet::new();
    for redaction_id in redaction_ids {
        validate_identifier(redaction_id)?;
        if !unique.insert(redaction_id) {
            return Err(PrivacyStoreError::InvalidInput);
        }
    }
    Ok(())
}

fn load_verified_display_name(
    protected: Option<Vec<u8>>,
    expected_sha256: Option<String>,
    scheme: Option<String>,
) -> Result<Option<String>, PrivacyStoreError> {
    match (protected, expected_sha256, scheme) {
        (None, None, None) => Ok(None),
        (Some(protected), Some(expected_sha256), Some(scheme))
            if scheme == LOCAL_PROTECTION_SCHEME && valid_lower_hash(&expected_sha256) =>
        {
            let plaintext =
                unprotect_local(&protected).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
            if sha256_hex(&plaintext) != expected_sha256 {
                return Err(PrivacyStoreError::Conflict);
            }
            let display_name =
                String::from_utf8(plaintext).map_err(|_| PrivacyStoreError::Conflict)?;
            if display_name.is_empty()
                || display_name.len() > 4_096
                || display_name.chars().any(char::is_control)
            {
                return Err(PrivacyStoreError::Conflict);
            }
            Ok(Some(display_name))
        }
        _ => Err(PrivacyStoreError::Conflict),
    }
}

fn require_project_binding(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<(), PrivacyStoreError> {
    ProjectPrivacyCaseBindingStore::resolve(connection, project_id)
        .map_err(|_| PrivacyStoreError::Conflict)?
        .ok_or(PrivacyStoreError::Conflict)
        .map(|_| ())
}

fn decode_canonical_payload(bytes: &[u8]) -> Result<ApprovedCasePayloadV1, PrivacyStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_APPROVED_CASE_PAYLOAD_BYTES {
        return Err(PrivacyStoreError::InvalidInput);
    }
    let payload: ApprovedCasePayloadV1 =
        serde_json::from_slice(bytes).map_err(|_| PrivacyStoreError::Conflict)?;
    validate_payload_shape(&payload)?;
    let canonical = serde_json::to_vec(&payload).map_err(|_| PrivacyStoreError::Conflict)?;
    if canonical != bytes {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(payload)
}

fn validate_payload_shape(payload: &ApprovedCasePayloadV1) -> Result<(), PrivacyStoreError> {
    if payload.schema_version != APPROVED_CASE_PAYLOAD_SCHEMA_VERSION
        || !valid_lower_hash(&payload.source_sha256)
        || !valid_lower_hash(&payload.extraction_sha256)
        || payload.media_type.is_empty()
        || payload.media_type.len() > 128
        || payload.pages.is_empty()
        || payload.pages.len() > 10_000
    {
        return Err(PrivacyStoreError::InvalidInput);
    }
    let mut previous = 0_u32;
    let mut total_bytes = 0_usize;
    for page in &payload.pages {
        if page.page_number == 0 || page.page_number <= previous {
            return Err(PrivacyStoreError::InvalidInput);
        }
        previous = page.page_number;
        total_bytes = total_bytes
            .checked_add(page.text.len())
            .ok_or(PrivacyStoreError::InvalidInput)?;
        if total_bytes > MAX_APPROVED_CASE_PAYLOAD_BYTES {
            return Err(PrivacyStoreError::InvalidInput);
        }
    }
    Ok(())
}

fn redacted_content_sha256(pages: &[ApprovedCasePageV1]) -> Result<String, PrivacyStoreError> {
    let canonical = serde_json::to_vec(&CanonicalRedactedContent {
        schema_version: APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
        pages,
    })
    .map_err(|_| PrivacyStoreError::Conflict)?;
    Ok(sha256_hex(&canonical))
}

struct RiskRevisionHashInput<'a> {
    redaction_id: &'a str,
    revision: u64,
    state_sha256: &'a str,
    risk_sha256: &'a str,
    hard_gate_sha256: &'a str,
    action_code: &'a str,
    reason_codes_json: &'a str,
    protected_sha256: &'a str,
    previous_revision_hash: &'a str,
}

fn risk_revision_hash(input: &RiskRevisionHashInput<'_>) -> String {
    let RiskRevisionHashInput {
        redaction_id,
        revision,
        state_sha256,
        risk_sha256,
        hard_gate_sha256,
        action_code,
        reason_codes_json,
        protected_sha256,
        previous_revision_hash,
    } = input;
    sha256_hex(
        format!(
            "privacy-risk-review-revision-v1\0{redaction_id}\0{revision}\0{state_sha256}\0\
             {risk_sha256}\0{hard_gate_sha256}\0{action_code}\0{reason_codes_json}\0\
             {protected_sha256}\0{previous_revision_hash}"
        )
        .as_bytes(),
    )
}

fn append_projection_migration_ledger(
    connection: &Connection,
    redaction_id: &str,
    material_id: &str,
    generation_number: u64,
    source_fingerprint: &str,
    result_state: &str,
    error_code: Option<&str>,
) -> Result<(), PrivacyStoreError> {
    let event_id = format!(
        "evt_{}",
        sha256_hex(
            format!(
                "{APPROVED_CASE_PROJECTION_MIGRATION_ID}\0{redaction_id}\0\
                 {source_fingerprint}\0{result_state}\0{}",
                error_code.unwrap_or("")
            )
            .as_bytes()
        )
    );
    connection
        .execute(
            "INSERT INTO case_material_migration_ledger(
                migration_id,source_store,source_table,source_key,source_fingerprint,
                target_material_id,target_redaction_id,assigned_generation_number,
                result_state,error_code,started_at,completed_at
             ) VALUES(?1,'privacy-workflow.sqlite','privacy_redactions',?2,?3,
                      ?4,?2,?5,?6,?7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            params![
                APPROVED_CASE_PROJECTION_MIGRATION_ID,
                redaction_id,
                source_fingerprint,
                material_id,
                sql_u64(generation_number)?,
                result_state,
                error_code,
            ],
        )
        .map_err(map_constraint)?;
    connection
        .execute(
            "INSERT INTO case_material_migration_events(
                migration_event_id,migration_id,source_store,source_table,source_key,
                event_type,source_fingerprint,target_material_id,target_redaction_id,
                assigned_generation_number,result_state,error_code,occurred_at
             ) VALUES(?1,?2,'privacy-workflow.sqlite','privacy_redactions',?3,
                      'approved_projection_backfill',?4,?5,?3,?6,?7,?8,CURRENT_TIMESTAMP)",
            params![
                event_id,
                APPROVED_CASE_PROJECTION_MIGRATION_ID,
                redaction_id,
                source_fingerprint,
                material_id,
                sql_u64(generation_number)?,
                result_state,
                error_code,
            ],
        )
        .map_err(map_constraint)?;
    Ok(())
}

fn load_projection_migration_ledger(
    connection: &Connection,
    redaction_id: &str,
) -> Result<Option<(String, String, Option<String>)>, PrivacyStoreError> {
    connection
        .query_row(
            "SELECT source_fingerprint,result_state,error_code
             FROM case_material_migration_ledger
             WHERE migration_id=?1
               AND source_store='privacy-workflow.sqlite'
               AND source_table='privacy_redactions'
               AND source_key=?2",
            params![APPROVED_CASE_PROJECTION_MIGRATION_ID, redaction_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)
}

fn append_risk_source(
    digest: &mut Sha256,
    connection: &Connection,
    redaction_id: Option<&str>,
) -> Result<(), PrivacyStoreError> {
    let sql = if redaction_id.is_some() {
        "SELECT redaction_id,revision,state_sha256,risk_sha256,hard_gate_sha256,
                action_code,reason_codes_json,protected_state_blob,protection_scheme,
                previous_revision_hash,revision_hash,created_at
         FROM privacy_risk_review_revisions
         WHERE redaction_id=?1
         ORDER BY redaction_id ASC,revision ASC"
    } else {
        "SELECT redaction_id,revision,state_sha256,risk_sha256,hard_gate_sha256,
                action_code,reason_codes_json,protected_state_blob,protection_scheme,
                previous_revision_hash,revision_hash,created_at
         FROM privacy_risk_review_revisions
         ORDER BY redaction_id ASC,revision ASC"
    };
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| PrivacyStoreError::Database)?;
    let mut rows = match redaction_id {
        Some(value) => statement
            .query([value])
            .map_err(|_| PrivacyStoreError::Database)?,
        None => statement
            .query([])
            .map_err(|_| PrivacyStoreError::Database)?,
    };
    while let Some(row) = rows.next().map_err(|_| PrivacyStoreError::Database)? {
        append_len_prefixed(digest, b"risk");
        for index in 0..7 {
            append_sql_value(
                digest,
                row.get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?,
            )?;
        }
        let protected = row
            .get::<_, Vec<u8>>(7)
            .map_err(|_| PrivacyStoreError::Database)?;
        append_len_prefixed(digest, sha256_hex(&protected).as_bytes());
        for index in 8..12 {
            append_sql_value(
                digest,
                row.get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?,
            )?;
        }
    }
    Ok(())
}

fn append_binding_source(
    digest: &mut Sha256,
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    if !table_exists(connection, "project_privacy_case_bindings")? {
        return Ok(());
    }
    let mut statement = connection
        .prepare(
            "SELECT project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id,created_at,updated_at
             FROM project_privacy_case_bindings
             ORDER BY project_id ASC",
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyStoreError::Database)?;
    while let Some(row) = rows.next().map_err(|_| PrivacyStoreError::Database)? {
        append_len_prefixed(digest, b"binding");
        append_sql_value(
            digest,
            row.get_ref(0).map_err(|_| PrivacyStoreError::Database)?,
        )?;
        let privacy_case_id = row
            .get::<_, String>(1)
            .map_err(|_| PrivacyStoreError::Database)?;
        append_len_prefixed(digest, sha256_hex(privacy_case_id.as_bytes()).as_bytes());
        for index in 2..8 {
            append_sql_value(
                digest,
                row.get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?,
            )?;
        }
    }
    Ok(())
}

fn append_vault_source(
    digest: &mut Sha256,
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    // Canonical v5 permits this table to be absent, while v6 requires the
    // canonical table even when it has no rows. Bind the content domain in
    // both cases instead of treating authorized empty-table installation as a
    // source mutation. A present table must still expose the exact columns
    // below, and every real row is included in the digest.
    append_len_prefixed(digest, b"privacy_vault_material_refs/canonical-rows/v1");
    if !table_exists(connection, "privacy_vault_material_refs")? {
        return Ok(());
    }
    let mut statement = connection
        .prepare(
            "SELECT material_id,case_id,object_id,object_version,source_sha256,
                    envelope_sha256,content_bytes,retention_expires_at_unix,
                    retention_policy_revision,bound_at_unix,import_state,failure_code,
                    created_at,updated_at
             FROM privacy_vault_material_refs
             ORDER BY material_id ASC",
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyStoreError::Database)?;
    while let Some(row) = rows.next().map_err(|_| PrivacyStoreError::Database)? {
        append_len_prefixed(digest, b"vault");
        for index in 0..14 {
            append_sql_value(
                digest,
                row.get_ref(index)
                    .map_err(|_| PrivacyStoreError::Database)?,
            )?;
        }
    }
    Ok(())
}

fn append_table_presence(
    digest: &mut Sha256,
    connection: &Connection,
    table: &str,
) -> Result<(), PrivacyStoreError> {
    append_len_prefixed(digest, table.as_bytes());
    append_len_prefixed(
        digest,
        if table_exists(connection, table)? {
            b"present"
        } else {
            b"absent"
        },
    );
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, PrivacyStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1
             )",
            [table],
            |row| row.get(0),
        )
        .map_err(|_| PrivacyStoreError::Database)
}

fn append_sql_value(
    digest: &mut Sha256,
    value: rusqlite::types::ValueRef<'_>,
) -> Result<(), PrivacyStoreError> {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => append_len_prefixed(digest, b"<null>"),
        ValueRef::Integer(value) => append_len_prefixed(digest, value.to_string().as_bytes()),
        ValueRef::Real(_) => return Err(PrivacyStoreError::Conflict),
        ValueRef::Text(value) => append_len_prefixed(digest, value),
        ValueRef::Blob(value) => append_len_prefixed(digest, sha256_hex(value).as_bytes()),
    }
    Ok(())
}

fn append_len_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn map_constraint(error: rusqlite::Error) -> PrivacyStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        PrivacyStoreError::Conflict
    } else {
        PrivacyStoreError::Database
    }
}

fn sql_u64(value: u64) -> Result<i64, PrivacyStoreError> {
    i64::try_from(value).map_err(|_| PrivacyStoreError::InvalidInput)
}

fn validate_identifier(value: &str) -> Result<(), PrivacyStoreError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(PrivacyStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::{
        BindingCreationSource, BindingLifecycleContext, RegisterPrivacyMaterial, SaveReviewDraft,
        SaveRiskReviewRevision,
    };

    #[cfg(windows)]
    struct ApprovedProjectionFixture {
        connection: Connection,
        project_id: ProjectId,
        privacy_case_id: String,
        redaction_id: String,
        pages: Vec<ApprovedCasePageV1>,
        legacy_secret: String,
    }

    #[cfg(windows)]
    fn approved_projection_fixture() -> ApprovedProjectionFixture {
        let mut connection = Connection::open_in_memory().expect("database");
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON;")
            .expect("privacy pragmas");
        PrivacyStore::initialize(&connection).expect("privacy schema");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection).expect("binding schema");

        let project_id = ProjectId::parse("case-approved-projection-test").expect("project id");
        let lifecycle = BindingLifecycleContext::new(
            BindingCreationSource::LifecycleInitialization,
            "audit-approved-projection-test",
            None,
        )
        .expect("lifecycle");
        let privacy_case_id = ProjectPrivacyCaseBindingStore::resolve_or_create(
            &mut connection,
            &project_id,
            &lifecycle,
        )
        .expect("binding")
        .to_string();

        let material_id = "material-approved-projection-test";
        let redaction_id = "redaction-approved-projection-test";
        let source_sha256 = sha256_hex(b"approved projection source");
        let extraction_sha256 = sha256_hex(b"approved projection extraction");
        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id,
                project_id: Some(project_id.as_str()),
                attachment_id: None,
                source_sha256: &source_sha256,
                source_name_sha256: &sha256_hex(b"approved projection source name"),
                media_type: "text/plain",
                page_count: Some(1),
            },
        )
        .expect("material");
        PrivacyStore::set_material_display_name(&connection, material_id, None, "已批准材料.txt")
            .expect("display name");

        let pages = vec![ApprovedCasePageV1 {
            page_number: 1,
            text: "[PERSON_001] 与 [ORG_001] 的已脱敏事实。".to_owned(),
        }];
        let approved_redacted_content_sha256 =
            redacted_content_sha256(&pages).expect("redacted content hash");
        let legacy_secret = "LEGACY_FULL_REVIEW_MUST_NEVER_BE_READ".to_owned();
        let legacy_review =
            format!("{{\"original\":\"{legacy_secret}\",\"redacted\":\"[PERSON_001]\"}}");
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id,
                material_id,
                extraction_sha256: &extraction_sha256,
                redacted_content_sha256: &approved_redacted_content_sha256,
                policy_id: "cn-legal-approved-projection-v1",
                policy_version: 1,
                detector_version: "detector-v1",
                unresolved_high_risk_count: 0,
                review_payload_plaintext: legacy_review.as_bytes(),
            },
        )
        .expect("review draft");
        PrivacyStore::append_risk_review_revision(
            &connection,
            &SaveRiskReviewRevision {
                redaction_id,
                expected_previous_revision: 0,
                risk_sha256: &sha256_hex(b"initial risk"),
                hard_gate_sha256: &sha256_hex(b"initial hard gates"),
                action_code: "review_initialized",
                reason_codes: &[],
                state_plaintext: b"{\"revision\":1}",
            },
        )
        .expect("initial risk revision");

        let approved_payload = ApprovedCasePayloadV1 {
            schema_version: APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
            source_sha256,
            extraction_sha256,
            media_type: "text/plain".to_owned(),
            pages: pages.clone(),
        }
        .canonical_bytes()
        .expect("canonical approved payload");
        PrivacyStore::approve_review_with_risk_revision(
            &mut connection,
            &crate::ApproveReviewWithRiskRevision {
                redaction_id,
                expected_redacted_sha256: &approved_redacted_content_sha256,
                approved_redacted_content_sha256: &approved_redacted_content_sha256,
                approved_payload_sha256: &sha256_hex(&approved_payload),
                reviewed_by_sha256: &sha256_hex(b"approved projection reviewer"),
                approved_review_payload_plaintext: legacy_review.as_bytes(),
                approved_payload_plaintext: &approved_payload,
                risk_revision: SaveRiskReviewRevision {
                    redaction_id,
                    expected_previous_revision: 1,
                    risk_sha256: &sha256_hex(b"approved risk"),
                    hard_gate_sha256: &sha256_hex(b"approved hard gates"),
                    action_code: "bind_publication_context",
                    reason_codes: &[],
                    state_plaintext: b"{\"revision\":2,\"approved\":true}",
                },
            },
        )
        .expect("approval");

        ApprovedProjectionFixture {
            connection,
            project_id,
            privacy_case_id,
            redaction_id: redaction_id.to_owned(),
            pages,
            legacy_secret,
        }
    }

    #[test]
    fn approved_payload_rejects_unknown_fields_and_noncanonical_encoding() {
        let source = "a".repeat(64);
        let extraction = "b".repeat(64);
        let canonical = format!(
            "{{\"schemaVersion\":1,\"sourceSha256\":\"{source}\",\
             \"extractionSha256\":\"{extraction}\",\"mediaType\":\"text/plain\",\
             \"pages\":[{{\"pageNumber\":1,\"text\":\"[PERSON_001]\"}}]}}"
        );
        assert!(decode_canonical_payload(canonical.as_bytes()).is_ok());
        let unknown = canonical.replacen("\"pages\"", "\"unexpected\":true,\"pages\"", 1);
        assert_eq!(
            decode_canonical_payload(unknown.as_bytes()),
            Err(PrivacyStoreError::Conflict)
        );
        let whitespace = format!(" {canonical}");
        assert_eq!(
            decode_canonical_payload(whitespace.as_bytes()),
            Err(PrivacyStoreError::Conflict)
        );
    }

    #[test]
    fn projection_source_normalizes_only_absent_and_canonical_empty_vault_refs() {
        let mut connection = Connection::open_in_memory().expect("database");
        PrivacyStore::initialize(&connection).expect("privacy schema");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection).expect("binding schema");

        let absent = PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
            .expect("absent optional v5 Vault table fingerprint");
        crate::initialize_privacy_vault_link_schema(&connection)
            .expect("canonical empty v6 Vault table");
        let canonical_empty =
            PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
                .expect("canonical empty Vault table fingerprint");
        assert_eq!(absent, canonical_empty);

        PrivacyStore::register_material(
            &connection,
            &crate::RegisterPrivacyMaterial {
                material_id: "material-vault-fingerprint",
                project_id: None,
                attachment_id: None,
                source_sha256: &sha256_hex(b"vault fingerprint source"),
                source_name_sha256: &sha256_hex(b"vault fingerprint source name"),
                media_type: "application/pdf",
                page_count: Some(1),
            },
        )
        .expect("source material");
        connection
            .execute(
                "INSERT INTO privacy_vault_material_refs(
                    material_id,case_id,object_id,object_version,source_sha256,
                    envelope_sha256,content_bytes,retention_expires_at_unix,
                    retention_policy_revision,bound_at_unix,import_state
                 ) VALUES(?1,?2,?3,1,?4,?5,1,2,1,1,'review_ready')",
                params![
                    "material-vault-fingerprint",
                    "case_vault_fingerprint",
                    "object-vault-fingerprint",
                    sha256_hex(b"vault fingerprint source"),
                    sha256_hex(b"vault fingerprint envelope"),
                ],
            )
            .expect("valid Vault reference");
        let one_row = PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
            .expect("one-row Vault fingerprint");
        assert_ne!(canonical_empty, one_row);

        connection
            .execute_batch(
                "DROP TABLE privacy_vault_material_refs;
                 CREATE TABLE privacy_vault_material_refs(material_id TEXT PRIMARY KEY);",
            )
            .expect("drifted Vault schema");
        assert_eq!(
            PrivacyStore::approved_projection_migration_source_fingerprint(&connection),
            Err(PrivacyStoreError::Database)
        );
    }

    #[test]
    fn projection_debug_never_renders_approved_text() {
        let projection = ApprovedCaseProjection {
            snapshot: ApprovedCaseSourceSnapshot {
                project_id: "case-test".to_owned(),
                redaction_id: "redaction-test".to_owned(),
                material_id: "material-test".to_owned(),
                generation_number: 1,
                source_sha256: "a".repeat(64),
                extraction_sha256: "b".repeat(64),
                redacted_content_sha256: "c".repeat(64),
                approved_payload_sha256: "d".repeat(64),
                policy_id: "policy".to_owned(),
                policy_version: 1,
                detector_version: "detector".to_owned(),
                risk_revision: 1,
                approved_risk_revision_hash: "e".repeat(64),
                generation_row_version: 2,
                binding_version: 1,
                selection_id: "selection".to_owned(),
                selection_row_version: 1,
            },
            media_type: "text/plain".to_owned(),
            pages: vec![ApprovedCasePageV1 {
                page_number: 1,
                text: "approved secret canary".to_owned(),
            }],
            canonical_payload: b"approved secret canary".to_vec(),
        };
        let debug = format!("{projection:?}");
        assert!(!debug.contains("approved secret canary"));
        assert!(debug.contains("<approved-redacted-pages>"));
    }

    #[cfg(windows)]
    #[test]
    fn safe_projection_succeeds_when_legacy_review_is_corrupt_and_never_falls_back() {
        let ApprovedProjectionFixture {
            mut connection,
            project_id,
            privacy_case_id,
            redaction_id,
            pages,
            legacy_secret,
        } = approved_projection_fixture();
        connection
            .execute_batch("DROP TRIGGER trg_privacy_redaction_approved_immutable;")
            .expect("disable immutable trigger only for corruption simulation");
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET protected_review_blob=x'00',row_version=row_version+1
                 WHERE redaction_id=?1",
                [&redaction_id],
            )
            .expect("corrupt legacy full review blob");
        assert_eq!(
            PrivacyStore::load_review_draft(&connection, &redaction_id).map(|_| ()),
            Err(PrivacyStoreError::ProtectedBlob)
        );

        let metadata =
            PrivacyStore::list_current_approved_case_generations(&connection, &project_id)
                .expect("safe metadata");
        assert_eq!(metadata.len(), 1);
        assert!(!metadata[0].selected);
        assert_eq!(metadata[0].display_name.as_deref(), Some("已批准材料.txt"));
        let metadata_json = serde_json::to_value(&metadata[0]).expect("metadata json");
        let metadata_object = metadata_json.as_object().expect("metadata object");
        assert_eq!(
            metadata_object.keys().cloned().collect::<BTreeSet<_>>(),
            [
                "approvedAt",
                "displayName",
                "generationNumber",
                "materialId",
                "mediaType",
                "pageCount",
                "redactionGenerationId",
                "selected",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let serialized_metadata = metadata_json.to_string();
        assert!(!serialized_metadata.contains("privacyCaseId"));
        assert!(!serialized_metadata.contains(&privacy_case_id));
        assert!(!serialized_metadata.contains("Sha256"));

        let projections = PrivacyStore::validate_and_append_case_work_selections(
            &mut connection,
            &project_id,
            std::slice::from_ref(&redaction_id),
        )
        .expect("selection from approved-only projection");
        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].pages, pages);
        assert!(
            !String::from_utf8_lossy(&projections[0].canonical_payload).contains(&legacy_secret)
        );
        let revalidated = PrivacyStore::revalidate_case_work_source_snapshots(
            &connection,
            &project_id,
            &[projections[0].snapshot.clone()],
        )
        .expect("exact projection snapshot");
        assert_eq!(
            revalidated[0].canonical_payload,
            projections[0].canonical_payload
        );

        connection
            .execute(
                "UPDATE privacy_redactions
                 SET protected_approved_payload_blob=x'00',row_version=row_version+1
                 WHERE redaction_id=?1",
                [&redaction_id],
            )
            .expect("corrupt approved-only projection");
        assert_eq!(
            PrivacyStore::list_current_approved_case_generations(&connection, &project_id),
            Err(PrivacyStoreError::ProtectedBlob)
        );
    }

    #[cfg(windows)]
    #[test]
    fn exact_selection_is_idempotent_append_preserving_and_invalidation_breaks_snapshot() {
        let ApprovedProjectionFixture {
            mut connection,
            project_id,
            redaction_id,
            ..
        } = approved_projection_fixture();
        let first = PrivacyStore::validate_and_append_case_work_selections(
            &mut connection,
            &project_id,
            std::slice::from_ref(&redaction_id),
        )
        .expect("first selection");
        let replay = PrivacyStore::validate_and_append_case_work_selections(
            &mut connection,
            &project_id,
            std::slice::from_ref(&redaction_id),
        )
        .expect("idempotent exact selection");
        assert_eq!(replay[0].snapshot, first[0].snapshot);
        assert_eq!(
            PrivacyStore::validate_and_append_case_work_selections(
                &mut connection,
                &project_id,
                &[redaction_id.clone(), redaction_id.clone()],
            ),
            Err(PrivacyStoreError::InvalidInput)
        );

        assert_eq!(
            PrivacyStore::invalidate_case_work_selections_for_generation(
                &connection,
                &redaction_id,
                "generation_revoked",
            )
            .expect("invalidate selection"),
            1
        );
        assert_eq!(
            PrivacyStore::revalidate_case_work_source_snapshots(
                &connection,
                &project_id,
                &[first[0].snapshot.clone()],
            ),
            Err(PrivacyStoreError::Conflict)
        );
        let after_invalidation =
            PrivacyStore::list_current_approved_case_generations(&connection, &project_id)
                .expect("metadata after invalidation");
        assert!(!after_invalidation[0].selected);

        let replacement = PrivacyStore::validate_and_append_case_work_selections(
            &mut connection,
            &project_id,
            &[redaction_id],
        )
        .expect("replacement selection");
        assert_ne!(
            replacement[0].snapshot.selection_id,
            first[0].snapshot.selection_id
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM case_material_selections", [], |row| {
                    row.get::<_, u32>(0)
                },)
                .expect("selection history"),
            2
        );
    }

    #[cfg(windows)]
    #[test]
    fn migration_backfill_refuses_a_pre_migration_revoked_approved_ready_row() {
        let ApprovedProjectionFixture {
            mut connection,
            redaction_id,
            pages,
            ..
        } = approved_projection_fixture();
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='revoked',revoked_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE redaction_id=?1",
                [&redaction_id],
            )
            .expect("revoke approved generation");
        let (source_sha256, extraction_sha256, media_type) = connection
            .query_row(
                "SELECT material.source_sha256,generation.extraction_sha256,
                        material.media_type
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.redaction_id=?1",
                [&redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("projection identity");
        let canonical_payload = ApprovedCasePayloadV1 {
            schema_version: APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
            source_sha256,
            extraction_sha256,
            media_type,
            pages,
        }
        .canonical_bytes()
        .expect("canonical payload");
        let (_, risk_head) =
            PrivacyStore::verify_complete_risk_review_chain(&connection, &redaction_id)
                .expect("risk head");
        let source_fingerprint =
            PrivacyStore::approved_projection_migration_row_fingerprint(&connection, &redaction_id)
                .expect("source fingerprint");

        connection
            .execute_batch("DROP TRIGGER trg_privacy_redaction_approved_immutable;")
            .expect("simulate pre-v6 immutable trigger");
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET approved_payload_schema_version=NULL,
                     protected_approved_payload_blob=NULL,
                     approved_payload_protection_scheme=NULL,
                     approved_risk_revision_hash=NULL,
                     row_version=row_version+1
                 WHERE redaction_id=?1",
                [&redaction_id],
            )
            .expect("simulate a revoked v5 source row without projection");

        assert_eq!(
            PrivacyStore::backfill_approved_projection_after_backup(
                &mut connection,
                &ApprovedProjectionBackfill {
                    redaction_id: &redaction_id,
                    source_fingerprint: &source_fingerprint,
                    approved_payload_plaintext: &canonical_payload,
                    approved_risk_revision_hash: &risk_head,
                },
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert!(connection
            .query_row(
                "SELECT approved_payload_schema_version IS NULL
                     FROM privacy_redactions WHERE redaction_id=?1",
                [&redaction_id],
                |row| row.get::<_, bool>(0),
            )
            .expect("projection remains absent"));
    }

    #[cfg(windows)]
    #[test]
    fn broken_risk_chain_blocks_safe_projection_even_when_legacy_review_is_valid() {
        let ApprovedProjectionFixture {
            connection,
            project_id,
            redaction_id,
            ..
        } = approved_projection_fixture();
        assert!(PrivacyStore::load_review_draft(&connection, &redaction_id).is_ok());
        connection
            .execute_batch("DROP TRIGGER trg_privacy_risk_review_no_update;")
            .expect("disable append-only trigger only for corruption simulation");
        connection
            .execute(
                "UPDATE privacy_risk_review_revisions
                 SET action_code='tampered_action'
                 WHERE redaction_id=?1 AND revision=2",
                [&redaction_id],
            )
            .expect("corrupt risk chain");
        assert_eq!(
            PrivacyStore::list_current_approved_case_generations(&connection, &project_id),
            Err(PrivacyStoreError::Conflict)
        );
    }

    #[cfg(windows)]
    #[test]
    fn migration_blocking_cannot_reclassify_an_already_projected_v6_approval() {
        let ApprovedProjectionFixture {
            mut connection,
            redaction_id,
            ..
        } = approved_projection_fixture();
        connection
            .execute_batch("DROP TRIGGER trg_privacy_risk_review_no_delete;")
            .expect("disable delete trigger only for corruption simulation");
        connection
            .execute(
                "DELETE FROM privacy_risk_review_revisions WHERE redaction_id=?1",
                [&redaction_id],
            )
            .expect("remove corrupt risk history");
        let source_fingerprint =
            PrivacyStore::approved_projection_migration_row_fingerprint(&connection, &redaction_id)
                .expect("row fingerprint");
        assert_eq!(
            PrivacyStore::block_approved_projection_after_backup(
                &mut connection,
                &redaction_id,
                &source_fingerprint,
                "approved_projection_risk_chain_invalid",
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT generation_status,
                            approved_payload_schema_version IS NOT NULL
                     FROM privacy_redactions WHERE redaction_id=?1",
                    [&redaction_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
                )
                .expect("immutable projected row"),
            ("ready".to_owned(), true)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_key=?2",
                    params![APPROVED_CASE_PROJECTION_MIGRATION_ID, &redaction_id],
                    |row| row.get::<_, u32>(0),
                )
                .expect("no migration rewrite ledger"),
            0
        );
    }
}
