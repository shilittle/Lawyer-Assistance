use super::{vault_broker, PrivacyWorkflowError, PrivacyWorkflowManager, StoredReviewPayload};
use privacy::{
    case_dictionary::{
        build_dictionary_record, match_case_dictionary, CaseAliasLedgerV1, CaseDictionaryRecordV1,
        DictionaryCategoryV1, ResolvedCaseDictionaryTermV1, MAX_DICTIONARY_ENTRIES,
        MAX_DICTIONARY_VARIANTS,
    },
    deterministic::{DetectionContextV1, StoredPrivateValueBindingV1},
    finding_engine::FindingCandidateV1,
    residual_scan::{
        scan_independent_residuals, IndependentResidualScanReportV1, ResidualDictionaryTermV1,
    },
    sha256_hex,
    vnext::{
        canonical_json_v1, CaseId, EntityType, MaterialId, PrivacyFindingV1, PrivateValueRefV1,
        Sha256Hex,
    },
    ReceiptSigner,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{compiler_fence, Ordering},
};

const DICTIONARY_STATE_SCHEMA_VERSION: &str = "encrypted-case-dictionary-state-v1";
const DICTIONARY_STATE_PAYLOAD_KIND: &str = "case-dictionary-state-v1";
const FINDING_EVIDENCE_SCHEMA_VERSION: &str = "encrypted-finding-secret-evidence-v1";
const FINDING_EVIDENCE_PAYLOAD_KIND: &str = "finding-secret-evidence-v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct CaseDictionarySecretTermV1 {
    entry_id: String,
    primary_value: String,
    variants: Vec<String>,
}

impl Drop for CaseDictionarySecretTermV1 {
    fn drop(&mut self) {
        zeroize_string(&mut self.primary_value);
        for variant in &mut self.variants {
            zeroize_string(variant);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct CaseDictionarySnapshotV1 {
    schema_version: String,
    case_id: CaseId,
    revision: u64,
    ledger: CaseAliasLedgerV1,
    records: Vec<CaseDictionaryRecordV1>,
    terms: Vec<CaseDictionarySecretTermV1>,
    revision_hash: Sha256Hex,
}

impl CaseDictionarySnapshotV1 {
    fn empty(case_id: CaseId) -> Result<Self, PrivacyWorkflowError> {
        let mut state = Self {
            schema_version: DICTIONARY_STATE_SCHEMA_VERSION.to_owned(),
            case_id: case_id.clone(),
            revision: 1,
            ledger: CaseAliasLedgerV1::empty(case_id).map_err(dictionary_error)?,
            records: Vec::new(),
            terms: Vec::new(),
            revision_hash: parse_hash(sha256_hex(b"pending-dictionary-state"))?,
        };
        state.rehash()?;
        Ok(state)
    }

    pub(super) fn revision_hash(&self) -> &Sha256Hex {
        &self.revision_hash
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the decrypted dictionary spellings only for an immediate, in-process egress
    /// guard calculation. Callers must not serialize, log, cache, or return these values.
    pub(super) fn egress_terms(&self) -> Vec<String> {
        let mut terms = BTreeSet::new();
        for term in &self.terms {
            terms.insert(term.primary_value.clone());
            terms.extend(term.variants.iter().cloned());
        }
        terms.into_iter().collect()
    }

    fn validate(&self, signer: &ReceiptSigner) -> Result<(), PrivacyWorkflowError> {
        if self.schema_version != DICTIONARY_STATE_SCHEMA_VERSION
            || self.revision == 0
            || self.records.len() != self.terms.len()
            || self.records.len() > MAX_DICTIONARY_ENTRIES
            || self.ledger.case_id != self.case_id
        {
            return Err(invalid_state());
        }
        self.ledger.validate().map_err(dictionary_error)?;

        let mut entry_ids = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        let mut prior_entry_id: Option<&str> = None;
        for (record, term) in self.records.iter().zip(&self.terms) {
            record.validate().map_err(dictionary_error)?;
            if record.case_id != self.case_id
                || record.revision == 0
                || record.revision > self.revision
                || record.entry_id != term.entry_id
                || term.primary_value.trim().is_empty()
                || term.primary_value.len() > 512
                || term.primary_value.chars().any(char::is_control)
                || term.variants.len() > MAX_DICTIONARY_VARIANTS
                || term.variants.iter().any(|variant| {
                    variant.trim().is_empty()
                        || variant.len() > 512
                        || variant.chars().any(char::is_control)
                })
                || prior_entry_id.is_some_and(|prior| prior >= record.entry_id.as_str())
                || !entry_ids.insert(record.entry_id.clone())
                || !fingerprints.insert(record.value_fingerprint.as_str().to_owned())
            {
                return Err(invalid_state());
            }
            let fingerprint = signer
                .case_value_fingerprint(&self.case_id, &term.primary_value)
                .map_err(|_| invalid_state())?;
            let locator = dictionary_value_locator(&self.case_id, &fingerprint)?;
            if fingerprint != record.value_fingerprint
                || locator != record.private_value_ref.value_locator_hash
            {
                return Err(invalid_state());
            }
            let ledger_alias = self
                .ledger
                .aliases
                .iter()
                .find(|alias| alias.value_fingerprint == record.value_fingerprint)
                .ok_or_else(invalid_state)?;
            if ledger_alias.stable_alias != record.stable_alias {
                return Err(invalid_state());
            }
            prior_entry_id = Some(&record.entry_id);
        }
        if self.ledger.aliases.len() != self.records.len() {
            return Err(invalid_state());
        }
        let mut copy = self.clone();
        copy.rehash()?;
        if copy.revision_hash != self.revision_hash {
            return Err(invalid_state());
        }
        Ok(())
    }

    fn rehash(&mut self) -> Result<(), PrivacyWorkflowError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Claims<'a> {
            schema_version: &'a str,
            case_id: &'a CaseId,
            revision: u64,
            ledger: &'a CaseAliasLedgerV1,
            records: &'a [CaseDictionaryRecordV1],
            terms: &'a [CaseDictionarySecretTermV1],
        }
        let bytes = canonical_json_v1(&Claims {
            schema_version: &self.schema_version,
            case_id: &self.case_id,
            revision: self.revision,
            ledger: &self.ledger,
            records: &self.records,
            terms: &self.terms,
        })
        .map_err(|_| invalid_state())?;
        self.revision_hash = parse_hash(sha256_hex(&bytes))?;
        Ok(())
    }
}

pub(super) struct PendingCaseDictionaryRevisionV1 {
    expected_revision: Option<u64>,
    expected_revision_hash: Option<Sha256Hex>,
    state_binding: vault_broker::VaultAuxBinding,
    snapshot: CaseDictionarySnapshotV1,
    updated_at_unix: u64,
}

impl PendingCaseDictionaryRevisionV1 {
    pub(super) fn snapshot(&self) -> &CaseDictionarySnapshotV1 {
        &self.snapshot
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FindingSecretEntryV1 {
    finding_id: String,
    value_fingerprint: Sha256Hex,
    private_value_ref: PrivateValueRefV1,
    entity_type: EntityType,
    primary_value: String,
}

impl Drop for FindingSecretEntryV1 {
    fn drop(&mut self) {
        zeroize_string(&mut self.primary_value);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FindingSecretEvidenceV1 {
    schema_version: String,
    case_id: CaseId,
    redaction_id: String,
    document_version: u64,
    entries: Vec<FindingSecretEntryV1>,
    evidence_hash: Sha256Hex,
}

pub(super) struct FindingSecretV1 {
    value: String,
}

impl FindingSecretV1 {
    pub(super) fn as_str(&self) -> &str {
        &self.value
    }
}

impl Drop for FindingSecretV1 {
    fn drop(&mut self) {
        zeroize_string(&mut self.value);
    }
}

pub(super) fn initialize_schema(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS privacy_case_dictionary_heads (
                case_id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL CHECK(revision > 0),
                revision_hash TEXT NOT NULL CHECK(length(revision_hash) = 64),
                state_object_id TEXT NOT NULL,
                state_object_version INTEGER NOT NULL CHECK(state_object_version > 0),
                state_content_sha256 TEXT NOT NULL CHECK(length(state_content_sha256) = 64),
                state_envelope_sha256 TEXT NOT NULL CHECK(length(state_envelope_sha256) = 64),
                state_content_bytes INTEGER NOT NULL CHECK(state_content_bytes > 0),
                updated_at_unix INTEGER NOT NULL CHECK(updated_at_unix > 0)
            );
            CREATE TABLE IF NOT EXISTS privacy_finding_secret_evidence (
                redaction_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL CHECK(length(evidence_hash) = 64),
                object_id TEXT NOT NULL,
                object_version INTEGER NOT NULL CHECK(object_version > 0),
                content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
                envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64),
                content_bytes INTEGER NOT NULL CHECK(content_bytes > 0),
                created_at_unix INTEGER NOT NULL CHECK(created_at_unix > 0)
            );
            CREATE INDEX IF NOT EXISTS idx_privacy_finding_secret_case
                ON privacy_finding_secret_evidence(case_id,redaction_id);
            ",
        )
        .map_err(|_| database_error())?;
    Ok(())
}

pub(super) fn ensure_case_dictionary(
    manager: &PrivacyWorkflowManager,
    case_id: &CaseId,
    material_id: &MaterialId,
    custom_terms: &[String],
    now_unix: u64,
) -> Result<CaseDictionarySnapshotV1, PrivacyWorkflowError> {
    let signer = manager.receipt_signer()?;
    let mut connection = manager.open_connection()?;
    let current = load_case_dictionary(&connection, manager, case_id, &signer)?;
    let additions = custom_terms
        .iter()
        .map(|term| DictionaryAdditionV1 {
            value: term.as_str(),
            category: DictionaryCategoryV1::Custom,
            required: true,
        })
        .collect::<Vec<_>>();
    let pending = prepare_revision(
        manager,
        current.as_ref(),
        case_id,
        material_id,
        &additions,
        now_unix,
    )?;
    let Some(pending) = pending else {
        return current.ok_or_else(invalid_state);
    };
    // Revoke every previously approved publication before advancing the
    // case-bound dictionary head. If invalidation fails, the dictionary
    // transaction is never started and the old revision remains current.
    manager.invalidate_case_publications(case_id, "case_dictionary_revision_changed")?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| database_error())?;
    commit_pending_revision(&transaction, &pending)?;
    transaction.commit().map_err(|_| database_error())?;
    Ok(pending.snapshot)
}

pub(super) fn load_required_case_dictionary(
    connection: &Connection,
    manager: &PrivacyWorkflowManager,
    case_id: &CaseId,
) -> Result<CaseDictionarySnapshotV1, PrivacyWorkflowError> {
    let signer = manager.receipt_signer()?;
    load_case_dictionary(connection, manager, case_id, &signer)?.ok_or_else(|| {
        PrivacyWorkflowError::new(
            "privacy_case_dictionary_missing",
            "The case-bound dictionary evidence is unavailable; the operation failed closed.",
        )
    })
}

fn load_case_dictionary(
    connection: &Connection,
    manager: &PrivacyWorkflowManager,
    case_id: &CaseId,
    signer: &ReceiptSigner,
) -> Result<Option<CaseDictionarySnapshotV1>, PrivacyWorkflowError> {
    let row = connection
        .query_row(
            "SELECT revision,revision_hash,state_object_id,state_object_version,
                    state_content_sha256,state_envelope_sha256,state_content_bytes
             FROM privacy_case_dictionary_heads WHERE case_id=?1",
            [case_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| database_error())?;
    let Some(row) = row else {
        return Ok(None);
    };
    let binding = vault_broker::VaultAuxBinding {
        case_id: case_id.clone(),
        object_id: privacy::vnext::ObjectId::parse(row.2).map_err(|_| invalid_state())?,
        object_version: u64::try_from(row.3).map_err(|_| invalid_state())?,
        content_sha256: parse_hash(row.4)?,
        envelope_sha256: parse_hash(row.5)?,
        content_bytes: u64::try_from(row.6).map_err(|_| invalid_state())?,
    };
    let lease = manager
        .shared
        .vault_broker
        .read_aux_payload(&binding)
        .map_err(PrivacyWorkflowError::vault)?;
    let state: CaseDictionarySnapshotV1 =
        serde_json::from_slice(lease.content()).map_err(|_| invalid_state())?;
    state.validate(signer)?;
    if state.case_id != *case_id
        || state.revision != u64::try_from(row.0).map_err(|_| invalid_state())?
        || state.revision_hash.as_str() != row.1
        || binding.content_sha256 != parse_hash(sha256_hex(lease.content()))?
    {
        return Err(invalid_state());
    }
    Ok(Some(state))
}

pub(super) fn prepare_add_finding_revision(
    manager: &PrivacyWorkflowManager,
    current: &CaseDictionarySnapshotV1,
    material_id: &MaterialId,
    value: &str,
    category: DictionaryCategoryV1,
    required: bool,
    now_unix: u64,
) -> Result<Option<PendingCaseDictionaryRevisionV1>, PrivacyWorkflowError> {
    prepare_revision(
        manager,
        Some(current),
        current.case_id(),
        material_id,
        &[DictionaryAdditionV1 {
            value,
            category,
            required,
        }],
        now_unix,
    )
}

struct DictionaryAdditionV1<'a> {
    value: &'a str,
    category: DictionaryCategoryV1,
    required: bool,
}

fn prepare_revision(
    manager: &PrivacyWorkflowManager,
    current: Option<&CaseDictionarySnapshotV1>,
    case_id: &CaseId,
    material_id: &MaterialId,
    additions: &[DictionaryAdditionV1<'_>],
    now_unix: u64,
) -> Result<Option<PendingCaseDictionaryRevisionV1>, PrivacyWorkflowError> {
    if now_unix == 0 || additions.len() > MAX_DICTIONARY_ENTRIES {
        return Err(invalid_state());
    }
    let signer = manager.receipt_signer()?;
    let mut state = current
        .cloned()
        .map_or_else(|| CaseDictionarySnapshotV1::empty(case_id.clone()), Ok)?;
    state.validate(&signer)?;
    if state.case_id != *case_id {
        return Err(invalid_state());
    }

    let target_revision = if current.is_some() {
        state.revision.checked_add(1).ok_or_else(invalid_state)?
    } else {
        1
    };
    let mut requested = BTreeMap::<String, (Sha256Hex, &DictionaryAdditionV1<'_>)>::new();
    for addition in additions {
        let value = addition.value.trim();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(PrivacyWorkflowError::new(
                "privacy_case_dictionary_value_invalid",
                "The case dictionary value is invalid; it was not persisted.",
            ));
        }
        let fingerprint = signer
            .case_value_fingerprint(case_id, value)
            .map_err(|_| invalid_state())?;
        requested.insert(fingerprint.as_str().to_owned(), (fingerprint, addition));
    }

    let mut new_values = Vec::new();
    let mut changed = current.is_none();
    for (fingerprint_text, (fingerprint, addition)) in &requested {
        if let Some(existing) = state
            .records
            .iter()
            .find(|record| record.value_fingerprint.as_str() == fingerprint_text)
        {
            if existing.category != addition.category || existing.required != addition.required {
                changed = true;
            }
        } else {
            changed = true;
            new_values.push((
                fingerprint.clone(),
                addition.value.trim(),
                addition.category,
                addition.required,
            ));
        }
    }
    if !changed {
        return Ok(None);
    }

    let connection = manager.open_connection()?;
    let lifecycle = manager.privacy_lifecycle(&connection)?;
    let retention = lifecycle
        .retention_policy(&connection)
        .map_err(PrivacyWorkflowError::lifecycle)?;
    drop(connection);
    let expires_at_unix = now_unix
        .checked_add(retention.review_retention_seconds)
        .ok_or_else(invalid_state)?;

    let locators = new_values
        .iter()
        .map(|(fingerprint, _, _, _)| dictionary_value_locator(case_id, fingerprint))
        .collect::<Result<Vec<_>, _>>()?;
    let to_seal = new_values
        .iter()
        .zip(&locators)
        .map(
            |((_, value, _, _), locator)| vault_broker::PrivateValueToSeal {
                value_locator_hash: locator.clone(),
                private_value: value,
            },
        )
        .collect::<Vec<_>>();
    let sealed = if to_seal.is_empty() {
        None
    } else {
        let sealed = manager
            .shared
            .vault_broker
            .seal_private_values(case_id, material_id, &to_seal, now_unix)
            .map_err(PrivacyWorkflowError::vault)?;
        manager
            .shared
            .vault_broker
            .bind_aux_retention(
                &sealed.binding,
                expires_at_unix,
                false,
                retention.revision,
                now_unix,
            )
            .map_err(PrivacyWorkflowError::vault)?;
        if sealed.references.len() != new_values.len() {
            return Err(invalid_state());
        }
        Some(sealed)
    };

    for (_, (fingerprint, addition)) in requested {
        let existing_index = state
            .records
            .iter()
            .position(|record| record.value_fingerprint == fingerprint);
        let binding = if let Some(index) = existing_index {
            StoredPrivateValueBindingV1 {
                value_fingerprint: fingerprint.clone(),
                private_value_ref: state.records[index].private_value_ref.clone(),
                proposed_replacement: state.records[index].stable_alias.clone(),
            }
        } else {
            let new_index = new_values
                .iter()
                .position(|(candidate, _, _, _)| candidate == &fingerprint)
                .ok_or_else(invalid_state)?;
            let reference = sealed
                .as_ref()
                .and_then(|batch| batch.references.get(new_index))
                .cloned()
                .ok_or_else(invalid_state)?;
            StoredPrivateValueBindingV1 {
                value_fingerprint: fingerprint.clone(),
                private_value_ref: reference,
                proposed_replacement: "[dictionary-pending]".to_owned(),
            }
        };
        let record = build_dictionary_record(
            case_id.clone(),
            addition.category,
            addition.required,
            target_revision,
            binding,
            &mut state.ledger,
        )
        .map_err(dictionary_error)?;
        if let Some(index) = existing_index {
            state.records[index] = record;
        } else {
            state.terms.push(CaseDictionarySecretTermV1 {
                entry_id: record.entry_id.clone(),
                primary_value: addition.value.trim().to_owned(),
                variants: Vec::new(),
            });
            state.records.push(record);
        }
    }
    let mut paired = state
        .records
        .drain(..)
        .zip(state.terms.drain(..))
        .collect::<Vec<_>>();
    paired.sort_by(|left, right| left.0.entry_id.cmp(&right.0.entry_id));
    (state.records, state.terms) = paired.into_iter().unzip();
    state.revision = target_revision;
    state.rehash()?;
    state.validate(&signer)?;

    let plaintext =
        vault_broker::ZeroizingBytes::new(serde_json::to_vec(&state).map_err(|_| invalid_state())?);
    let state_binding = manager
        .shared
        .vault_broker
        .seal_aux_payload(case_id, DICTIONARY_STATE_PAYLOAD_KIND, &plaintext, now_unix)
        .map_err(PrivacyWorkflowError::vault)?;
    manager
        .shared
        .vault_broker
        .bind_aux_retention(
            &state_binding,
            expires_at_unix,
            false,
            retention.revision,
            now_unix,
        )
        .map_err(PrivacyWorkflowError::vault)?;
    if state_binding.content_sha256.as_str() != sha256_hex(&plaintext) {
        return Err(invalid_state());
    }
    Ok(Some(PendingCaseDictionaryRevisionV1 {
        expected_revision: current.map(CaseDictionarySnapshotV1::revision),
        expected_revision_hash: current.map(|value| value.revision_hash().clone()),
        state_binding,
        snapshot: state,
        updated_at_unix: now_unix,
    }))
}

pub(super) fn commit_pending_revision(
    transaction: &Transaction<'_>,
    pending: &PendingCaseDictionaryRevisionV1,
) -> Result<(), PrivacyWorkflowError> {
    let changed = if let (Some(revision), Some(revision_hash)) = (
        pending.expected_revision,
        pending.expected_revision_hash.as_ref(),
    ) {
        transaction
            .execute(
                "UPDATE privacy_case_dictionary_heads SET
                   revision=?2,revision_hash=?3,state_object_id=?4,state_object_version=?5,
                   state_content_sha256=?6,state_envelope_sha256=?7,state_content_bytes=?8,
                   updated_at_unix=?9
                 WHERE case_id=?1 AND revision=?10 AND revision_hash=?11",
                params![
                    pending.snapshot.case_id.as_str(),
                    sql_i64(pending.snapshot.revision)?,
                    pending.snapshot.revision_hash.as_str(),
                    pending.state_binding.object_id.as_str(),
                    sql_i64(pending.state_binding.object_version)?,
                    pending.state_binding.content_sha256.as_str(),
                    pending.state_binding.envelope_sha256.as_str(),
                    sql_i64(pending.state_binding.content_bytes)?,
                    sql_i64(pending.updated_at_unix)?,
                    sql_i64(revision)?,
                    revision_hash.as_str(),
                ],
            )
            .map_err(|_| database_error())?
    } else {
        transaction
            .execute(
                "INSERT INTO privacy_case_dictionary_heads(
                   case_id,revision,revision_hash,state_object_id,state_object_version,
                   state_content_sha256,state_envelope_sha256,state_content_bytes,updated_at_unix
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    pending.snapshot.case_id.as_str(),
                    sql_i64(pending.snapshot.revision)?,
                    pending.snapshot.revision_hash.as_str(),
                    pending.state_binding.object_id.as_str(),
                    sql_i64(pending.state_binding.object_version)?,
                    pending.state_binding.content_sha256.as_str(),
                    pending.state_binding.envelope_sha256.as_str(),
                    sql_i64(pending.state_binding.content_bytes)?,
                    sql_i64(pending.updated_at_unix)?,
                ],
            )
            .map_err(|_| database_error())?
    };
    if changed != 1 {
        return Err(PrivacyWorkflowError::new(
            "privacy_case_dictionary_revision_conflict",
            "The case dictionary changed concurrently; the review operation failed closed.",
        ));
    }
    Ok(())
}

pub(super) fn match_candidates(
    snapshot: &CaseDictionarySnapshotV1,
    text: &str,
    context: DetectionContextV1<'_>,
) -> Result<Vec<FindingCandidateV1>, PrivacyWorkflowError> {
    let variants = snapshot
        .terms
        .iter()
        .map(|term| term.variants.iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let resolved = snapshot
        .records
        .iter()
        .zip(&snapshot.terms)
        .zip(&variants)
        .map(|((record, term), variants)| ResolvedCaseDictionaryTermV1 {
            record,
            primary_value: &term.primary_value,
            variants,
        })
        .collect::<Vec<_>>();
    let mut candidates =
        match_case_dictionary(text, context, &resolved).map_err(dictionary_error)?;
    // The dictionary ledger deliberately uses full-width legal-document brackets, while the
    // finding engine accepts only ASCII-delimited replacement tokens. Preserve the stable alias
    // body and adapt only the delimiters at this internal boundary.
    for candidate in &mut candidates {
        if let Some(alias) = candidate.proposed_replacement.as_mut() {
            if let Some(inner) = alias
                .strip_prefix('\u{3010}')
                .and_then(|value| value.strip_suffix('\u{3011}'))
            {
                *alias = format!("[{inner}]");
            }
        }
    }
    Ok(candidates)
}

pub(super) fn scan_residuals(
    snapshot: &CaseDictionarySnapshotV1,
    pages: &[String],
    source_display_name: &str,
) -> Result<IndependentResidualScanReportV1, PrivacyWorkflowError> {
    let variants = snapshot
        .terms
        .iter()
        .map(|term| term.variants.iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let terms = snapshot
        .records
        .iter()
        .zip(&snapshot.terms)
        .zip(&variants)
        .map(|((record, term), variants)| ResidualDictionaryTermV1 {
            entity_type: record.entity_type,
            primary_value: &term.primary_value,
            variants,
            expected_alias: &record.stable_alias,
        })
        .collect::<Vec<_>>();
    let source_names = (!source_display_name.trim().is_empty())
        .then_some(source_display_name)
        .into_iter()
        .collect::<Vec<_>>();
    scan_independent_residuals(privacy::residual_scan::IndependentResidualScanInputV1 {
        pages,
        dictionary_terms: &terms,
        source_names: &source_names,
    })
    .map_err(|_| {
        PrivacyWorkflowError::new(
            "privacy_residual_scan_failed",
            "The case-bound independent residual scan failed closed.",
        )
    })
}

pub(super) fn persist_finding_secret_evidence(
    manager: &PrivacyWorkflowManager,
    stored: &StoredReviewPayload,
    findings: &[PrivacyFindingV1],
    signer: &ReceiptSigner,
    expires_at_unix: u64,
    policy_revision: u64,
    now_unix: u64,
) -> Result<(), PrivacyWorkflowError> {
    if findings.is_empty() {
        return Ok(());
    }
    let case_id = CaseId::parse(stored.case_id.clone().ok_or_else(invalid_state)?)
        .map_err(|_| invalid_state())?;
    let mut entries = Vec::with_capacity(findings.len());
    for finding in findings {
        let page_index = usize::try_from(finding.page_index).map_err(|_| invalid_state())?;
        let page = stored.pages.get(page_index).ok_or_else(invalid_state)?;
        if finding.block_id != format!("page-{page_index}") {
            return Err(invalid_state());
        }
        let start = usize::try_from(finding.start_offset).map_err(|_| invalid_state())?;
        let end = usize::try_from(finding.end_offset).map_err(|_| invalid_state())?;
        let value = page
            .original_text
            .get(start..end)
            .ok_or_else(invalid_state)?;
        let fingerprint = signer
            .case_value_fingerprint(&case_id, value)
            .map_err(|_| invalid_state())?;
        entries.push(FindingSecretEntryV1 {
            finding_id: finding.finding_id.as_str().to_owned(),
            value_fingerprint: fingerprint,
            private_value_ref: finding.private_value_ref.clone(),
            entity_type: finding.entity_type,
            primary_value: value.to_owned(),
        });
    }
    entries.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    if entries
        .windows(2)
        .any(|pair| pair[0].finding_id == pair[1].finding_id)
    {
        return Err(invalid_state());
    }
    let evidence_hash = finding_evidence_hash(&case_id, &stored.redaction_id, 1, &entries)?;
    let evidence = FindingSecretEvidenceV1 {
        schema_version: FINDING_EVIDENCE_SCHEMA_VERSION.to_owned(),
        case_id: case_id.clone(),
        redaction_id: stored.redaction_id.clone(),
        document_version: 1,
        entries,
        evidence_hash: evidence_hash.clone(),
    };
    let plaintext = vault_broker::ZeroizingBytes::new(
        serde_json::to_vec(&evidence).map_err(|_| invalid_state())?,
    );
    let binding = manager
        .shared
        .vault_broker
        .seal_aux_payload(
            &case_id,
            FINDING_EVIDENCE_PAYLOAD_KIND,
            &plaintext,
            now_unix,
        )
        .map_err(PrivacyWorkflowError::vault)?;
    manager
        .shared
        .vault_broker
        .bind_aux_retention(&binding, expires_at_unix, false, policy_revision, now_unix)
        .map_err(PrivacyWorkflowError::vault)?;
    let connection = manager.open_connection()?;
    connection
        .execute(
            "INSERT INTO privacy_finding_secret_evidence(
               redaction_id,case_id,evidence_hash,object_id,object_version,content_sha256,
               envelope_sha256,content_bytes,created_at_unix
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(redaction_id) DO UPDATE SET
               case_id=excluded.case_id,evidence_hash=excluded.evidence_hash,
               object_id=excluded.object_id,object_version=excluded.object_version,
               content_sha256=excluded.content_sha256,envelope_sha256=excluded.envelope_sha256,
               content_bytes=excluded.content_bytes,created_at_unix=excluded.created_at_unix",
            params![
                stored.redaction_id,
                case_id.as_str(),
                evidence_hash.as_str(),
                binding.object_id.as_str(),
                sql_i64(binding.object_version)?,
                binding.content_sha256.as_str(),
                binding.envelope_sha256.as_str(),
                sql_i64(binding.content_bytes)?,
                sql_i64(now_unix)?,
            ],
        )
        .map_err(|_| database_error())?;
    Ok(())
}

pub(super) fn load_finding_secret(
    connection: &Connection,
    manager: &PrivacyWorkflowManager,
    case_id: &CaseId,
    redaction_id: &str,
    finding: &PrivacyFindingV1,
) -> Result<FindingSecretV1, PrivacyWorkflowError> {
    let row = connection
        .query_row(
            "SELECT evidence_hash,object_id,object_version,content_sha256,envelope_sha256,
                    content_bytes
             FROM privacy_finding_secret_evidence
             WHERE redaction_id=?1 AND case_id=?2",
            params![redaction_id, case_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| database_error())?
        .ok_or_else(|| {
            PrivacyWorkflowError::new(
                "privacy_finding_secret_evidence_missing",
                "The encrypted finding evidence is unavailable; the dictionary was not changed.",
            )
        })?;
    let binding = vault_broker::VaultAuxBinding {
        case_id: case_id.clone(),
        object_id: privacy::vnext::ObjectId::parse(row.1).map_err(|_| invalid_state())?,
        object_version: u64::try_from(row.2).map_err(|_| invalid_state())?,
        content_sha256: parse_hash(row.3)?,
        envelope_sha256: parse_hash(row.4)?,
        content_bytes: u64::try_from(row.5).map_err(|_| invalid_state())?,
    };
    let lease = manager
        .shared
        .vault_broker
        .read_aux_payload(&binding)
        .map_err(PrivacyWorkflowError::vault)?;
    let evidence: FindingSecretEvidenceV1 =
        serde_json::from_slice(lease.content()).map_err(|_| invalid_state())?;
    if evidence.schema_version != FINDING_EVIDENCE_SCHEMA_VERSION
        || evidence.case_id != *case_id
        || evidence.redaction_id != redaction_id
        || evidence.document_version != 1
        || evidence.evidence_hash.as_str() != row.0
        || finding_evidence_hash(
            &evidence.case_id,
            &evidence.redaction_id,
            evidence.document_version,
            &evidence.entries,
        )? != evidence.evidence_hash
    {
        return Err(invalid_state());
    }
    let signer = manager.receipt_signer()?;
    let entry = evidence
        .entries
        .iter()
        .find(|entry| entry.finding_id == finding.finding_id.as_str())
        .ok_or_else(invalid_state)?;
    let fingerprint = signer
        .case_value_fingerprint(case_id, &entry.primary_value)
        .map_err(|_| invalid_state())?;
    if fingerprint != entry.value_fingerprint
        || entry.private_value_ref != finding.private_value_ref
        || entry.entity_type != finding.entity_type
    {
        return Err(invalid_state());
    }
    Ok(FindingSecretV1 {
        value: entry.primary_value.clone(),
    })
}

fn finding_evidence_hash(
    case_id: &CaseId,
    redaction_id: &str,
    document_version: u64,
    entries: &[FindingSecretEntryV1],
) -> Result<Sha256Hex, PrivacyWorkflowError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Claims<'a> {
        schema_version: &'static str,
        case_id: &'a CaseId,
        redaction_id: &'a str,
        document_version: u64,
        entries: &'a [FindingSecretEntryV1],
    }
    let bytes = canonical_json_v1(&Claims {
        schema_version: FINDING_EVIDENCE_SCHEMA_VERSION,
        case_id,
        redaction_id,
        document_version,
        entries,
    })
    .map_err(|_| invalid_state())?;
    parse_hash(sha256_hex(&bytes))
}

fn dictionary_value_locator(
    case_id: &CaseId,
    fingerprint: &Sha256Hex,
) -> Result<Sha256Hex, PrivacyWorkflowError> {
    parse_hash(sha256_hex(
        format!(
            "case-dictionary-value-locator-v1\0{}\0{}",
            case_id.as_str(),
            fingerprint.as_str()
        )
        .as_bytes(),
    ))
}

fn parse_hash(value: String) -> Result<Sha256Hex, PrivacyWorkflowError> {
    Sha256Hex::parse(value).map_err(|_| invalid_state())
}

fn sql_i64(value: u64) -> Result<i64, PrivacyWorkflowError> {
    i64::try_from(value).map_err(|_| invalid_state())
}

fn invalid_state() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "privacy_case_dictionary_evidence_invalid",
        "The encrypted case dictionary evidence is invalid; the operation failed closed.",
    )
}

fn database_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "privacy_case_dictionary_store_failed",
        "The protected case dictionary store is unavailable; the operation failed closed.",
    )
}

fn dictionary_error(error: privacy::case_dictionary::CaseDictionaryError) -> PrivacyWorkflowError {
    let _ = error;
    PrivacyWorkflowError::new(
        "privacy_case_dictionary_validation_failed",
        "Case dictionary validation failed closed.",
    )
}

fn zeroize_string(value: &mut str) {
    unsafe {
        value.as_bytes_mut().fill(0);
    }
    compiler_fence(Ordering::SeqCst);
}
