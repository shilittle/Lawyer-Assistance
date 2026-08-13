use database::{
    UserMigrationSourceFileProof, UserMigrationSourceProof, UserMigrationTableProof,
    ValidatedUserSourceSchema, V031_USER_SCHEMA_MANIFEST_SHA256, V031_USER_SCHEMA_OBJECT_COUNT,
};
use privacy::{
    original_rollback_v2::{
        V031OriginalRollbackIdentityV2, V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL,
        V031_VAULT_AUTHENTICATED_ABSENT_SENTINEL, V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL,
    },
    vnext::canonical_json_v1,
    PrivacyV1BusinessTableManifest, PrivacyV1LogicalTableManifest, ValidatedPrivacyV1Source,
    PRIVACY_V1_SCHEMA_OBJECT_COUNT,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
    Storage::FileSystem::GetDiskFreeSpaceExW,
};
use zeroize::Zeroize;

const SOURCE_PROFILE_EVIDENCE_SCHEMA: &str = "lawyer-assistance-v031-exact-source-profile-proof-v1";
const SOURCE_PROFILE_VALIDATOR_VERSION: &str = "v031-exact-source-validator-r1";
const SOURCE_PROFILE_NAME: &str = "v0.3.1-exact";
const V031_TAG_OBJECT: &str = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc";
const V031_PEELED_COMMIT: &str = "0970f1c614b1bec1856869c68065162339849468";
const V031_TAGGER_UTC: &str = "2026-07-19T15:41:29Z";
const V031_PRIVACY_SCHEMA_MANIFEST_SHA256: &str =
    "c41507b6441799decf2b2c506e884439b0ede732fa4ef2382ce5e22aaf9534b5";
const V031_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
const BINDING_DOMAIN: &[u8] = b"lawyer-assistance\0v031-original-rollback\0envelope-binding-v1\0";
const LINEAGE_DOMAIN: &[u8] = b"lawyer-assistance\0v031-to-v040-upgrade\0lineage-v1\0";
const ABSENT_PROOF_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0authenticated-absent-proof-v1\0";
const CAPACITY_PROOF_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0capacity-proof-v1\0";
const TARGET_ABSENCE_POLICY_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0target-absence-policy-v1\0";
const LOCAL_PROTECTION_PREFLIGHT_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0dpapi-preflight-v1\0";
const LOCAL_PROTECTION_PREFLIGHT_CHALLENGE: &[u8] =
    b"lawyer-assistance-v031-original-rollback-current-user-preflight";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031UpgradeSourceError {
    InvalidProof,
    CountOverflow,
    CryptoUnavailable,
    CapacityUnavailable,
    InsufficientCapacity,
    Encoding,
}

impl V031UpgradeSourceError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidProof => "v031_upgrade_source_proof_invalid",
            Self::CountOverflow => "v031_upgrade_source_count_overflow",
            Self::CryptoUnavailable => "v031_upgrade_source_crypto_unavailable",
            Self::CapacityUnavailable => "v031_upgrade_source_capacity_unavailable",
            Self::InsufficientCapacity => "v031_upgrade_source_capacity_insufficient",
            Self::Encoding => "v031_upgrade_source_evidence_encoding_failed",
        }
    }
}

impl fmt::Display for V031UpgradeSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031UpgradeSourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031TargetAbsenceEvidence {
    policy_sha256: String,
    filesystem_checks: u64,
    credential_checks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031BackupCapacityEvidence {
    user_bytes: u64,
    privacy_bytes: u64,
    required_bytes: u64,
    available_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031SourceProfileProof {
    sha256: String,
    user_logical_sha256: String,
    user_business_sha256: String,
    user_total_rows: u64,
    privacy_logical_sha256: String,
    privacy_business_sha256: String,
    privacy_total_rows: u64,
    privacy_protected_payloads: u64,
    target_absence_checks: u64,
}

impl V031SourceProfileProof {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn user_logical_sha256(&self) -> &str {
        &self.user_logical_sha256
    }

    pub(crate) fn user_business_sha256(&self) -> &str {
        &self.user_business_sha256
    }

    pub(crate) const fn user_total_rows(&self) -> u64 {
        self.user_total_rows
    }

    pub(crate) fn privacy_logical_sha256(&self) -> &str {
        &self.privacy_logical_sha256
    }

    pub(crate) fn privacy_business_sha256(&self) -> &str {
        &self.privacy_business_sha256
    }

    pub(crate) const fn privacy_total_rows(&self) -> u64 {
        self.privacy_total_rows
    }

    pub(crate) const fn privacy_protected_payloads(&self) -> u64 {
        self.privacy_protected_payloads
    }

    pub(crate) const fn target_absence_checks(&self) -> u64 {
        self.target_absence_checks
    }
}

/// Reconstructs the non-secret source summary needed after the active stores
/// have advanced beyond v0.3.1. The caller must first authenticate the V2
/// identity and decrypt its two SQLite images; this function then requires
/// both images to have passed the exact in-memory validators and binds their
/// semantic manifests back to that identity. The original full source-profile
/// digest remains the DPAPI/AEAD-authenticated digest and is never guessed from
/// the different in-memory file identity.
pub(crate) fn recover_v031_source_profile_from_authenticated_original_v2(
    identity: &V031OriginalRollbackIdentityV2,
    user: &UserMigrationSourceProof,
    privacy: &ValidatedPrivacyV1Source,
) -> Result<V031SourceProfileProof, V031UpgradeSourceError> {
    if !is_lower_hash(&identity.source_profile_proof_sha256)
        || user.schema != ValidatedUserSourceSchema::V031V10
        || user.schema_manifest_sha256 != V031_USER_SCHEMA_MANIFEST_SHA256
        || user.tables.len() != 27
        || privacy.schema_version != 1
        || privacy.schema_object_count != PRIVACY_V1_SCHEMA_OBJECT_COUNT
        || privacy.normalized_sqlite_master_sha256 != V031_PRIVACY_SCHEMA_MANIFEST_SHA256
        || user.logical_database_manifest_sha256 != identity.source_user_logical_manifest_sha256
        || user.business_manifest_sha256 != identity.source_user_business_manifest_sha256
        || privacy.logical_manifest.sha256 != identity.source_privacy_logical_manifest_sha256
        || privacy.business_manifest.sha256 != identity.source_privacy_business_manifest_sha256
    {
        return Err(V031UpgradeSourceError::InvalidProof);
    }
    for hash in [
        &user.business_primary_key_manifest_sha256,
        &user.business_row_manifest_sha256,
        &privacy.business_manifest.primary_key_sha256,
        &privacy.business_manifest.row_sha256,
    ] {
        if !is_lower_hash(hash) {
            return Err(V031UpgradeSourceError::InvalidProof);
        }
    }
    let target_absence_checks = 26;
    Ok(V031SourceProfileProof {
        sha256: identity.source_profile_proof_sha256.clone(),
        user_logical_sha256: user.logical_database_manifest_sha256.clone(),
        user_business_sha256: user.business_manifest_sha256.clone(),
        user_total_rows: user.total_rows,
        privacy_logical_sha256: privacy.logical_manifest.sha256.clone(),
        privacy_business_sha256: privacy.business_manifest.sha256.clone(),
        privacy_total_rows: privacy.logical_manifest.total_row_count,
        privacy_protected_payloads: privacy.protected_review_payload_count,
        target_absence_checks,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031GeneratedUpgradeIdentity {
    envelope_binding_id: String,
    lineage_id: String,
}

impl V031GeneratedUpgradeIdentity {
    pub(crate) fn envelope_binding_id(&self) -> &str {
        &self.envelope_binding_id
    }

    pub(crate) fn lineage_id(&self) -> &str {
        &self.lineage_id
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceProfileEvidenceV1 {
    schema_version: &'static str,
    validator_version: &'static str,
    source_profile: &'static str,
    provenance: ProvenanceEvidenceV1,
    user: UserEvidenceV1,
    privacy: PrivacyEvidenceV1,
    authenticated_absent_proof_sha256: String,
    target_absence_policy_sha256: String,
    capacity_proof_sha256: String,
    local_protection_preflight_sha256: String,
    counts: BTreeMap<&'static str, u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvenanceEvidenceV1 {
    tag_object: &'static str,
    peeled_commit: &'static str,
    tagger_utc: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserEvidenceV1 {
    schema_version: i64,
    schema_manifest_sha256: String,
    database_file: FileEvidenceV1,
    wal: Option<FileEvidenceV1>,
    shm: Option<FileEvidenceV1>,
    journal: Option<FileEvidenceV1>,
    logical_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    tables: Vec<UserTableEvidenceV1>,
    total_rows: u64,
    data_version: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyEvidenceV1 {
    schema_version: i64,
    schema_manifest_sha256: &'static str,
    database_file: FileEvidenceV1,
    wal: Option<FileEvidenceV1>,
    shm: Option<FileEvidenceV1>,
    journal: Option<FileEvidenceV1>,
    logical_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    logical_tables: Vec<PrivacyTableEvidenceV1>,
    business_tables: Vec<PrivacyTableEvidenceV1>,
    total_rows: u64,
    protected_payloads: u64,
    data_version: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileEvidenceV1 {
    identity_sha256: String,
    length: u64,
    modified_unix_nanos: Option<u128>,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserTableEvidenceV1 {
    table: String,
    rows: u64,
    logical_manifest_sha256: String,
    business_manifest_sha256: Option<String>,
    business_primary_key_manifest_sha256: Option<String>,
    business_row_manifest_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyTableEvidenceV1 {
    table: String,
    rows: u64,
    manifest_sha256: String,
    primary_key_sha256: Option<String>,
    row_sha256: Option<String>,
}

pub(crate) fn build_v031_source_profile_proof(
    user: &UserMigrationSourceProof,
    privacy: &ValidatedPrivacyV1Source,
    target_absence: &V031TargetAbsenceEvidence,
    capacity: &V031BackupCapacityEvidence,
    local_protection_preflight_sha256: &str,
) -> Result<V031SourceProfileProof, V031UpgradeSourceError> {
    validate_source_contract(user, privacy, target_absence, capacity)?;
    if !is_lower_hash(local_protection_preflight_sha256) {
        return Err(V031UpgradeSourceError::InvalidProof);
    }
    let authenticated_absent_proof_sha256 = authenticated_absent_proof();
    let target_absence_checks = target_absence
        .filesystem_checks
        .checked_add(target_absence.credential_checks)
        .ok_or(V031UpgradeSourceError::CountOverflow)?;
    let mut counts = BTreeMap::new();
    for (key, value) in [
        ("authenticatedAbsentSlots", 3),
        ("capacityChecks", 2),
        ("credentialAbsenceChecks", target_absence.credential_checks),
        ("presentSlots", 2),
        (
            "privacySchemaObjects",
            PRIVACY_V1_SCHEMA_OBJECT_COUNT as u64,
        ),
        ("protectedPayloads", privacy.protected_review_payload_count),
        ("targetAbsenceChecks", target_absence_checks),
        ("userSchemaObjects", V031_USER_SCHEMA_OBJECT_COUNT as u64),
    ] {
        if value > i64::MAX as u64 {
            return Err(V031UpgradeSourceError::CountOverflow);
        }
        counts.insert(key, value);
    }
    let evidence = SourceProfileEvidenceV1 {
        schema_version: SOURCE_PROFILE_EVIDENCE_SCHEMA,
        validator_version: SOURCE_PROFILE_VALIDATOR_VERSION,
        source_profile: SOURCE_PROFILE_NAME,
        provenance: ProvenanceEvidenceV1 {
            tag_object: V031_TAG_OBJECT,
            peeled_commit: V031_PEELED_COMMIT,
            tagger_utc: V031_TAGGER_UTC,
        },
        user: user_evidence(user),
        privacy: privacy_evidence(privacy),
        authenticated_absent_proof_sha256,
        target_absence_policy_sha256: target_absence.policy_sha256.clone(),
        capacity_proof_sha256: capacity.sha256.clone(),
        local_protection_preflight_sha256: local_protection_preflight_sha256.to_owned(),
        counts,
    };
    let canonical = canonical_json_v1(&evidence).map_err(|_| V031UpgradeSourceError::Encoding)?;
    Ok(V031SourceProfileProof {
        sha256: sha256_hex(&canonical),
        user_logical_sha256: user.logical_database_manifest_sha256.clone(),
        user_business_sha256: user.business_manifest_sha256.clone(),
        user_total_rows: user.total_rows,
        privacy_logical_sha256: privacy.logical_manifest.sha256.clone(),
        privacy_business_sha256: privacy.business_manifest.sha256.clone(),
        privacy_total_rows: privacy.logical_manifest.total_row_count,
        privacy_protected_payloads: privacy.protected_review_payload_count,
        target_absence_checks,
    })
}

pub(crate) fn target_absence_evidence_from_verified(
    proof: &crate::v031_upgrade_r2::TargetAbsenceProof,
) -> Result<V031TargetAbsenceEvidence, V031UpgradeSourceError> {
    let credential_checks = u64::try_from(proof.credential_roles_checked())
        .map_err(|_| V031UpgradeSourceError::CountOverflow)?;
    let filesystem_checks = proof
        .fixed_paths_checked()
        .checked_add(proof.sibling_directories_scanned())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(V031UpgradeSourceError::CountOverflow)?;
    if credential_checks != 4 || filesystem_checks != 22 {
        return Err(V031UpgradeSourceError::InvalidProof);
    }
    Ok(V031TargetAbsenceEvidence {
        policy_sha256: v031_target_absence_policy_sha256(),
        filesystem_checks,
        credential_checks,
    })
}

pub(crate) fn required_v031_backup_capacity_bytes(
    user_bytes: u64,
    privacy_bytes: u64,
) -> Result<u64, V031UpgradeSourceError> {
    user_bytes
        .checked_add(privacy_bytes)
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .ok_or(V031UpgradeSourceError::CountOverflow)
}

pub(crate) fn verify_v031_backup_capacity(
    app_local_data_dir: &Path,
    user_bytes: u64,
    privacy_bytes: u64,
) -> Result<V031BackupCapacityEvidence, V031UpgradeSourceError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031UpgradeSourceError::CapacityUnavailable);
    }
    let required_bytes = required_v031_backup_capacity_bytes(user_bytes, privacy_bytes)?;
    let wide = app_local_data_dir
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut available_bytes = 0_u64;
    let succeeded = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available_bytes,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(V031UpgradeSourceError::CapacityUnavailable);
    }
    if available_bytes < required_bytes {
        return Err(V031UpgradeSourceError::InsufficientCapacity);
    }
    let sha256 = capacity_proof(user_bytes, privacy_bytes, required_bytes);
    Ok(V031BackupCapacityEvidence {
        user_bytes,
        privacy_bytes,
        required_bytes,
        available_bytes,
        sha256,
    })
}

pub(crate) fn run_v031_local_protection_preflight() -> Result<String, V031UpgradeSourceError> {
    let mut protected = privacy::protect_local(LOCAL_PROTECTION_PREFLIGHT_CHALLENGE)
        .map_err(|_| V031UpgradeSourceError::CryptoUnavailable)?;
    let mut opened = privacy::unprotect_local(&protected)
        .map_err(|_| V031UpgradeSourceError::CryptoUnavailable)?;
    let matches = opened == LOCAL_PROTECTION_PREFLIGHT_CHALLENGE;
    protected.zeroize();
    opened.zeroize();
    if !matches {
        return Err(V031UpgradeSourceError::CryptoUnavailable);
    }
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_PROTECTION_PREFLIGHT_DOMAIN);
    hasher.update(LOCAL_PROTECTION_PREFLIGHT_CHALLENGE);
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn v031_target_absence_policy_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(TARGET_ABSENCE_POLICY_DOMAIN);
    for role in crate::v031_upgrade_r2::ApprovedMcpCredentialRole::ALL {
        hasher.update([0x10]);
        hasher.update((role.target().len() as u64).to_be_bytes());
        hasher.update(role.target().as_bytes());
    }
    for path in crate::v031_upgrade_r2::TargetAbsencePath::ALL {
        hasher.update([0x20]);
        hasher.update((path.relative_path().len() as u64).to_be_bytes());
        hasher.update(path.relative_path().as_bytes());
    }
    // The filesystem verifier also scans these two fixed sibling namespaces
    // and rejects every unknown near-marker before target writes.
    for scope in [b"app_root".as_slice(), b"privacy_root".as_slice()] {
        hasher.update([0x30]);
        hasher.update((scope.len() as u64).to_be_bytes());
        hasher.update(scope);
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn generate_v031_upgrade_identity(
    proof: &V031SourceProfileProof,
) -> Result<V031GeneratedUpgradeIdentity, V031UpgradeSourceError> {
    for hash in [
        &proof.sha256,
        &proof.user_logical_sha256,
        &proof.privacy_logical_sha256,
    ] {
        if !is_lower_hash(hash) {
            return Err(V031UpgradeSourceError::InvalidProof);
        }
    }

    let mut binding_random = [0_u8; 32];
    fill_random(&mut binding_random)?;
    let mut binding_hasher = Sha256::new();
    binding_hasher.update(BINDING_DOMAIN);
    binding_hasher.update(binding_random);
    let binding_digest = format!("{:x}", binding_hasher.finalize());
    binding_random.zeroize();
    let envelope_binding_id = format!("ws_{}", &binding_digest[..32]);

    let mut lineage_random = [0_u8; 32];
    fill_random(&mut lineage_random)?;
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(LINEAGE_DOMAIN);
    append_field(&mut preimage, 0x01, &lineage_random)?;
    append_field(&mut preimage, 0x02, V031_MIGRATION_ID.as_bytes())?;
    append_field(&mut preimage, 0x03, &decode_hash(&proof.sha256)?)?;
    append_field(
        &mut preimage,
        0x04,
        &decode_hash(&proof.user_logical_sha256)?,
    )?;
    append_field(
        &mut preimage,
        0x05,
        &decode_hash(&proof.privacy_logical_sha256)?,
    )?;
    append_field(&mut preimage, 0x06, envelope_binding_id.as_bytes())?;
    let lineage_id = sha256_hex(&preimage);
    lineage_random.zeroize();
    preimage.zeroize();
    Ok(V031GeneratedUpgradeIdentity {
        envelope_binding_id,
        lineage_id,
    })
}

fn validate_source_contract(
    user: &UserMigrationSourceProof,
    privacy: &ValidatedPrivacyV1Source,
    target_absence: &V031TargetAbsenceEvidence,
    capacity: &V031BackupCapacityEvidence,
) -> Result<(), V031UpgradeSourceError> {
    let expected_required = required_v031_backup_capacity_bytes(
        user.database_file.length,
        privacy.database_file.length,
    )?;
    let expected_capacity_sha256 = capacity_proof(
        capacity.user_bytes,
        capacity.privacy_bytes,
        capacity.required_bytes,
    );
    if user.schema != ValidatedUserSourceSchema::V031V10
        || user.schema_manifest_sha256 != V031_USER_SCHEMA_MANIFEST_SHA256
        || user.tables.len() != 27
        || privacy.schema_version != 1
        || privacy.schema_object_count != PRIVACY_V1_SCHEMA_OBJECT_COUNT
        || privacy.normalized_sqlite_master_sha256 != V031_PRIVACY_SCHEMA_MANIFEST_SHA256
        || privacy.logical_manifest.tables.len() != 5
        || privacy.business_manifest.tables.len() != 4
        || target_absence.policy_sha256 != v031_target_absence_policy_sha256()
        || target_absence.filesystem_checks != 22
        || target_absence.credential_checks != 4
        || capacity.user_bytes != user.database_file.length
        || capacity.privacy_bytes != privacy.database_file.length
        || capacity.required_bytes != expected_required
        || capacity.available_bytes < capacity.required_bytes
        || capacity.sha256 != expected_capacity_sha256
    {
        return Err(V031UpgradeSourceError::InvalidProof);
    }
    Ok(())
}

fn user_evidence(proof: &UserMigrationSourceProof) -> UserEvidenceV1 {
    UserEvidenceV1 {
        schema_version: 10,
        schema_manifest_sha256: proof.schema_manifest_sha256.clone(),
        database_file: user_file_evidence(&proof.database_file),
        wal: proof.wal.as_ref().map(user_file_evidence),
        shm: proof.shm.as_ref().map(user_file_evidence),
        journal: proof.journal.as_ref().map(user_file_evidence),
        logical_manifest_sha256: proof.logical_database_manifest_sha256.clone(),
        business_manifest_sha256: proof.business_manifest_sha256.clone(),
        business_primary_key_manifest_sha256: proof.business_primary_key_manifest_sha256.clone(),
        business_row_manifest_sha256: proof.business_row_manifest_sha256.clone(),
        tables: proof.tables.iter().map(user_table_evidence).collect(),
        total_rows: proof.total_rows,
        data_version: proof.data_version,
    }
}

fn privacy_evidence(proof: &ValidatedPrivacyV1Source) -> PrivacyEvidenceV1 {
    PrivacyEvidenceV1 {
        schema_version: proof.schema_version,
        schema_manifest_sha256: proof.normalized_sqlite_master_sha256,
        database_file: privacy_file_evidence(&proof.database_file),
        wal: proof.wal.as_ref().map(privacy_file_evidence),
        shm: proof.shm.as_ref().map(privacy_file_evidence),
        journal: proof.journal.as_ref().map(privacy_file_evidence),
        logical_manifest_sha256: proof.logical_manifest.sha256.clone(),
        business_manifest_sha256: proof.business_manifest.sha256.clone(),
        business_primary_key_manifest_sha256: proof.business_manifest.primary_key_sha256.clone(),
        business_row_manifest_sha256: proof.business_manifest.row_sha256.clone(),
        logical_tables: proof
            .logical_manifest
            .tables
            .iter()
            .map(privacy_logical_table_evidence)
            .collect(),
        business_tables: proof
            .business_manifest
            .tables
            .iter()
            .map(privacy_business_table_evidence)
            .collect(),
        total_rows: proof.logical_manifest.total_row_count,
        protected_payloads: proof.protected_review_payload_count,
        data_version: proof.data_version,
    }
}

fn user_file_evidence(proof: &UserMigrationSourceFileProof) -> FileEvidenceV1 {
    FileEvidenceV1 {
        identity_sha256: proof.identity_sha256.clone(),
        length: proof.length,
        modified_unix_nanos: proof.modified_unix_nanos,
        sha256: proof.sha256.clone(),
    }
}

fn privacy_file_evidence(proof: &privacy::PrivacyV1SourceFileProof) -> FileEvidenceV1 {
    FileEvidenceV1 {
        identity_sha256: proof.identity_sha256.clone(),
        length: proof.length,
        modified_unix_nanos: proof.modified_unix_nanos,
        sha256: proof.sha256.clone(),
    }
}

fn user_table_evidence(table: &UserMigrationTableProof) -> UserTableEvidenceV1 {
    UserTableEvidenceV1 {
        table: table.table.clone(),
        rows: table.rows,
        logical_manifest_sha256: table.logical_manifest_sha256.clone(),
        business_manifest_sha256: table.business_manifest_sha256.clone(),
        business_primary_key_manifest_sha256: table.business_primary_key_manifest_sha256.clone(),
        business_row_manifest_sha256: table.business_row_manifest_sha256.clone(),
    }
}

fn privacy_logical_table_evidence(table: &PrivacyV1LogicalTableManifest) -> PrivacyTableEvidenceV1 {
    PrivacyTableEvidenceV1 {
        table: table.table_name.clone(),
        rows: table.row_count,
        manifest_sha256: table.sha256.clone(),
        primary_key_sha256: None,
        row_sha256: None,
    }
}

fn privacy_business_table_evidence(
    table: &PrivacyV1BusinessTableManifest,
) -> PrivacyTableEvidenceV1 {
    PrivacyTableEvidenceV1 {
        table: table.table_name.clone(),
        rows: table.row_count,
        manifest_sha256: table.sha256.clone(),
        primary_key_sha256: Some(table.primary_key_sha256.clone()),
        row_sha256: Some(table.row_sha256.clone()),
    }
}

fn authenticated_absent_proof() -> String {
    let mut hasher = Sha256::new();
    hasher.update(ABSENT_PROOF_DOMAIN);
    for (tag, sentinel) in [
        (0x01, V031_VAULT_AUTHENTICATED_ABSENT_SENTINEL),
        (0x02, V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL),
        (0x03, V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL),
    ] {
        hasher.update([tag]);
        hasher.update((sentinel.len() as u64).to_be_bytes());
        hasher.update(sentinel);
    }
    format!("{:x}", hasher.finalize())
}

fn capacity_proof(user_bytes: u64, privacy_bytes: u64, required_bytes: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CAPACITY_PROOF_DOMAIN);
    hasher.update(user_bytes.to_be_bytes());
    hasher.update(privacy_bytes.to_be_bytes());
    hasher.update(required_bytes.to_be_bytes());
    // The opaque live evidence still proves available >= required. The
    // transient available-byte value is intentionally not persisted so an
    // authenticated receipt-zero can be revalidated after free space changes.
    hasher.update([0x01]);
    format!("{:x}", hasher.finalize())
}

fn fill_random(output: &mut [u8]) -> Result<(), V031UpgradeSourceError> {
    let length = u32::try_from(output.len()).map_err(|_| V031UpgradeSourceError::CountOverflow)?;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            output.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || output.iter().all(|byte| *byte == 0) {
        output.zeroize();
        return Err(V031UpgradeSourceError::CryptoUnavailable);
    }
    Ok(())
}

fn append_field(output: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), V031UpgradeSourceError> {
    let length = u64::try_from(value.len()).map_err(|_| V031UpgradeSourceError::CountOverflow)?;
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_hash(value: &str) -> Result<[u8; 32], V031UpgradeSourceError> {
    if !is_lower_hash(value) {
        return Err(V031UpgradeSourceError::InvalidProof);
    }
    let mut decoded = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, V031UpgradeSourceError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(V031UpgradeSourceError::InvalidProof),
    }
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_user_proof() -> UserMigrationSourceProof {
        UserMigrationSourceProof {
            schema: ValidatedUserSourceSchema::V031V10,
            database_file: UserMigrationSourceFileProof {
                identity_sha256: "10".repeat(32),
                length: 4096,
                modified_unix_nanos: None,
                sha256: "11".repeat(32),
            },
            wal: None,
            shm: None,
            journal: None,
            schema_manifest_sha256: V031_USER_SCHEMA_MANIFEST_SHA256.to_owned(),
            logical_database_manifest_sha256: "12".repeat(32),
            business_manifest_sha256: "13".repeat(32),
            business_primary_key_manifest_sha256: "14".repeat(32),
            business_row_manifest_sha256: "15".repeat(32),
            tables: (0..27)
                .map(|index| UserMigrationTableProof {
                    table: format!("table_{index:02}"),
                    rows: index,
                    logical_manifest_sha256: "16".repeat(32),
                    business_manifest_sha256: None,
                    business_primary_key_manifest_sha256: None,
                    business_row_manifest_sha256: None,
                })
                .collect(),
            total_rows: 351,
            data_version: 1,
        }
    }

    fn recovery_privacy_proof() -> ValidatedPrivacyV1Source {
        ValidatedPrivacyV1Source {
            schema_version: 1,
            schema_object_count: PRIVACY_V1_SCHEMA_OBJECT_COUNT,
            protected_review_payload_count: 3,
            normalized_sqlite_master_sha256: V031_PRIVACY_SCHEMA_MANIFEST_SHA256,
            database_file: privacy::PrivacyV1SourceFileProof {
                identity_sha256: "20".repeat(32),
                length: 4096,
                modified_unix_nanos: None,
                sha256: "21".repeat(32),
            },
            wal: None,
            shm: None,
            journal: None,
            logical_manifest: privacy::PrivacyV1LogicalManifest {
                sha256: "22".repeat(32),
                total_row_count: 7,
                tables: Vec::new(),
            },
            business_manifest: privacy::PrivacyV1BusinessManifest {
                sha256: "23".repeat(32),
                primary_key_sha256: "24".repeat(32),
                row_sha256: "25".repeat(32),
                total_row_count: 7,
                tables: Vec::new(),
            },
            data_version: 1,
        }
    }

    fn recovery_identity(
        user: &UserMigrationSourceProof,
        privacy: &ValidatedPrivacyV1Source,
    ) -> V031OriginalRollbackIdentityV2 {
        V031OriginalRollbackIdentityV2 {
            schema_version:
                privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_IDENTITY_SCHEMA_VERSION
                    .to_owned(),
            format_version: privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_FORMAT_VERSION,
            migration_id: privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_MIGRATION_ID
                .to_owned(),
            creator_app_version:
                privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION.to_owned(),
            source_profile: privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE
                .to_owned(),
            source_profile_proof_sha256: "30".repeat(32),
            source_user_physical_file_set_sha256: "26".repeat(32),
            source_privacy_physical_file_set_sha256: "27".repeat(32),
            source_user_logical_manifest_sha256: user.logical_database_manifest_sha256.clone(),
            source_user_business_manifest_sha256: user.business_manifest_sha256.clone(),
            source_privacy_logical_manifest_sha256: privacy.logical_manifest.sha256.clone(),
            source_privacy_business_manifest_sha256: privacy.business_manifest.sha256.clone(),
            envelope_binding_id: "ws_0123456789abcdef0123456789abcdef".to_owned(),
            lineage_id: "31".repeat(32),
            created_at_unix: 1,
            expires_at_unix: privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX,
            bundle_file_name:
                privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME.to_owned(),
            bundle_bytes: 1,
            bundle_sha256: "32".repeat(32),
            wrapped_data_key_sha256: "33".repeat(32),
            chunk_bytes: privacy::original_rollback_v2::V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32,
            total_chunk_count: 5,
            slots: Vec::new(),
        }
    }

    #[test]
    fn authenticated_original_v2_reconstructs_only_the_bound_source_summary() {
        let user = recovery_user_proof();
        let privacy = recovery_privacy_proof();
        let identity = recovery_identity(&user, &privacy);

        let recovered =
            recover_v031_source_profile_from_authenticated_original_v2(&identity, &user, &privacy)
                .expect("authenticated source summary");
        assert_eq!(recovered.sha256(), identity.source_profile_proof_sha256);
        assert_eq!(
            recovered.user_logical_sha256(),
            identity.source_user_logical_manifest_sha256
        );
        assert_eq!(
            recovered.privacy_business_sha256(),
            identity.source_privacy_business_manifest_sha256
        );
        assert_eq!(recovered.user_total_rows(), 351);
        assert_eq!(recovered.privacy_total_rows(), 7);
        assert_eq!(recovered.privacy_protected_payloads(), 3);
        assert_eq!(recovered.target_absence_checks(), 26);

        let mut wrong_identity = identity.clone();
        wrong_identity.source_user_business_manifest_sha256 = "34".repeat(32);
        assert_eq!(
            recover_v031_source_profile_from_authenticated_original_v2(
                &wrong_identity,
                &user,
                &privacy,
            ),
            Err(V031UpgradeSourceError::InvalidProof)
        );

        let mut current_user = user;
        current_user.schema = ValidatedUserSourceSchema::CurrentV11;
        assert_eq!(
            recover_v031_source_profile_from_authenticated_original_v2(
                &identity,
                &current_user,
                &privacy,
            ),
            Err(V031UpgradeSourceError::InvalidProof)
        );
    }

    #[test]
    fn lineage_field_encoding_and_hash_decoder_are_strict() {
        let hash = "ab".repeat(32);
        assert_eq!(decode_hash(&hash).unwrap(), [0xab; 32]);
        assert_eq!(
            decode_hash(&"AB".repeat(32)),
            Err(V031UpgradeSourceError::InvalidProof)
        );
        assert_eq!(
            decode_hash("abc"),
            Err(V031UpgradeSourceError::InvalidProof)
        );

        let mut field = Vec::new();
        append_field(&mut field, 0x06, b"ws_fixed").unwrap();
        assert_eq!(field[0], 0x06);
        assert_eq!(&field[1..9], &8_u64.to_be_bytes());
        assert_eq!(&field[9..], b"ws_fixed");
    }

    #[test]
    fn absent_and_capacity_proofs_are_domain_separated_and_stable() {
        assert_eq!(authenticated_absent_proof(), authenticated_absent_proof());
        let first = capacity_proof(4096, 8192, 67_158_016);
        assert_ne!(authenticated_absent_proof(), first);
        assert_ne!(
            capacity_proof(4096, 8192, 67_158_016),
            capacity_proof(8192, 4096, 67_158_016)
        );
    }

    #[test]
    fn live_capacity_evidence_checks_observed_space_and_emits_a_stable_proof() {
        let directory = tempfile::tempdir().expect("capacity test directory");
        let evidence = verify_v031_backup_capacity(directory.path(), 4096, 8192)
            .expect("test volume has the bounded migration capacity");
        assert_eq!(evidence.user_bytes, 4096);
        assert_eq!(evidence.privacy_bytes, 8192);
        assert!(evidence.available_bytes >= evidence.required_bytes);
        assert_eq!(
            evidence.sha256,
            capacity_proof(
                evidence.user_bytes,
                evidence.privacy_bytes,
                evidence.required_bytes,
            )
        );
    }
}
