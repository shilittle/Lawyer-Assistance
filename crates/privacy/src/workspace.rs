#![allow(unsafe_code)]

//! Immutable approved-material workspace with recoverable publication transactions.
//!
//! This first implementation is explicitly user-boundary-only. Its HMAC verifier is not a
//! substitute for the planned independent Broker signing identity.

use crate::{
    normalize_sensitive_text, scan_residual, sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, ApprovedEgressGuardV1,
        ApprovedEgressTermKindV1, ApprovedMaterialManifestV1, ApprovedMaterialRefV1,
        BlindEgressFingerprintV1, CaseId, MaterialId, PublicationId, Sha256Hex,
        SignedApprovedEgressGuardV1, SignedApprovedMaterialManifestV1, WorkspaceInstanceId,
        WorkspaceIsolationLevel, APPROVED_EGRESS_GUARD_VERSION,
        APPROVED_EGRESS_NORMALIZATION_VERSION, MAX_APPROVED_EGRESS_FINGERPRINTS,
        MAX_APPROVED_EGRESS_TERM_CHAR_LENGTH,
    },
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
};
use unicode_normalization::UnicodeNormalization;

pub const WORKSPACE_SCHEMA_VERSION: u32 = 1;
pub const USER_BOUNDARY_SIGNING_ALGORITHM: &str = "hmac-sha256-user-boundary-v1";
pub const MAX_APPROVED_CONTENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_EGRESS_GUARD_BYTES: usize = 4 * 1024 * 1024;
pub const APPROVED_WORKSPACE_DESTINATION_SCOPE: &str = "approved_case_workspace";
pub const APPROVED_MATERIAL_READ_PURPOSE: &str = "mcp.case_read_approved_material.v1";
const SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/approved-material-manifest/v1\0";
const EGRESS_GUARD_SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/approved-egress-guard/v1\0";
const EGRESS_GUARD_FINGERPRINT_DOMAIN: &[u8] = b"LawyerAssistance/approved-egress-fingerprint/v1\0";
const BUNDLE_COMMIT_VERSION: &str = "approved-generation-commit-v2";
const OPERATION_LOCK_FILE_NAME: &str = ".approved-workspace-operation.lock";
#[cfg(windows)]
const OPERATION_LOCK_ATTEMPTS: usize = 2_000;
#[cfg(windows)]
const OPERATION_LOCK_RETRY_MILLIS: u64 = 5;

/// Borrowed raw values used only while constructing a keyed guard. This type intentionally does
/// not implement `Serialize`, `Clone`, or ordinary `Debug`.
#[derive(Default)]
pub struct ApprovedEgressGuardInputV1<'a> {
    pub case_dictionary_terms: &'a [&'a str],
    pub source_terms: &'a [&'a str],
    pub raw_canary_terms: &'a [&'a str],
}

impl ApprovedEgressGuardInputV1<'_> {
    pub const fn empty() -> Self {
        Self {
            case_dictionary_terms: &[],
            source_terms: &[],
            raw_canary_terms: &[],
        }
    }
}

impl fmt::Debug for ApprovedEgressGuardInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedEgressGuardInputV1")
            .field(
                "case_dictionary_term_count",
                &self.case_dictionary_terms.len(),
            )
            .field("source_term_count", &self.source_terms.len())
            .field("raw_canary_term_count", &self.raw_canary_terms.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceError {
    PlatformUnavailable,
    InvalidRoot,
    UnsafeFilesystem,
    InvalidInput,
    ContentTooLarge,
    ManifestInvalid,
    SignatureInvalid,
    ContentMismatch,
    ResidualSensitiveContent,
    PublicationNotAvailable,
    PublicationExpired,
    PublicationRevoked,
    DestinationMismatch,
    PurposeMismatch,
    AlreadyExists,
    DatabaseFailed,
    IoFailed,
    RecoveryFailed,
}

impl WorkspaceError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnavailable => "workspace_platform_unavailable",
            Self::InvalidRoot => "workspace_invalid_root",
            Self::UnsafeFilesystem => "workspace_unsafe_filesystem",
            Self::InvalidInput => "workspace_invalid_input",
            Self::ContentTooLarge => "workspace_content_too_large",
            Self::ManifestInvalid => "workspace_manifest_invalid",
            Self::SignatureInvalid => "workspace_signature_invalid",
            Self::ContentMismatch => "workspace_content_mismatch",
            Self::ResidualSensitiveContent => "workspace_residual_sensitive_content",
            Self::PublicationNotAvailable => "approved_material_not_available",
            Self::PublicationExpired => "publication_expired",
            Self::PublicationRevoked => "publication_revoked",
            Self::DestinationMismatch => "publication_destination_mismatch",
            Self::PurposeMismatch => "publication_purpose_mismatch",
            Self::AlreadyExists => "workspace_generation_already_exists",
            Self::DatabaseFailed => "workspace_database_failed",
            Self::IoFailed => "workspace_io_failed",
            Self::RecoveryFailed => "workspace_recovery_failed",
        }
    }
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for WorkspaceError {}

pub struct ManifestSigningKey {
    key: [u8; 32],
    key_id: String,
    key_version: u64,
}

impl ManifestSigningKey {
    pub fn generate(key_version: u64) -> Result<Self, WorkspaceError> {
        if key_version == 0 {
            return Err(WorkspaceError::InvalidInput);
        }
        let mut key = [0_u8; 32];
        platform::random(&mut key)?;
        let key_id = format!("hmackey_{}", &sha256_hex(&key)[..24]);
        Ok(Self {
            key,
            key_id,
            key_version,
        })
    }

    pub fn from_bytes(key: [u8; 32], key_version: u64) -> Result<Self, WorkspaceError> {
        if key_version == 0 {
            return Err(WorkspaceError::InvalidInput);
        }
        let key_id = format!("hmackey_{}", &sha256_hex(&key)[..24]);
        Ok(Self {
            key,
            key_id,
            key_version,
        })
    }

    pub fn verification_key(&self) -> ManifestVerificationKey {
        ManifestVerificationKey {
            key: self.key,
            key_id: self.key_id.clone(),
            key_version: self.key_version,
        }
    }

    pub(crate) fn sign_domain(&self, domain: &[u8], canonical: &[u8]) -> String {
        hmac_sha256_hex(&self.key, domain, canonical)
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) const fn key_version(&self) -> u64 {
        self.key_version
    }

    fn sign(
        &self,
        claims: ApprovedMaterialManifestV1,
    ) -> Result<SignedApprovedMaterialManifestV1, WorkspaceError> {
        claims
            .validate()
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        if claims.workspace_isolation_level != WorkspaceIsolationLevel::UserBoundaryOnly {
            return Err(WorkspaceError::ManifestInvalid);
        }
        let canonical = canonical_json_v1(&claims).map_err(|_| WorkspaceError::ManifestInvalid)?;
        let canonical_claims_sha256 = Sha256Hex::parse(sha256_hex(&canonical))
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let signature = hmac_sha256_hex(&self.key, SIGNING_DOMAIN, &canonical);
        Ok(SignedApprovedMaterialManifestV1 {
            claims,
            canonical_claims_sha256,
            signing_algorithm: USER_BOUNDARY_SIGNING_ALGORITHM.to_owned(),
            signing_key_id: self.key_id.clone(),
            signing_key_version: self.key_version,
            signature,
        })
    }

    fn sign_egress_guard(
        &self,
        claims: ApprovedEgressGuardV1,
    ) -> Result<SignedApprovedEgressGuardV1, WorkspaceError> {
        claims
            .validate()
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let canonical = canonical_json_v1(&claims).map_err(|_| WorkspaceError::ManifestInvalid)?;
        Ok(SignedApprovedEgressGuardV1 {
            canonical_claims_sha256: Sha256Hex::parse(sha256_hex(&canonical))
                .map_err(|_| WorkspaceError::ManifestInvalid)?,
            signature: self.sign_domain(EGRESS_GUARD_SIGNING_DOMAIN, &canonical),
            claims,
            signing_algorithm: USER_BOUNDARY_SIGNING_ALGORITHM.to_owned(),
            signing_key_id: self.key_id.clone(),
            signing_key_version: self.key_version,
        })
    }
}

impl fmt::Debug for ManifestSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestSigningKey")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ManifestSigningKey {
    fn drop(&mut self) {
        zeroize(&mut self.key);
    }
}

pub struct ManifestVerificationKey {
    key: [u8; 32],
    key_id: String,
    key_version: u64,
}

impl ManifestVerificationKey {
    pub fn verify(&self, signed: &SignedApprovedMaterialManifestV1) -> Result<(), WorkspaceError> {
        signed
            .validate_structure()
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        if signed.signing_algorithm != USER_BOUNDARY_SIGNING_ALGORITHM
            || signed.signing_key_id != self.key_id
            || signed.signing_key_version != self.key_version
            || signed.claims.workspace_isolation_level != WorkspaceIsolationLevel::UserBoundaryOnly
        {
            return Err(WorkspaceError::SignatureInvalid);
        }
        let canonical =
            canonical_json_v1(&signed.claims).map_err(|_| WorkspaceError::ManifestInvalid)?;
        let expected = hmac_sha256_hex(&self.key, SIGNING_DOMAIN, &canonical);
        if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
            return Err(WorkspaceError::SignatureInvalid);
        }
        Ok(())
    }

    pub(crate) fn verify_domain(
        &self,
        domain: &[u8],
        canonical: &[u8],
        signing_algorithm: &str,
        signing_key_id: &str,
        signing_key_version: u64,
        signature: &str,
    ) -> Result<(), WorkspaceError> {
        if signing_algorithm != USER_BOUNDARY_SIGNING_ALGORITHM
            || signing_key_id != self.key_id
            || signing_key_version != self.key_version
        {
            return Err(WorkspaceError::SignatureInvalid);
        }
        let expected = hmac_sha256_hex(&self.key, domain, canonical);
        if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(WorkspaceError::SignatureInvalid);
        }
        Ok(())
    }

    fn verify_egress_guard(
        &self,
        signed: &SignedApprovedEgressGuardV1,
    ) -> Result<(), WorkspaceError> {
        signed
            .validate_structure()
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let canonical =
            canonical_json_v1(&signed.claims).map_err(|_| WorkspaceError::ManifestInvalid)?;
        self.verify_domain(
            EGRESS_GUARD_SIGNING_DOMAIN,
            &canonical,
            &signed.signing_algorithm,
            &signed.signing_key_id,
            signed.signing_key_version,
            &signed.signature,
        )
    }
}

impl fmt::Debug for ManifestVerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestVerificationKey")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ManifestVerificationKey {
    fn drop(&mut self) {
        zeroize(&mut self.key);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BundleCommitV1 {
    schema_version: String,
    publication_id: PublicationId,
    manifest_sha256: Sha256Hex,
    egress_guard_sha256: Sha256Hex,
    content_sha256: Sha256Hex,
    content_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedMaterialSummaryV1 {
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub content_sha256: Sha256Hex,
    pub manifest_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPublicationHistoryV1 {
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub manifest_sha256: Sha256Hex,
    pub content_sha256: Sha256Hex,
    pub created_at_unix: u64,
    pub committed_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    pub revocation_epoch: u64,
}

pub struct WorkspacePublisher {
    root: ValidatedWorkspaceRoot,
    signer: ManifestSigningKey,
}

impl WorkspacePublisher {
    pub fn initialize(
        root: impl AsRef<Path>,
        signer: ManifestSigningKey,
    ) -> Result<Self, WorkspaceError> {
        let root = ValidatedWorkspaceRoot::initialize(root.as_ref())?;
        initialize_database(&root)?;
        Ok(Self { root, signer })
    }

    pub fn publish(
        &self,
        claims: ApprovedMaterialManifestV1,
        content: &[u8],
    ) -> Result<PublishedMaterialSummaryV1, WorkspaceError> {
        self.publish_with_egress_guard(claims, content, ApprovedEgressGuardInputV1::empty())
    }

    pub fn publish_with_egress_guard(
        &self,
        claims: ApprovedMaterialManifestV1,
        content: &[u8],
        guard_input: ApprovedEgressGuardInputV1<'_>,
    ) -> Result<PublishedMaterialSummaryV1, WorkspaceError> {
        self.publish_with_egress_guard_and_lifecycle_binding(claims, content, guard_input, None)
    }

    pub fn publish_with_egress_guard_and_lifecycle_binding(
        &self,
        claims: ApprovedMaterialManifestV1,
        content: &[u8],
        guard_input: ApprovedEgressGuardInputV1<'_>,
        lifecycle_binding_id: Option<&str>,
    ) -> Result<PublishedMaterialSummaryV1, WorkspaceError> {
        if lifecycle_binding_id.is_some_and(|value| !valid_lifecycle_binding_id(value)) {
            return Err(WorkspaceError::InvalidInput);
        }
        if content.is_empty() || content.len() > MAX_APPROVED_CONTENT_BYTES {
            return Err(if content.is_empty() {
                WorkspaceError::InvalidInput
            } else {
                WorkspaceError::ContentTooLarge
            });
        }
        let _operation = acquire_workspace_operation_guard(&self.root)?;
        let residual =
            scan_residual(content).map_err(|_| WorkspaceError::ResidualSensitiveContent)?;
        if !residual.passed {
            return Err(WorkspaceError::ResidualSensitiveContent);
        }
        claims
            .validate()
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let content_bytes =
            u64::try_from(content.len()).map_err(|_| WorkspaceError::ContentTooLarge)?;
        if claims.content_bytes != content_bytes
            || claims.content_sha256.as_str() != sha256_hex(content)
        {
            return Err(WorkspaceError::ContentMismatch);
        }

        let signed = self.signer.sign(claims)?;
        let signed_guard = build_egress_guard(&self.signer, &signed.claims, guard_input)?;
        scan_case_specific_with_guard(&self.signer.key, &signed_guard.claims, content)?;
        let manifest_bytes =
            canonical_json_v1(&signed).map_err(|_| WorkspaceError::ManifestInvalid)?;
        if manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(WorkspaceError::ManifestInvalid);
        }
        let guard_bytes =
            canonical_json_v1(&signed_guard).map_err(|_| WorkspaceError::ManifestInvalid)?;
        if guard_bytes.len() > MAX_EGRESS_GUARD_BYTES {
            return Err(WorkspaceError::ManifestInvalid);
        }
        let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let egress_guard_sha256 = Sha256Hex::parse(sha256_hex(&guard_bytes))
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let document_version_sql = sql_i64(signed.claims.document_version)?;
        let issued_at_sql = sql_i64(signed.claims.issued_at_unix)?;
        let commit = BundleCommitV1 {
            schema_version: BUNDLE_COMMIT_VERSION.to_owned(),
            publication_id: signed.claims.publication_id.clone(),
            manifest_sha256: manifest_sha256.clone(),
            egress_guard_sha256,
            content_sha256: signed.claims.content_sha256.clone(),
            content_bytes,
        };
        let commit_bytes =
            canonical_json_v1(&commit).map_err(|_| WorkspaceError::ManifestInvalid)?;
        let transaction_id = generate_prefixed_id("tx_")?;

        let staging = self.root.staging.join(&transaction_id);
        let final_parent = self
            .root
            .cases
            .join(signed.claims.case_id.as_str())
            .join("approved");
        let final_directory = final_parent.join(signed.claims.publication_id.as_str());
        if final_directory.exists() {
            return Err(WorkspaceError::AlreadyExists);
        }
        fs::create_dir(&staging).map_err(|_| WorkspaceError::IoFailed)?;
        platform::mark_not_content_indexed(&staging)?;

        let db = open_database(&self.root)?;
        db.execute(
            "INSERT INTO publication_journal(
                transaction_id,case_id,material_id,document_version,publication_id,
                manifest_sha256,content_sha256,state,created_at_unix,lifecycle_binding_id
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,'prepared',?8,?9)",
            params![
                transaction_id,
                signed.claims.case_id.as_str(),
                signed.claims.material_id.as_str(),
                document_version_sql,
                signed.claims.publication_id.as_str(),
                manifest_sha256.as_str(),
                signed.claims.content_sha256.as_str(),
                issued_at_sql,
                lifecycle_binding_id
            ],
        )
        .map_err(|_| WorkspaceError::DatabaseFailed)?;

        let stage_result = (|| {
            write_new_file(&staging.join("content.bin"), content)?;
            write_new_file(&staging.join("manifest.json"), &manifest_bytes)?;
            write_new_file(&staging.join("egress-guard.json"), &guard_bytes)?;
            write_new_file(&staging.join("commit.json"), &commit_bytes)?;
            fs::create_dir_all(&final_parent).map_err(|_| WorkspaceError::IoFailed)?;
            platform::mark_not_content_indexed(&final_parent)?;
            fs::rename(&staging, &final_directory).map_err(|_| WorkspaceError::IoFailed)?;
            Ok::<(), WorkspaceError>(())
        })();
        if let Err(error) = stage_result {
            let _ = quarantine_path(&self.root, &transaction_id, &staging);
            let _ = db.execute(
                "UPDATE publication_journal SET state='quarantined' WHERE transaction_id=?1",
                params![transaction_id],
            );
            return Err(error);
        }

        db.execute(
            "UPDATE publication_journal SET state='committed',committed_at_unix=?2
             WHERE transaction_id=?1 AND state='prepared'",
            params![transaction_id, issued_at_sql],
        )
        .map_err(|_| WorkspaceError::DatabaseFailed)?;

        Ok(PublishedMaterialSummaryV1 {
            case_id: signed.claims.case_id,
            material_id: signed.claims.material_id,
            document_version: signed.claims.document_version,
            publication_id: signed.claims.publication_id,
            content_sha256: signed.claims.content_sha256,
            manifest_sha256,
        })
    }

    pub fn next_document_version(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
    ) -> Result<u64, WorkspaceError> {
        let db = open_database(&self.root)?;
        let current = db
            .query_row(
                "SELECT MAX(document_version) FROM publication_journal
                 WHERE case_id=?1 AND material_id=?2",
                params![case_id.as_str(), material_id.as_str()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .unwrap_or(0);
        current.checked_add(1).ok_or(WorkspaceError::InvalidInput)
    }

    pub fn recover(
        &self,
        verifier: &ManifestVerificationKey,
        now_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        let _operation = acquire_workspace_operation_guard(&self.root)?;
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT transaction_id,case_id,publication_id
                 FROM publication_journal WHERE state='prepared' ORDER BY transaction_id",
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        drop(statement);

        let mut recovered = 0_u64;
        for (transaction_id, case_id, publication_id) in rows {
            let final_directory = self
                .root
                .cases
                .join(&case_id)
                .join("approved")
                .join(&publication_id);
            if final_directory.is_dir()
                && verify_bundle(&self.root, &final_directory, verifier, now_unix, None, None)
                    .is_ok()
            {
                db.execute(
                    "UPDATE publication_journal SET state='committed',committed_at_unix=?2
                     WHERE transaction_id=?1 AND state='prepared'",
                    params![transaction_id, sql_i64(now_unix)?],
                )
                .map_err(|_| WorkspaceError::RecoveryFailed)?;
                recovered = recovered.saturating_add(1);
                continue;
            }
            let staging = self.root.staging.join(&transaction_id);
            let _ = quarantine_path(&self.root, &transaction_id, &staging);
            db.execute(
                "UPDATE publication_journal SET state='quarantined'
                 WHERE transaction_id=?1 AND state='prepared'",
                params![transaction_id],
            )
            .map_err(|_| WorkspaceError::RecoveryFailed)?;
        }
        Ok(recovered)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCaseSummaryV1 {
    pub case_id: CaseId,
    pub approved_material_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedMaterialSummaryV1 {
    pub case_id: CaseId,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub content_media_type: String,
    pub content_sha256: Sha256Hex,
    pub manifest_sha256: Sha256Hex,
    pub expires_at_unix: u64,
}

pub struct VerifiedApprovedMaterial {
    summary: ApprovedMaterialSummaryV1,
    content: Vec<u8>,
    egress_guard: SignedApprovedEgressGuardV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePublicationRevocationV1 {
    pub newly_revoked: u64,
    pub publication_ids: BTreeSet<PublicationId>,
}

impl VerifiedApprovedMaterial {
    pub fn summary(&self) -> &ApprovedMaterialSummaryV1 {
        &self.summary
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn dictionary_revision_hash(&self) -> &Sha256Hex {
        &self.egress_guard.claims.dictionary_revision_hash
    }

    pub fn mapping_revision_hash(&self) -> &Sha256Hex {
        &self.egress_guard.claims.mapping_revision_hash
    }

    pub fn source_revision_hash(&self) -> &Sha256Hex {
        &self.egress_guard.claims.source_revision_hash
    }
}

impl fmt::Debug for VerifiedApprovedMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedApprovedMaterial")
            .field("summary", &self.summary)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

pub struct ApprovedWorkspaceService {
    root: ValidatedWorkspaceRoot,
    verifier: ManifestVerificationKey,
}

impl ApprovedWorkspaceService {
    pub fn open(
        root: impl AsRef<Path>,
        verifier: ManifestVerificationKey,
    ) -> Result<Self, WorkspaceError> {
        let root = ValidatedWorkspaceRoot::open(root.as_ref())?;
        initialize_database(&root)?;
        Ok(Self { root, verifier })
    }

    /// Opens an already initialized workspace without creating or repairing any
    /// directory, lock file, schema object, journal mode, or database row.
    ///
    /// This narrow entry point exists for pre-manager startup arbitration.  All
    /// database handles subsequently opened through this service are query-only
    /// SQLite handles, so a caller cannot accidentally turn observation into a
    /// schema migration merely by invoking an ordinary read method.
    pub fn open_read_only(
        root: impl AsRef<Path>,
        verifier: ManifestVerificationKey,
    ) -> Result<Self, WorkspaceError> {
        let root = ValidatedWorkspaceRoot::open_read_only(root.as_ref())?;
        Ok(Self { root, verifier })
    }
    pub fn acquire_operation_guard(
        &self,
    ) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
        acquire_workspace_operation_guard(&self.root)
    }

    /// Excludes every writer while permitting additional read-only handles to
    /// inspect the operation-lock file itself. R3 Safety V3 uses this narrower
    /// boundary so its exact recursive directory fingerprint can include the
    /// fixed lock file while the writer barrier remains continuously held.
    pub fn acquire_writer_exclusion_guard(
        &self,
    ) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
        acquire_workspace_writer_exclusion_guard(&self.root)
    }

    pub fn validate_operation_guard(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
    ) -> Result<(), WorkspaceError> {
        if operation.workspace_root == self.root.root && operation.allows_mutation {
            Ok(())
        } else {
            Err(WorkspaceError::InvalidRoot)
        }
    }

    pub fn validate_read_operation_guard(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
    ) -> Result<(), WorkspaceError> {
        if operation.workspace_root == self.root.root {
            Ok(())
        } else {
            Err(WorkspaceError::InvalidRoot)
        }
    }

    pub fn recover(&self, now_unix: u64) -> Result<u64, WorkspaceError> {
        let _operation = self.acquire_operation_guard()?;
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT transaction_id,case_id,publication_id
                 FROM publication_journal WHERE state='prepared' ORDER BY transaction_id",
            )
            .map_err(|_| WorkspaceError::RecoveryFailed)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| WorkspaceError::RecoveryFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::RecoveryFailed)?;
        drop(statement);
        let mut recovered = 0_u64;
        for (transaction_id, case_id, publication_id) in rows {
            let final_directory = self
                .root
                .cases
                .join(&case_id)
                .join("approved")
                .join(&publication_id);
            if final_directory.is_dir()
                && verify_bundle(
                    &self.root,
                    &final_directory,
                    &self.verifier,
                    now_unix,
                    None,
                    None,
                )
                .is_ok()
            {
                db.execute(
                    "UPDATE publication_journal SET state='committed',committed_at_unix=?2
                     WHERE transaction_id=?1 AND state='prepared'",
                    params![transaction_id, sql_i64(now_unix)?],
                )
                .map_err(|_| WorkspaceError::RecoveryFailed)?;
                recovered = recovered.saturating_add(1);
                continue;
            }
            let staging = self.root.staging.join(&transaction_id);
            let _ = quarantine_path(&self.root, &transaction_id, &staging);
            db.execute(
                "UPDATE publication_journal SET state='quarantined'
                 WHERE transaction_id=?1 AND state='prepared'",
                params![transaction_id],
            )
            .map_err(|_| WorkspaceError::RecoveryFailed)?;
        }
        Ok(recovered)
    }

    pub fn list_cases(&self, now_unix: u64) -> Result<Vec<ApprovedCaseSummaryV1>, WorkspaceError> {
        let operation = self.acquire_operation_guard()?;
        self.list_cases_locked(&operation, now_unix)
    }

    pub fn list_cases_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        now_unix: u64,
    ) -> Result<Vec<ApprovedCaseSummaryV1>, WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT DISTINCT case_id FROM publication_journal
                 WHERE state='committed' AND revoked_at_unix IS NULL ORDER BY case_id",
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let mut output = Vec::with_capacity(ids.len());
        for value in ids {
            let case_id = CaseId::parse(value).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let count = self
                .list_case_materials_locked(operation, &case_id, now_unix)?
                .len();
            if count > 0 {
                output.push(ApprovedCaseSummaryV1 {
                    case_id,
                    approved_material_count: u64::try_from(count)
                        .map_err(|_| WorkspaceError::DatabaseFailed)?,
                });
            }
        }
        Ok(output)
    }

    pub fn list_publication_history(
        &self,
        case_id: Option<&CaseId>,
    ) -> Result<Vec<ApprovedPublicationHistoryV1>, WorkspaceError> {
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT case_id,material_id,document_version,publication_id,
                        manifest_sha256,content_sha256,created_at_unix,
                        committed_at_unix,revoked_at_unix,revocation_epoch
                 FROM publication_journal
                 WHERE state='committed' AND (?1 IS NULL OR case_id=?1)
                 ORDER BY case_id,material_id,document_version,publication_id",
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let rows = statement
            .query_map([case_id.map(CaseId::as_str)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        rows.into_iter()
            .map(
                |(
                    case_id,
                    material_id,
                    document_version,
                    publication_id,
                    manifest_sha256,
                    content_sha256,
                    created_at_unix,
                    committed_at_unix,
                    revoked_at_unix,
                    revocation_epoch,
                )| {
                    Ok(ApprovedPublicationHistoryV1 {
                        case_id: CaseId::parse(case_id)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        material_id: MaterialId::parse(material_id)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        document_version: u64::try_from(document_version)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        publication_id: PublicationId::parse(publication_id)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        manifest_sha256: Sha256Hex::parse(manifest_sha256)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        content_sha256: Sha256Hex::parse(content_sha256)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        created_at_unix: u64::try_from(created_at_unix)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        committed_at_unix: u64::try_from(
                            committed_at_unix.ok_or(WorkspaceError::DatabaseFailed)?,
                        )
                        .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        revoked_at_unix: revoked_at_unix
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                        revocation_epoch: u64::try_from(revocation_epoch)
                            .map_err(|_| WorkspaceError::DatabaseFailed)?,
                    })
                },
            )
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_publication(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        publication_id: &PublicationId,
        now_unix: u64,
        expected_destination_scope: Option<&str>,
        expected_purpose: Option<&str>,
    ) -> Result<VerifiedApprovedMaterial, WorkspaceError> {
        let operation = self.acquire_operation_guard()?;
        self.read_publication_locked(
            &operation,
            case_id,
            material_id,
            publication_id,
            now_unix,
            expected_destination_scope,
            expected_purpose,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_publication_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        material_id: &MaterialId,
        publication_id: &PublicationId,
        now_unix: u64,
        expected_destination_scope: Option<&str>,
        expected_purpose: Option<&str>,
    ) -> Result<VerifiedApprovedMaterial, WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let db = open_database(&self.root)?;
        let document_version = db
            .query_row(
                "SELECT document_version FROM publication_journal
                 WHERE case_id=?1 AND material_id=?2 AND publication_id=?3
                   AND state='committed'",
                params![
                    case_id.as_str(),
                    material_id.as_str(),
                    publication_id.as_str()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .ok_or(WorkspaceError::PublicationNotAvailable)?;
        self.read_locked(
            operation,
            case_id,
            material_id,
            sql_u64(document_version)?,
            publication_id,
            now_unix,
            expected_destination_scope,
            expected_purpose,
        )
    }

    pub fn list_case_materials(
        &self,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<Vec<ApprovedMaterialSummaryV1>, WorkspaceError> {
        let operation = self.acquire_operation_guard()?;
        self.list_case_materials_locked(&operation, case_id, now_unix)
    }

    pub fn list_case_materials_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<Vec<ApprovedMaterialSummaryV1>, WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT material_id,document_version,publication_id
                 FROM publication_journal
                 WHERE case_id=?1 AND state='committed' AND revoked_at_unix IS NULL
                 ORDER BY material_id,document_version,publication_id",
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let ids = statement
            .query_map(params![case_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let mut output = Vec::with_capacity(ids.len());
        for (material_id, document_version, publication_id) in ids {
            let document_version = sql_u64(document_version)?;
            let material_id =
                MaterialId::parse(material_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let publication_id =
                PublicationId::parse(publication_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let verified = self.read_locked(
                operation,
                case_id,
                &material_id,
                document_version,
                &publication_id,
                now_unix,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            )?;
            output.push(verified.summary);
        }
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        document_version: u64,
        publication_id: &PublicationId,
        now_unix: u64,
        expected_destination_scope: Option<&str>,
        expected_purpose: Option<&str>,
    ) -> Result<VerifiedApprovedMaterial, WorkspaceError> {
        let operation = self.acquire_operation_guard()?;
        self.read_locked(
            &operation,
            case_id,
            material_id,
            document_version,
            publication_id,
            now_unix,
            expected_destination_scope,
            expected_purpose,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        material_id: &MaterialId,
        document_version: u64,
        publication_id: &PublicationId,
        now_unix: u64,
        expected_destination_scope: Option<&str>,
        expected_purpose: Option<&str>,
    ) -> Result<VerifiedApprovedMaterial, WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let document_version_sql = sql_i64(document_version)?;
        self.ensure_publication_active(case_id, material_id, document_version_sql, publication_id)?;
        let directory = self
            .root
            .cases
            .join(case_id.as_str())
            .join("approved")
            .join(publication_id.as_str());
        let bundle = verify_bundle(
            &self.root,
            &directory,
            &self.verifier,
            now_unix,
            expected_destination_scope,
            expected_purpose,
        )?;
        let signed = bundle.manifest;
        if signed.claims.case_id != *case_id
            || signed.claims.material_id != *material_id
            || signed.claims.document_version != document_version
            || signed.claims.publication_id != *publication_id
        {
            return Err(WorkspaceError::ManifestInvalid);
        }
        let verified = VerifiedApprovedMaterial {
            summary: ApprovedMaterialSummaryV1 {
                case_id: signed.claims.case_id,
                workspace_instance_id: signed.claims.workspace_instance_id,
                material_id: signed.claims.material_id,
                document_version: signed.claims.document_version,
                publication_id: signed.claims.publication_id,
                content_media_type: signed.claims.content_media_type,
                content_sha256: signed.claims.content_sha256,
                manifest_sha256: bundle.manifest_sha256,
                expires_at_unix: signed.claims.expires_at_unix,
            },
            content: bundle.content,
            egress_guard: bundle.egress_guard,
        };
        self.ensure_publication_active(case_id, material_id, document_version_sql, publication_id)?;
        Ok(verified)
    }

    /// Revalidates every referenced approved generation and scans `content` against the union of
    /// their case-bound keyed fingerprints. Revision checks use the newest committed case
    /// dictionary and newest committed mapping for each referenced material.
    pub fn scan_case_specific_content(
        &self,
        case_id: &CaseId,
        references: &[ApprovedMaterialRefV1],
        content: &[u8],
        now_unix: u64,
    ) -> Result<(), WorkspaceError> {
        let operation = self.acquire_operation_guard()?;
        self.scan_case_specific_content_locked(&operation, case_id, references, content, now_unix)
    }

    pub fn scan_case_specific_content_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        references: &[ApprovedMaterialRefV1],
        content: &[u8],
        now_unix: u64,
    ) -> Result<(), WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        if references.is_empty() || content.is_empty() {
            return Err(WorkspaceError::InvalidInput);
        }
        if content.len() > MAX_APPROVED_CONTENT_BYTES {
            return Err(WorkspaceError::ContentTooLarge);
        }

        let mut guards = Vec::with_capacity(references.len());
        let mut expected_workspace_instance_id = None;
        for reference in references {
            let verified = self.read_locked(
                operation,
                case_id,
                &reference.material_id,
                reference.document_version,
                &reference.publication_id,
                now_unix,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            )?;
            if verified.summary.manifest_sha256 != reference.manifest_sha256 {
                return Err(WorkspaceError::PublicationRevoked);
            }
            if expected_workspace_instance_id
                .as_ref()
                .is_some_and(|expected| expected != &verified.summary.workspace_instance_id)
            {
                return Err(WorkspaceError::ManifestInvalid);
            }
            expected_workspace_instance_id = Some(verified.summary.workspace_instance_id.clone());
            self.verify_current_revisions_locked(
                operation,
                case_id,
                &verified.egress_guard.claims,
                now_unix,
            )?;
            guards.push(verified.egress_guard);
        }

        for guard in guards {
            scan_case_specific_with_guard(&self.verifier.key, &guard.claims, content)?;
        }
        Ok(())
    }

    fn verify_current_revisions_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        guard: &ApprovedEgressGuardV1,
        now_unix: u64,
    ) -> Result<(), WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let latest_case = self.latest_revision_bundle_locked(operation, case_id, None, now_unix)?;
        if latest_case.egress_guard.claims.workspace_instance_id != guard.workspace_instance_id
            || latest_case.egress_guard.claims.dictionary_revision_hash
                != guard.dictionary_revision_hash
        {
            return Err(WorkspaceError::PublicationRevoked);
        }
        let latest_material = self.latest_revision_bundle_locked(
            operation,
            case_id,
            Some(&guard.material_id),
            now_unix,
        )?;
        if latest_material.egress_guard.claims.workspace_instance_id != guard.workspace_instance_id
            || latest_material.egress_guard.claims.source_revision_hash
                != guard.source_revision_hash
            || latest_material.egress_guard.claims.mapping_revision_hash
                != guard.mapping_revision_hash
        {
            return Err(WorkspaceError::PublicationRevoked);
        }
        Ok(())
    }

    fn latest_revision_bundle_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        material_id: Option<&MaterialId>,
        now_unix: u64,
    ) -> Result<VerifiedBundle, WorkspaceError> {
        self.validate_read_operation_guard(operation)?;
        let db = open_database(&self.root)?;
        let row = match material_id {
            Some(material_id) => db
                .query_row(
                    "SELECT material_id,document_version,publication_id
                     FROM publication_journal
                     WHERE case_id=?1 AND material_id=?2 AND state='committed'
                       AND committed_at_unix IS NOT NULL AND revoked_at_unix IS NULL
                     ORDER BY rowid DESC LIMIT 1",
                    params![case_id.as_str(), material_id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| WorkspaceError::DatabaseFailed)?,
            None => db
                .query_row(
                    "SELECT material_id,document_version,publication_id
                     FROM publication_journal WHERE case_id=?1 AND state='committed'
                       AND committed_at_unix IS NOT NULL AND revoked_at_unix IS NULL
                     ORDER BY rowid DESC LIMIT 1",
                    params![case_id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| WorkspaceError::DatabaseFailed)?,
        }
        .ok_or(WorkspaceError::PublicationNotAvailable)?;
        let material_id = MaterialId::parse(row.0).map_err(|_| WorkspaceError::DatabaseFailed)?;
        let document_version = sql_u64(row.1)?;
        let publication_id =
            PublicationId::parse(row.2).map_err(|_| WorkspaceError::DatabaseFailed)?;
        let directory = self
            .root
            .cases
            .join(case_id.as_str())
            .join("approved")
            .join(publication_id.as_str());
        let bundle = verify_bundle(
            &self.root,
            &directory,
            &self.verifier,
            now_unix,
            Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
            Some(APPROVED_MATERIAL_READ_PURPOSE),
        )?;
        if bundle.manifest.claims.case_id != *case_id
            || bundle.manifest.claims.material_id != material_id
            || bundle.manifest.claims.document_version != document_version
            || bundle.manifest.claims.publication_id != publication_id
        {
            return Err(WorkspaceError::ManifestInvalid);
        }
        Ok(bundle)
    }

    fn ensure_publication_active(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        document_version_sql: i64,
        publication_id: &PublicationId,
    ) -> Result<(), WorkspaceError> {
        let db = open_database(&self.root)?;
        let state = db
            .query_row(
                "SELECT state,revoked_at_unix FROM publication_journal
                 WHERE case_id=?1 AND material_id=?2 AND document_version=?3 AND publication_id=?4",
                params![
                    case_id.as_str(),
                    material_id.as_str(),
                    document_version_sql,
                    publication_id.as_str()
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .ok_or(WorkspaceError::PublicationNotAvailable)?;
        if state.0 != "committed" {
            return Err(WorkspaceError::PublicationNotAvailable);
        }
        if state.1.is_some() {
            return Err(WorkspaceError::PublicationRevoked);
        }
        Ok(())
    }

    pub fn revoke(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        document_version: u64,
        publication_id: &PublicationId,
        revoked_at_unix: u64,
    ) -> Result<(), WorkspaceError> {
        let _operation = self.acquire_operation_guard()?;
        let document_version_sql = sql_i64(document_version)?;
        let revoked_at_sql = sql_i64(revoked_at_unix)?;
        let db = open_database(&self.root)?;
        let changed = db
            .execute(
                "UPDATE publication_journal
                 SET revoked_at_unix=?5,revocation_epoch=revocation_epoch+1
                 WHERE case_id=?1 AND material_id=?2 AND document_version=?3
                   AND publication_id=?4 AND state='committed' AND revoked_at_unix IS NULL",
                params![
                    case_id.as_str(),
                    material_id.as_str(),
                    document_version_sql,
                    publication_id.as_str(),
                    revoked_at_sql
                ],
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        if changed != 1 {
            return Err(WorkspaceError::PublicationNotAvailable);
        }
        Ok(())
    }

    /// Atomically revokes every currently committed publication for a case. This is the
    /// cross-database, revoke-first boundary used before an App dictionary/source mutation.
    pub fn revoke_case_publications(
        &self,
        case_id: &CaseId,
        revoked_at_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        self.revoke_matching_publications(case_id, None, revoked_at_unix)
    }

    /// Atomically revokes every currently committed publication for one case material.
    pub fn revoke_material_publications(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        revoked_at_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        self.revoke_matching_publications(case_id, Some(material_id), revoked_at_unix)
    }

    /// Atomically revokes every active approved publication whose signed manifest proves that
    /// local OCR contributed to the generation. Native-text publications are deliberately left
    /// active, even when they share a case or an MCP session with an OCR-derived publication.
    ///
    /// The immediate transaction is held while every active bundle is verified. This prevents a
    /// concurrent publication from appearing between provenance classification and revocation,
    /// and makes an unreadable or forged active bundle fail the whole operation without changing
    /// any revocation epoch.
    pub fn revoke_ocr_derived_publications(
        &self,
        revoked_at_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        if revoked_at_unix == 0 {
            return Err(WorkspaceError::InvalidInput);
        }
        let _operation = self.acquire_operation_guard()?;
        let revoked_at_sql = sql_i64(revoked_at_unix)?;
        let mut db = open_database(&self.root)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let mut statement = transaction
            .prepare(
                "SELECT case_id,material_id,document_version,publication_id,
                        manifest_sha256,content_sha256
                 FROM publication_journal
                 WHERE state='committed' AND revoked_at_unix IS NULL
                 ORDER BY case_id,material_id,document_version,publication_id",
            )
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        drop(statement);

        let mut targets = Vec::new();
        for (
            case_id,
            material_id,
            document_version,
            publication_id,
            journal_manifest_sha256,
            journal_content_sha256,
        ) in rows
        {
            let case_id = CaseId::parse(case_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let material_id =
                MaterialId::parse(material_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let document_version = sql_u64(document_version)?;
            let publication_id =
                PublicationId::parse(publication_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let directory = self
                .root
                .cases
                .join(case_id.as_str())
                .join("approved")
                .join(publication_id.as_str());
            // `0` intentionally verifies signatures and content without treating an already
            // expired publication as unverifiable: expiry is itself an OCR invalidation trigger.
            let bundle = verify_bundle(&self.root, &directory, &self.verifier, 0, None, None)?;
            let claims = &bundle.manifest.claims;
            if claims.case_id != case_id
                || claims.material_id != material_id
                || claims.document_version != document_version
                || claims.publication_id != publication_id
                || bundle.manifest_sha256.as_str() != journal_manifest_sha256
                || claims.content_sha256.as_str() != journal_content_sha256
            {
                return Err(WorkspaceError::ManifestInvalid);
            }
            if claims.ocr_output_sha256.is_some()
                || claims.worker_sha256.is_some()
                || claims.model_manifest_sha256.is_some()
            {
                targets.push((case_id, material_id, document_version, publication_id));
            }
        }

        for (case_id, material_id, document_version, publication_id) in &targets {
            let changed = transaction
                .execute(
                    "UPDATE publication_journal
                     SET revoked_at_unix=?5,revocation_epoch=revocation_epoch+1
                     WHERE case_id=?1 AND material_id=?2 AND document_version=?3
                       AND publication_id=?4 AND state='committed'
                       AND revoked_at_unix IS NULL",
                    params![
                        case_id.as_str(),
                        material_id.as_str(),
                        sql_i64(*document_version)?,
                        publication_id.as_str(),
                        revoked_at_sql
                    ],
                )
                .map_err(|_| WorkspaceError::DatabaseFailed)?;
            if changed != 1 {
                return Err(WorkspaceError::DatabaseFailed);
            }
        }
        transaction
            .commit()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        u64::try_from(targets.len()).map_err(|_| WorkspaceError::DatabaseFailed)
    }

    /// Revoke-first phase for retention cleanup. The opaque lifecycle ids are App-local
    /// redaction ids bound at publication time; no case/material widening is permitted.
    pub fn prepare_lifecycle_retention_revocation(
        &self,
        lifecycle_binding_ids: &BTreeSet<String>,
        revoked_at_unix: u64,
        reason_code: &str,
    ) -> Result<LifecyclePublicationRevocationV1, WorkspaceError> {
        if revoked_at_unix == 0
            || reason_code.is_empty()
            || reason_code.len() > 128
            || lifecycle_binding_ids
                .iter()
                .any(|value| !valid_lifecycle_binding_id(value))
        {
            return Err(WorkspaceError::InvalidInput);
        }
        if lifecycle_binding_ids.is_empty() {
            return Ok(LifecyclePublicationRevocationV1 {
                newly_revoked: 0,
                publication_ids: BTreeSet::new(),
            });
        }
        let _operation = self.acquire_operation_guard()?;
        let revoked_at_sql = sql_i64(revoked_at_unix)?;
        let mut db = open_database(&self.root)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT case_id,material_id,document_version,publication_id,
                            manifest_sha256,content_sha256,revoked_at_unix,lifecycle_binding_id
                     FROM publication_journal
                     WHERE state='committed' AND lifecycle_binding_id IS NOT NULL
                     ORDER BY case_id,material_id,document_version,publication_id",
                )
                .map_err(|_| WorkspaceError::DatabaseFailed)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                })
                .map_err(|_| WorkspaceError::DatabaseFailed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WorkspaceError::DatabaseFailed)?;
            rows
        };
        let mut publication_ids = BTreeSet::new();
        let mut newly_revoked = 0_u64;
        for (
            case_id,
            material_id,
            document_version,
            publication_id,
            journal_manifest_sha256,
            journal_content_sha256,
            revoked_at,
            lifecycle_binding_id,
        ) in rows
        {
            if !lifecycle_binding_ids.contains(&lifecycle_binding_id) {
                continue;
            }
            let case_id = CaseId::parse(case_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let material_id =
                MaterialId::parse(material_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let document_version = sql_u64(document_version)?;
            let publication_id =
                PublicationId::parse(publication_id).map_err(|_| WorkspaceError::DatabaseFailed)?;
            let cleanup_state = transaction
                .query_row(
                    "SELECT state FROM publication_retention_cleanup WHERE publication_id=?1",
                    [publication_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| WorkspaceError::DatabaseFailed)?;
            if cleanup_state.is_none() {
                let directory = self
                    .root
                    .cases
                    .join(case_id.as_str())
                    .join("approved")
                    .join(publication_id.as_str());
                let bundle = verify_bundle(&self.root, &directory, &self.verifier, 0, None, None)?;
                let claims = &bundle.manifest.claims;
                if claims.case_id != case_id
                    || claims.material_id != material_id
                    || claims.document_version != document_version
                    || claims.publication_id != publication_id
                    || bundle.manifest_sha256.as_str() != journal_manifest_sha256
                    || claims.content_sha256.as_str() != journal_content_sha256
                {
                    return Err(WorkspaceError::ManifestInvalid);
                }
            }
            if revoked_at.is_none() {
                let changed = transaction
                    .execute(
                        "UPDATE publication_journal
                         SET revoked_at_unix=?2,revocation_epoch=revocation_epoch+1
                         WHERE publication_id=?1 AND state='committed'
                           AND revoked_at_unix IS NULL",
                        params![publication_id.as_str(), revoked_at_sql],
                    )
                    .map_err(|_| WorkspaceError::DatabaseFailed)?;
                if changed != 1 {
                    return Err(WorkspaceError::DatabaseFailed);
                }
                newly_revoked = newly_revoked.saturating_add(1);
            }
            if cleanup_state.is_none() {
                transaction
                    .execute(
                        "INSERT INTO publication_retention_cleanup(
                           publication_id,case_id,lifecycle_binding_id,state,
                           prepared_at_unix,reason_code
                         ) VALUES(?1,?2,?3,'prepared',?4,?5)",
                        params![
                            publication_id.as_str(),
                            case_id.as_str(),
                            lifecycle_binding_id,
                            revoked_at_sql,
                            reason_code
                        ],
                    )
                    .map_err(|_| WorkspaceError::DatabaseFailed)?;
            }
            publication_ids.insert(publication_id);
        }
        transaction
            .commit()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        Ok(LifecyclePublicationRevocationV1 {
            newly_revoked,
            publication_ids,
        })
    }

    /// Completes or resumes physical cleanup for already-revoked lifecycle targets. Missing final
    /// and quarantine directories are treated as the crash point after deletion and before the
    /// journal commit, making recovery idempotent.
    pub fn recover_lifecycle_retention_cleanup(
        &self,
        completed_at_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        if completed_at_unix == 0 {
            return Err(WorkspaceError::InvalidInput);
        }
        let _operation = self.acquire_operation_guard()?;
        let db = open_database(&self.root)?;
        let rows = {
            let mut statement = db
                .prepare(
                    "SELECT case_id,publication_id FROM publication_retention_cleanup
                     WHERE state='prepared' ORDER BY publication_id",
                )
                .map_err(|_| WorkspaceError::RecoveryFailed)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| WorkspaceError::RecoveryFailed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WorkspaceError::RecoveryFailed)?;
            rows
        };
        let mut recovered = 0_u64;
        for (case_id, publication_id) in rows {
            let case_id = CaseId::parse(case_id).map_err(|_| WorkspaceError::RecoveryFailed)?;
            let publication_id =
                PublicationId::parse(publication_id).map_err(|_| WorkspaceError::RecoveryFailed)?;
            let final_directory = self
                .root
                .cases
                .join(case_id.as_str())
                .join("approved")
                .join(publication_id.as_str());
            let quarantine_directory = self
                .root
                .quarantine
                .join(format!("retention-{}", publication_id.as_str()));
            if final_directory.exists() {
                validate_controlled_path(&self.root, &final_directory, false)?;
                if quarantine_directory.exists() {
                    return Err(WorkspaceError::RecoveryFailed);
                }
                fs::rename(&final_directory, &quarantine_directory)
                    .map_err(|_| WorkspaceError::RecoveryFailed)?;
            }
            if quarantine_directory.exists() {
                validate_controlled_path(&self.root, &quarantine_directory, false)?;
                fs::remove_dir_all(&quarantine_directory)
                    .map_err(|_| WorkspaceError::RecoveryFailed)?;
            }
            let changed = db
                .execute(
                    "UPDATE publication_retention_cleanup
                     SET state='committed',completed_at_unix=?2
                     WHERE publication_id=?1 AND state='prepared'",
                    params![publication_id.as_str(), sql_i64(completed_at_unix)?],
                )
                .map_err(|_| WorkspaceError::RecoveryFailed)?;
            if changed != 1 {
                return Err(WorkspaceError::RecoveryFailed);
            }
            recovered = recovered.saturating_add(1);
        }
        Ok(recovered)
    }

    fn revoke_matching_publications(
        &self,
        case_id: &CaseId,
        material_id: Option<&MaterialId>,
        revoked_at_unix: u64,
    ) -> Result<u64, WorkspaceError> {
        if revoked_at_unix == 0 {
            return Err(WorkspaceError::InvalidInput);
        }
        let _operation = self.acquire_operation_guard()?;
        let revoked_at_sql = sql_i64(revoked_at_unix)?;
        let mut db = open_database(&self.root)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let changed = match material_id {
            Some(material_id) => transaction.execute(
                "UPDATE publication_journal
                 SET revoked_at_unix=?3,revocation_epoch=revocation_epoch+1
                 WHERE case_id=?1 AND material_id=?2 AND state='committed'
                   AND revoked_at_unix IS NULL",
                params![case_id.as_str(), material_id.as_str(), revoked_at_sql],
            ),
            None => transaction.execute(
                "UPDATE publication_journal
                 SET revoked_at_unix=?2,revocation_epoch=revocation_epoch+1
                 WHERE case_id=?1 AND state='committed' AND revoked_at_unix IS NULL",
                params![case_id.as_str(), revoked_at_sql],
            ),
        }
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
        transaction
            .commit()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        u64::try_from(changed).map_err(|_| WorkspaceError::DatabaseFailed)
    }
}

#[derive(Clone)]
struct ValidatedWorkspaceRoot {
    root: PathBuf,
    cases: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    database: PathBuf,
    operation_lock: PathBuf,
    read_only: bool,
}

impl ValidatedWorkspaceRoot {
    fn initialize(root: &Path) -> Result<Self, WorkspaceError> {
        if !root.is_absolute() {
            return Err(WorkspaceError::InvalidRoot);
        }
        fs::create_dir_all(root).map_err(|_| WorkspaceError::IoFailed)?;
        platform::validate_fixed_local_root(root)?;
        platform::mark_not_content_indexed(root)?;
        let canonical = fs::canonicalize(root).map_err(|_| WorkspaceError::InvalidRoot)?;
        let layout = Self::from_canonical(canonical, false);
        for directory in [&layout.cases, &layout.staging, &layout.quarantine] {
            fs::create_dir_all(directory).map_err(|_| WorkspaceError::IoFailed)?;
            platform::mark_not_content_indexed(directory)?;
        }
        ensure_operation_lock_file(&layout)?;
        Ok(layout)
    }

    fn open(root: &Path) -> Result<Self, WorkspaceError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        platform::validate_fixed_local_root(root)?;
        let canonical = fs::canonicalize(root).map_err(|_| WorkspaceError::InvalidRoot)?;
        let layout = Self::from_canonical(canonical, false);
        if !layout.cases.is_dir() || !layout.staging.is_dir() || !layout.quarantine.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        ensure_operation_lock_file(&layout)?;
        Ok(layout)
    }

    fn open_read_only(root: &Path) -> Result<Self, WorkspaceError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        platform::validate_fixed_local_root(root)?;
        let canonical = fs::canonicalize(root).map_err(|_| WorkspaceError::InvalidRoot)?;
        let layout = Self::from_canonical(canonical, true);
        if !layout.cases.is_dir() || !layout.staging.is_dir() || !layout.quarantine.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        validate_operation_lock_file(&layout)?;
        Ok(layout)
    }

    fn from_canonical(root: PathBuf, read_only: bool) -> Self {
        Self {
            cases: root.join("cases"),
            staging: root.join(".staging"),
            quarantine: root.join(".quarantine"),
            database: root.join("workspace-state.sqlite"),
            operation_lock: root.join(OPERATION_LOCK_FILE_NAME),
            root,
            read_only,
        }
    }
}

pub struct ApprovedWorkspaceOperationGuard {
    _file: File,
    workspace_root: PathBuf,
    allows_mutation: bool,
}

fn ensure_operation_lock_file(root: &ValidatedWorkspaceRoot) -> Result<(), WorkspaceError> {
    if !root.operation_lock.exists() {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&root.operation_lock)
        {
            Ok(file) => file.sync_all().map_err(|_| WorkspaceError::IoFailed)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(WorkspaceError::IoFailed),
        }
    }
    validate_operation_lock_file(root)
}

fn validate_operation_lock_file(root: &ValidatedWorkspaceRoot) -> Result<(), WorkspaceError> {
    platform::reject_reparse_components(&root.root, &root.operation_lock)?;
    let metadata =
        fs::symlink_metadata(&root.operation_lock).map_err(|_| WorkspaceError::UnsafeFilesystem)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkspaceError::UnsafeFilesystem);
    }
    Ok(())
}

#[cfg(windows)]
fn acquire_workspace_operation_guard(
    root: &ValidatedWorkspaceRoot,
) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
    use std::os::windows::fs::OpenOptionsExt;

    for attempt in 0..OPERATION_LOCK_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.read(true).write(!root.read_only).share_mode(0);
        match options.open(&root.operation_lock) {
            Ok(file) => {
                return Ok(ApprovedWorkspaceOperationGuard {
                    _file: file,
                    workspace_root: root.root.clone(),
                    allows_mutation: true,
                })
            }
            Err(_) if attempt + 1 < OPERATION_LOCK_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(
                    OPERATION_LOCK_RETRY_MILLIS,
                ));
            }
            Err(_) => return Err(WorkspaceError::DatabaseFailed),
        }
    }
    Err(WorkspaceError::DatabaseFailed)
}

#[cfg(windows)]
fn acquire_workspace_writer_exclusion_guard(
    root: &ValidatedWorkspaceRoot,
) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    for attempt in 0..OPERATION_LOCK_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.read(true).share_mode(FILE_SHARE_READ);
        match options.open(&root.operation_lock) {
            Ok(file) => {
                return Ok(ApprovedWorkspaceOperationGuard {
                    _file: file,
                    workspace_root: root.root.clone(),
                    allows_mutation: false,
                })
            }
            Err(_) if attempt + 1 < OPERATION_LOCK_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(
                    OPERATION_LOCK_RETRY_MILLIS,
                ));
            }
            Err(_) => return Err(WorkspaceError::DatabaseFailed),
        }
    }
    Err(WorkspaceError::DatabaseFailed)
}

#[cfg(not(windows))]
fn acquire_workspace_operation_guard(
    _root: &ValidatedWorkspaceRoot,
) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
    Err(WorkspaceError::PlatformUnavailable)
}

#[cfg(not(windows))]
fn acquire_workspace_writer_exclusion_guard(
    _root: &ValidatedWorkspaceRoot,
) -> Result<ApprovedWorkspaceOperationGuard, WorkspaceError> {
    Err(WorkspaceError::PlatformUnavailable)
}

fn initialize_database(root: &ValidatedWorkspaceRoot) -> Result<(), WorkspaceError> {
    let db = open_database(root)?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS workspace_meta(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             schema_version INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO workspace_meta(singleton,schema_version) VALUES(1,1);
         CREATE TABLE IF NOT EXISTS publication_journal(
             transaction_id TEXT PRIMARY KEY,
             case_id TEXT NOT NULL,
             material_id TEXT NOT NULL,
             document_version INTEGER NOT NULL CHECK(document_version>0),
             publication_id TEXT NOT NULL UNIQUE,
             manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64),
             content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
             state TEXT NOT NULL CHECK(state IN('prepared','committed','quarantined')),
             created_at_unix INTEGER NOT NULL,
             committed_at_unix INTEGER,
             revoked_at_unix INTEGER,
             revocation_epoch INTEGER NOT NULL DEFAULT 0,
             lifecycle_binding_id TEXT,
             UNIQUE(case_id,material_id,document_version,publication_id)
         );
         CREATE TABLE IF NOT EXISTS publication_retention_cleanup(
             publication_id TEXT PRIMARY KEY,
             case_id TEXT NOT NULL,
             lifecycle_binding_id TEXT NOT NULL,
             state TEXT NOT NULL CHECK(state IN('prepared','committed')),
             prepared_at_unix INTEGER NOT NULL,
             completed_at_unix INTEGER,
             reason_code TEXT NOT NULL,
             FOREIGN KEY(publication_id) REFERENCES publication_journal(publication_id)
         );
         CREATE TRIGGER IF NOT EXISTS trg_publication_cleanup_final_no_update
         BEFORE UPDATE ON publication_retention_cleanup
         WHEN OLD.state='committed' BEGIN
             SELECT RAISE(ABORT,'final publication cleanup journal is immutable');
         END;
         CREATE TRIGGER IF NOT EXISTS trg_publication_cleanup_no_delete
         BEFORE DELETE ON publication_retention_cleanup BEGIN
             SELECT RAISE(ABORT,'publication cleanup journal is append only');
         END;",
    )
    .map_err(|_| WorkspaceError::DatabaseFailed)?;
    let has_lifecycle_binding = {
        let mut statement = db
            .prepare("PRAGMA table_info(publication_journal)")
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| WorkspaceError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkspaceError::DatabaseFailed)?;
        columns
            .iter()
            .any(|column| column == "lifecycle_binding_id")
    };
    if !has_lifecycle_binding {
        db.execute(
            "ALTER TABLE publication_journal ADD COLUMN lifecycle_binding_id TEXT",
            [],
        )
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
    }
    let version: u32 = db
        .query_row(
            "SELECT schema_version FROM workspace_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
    if version != WORKSPACE_SCHEMA_VERSION {
        return Err(WorkspaceError::DatabaseFailed);
    }
    Ok(())
}

fn open_database(root: &ValidatedWorkspaceRoot) -> Result<Connection, WorkspaceError> {
    if !root.database.exists() && !root.root.is_dir() {
        return Err(WorkspaceError::InvalidRoot);
    }
    let db = if root.read_only {
        open_existing_sqlite_read_only(&root.database)?
    } else {
        Connection::open(&root.database).map_err(|_| WorkspaceError::DatabaseFailed)?
    };
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
    Ok(db)
}

/// Opens an existing SQLite database without creating sidecars for a cold
/// WAL-mode main file.  A non-empty WAL is deliberately opened in ordinary
/// read-only URI mode so committed frames remain visible; callers that need a
/// physical no-write guarantee must additionally pin the database/WAL/SHM
/// files against writes for the lifetime of the connection.
pub fn open_existing_sqlite_read_only(path: &Path) -> Result<Connection, WorkspaceError> {
    let canonical = fs::canonicalize(path).map_err(|_| WorkspaceError::DatabaseFailed)?;
    let mut wal_name = path.as_os_str().to_os_string();
    wal_name.push("-wal");
    let wal_path = PathBuf::from(wal_name);
    let cold = match fs::symlink_metadata(&wal_path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(WorkspaceError::UnsafeFilesystem);
            }
            metadata.len() == 0
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => return Err(WorkspaceError::DatabaseFailed),
    };
    let raw = canonical
        .to_str()
        .ok_or(WorkspaceError::InvalidRoot)?
        .strip_prefix(r"\\?\")
        .unwrap_or_else(|| canonical.to_str().expect("Unicode path checked"))
        .replace('\\', "/");
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    #[cfg(windows)]
    let prefix = "file:///";
    #[cfg(not(windows))]
    let prefix = "file:";
    let immutable = if cold { "&immutable=1" } else { "" };
    let uri = format!("{prefix}{encoded}?mode=ro{immutable}");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| WorkspaceError::DatabaseFailed)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
    Ok(connection)
}

fn build_egress_guard(
    signer: &ManifestSigningKey,
    manifest: &ApprovedMaterialManifestV1,
    input: ApprovedEgressGuardInputV1<'_>,
) -> Result<SignedApprovedEgressGuardV1, WorkspaceError> {
    let supplied_count = input
        .case_dictionary_terms
        .len()
        .checked_add(input.source_terms.len())
        .and_then(|count| count.checked_add(input.raw_canary_terms.len()))
        .ok_or(WorkspaceError::InvalidInput)?;
    if supplied_count > MAX_APPROVED_EGRESS_FINGERPRINTS {
        return Err(WorkspaceError::InvalidInput);
    }

    let mut fingerprints = BTreeSet::new();
    for (kind, terms) in [
        (
            ApprovedEgressTermKindV1::CaseDictionary,
            input.case_dictionary_terms,
        ),
        (ApprovedEgressTermKindV1::SourceTerm, input.source_terms),
        (ApprovedEgressTermKindV1::RawCanary, input.raw_canary_terms),
    ] {
        for term in terms {
            let normalized = normalize_egress_term(term)?;
            let normalized_char_length = u32::try_from(normalized.chars().count())
                .map_err(|_| WorkspaceError::InvalidInput)?;
            let fingerprint = Sha256Hex::parse(blind_egress_fingerprint(
                &signer.key,
                &manifest.workspace_instance_id,
                &manifest.case_id,
                kind,
                &normalized,
            ))
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
            fingerprints.insert(BlindEgressFingerprintV1 {
                kind,
                normalized_char_length,
                fingerprint,
            });
        }
    }

    signer.sign_egress_guard(ApprovedEgressGuardV1 {
        schema_version: APPROVED_EGRESS_GUARD_VERSION.to_owned(),
        normalization_version: APPROVED_EGRESS_NORMALIZATION_VERSION.to_owned(),
        workspace_instance_id: manifest.workspace_instance_id.clone(),
        case_id: manifest.case_id.clone(),
        material_id: manifest.material_id.clone(),
        document_version: manifest.document_version,
        publication_id: manifest.publication_id.clone(),
        content_sha256: manifest.content_sha256.clone(),
        source_name_sha256: manifest.source_name_sha256.clone(),
        source_revision_hash: manifest.source_revision_hash.clone(),
        dictionary_revision_hash: manifest.dictionary_revision_hash.clone(),
        mapping_revision_hash: manifest.mapping_revision_hash.clone(),
        fingerprints: fingerprints.into_iter().collect(),
    })
}

fn normalize_egress_term(value: &str) -> Result<String, WorkspaceError> {
    if value.len() > 16 * 1024 {
        return Err(WorkspaceError::InvalidInput);
    }
    let normalized = normalize_egress_text(value);
    let normalized = normalized.trim().to_owned();
    let char_length = normalized.chars().count();
    if normalized.is_empty()
        || char_length
            > usize::try_from(MAX_APPROVED_EGRESS_TERM_CHAR_LENGTH)
                .map_err(|_| WorkspaceError::InvalidInput)?
    {
        return Err(WorkspaceError::InvalidInput);
    }
    Ok(normalized)
}

fn normalize_egress_text(value: &str) -> String {
    let compatibility_normalized: String = value.nfkc().collect();
    normalize_sensitive_text(&compatibility_normalized)
}

fn blind_egress_fingerprint(
    key: &[u8],
    workspace_instance_id: &WorkspaceInstanceId,
    case_id: &CaseId,
    kind: ApprovedEgressTermKindV1,
    normalized_value: &str,
) -> String {
    hmac_sha256_hex_parts(
        key,
        EGRESS_GUARD_FINGERPRINT_DOMAIN,
        &[
            APPROVED_EGRESS_NORMALIZATION_VERSION.as_bytes(),
            b"\0",
            workspace_instance_id.as_str().as_bytes(),
            b"\0",
            case_id.as_str().as_bytes(),
            b"\0",
            kind.code().as_bytes(),
            b"\0",
            normalized_value.as_bytes(),
        ],
    )
}

fn scan_case_specific_with_guard(
    key: &[u8],
    guard: &ApprovedEgressGuardV1,
    content: &[u8],
) -> Result<(), WorkspaceError> {
    if guard.fingerprints.is_empty() {
        return Ok(());
    }
    let text =
        std::str::from_utf8(content).map_err(|_| WorkspaceError::ResidualSensitiveContent)?;
    let normalized = normalize_egress_text(text);
    let mut boundaries = normalized
        .char_indices()
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    boundaries.push(normalized.len());
    let character_count = boundaries.len().saturating_sub(1);

    let mut groups: BTreeMap<(ApprovedEgressTermKindV1, u32), BTreeSet<String>> = BTreeMap::new();
    for entry in &guard.fingerprints {
        groups
            .entry((entry.kind, entry.normalized_char_length))
            .or_default()
            .insert(entry.fingerprint.as_str().to_owned());
    }
    for ((kind, normalized_char_length), targets) in groups {
        let window_length =
            usize::try_from(normalized_char_length).map_err(|_| WorkspaceError::ManifestInvalid)?;
        if window_length > character_count {
            continue;
        }
        for start in 0..=character_count - window_length {
            let candidate = &normalized[boundaries[start]..boundaries[start + window_length]];
            let fingerprint = blind_egress_fingerprint(
                key,
                &guard.workspace_instance_id,
                &guard.case_id,
                kind,
                candidate,
            );
            if targets.contains(&fingerprint) {
                return Err(WorkspaceError::ResidualSensitiveContent);
            }
        }
    }
    Ok(())
}

struct VerifiedBundle {
    manifest: SignedApprovedMaterialManifestV1,
    egress_guard: SignedApprovedEgressGuardV1,
    content: Vec<u8>,
    manifest_sha256: Sha256Hex,
}

fn verify_bundle(
    root: &ValidatedWorkspaceRoot,
    directory: &Path,
    verifier: &ManifestVerificationKey,
    now_unix: u64,
    expected_destination_scope: Option<&str>,
    expected_purpose: Option<&str>,
) -> Result<VerifiedBundle, WorkspaceError> {
    validate_controlled_path(root, directory, false)?;
    let content_path = directory.join("content.bin");
    let manifest_path = directory.join("manifest.json");
    let guard_path = directory.join("egress-guard.json");
    let commit_path = directory.join("commit.json");
    validate_controlled_path(root, &content_path, true)?;
    validate_controlled_path(root, &manifest_path, true)?;
    validate_controlled_path(root, &guard_path, true)?;
    validate_controlled_path(root, &commit_path, true)?;

    let content = read_bounded(&content_path, MAX_APPROVED_CONTENT_BYTES)?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let guard_bytes = read_bounded(&guard_path, MAX_EGRESS_GUARD_BYTES)?;
    let residual = scan_residual(&content).map_err(|_| WorkspaceError::ResidualSensitiveContent)?;
    if !residual.passed {
        return Err(WorkspaceError::ResidualSensitiveContent);
    }
    let commit_bytes = read_bounded(&commit_path, MAX_MANIFEST_BYTES)?;
    let signed: SignedApprovedMaterialManifestV1 =
        strict_json_v1_from_slice(&manifest_bytes).map_err(|_| WorkspaceError::ManifestInvalid)?;
    let signed_guard: SignedApprovedEgressGuardV1 =
        strict_json_v1_from_slice(&guard_bytes).map_err(|_| WorkspaceError::ManifestInvalid)?;
    verifier.verify(&signed)?;
    verifier.verify_egress_guard(&signed_guard)?;
    if now_unix >= signed.claims.expires_at_unix {
        return Err(WorkspaceError::PublicationExpired);
    }
    if expected_destination_scope
        .is_some_and(|expected| expected != signed.claims.destination_scope)
    {
        return Err(WorkspaceError::DestinationMismatch);
    }
    if expected_purpose.is_some_and(|expected| expected != signed.claims.purpose) {
        return Err(WorkspaceError::PurposeMismatch);
    }
    if signed.claims.content_bytes
        != u64::try_from(content.len()).map_err(|_| WorkspaceError::ContentTooLarge)?
        || signed.claims.content_sha256.as_str() != sha256_hex(&content)
    {
        return Err(WorkspaceError::ContentMismatch);
    }
    let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
        .map_err(|_| WorkspaceError::ManifestInvalid)?;
    let guard_sha256 =
        Sha256Hex::parse(sha256_hex(&guard_bytes)).map_err(|_| WorkspaceError::ManifestInvalid)?;
    let commit: BundleCommitV1 =
        strict_json_v1_from_slice(&commit_bytes).map_err(|_| WorkspaceError::ManifestInvalid)?;
    if commit.schema_version != BUNDLE_COMMIT_VERSION
        || commit.publication_id != signed.claims.publication_id
        || commit.manifest_sha256 != manifest_sha256
        || commit.egress_guard_sha256 != guard_sha256
        || commit.content_sha256 != signed.claims.content_sha256
        || commit.content_bytes != signed.claims.content_bytes
        || signed_guard.claims.workspace_instance_id != signed.claims.workspace_instance_id
        || signed_guard.claims.case_id != signed.claims.case_id
        || signed_guard.claims.material_id != signed.claims.material_id
        || signed_guard.claims.document_version != signed.claims.document_version
        || signed_guard.claims.publication_id != signed.claims.publication_id
        || signed_guard.claims.content_sha256 != signed.claims.content_sha256
        || signed_guard.claims.source_name_sha256 != signed.claims.source_name_sha256
        || signed_guard.claims.source_revision_hash != signed.claims.source_revision_hash
        || signed_guard.claims.dictionary_revision_hash != signed.claims.dictionary_revision_hash
        || signed_guard.claims.mapping_revision_hash != signed.claims.mapping_revision_hash
    {
        return Err(WorkspaceError::ManifestInvalid);
    }
    scan_case_specific_with_guard(&verifier.key, &signed_guard.claims, &content)?;
    Ok(VerifiedBundle {
        manifest: signed,
        egress_guard: signed_guard,
        content,
        manifest_sha256,
    })
}

fn validate_controlled_path(
    root: &ValidatedWorkspaceRoot,
    path: &Path,
    require_file: bool,
) -> Result<(), WorkspaceError> {
    if !path.starts_with(&root.root) {
        return Err(WorkspaceError::UnsafeFilesystem);
    }
    platform::reject_reparse_components(&root.root, path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| WorkspaceError::PublicationNotAvailable)?;
    if metadata.file_type().is_symlink()
        || (require_file && !metadata.is_file())
        || (!require_file && !metadata.is_dir())
    {
        return Err(WorkspaceError::UnsafeFilesystem);
    }
    let canonical = fs::canonicalize(path).map_err(|_| WorkspaceError::UnsafeFilesystem)?;
    if !canonical.starts_with(&root.root) {
        return Err(WorkspaceError::UnsafeFilesystem);
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, WorkspaceError> {
    let metadata = fs::metadata(path).map_err(|_| WorkspaceError::PublicationNotAvailable)?;
    let length = usize::try_from(metadata.len()).map_err(|_| WorkspaceError::ContentTooLarge)?;
    if length == 0 || length > maximum {
        return Err(WorkspaceError::ContentTooLarge);
    }
    let file = File::open(path).map_err(|_| WorkspaceError::IoFailed)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(
        u64::try_from(maximum.saturating_add(1)).map_err(|_| WorkspaceError::ContentTooLarge)?,
    )
    .read_to_end(&mut bytes)
    .map_err(|_| WorkspaceError::IoFailed)?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(WorkspaceError::ContentTooLarge);
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), WorkspaceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| WorkspaceError::IoFailed)?;
    file.write_all(bytes)
        .map_err(|_| WorkspaceError::IoFailed)?;
    file.sync_all().map_err(|_| WorkspaceError::IoFailed)?;
    Ok(())
}

fn sql_i64(value: u64) -> Result<i64, WorkspaceError> {
    i64::try_from(value).map_err(|_| WorkspaceError::InvalidInput)
}

fn sql_u64(value: i64) -> Result<u64, WorkspaceError> {
    u64::try_from(value).map_err(|_| WorkspaceError::DatabaseFailed)
}

fn quarantine_path(
    root: &ValidatedWorkspaceRoot,
    transaction_id: &str,
    path: &Path,
) -> Result<(), WorkspaceError> {
    if !path.exists() {
        return Ok(());
    }
    let destination = root.quarantine.join(transaction_id);
    if destination.exists() {
        return Err(WorkspaceError::RecoveryFailed);
    }
    fs::rename(path, destination).map_err(|_| WorkspaceError::RecoveryFailed)
}

fn valid_lifecycle_binding_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.starts_with("red_")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn generate_prefixed_id(prefix: &str) -> Result<String, WorkspaceError> {
    let mut random = [0_u8; 16];
    platform::random(&mut random)?;
    let mut output = String::with_capacity(prefix.len() + 32);
    output.push_str(prefix);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").map_err(|_| WorkspaceError::InvalidInput)?;
    }
    Ok(output)
}

fn hmac_sha256_hex(key: &[u8], domain: &[u8], message: &[u8]) -> String {
    hmac_sha256_hex_parts(key, domain, &[message])
}

fn hmac_sha256_hex_parts(key: &[u8], domain: &[u8], message_parts: &[&[u8]]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    for part in message_parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let result = outer.finalize();
    let mut output = String::with_capacity(64);
    for byte in result {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    zeroize(&mut normalized);
    zeroize(&mut inner_pad);
    zeroize(&mut outer_pad);
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(windows)]
mod platform {
    use super::WorkspaceError;
    use std::{
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        ptr,
    };
    use windows_sys::Win32::{
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        Storage::FileSystem::{
            GetDriveTypeW, GetFileAttributesW, SetFileAttributesW,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT,
            INVALID_FILE_ATTRIBUTES,
        },
    };

    const DRIVE_FIXED_TYPE: u32 = 3;

    pub fn random(output: &mut [u8]) -> Result<(), WorkspaceError> {
        let length = u32::try_from(output.len()).map_err(|_| WorkspaceError::InvalidInput)?;
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                output.as_mut_ptr(),
                length,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(WorkspaceError::PlatformUnavailable);
        }
        Ok(())
    }

    pub fn validate_fixed_local_root(root: &Path) -> Result<(), WorkspaceError> {
        let canonical = std::fs::canonicalize(root).map_err(|_| WorkspaceError::InvalidRoot)?;
        let drive_root = canonical
            .ancestors()
            .last()
            .map(PathBuf::from)
            .ok_or(WorkspaceError::InvalidRoot)?;
        let drive_wide = wide(&drive_root);
        if unsafe { GetDriveTypeW(drive_wide.as_ptr()) } != DRIVE_FIXED_TYPE {
            return Err(WorkspaceError::UnsafeFilesystem);
        }
        reject_reparse_components(&canonical, &canonical)
    }

    pub fn reject_reparse_components(root: &Path, path: &Path) -> Result<(), WorkspaceError> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| WorkspaceError::UnsafeFilesystem)?;
        let mut current = root.to_path_buf();
        check_not_reparse(&current)?;
        for component in relative.components() {
            current.push(component.as_os_str());
            check_not_reparse(&current)?;
        }
        Ok(())
    }

    pub fn mark_not_content_indexed(path: &Path) -> Result<(), WorkspaceError> {
        let wide = wide(path);
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(WorkspaceError::UnsafeFilesystem);
        }
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WorkspaceError::UnsafeFilesystem);
        }
        let ok = unsafe {
            SetFileAttributesW(
                wide.as_ptr(),
                attributes | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            )
        };
        if ok == 0 {
            return Err(WorkspaceError::UnsafeFilesystem);
        }
        Ok(())
    }

    fn check_not_reparse(path: &Path) -> Result<(), WorkspaceError> {
        let wide = wide(path);
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WorkspaceError::UnsafeFilesystem);
        }
        Ok(())
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::WorkspaceError;
    use std::path::Path;

    pub fn random(_output: &mut [u8]) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::PlatformUnavailable)
    }

    pub fn validate_fixed_local_root(_root: &Path) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::PlatformUnavailable)
    }

    pub fn reject_reparse_components(_root: &Path, _path: &Path) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::PlatformUnavailable)
    }

    pub fn mark_not_content_indexed(_path: &Path) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::PlatformUnavailable)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::vnext::{
        ApprovalMode, ReceiptId, WorkspaceInstanceId, APPROVED_MATERIAL_MANIFEST_VERSION,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::{BufRead, BufReader},
        os::windows::fs::OpenOptionsExt,
        process::{Command, Stdio},
    };

    const OPERATION_LOCK_CHILD_ENV: &str = "LA_TEST_APPROVED_OPERATION_LOCK_PATH";
    const OPERATION_LOCK_CHILD_READY: &str = "LA_APPROVED_OPERATION_LOCK_READY";

    fn hash(seed: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(sha256_hex(seed)).expect("hash")
    }

    fn id<T>(
        value: &str,
        parser: impl FnOnce(String) -> Result<T, crate::vnext::VNextSchemaError>,
    ) -> T {
        parser(value.to_owned()).expect("id")
    }

    fn claims(content: &[u8], issued: u64, expires: u64) -> ApprovedMaterialManifestV1 {
        ApprovedMaterialManifestV1 {
            schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
            classification: crate::vnext::APPROVED_CLASSIFICATION.to_owned(),
            workspace_instance_id: id(
                "ws_00000000000000000000000000000001",
                WorkspaceInstanceId::parse,
            ),
            case_id: id("case_00000000000000000000000000000001", CaseId::parse),
            material_id: id("mat_00000000000000000000000000000001", MaterialId::parse),
            document_version: 1,
            publication_id: id("pub_00000000000000000000000000000001", PublicationId::parse),
            content_media_type: "text/plain".to_owned(),
            content_sha256: hash(content),
            content_bytes: content.len() as u64,
            source_sha256: hash(b"synthetic-source"),
            source_name_sha256: hash(b"synthetic-source.pdf"),
            source_revision_hash: hash(b"synthetic-source-revision"),
            extraction_sha256: hash(b"synthetic-extraction"),
            ocr_output_sha256: None,
            finding_summary_hash: hash(b"findings"),
            hard_gate_evaluation_hash: hash(b"gates"),
            policy_id: "strict".to_owned(),
            policy_version: 1,
            policy_sha256: hash(b"policy"),
            detector_versions: BTreeMap::from([("deterministic".to_owned(), "v1".to_owned())]),
            model_versions: BTreeMap::new(),
            worker_sha256: None,
            model_manifest_sha256: None,
            qualification_report_id: Some("native-text-qualified-v1".to_owned()),
            calibration_evidence_version: None,
            dictionary_revision_hash: hash(b"dictionary"),
            mapping_revision_hash: hash(b"mapping"),
            approval_mode: ApprovalMode::Human,
            readiness_score: 100,
            unresolved_p0: 0,
            unresolved_p1: 0,
            unresolved_p2: 0,
            destination_scope: "approved_case_workspace".to_owned(),
            purpose: "mcp.case_read_approved_material.v1".to_owned(),
            workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
            issued_at_unix: issued,
            expires_at_unix: expires,
            receipt_id: id("rct_00000000000000000000000000000001", ReceiptId::parse),
            receipt_nonce: "synthetic-nonce".to_owned(),
            revocation_epoch: 0,
        }
    }

    fn test_root() -> PathBuf {
        let mut random = [0_u8; 16];
        platform::random(&mut random).expect("random");
        std::env::temp_dir().join(format!("la-workspace-test-{}", sha256_hex(&random)))
    }

    #[test]
    fn publish_read_tamper_and_revoke_are_fail_closed() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[PERSON_001] synthetic approved text";
        let claims = claims(content, 10, 100);
        let summary = publisher.publish(claims.clone(), content).expect("publish");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        let verified = service
            .read(
                &claims.case_id,
                &claims.material_id,
                1,
                &claims.publication_id,
                20,
                Some("approved_case_workspace"),
                Some("mcp.case_read_approved_material.v1"),
            )
            .expect("read");
        assert_eq!(verified.content(), content);
        assert_eq!(summary.content_sha256, claims.content_sha256);

        service
            .revoke(
                &claims.case_id,
                &claims.material_id,
                1,
                &claims.publication_id,
                30,
            )
            .expect("revoke");
        assert!(matches!(
            service.read(
                &claims.case_id,
                &claims.material_id,
                1,
                &claims.publication_id,
                31,
                None,
                None,
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn operation_guard_serializes_cross_store_publish_boundaries() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        let guard = service
            .acquire_operation_guard()
            .expect("hold workspace operation boundary");
        let content = b"[PERSON_001] serialized approved text".to_vec();
        let claims = claims(&content, 10, 100);
        let (sender, receiver) = std::sync::mpsc::channel();
        let publisher_thread = std::thread::spawn(move || {
            sender
                .send(publisher.publish(claims, &content))
                .expect("send publication result");
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "publisher must wait while the cross-process boundary is held"
        );
        drop(guard);
        receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("publisher resumes after boundary release")
            .expect("publication succeeds");
        publisher_thread.join().expect("publisher thread");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn completed_read_linearizes_before_concurrent_revoke() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let reader_verifier = signing.verification_key();
        let revoker_verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[PERSON_001] read-before-revoke approved text";
        let claims = claims(content, 10, 100);
        publisher
            .publish(claims.clone(), content)
            .expect("publication");
        let reader = ApprovedWorkspaceService::open(&root, reader_verifier).expect("reader");
        let revoker = ApprovedWorkspaceService::open(&root, revoker_verifier).expect("revoker");

        let operation = reader
            .acquire_operation_guard()
            .expect("read operation boundary");
        let verified = reader
            .read_locked(
                &operation,
                &claims.case_id,
                &claims.material_id,
                claims.document_version,
                &claims.publication_id,
                20,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            )
            .expect("construct verified read result");
        let response_content = verified.content().to_vec();

        let revoke_claims = claims.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let revoke_thread = std::thread::spawn(move || {
            sender
                .send(revoker.revoke(
                    &revoke_claims.case_id,
                    &revoke_claims.material_id,
                    revoke_claims.document_version,
                    &revoke_claims.publication_id,
                    30,
                ))
                .expect("send revoke result");
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "revoke must wait until the completed read response leaves its operation boundary"
        );
        assert_eq!(response_content, content);
        drop(verified);
        drop(operation);
        receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("revoke resumes after read boundary release")
            .expect("revoke succeeds");
        revoke_thread.join().expect("revoke thread");
        assert!(matches!(
            reader.read_publication(
                &claims.case_id,
                &claims.material_id,
                &claims.publication_id,
                31,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// Helper invoked as an exact, separate libtest process by the following test. A normal test
    /// run has no environment binding and returns immediately.
    #[test]
    fn operation_lock_child_process() {
        let Some(lock_path) = std::env::var_os(OPERATION_LOCK_CHILD_ENV) else {
            return;
        };
        let _remote_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(PathBuf::from(lock_path))
            .expect("child acquires exclusive operation lock");
        println!("{OPERATION_LOCK_CHILD_READY}");
        std::io::stdout().flush().expect("flush ready marker");
        let mut release = [0_u8; 1];
        std::io::stdin()
            .read_exact(&mut release)
            .expect("parent releases child lock");
    }

    #[test]
    fn read_honors_operation_lock_held_by_a_separate_process() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[PERSON_001] cross-process approved text";
        let claims = claims(content, 10, 100);
        publisher
            .publish(claims.clone(), content)
            .expect("publication");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("reader");

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--exact")
            .arg("workspace::tests::operation_lock_child_process")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(
                OPERATION_LOCK_CHILD_ENV,
                root.join(OPERATION_LOCK_FILE_NAME),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn operation lock child");
        let mut child_output = BufReader::new(child.stdout.take().expect("child stdout"));
        loop {
            let mut line = String::new();
            let bytes = child_output.read_line(&mut line).expect("child output");
            assert!(
                bytes > 0,
                "child exited before acquiring the operation lock"
            );
            if line.contains(OPERATION_LOCK_CHILD_READY) {
                break;
            }
        }

        let (sender, receiver) = std::sync::mpsc::channel();
        let read_claims = claims.clone();
        let read_thread = std::thread::spawn(move || {
            let result = service.read_publication(
                &read_claims.case_id,
                &read_claims.material_id,
                &read_claims.publication_id,
                20,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            );
            sender
                .send(result.map(|verified| verified.content().to_vec()))
                .expect("send cross-process read result");
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "read must wait for an operation lock owned by another process"
        );
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(b"R")
            .expect("release child lock");
        assert!(child.wait().expect("wait for lock child").success());
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(3))
                .expect("read resumes after remote lock release")
                .expect("read succeeds"),
            content
        );
        read_thread.join().expect("read thread");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn revoke_first_case_and_material_operations_are_atomic_and_idempotent() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[PERSON_001] synthetic approved text";
        let first = claims(content, 10, 100);
        publisher
            .publish(first.clone(), content)
            .expect("first publication");
        let mut second = first.clone();
        second.material_id =
            MaterialId::parse("mat_00000000000000000000000000000002").expect("second material");
        second.publication_id = PublicationId::parse("pub_00000000000000000000000000000002")
            .expect("second publication");
        publisher
            .publish(second.clone(), content)
            .expect("second publication");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");

        assert_eq!(
            service
                .revoke_material_publications(&first.case_id, &first.material_id, 20)
                .expect("material revoke"),
            1
        );
        assert_eq!(
            service
                .revoke_material_publications(&first.case_id, &first.material_id, 21)
                .expect("idempotent material revoke"),
            0
        );
        assert!(matches!(
            service.read(
                &first.case_id,
                &first.material_id,
                first.document_version,
                &first.publication_id,
                22,
                None,
                None,
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        service
            .read(
                &second.case_id,
                &second.material_id,
                second.document_version,
                &second.publication_id,
                22,
                None,
                None,
            )
            .expect("unrelated material remains active");

        assert_eq!(
            service
                .revoke_case_publications(&first.case_id, 23)
                .expect("case revoke"),
            1
        );
        assert!(matches!(
            service.read(
                &second.case_id,
                &second.material_id,
                second.document_version,
                &second.publication_id,
                24,
                None,
                None,
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ocr_provenance_revoke_is_atomic_selective_and_idempotent() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let native_content = b"[PERSON_001] native approved text";
        let native = claims(native_content, 10, 100);
        publisher
            .publish(native.clone(), native_content)
            .expect("native publication");

        let ocr_content = b"[PERSON_002] OCR approved text";
        let mut ocr = claims(ocr_content, 10, 100);
        ocr.material_id =
            MaterialId::parse("mat_00000000000000000000000000000002").expect("ocr material");
        ocr.publication_id =
            PublicationId::parse("pub_00000000000000000000000000000002").expect("ocr publication");
        ocr.content_sha256 = hash(ocr_content);
        ocr.content_bytes = ocr_content.len() as u64;
        ocr.ocr_output_sha256 = Some(hash(b"ocr-output"));
        ocr.worker_sha256 = Some(hash(b"worker"));
        ocr.model_manifest_sha256 = Some(hash(b"model-manifest"));
        ocr.model_versions.insert(
            "mineru_model_manifest".to_owned(),
            ocr.model_manifest_sha256
                .as_ref()
                .expect("model hash")
                .as_str()
                .to_owned(),
        );
        publisher
            .publish(ocr.clone(), ocr_content)
            .expect("OCR publication");

        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        assert_eq!(
            service
                .revoke_ocr_derived_publications(20)
                .expect("selective OCR revoke"),
            1
        );
        assert_eq!(
            service
                .revoke_ocr_derived_publications(21)
                .expect("idempotent OCR revoke"),
            0
        );
        service
            .read_publication(
                &native.case_id,
                &native.material_id,
                &native.publication_id,
                22,
                None,
                None,
            )
            .expect("native publication remains active");
        assert!(matches!(
            service.read_publication(
                &ocr.case_id,
                &ocr.material_id,
                &ocr.publication_id,
                22,
                None,
                None,
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        let history = service
            .list_publication_history(Some(&native.case_id))
            .expect("history");
        let native_history = history
            .iter()
            .find(|row| row.publication_id == native.publication_id)
            .expect("native history");
        let ocr_history = history
            .iter()
            .find(|row| row.publication_id == ocr.publication_id)
            .expect("OCR history");
        assert_eq!(native_history.revoked_at_unix, None);
        assert_eq!(native_history.revocation_epoch, 0);
        assert_eq!(ocr_history.revoked_at_unix, Some(20));
        assert_eq!(ocr_history.revocation_epoch, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lifecycle_retention_revoke_is_exact_revoke_first_and_crash_recoverable() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let expired_content = b"[PERSON_001] expired approved text";
        let expired = claims(expired_content, 10, 100);
        let expired_binding = "red_00000000000000000000000000000001";

        let protected_content = b"[PERSON_002] legal-hold approved text";
        let mut protected = claims(protected_content, 10, 100);
        protected.material_id =
            MaterialId::parse("mat_00000000000000000000000000000002").expect("material");
        protected.publication_id =
            PublicationId::parse("pub_00000000000000000000000000000002").expect("publication");
        protected.content_sha256 = hash(protected_content);
        protected.content_bytes = protected_content.len() as u64;
        let protected_binding = "red_00000000000000000000000000000002";
        let protected_summary = publisher
            .publish_with_egress_guard_and_lifecycle_binding(
                protected.clone(),
                protected_content,
                ApprovedEgressGuardInputV1::empty(),
                Some(protected_binding),
            )
            .expect("protected lifecycle publication");
        // Publish the expiring generation last. Recovery must not leave this deleted bundle as
        // the revision anchor for the unrelated active generation.
        publisher
            .publish_with_egress_guard_and_lifecycle_binding(
                expired.clone(),
                expired_content,
                ApprovedEgressGuardInputV1::empty(),
                Some(expired_binding),
            )
            .expect("expired lifecycle publication");

        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        let result = service
            .prepare_lifecycle_retention_revocation(
                &BTreeSet::from([expired_binding.to_owned()]),
                20,
                "retention_expired",
            )
            .expect("prepare exact retention revoke");
        assert_eq!(result.newly_revoked, 1);
        assert_eq!(
            result.publication_ids,
            BTreeSet::from([expired.publication_id.clone()])
        );
        assert!(matches!(
            service.read_publication(
                &expired.case_id,
                &expired.material_id,
                &expired.publication_id,
                21,
                None,
                None,
            ),
            Err(WorkspaceError::PublicationRevoked)
        ));
        service
            .read_publication(
                &protected.case_id,
                &protected.material_id,
                &protected.publication_id,
                21,
                None,
                None,
            )
            .expect("unrelated legal-hold publication remains active");
        let expired_directory = root
            .join("cases")
            .join(expired.case_id.as_str())
            .join("approved")
            .join(expired.publication_id.as_str());
        let protected_directory = root
            .join("cases")
            .join(protected.case_id.as_str())
            .join("approved")
            .join(protected.publication_id.as_str());
        assert!(
            expired_directory.is_dir(),
            "revoke precedes physical cleanup"
        );

        let retry = service
            .prepare_lifecycle_retention_revocation(
                &BTreeSet::from([expired_binding.to_owned()]),
                22,
                "retention_expired",
            )
            .expect("idempotent preparation");
        assert_eq!(retry.newly_revoked, 0);
        assert_eq!(retry.publication_ids, result.publication_ids);
        assert_eq!(
            service
                .recover_lifecycle_retention_cleanup(23)
                .expect("physical cleanup recovery"),
            1
        );
        assert!(!expired_directory.exists());
        assert!(protected_directory.is_dir());
        service
            .scan_case_specific_content(
                &protected.case_id,
                &[ApprovedMaterialRefV1 {
                    material_id: protected.material_id.clone(),
                    document_version: protected.document_version,
                    publication_id: protected.publication_id.clone(),
                    manifest_sha256: protected_summary.manifest_sha256,
                }],
                b"synthetic unrelated work product",
                23,
            )
            .expect("unrelated active publication remains a usable revision anchor");
        assert_eq!(
            service
                .recover_lifecycle_retention_cleanup(24)
                .expect("idempotent physical recovery"),
            0
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_signature_and_content_hash_detect_tampering() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[ORG_001] synthetic approved text";
        let claims = claims(content, 10, 100);
        publisher.publish(claims.clone(), content).expect("publish");
        let content_path = root
            .join("cases")
            .join(claims.case_id.as_str())
            .join("approved")
            .join(claims.publication_id.as_str())
            .join("content.bin");
        fs::write(&content_path, b"tampered").expect("tamper fixture");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        assert!(matches!(
            service.read(
                &claims.case_id,
                &claims.material_id,
                1,
                &claims.publication_id,
                20,
                None,
                None,
            ),
            Err(WorkspaceError::ContentMismatch)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn blind_guard_never_serializes_raw_terms_and_matches_short_and_nfkc_forms() {
        let root = test_root();
        let signing = ManifestSigningKey::from_bytes([9_u8; 32], 1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[PERSON_001] approved synthetic text";
        let claims = claims(content, 10, 100);
        let dictionary = ["\u{212b}"];
        let source_terms = ["Confidential Source"];
        let canaries = ["\u{4e95}"];
        let summary = publisher
            .publish_with_egress_guard(
                claims.clone(),
                content,
                ApprovedEgressGuardInputV1 {
                    case_dictionary_terms: &dictionary,
                    source_terms: &source_terms,
                    raw_canary_terms: &canaries,
                },
            )
            .expect("publish with guard");
        let guard_path = root
            .join("cases")
            .join(claims.case_id.as_str())
            .join("approved")
            .join(claims.publication_id.as_str())
            .join("egress-guard.json");
        let guard_bytes = fs::read(&guard_path).expect("guard bytes");
        let guard_text = std::str::from_utf8(&guard_bytes).expect("guard json");
        for raw in dictionary.into_iter().chain(source_terms).chain(canaries) {
            assert!(!guard_text.contains(raw));
        }
        assert!(!guard_text.contains("\u{00c5}"));
        let signed_guard: SignedApprovedEgressGuardV1 =
            strict_json_v1_from_slice(&guard_bytes).expect("strict guard");
        assert_eq!(signed_guard.claims.fingerprints.len(), 3);
        assert!(signed_guard
            .claims
            .fingerprints
            .iter()
            .any(|entry| entry.kind == ApprovedEgressTermKindV1::RawCanary
                && entry.normalized_char_length == 1));

        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");
        let reference = ApprovedMaterialRefV1 {
            material_id: claims.material_id.clone(),
            document_version: claims.document_version,
            publication_id: claims.publication_id.clone(),
            manifest_sha256: summary.manifest_sha256,
        };
        assert_eq!(
            service.scan_case_specific_content(
                &claims.case_id,
                std::slice::from_ref(&reference),
                "prefix A\u{030a} suffix".as_bytes(),
                20,
            ),
            Err(WorkspaceError::ResidualSensitiveContent)
        );
        assert_eq!(
            service.scan_case_specific_content(
                &claims.case_id,
                std::slice::from_ref(&reference),
                "prefix \u{4e95} suffix".as_bytes(),
                20,
            ),
            Err(WorkspaceError::ResidualSensitiveContent)
        );
        service
            .scan_case_specific_content(
                &claims.case_id,
                std::slice::from_ref(&reference),
                b"synthetic clean output",
                20,
            )
            .expect("clean content");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn guard_tamper_and_missing_file_fail_closed() {
        let root = test_root();
        let signing = ManifestSigningKey::generate(1).expect("signer");
        let verifier = signing.verification_key();
        let publisher = WorkspacePublisher::initialize(&root, signing).expect("publisher");
        let content = b"[ORG_001] synthetic approved text";
        let claims = claims(content, 10, 100);
        publisher.publish(claims.clone(), content).expect("publish");
        let guard_path = root
            .join("cases")
            .join(claims.case_id.as_str())
            .join("approved")
            .join(claims.publication_id.as_str())
            .join("egress-guard.json");
        let original = fs::read(&guard_path).expect("guard");
        let service = ApprovedWorkspaceService::open(&root, verifier).expect("service");

        fs::write(&guard_path, b"{}").expect("tamper guard");
        assert!(matches!(
            service.read(
                &claims.case_id,
                &claims.material_id,
                claims.document_version,
                &claims.publication_id,
                20,
                None,
                None,
            ),
            Err(WorkspaceError::ManifestInvalid)
        ));

        fs::write(&guard_path, original).expect("restore guard");
        service
            .read(
                &claims.case_id,
                &claims.material_id,
                claims.document_version,
                &claims.publication_id,
                20,
                None,
                None,
            )
            .expect("restored guard");
        fs::remove_file(&guard_path).expect("remove guard");
        assert!(service
            .read(
                &claims.case_id,
                &claims.material_id,
                claims.document_version,
                &claims.publication_id,
                20,
                None,
                None,
            )
            .is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn blind_fingerprints_are_key_and_case_bound() {
        let content = b"synthetic";
        let first_signer = ManifestSigningKey::from_bytes([4_u8; 32], 1).expect("first signer");
        let second_signer = ManifestSigningKey::from_bytes([5_u8; 32], 1).expect("second signer");
        let first_claims = claims(content, 10, 100);
        let mut second_case_claims = first_claims.clone();
        second_case_claims.case_id =
            CaseId::parse("case_00000000000000000000000000000002").expect("second case");
        let terms = ["synthetic-secret"];
        let first = build_egress_guard(
            &first_signer,
            &first_claims,
            ApprovedEgressGuardInputV1 {
                case_dictionary_terms: &terms,
                ..ApprovedEgressGuardInputV1::empty()
            },
        )
        .expect("first guard");
        let other_case = build_egress_guard(
            &first_signer,
            &second_case_claims,
            ApprovedEgressGuardInputV1 {
                case_dictionary_terms: &terms,
                ..ApprovedEgressGuardInputV1::empty()
            },
        )
        .expect("other case guard");
        let other_key = build_egress_guard(
            &second_signer,
            &first_claims,
            ApprovedEgressGuardInputV1 {
                case_dictionary_terms: &terms,
                ..ApprovedEgressGuardInputV1::empty()
            },
        )
        .expect("other key guard");
        assert_ne!(
            first.claims.fingerprints[0].fingerprint,
            other_case.claims.fingerprints[0].fingerprint
        );
        assert_ne!(
            first.claims.fingerprints[0].fingerprint,
            other_key.claims.fingerprints[0].fingerprint
        );
    }

    #[test]
    fn verifier_cannot_accept_changed_claims_or_wrong_key() {
        let signer = ManifestSigningKey::from_bytes([7_u8; 32], 1).expect("signer");
        let verifier = signer.verification_key();
        let content = b"synthetic";
        let mut signed = signer.sign(claims(content, 10, 100)).expect("signed");
        signed.claims.purpose = "changed".to_owned();
        assert!(verifier.verify(&signed).is_err());

        let other = ManifestSigningKey::from_bytes([8_u8; 32], 1)
            .expect("other signer")
            .verification_key();
        let signed = signer.sign(claims(content, 10, 100)).expect("signed");
        assert!(other.verify(&signed).is_err());
    }
}
