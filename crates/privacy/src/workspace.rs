#![allow(unsafe_code)]

//! Immutable approved-material workspace with recoverable publication transactions.
//!
//! This first implementation is explicitly user-boundary-only. Its HMAC verifier is not a
//! substitute for the planned independent Broker signing identity.

use crate::{
    sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, ApprovedMaterialManifestV1, CaseId,
        MaterialId, PublicationId, Sha256Hex, SignedApprovedMaterialManifestV1,
        WorkspaceIsolationLevel,
    },
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
};

pub const WORKSPACE_SCHEMA_VERSION: u32 = 1;
pub const USER_BOUNDARY_SIGNING_ALGORITHM: &str = "hmac-sha256-user-boundary-v1";
pub const MAX_APPROVED_CONTENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/approved-material-manifest/v1\0";
const BUNDLE_COMMIT_VERSION: &str = "approved-generation-commit-v1";

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
        if content.is_empty() || content.len() > MAX_APPROVED_CONTENT_BYTES {
            return Err(if content.is_empty() {
                WorkspaceError::InvalidInput
            } else {
                WorkspaceError::ContentTooLarge
            });
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
        let manifest_bytes =
            canonical_json_v1(&signed).map_err(|_| WorkspaceError::ManifestInvalid)?;
        if manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(WorkspaceError::ManifestInvalid);
        }
        let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
            .map_err(|_| WorkspaceError::ManifestInvalid)?;
        let document_version_sql = sql_i64(signed.claims.document_version)?;
        let issued_at_sql = sql_i64(signed.claims.issued_at_unix)?;
        let commit = BundleCommitV1 {
            schema_version: BUNDLE_COMMIT_VERSION.to_owned(),
            publication_id: signed.claims.publication_id.clone(),
            manifest_sha256: manifest_sha256.clone(),
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
                manifest_sha256,content_sha256,state,created_at_unix
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,'prepared',?8)",
            params![
                transaction_id,
                signed.claims.case_id.as_str(),
                signed.claims.material_id.as_str(),
                document_version_sql,
                signed.claims.publication_id.as_str(),
                manifest_sha256.as_str(),
                signed.claims.content_sha256.as_str(),
                issued_at_sql
            ],
        )
        .map_err(|_| WorkspaceError::DatabaseFailed)?;

        let stage_result = (|| {
            write_new_file(&staging.join("content.bin"), content)?;
            write_new_file(&staging.join("manifest.json"), &manifest_bytes)?;
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

    pub fn recover(
        &self,
        verifier: &ManifestVerificationKey,
        now_unix: u64,
    ) -> Result<u64, WorkspaceError> {
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
pub struct ApprovedMaterialSummaryV1 {
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub content_sha256: Sha256Hex,
    pub manifest_sha256: Sha256Hex,
    pub expires_at_unix: u64,
}

pub struct VerifiedApprovedMaterial {
    summary: ApprovedMaterialSummaryV1,
    content: Vec<u8>,
}

impl VerifiedApprovedMaterial {
    pub fn summary(&self) -> &ApprovedMaterialSummaryV1 {
        &self.summary
    }

    pub fn content(&self) -> &[u8] {
        &self.content
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

    pub fn list_case_materials(
        &self,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<Vec<ApprovedMaterialSummaryV1>, WorkspaceError> {
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
            let verified = self.read(
                case_id,
                &material_id,
                document_version,
                &publication_id,
                now_unix,
                None,
                None,
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
        let document_version_sql = sql_i64(document_version)?;
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
        let directory = self
            .root
            .cases
            .join(case_id.as_str())
            .join("approved")
            .join(publication_id.as_str());
        let (signed, content, manifest_sha256) = verify_bundle(
            &self.root,
            &directory,
            &self.verifier,
            now_unix,
            expected_destination_scope,
            expected_purpose,
        )?;
        if signed.claims.case_id != *case_id
            || signed.claims.material_id != *material_id
            || signed.claims.document_version != document_version
            || signed.claims.publication_id != *publication_id
        {
            return Err(WorkspaceError::ManifestInvalid);
        }
        Ok(VerifiedApprovedMaterial {
            summary: ApprovedMaterialSummaryV1 {
                case_id: signed.claims.case_id,
                material_id: signed.claims.material_id,
                document_version: signed.claims.document_version,
                publication_id: signed.claims.publication_id,
                content_sha256: signed.claims.content_sha256,
                manifest_sha256,
                expires_at_unix: signed.claims.expires_at_unix,
            },
            content,
        })
    }

    pub fn revoke(
        &self,
        case_id: &CaseId,
        material_id: &MaterialId,
        document_version: u64,
        publication_id: &PublicationId,
        revoked_at_unix: u64,
    ) -> Result<(), WorkspaceError> {
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
}

#[derive(Clone)]
struct ValidatedWorkspaceRoot {
    root: PathBuf,
    cases: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    database: PathBuf,
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
        let layout = Self::from_canonical(canonical);
        for directory in [&layout.cases, &layout.staging, &layout.quarantine] {
            fs::create_dir_all(directory).map_err(|_| WorkspaceError::IoFailed)?;
            platform::mark_not_content_indexed(directory)?;
        }
        Ok(layout)
    }

    fn open(root: &Path) -> Result<Self, WorkspaceError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        platform::validate_fixed_local_root(root)?;
        let canonical = fs::canonicalize(root).map_err(|_| WorkspaceError::InvalidRoot)?;
        let layout = Self::from_canonical(canonical);
        if !layout.cases.is_dir() || !layout.staging.is_dir() || !layout.quarantine.is_dir() {
            return Err(WorkspaceError::InvalidRoot);
        }
        Ok(layout)
    }

    fn from_canonical(root: PathBuf) -> Self {
        Self {
            cases: root.join("cases"),
            staging: root.join(".staging"),
            quarantine: root.join(".quarantine"),
            database: root.join("workspace-state.sqlite"),
            root,
        }
    }
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
             UNIQUE(case_id,material_id,document_version,publication_id)
         );",
    )
    .map_err(|_| WorkspaceError::DatabaseFailed)?;
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
    let db = Connection::open(&root.database).map_err(|_| WorkspaceError::DatabaseFailed)?;
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| WorkspaceError::DatabaseFailed)?;
    Ok(db)
}

type VerifiedBundle = (SignedApprovedMaterialManifestV1, Vec<u8>, Sha256Hex);

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
    let commit_path = directory.join("commit.json");
    validate_controlled_path(root, &content_path, true)?;
    validate_controlled_path(root, &manifest_path, true)?;
    validate_controlled_path(root, &commit_path, true)?;

    let content = read_bounded(&content_path, MAX_APPROVED_CONTENT_BYTES)?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let commit_bytes = read_bounded(&commit_path, MAX_MANIFEST_BYTES)?;
    let signed: SignedApprovedMaterialManifestV1 =
        strict_json_v1_from_slice(&manifest_bytes).map_err(|_| WorkspaceError::ManifestInvalid)?;
    verifier.verify(&signed)?;
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
    let commit: BundleCommitV1 =
        strict_json_v1_from_slice(&commit_bytes).map_err(|_| WorkspaceError::ManifestInvalid)?;
    if commit.schema_version != BUNDLE_COMMIT_VERSION
        || commit.publication_id != signed.claims.publication_id
        || commit.manifest_sha256 != manifest_sha256
        || commit.content_sha256 != signed.claims.content_sha256
        || commit.content_bytes != signed.claims.content_bytes
    {
        return Err(WorkspaceError::ManifestInvalid);
    }
    Ok((signed, content, manifest_sha256))
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
    inner.update(message);
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
    use std::collections::BTreeMap;

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
