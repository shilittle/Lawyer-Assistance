//! Immutable, signed work-product generations sourced only from verified approved materials.

use crate::{
    scan_residual, sha256_hex,
    vault_crypto::fill_random,
    vault_store::{FixedLocalStorageRoot, VaultStoreError},
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, ApprovedMaterialRefV1, CaseId, Sha256Hex,
        WorkProductId, WorkProductManifestV1, WorkspaceInstanceId, WORK_PRODUCT_MANIFEST_VERSION,
    },
    workspace::{
        ApprovedWorkspaceService, ManifestSigningKey, ManifestVerificationKey, WorkspaceError,
        USER_BOUNDARY_SIGNING_ALGORITHM,
    },
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const WORK_PRODUCT_STORE_SCHEMA_VERSION: u32 = 1;
pub const MAX_WORK_PRODUCT_CONTENT_BYTES: usize = 1024 * 1024;
pub const MAX_WORK_PRODUCT_MANIFEST_BYTES: usize = 1024 * 1024;
pub const APPROVED_SOURCE_DESTINATION_SCOPE: &str = "approved_case_workspace";
pub const APPROVED_SOURCE_PURPOSE: &str = "mcp.case_read_approved_material.v1";
const SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/work-product-manifest/v1\0";
const COMMIT_SCHEMA_VERSION: &str = "work-product-generation-commit-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkProductError {
    PlatformUnavailable,
    InvalidRoot,
    UnsafeFilesystem,
    InvalidInput,
    ContentTooLarge,
    ResidualSensitiveContent,
    ApprovedSourceUnavailable,
    ApprovedSourceStale,
    ManifestInvalid,
    SignatureInvalid,
    ContentMismatch,
    VersionConflict,
    IdempotencyConflict,
    AlreadyExists,
    NotAvailable,
    DatabaseFailed,
    IoFailed,
    RecoveryFailed,
}

impl WorkProductError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnavailable => "work_product_platform_unavailable",
            Self::InvalidRoot => "work_product_invalid_root",
            Self::UnsafeFilesystem => "work_product_unsafe_filesystem",
            Self::InvalidInput => "work_product_invalid_input",
            Self::ContentTooLarge => "work_product_content_too_large",
            Self::ResidualSensitiveContent => "work_product_residual_sensitive_content",
            Self::ApprovedSourceUnavailable => "work_product_approved_source_unavailable",
            Self::ApprovedSourceStale => "work_product_approved_source_stale",
            Self::ManifestInvalid => "work_product_manifest_invalid",
            Self::SignatureInvalid => "work_product_signature_invalid",
            Self::ContentMismatch => "work_product_content_mismatch",
            Self::VersionConflict => "work_product_version_conflict",
            Self::IdempotencyConflict => "work_product_idempotency_conflict",
            Self::AlreadyExists => "work_product_generation_already_exists",
            Self::NotAvailable => "work_product_not_available",
            Self::DatabaseFailed => "work_product_database_failed",
            Self::IoFailed => "work_product_io_failed",
            Self::RecoveryFailed => "work_product_recovery_failed",
        }
    }
}

impl fmt::Display for WorkProductError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for WorkProductError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkProductWriteV1 {
    pub task_type: String,
    pub status: String,
    pub source_approved_refs: Vec<ApprovedMaterialRefV1>,
    pub content_media_type: String,
    pub placeholder_policy_version: String,
    pub author_tool: String,
    pub author_tool_version: String,
    pub idempotency_key: String,
}

impl WorkProductWriteV1 {
    fn validate(&self) -> Result<(), WorkProductError> {
        if !safe_token(&self.task_type, 64)
            || !matches!(
                self.task_type.as_str(),
                "case_analysis"
                    | "legal_research"
                    | "draft_pleading"
                    | "evidence_summary"
                    | "timeline"
                    | "citation_review"
            )
            || !matches!(self.status.as_str(), "draft" | "final")
            || !safe_media_type(&self.content_media_type)
            || !safe_token(&self.placeholder_policy_version, 128)
            || !safe_token(&self.author_tool, 128)
            || !safe_token(&self.author_tool_version, 128)
            || !valid_idempotency_key(&self.idempotency_key)
            || self.source_approved_refs.is_empty()
            || self.source_approved_refs.len() > 256
        {
            return Err(WorkProductError::InvalidInput);
        }
        let mut references = self.source_approved_refs.clone();
        references.sort_by(|left, right| {
            left.material_id
                .cmp(&right.material_id)
                .then_with(|| left.document_version.cmp(&right.document_version))
                .then_with(|| left.publication_id.cmp(&right.publication_id))
        });
        references.dedup();
        if references.len() != self.source_approved_refs.len() {
            return Err(WorkProductError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedWorkProductManifestV1 {
    pub claims: WorkProductManifestV1,
    pub canonical_claims_sha256: Sha256Hex,
    pub signing_algorithm: String,
    pub signing_key_id: String,
    pub signing_key_version: u64,
    pub signature: String,
}

impl SignedWorkProductManifestV1 {
    fn validate_structure(&self) -> Result<(), WorkProductError> {
        self.claims
            .validate()
            .map_err(|_| WorkProductError::ManifestInvalid)?;
        if self.signing_algorithm != USER_BOUNDARY_SIGNING_ALGORITHM
            || self.signing_key_id.is_empty()
            || self.signing_key_version == 0
            || self.signature.len() != 64
            || !lower_hex(&self.signature)
        {
            return Err(WorkProductError::ManifestInvalid);
        }
        let canonical =
            canonical_json_v1(&self.claims).map_err(|_| WorkProductError::ManifestInvalid)?;
        if self.canonical_claims_sha256.as_str() != sha256_hex(&canonical) {
            return Err(WorkProductError::ManifestInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedWorkProductV1 {
    pub case_id: CaseId,
    pub work_product_id: WorkProductId,
    pub version: u64,
    pub manifest_sha256: Sha256Hex,
    pub content_sha256: Sha256Hex,
    pub replayed: bool,
}

pub struct VerifiedWorkProductV1 {
    manifest: SignedWorkProductManifestV1,
    manifest_sha256: Sha256Hex,
    content: Vec<u8>,
}

impl VerifiedWorkProductV1 {
    pub fn manifest(&self) -> &SignedWorkProductManifestV1 {
        &self.manifest
    }

    pub fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl fmt::Debug for VerifiedWorkProductV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedWorkProductV1")
            .field("claims", &self.manifest.claims)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

pub struct WorkProductPublisher {
    root: WorkProductRoot,
    workspace_instance_id: WorkspaceInstanceId,
    signer: ManifestSigningKey,
}

impl WorkProductPublisher {
    pub fn initialize(
        root: impl AsRef<Path>,
        workspace_instance_id: WorkspaceInstanceId,
        signer: ManifestSigningKey,
    ) -> Result<Self, WorkProductError> {
        let root = WorkProductRoot::initialize(root.as_ref())?;
        initialize_database(&root, &workspace_instance_id)?;
        Ok(Self {
            root,
            workspace_instance_id,
            signer,
        })
    }

    pub fn create(
        &self,
        case_id: &CaseId,
        request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        self.publish(
            case_id,
            None,
            None,
            request,
            content,
            approved,
            created_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &self,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        expected_parent_version: u64,
        request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        if expected_parent_version == 0 {
            return Err(WorkProductError::InvalidInput);
        }
        self.publish(
            case_id,
            Some(work_product_id),
            Some(expected_parent_version),
            request,
            content,
            approved,
            created_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        case_id: &CaseId,
        requested_work_product_id: Option<&WorkProductId>,
        expected_parent_version: Option<u64>,
        mut request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        request.validate()?;
        if created_at_unix == 0 || content.is_empty() {
            return Err(WorkProductError::InvalidInput);
        }
        if content.len() > MAX_WORK_PRODUCT_CONTENT_BYTES {
            return Err(WorkProductError::ContentTooLarge);
        }
        request.source_approved_refs.sort_by(|left, right| {
            left.material_id
                .cmp(&right.material_id)
                .then_with(|| left.document_version.cmp(&right.document_version))
                .then_with(|| left.publication_id.cmp(&right.publication_id))
        });
        verify_approved_sources(
            case_id,
            &request.source_approved_refs,
            approved,
            created_at_unix,
        )?;
        let residual = scan_residual(content).map_err(|_| WorkProductError::InvalidInput)?;
        if !residual.passed {
            return Err(WorkProductError::ResidualSensitiveContent);
        }
        let residual_scan_hash = Sha256Hex::parse(sha256_hex(
            &canonical_json_v1(&residual).map_err(|_| WorkProductError::InvalidInput)?,
        ))
        .map_err(|_| WorkProductError::InvalidInput)?;
        let content_sha256 =
            Sha256Hex::parse(sha256_hex(content)).map_err(|_| WorkProductError::InvalidInput)?;
        let request_hash = request_hash(
            case_id,
            requested_work_product_id,
            expected_parent_version,
            &request,
            &content_sha256,
            &residual_scan_hash,
        )?;

        let db = open_database(&self.root)?;
        if let Some(replay) = lookup_idempotency(&db, &request.idempotency_key, &request_hash)? {
            return Ok(replay);
        }

        let (work_product_id, version, task_type) = match requested_work_product_id {
            None => (generate_work_product_id()?, 1, request.task_type.clone()),
            Some(work_product_id) => {
                let expected = expected_parent_version.ok_or(WorkProductError::InvalidInput)?;
                let current = latest_committed_version(&db, case_id, work_product_id)?
                    .ok_or(WorkProductError::NotAvailable)?;
                if current != expected {
                    return Err(WorkProductError::VersionConflict);
                }
                let prior = read_bundle(
                    &self.root,
                    &self.signer.verification_key(),
                    case_id,
                    work_product_id,
                    expected,
                )?;
                (
                    work_product_id.clone(),
                    expected
                        .checked_add(1)
                        .ok_or(WorkProductError::VersionConflict)?,
                    prior.manifest.claims.task_type,
                )
            }
        };
        if requested_work_product_id.is_some() && request.task_type != task_type {
            return Err(WorkProductError::InvalidInput);
        }

        let content_bytes =
            u64::try_from(content.len()).map_err(|_| WorkProductError::ContentTooLarge)?;
        let claims = WorkProductManifestV1 {
            schema_version: WORK_PRODUCT_MANIFEST_VERSION.to_owned(),
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            work_product_id: work_product_id.clone(),
            version,
            expected_parent_version,
            task_type,
            status: request.status,
            source_approved_refs: request.source_approved_refs,
            content_media_type: request.content_media_type,
            content_sha256: content_sha256.clone(),
            content_bytes,
            placeholder_policy_version: request.placeholder_policy_version,
            residual_scan_hash,
            author_tool: request.author_tool,
            author_tool_version: request.author_tool_version,
            created_at_unix,
        };
        claims
            .validate()
            .map_err(|_| WorkProductError::ManifestInvalid)?;
        let signed = sign_manifest(&self.signer, claims)?;
        let manifest_bytes =
            canonical_json_v1(&signed).map_err(|_| WorkProductError::ManifestInvalid)?;
        if manifest_bytes.len() > MAX_WORK_PRODUCT_MANIFEST_BYTES {
            return Err(WorkProductError::ManifestInvalid);
        }
        let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
            .map_err(|_| WorkProductError::ManifestInvalid)?;
        let transaction_id = random_hex_id("tx_")?;
        insert_prepared(
            &db,
            case_id,
            &work_product_id,
            version,
            &request.idempotency_key,
            &request_hash,
            &transaction_id,
            &manifest_sha256,
            &content_sha256,
            created_at_unix,
        )?;

        let staging_relative = PathBuf::from(".work-product-staging").join(&transaction_id);
        let staging = self.root.fixed.ensure_directory(&staging_relative)?;
        let final_parent_relative = PathBuf::from("work-products")
            .join(case_id.as_str())
            .join(work_product_id.as_str());
        self.root.fixed.ensure_directory(&final_parent_relative)?;
        let final_relative = final_parent_relative.join(version_directory(version));
        let final_directory = self.root.fixed.validate_new_path(&final_relative)?;
        let commit = WorkProductCommitFileV1 {
            schema_version: COMMIT_SCHEMA_VERSION.to_owned(),
            case_id: case_id.clone(),
            work_product_id: work_product_id.clone(),
            version,
            manifest_sha256: manifest_sha256.clone(),
            content_sha256: content_sha256.clone(),
            content_bytes,
        };
        let commit_bytes =
            canonical_json_v1(&commit).map_err(|_| WorkProductError::ManifestInvalid)?;
        write_new_file(&staging.join("content.bin"), content)?;
        write_new_file(&staging.join("manifest.json"), &manifest_bytes)?;
        write_new_file(&staging.join("commit.json"), &commit_bytes)?;
        sync_directory(&staging)?;
        self.root
            .fixed
            .validate_existing_directory(&staging_relative)?;
        fs::rename(&staging, &final_directory).map_err(|_| WorkProductError::IoFailed)?;
        self.root
            .fixed
            .validate_existing_directory(&final_relative)?;
        sync_directory(
            final_directory
                .parent()
                .ok_or(WorkProductError::UnsafeFilesystem)?,
        )?;
        let changed = db
            .execute(
                "UPDATE work_product_versions SET state='committed'\n                 WHERE case_id=?1 AND work_product_id=?2 AND version=?3\n                   AND transaction_id=?4 AND state='prepared'",
                params![
                    case_id.as_str(),
                    work_product_id.as_str(),
                    sql_i64(version)?,
                    transaction_id
                ],
            )
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        if changed != 1 {
            return Err(WorkProductError::DatabaseFailed);
        }
        Ok(PublishedWorkProductV1 {
            case_id: case_id.clone(),
            work_product_id,
            version,
            manifest_sha256,
            content_sha256,
            replayed: false,
        })
    }

    pub fn recover(&self) -> Result<u64, WorkProductError> {
        let verifier = self.signer.verification_key();
        recover_prepared(&self.root, &verifier)
    }
}

pub struct WorkProductService {
    root: WorkProductRoot,
    workspace_instance_id: WorkspaceInstanceId,
    verifier: ManifestVerificationKey,
}

impl WorkProductService {
    pub fn open(
        root: impl AsRef<Path>,
        workspace_instance_id: WorkspaceInstanceId,
        verifier: ManifestVerificationKey,
    ) -> Result<Self, WorkProductError> {
        let root = WorkProductRoot::open(root.as_ref())?;
        initialize_database(&root, &workspace_instance_id)?;
        Ok(Self {
            root,
            workspace_instance_id,
            verifier,
        })
    }

    pub fn read(
        &self,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        version: u64,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<VerifiedWorkProductV1, WorkProductError> {
        let db = open_database(&self.root)?;
        let state = db
            .query_row(
                "SELECT state FROM work_product_versions\n                 WHERE case_id=?1 AND work_product_id=?2 AND version=?3",
                params![case_id.as_str(), work_product_id.as_str(), sql_i64(version)?],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| WorkProductError::DatabaseFailed)?
            .ok_or(WorkProductError::NotAvailable)?;
        if state != "committed" {
            return Err(WorkProductError::NotAvailable);
        }
        let verified = read_bundle(
            &self.root,
            &self.verifier,
            case_id,
            work_product_id,
            version,
        )?;
        if verified.manifest.claims.workspace_instance_id != self.workspace_instance_id {
            return Err(WorkProductError::ManifestInvalid);
        }
        verify_approved_sources(
            case_id,
            &verified.manifest.claims.source_approved_refs,
            approved,
            now_unix,
        )?;
        Ok(verified)
    }

    pub fn export_manifest(
        &self,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        version: u64,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<SignedWorkProductManifestV1, WorkProductError> {
        Ok(self
            .read(case_id, work_product_id, version, approved, now_unix)?
            .manifest)
    }
}

fn sign_manifest(
    signer: &ManifestSigningKey,
    claims: WorkProductManifestV1,
) -> Result<SignedWorkProductManifestV1, WorkProductError> {
    let canonical = canonical_json_v1(&claims).map_err(|_| WorkProductError::ManifestInvalid)?;
    let signed = SignedWorkProductManifestV1 {
        claims,
        canonical_claims_sha256: Sha256Hex::parse(sha256_hex(&canonical))
            .map_err(|_| WorkProductError::ManifestInvalid)?,
        signing_algorithm: USER_BOUNDARY_SIGNING_ALGORITHM.to_owned(),
        signing_key_id: signer.key_id().to_owned(),
        signing_key_version: signer.key_version(),
        signature: signer.sign_domain(SIGNING_DOMAIN, &canonical),
    };
    signed.validate_structure()?;
    Ok(signed)
}

fn verify_manifest(
    verifier: &ManifestVerificationKey,
    signed: &SignedWorkProductManifestV1,
) -> Result<(), WorkProductError> {
    signed.validate_structure()?;
    let canonical =
        canonical_json_v1(&signed.claims).map_err(|_| WorkProductError::ManifestInvalid)?;
    verifier
        .verify_domain(
            SIGNING_DOMAIN,
            &canonical,
            &signed.signing_algorithm,
            &signed.signing_key_id,
            signed.signing_key_version,
            &signed.signature,
        )
        .map_err(|_| WorkProductError::SignatureInvalid)
}

fn verify_approved_sources(
    case_id: &CaseId,
    references: &[ApprovedMaterialRefV1],
    approved: &ApprovedWorkspaceService,
    now_unix: u64,
) -> Result<(), WorkProductError> {
    for reference in references {
        let verified = approved
            .read(
                case_id,
                &reference.material_id,
                reference.document_version,
                &reference.publication_id,
                now_unix,
                Some(APPROVED_SOURCE_DESTINATION_SCOPE),
                Some(APPROVED_SOURCE_PURPOSE),
            )
            .map_err(map_approved_error)?;
        if verified.summary().manifest_sha256 != reference.manifest_sha256 {
            return Err(WorkProductError::ApprovedSourceStale);
        }
    }
    Ok(())
}

fn map_approved_error(error: WorkspaceError) -> WorkProductError {
    match error {
        WorkspaceError::PublicationExpired | WorkspaceError::PublicationRevoked => {
            WorkProductError::ApprovedSourceStale
        }
        WorkspaceError::PublicationNotAvailable
        | WorkspaceError::DestinationMismatch
        | WorkspaceError::PurposeMismatch => WorkProductError::ApprovedSourceUnavailable,
        _ => WorkProductError::ApprovedSourceUnavailable,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkProductRequestClaims<'a> {
    case_id: &'a CaseId,
    work_product_id: Option<&'a WorkProductId>,
    expected_parent_version: Option<u64>,
    request: &'a WorkProductWriteV1,
    content_sha256: &'a Sha256Hex,
    residual_scan_hash: &'a Sha256Hex,
}

fn request_hash(
    case_id: &CaseId,
    work_product_id: Option<&WorkProductId>,
    expected_parent_version: Option<u64>,
    request: &WorkProductWriteV1,
    content_sha256: &Sha256Hex,
    residual_scan_hash: &Sha256Hex,
) -> Result<Sha256Hex, WorkProductError> {
    let claims = WorkProductRequestClaims {
        case_id,
        work_product_id,
        expected_parent_version,
        request,
        content_sha256,
        residual_scan_hash,
    };
    Sha256Hex::parse(sha256_hex(
        &canonical_json_v1(&claims).map_err(|_| WorkProductError::InvalidInput)?,
    ))
    .map_err(|_| WorkProductError::InvalidInput)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorkProductCommitFileV1 {
    schema_version: String,
    case_id: CaseId,
    work_product_id: WorkProductId,
    version: u64,
    manifest_sha256: Sha256Hex,
    content_sha256: Sha256Hex,
    content_bytes: u64,
}

fn read_bundle(
    root: &WorkProductRoot,
    verifier: &ManifestVerificationKey,
    case_id: &CaseId,
    work_product_id: &WorkProductId,
    version: u64,
) -> Result<VerifiedWorkProductV1, WorkProductError> {
    if version == 0 {
        return Err(WorkProductError::InvalidInput);
    }
    let relative = PathBuf::from("work-products")
        .join(case_id.as_str())
        .join(work_product_id.as_str())
        .join(version_directory(version));
    root.fixed.validate_existing_directory(&relative)?;
    let content_path = root
        .fixed
        .validate_existing_file(&relative.join("content.bin"))?;
    let manifest_path = root
        .fixed
        .validate_existing_file(&relative.join("manifest.json"))?;
    let commit_path = root
        .fixed
        .validate_existing_file(&relative.join("commit.json"))?;
    let content = read_bounded(&content_path, MAX_WORK_PRODUCT_CONTENT_BYTES)?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_WORK_PRODUCT_MANIFEST_BYTES)?;
    let commit_bytes = read_bounded(&commit_path, MAX_WORK_PRODUCT_MANIFEST_BYTES)?;
    let signed: SignedWorkProductManifestV1 = strict_json_v1_from_slice(&manifest_bytes)
        .map_err(|_| WorkProductError::ManifestInvalid)?;
    let commit: WorkProductCommitFileV1 =
        strict_json_v1_from_slice(&commit_bytes).map_err(|_| WorkProductError::ManifestInvalid)?;
    verify_manifest(verifier, &signed)?;
    let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
        .map_err(|_| WorkProductError::ManifestInvalid)?;
    if commit.schema_version != COMMIT_SCHEMA_VERSION
        || commit.case_id != *case_id
        || commit.work_product_id != *work_product_id
        || commit.version != version
        || commit.manifest_sha256 != manifest_sha256
        || commit.content_sha256.as_str() != sha256_hex(&content)
        || commit.content_bytes != u64::try_from(content.len()).unwrap_or(u64::MAX)
        || signed.claims.case_id != *case_id
        || signed.claims.work_product_id != *work_product_id
        || signed.claims.version != version
        || signed.claims.content_sha256 != commit.content_sha256
        || signed.claims.content_bytes != commit.content_bytes
    {
        return Err(WorkProductError::ContentMismatch);
    }
    Ok(VerifiedWorkProductV1 {
        manifest: signed,
        manifest_sha256,
        content,
    })
}

#[derive(Clone)]
struct WorkProductRoot {
    fixed: FixedLocalStorageRoot,
    database: PathBuf,
}

impl WorkProductRoot {
    fn initialize(root: &Path) -> Result<Self, WorkProductError> {
        let fixed = FixedLocalStorageRoot::initialize(root)?;
        for relative in [
            "work-products",
            ".work-product-staging",
            ".work-product-quarantine",
        ] {
            fixed.ensure_directory(Path::new(relative))?;
        }
        let database = fixed.canonical_root().join("work-products.sqlite");
        Ok(Self { fixed, database })
    }

    fn open(root: &Path) -> Result<Self, WorkProductError> {
        let fixed = FixedLocalStorageRoot::open(root)?;
        for relative in [
            "work-products",
            ".work-product-staging",
            ".work-product-quarantine",
        ] {
            fixed.validate_existing_directory(Path::new(relative))?;
        }
        let database = fixed.validate_existing_file(Path::new("work-products.sqlite"))?;
        Ok(Self { fixed, database })
    }
}

fn initialize_database(
    root: &WorkProductRoot,
    workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), WorkProductError> {
    let db = open_database(root)?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;\n         PRAGMA synchronous=FULL;\n         PRAGMA foreign_keys=ON;\n         CREATE TABLE IF NOT EXISTS work_product_meta(\n           singleton INTEGER PRIMARY KEY CHECK(singleton=1),\n           schema_version INTEGER NOT NULL,\n           workspace_instance_id TEXT NOT NULL\n         ) STRICT;\n         CREATE TABLE IF NOT EXISTS work_product_versions(\n           case_id TEXT NOT NULL,\n           work_product_id TEXT NOT NULL,\n           version INTEGER NOT NULL CHECK(version > 0),\n           state TEXT NOT NULL CHECK(state IN ('prepared','committed','quarantined')),\n           idempotency_key TEXT NOT NULL UNIQUE,\n           request_sha256 TEXT NOT NULL,\n           transaction_id TEXT NOT NULL UNIQUE,\n           manifest_sha256 TEXT NOT NULL,\n           content_sha256 TEXT NOT NULL,\n           created_at_unix INTEGER NOT NULL CHECK(created_at_unix > 0),\n           PRIMARY KEY(case_id,work_product_id,version)\n         ) STRICT;",
    )
    .map_err(|_| WorkProductError::DatabaseFailed)?;
    let existing = db
        .query_row(
            "SELECT schema_version, workspace_instance_id FROM work_product_meta WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    match existing {
        Some((version, stored_workspace)) => {
            if version != i64::from(WORK_PRODUCT_STORE_SCHEMA_VERSION)
                || stored_workspace != workspace_instance_id.as_str()
            {
                return Err(WorkProductError::DatabaseFailed);
            }
        }
        None => {
            db.execute(
                "INSERT INTO work_product_meta(singleton,schema_version,workspace_instance_id) VALUES(1,1,?)",
                [workspace_instance_id.as_str()],
            )
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        }
    }
    let row_count = db
        .query_row("SELECT COUNT(*) FROM work_product_meta", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    if row_count != 1 {
        return Err(WorkProductError::DatabaseFailed);
    }
    Ok(())
}

fn open_database(root: &WorkProductRoot) -> Result<Connection, WorkProductError> {
    if root.database.exists() {
        root.fixed
            .validate_existing_file(Path::new("work-products.sqlite"))?;
    } else {
        root.fixed
            .validate_new_path(Path::new("work-products.sqlite"))?;
    }
    let db = Connection::open(&root.database).map_err(|_| WorkProductError::DatabaseFailed)?;
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    Ok(db)
}

#[allow(clippy::too_many_arguments)]
fn insert_prepared(
    db: &Connection,
    case_id: &CaseId,
    work_product_id: &WorkProductId,
    version: u64,
    idempotency_key: &str,
    request_hash: &Sha256Hex,
    transaction_id: &str,
    manifest_hash: &Sha256Hex,
    content_hash: &Sha256Hex,
    created_at_unix: u64,
) -> Result<(), WorkProductError> {
    db.execute(
        "INSERT INTO work_product_versions(\n           case_id,work_product_id,version,state,idempotency_key,request_sha256,\n           transaction_id,manifest_sha256,content_sha256,created_at_unix\n         ) VALUES(?1,?2,?3,'prepared',?4,?5,?6,?7,?8,?9)",
        params![
            case_id.as_str(),
            work_product_id.as_str(),
            sql_i64(version)?,
            idempotency_key,
            request_hash.as_str(),
            transaction_id,
            manifest_hash.as_str(),
            content_hash.as_str(),
            sql_i64(created_at_unix)?
        ],
    )
    .map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            WorkProductError::AlreadyExists
        } else {
            WorkProductError::DatabaseFailed
        }
    })?;
    Ok(())
}

fn lookup_idempotency(
    db: &Connection,
    idempotency_key: &str,
    request_hash: &Sha256Hex,
) -> Result<Option<PublishedWorkProductV1>, WorkProductError> {
    let row = db
        .query_row(
            "SELECT case_id,work_product_id,version,state,request_sha256,manifest_sha256,content_sha256\n             FROM work_product_versions WHERE idempotency_key=?1",
            params![idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.4 != request_hash.as_str() {
        return Err(WorkProductError::IdempotencyConflict);
    }
    if row.3 != "committed" {
        return Err(WorkProductError::NotAvailable);
    }
    Ok(Some(PublishedWorkProductV1 {
        case_id: CaseId::parse(row.0).map_err(|_| WorkProductError::DatabaseFailed)?,
        work_product_id: WorkProductId::parse(row.1)
            .map_err(|_| WorkProductError::DatabaseFailed)?,
        version: sql_u64(row.2)?,
        manifest_sha256: Sha256Hex::parse(row.5).map_err(|_| WorkProductError::DatabaseFailed)?,
        content_sha256: Sha256Hex::parse(row.6).map_err(|_| WorkProductError::DatabaseFailed)?,
        replayed: true,
    }))
}

fn latest_committed_version(
    db: &Connection,
    case_id: &CaseId,
    work_product_id: &WorkProductId,
) -> Result<Option<u64>, WorkProductError> {
    let value = db
        .query_row(
            "SELECT MAX(version) FROM work_product_versions\n             WHERE case_id=?1 AND work_product_id=?2 AND state='committed'",
            params![case_id.as_str(), work_product_id.as_str()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    value.map(sql_u64).transpose()
}

fn recover_prepared(
    root: &WorkProductRoot,
    verifier: &ManifestVerificationKey,
) -> Result<u64, WorkProductError> {
    let db = open_database(root)?;
    let rows = {
        let mut statement = db
            .prepare(
                "SELECT case_id,work_product_id,version,transaction_id\n                 FROM work_product_versions WHERE state='prepared'\n                 ORDER BY created_at_unix,transaction_id",
            )
            .map_err(|_| WorkProductError::RecoveryFailed)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| WorkProductError::RecoveryFailed)?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkProductError::RecoveryFailed)?
    };
    let mut recovered = 0_u64;
    for (case_id, work_product_id, version, transaction_id) in rows {
        let case_id = CaseId::parse(case_id).map_err(|_| WorkProductError::RecoveryFailed)?;
        let work_product_id =
            WorkProductId::parse(work_product_id).map_err(|_| WorkProductError::RecoveryFailed)?;
        let version = sql_u64(version)?;
        let final_relative = PathBuf::from("work-products")
            .join(case_id.as_str())
            .join(work_product_id.as_str())
            .join(version_directory(version));
        if root
            .fixed
            .validate_existing_directory(&final_relative)
            .is_ok()
            && read_bundle(root, verifier, &case_id, &work_product_id, version).is_ok()
        {
            db.execute(
                "UPDATE work_product_versions SET state='committed'\n                 WHERE transaction_id=?1 AND state='prepared'",
                params![transaction_id],
            )
            .map_err(|_| WorkProductError::RecoveryFailed)?;
            recovered = recovered.saturating_add(1);
            continue;
        }
        let staging_relative = PathBuf::from(".work-product-staging").join(&transaction_id);
        if let Ok(staging) = root.fixed.validate_existing_directory(&staging_relative) {
            let quarantine_relative =
                PathBuf::from(".work-product-quarantine").join(&transaction_id);
            let quarantine = root.fixed.validate_new_path(&quarantine_relative)?;
            fs::rename(staging, quarantine).map_err(|_| WorkProductError::RecoveryFailed)?;
        }
        db.execute(
            "UPDATE work_product_versions SET state='quarantined'\n             WHERE transaction_id=?1 AND state='prepared'",
            params![transaction_id],
        )
        .map_err(|_| WorkProductError::RecoveryFailed)?;
    }
    Ok(recovered)
}

fn generate_work_product_id() -> Result<WorkProductId, WorkProductError> {
    WorkProductId::parse(random_hex_id("wp_")?).map_err(|_| WorkProductError::InvalidInput)
}

fn random_hex_id(prefix: &str) -> Result<String, WorkProductError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes).map_err(|_| WorkProductError::PlatformUnavailable)?;
    let mut value = String::with_capacity(prefix.len() + 32);
    value.push_str(prefix);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    Ok(value)
}

fn version_directory(version: u64) -> String {
    format!("v{version:020}")
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), WorkProductError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| WorkProductError::IoFailed)?;
    file.write_all(bytes)
        .map_err(|_| WorkProductError::IoFailed)?;
    file.sync_all().map_err(|_| WorkProductError::IoFailed)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, WorkProductError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkProductError::NotAvailable)?;
    let length = usize::try_from(metadata.len()).map_err(|_| WorkProductError::ContentTooLarge)?;
    if length == 0 || length > maximum {
        return Err(WorkProductError::ContentTooLarge);
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(|_| WorkProductError::NotAvailable)?
        .take(u64::try_from(maximum).map_err(|_| WorkProductError::ContentTooLarge)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkProductError::IoFailed)?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(WorkProductError::ContentTooLarge);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), WorkProductError> {
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WorkProductError::IoFailed)
    }
}

fn sql_i64(value: u64) -> Result<i64, WorkProductError> {
    i64::try_from(value).map_err(|_| WorkProductError::InvalidInput)
}

fn sql_u64(value: i64) -> Result<u64, WorkProductError> {
    u64::try_from(value).map_err(|_| WorkProductError::DatabaseFailed)
}

fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn safe_media_type(value: &str) -> bool {
    matches!(value, "text/plain" | "text/markdown" | "application/json")
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl From<VaultStoreError> for WorkProductError {
    fn from(error: VaultStoreError) -> Self {
        match error {
            VaultStoreError::PlatformUnavailable => Self::PlatformUnavailable,
            VaultStoreError::InvalidRoot => Self::InvalidRoot,
            VaultStoreError::UnsafeFilesystem => Self::UnsafeFilesystem,
            VaultStoreError::AlreadyExists => Self::AlreadyExists,
            VaultStoreError::ObjectNotAvailable => Self::NotAvailable,
            VaultStoreError::DatabaseFailed => Self::DatabaseFailed,
            _ => Self::IoFailed,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        vnext::{
            ApprovalMode, ApprovedMaterialManifestV1, MaterialId, PublicationId, ReceiptId,
            WorkspaceIsolationLevel, APPROVED_CLASSIFICATION, APPROVED_MATERIAL_MANIFEST_VERSION,
        },
        workspace::WorkspacePublisher,
    };
    use std::collections::BTreeMap;

    fn hash(seed: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(sha256_hex(seed)).expect("hash")
    }

    fn ids() -> (WorkspaceInstanceId, CaseId, MaterialId, PublicationId) {
        (
            WorkspaceInstanceId::parse("ws_00000000000000000000000000000001").expect("ws"),
            CaseId::parse("case_00000000000000000000000000000001").expect("case"),
            MaterialId::parse("mat_00000000000000000000000000000001").expect("material"),
            PublicationId::parse("pub_00000000000000000000000000000001").expect("publication"),
        )
    }

    fn approved_claims(content: &[u8]) -> ApprovedMaterialManifestV1 {
        let (workspace_instance_id, case_id, material_id, publication_id) = ids();
        ApprovedMaterialManifestV1 {
            schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
            classification: APPROVED_CLASSIFICATION.to_owned(),
            workspace_instance_id,
            case_id,
            material_id,
            document_version: 1,
            publication_id,
            content_media_type: "text/plain".to_owned(),
            content_sha256: hash(content),
            content_bytes: content.len() as u64,
            source_sha256: hash(b"source"),
            extraction_sha256: hash(b"extraction"),
            ocr_output_sha256: None,
            finding_summary_hash: hash(b"findings"),
            hard_gate_evaluation_hash: hash(b"gates"),
            policy_id: "strict".to_owned(),
            policy_version: 1,
            policy_sha256: hash(b"policy"),
            detector_versions: BTreeMap::from([("rules".to_owned(), "v1".to_owned())]),
            model_versions: BTreeMap::new(),
            worker_sha256: None,
            model_manifest_sha256: None,
            qualification_report_id: Some("native-qualified".to_owned()),
            calibration_evidence_version: None,
            dictionary_revision_hash: hash(b"dictionary"),
            mapping_revision_hash: hash(b"mapping"),
            approval_mode: ApprovalMode::Human,
            readiness_score: 100,
            unresolved_p0: 0,
            unresolved_p1: 0,
            unresolved_p2: 0,
            destination_scope: APPROVED_SOURCE_DESTINATION_SCOPE.to_owned(),
            purpose: APPROVED_SOURCE_PURPOSE.to_owned(),
            workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
            issued_at_unix: 10,
            expires_at_unix: 10_000,
            receipt_id: ReceiptId::parse("rct_00000000000000000000000000000001").expect("receipt"),
            receipt_nonce: "synthetic-nonce".to_owned(),
            revocation_epoch: 0,
        }
    }

    fn request(reference: ApprovedMaterialRefV1, key: &str) -> WorkProductWriteV1 {
        WorkProductWriteV1 {
            task_type: "case_analysis".to_owned(),
            status: "draft".to_owned(),
            source_approved_refs: vec![reference],
            content_media_type: "text/markdown".to_owned(),
            placeholder_policy_version: "placeholder-v1".to_owned(),
            author_tool: "case_write_work_product".to_owned(),
            author_tool_version: "1".to_owned(),
            idempotency_key: key.to_owned(),
        }
    }

    struct Fixture {
        root: PathBuf,
        approved_root: PathBuf,
        workspace_id: WorkspaceInstanceId,
        case_id: CaseId,
        material_id: MaterialId,
        publication_id: PublicationId,
        manifest_hash: Sha256Hex,
        approved_service: ApprovedWorkspaceService,
        work_publisher: WorkProductPublisher,
        work_verifier: ManifestVerificationKey,
    }

    fn fixture() -> Fixture {
        let mut random = [0_u8; 16];
        fill_random(&mut random).expect("random");
        let base = std::env::temp_dir().join(format!("la-work-product-{}", sha256_hex(&random)));
        let approved_root = base.join("approved-workspace");
        let root = base.join("work-product-workspace");
        let source_signer = ManifestSigningKey::generate(1).expect("source signer");
        let source_verifier = source_signer.verification_key();
        let source_publisher = WorkspacePublisher::initialize(&approved_root, source_signer)
            .expect("source publisher");
        let content = b"[PERSON_001] approved synthetic source";
        let claims = approved_claims(content);
        let published = source_publisher
            .publish(claims.clone(), content)
            .expect("approved publish");
        let approved_service =
            ApprovedWorkspaceService::open(&approved_root, source_verifier).expect("source reader");
        let work_signer = ManifestSigningKey::generate(1).expect("work signer");
        let work_verifier = work_signer.verification_key();
        let work_publisher = WorkProductPublisher::initialize(
            &root,
            claims.workspace_instance_id.clone(),
            work_signer,
        )
        .expect("work publisher");
        Fixture {
            root,
            approved_root,
            workspace_id: claims.workspace_instance_id,
            case_id: claims.case_id,
            material_id: claims.material_id,
            publication_id: claims.publication_id,
            manifest_hash: published.manifest_sha256,
            approved_service,
            work_publisher,
            work_verifier,
        }
    }

    fn reference(fixture: &Fixture) -> ApprovedMaterialRefV1 {
        ApprovedMaterialRefV1 {
            material_id: fixture.material_id.clone(),
            document_version: 1,
            publication_id: fixture.publication_id.clone(),
            manifest_sha256: fixture.manifest_hash.clone(),
        }
    }

    #[test]
    fn immutable_create_update_read_and_idempotent_replay() {
        let fixture = fixture();
        let content = b"synthetic approved work product";
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "create-key-00000001"),
                content,
                &fixture.approved_service,
                100,
            )
            .expect("create");
        let replayed = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "create-key-00000001"),
                content,
                &fixture.approved_service,
                100,
            )
            .expect("replay");
        assert_eq!(created.work_product_id, replayed.work_product_id);
        assert!(replayed.replayed);

        let updated = fixture
            .work_publisher
            .update(
                &fixture.case_id,
                &created.work_product_id,
                1,
                request(reference(&fixture), "update-key-00000001"),
                b"synthetic approved work product revision",
                &fixture.approved_service,
                101,
            )
            .expect("update");
        assert_eq!(updated.version, 2);
        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_verifier,
        )
        .expect("reader");
        let verified = reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                2,
                &fixture.approved_service,
                200,
            )
            .expect("read");
        assert_eq!(
            verified.content(),
            b"synthetic approved work product revision"
        );
        assert_eq!(verified.manifest().claims.expected_parent_version, Some(1));
        fs::remove_dir_all(
            fixture
                .root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn version_idempotency_residual_and_source_revocation_fail_closed() {
        let fixture = fixture();
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "create-key-00000002"),
                b"synthetic approved work product",
                &fixture.approved_service,
                100,
            )
            .expect("create");
        assert_eq!(
            fixture.work_publisher.update(
                &fixture.case_id,
                &created.work_product_id,
                2,
                request(reference(&fixture), "update-key-00000002"),
                b"synthetic revision",
                &fixture.approved_service,
                101,
            ),
            Err(WorkProductError::VersionConflict)
        );
        assert_eq!(
            fixture.work_publisher.create(
                &fixture.case_id,
                request(reference(&fixture), "create-key-00000003"),
                b"identity number: 11010519491231002X",
                &fixture.approved_service,
                102,
            ),
            Err(WorkProductError::ResidualSensitiveContent)
        );
        fixture
            .approved_service
            .revoke(
                &fixture.case_id,
                &fixture.material_id,
                1,
                &fixture.publication_id,
                103,
            )
            .expect("revoke source");
        let reader =
            WorkProductService::open(&fixture.root, fixture.workspace_id, fixture.work_verifier)
                .expect("reader");
        assert!(matches!(
            reader.read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            ),
            Err(WorkProductError::ApprovedSourceStale)
        ));
        fs::remove_dir_all(
            fixture
                .approved_root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }
    #[test]
    fn work_product_database_is_bound_to_workspace_instance() {
        let fixture = fixture();
        let wrong_workspace = WorkspaceInstanceId::parse("ws_00000000000000000000000000000002")
            .expect("wrong workspace");
        assert!(matches!(
            WorkProductService::open(&fixture.root, wrong_workspace, fixture.work_verifier),
            Err(WorkProductError::DatabaseFailed)
        ));
        fs::remove_dir_all(
            fixture
                .approved_root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }
}
