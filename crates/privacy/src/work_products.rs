//! Immutable, signed work-product generations sourced only from verified approved materials.

use crate::{
    scan_residual, sha256_hex,
    vault_crypto::{
        fill_random, open, seal, unwrap_case_key, wrap_case_key, AeadSealedV1, SecretKey32,
        VaultCryptoError, GCM_NONCE_BYTES, GCM_TAG_BYTES, VAULT_CRYPTO_SUITE,
        VAULT_KEY_WRAP_PROVIDER,
    },
    vault_store::{validate_fixed_local_regular_file, FixedLocalStorageRoot, VaultStoreError},
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, ApprovedMaterialRefV1, CaseId, PublicationId,
        Sha256Hex, WorkProductId, WorkProductManifestV1, WorkspaceInstanceId,
        WORK_PRODUCT_MANIFEST_VERSION,
    },
    workspace::{
        ApprovedWorkspaceOperationGuard, ApprovedWorkspaceService, ManifestSigningKey,
        ManifestVerificationKey, WorkspaceError, USER_BOUNDARY_SIGNING_ALGORITHM,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

pub const WORK_PRODUCT_STORE_SCHEMA_VERSION: u32 = 1;
pub const MAX_WORK_PRODUCT_CONTENT_BYTES: usize = 1024 * 1024;
pub const MAX_WORK_PRODUCT_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_WORK_PRODUCT_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
pub const APPROVED_SOURCE_DESTINATION_SCOPE: &str = "approved_case_workspace";
pub const APPROVED_SOURCE_PURPOSE: &str = "mcp.case_read_approved_material.v1";
const SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/work-product-manifest/v1\0";
const COMMIT_SCHEMA_VERSION: &str = "work-product-generation-commit-v2";
const CONTENT_ENVELOPE_SCHEMA_VERSION: &str = "work-product-content-envelope-v1";
const CONTENT_AAD_SCHEMA_VERSION: &str = "work-product-content-aad-v1";
const CONTENT_ENVELOPE_FILE: &str = "content.envelope.json";
const MANIFEST_FILE: &str = "manifest.json";
const COMMIT_FILE: &str = "commit.json";
const MAX_WRAPPED_DATA_KEY_BYTES: usize = 64 * 1024;

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
    Revoked,
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
            Self::Revoked => "work_product_revoked",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagram_spec_sha256: Option<Sha256Hex>,
    pub placeholder_policy_version: String,
    pub author_tool: String,
    pub author_tool_version: String,
    pub idempotency_key: String,
}

impl WorkProductWriteV1 {
    fn validate(&self) -> Result<(), WorkProductError> {
        let diagram_binding_is_valid = if self.task_type == "legal_diagram" {
            self.content_media_type == "text/html"
                && self.diagram_spec_sha256.is_some()
                && matches!(
                    self.author_tool.as_str(),
                    "diagram.render" | "diagram.update"
                )
        } else {
            self.diagram_spec_sha256.is_none()
                && !matches!(
                    self.author_tool.as_str(),
                    "diagram.render" | "diagram.update"
                )
        };
        if !safe_token(&self.task_type, 64)
            || !matches!(
                self.task_type.as_str(),
                "case_analysis"
                    | "legal_research"
                    | "draft_pleading"
                    | "evidence_summary"
                    | "timeline"
                    | "citation_review"
                    | "legal_diagram"
            )
            || !matches!(self.status.as_str(), "draft" | "final")
            || !safe_media_type(&self.content_media_type)
            || !safe_token(&self.placeholder_policy_version, 128)
            || !safe_token(&self.author_tool, 128)
            || !safe_token(&self.author_tool_version, 128)
            || !diagram_binding_is_valid
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkProductSummaryV1 {
    pub case_id: CaseId,
    pub work_product_id: WorkProductId,
    pub version: u64,
    pub task_type: String,
    pub status: String,
    pub manifest_sha256: Sha256Hex,
    pub content_sha256: Sha256Hex,
    pub created_at_unix: u64,
}

pub struct VerifiedWorkProductV1 {
    manifest: SignedWorkProductManifestV1,
    manifest_sha256: Sha256Hex,
    content: SensitiveContent,
}

impl VerifiedWorkProductV1 {
    pub fn manifest(&self) -> &SignedWorkProductManifestV1 {
        &self.manifest
    }

    pub fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_slice()
    }
}

impl Drop for VerifiedWorkProductV1 {
    fn drop(&mut self) {
        self.content.zeroize();
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

struct SensitiveContent(Vec<u8>);

impl SensitiveContent {
    fn new(content: Vec<u8>) -> Self {
        Self(content)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SensitiveContent {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SensitiveContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveContent")
            .field("bytes", &self.len())
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

    pub fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub fn create(
        &self,
        case_id: &CaseId,
        request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.create_locked(
            &operation,
            case_id,
            request,
            content,
            approved,
            created_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        self.publish_locked(
            operation,
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
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.update_locked(
            &operation,
            case_id,
            work_product_id,
            expected_parent_version,
            request,
            content,
            approved,
            created_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
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
        self.publish_locked(
            operation,
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
    fn publish_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        requested_work_product_id: Option<&WorkProductId>,
        expected_parent_version: Option<u64>,
        mut request: WorkProductWriteV1,
        content: &[u8],
        approved: &ApprovedWorkspaceService,
        created_at_unix: u64,
    ) -> Result<PublishedWorkProductV1, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
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
        verify_approved_sources_locked(
            operation,
            case_id,
            &self.workspace_instance_id,
            &request.source_approved_refs,
            approved,
            created_at_unix,
        )?;
        approved
            .scan_case_specific_content_locked(
                operation,
                case_id,
                &request.source_approved_refs,
                content,
                created_at_unix,
            )
            .map_err(map_approved_error)?;
        let residual = scan_residual(content).map_err(|_| WorkProductError::InvalidInput)?;
        if !residual.passed {
            return Err(WorkProductError::ResidualSensitiveContent);
        }
        approved
            .scan_case_specific_content_locked(
                operation,
                case_id,
                &request.source_approved_refs,
                content,
                created_at_unix,
            )
            .map_err(map_approved_error)?;
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
            read_bundle(
                &self.root,
                &self.signer.verification_key(),
                &self.workspace_instance_id,
                &replay.case_id,
                &replay.work_product_id,
                replay.version,
            )?;
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
                    &self.workspace_instance_id,
                    case_id,
                    work_product_id,
                    expected,
                )?;
                (
                    work_product_id.clone(),
                    expected
                        .checked_add(1)
                        .ok_or(WorkProductError::VersionConflict)?,
                    prior.manifest.claims.task_type.clone(),
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
            diagram_spec_sha256: request.diagram_spec_sha256,
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
        let envelope_bytes = seal_work_product_content(&signed, &manifest_sha256, content)?;
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
        write_new_file(&staging.join(CONTENT_ENVELOPE_FILE), &envelope_bytes)?;
        write_new_file(&staging.join(MANIFEST_FILE), &manifest_bytes)?;
        write_new_file(&staging.join(COMMIT_FILE), &commit_bytes)?;
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

    pub fn recover(&self, approved: &ApprovedWorkspaceService) -> Result<u64, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.recover_locked(&operation, approved)
    }

    pub fn recover_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        approved: &ApprovedWorkspaceService,
    ) -> Result<u64, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
        let verifier = self.signer.verification_key();
        recover_prepared(&self.root, &verifier, &self.workspace_instance_id)
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

    pub fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub fn list_case(
        &self,
        case_id: &CaseId,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<Vec<WorkProductSummaryV1>, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.list_case_locked(&operation, case_id, approved, now_unix)
    }

    pub fn list_case_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<Vec<WorkProductSummaryV1>, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
        let db = open_database(&self.root)?;
        let mut statement = db
            .prepare(
                "SELECT work_product_id,version FROM work_product_versions
                 WHERE case_id=?1 AND state='committed' AND revoked_at_unix IS NULL
                 ORDER BY work_product_id,version",
            )
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        let rows = statement
            .query_map(params![case_id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|_| WorkProductError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        let mut output = Vec::with_capacity(rows.len());
        for (work_product_id, version) in rows {
            let work_product_id = WorkProductId::parse(work_product_id)
                .map_err(|_| WorkProductError::DatabaseFailed)?;
            let version = sql_u64(version)?;
            let verified = self.read_locked(
                operation,
                case_id,
                &work_product_id,
                version,
                approved,
                now_unix,
            )?;
            output.push(WorkProductSummaryV1 {
                case_id: case_id.clone(),
                work_product_id,
                version,
                task_type: verified.manifest.claims.task_type.clone(),
                status: verified.manifest.claims.status.clone(),
                manifest_sha256: verified.manifest_sha256.clone(),
                content_sha256: verified.manifest.claims.content_sha256.clone(),
                created_at_unix: verified.manifest.claims.created_at_unix,
            });
        }
        Ok(output)
    }

    pub fn read(
        &self,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        version: u64,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<VerifiedWorkProductV1, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.read_locked(
            &operation,
            case_id,
            work_product_id,
            version,
            approved,
            now_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        version: u64,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<VerifiedWorkProductV1, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
        let version_sql = sql_i64(version)?;
        let db = open_database(&self.root)?;
        ensure_work_product_active(&db, case_id, work_product_id, version_sql)?;
        let verified = read_bundle(
            &self.root,
            &self.verifier,
            &self.workspace_instance_id,
            case_id,
            work_product_id,
            version,
        )?;
        if verified.manifest.claims.workspace_instance_id != self.workspace_instance_id {
            return Err(WorkProductError::ManifestInvalid);
        }
        verify_approved_sources_locked(
            operation,
            case_id,
            &self.workspace_instance_id,
            &verified.manifest.claims.source_approved_refs,
            approved,
            now_unix,
        )?;
        approved
            .scan_case_specific_content_locked(
                operation,
                case_id,
                &verified.manifest.claims.source_approved_refs,
                verified.content(),
                now_unix,
            )
            .map_err(map_approved_error)?;
        ensure_work_product_active(&db, case_id, work_product_id, version_sql)?;
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
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.export_manifest_locked(
            &operation,
            case_id,
            work_product_id,
            version,
            approved,
            now_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_manifest_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        work_product_id: &WorkProductId,
        version: u64,
        approved: &ApprovedWorkspaceService,
        now_unix: u64,
    ) -> Result<SignedWorkProductManifestV1, WorkProductError> {
        Ok(self
            .read_locked(
                operation,
                case_id,
                work_product_id,
                version,
                approved,
                now_unix,
            )?
            .manifest
            .clone())
    }

    /// Revoke-first phase for work-product versions derived from an exact set of approved
    /// publications. Signed manifests are verified before any journal mutation.
    pub fn prepare_retention_revocation_by_sources(
        &self,
        approved: &ApprovedWorkspaceService,
        source_publication_ids: &BTreeSet<PublicationId>,
        revoked_at_unix: u64,
        reason_code: &str,
    ) -> Result<u64, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.prepare_retention_revocation_by_sources_locked(
            &operation,
            approved,
            source_publication_ids,
            revoked_at_unix,
            reason_code,
        )
    }

    pub fn prepare_retention_revocation_by_sources_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        approved: &ApprovedWorkspaceService,
        source_publication_ids: &BTreeSet<PublicationId>,
        revoked_at_unix: u64,
        reason_code: &str,
    ) -> Result<u64, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
        if revoked_at_unix == 0 || reason_code.is_empty() || reason_code.len() > 128 {
            return Err(WorkProductError::InvalidInput);
        }
        if source_publication_ids.is_empty() {
            return Ok(0);
        }
        let mut db = open_database(&self.root)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT case_id,work_product_id,version,revoked_at_unix
                     FROM work_product_versions WHERE state='committed'
                     ORDER BY case_id,work_product_id,version",
                )
                .map_err(|_| WorkProductError::DatabaseFailed)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })
                .map_err(|_| WorkProductError::DatabaseFailed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WorkProductError::DatabaseFailed)?;
            rows
        };
        let mut newly_revoked = 0_u64;
        for (case_id, work_product_id, version, revoked_at) in rows {
            let case_id = CaseId::parse(case_id).map_err(|_| WorkProductError::DatabaseFailed)?;
            let work_product_id = WorkProductId::parse(work_product_id)
                .map_err(|_| WorkProductError::DatabaseFailed)?;
            let version = sql_u64(version)?;
            let cleanup_state = transaction
                .query_row(
                    "SELECT state FROM work_product_retention_cleanup
                     WHERE case_id=?1 AND work_product_id=?2 AND version=?3",
                    params![
                        case_id.as_str(),
                        work_product_id.as_str(),
                        sql_i64(version)?
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| WorkProductError::DatabaseFailed)?;
            let affected = if cleanup_state.is_some() {
                true
            } else {
                let verified = read_bundle(
                    &self.root,
                    &self.verifier,
                    &self.workspace_instance_id,
                    &case_id,
                    &work_product_id,
                    version,
                )?;
                verified
                    .manifest
                    .claims
                    .source_approved_refs
                    .iter()
                    .any(|source| source_publication_ids.contains(&source.publication_id))
            };
            if !affected {
                continue;
            }
            if revoked_at.is_none() {
                let changed = transaction
                    .execute(
                        "UPDATE work_product_versions SET revoked_at_unix=?4
                         WHERE case_id=?1 AND work_product_id=?2 AND version=?3
                           AND state='committed' AND revoked_at_unix IS NULL",
                        params![
                            case_id.as_str(),
                            work_product_id.as_str(),
                            sql_i64(version)?,
                            sql_i64(revoked_at_unix)?
                        ],
                    )
                    .map_err(|_| WorkProductError::DatabaseFailed)?;
                if changed != 1 {
                    return Err(WorkProductError::DatabaseFailed);
                }
                newly_revoked = newly_revoked.saturating_add(1);
            }
            if cleanup_state.is_none() {
                transaction
                    .execute(
                        "INSERT INTO work_product_retention_cleanup(
                           case_id,work_product_id,version,state,prepared_at_unix,reason_code
                         ) VALUES(?1,?2,?3,'prepared',?4,?5)",
                        params![
                            case_id.as_str(),
                            work_product_id.as_str(),
                            sql_i64(version)?,
                            sql_i64(revoked_at_unix)?,
                            reason_code
                        ],
                    )
                    .map_err(|_| WorkProductError::DatabaseFailed)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        Ok(newly_revoked)
    }

    pub fn recover_retention_cleanup(
        &self,
        approved: &ApprovedWorkspaceService,
        completed_at_unix: u64,
    ) -> Result<u64, WorkProductError> {
        let operation = approved
            .acquire_operation_guard()
            .map_err(map_approved_error)?;
        self.recover_retention_cleanup_locked(&operation, approved, completed_at_unix)
    }

    pub fn recover_retention_cleanup_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        approved: &ApprovedWorkspaceService,
        completed_at_unix: u64,
    ) -> Result<u64, WorkProductError> {
        approved
            .validate_operation_guard(operation)
            .map_err(map_approved_error)?;
        if completed_at_unix == 0 {
            return Err(WorkProductError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        let rows = {
            let mut statement = db
                .prepare(
                    "SELECT case_id,work_product_id,version
                     FROM work_product_retention_cleanup WHERE state='prepared'
                     ORDER BY case_id,work_product_id,version",
                )
                .map_err(|_| WorkProductError::RecoveryFailed)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|_| WorkProductError::RecoveryFailed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WorkProductError::RecoveryFailed)?;
            rows
        };
        let mut recovered = 0_u64;
        for (case_id, work_product_id, version) in rows {
            let case_id = CaseId::parse(case_id).map_err(|_| WorkProductError::RecoveryFailed)?;
            let work_product_id = WorkProductId::parse(work_product_id)
                .map_err(|_| WorkProductError::RecoveryFailed)?;
            let version = sql_u64(version)?;
            let final_relative = PathBuf::from("work-products")
                .join(case_id.as_str())
                .join(work_product_id.as_str())
                .join(version_directory(version));
            let quarantine_relative = PathBuf::from(".work-product-quarantine").join(format!(
                "retention-{}-{}-{}",
                case_id.as_str(),
                work_product_id.as_str(),
                version
            ));
            let final_path = self.root.fixed.canonical_root().join(&final_relative);
            let quarantine_path = self.root.fixed.canonical_root().join(&quarantine_relative);
            if final_path.exists() {
                let final_path = self
                    .root
                    .fixed
                    .validate_existing_directory(&final_relative)?;
                if quarantine_path.exists() {
                    return Err(WorkProductError::RecoveryFailed);
                }
                let quarantine_path = self.root.fixed.validate_new_path(&quarantine_relative)?;
                fs::rename(final_path, quarantine_path)
                    .map_err(|_| WorkProductError::RecoveryFailed)?;
            }
            if quarantine_path.exists() {
                let quarantine_path = self
                    .root
                    .fixed
                    .validate_existing_directory(&quarantine_relative)?;
                fs::remove_dir_all(quarantine_path)
                    .map_err(|_| WorkProductError::RecoveryFailed)?;
            }
            let changed = db
                .execute(
                    "UPDATE work_product_retention_cleanup
                     SET state='committed',completed_at_unix=?4
                     WHERE case_id=?1 AND work_product_id=?2 AND version=?3
                       AND state='prepared'",
                    params![
                        case_id.as_str(),
                        work_product_id.as_str(),
                        sql_i64(version)?,
                        sql_i64(completed_at_unix)?
                    ],
                )
                .map_err(|_| WorkProductError::RecoveryFailed)?;
            if changed != 1 {
                return Err(WorkProductError::RecoveryFailed);
            }
            recovered = recovered.saturating_add(1);
        }
        Ok(recovered)
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

fn verify_approved_sources_locked(
    operation: &ApprovedWorkspaceOperationGuard,
    case_id: &CaseId,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    references: &[ApprovedMaterialRefV1],
    approved: &ApprovedWorkspaceService,
    now_unix: u64,
) -> Result<(), WorkProductError> {
    for reference in references {
        let verified = approved
            .read_locked(
                operation,
                case_id,
                &reference.material_id,
                reference.document_version,
                &reference.publication_id,
                now_unix,
                Some(APPROVED_SOURCE_DESTINATION_SCOPE),
                Some(APPROVED_SOURCE_PURPOSE),
            )
            .map_err(map_approved_error)?;
        if verified.summary().workspace_instance_id != *expected_workspace_instance_id {
            return Err(WorkProductError::ApprovedSourceUnavailable);
        }
        if verified.summary().manifest_sha256 != reference.manifest_sha256 {
            return Err(WorkProductError::ApprovedSourceStale);
        }
    }
    Ok(())
}

fn ensure_work_product_active(
    db: &Connection,
    case_id: &CaseId,
    work_product_id: &WorkProductId,
    version_sql: i64,
) -> Result<(), WorkProductError> {
    let state = db
        .query_row(
            "SELECT state,revoked_at_unix FROM work_product_versions
             WHERE case_id=?1 AND work_product_id=?2 AND version=?3",
            params![case_id.as_str(), work_product_id.as_str(), version_sql],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(|_| WorkProductError::DatabaseFailed)?
        .ok_or(WorkProductError::NotAvailable)?;
    if state.0 != "committed" {
        return Err(WorkProductError::NotAvailable);
    }
    if state.1.is_some() {
        return Err(WorkProductError::Revoked);
    }
    Ok(())
}

fn map_approved_error(error: WorkspaceError) -> WorkProductError {
    match error {
        WorkspaceError::ResidualSensitiveContent => WorkProductError::ResidualSensitiveContent,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorkProductContentEnvelopeV1 {
    schema_version: String,
    crypto_suite: String,
    key_wrap_provider: String,
    workspace_instance_id: WorkspaceInstanceId,
    case_id: CaseId,
    work_product_id: WorkProductId,
    version: u64,
    signed_manifest_sha256: Sha256Hex,
    content_sha256: Sha256Hex,
    content_bytes: u64,
    content_media_type: String,
    aad_sha256: Sha256Hex,
    wrapped_data_key_base64: String,
    nonce_base64: String,
    ciphertext_base64: String,
    tag_base64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkProductContentAadV1<'a> {
    schema_version: &'static str,
    crypto_suite: &'static str,
    key_wrap_provider: &'static str,
    workspace_instance_id: &'a WorkspaceInstanceId,
    case_id: &'a CaseId,
    work_product_id: &'a WorkProductId,
    version: u64,
    signed_manifest_sha256: &'a Sha256Hex,
    content_sha256: &'a Sha256Hex,
    content_bytes: u64,
    content_media_type: &'a str,
}

fn content_aad_bytes(
    signed: &SignedWorkProductManifestV1,
    signed_manifest_sha256: &Sha256Hex,
) -> Result<Vec<u8>, WorkProductError> {
    canonical_json_v1(&WorkProductContentAadV1 {
        schema_version: CONTENT_AAD_SCHEMA_VERSION,
        crypto_suite: VAULT_CRYPTO_SUITE,
        key_wrap_provider: VAULT_KEY_WRAP_PROVIDER,
        workspace_instance_id: &signed.claims.workspace_instance_id,
        case_id: &signed.claims.case_id,
        work_product_id: &signed.claims.work_product_id,
        version: signed.claims.version,
        signed_manifest_sha256,
        content_sha256: &signed.claims.content_sha256,
        content_bytes: signed.claims.content_bytes,
        content_media_type: &signed.claims.content_media_type,
    })
    .map_err(|_| WorkProductError::ManifestInvalid)
}

fn seal_work_product_content(
    signed: &SignedWorkProductManifestV1,
    signed_manifest_sha256: &Sha256Hex,
    content: &[u8],
) -> Result<Vec<u8>, WorkProductError> {
    if signed.claims.content_sha256.as_str() != sha256_hex(content)
        || signed.claims.content_bytes != u64::try_from(content.len()).unwrap_or(u64::MAX)
    {
        return Err(WorkProductError::ContentMismatch);
    }
    let aad = content_aad_bytes(signed, signed_manifest_sha256)?;
    let key = SecretKey32::generate().map_err(map_crypto_write_error)?;
    let wrapped_data_key = wrap_case_key(&key).map_err(map_crypto_write_error)?;
    if wrapped_data_key.is_empty() || wrapped_data_key.len() > MAX_WRAPPED_DATA_KEY_BYTES {
        return Err(WorkProductError::IoFailed);
    }
    let sealed = seal(&key, content, &aad).map_err(map_crypto_write_error)?;
    let envelope = WorkProductContentEnvelopeV1 {
        schema_version: CONTENT_ENVELOPE_SCHEMA_VERSION.to_owned(),
        crypto_suite: VAULT_CRYPTO_SUITE.to_owned(),
        key_wrap_provider: VAULT_KEY_WRAP_PROVIDER.to_owned(),
        workspace_instance_id: signed.claims.workspace_instance_id.clone(),
        case_id: signed.claims.case_id.clone(),
        work_product_id: signed.claims.work_product_id.clone(),
        version: signed.claims.version,
        signed_manifest_sha256: signed_manifest_sha256.clone(),
        content_sha256: signed.claims.content_sha256.clone(),
        content_bytes: signed.claims.content_bytes,
        content_media_type: signed.claims.content_media_type.clone(),
        aad_sha256: Sha256Hex::parse(sha256_hex(&aad))
            .map_err(|_| WorkProductError::ManifestInvalid)?,
        wrapped_data_key_base64: BASE64_STANDARD.encode(wrapped_data_key),
        nonce_base64: BASE64_STANDARD.encode(sealed.nonce()),
        ciphertext_base64: BASE64_STANDARD.encode(sealed.ciphertext()),
        tag_base64: BASE64_STANDARD.encode(sealed.tag()),
    };
    let bytes = canonical_json_v1(&envelope).map_err(|_| WorkProductError::ManifestInvalid)?;
    if bytes.len() > MAX_WORK_PRODUCT_ENVELOPE_BYTES {
        return Err(WorkProductError::ContentTooLarge);
    }
    Ok(bytes)
}

fn open_work_product_content(
    envelope_bytes: &[u8],
    signed: &SignedWorkProductManifestV1,
    signed_manifest_sha256: &Sha256Hex,
) -> Result<SensitiveContent, WorkProductError> {
    let envelope: WorkProductContentEnvelopeV1 =
        strict_json_v1_from_slice(envelope_bytes).map_err(|_| WorkProductError::ContentMismatch)?;
    let canonical = canonical_json_v1(&envelope).map_err(|_| WorkProductError::ContentMismatch)?;
    if canonical != envelope_bytes
        || envelope.schema_version != CONTENT_ENVELOPE_SCHEMA_VERSION
        || envelope.crypto_suite != VAULT_CRYPTO_SUITE
        || envelope.key_wrap_provider != VAULT_KEY_WRAP_PROVIDER
        || envelope.workspace_instance_id != signed.claims.workspace_instance_id
        || envelope.case_id != signed.claims.case_id
        || envelope.work_product_id != signed.claims.work_product_id
        || envelope.version != signed.claims.version
        || envelope.signed_manifest_sha256 != *signed_manifest_sha256
        || envelope.content_sha256 != signed.claims.content_sha256
        || envelope.content_bytes != signed.claims.content_bytes
        || envelope.content_media_type != signed.claims.content_media_type
    {
        return Err(WorkProductError::ContentMismatch);
    }
    let aad = content_aad_bytes(signed, signed_manifest_sha256)?;
    if envelope.aad_sha256.as_str() != sha256_hex(&aad) {
        return Err(WorkProductError::ContentMismatch);
    }
    let wrapped_data_key = decode_bounded_base64(
        &envelope.wrapped_data_key_base64,
        MAX_WRAPPED_DATA_KEY_BYTES,
    )?;
    let nonce = decode_bounded_base64(&envelope.nonce_base64, GCM_NONCE_BYTES)?;
    let ciphertext =
        decode_bounded_base64(&envelope.ciphertext_base64, MAX_WORK_PRODUCT_CONTENT_BYTES)?;
    let tag = decode_bounded_base64(&envelope.tag_base64, GCM_TAG_BYTES)?;
    if nonce.len() != GCM_NONCE_BYTES
        || tag.len() != GCM_TAG_BYTES
        || ciphertext.len() != usize::try_from(envelope.content_bytes).unwrap_or(usize::MAX)
    {
        return Err(WorkProductError::ContentMismatch);
    }
    let key = unwrap_case_key(&wrapped_data_key).map_err(map_crypto_read_error)?;
    let sealed =
        AeadSealedV1::from_parts(&nonce, ciphertext, &tag).map_err(map_crypto_read_error)?;
    open(&key, &sealed, &aad)
        .map(SensitiveContent::new)
        .map_err(map_crypto_read_error)
}

fn decode_bounded_base64(value: &str, maximum: usize) -> Result<Vec<u8>, WorkProductError> {
    let maximum_encoded = maximum
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(WorkProductError::ContentMismatch)?;
    if value.is_empty() || value.len() > maximum_encoded {
        return Err(WorkProductError::ContentMismatch);
    }
    let decoded = BASE64_STANDARD
        .decode(value.as_bytes())
        .map_err(|_| WorkProductError::ContentMismatch)?;
    if decoded.is_empty() || decoded.len() > maximum || BASE64_STANDARD.encode(&decoded) != value {
        return Err(WorkProductError::ContentMismatch);
    }
    Ok(decoded)
}

fn validate_generation_file_set(directory: &Path) -> Result<(), WorkProductError> {
    let mut expected = BTreeSet::from([CONTENT_ENVELOPE_FILE, MANIFEST_FILE, COMMIT_FILE]);
    for entry in fs::read_dir(directory).map_err(|_| WorkProductError::NotAvailable)? {
        let entry = entry.map_err(|_| WorkProductError::UnsafeFilesystem)?;
        let file_type = entry
            .file_type()
            .map_err(|_| WorkProductError::UnsafeFilesystem)?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(WorkProductError::UnsafeFilesystem);
        }
        let file_name = entry.file_name();
        let file_name = file_name
            .to_str()
            .ok_or(WorkProductError::UnsafeFilesystem)?;
        if !expected.remove(file_name) {
            return Err(WorkProductError::ContentMismatch);
        }
    }
    if !expected.is_empty() {
        return Err(WorkProductError::NotAvailable);
    }
    Ok(())
}

fn read_bundle(
    root: &WorkProductRoot,
    verifier: &ManifestVerificationKey,
    expected_workspace_instance_id: &WorkspaceInstanceId,
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
    let generation_directory = root.fixed.validate_existing_directory(&relative)?;
    validate_generation_file_set(&generation_directory)?;
    let envelope_path = root
        .fixed
        .validate_existing_file(&relative.join(CONTENT_ENVELOPE_FILE))?;
    let manifest_path = root
        .fixed
        .validate_existing_file(&relative.join(MANIFEST_FILE))?;
    let commit_path = root
        .fixed
        .validate_existing_file(&relative.join(COMMIT_FILE))?;
    for path in [&envelope_path, &manifest_path, &commit_path] {
        validate_fixed_local_regular_file(path)?;
    }
    let envelope_bytes = read_bounded(&envelope_path, MAX_WORK_PRODUCT_ENVELOPE_BYTES)?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_WORK_PRODUCT_MANIFEST_BYTES)?;
    let commit_bytes = read_bounded(&commit_path, MAX_WORK_PRODUCT_MANIFEST_BYTES)?;
    let signed: SignedWorkProductManifestV1 = strict_json_v1_from_slice(&manifest_bytes)
        .map_err(|_| WorkProductError::ManifestInvalid)?;
    let commit: WorkProductCommitFileV1 =
        strict_json_v1_from_slice(&commit_bytes).map_err(|_| WorkProductError::ManifestInvalid)?;
    if canonical_json_v1(&signed).map_err(|_| WorkProductError::ManifestInvalid)? != manifest_bytes
        || canonical_json_v1(&commit).map_err(|_| WorkProductError::ManifestInvalid)?
            != commit_bytes
    {
        return Err(WorkProductError::ManifestInvalid);
    }
    verify_manifest(verifier, &signed)?;
    let manifest_sha256 = Sha256Hex::parse(sha256_hex(&manifest_bytes))
        .map_err(|_| WorkProductError::ManifestInvalid)?;
    if commit.schema_version != COMMIT_SCHEMA_VERSION
        || commit.case_id != *case_id
        || commit.work_product_id != *work_product_id
        || commit.version != version
        || commit.manifest_sha256 != manifest_sha256
        || signed.claims.workspace_instance_id != *expected_workspace_instance_id
        || signed.claims.case_id != *case_id
        || signed.claims.work_product_id != *work_product_id
        || signed.claims.version != version
        || signed.claims.content_sha256 != commit.content_sha256
        || signed.claims.content_bytes != commit.content_bytes
    {
        return Err(WorkProductError::ContentMismatch);
    }
    let content = open_work_product_content(&envelope_bytes, &signed, &manifest_sha256)?;
    if commit.content_sha256.as_str() != sha256_hex(content.as_slice())
        || commit.content_bytes != u64::try_from(content.len()).unwrap_or(u64::MAX)
    {
        return Err(WorkProductError::ContentMismatch);
    }
    let residual = scan_residual(content.as_slice())
        .map_err(|_| WorkProductError::ResidualSensitiveContent)?;
    if !residual.passed {
        return Err(WorkProductError::ResidualSensitiveContent);
    }
    let residual_hash = Sha256Hex::parse(sha256_hex(
        &canonical_json_v1(&residual).map_err(|_| WorkProductError::ManifestInvalid)?,
    ))
    .map_err(|_| WorkProductError::ManifestInvalid)?;
    if residual_hash != signed.claims.residual_scan_hash {
        return Err(WorkProductError::ManifestInvalid);
    }
    Ok(VerifiedWorkProductV1 {
        manifest: signed,
        manifest_sha256,
        content,
    })
}

fn map_crypto_write_error(error: VaultCryptoError) -> WorkProductError {
    match error {
        VaultCryptoError::PlatformUnavailable => WorkProductError::PlatformUnavailable,
        VaultCryptoError::ObjectTooLarge => WorkProductError::ContentTooLarge,
        _ => WorkProductError::IoFailed,
    }
}

fn map_crypto_read_error(error: VaultCryptoError) -> WorkProductError {
    match error {
        VaultCryptoError::PlatformUnavailable => WorkProductError::PlatformUnavailable,
        _ => WorkProductError::ContentMismatch,
    }
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
        "PRAGMA journal_mode=WAL;\n         PRAGMA synchronous=FULL;\n         PRAGMA foreign_keys=ON;\n         CREATE TABLE IF NOT EXISTS work_product_meta(\n           singleton INTEGER PRIMARY KEY CHECK(singleton=1),\n           schema_version INTEGER NOT NULL,\n           workspace_instance_id TEXT NOT NULL\n         ) STRICT;\n         CREATE TABLE IF NOT EXISTS work_product_versions(\n           case_id TEXT NOT NULL,\n           work_product_id TEXT NOT NULL,\n           version INTEGER NOT NULL CHECK(version > 0),\n           state TEXT NOT NULL CHECK(state IN ('prepared','committed','quarantined')),\n           idempotency_key TEXT NOT NULL UNIQUE,\n           request_sha256 TEXT NOT NULL,\n           transaction_id TEXT NOT NULL UNIQUE,\n           manifest_sha256 TEXT NOT NULL,\n           content_sha256 TEXT NOT NULL,\n           created_at_unix INTEGER NOT NULL CHECK(created_at_unix > 0),\n           revoked_at_unix INTEGER,\n           PRIMARY KEY(case_id,work_product_id,version)\n         ) STRICT;\n         CREATE TABLE IF NOT EXISTS work_product_retention_cleanup(\n           case_id TEXT NOT NULL,\n           work_product_id TEXT NOT NULL,\n           version INTEGER NOT NULL,\n           state TEXT NOT NULL CHECK(state IN('prepared','committed')),\n           prepared_at_unix INTEGER NOT NULL,\n           completed_at_unix INTEGER,\n           reason_code TEXT NOT NULL,\n           PRIMARY KEY(case_id,work_product_id,version),\n           FOREIGN KEY(case_id,work_product_id,version)\n             REFERENCES work_product_versions(case_id,work_product_id,version)\n         ) STRICT;\n         CREATE TRIGGER IF NOT EXISTS trg_work_product_cleanup_final_no_update\n         BEFORE UPDATE ON work_product_retention_cleanup\n         WHEN OLD.state='committed' BEGIN\n           SELECT RAISE(ABORT,'final work product cleanup journal is immutable');\n         END;\n         CREATE TRIGGER IF NOT EXISTS trg_work_product_cleanup_no_delete\n         BEFORE DELETE ON work_product_retention_cleanup BEGIN\n           SELECT RAISE(ABORT,'work product cleanup journal is append only');\n         END;",
    )
    .map_err(|_| WorkProductError::DatabaseFailed)?;
    let has_revoked_at = {
        let mut statement = db
            .prepare("PRAGMA table_info(work_product_versions)")
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| WorkProductError::DatabaseFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WorkProductError::DatabaseFailed)?;
        columns.iter().any(|column| column == "revoked_at_unix")
    };
    if !has_revoked_at {
        db.execute(
            "ALTER TABLE work_product_versions ADD COLUMN revoked_at_unix INTEGER",
            [],
        )
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    }
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
            "SELECT case_id,work_product_id,version,state,request_sha256,manifest_sha256,
                    content_sha256,revoked_at_unix
             FROM work_product_versions WHERE idempotency_key=?1",
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
                    row.get::<_, Option<i64>>(7)?,
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
    if row.7.is_some() {
        return Err(WorkProductError::Revoked);
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
            "SELECT MAX(version) FROM work_product_versions
             WHERE case_id=?1 AND work_product_id=?2 AND state='committed'
               AND revoked_at_unix IS NULL",
            params![case_id.as_str(), work_product_id.as_str()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|_| WorkProductError::DatabaseFailed)?;
    value.map(sql_u64).transpose()
}

fn recover_prepared(
    root: &WorkProductRoot,
    verifier: &ManifestVerificationKey,
    expected_workspace_instance_id: &WorkspaceInstanceId,
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
            && read_bundle(
                root,
                verifier,
                expected_workspace_instance_id,
                &case_id,
                &work_product_id,
                version,
            )
            .is_ok()
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
    matches!(
        value,
        "text/plain" | "text/markdown" | "text/html" | "application/json"
    )
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
        workspace::{ApprovedEgressGuardInputV1, WorkspacePublisher},
    };
    use std::collections::{BTreeMap, BTreeSet};

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
            source_name_sha256: hash(b"source.pdf"),
            source_revision_hash: hash(b"source-revision"),
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
            diagram_spec_sha256: None,
            placeholder_policy_version: "placeholder-v1".to_owned(),
            author_tool: "case_write_work_product".to_owned(),
            author_tool_version: "1".to_owned(),
            idempotency_key: key.to_owned(),
        }
    }

    #[test]
    fn legal_diagram_write_contract_requires_specialized_author_media_and_spec_hash() {
        let (_, _, material_id, publication_id) = ids();
        let reference = ApprovedMaterialRefV1 {
            material_id,
            document_version: 1,
            publication_id,
            manifest_sha256: hash(b"manifest"),
        };
        let mut diagram = request(reference, "diagram-contract-0001");
        diagram.task_type = "legal_diagram".to_owned();
        diagram.content_media_type = "text/html".to_owned();
        diagram.diagram_spec_sha256 = Some(hash(b"diagram-spec"));
        diagram.author_tool = "diagram.render".to_owned();
        diagram.validate().expect("specialized diagram contract");

        let mut missing_hash = diagram.clone();
        missing_hash.diagram_spec_sha256 = None;
        assert_eq!(missing_hash.validate(), Err(WorkProductError::InvalidInput));

        let mut generic_author = diagram.clone();
        generic_author.author_tool = "case_update_work_product".to_owned();
        assert_eq!(
            generic_author.validate(),
            Err(WorkProductError::InvalidInput)
        );

        let mut wrong_media = diagram.clone();
        wrong_media.content_media_type = "text/markdown".to_owned();
        assert_eq!(wrong_media.validate(), Err(WorkProductError::InvalidInput));

        let mut generic = diagram;
        generic.task_type = "case_analysis".to_owned();
        assert_eq!(generic.validate(), Err(WorkProductError::InvalidInput));
    }

    struct Fixture {
        root: PathBuf,
        approved_root: PathBuf,
        workspace_id: WorkspaceInstanceId,
        case_id: CaseId,
        material_id: MaterialId,
        publication_id: PublicationId,
        manifest_hash: Sha256Hex,
        source_publisher: WorkspacePublisher,
        approved_service: ApprovedWorkspaceService,
        approved_verifier_for_reopen: ManifestVerificationKey,
        work_publisher: WorkProductPublisher,
        work_verifier: ManifestVerificationKey,
    }

    fn fixture() -> Fixture {
        fixture_with_guard(&[], &[], &[])
    }

    fn fixture_with_guard(
        case_dictionary_terms: &[&str],
        source_terms: &[&str],
        raw_canary_terms: &[&str],
    ) -> Fixture {
        let mut random = [0_u8; 16];
        fill_random(&mut random).expect("random");
        let base = std::env::temp_dir().join(format!("la-work-product-{}", sha256_hex(&random)));
        let approved_root = base.join("approved-workspace");
        let root = base.join("work-product-workspace");
        let source_signer = ManifestSigningKey::generate(1).expect("source signer");
        let source_verifier = source_signer.verification_key();
        let approved_verifier_for_reopen = source_signer.verification_key();
        let source_publisher = WorkspacePublisher::initialize(&approved_root, source_signer)
            .expect("source publisher");
        let content = b"[PERSON_001] approved synthetic source";
        let claims = approved_claims(content);
        let published = source_publisher
            .publish_with_egress_guard(
                claims.clone(),
                content,
                ApprovedEgressGuardInputV1 {
                    case_dictionary_terms,
                    source_terms,
                    raw_canary_terms,
                },
            )
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
            source_publisher,
            approved_service,
            approved_verifier_for_reopen,
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

    fn generation_directory(fixture: &Fixture, published: &PublishedWorkProductV1) -> PathBuf {
        fixture
            .root
            .join("work-products")
            .join(fixture.case_id.as_str())
            .join(published.work_product_id.as_str())
            .join(version_directory(published.version))
    }

    fn read_test_envelope(path: &Path) -> WorkProductContentEnvelopeV1 {
        strict_json_v1_from_slice(&fs::read(path).expect("read envelope")).expect("strict envelope")
    }

    fn write_test_envelope(path: &Path, envelope: &WorkProductContentEnvelopeV1) {
        fs::write(
            path,
            canonical_json_v1(envelope).expect("canonical envelope"),
        )
        .expect("write envelope");
    }

    #[test]
    fn generation_tree_contains_only_encrypted_canonical_content() {
        let fixture = fixture();
        let secret = b"SYNTHETIC_WORK_PRODUCT_SECRET_NEVER_ON_DISK_4f5d8c31";
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "encrypted-tree-key-0001"),
                secret,
                &fixture.approved_service,
                100,
            )
            .expect("encrypted work product");
        let generation = generation_directory(&fixture, &created);
        let names = fs::read_dir(&generation)
            .expect("generation directory")
            .map(|entry| {
                entry
                    .expect("generation entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                CONTENT_ENVELOPE_FILE.to_owned(),
                MANIFEST_FILE.to_owned(),
                COMMIT_FILE.to_owned(),
            ])
        );
        assert!(!generation.join("content.bin").exists());
        for name in names {
            let bytes = fs::read(generation.join(name)).expect("generation file");
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "plaintext secret must not occur in the generation tree"
            );
        }

        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_publisher.signer.verification_key(),
        )
        .expect("reader");
        let verified = reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                created.version,
                &fixture.approved_service,
                200,
            )
            .expect("decrypt verified work product");
        assert_eq!(verified.content(), secret);
        assert!(!format!("{verified:?}").contains("SYNTHETIC_WORK_PRODUCT_SECRET"));
        fs::remove_dir_all(
            fixture
                .root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn envelope_ciphertext_key_aad_swap_unknown_field_and_legacy_plaintext_fail_closed() {
        let fixture = fixture();
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "tamper-envelope-key-0001"),
                b"synthetic encrypted work product alpha",
                &fixture.approved_service,
                100,
            )
            .expect("first encrypted work product");
        let generation = generation_directory(&fixture, &created);
        let envelope_path = generation.join(CONTENT_ENVELOPE_FILE);
        let original_bytes = fs::read(&envelope_path).expect("original envelope");
        let original_envelope = read_test_envelope(&envelope_path);
        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_publisher.signer.verification_key(),
        )
        .expect("reader");

        let mut ciphertext_tamper = original_envelope.clone();
        let mut ciphertext = BASE64_STANDARD
            .decode(ciphertext_tamper.ciphertext_base64.as_bytes())
            .expect("ciphertext");
        ciphertext[0] ^= 0x80;
        ciphertext_tamper.ciphertext_base64 = BASE64_STANDARD.encode(ciphertext);
        write_test_envelope(&envelope_path, &ciphertext_tamper);
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        let mut key_tamper = original_envelope.clone();
        let mut wrapped = BASE64_STANDARD
            .decode(key_tamper.wrapped_data_key_base64.as_bytes())
            .expect("wrapped key");
        wrapped[0] ^= 0x40;
        key_tamper.wrapped_data_key_base64 = BASE64_STANDARD.encode(wrapped);
        write_test_envelope(&envelope_path, &key_tamper);
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        let mut aad_tamper = original_envelope.clone();
        aad_tamper.aad_sha256 = hash(b"cross-object-aad");
        write_test_envelope(&envelope_path, &aad_tamper);
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        let mut with_unknown_field: serde_json::Value =
            serde_json::from_slice(&original_bytes).expect("envelope value");
        with_unknown_field
            .as_object_mut()
            .expect("envelope object")
            .insert(
                "futureUnsafeField".to_owned(),
                serde_json::Value::Bool(true),
            );
        fs::write(
            &envelope_path,
            canonical_json_v1(&with_unknown_field).expect("canonical tamper"),
        )
        .expect("write unknown field");
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        let mut noncanonical = original_bytes.clone();
        noncanonical.push(b'\n');
        fs::write(&envelope_path, noncanonical).expect("write noncanonical envelope");
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        fs::write(&envelope_path, &original_bytes).expect("restore first envelope");
        let second = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "tamper-envelope-key-0002"),
                b"synthetic encrypted work product beta",
                &fixture.approved_service,
                101,
            )
            .expect("second encrypted work product");
        let second_envelope = generation_directory(&fixture, &second).join(CONTENT_ENVELOPE_FILE);
        let second_original_envelope = read_test_envelope(&second_envelope);
        assert_ne!(
            original_envelope.wrapped_data_key_base64,
            second_original_envelope.wrapped_data_key_base64,
            "every generation receives a new random data key"
        );
        assert_ne!(
            original_envelope.nonce_base64, second_original_envelope.nonce_base64,
            "every generation receives a new random GCM nonce"
        );
        fs::write(&second_envelope, &original_bytes).expect("swap envelope across objects");
        assert!(reader
            .read(
                &fixture.case_id,
                &second.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());

        fs::write(
            generation.join("content.bin"),
            b"legacy plaintext must never be accepted",
        )
        .expect("legacy plaintext file");
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());
        fs::remove_file(generation.join("content.bin")).expect("remove legacy test file");
        let hardlink = fixture.root.join("synthetic-envelope-hardlink.json");
        fs::hard_link(&envelope_path, &hardlink).expect("create envelope hardlink");
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .is_err());
        fs::remove_file(hardlink).expect("remove envelope hardlink");
        reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .expect("restored envelope remains readable");
        fs::remove_dir_all(
            fixture
                .root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn encrypted_generation_recovery_remains_idempotent() {
        let fixture = fixture();
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "encrypted-recover-key-0001"),
                b"synthetic crash recovery content",
                &fixture.approved_service,
                100,
            )
            .expect("encrypted work product");
        let db = Connection::open(fixture.root.join("work-products.sqlite")).expect("database");
        assert_eq!(
            db.execute(
                "UPDATE work_product_versions SET state='prepared' WHERE case_id=?1 AND work_product_id=?2 AND version=1",
                params![fixture.case_id.as_str(), created.work_product_id.as_str()],
            )
            .expect("simulate crash before database commit"),
            1
        );
        drop(db);
        assert_eq!(
            fixture
                .work_publisher
                .recover(&fixture.approved_service)
                .expect("recover encrypted generation"),
            1
        );
        assert_eq!(
            fixture
                .work_publisher
                .recover(&fixture.approved_service)
                .expect("idempotent recovery"),
            0
        );
        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_publisher.signer.verification_key(),
        )
        .expect("reader");
        assert_eq!(
            reader
                .read(
                    &fixture.case_id,
                    &created.work_product_id,
                    1,
                    &fixture.approved_service,
                    200,
                )
                .expect("recovered read")
                .content(),
            b"synthetic crash recovery content"
        );
        fs::remove_dir_all(
            fixture
                .root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
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
    fn retention_source_revocation_is_exact_revoke_first_and_crash_recoverable() {
        let fixture = fixture();
        let targeted = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "retention-target-key-0001"),
                b"synthetic targeted work product",
                &fixture.approved_service,
                100,
            )
            .expect("targeted work product");

        let other_source_content = b"[PERSON_002] unrelated approved source";
        let mut other_claims = approved_claims(other_source_content);
        other_claims.material_id =
            MaterialId::parse("mat_00000000000000000000000000000002").expect("material");
        other_claims.publication_id =
            PublicationId::parse("pub_00000000000000000000000000000002").expect("publication");
        other_claims.content_sha256 = hash(other_source_content);
        other_claims.content_bytes = other_source_content.len() as u64;
        other_claims.source_sha256 = hash(b"other-source");
        other_claims.source_name_sha256 = hash(b"other-source.pdf");
        other_claims.source_revision_hash = hash(b"other-source-revision");
        other_claims.extraction_sha256 = hash(b"other-extraction");
        let other_publication = fixture
            .source_publisher
            .publish(other_claims.clone(), other_source_content)
            .expect("other approved publication");
        let other_reference = ApprovedMaterialRefV1 {
            material_id: other_claims.material_id,
            document_version: other_claims.document_version,
            publication_id: other_claims.publication_id.clone(),
            manifest_sha256: other_publication.manifest_sha256,
        };
        let unrelated = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(other_reference, "retention-unrelated-key-0001"),
                b"synthetic unrelated work product",
                &fixture.approved_service,
                101,
            )
            .expect("unrelated work product");

        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_verifier,
        )
        .expect("reader");
        assert_eq!(
            reader
                .prepare_retention_revocation_by_sources(
                    &fixture.approved_service,
                    &BTreeSet::from([fixture.publication_id.clone()]),
                    200,
                    "retention_expired",
                )
                .expect("prepare exact work-product revocation"),
            1
        );
        assert!(matches!(
            reader.read(
                &fixture.case_id,
                &targeted.work_product_id,
                1,
                &fixture.approved_service,
                201,
            ),
            Err(WorkProductError::Revoked)
        ));
        reader
            .read(
                &fixture.case_id,
                &unrelated.work_product_id,
                1,
                &fixture.approved_service,
                201,
            )
            .expect("unrelated work product remains active");
        let targeted_directory = fixture
            .root
            .join("work-products")
            .join(fixture.case_id.as_str())
            .join(targeted.work_product_id.as_str())
            .join(version_directory(1));
        let unrelated_directory = fixture
            .root
            .join("work-products")
            .join(fixture.case_id.as_str())
            .join(unrelated.work_product_id.as_str())
            .join(version_directory(1));
        assert!(
            targeted_directory.is_dir(),
            "revoke precedes physical cleanup"
        );
        assert_eq!(
            reader
                .prepare_retention_revocation_by_sources(
                    &fixture.approved_service,
                    &BTreeSet::from([fixture.publication_id.clone()]),
                    202,
                    "retention_expired",
                )
                .expect("idempotent preparation"),
            0
        );
        assert_eq!(
            reader
                .recover_retention_cleanup(&fixture.approved_service, 203)
                .expect("recover physical cleanup"),
            1
        );
        assert!(!targeted_directory.exists());
        assert!(unrelated_directory.is_dir());
        assert_eq!(
            reader
                .recover_retention_cleanup(&fixture.approved_service, 204)
                .expect("idempotent recovery"),
            0
        );
        fs::remove_dir_all(
            fixture
                .approved_root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn completed_work_product_read_linearizes_before_concurrent_retention_revoke() {
        let fixture = fixture();
        let response_content = b"synthetic read-before-revoke work product";
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "retention-race-key-0001"),
                response_content,
                &fixture.approved_service,
                100,
            )
            .expect("work product");
        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_verifier,
        )
        .expect("reader");
        let revoker_approved = ApprovedWorkspaceService::open(
            &fixture.approved_root,
            fixture.approved_verifier_for_reopen,
        )
        .expect("revoker approved workspace");

        let operation = fixture
            .approved_service
            .acquire_operation_guard()
            .expect("work-product read operation boundary");
        let verified = reader
            .read_locked(
                &operation,
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                200,
            )
            .expect("construct verified work-product response");
        let completed_response = verified.content().to_vec();

        let source_id = fixture.publication_id.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let revoke_thread = std::thread::spawn(move || {
            let result = reader.prepare_retention_revocation_by_sources(
                &revoker_approved,
                &BTreeSet::from([source_id]),
                201,
                "retention_expired",
            );
            sender.send(()).expect("send revoke completion");
            (reader, result)
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "work-product revoke must wait for complete response construction"
        );
        assert_eq!(completed_response, response_content);
        drop(verified);
        drop(operation);
        receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("work-product revoke resumes after read boundary release");
        let (reader, revoke_result) = revoke_thread.join().expect("revoke thread");
        assert_eq!(revoke_result.expect("retention revoke"), 1);
        assert!(matches!(
            reader.read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                202,
            ),
            Err(WorkProductError::Revoked)
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
    fn create_and_update_enforce_short_canary_and_unicode_guard() {
        let fixture = fixture_with_guard(&["\u{212b}"], &[], &["\u{4e95}"]);
        assert_eq!(
            fixture.work_publisher.create(
                &fixture.case_id,
                request(reference(&fixture), "guard-create-key-0001"),
                "synthetic output with \u{4e95}".as_bytes(),
                &fixture.approved_service,
                100,
            ),
            Err(WorkProductError::ResidualSensitiveContent)
        );
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "guard-create-key-0002"),
                b"synthetic clean output",
                &fixture.approved_service,
                101,
            )
            .expect("clean create");
        assert_eq!(
            fixture.work_publisher.update(
                &fixture.case_id,
                &created.work_product_id,
                1,
                request(reference(&fixture), "guard-update-key-0001"),
                "synthetic A\u{030a} revision".as_bytes(),
                &fixture.approved_service,
                102,
            ),
            Err(WorkProductError::ResidualSensitiveContent)
        );
        fs::remove_dir_all(
            fixture
                .approved_root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn read_list_and_export_revalidate_guard_integrity() {
        let fixture = fixture_with_guard(&[], &[], &["ZX"]);
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "guard-read-key-000001"),
                b"synthetic clean output",
                &fixture.approved_service,
                100,
            )
            .expect("create");
        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_verifier,
        )
        .expect("reader");
        reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                110,
            )
            .expect("read before tamper");
        assert_eq!(
            reader
                .list_case(&fixture.case_id, &fixture.approved_service, 110)
                .expect("list before tamper")
                .len(),
            1
        );
        reader
            .export_manifest(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                110,
            )
            .expect("export before tamper");

        let guard_path = fixture
            .approved_root
            .join("cases")
            .join(fixture.case_id.as_str())
            .join("approved")
            .join(fixture.publication_id.as_str())
            .join("egress-guard.json");
        fs::write(guard_path, b"{}").expect("tamper guard");
        assert!(reader
            .read(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                111,
            )
            .is_err());
        assert!(reader
            .list_case(&fixture.case_id, &fixture.approved_service, 111)
            .is_err());
        assert!(reader
            .export_manifest(
                &fixture.case_id,
                &created.work_product_id,
                1,
                &fixture.approved_service,
                111,
            )
            .is_err());
        fs::remove_dir_all(
            fixture
                .approved_root
                .parent()
                .expect("fixture parent remains below temp"),
        )
        .expect("cleanup");
    }

    #[test]
    fn newer_source_revision_makes_existing_work_product_stale() {
        let fixture = fixture();
        let created = fixture
            .work_publisher
            .create(
                &fixture.case_id,
                request(reference(&fixture), "stale-create-key-0001"),
                b"synthetic clean output",
                &fixture.approved_service,
                100,
            )
            .expect("create");

        let replacement_content = b"[PERSON_002] replacement approved source";
        let mut replacement = approved_claims(replacement_content);
        replacement.document_version = 2;
        replacement.publication_id = PublicationId::parse("pub_00000000000000000000000000000002")
            .expect("replacement publication");
        replacement.content_sha256 = hash(replacement_content);
        replacement.content_bytes = replacement_content.len() as u64;
        replacement.dictionary_revision_hash = hash(b"dictionary-v2");
        replacement.mapping_revision_hash = hash(b"mapping-v2");
        replacement.issued_at_unix = 20;
        fixture
            .source_publisher
            .publish(replacement, replacement_content)
            .expect("replacement publish");

        let reader = WorkProductService::open(
            &fixture.root,
            fixture.workspace_id.clone(),
            fixture.work_verifier,
        )
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
