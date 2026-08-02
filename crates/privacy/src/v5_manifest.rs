//! Strict, read-only proof for the frozen intermediate Privacy schema 5.
//!
//! Schema 5 is a migration checkpoint, not an ordinary application schema.
//! The proof is therefore built from an independently constructed canonical
//! v0.3.1 schema-1 fixture and rejects every additional, missing, or weakened
//! SQLite object before hashing any rows.

use crate::{
    lifecycle::{PrivacyLifecycle, RetentionPolicyV1, PRIVACY_LIFECYCLE_SCHEMA_VERSION},
    migration_source::{
        canonical_sqlite_manifests, internal_schema_objects,
        reconstruct_privacy_v1_projection_from_evolved_store_read_only, schema_objects,
        validate_foreign_keys, validate_quick_check, PrivacyV1BusinessManifest,
        PrivacyV1LogicalManifest, PrivacyV1SourceValidationError, SchemaObject,
        PRIVACY_V1_SCHEMA_MANIFEST_DDL,
    },
    project_case_binding::ProjectPrivacyCaseBindingStore,
    sha256_hex,
    store::{
        validate_v5_schema, PrivacyStore, PrivacyStoreError, PrivacyStoreSchemaStatus,
        INTERMEDIATE_PRIVACY_STORE_SCHEMA_VERSION,
    },
    vault_crypto::unwrap_case_key,
    vnext::WorkspaceInstanceId,
};
use rusqlite::{Connection, TransactionBehavior};

pub const PRIVACY_V5_SCHEMA_MANIFEST_SHA256: &str =
    "6b79e28a35df8196642d3cd958f0f702bb8c04c3f12fdfb3d0ee7f40b8a32ab5";
pub const PRIVACY_V5_INTERNAL_SCHEMA_MANIFEST_SHA256: &str =
    "1e0eea987914223845371b0eee97806ef029d9c3bac0d2862e46b427e5780f04";
pub const PRIVACY_V5_SCHEMA_OBJECT_COUNT: u64 = 86;
use std::io::Cursor;

pub const PRIVACY_V5_APPLICATION_TABLES: [&str; 23] = [
    "case_material_legacy_references",
    "case_material_migration_events",
    "case_material_migration_ledger",
    "case_material_selections",
    "privacy_approved_outputs",
    "privacy_backup_registry",
    "privacy_cleanup_candidates",
    "privacy_cleanup_journal",
    "privacy_cleanup_redaction_evidence",
    "privacy_egress_audit",
    "privacy_lifecycle_meta",
    "privacy_mapping_access_audit",
    "privacy_mapping_keys",
    "privacy_materials",
    "privacy_receipts",
    "privacy_redactions",
    "privacy_retention_bindings",
    "privacy_retention_policy",
    "privacy_risk_review_revisions",
    "privacy_schema_metadata",
    "privacy_sensitive_mappings",
    "project_privacy_case_binding_audit",
    "project_privacy_case_bindings",
];

const PRIVACY_V5_BUSINESS_MANIFEST_EXCLUDED_TABLES: [&str; 1] = ["privacy_schema_metadata"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyV5ManifestError {
    Database,
    UnsupportedSchema,
    DataBoundary,
    IntegrityCheckFailed,
    ForeignKeyViolation,
    SourceDrift,
}

impl PrivacyV5ManifestError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_v5_manifest_database_error",
            Self::UnsupportedSchema => "privacy_v5_manifest_schema_unsupported",
            Self::DataBoundary => "privacy_v5_manifest_data_boundary_invalid",
            Self::IntegrityCheckFailed => "privacy_v5_manifest_integrity_check_failed",
            Self::ForeignKeyViolation => "privacy_v5_manifest_foreign_key_violation",
            Self::SourceDrift => "privacy_v5_manifest_source_drift",
        }
    }
}

impl std::fmt::Display for PrivacyV5ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivacyV5ManifestError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5ManifestProof {
    pub schema_version: i64,
    pub schema_manifest_sha256: String,
    pub internal_schema_manifest_sha256: String,
    pub schema_object_count: u64,
    pub table_count: u64,
    pub total_row_count: u64,
    pub data_version: i64,
    pub logical_manifest: PrivacyV5LogicalManifest,
    pub business_manifest: PrivacyV5BusinessManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5LogicalManifest {
    pub sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV5LogicalTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5LogicalTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5BusinessManifest {
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV5BusinessTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5BusinessTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
}

/// The only two durable, pre-receipt-4 schema-5 prefixes produced by the
/// frozen v0.3.1 transition.  Binding schema creation is deliberately not a
/// partial state: once those objects exist the database must satisfy the full
/// canonical v5 manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyV5PartialStage {
    SchemaCommittedBeforeLifecycle,
    LifecycleCommittedBeforeBinding,
}

/// Strict read-only proof for one authorized partial-v5 prefix.  Its whole
/// partial-store manifests bind the random DPAPI lifecycle key and timestamps,
/// while the reconstructed v1 business proof binds the evolved rows back to
/// the authenticated pre-upgrade source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5PartialProof {
    stage: PrivacyV5PartialStage,
    schema_object_count: u64,
    logical_manifest_sha256: String,
    business_manifest_sha256: String,
    source_business_manifest_sha256: String,
    source_total_row_count: u64,
    protected_review_payload_count: u64,
}

impl PrivacyV5PartialProof {
    pub const fn stage(&self) -> PrivacyV5PartialStage {
        self.stage
    }

    pub const fn schema_object_count(&self) -> u64 {
        self.schema_object_count
    }

    pub fn logical_manifest_sha256(&self) -> &str {
        &self.logical_manifest_sha256
    }

    pub fn business_manifest_sha256(&self) -> &str {
        &self.business_manifest_sha256
    }

    pub fn source_business_manifest_sha256(&self) -> &str {
        &self.source_business_manifest_sha256
    }

    pub const fn source_total_row_count(&self) -> u64 {
        self.source_total_row_count
    }

    pub const fn protected_review_payload_count(&self) -> u64 {
        self.protected_review_payload_count
    }
}

/// Authenticated source and workspace expectations for the one exact, fully
/// initialized schema-5 state that may precede Receipt 4.  The source values
/// come from the already authenticated v0.3.1 rollback/checkpoint chain; the
/// verifier never treats the live evolved store as its own authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyV5InitialFullExpectation<'a> {
    pub expected_workspace_instance_id: &'a WorkspaceInstanceId,
    pub expected_source_business_manifest_sha256: &'a str,
    pub expected_source_total_row_count: u64,
    pub expected_protected_review_payload_count: u64,
}

/// Strict proof for the exact initial full-v5 state immediately before
/// Receipt 4.  In addition to the canonical full-v5 manifest, it retains the
/// independently reconstructed v0.3.1 source identity used by the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV5InitialFullProof {
    manifest: PrivacyV5ManifestProof,
    source_business_manifest_sha256: String,
    source_total_row_count: u64,
    protected_review_payload_count: u64,
}

impl PrivacyV5InitialFullProof {
    pub const fn manifest(&self) -> &PrivacyV5ManifestProof {
        &self.manifest
    }

    pub fn into_manifest(self) -> PrivacyV5ManifestProof {
        self.manifest
    }

    pub fn source_business_manifest_sha256(&self) -> &str {
        &self.source_business_manifest_sha256
    }

    pub const fn source_total_row_count(&self) -> u64 {
        self.source_total_row_count
    }

    pub const fn protected_review_payload_count(&self) -> u64 {
        self.protected_review_payload_count
    }
}

struct ExactPrivacyV5Schema {
    application_objects: Vec<SchemaObject>,
    internal_objects: Vec<SchemaObject>,
    table_definitions: Vec<(String, String)>,
    schema_manifest_sha256: String,
    internal_schema_manifest_sha256: String,
}

/// Computes canonical schema, logical, and business proofs from one pinned
/// deferred/query-only schema-5 snapshot. No migration, repair, checkpoint, or
/// application row write is expressible through this API.
pub fn compute_privacy_v5_manifests_read_only(
    connection: &Connection,
) -> Result<PrivacyV5ManifestProof, PrivacyV5ManifestError> {
    if !connection.is_autocommit() {
        return Err(PrivacyV5ManifestError::Database);
    }
    require_intermediate_v5(connection)?;
    let exact_schema = build_exact_privacy_v5_schema()?;

    let previous_query_only = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV5ManifestError::Database)?;

    let proof_result = compute_from_pinned_snapshot(connection, &exact_schema);
    let restore_result = connection
        .pragma_update(
            None,
            "query_only",
            if previous_query_only { "ON" } else { "OFF" },
        )
        .map_err(|_| PrivacyV5ManifestError::Database);
    match (proof_result, restore_result) {
        (Ok(proof), Ok(())) => Ok(proof),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Verifies the only exact, fully initialized schema-5 state that may be
/// authenticated by Receipt 4.  Unlike the general manifest API, this boundary
/// binds the live database to an independently authenticated workspace and
/// v0.3.1 source identity, requires the exact initial lifecycle, and rejects
/// every row in a post-v1 table (including both binding tables).
///
/// The complete proof is captured in one deferred/query-only transaction.  No
/// migration, repair, lifecycle initialization, or binding write is performed.
pub fn verify_initial_privacy_v5_before_receipt4_read_only(
    connection: &Connection,
    expectation: &PrivacyV5InitialFullExpectation<'_>,
) -> Result<PrivacyV5InitialFullProof, PrivacyV5ManifestError> {
    if !connection.is_autocommit() {
        return Err(PrivacyV5ManifestError::Database);
    }
    if !is_lower_sha256(expectation.expected_source_business_manifest_sha256) {
        return Err(PrivacyV5ManifestError::DataBoundary);
    }
    require_intermediate_v5(connection)?;
    let exact_schema = build_exact_privacy_v5_schema()?;
    let previous_query_only = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV5ManifestError::Database)?;

    let proof_result = (|| {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
                .map_err(|_| PrivacyV5ManifestError::Database)?;
        let (data_version_before, schema_object_count) =
            authenticate_exact_v5_snapshot(&transaction, &exact_schema)?;
        validate_initial_v5_transformation(&transaction)?;
        let source = reconstruct_privacy_v1_projection_from_evolved_store_read_only(&transaction)
            .map_err(map_source_error)?;
        if source.business_manifest_sha256 != expectation.expected_source_business_manifest_sha256
            || source.total_row_count != expectation.expected_source_total_row_count
            || source.protected_review_payload_count
                != expectation.expected_protected_review_payload_count
        {
            return Err(PrivacyV5ManifestError::SourceDrift);
        }
        validate_exact_initial_full_v5_state(
            &transaction,
            expectation.expected_workspace_instance_id,
        )?;
        let manifest = compute_manifest_from_authenticated_snapshot(
            &transaction,
            &exact_schema,
            data_version_before,
            schema_object_count,
        )?;
        let proof = PrivacyV5InitialFullProof {
            manifest,
            source_business_manifest_sha256: source.business_manifest_sha256,
            source_total_row_count: source.total_row_count,
            protected_review_payload_count: source.protected_review_payload_count,
        };
        transaction
            .commit()
            .map_err(|_| PrivacyV5ManifestError::Database)?;
        Ok(proof)
    })();
    let restore_result = connection
        .pragma_update(
            None,
            "query_only",
            if previous_query_only { "ON" } else { "OFF" },
        )
        .map_err(|_| PrivacyV5ManifestError::Database);
    match (proof_result, restore_result) {
        (Ok(proof), Ok(())) => Ok(proof),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Classifies exactly one of the two recoverable schema-5 prefixes left by a
/// crash between the independently durable schema, lifecycle, and binding
/// commits.  The live connection is forced query-only and pinned for the
/// complete schema, row, DPAPI, and source-projection proof.  Arbitrary v5
/// stores, partial binding DDL, extra objects/rows, and another workspace's
/// lifecycle state are rejected.
pub fn classify_privacy_v5_partial_read_only(
    connection: &Connection,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<PrivacyV5PartialProof, PrivacyV5ManifestError> {
    if !connection.is_autocommit() {
        return Err(PrivacyV5ManifestError::Database);
    }

    // Rebuild and validate the full frozen v5 fixture first. This keeps the
    // pre-binding schema below anchored to the hard-coded full-v5 manifest
    // constants rather than accepting whatever the current initializer emits.
    let _full_schema = build_exact_privacy_v5_schema()?;
    let partial_schema = build_exact_privacy_v5_pre_binding_schema()?;
    let previous_query_only = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV5ManifestError::Database)?;

    let proof_result = (|| {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
                .map_err(|_| PrivacyV5ManifestError::Database)?;
        let proof = classify_privacy_v5_partial_in_transaction_inner(
            &transaction,
            expected_workspace_instance_id,
            &partial_schema,
        )?;
        transaction
            .commit()
            .map_err(|_| PrivacyV5ManifestError::Database)?;
        Ok(proof)
    })();
    let restore_result = connection
        .pragma_update(
            None,
            "query_only",
            if previous_query_only { "ON" } else { "OFF" },
        )
        .map_err(|_| PrivacyV5ManifestError::Database);
    match (proof_result, restore_result) {
        (Ok(proof), Ok(())) => Ok(proof),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Classifies a partial-v5 prefix inside a transaction owned by the caller.
///
/// This function neither begins nor commits the transaction and never changes
/// `PRAGMA query_only`.  A migration writer must pass its own `BEGIN IMMEDIATE`
/// transaction so the exact predecessor proof and the first authorized write
/// share one SQLite write lock.  The ordinary read-only API above uses the same
/// classifier inside its deferred/query-only snapshot.
pub fn classify_privacy_v5_partial_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<PrivacyV5PartialProof, PrivacyV5ManifestError> {
    // Anchor the pre-binding schema to the independently frozen full-v5
    // constants before accepting the caller-owned transaction's live objects.
    let _full_schema = build_exact_privacy_v5_schema()?;
    let partial_schema = build_exact_privacy_v5_pre_binding_schema()?;
    classify_privacy_v5_partial_in_transaction_inner(
        transaction,
        expected_workspace_instance_id,
        &partial_schema,
    )
}

fn classify_privacy_v5_partial_in_transaction_inner(
    transaction: &rusqlite::Transaction<'_>,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    partial_schema: &ExactPrivacyV5Schema,
) -> Result<PrivacyV5PartialProof, PrivacyV5ManifestError> {
    let (data_version_before, schema_object_count) =
        authenticate_exact_v5_snapshot(transaction, partial_schema)?;
    validate_initial_v5_transformation(transaction)?;
    let source = reconstruct_privacy_v1_projection_from_evolved_store_read_only(transaction)
        .map_err(map_source_error)?;
    let stage = classify_initial_lifecycle_prefix(transaction, expected_workspace_instance_id)?;
    let (logical, business) = canonical_sqlite_manifests(
        transaction,
        partial_schema.table_definitions.clone(),
        &PRIVACY_V5_BUSINESS_MANIFEST_EXCLUDED_TABLES,
    )
    .map_err(map_source_error)?;
    let data_version_after = sqlite_data_version(transaction)?;
    if data_version_before != data_version_after {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }
    Ok(PrivacyV5PartialProof {
        stage,
        schema_object_count,
        logical_manifest_sha256: logical.sha256,
        business_manifest_sha256: business.sha256,
        source_business_manifest_sha256: source.business_manifest_sha256,
        source_total_row_count: source.total_row_count,
        protected_review_payload_count: source.protected_review_payload_count,
    })
}

/// Authenticates one self-contained raw schema-5 SQLite image entirely in
/// SQLite-owned memory.  This is the custom migration-checkpoint verifier for
/// the V3 Privacy slot; ordinary application restore must continue to treat
/// that slot as an encrypted current-schema Privacy bundle and will reject the
/// checkpoint's user schema 10 before staging anything.
pub fn validate_privacy_v5_sqlite_image_read_only(
    sqlite_image: &[u8],
) -> Result<PrivacyV5ManifestProof, PrivacyV5ManifestError> {
    if sqlite_image.len() < 100
        || sqlite_image.len() > crate::lifecycle::MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES
        || !sqlite_image.starts_with(b"SQLite format 3\0")
    {
        return Err(PrivacyV5ManifestError::DataBoundary);
    }
    let image_length =
        u64::try_from(sqlite_image.len()).map_err(|_| PrivacyV5ManifestError::DataBoundary)?;
    let mut connection =
        Connection::open_in_memory().map_err(|_| PrivacyV5ManifestError::Database)?;
    connection
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            Cursor::new(sqlite_image),
            sqlite_image.len(),
            true,
        )
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    let expected_length = u64::try_from(page_size)
        .ok()
        .and_then(|size| {
            u64::try_from(page_count)
                .ok()
                .and_then(|count| size.checked_mul(count))
        })
        .filter(|length| *length > 0)
        .ok_or(PrivacyV5ManifestError::DataBoundary)?;
    if expected_length != image_length {
        return Err(PrivacyV5ManifestError::DataBoundary);
    }
    compute_privacy_v5_manifests_read_only(&connection)
}

fn compute_from_pinned_snapshot(
    connection: &Connection,
    exact_schema: &ExactPrivacyV5Schema,
) -> Result<PrivacyV5ManifestProof, PrivacyV5ManifestError> {
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
            .map_err(|_| PrivacyV5ManifestError::Database)?;
    let (data_version_before, schema_object_count) =
        authenticate_exact_v5_snapshot(&transaction, exact_schema)?;
    let proof = compute_manifest_from_authenticated_snapshot(
        &transaction,
        exact_schema,
        data_version_before,
        schema_object_count,
    )?;
    transaction
        .commit()
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    Ok(proof)
}

fn authenticate_exact_v5_snapshot(
    connection: &Connection,
    exact_schema: &ExactPrivacyV5Schema,
) -> Result<(i64, u64), PrivacyV5ManifestError> {
    require_intermediate_v5(connection)?;
    let data_version_before = sqlite_data_version(connection)?;
    validate_quick_check(connection).map_err(map_source_error)?;
    validate_foreign_keys(connection).map_err(map_source_error)?;
    validate_v5_schema(connection).map_err(map_store_error)?;

    let actual_application_objects = schema_objects(connection).map_err(map_source_error)?;
    let actual_internal_objects = internal_schema_objects(connection).map_err(map_source_error)?;
    if actual_application_objects != exact_schema.application_objects
        || actual_internal_objects != exact_schema.internal_objects
    {
        return Err(PrivacyV5ManifestError::UnsupportedSchema);
    }
    let schema_object_count = u64::try_from(actual_application_objects.len())
        .map_err(|_| PrivacyV5ManifestError::DataBoundary)?;
    Ok((data_version_before, schema_object_count))
}

fn compute_manifest_from_authenticated_snapshot(
    connection: &Connection,
    exact_schema: &ExactPrivacyV5Schema,
    data_version_before: i64,
    schema_object_count: u64,
) -> Result<PrivacyV5ManifestProof, PrivacyV5ManifestError> {
    let (logical, business) = canonical_sqlite_manifests(
        connection,
        exact_schema.table_definitions.clone(),
        &PRIVACY_V5_BUSINESS_MANIFEST_EXCLUDED_TABLES,
    )
    .map_err(map_source_error)?;
    let data_version_after = sqlite_data_version(connection)?;
    if data_version_before != data_version_after {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }

    let table_count = u64::try_from(exact_schema.table_definitions.len())
        .map_err(|_| PrivacyV5ManifestError::DataBoundary)?;
    let logical = convert_logical_manifest(logical);
    let total_row_count = logical.total_row_count;
    Ok(PrivacyV5ManifestProof {
        schema_version: INTERMEDIATE_PRIVACY_STORE_SCHEMA_VERSION,
        schema_manifest_sha256: exact_schema.schema_manifest_sha256.clone(),
        internal_schema_manifest_sha256: exact_schema.internal_schema_manifest_sha256.clone(),
        schema_object_count,
        table_count,
        total_row_count,
        data_version: data_version_before,
        logical_manifest: logical,
        business_manifest: convert_business_manifest(business),
    })
}

fn build_exact_privacy_v5_schema() -> Result<ExactPrivacyV5Schema, PrivacyV5ManifestError> {
    let mut fixture = canonical_v5_fixture()?;
    ProjectPrivacyCaseBindingStore::initialize(&mut fixture)
        .map_err(|_| PrivacyV5ManifestError::UnsupportedSchema)?;
    require_intermediate_v5(&fixture)?;
    validate_v5_schema(&fixture).map_err(map_store_error)?;

    let application_objects = schema_objects(&fixture).map_err(map_source_error)?;
    let internal_objects = internal_schema_objects(&fixture).map_err(map_source_error)?;
    let table_definitions = application_objects
        .iter()
        .filter(|object| object.object_type == "table")
        .map(|object| (object.name.clone(), object.sql.clone()))
        .collect::<Vec<_>>();
    let table_names = table_definitions
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    if table_names != PRIVACY_V5_APPLICATION_TABLES
        || table_definitions
            .windows(2)
            .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
    {
        return Err(PrivacyV5ManifestError::UnsupportedSchema);
    }
    let application_schema_manifest_sha256 = schema_manifest_sha256(&application_objects)?;
    let internal_schema_manifest_sha256 = schema_manifest_sha256(&internal_objects)?;
    if application_schema_manifest_sha256 != PRIVACY_V5_SCHEMA_MANIFEST_SHA256
        || internal_schema_manifest_sha256 != PRIVACY_V5_INTERNAL_SCHEMA_MANIFEST_SHA256
        || u64::try_from(application_objects.len())
            .map_err(|_| PrivacyV5ManifestError::DataBoundary)?
            != PRIVACY_V5_SCHEMA_OBJECT_COUNT
    {
        return Err(PrivacyV5ManifestError::UnsupportedSchema);
    }
    Ok(ExactPrivacyV5Schema {
        schema_manifest_sha256: application_schema_manifest_sha256,
        internal_schema_manifest_sha256,
        application_objects,
        internal_objects,
        table_definitions,
    })
}

fn build_exact_privacy_v5_pre_binding_schema(
) -> Result<ExactPrivacyV5Schema, PrivacyV5ManifestError> {
    let fixture = canonical_v5_fixture()?;
    require_intermediate_v5(&fixture)?;
    validate_v5_schema(&fixture).map_err(map_store_error)?;
    let application_objects = schema_objects(&fixture).map_err(map_source_error)?;
    let internal_objects = internal_schema_objects(&fixture).map_err(map_source_error)?;
    let table_definitions = application_objects
        .iter()
        .filter(|object| object.object_type == "table")
        .map(|object| (object.name.clone(), object.sql.clone()))
        .collect::<Vec<_>>();
    if table_definitions.is_empty()
        || table_definitions
            .windows(2)
            .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
        || table_definitions.iter().any(|(name, _)| {
            matches!(
                name.as_str(),
                "project_privacy_case_binding_audit" | "project_privacy_case_bindings"
            )
        })
    {
        return Err(PrivacyV5ManifestError::UnsupportedSchema);
    }
    Ok(ExactPrivacyV5Schema {
        schema_manifest_sha256: schema_manifest_sha256(&application_objects)?,
        internal_schema_manifest_sha256: schema_manifest_sha256(&internal_objects)?,
        application_objects,
        internal_objects,
        table_definitions,
    })
}

fn validate_initial_v5_transformation(
    connection: &Connection,
) -> Result<(), PrivacyV5ManifestError> {
    let metadata = connection
        .prepare("SELECT key,value,updated_at FROM privacy_schema_metadata ORDER BY key")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    if metadata.len() != 1
        || metadata[0].0 != "schema_version"
        || metadata[0].1 != "5"
        || metadata[0].2.is_empty()
        || metadata[0].2.len() > 128
        || metadata[0].2.chars().any(char::is_control)
    {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }

    let invalid_materials = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_materials
             WHERE project_id IS NOT NULL
                OR protected_display_name IS NOT NULL
                OR display_name_sha256 IS NOT NULL
                OR display_name_protection_scheme IS NOT NULL
                OR source_kind<>'local_review'
                OR extraction_status IS NOT state
                OR migration_status<>'unassigned'
                OR row_version<>1
                OR deleted_at IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    let invalid_redactions = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_redactions AS redaction
             WHERE generation_number <> (
                       SELECT 1 + COUNT(*)
                       FROM privacy_redactions AS earlier
                       WHERE earlier.material_id=redaction.material_id
                         AND (
                           earlier.created_at<redaction.created_at
                           OR (earlier.created_at=redaction.created_at
                               AND earlier.redaction_id<redaction.redaction_id)
                         )
                   )
                OR generation_status IS NOT CASE
                     WHEN review_state='approved' THEN 'blocked' ELSE 'ready' END
                OR risk_revision<>0
                OR approved_at IS NOT CASE
                     WHEN review_state='approved'
                      AND reviewed_at IS NOT NULL
                      AND datetime(reviewed_at) IS NOT NULL
                     THEN reviewed_at ELSE NULL END
                OR revocation_state IS NOT CASE
                     WHEN review_state='revoked'
                     THEN 'revoked_legacy_time_unknown' ELSE 'active' END
                OR revoked_at IS NOT NULL
                OR row_version<>1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    let invalid_receipts = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_receipts
             WHERE consumed_at_unix IS NOT NULL OR consumption_id IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    if invalid_materials != 0 || invalid_redactions != 0 || invalid_receipts != 0 {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }
    Ok(())
}

const INITIAL_V5_POST_SOURCE_EMPTY_TABLES: [&str; 15] = [
    "case_material_legacy_references",
    "case_material_migration_events",
    "case_material_migration_ledger",
    "case_material_selections",
    "privacy_approved_outputs",
    "privacy_backup_registry",
    "privacy_cleanup_candidates",
    "privacy_cleanup_journal",
    "privacy_cleanup_redaction_evidence",
    "privacy_mapping_access_audit",
    "privacy_retention_bindings",
    "privacy_risk_review_revisions",
    "privacy_sensitive_mappings",
    "project_privacy_case_binding_audit",
    "project_privacy_case_bindings",
];

fn validate_initial_v5_post_source_tables_empty(
    connection: &Connection,
    binding_schema_present: bool,
) -> Result<(), PrivacyV5ManifestError> {
    for table in INITIAL_V5_POST_SOURCE_EMPTY_TABLES {
        let binding_table = matches!(
            table,
            "project_privacy_case_binding_audit" | "project_privacy_case_bindings"
        );
        if !binding_schema_present && binding_table {
            continue;
        }
        if table_row_count(connection, table)? != 0 {
            return Err(PrivacyV5ManifestError::SourceDrift);
        }
    }
    Ok(())
}

fn classify_initial_lifecycle_prefix(
    connection: &Connection,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<PrivacyV5PartialStage, PrivacyV5ManifestError> {
    validate_initial_v5_post_source_tables_empty(connection, false)?;

    let lifecycle_meta = table_row_count(connection, "privacy_lifecycle_meta")?;
    let mapping_keys = table_row_count(connection, "privacy_mapping_keys")?;
    let retention_policy = table_row_count(connection, "privacy_retention_policy")?;
    match (lifecycle_meta, mapping_keys, retention_policy) {
        (0, 0, 0) => Ok(PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle),
        (1, 1, 1) => {
            validate_exact_initial_lifecycle_state(connection, expected_workspace_instance_id)?;
            Ok(PrivacyV5PartialStage::LifecycleCommittedBeforeBinding)
        }
        _ => Err(PrivacyV5ManifestError::SourceDrift),
    }
}

fn validate_exact_initial_full_v5_state(
    connection: &Connection,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), PrivacyV5ManifestError> {
    validate_initial_v5_post_source_tables_empty(connection, true)?;
    if (
        table_row_count(connection, "privacy_lifecycle_meta")?,
        table_row_count(connection, "privacy_mapping_keys")?,
        table_row_count(connection, "privacy_retention_policy")?,
    ) != (1, 1, 1)
    {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }
    validate_exact_initial_lifecycle_state(connection, expected_workspace_instance_id)
}

fn validate_exact_initial_lifecycle_state(
    connection: &Connection,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), PrivacyV5ManifestError> {
    let meta = connection
        .query_row(
            "SELECT singleton,schema_version,workspace_instance_id,
                    active_mapping_key_version,key_epoch,created_at_unix
             FROM privacy_lifecycle_meta",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|_| PrivacyV5ManifestError::SourceDrift)?;
    if meta.0 != 1
        || meta.1 != PRIVACY_LIFECYCLE_SCHEMA_VERSION
        || meta.2 != expected_workspace_instance_id.as_str()
        || meta.3 != 1
        || meta.4 != 1
        || meta.5 <= 0
    {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }

    let mapping_key = connection
        .query_row(
            "SELECT key_version,protected_key,protected_key_sha256,state,created_at_unix,
                    retired_at_unix,revoked_at_unix,destroyed_at_unix
             FROM privacy_mapping_keys",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .map_err(|_| PrivacyV5ManifestError::SourceDrift)?;
    let protected_key = mapping_key
        .1
        .as_deref()
        .ok_or(PrivacyV5ManifestError::SourceDrift)?;
    if mapping_key.0 != 1
        || mapping_key.2 != sha256_hex(protected_key)
        || mapping_key.3 != "active"
        || mapping_key.4 != meta.5
        || mapping_key.5.is_some()
        || mapping_key.6.is_some()
        || mapping_key.7.is_some()
        || unwrap_case_key(protected_key).is_err()
    {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }

    let created_at = u64::try_from(meta.5).map_err(|_| PrivacyV5ManifestError::DataBoundary)?;
    let lifecycle = PrivacyLifecycle::open(connection, expected_workspace_instance_id.clone())
        .map_err(|_| PrivacyV5ManifestError::SourceDrift)?;
    if lifecycle
        .current_key_epoch(connection)
        .map_err(|_| PrivacyV5ManifestError::SourceDrift)?
        != 1
        || lifecycle
            .retention_policy(connection)
            .map_err(|_| PrivacyV5ManifestError::SourceDrift)?
            != RetentionPolicyV1::default_at(created_at)
                .map_err(|_| PrivacyV5ManifestError::SourceDrift)?
    {
        return Err(PrivacyV5ManifestError::SourceDrift);
    }
    Ok(())
}

fn table_row_count(
    connection: &Connection,
    table_name: &str,
) -> Result<i64, PrivacyV5ManifestError> {
    if table_name.is_empty()
        || !table_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PrivacyV5ManifestError::UnsupportedSchema);
    }
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM \"{table_name}\""),
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyV5ManifestError::Database)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_v5_fixture() -> Result<Connection, PrivacyV5ManifestError> {
    let fixture = Connection::open_in_memory().map_err(|_| PrivacyV5ManifestError::Database)?;
    fixture
        .execute_batch(PRIVACY_V1_SCHEMA_MANIFEST_DDL)
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    fixture
        .execute(
            "INSERT INTO privacy_schema_metadata(key,value,updated_at)
             VALUES('schema_version','1','2026-07-19 15:41:29')",
            [],
        )
        .map_err(|_| PrivacyV5ManifestError::Database)?;
    PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&fixture)
        .map_err(map_store_error)?;
    Ok(fixture)
}

fn require_intermediate_v5(connection: &Connection) -> Result<(), PrivacyV5ManifestError> {
    match PrivacyStore::preflight_schema(connection).map_err(map_store_error)? {
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version }
            if found_version == INTERMEDIATE_PRIVACY_STORE_SCHEMA_VERSION =>
        {
            Ok(())
        }
        PrivacyStoreSchemaStatus::Empty
        | PrivacyStoreSchemaStatus::Current
        | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        }
    }
}

fn schema_manifest_sha256(objects: &[SchemaObject]) -> Result<String, PrivacyV5ManifestError> {
    let mut encoded = Vec::new();
    for object in objects {
        serde_json::to_writer(&mut encoded, object)
            .map_err(|_| PrivacyV5ManifestError::UnsupportedSchema)?;
        encoded.push(b'\n');
    }
    Ok(sha256_hex(&encoded))
}

fn sqlite_data_version(connection: &Connection) -> Result<i64, PrivacyV5ManifestError> {
    connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| PrivacyV5ManifestError::Database)
}

fn convert_logical_manifest(manifest: PrivacyV1LogicalManifest) -> PrivacyV5LogicalManifest {
    PrivacyV5LogicalManifest {
        sha256: manifest.sha256,
        total_row_count: manifest.total_row_count,
        tables: manifest
            .tables
            .into_iter()
            .map(|table| PrivacyV5LogicalTableManifest {
                table_name: table.table_name,
                row_count: table.row_count,
                sha256: table.sha256,
            })
            .collect(),
    }
}

fn convert_business_manifest(manifest: PrivacyV1BusinessManifest) -> PrivacyV5BusinessManifest {
    PrivacyV5BusinessManifest {
        sha256: manifest.sha256,
        primary_key_sha256: manifest.primary_key_sha256,
        row_sha256: manifest.row_sha256,
        total_row_count: manifest.total_row_count,
        tables: manifest
            .tables
            .into_iter()
            .map(|table| PrivacyV5BusinessTableManifest {
                table_name: table.table_name,
                row_count: table.row_count,
                sha256: table.sha256,
                primary_key_sha256: table.primary_key_sha256,
                row_sha256: table.row_sha256,
            })
            .collect(),
    }
}

fn map_store_error(error: PrivacyStoreError) -> PrivacyV5ManifestError {
    match error {
        PrivacyStoreError::Database => PrivacyV5ManifestError::Database,
        PrivacyStoreError::UnsupportedSchema => PrivacyV5ManifestError::UnsupportedSchema,
        PrivacyStoreError::Conflict => PrivacyV5ManifestError::DataBoundary,
        PrivacyStoreError::InvalidInput
        | PrivacyStoreError::NotApproved
        | PrivacyStoreError::ProtectedBlob
        | PrivacyStoreError::InvalidReceipt
        | PrivacyStoreError::ReceiptRevoked
        | PrivacyStoreError::ReceiptExpired
        | PrivacyStoreError::ReceiptConsumed => PrivacyV5ManifestError::DataBoundary,
    }
}

fn map_source_error(error: PrivacyV1SourceValidationError) -> PrivacyV5ManifestError {
    match error {
        PrivacyV1SourceValidationError::Database => PrivacyV5ManifestError::Database,
        PrivacyV1SourceValidationError::SchemaMismatch
        | PrivacyV1SourceValidationError::SchemaVersionMismatch
        | PrivacyV1SourceValidationError::UnsafeFilesystem => {
            PrivacyV5ManifestError::UnsupportedSchema
        }
        PrivacyV1SourceValidationError::IntegrityCheckFailed => {
            PrivacyV5ManifestError::IntegrityCheckFailed
        }
        PrivacyV1SourceValidationError::ForeignKeyViolation => {
            PrivacyV5ManifestError::ForeignKeyViolation
        }
        PrivacyV1SourceValidationError::DataBoundary
        | PrivacyV1SourceValidationError::ProtectedReviewPayload => {
            PrivacyV5ManifestError::DataBoundary
        }
        PrivacyV1SourceValidationError::SourceDrift => PrivacyV5ManifestError::SourceDrift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::migration_source::PrivacyV1EvolvedProjectionProof;
    #[cfg(windows)]
    use crate::with_validated_privacy_v5_migration_source_read_only;
    use crate::{BindingCreationSource, BindingLifecycleContext, ProjectId};

    fn exact_fixture() -> Connection {
        let mut connection = canonical_v5_fixture().expect("canonical v5 fixture");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("binding schema initializes");
        connection
    }

    #[cfg(windows)]
    fn initial_full_fixture(workspace: &WorkspaceInstanceId) -> Connection {
        let mut connection = canonical_v5_fixture().expect("canonical v5 fixture");
        PrivacyLifecycle::initialize(&mut connection, workspace.clone(), 1_800_000_000)
            .expect("initial lifecycle initializes");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("binding schema initializes");
        connection
    }

    #[cfg(windows)]
    fn initial_full_fixture_with_source_material(workspace: &WorkspaceInstanceId) -> Connection {
        let mut connection = Connection::open_in_memory().expect("v1 fixture opens");
        connection
            .execute_batch(PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .expect("v1 schema initializes");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                 VALUES('schema_version','1','2026-07-19 15:41:29')",
                [],
            )
            .expect("v1 schema version inserts");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                   material_id,project_id,attachment_id,source_sha256,
                   source_name_sha256,media_type,page_count,state
                 ) VALUES(?1,?2,NULL,?3,?4,'application/pdf',1,'review_required')",
                rusqlite::params![
                    "material-projection-source",
                    "case-projection-source",
                    sha256_hex(b"projection-source"),
                    sha256_hex(b"projection-name"),
                ],
            )
            .expect("v1 source material inserts");
        PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&connection)
            .expect("v1 upgrades to v5");
        PrivacyLifecycle::initialize(&mut connection, workspace.clone(), 1_800_000_000)
            .expect("initial lifecycle initializes");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("binding schema initializes");
        connection
    }

    #[cfg(windows)]
    fn initial_full_expectation<'a>(
        workspace: &'a WorkspaceInstanceId,
        source: &'a PrivacyV1EvolvedProjectionProof,
    ) -> PrivacyV5InitialFullExpectation<'a> {
        PrivacyV5InitialFullExpectation {
            expected_workspace_instance_id: workspace,
            expected_source_business_manifest_sha256: &source.business_manifest_sha256,
            expected_source_total_row_count: source.total_row_count,
            expected_protected_review_payload_count: source.protected_review_payload_count,
        }
    }

    fn partial_workspace(character: char) -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse(format!(
            "ws_{}",
            std::iter::repeat_n(character, 32).collect::<String>()
        ))
        .expect("partial-v5 workspace id")
    }

    #[test]
    fn caller_owned_transaction_partial_classifier_matches_read_only_wrapper() {
        let workspace = partial_workspace('0');
        let connection = canonical_v5_fixture().expect("schema-only partial v5");
        let wrapper = classify_privacy_v5_partial_read_only(&connection, &workspace)
            .expect("read-only wrapper classifies");
        let transaction =
            rusqlite::Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)
                .expect("caller-owned transaction begins");
        assert!(!transaction
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("query-only reads"));
        let in_transaction = classify_privacy_v5_partial_in_transaction(&transaction, &workspace)
            .expect("transaction classifier classifies");
        assert_eq!(in_transaction, wrapper);
        assert!(!transaction.is_autocommit());
        assert!(!transaction
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("classifier leaves query-only unchanged"));
        transaction
            .rollback()
            .expect("caller rolls transaction back");
    }

    #[test]
    fn partial_v5_classifier_accepts_only_exact_schema_prefix_and_rejects_extra_or_half_binding() {
        let workspace = partial_workspace('1');
        let exact = canonical_v5_fixture().expect("schema-only partial v5");
        let proof = classify_privacy_v5_partial_read_only(&exact, &workspace)
            .expect("exact schema-only prefix classifies");
        assert_eq!(
            proof.stage(),
            PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle
        );
        assert_eq!(proof.source_total_row_count(), 1);
        assert_eq!(proof.protected_review_payload_count(), 0);
        assert_eq!(proof.logical_manifest_sha256().len(), 64);
        assert_eq!(proof.business_manifest_sha256().len(), 64);
        assert!(!exact
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("query-only restored"));

        let extra = canonical_v5_fixture().expect("extra-object partial v5");
        extra
            .execute_batch("CREATE TABLE unexpected_partial_v5(id TEXT PRIMARY KEY);")
            .expect("extra partial object");
        assert_eq!(
            classify_privacy_v5_partial_read_only(&extra, &workspace),
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        );

        let half_binding = canonical_v5_fixture().expect("half-binding partial v5");
        half_binding
            .execute_batch(
                "CREATE TABLE project_privacy_case_binding_audit(
                   creation_audit_id TEXT PRIMARY KEY
                 );",
            )
            .expect("one binding object only");
        assert_eq!(
            classify_privacy_v5_partial_read_only(&half_binding, &workspace),
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        );

        let full = exact_fixture();
        assert_eq!(
            classify_privacy_v5_partial_read_only(&full, &workspace),
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        );
    }

    #[cfg(windows)]
    #[test]
    fn partial_v5_classifier_binds_exact_initial_lifecycle_workspace_and_dpapi_key() {
        let workspace = partial_workspace('2');
        let mut exact = canonical_v5_fixture().expect("lifecycle partial v5");
        PrivacyLifecycle::initialize(&mut exact, workspace.clone(), 1_800_000_000)
            .expect("initial lifecycle commits");
        let proof = classify_privacy_v5_partial_read_only(&exact, &workspace)
            .expect("exact lifecycle prefix classifies");
        assert_eq!(
            proof.stage(),
            PrivacyV5PartialStage::LifecycleCommittedBeforeBinding
        );
        assert_eq!(proof.source_total_row_count(), 1);
        assert!(classify_privacy_v5_partial_read_only(&exact, &partial_workspace('3')).is_err());

        exact
            .execute(
                "UPDATE privacy_mapping_keys
                 SET protected_key_sha256=?1 WHERE key_version=1",
                ["f".repeat(64)],
            )
            .expect("mapping-key hash tamper");
        assert!(classify_privacy_v5_partial_read_only(&exact, &workspace).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn initial_full_v5_before_receipt4_accepts_only_the_authenticated_initial_state() {
        let workspace = partial_workspace('4');
        let connection = initial_full_fixture(&workspace);
        let source = reconstruct_privacy_v1_projection_from_evolved_store_read_only(&connection)
            .expect("initial v1 projection reconstructs");
        let proof = verify_initial_privacy_v5_before_receipt4_read_only(
            &connection,
            &initial_full_expectation(&workspace, &source),
        )
        .expect("exact initial full v5 verifies");
        assert_eq!(
            proof.manifest().schema_object_count,
            PRIVACY_V5_SCHEMA_OBJECT_COUNT
        );
        assert_eq!(
            proof.source_business_manifest_sha256(),
            source.business_manifest_sha256
        );
        assert_eq!(proof.source_total_row_count(), source.total_row_count);
        assert_eq!(
            proof.protected_review_payload_count(),
            source.protected_review_payload_count
        );
        assert!(!connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("query-only restores"));
    }

    #[cfg(windows)]
    #[test]
    fn initial_full_v5_before_receipt4_rejects_binding_lifecycle_workspace_and_projection_drift() {
        let workspace = partial_workspace('5');

        let mut binding = initial_full_fixture(&workspace);
        let binding_source =
            reconstruct_privacy_v1_projection_from_evolved_store_read_only(&binding)
                .expect("binding source reconstructs");
        ProjectPrivacyCaseBindingStore::resolve_or_create(
            &mut binding,
            &ProjectId::parse("case-full-v5-binding-tamper").expect("project id"),
            &BindingLifecycleContext::new(
                BindingCreationSource::LegacyMigration,
                "initial-full-v5-binding-tamper",
                Some("project-privacy-case-binding-v1".to_owned()),
            )
            .expect("binding context"),
        )
        .expect("valid binding tamper inserts");
        assert_eq!(
            verify_initial_privacy_v5_before_receipt4_read_only(
                &binding,
                &initial_full_expectation(&workspace, &binding_source),
            ),
            Err(PrivacyV5ManifestError::SourceDrift)
        );

        let extra_lifecycle = initial_full_fixture(&workspace);
        let extra_lifecycle_source =
            reconstruct_privacy_v1_projection_from_evolved_store_read_only(&extra_lifecycle)
                .expect("lifecycle source reconstructs");
        extra_lifecycle
            .execute(
                "INSERT INTO privacy_mapping_keys(
                   key_version,protected_key,protected_key_sha256,state,created_at_unix,
                   retired_at_unix,revoked_at_unix,destroyed_at_unix
                 )
                 SELECT 2,protected_key,protected_key_sha256,'retired',created_at_unix,
                        created_at_unix,NULL,NULL
                 FROM privacy_mapping_keys WHERE key_version=1",
                [],
            )
            .expect("valid extra lifecycle row inserts");
        assert_eq!(
            verify_initial_privacy_v5_before_receipt4_read_only(
                &extra_lifecycle,
                &initial_full_expectation(&workspace, &extra_lifecycle_source),
            ),
            Err(PrivacyV5ManifestError::SourceDrift)
        );

        let wrong_workspace = initial_full_fixture(&workspace);
        let wrong_workspace_source =
            reconstruct_privacy_v1_projection_from_evolved_store_read_only(&wrong_workspace)
                .expect("workspace source reconstructs");
        wrong_workspace
            .execute(
                "UPDATE privacy_lifecycle_meta SET workspace_instance_id=?1 WHERE singleton=1",
                [partial_workspace('6').as_str()],
            )
            .expect("wrong workspace writes");
        assert_eq!(
            verify_initial_privacy_v5_before_receipt4_read_only(
                &wrong_workspace,
                &initial_full_expectation(&workspace, &wrong_workspace_source),
            ),
            Err(PrivacyV5ManifestError::SourceDrift)
        );

        let projection = initial_full_fixture_with_source_material(&workspace);
        let projection_source =
            reconstruct_privacy_v1_projection_from_evolved_store_read_only(&projection)
                .expect("material source reconstructs");
        projection
            .execute(
                "INSERT INTO privacy_materials(
                   material_id,project_id,legacy_case_id,attachment_id,
                   protected_display_name,display_name_sha256,
                   display_name_protection_scheme,source_sha256,source_name_sha256,
                   media_type,page_count,source_kind,extraction_status,migration_status,
                   state,row_version,created_at,updated_at,deleted_at
                 ) VALUES(
                   'material-projection-drift',NULL,'case-projection-drift',NULL,
                   NULL,NULL,NULL,?1,?2,'application/pdf',1,'local_review',
                   'review_required','unassigned','review_required',1,
                   '2026-07-19 15:41:29','2026-07-19 15:41:29',NULL
                 )",
                rusqlite::params![
                    sha256_hex(b"projection-drift-source"),
                    sha256_hex(b"projection-drift-name"),
                ],
            )
            .expect("valid evolved projection drift writes");
        assert_eq!(
            verify_initial_privacy_v5_before_receipt4_read_only(
                &projection,
                &initial_full_expectation(&workspace, &projection_source),
            ),
            Err(PrivacyV5ManifestError::SourceDrift)
        );
    }

    #[test]
    fn exact_v5_proof_is_read_only_deterministic_and_counted() {
        let connection = exact_fixture();
        let first = compute_privacy_v5_manifests_read_only(&connection).expect("first proof");
        let second = compute_privacy_v5_manifests_read_only(&connection).expect("second proof");
        assert_eq!(first, second);
        assert_eq!(first.schema_version, 5);
        assert_eq!(
            first.schema_manifest_sha256,
            PRIVACY_V5_SCHEMA_MANIFEST_SHA256
        );
        assert_eq!(
            first.internal_schema_manifest_sha256,
            PRIVACY_V5_INTERNAL_SCHEMA_MANIFEST_SHA256
        );
        assert_eq!(first.schema_object_count, PRIVACY_V5_SCHEMA_OBJECT_COUNT);
        assert_eq!(
            first.table_count,
            PRIVACY_V5_APPLICATION_TABLES.len() as u64
        );
        assert_eq!(
            first.logical_manifest.tables.len(),
            first.table_count as usize
        );
        assert_eq!(
            first.business_manifest.tables.len() + 1,
            first.table_count as usize
        );
        assert_eq!(
            first.total_row_count,
            first.logical_manifest.total_row_count
        );
        assert!(first.schema_object_count > first.table_count);
        assert!(!connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("query-only restored"));
    }

    #[test]
    fn exact_v5_manifest_changes_with_committed_business_rows() {
        let mut connection = exact_fixture();
        let before = compute_privacy_v5_manifests_read_only(&connection).expect("before proof");
        let project = ProjectId::parse("case-v5-manifest-project").expect("project id");
        ProjectPrivacyCaseBindingStore::resolve_or_create(
            &mut connection,
            &project,
            &BindingLifecycleContext::new(
                BindingCreationSource::LegacyMigration,
                "v5-manifest-binding",
                Some("project-privacy-case-binding-v1".to_owned()),
            )
            .expect("binding context"),
        )
        .expect("binding");
        let after = compute_privacy_v5_manifests_read_only(&connection).expect("after proof");
        assert_eq!(before.schema_manifest_sha256, after.schema_manifest_sha256);
        assert_ne!(
            before.logical_manifest.sha256,
            after.logical_manifest.sha256
        );
        assert_ne!(
            before.business_manifest.sha256,
            after.business_manifest.sha256
        );
        assert!(after.total_row_count > before.total_row_count);
    }

    #[cfg(windows)]
    #[test]
    #[allow(unsafe_code)]
    fn wal_source_backup_api_produces_one_exact_self_contained_v5_image() {
        let source_directory = tempfile::tempdir().expect("source directory");
        let source_path = source_directory.path().join("privacy-v5.sqlite");
        let source_fixture = exact_fixture();
        let mut writer = Connection::open(&source_path).expect("file destination opens");
        rusqlite::backup::Backup::new(&source_fixture, &mut writer)
            .expect("fixture backup starts")
            .run_to_completion(64, std::time::Duration::from_millis(1), None)
            .expect("fixture backup completes");
        drop(source_fixture);
        writer
            .pragma_update(None, "journal_mode", "WAL")
            .expect("WAL mode enables");
        writer
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpoint disables");
        let mut persist = 1_i32;
        let status = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                writer.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persist as *mut i32).cast(),
            )
        };
        assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        writer
            .execute(
                "UPDATE privacy_schema_metadata
                 SET updated_at='2026-08-01 00:00:01'
                 WHERE key='schema_version'",
                [],
            )
            .expect("committed WAL row writes");
        let _: i64 = writer
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .expect("WAL reader initializes shared memory");
        drop(writer);
        assert!(source_path
            .with_file_name("privacy-v5.sqlite-wal")
            .is_file());
        assert!(source_path
            .with_file_name("privacy-v5.sqlite-shm")
            .is_file());

        let (source_proof, image) =
            with_validated_privacy_v5_migration_source_read_only(&source_path, |session| {
                let mut destination = Connection::open_in_memory().expect("image target opens");
                session
                    .backup_to(&mut destination)
                    .expect("Backup API copies pinned WAL snapshot");
                let mut image = destination
                    .serialize(rusqlite::MAIN_DB)
                    .expect("image serializes")
                    .to_vec();
                assert_eq!(image.get(18..20), Some([2_u8, 2_u8].as_slice()));
                image[18] = 1;
                image[19] = 1;
                image
            })
            .expect("exact WAL source validates");
        let image_proof = validate_privacy_v5_sqlite_image_read_only(&image)
            .expect("self-contained v5 image validates");
        assert_eq!(image_proof.schema_version, source_proof.schema_version);
        assert_eq!(
            image_proof.schema_manifest_sha256,
            source_proof.schema_manifest_sha256
        );
        assert_eq!(
            image_proof.internal_schema_manifest_sha256,
            source_proof.internal_schema_manifest_sha256
        );
        assert_eq!(
            image_proof.schema_object_count,
            source_proof.schema_object_count
        );
        assert_eq!(image_proof.table_count, source_proof.table_count);
        assert_eq!(image_proof.total_row_count, source_proof.total_row_count);
        assert_eq!(image_proof.logical_manifest, source_proof.logical_manifest);
        assert_eq!(
            image_proof.business_manifest,
            source_proof.business_manifest
        );
        // `data_version` is connection-local.  The independently attached
        // immutable image starts at one while the original file connection
        // observed the committed WAL write at two.
        assert_eq!(image_proof.data_version, 1);
        assert_eq!(source_proof.data_version, 2);
        assert_eq!(
            image_proof.logical_manifest.tables,
            source_proof.logical_manifest.tables
        );
    }

    #[test]
    fn extra_or_weakened_schema_objects_are_rejected() {
        let extra = exact_fixture();
        extra
            .execute("CREATE TABLE unexpected_v5_state(id TEXT PRIMARY KEY)", [])
            .expect("extra table");
        assert_eq!(
            compute_privacy_v5_manifests_read_only(&extra),
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        );

        let weak = exact_fixture();
        weak.execute_batch(
            "DROP TRIGGER trg_case_material_migration_ledger_no_update;
             CREATE TRIGGER trg_case_material_migration_ledger_no_update
             BEFORE UPDATE ON case_material_migration_ledger BEGIN SELECT 1; END;",
        )
        .expect("weaken trigger");
        assert_eq!(
            compute_privacy_v5_manifests_read_only(&weak),
            Err(PrivacyV5ManifestError::UnsupportedSchema)
        );
    }

    #[test]
    fn foreign_key_violation_is_rejected_before_manifest_success() {
        let connection = exact_fixture();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("disable foreign keys for malformed fixture");
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                   redaction_id,material_id,generation_number,generation_status,
                   extraction_sha256,redacted_content_sha256,policy_id,policy_version,
                   detector_version,unresolved_high_risk_count,review_state,risk_revision,
                   protected_review_blob,protection_scheme,revocation_state,row_version
                 ) VALUES(
                   'redaction-orphan','missing-material',1,'ready',?1,?2,
                   'policy',1,'detector',0,'review_required',0,X'01',
                   'windows_dpapi_current_user_v1','active',1
                 )",
                [sha256_hex(b"extraction"), sha256_hex(b"redacted")],
            )
            .expect("orphan row");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("restore foreign keys");
        assert_eq!(
            compute_privacy_v5_manifests_read_only(&connection),
            Err(PrivacyV5ManifestError::ForeignKeyViolation)
        );
    }
}
