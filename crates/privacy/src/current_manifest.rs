use crate::{
    migration_source::{
        canonical_sqlite_manifests,
        canonical_sqlite_manifests_excluding_application_upgrade_lineage, internal_schema_objects,
        schema_objects, validate_foreign_keys, validate_quick_check, PrivacyV1BusinessManifest,
        PrivacyV1LogicalManifest, PrivacyV1SourceValidationError, SchemaObject,
    },
    project_case_binding::ProjectPrivacyCaseBindingStore,
    store::{
        configure_v6_connection, validate_v6_schema, PrivacyStore, PrivacyStoreError,
        PrivacyStoreSchemaStatus, PRIVACY_STORE_SCHEMA_VERSION,
    },
    upgrade_lineage::{
        load_application_upgrade_lineage, PRIVACY_V6_BUSINESS_MANIFEST_EXCLUDED_TABLES,
    },
    v6_application_schema::initialize_privacy_v6_application_extensions,
};
use rusqlite::{Connection, TransactionBehavior};

pub const PRIVACY_V6_APPLICATION_TABLES: [&str; 29] = [
    "application_upgrade_lineage",
    "case_material_assignment_audit",
    "case_material_legacy_references",
    "case_material_migration_events",
    "case_material_migration_ledger",
    "case_material_selections",
    "privacy_approved_outputs",
    "privacy_backup_registry",
    "privacy_case_dictionary_heads",
    "privacy_cleanup_candidates",
    "privacy_cleanup_journal",
    "privacy_cleanup_redaction_evidence",
    "privacy_egress_audit",
    "privacy_finding_secret_evidence",
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
    "privacy_vault_material_refs",
    "project_deletion_journal",
    "project_privacy_case_binding_audit",
    "project_privacy_case_bindings",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyV6ManifestError {
    Database,
    UnsupportedSchema,
    DataBoundary,
    IntegrityCheckFailed,
    ForeignKeyViolation,
    SourceDrift,
}

impl PrivacyV6ManifestError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_v6_manifest_database_error",
            Self::UnsupportedSchema => "privacy_v6_manifest_schema_unsupported",
            Self::DataBoundary => "privacy_v6_manifest_data_boundary_invalid",
            Self::IntegrityCheckFailed => "privacy_v6_manifest_integrity_check_failed",
            Self::ForeignKeyViolation => "privacy_v6_manifest_foreign_key_violation",
            Self::SourceDrift => "privacy_v6_manifest_source_drift",
        }
    }
}

impl std::fmt::Display for PrivacyV6ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivacyV6ManifestError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV6ManifestProof {
    pub schema_version: i64,
    pub schema_object_count: usize,
    pub data_version: i64,
    pub logical_manifest: PrivacyV6LogicalManifest,
    pub business_manifest: PrivacyV6BusinessManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV6LogicalManifest {
    pub sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV6LogicalTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV6LogicalTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV6BusinessManifest {
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV6BusinessTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV6BusinessTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
}

struct ExactPrivacyV6Schema {
    application_objects: Vec<SchemaObject>,
    internal_objects: Vec<SchemaObject>,
    table_definitions: Vec<(String, String)>,
}

/// Computes the current Privacy schema-6 logical and business manifests from
/// one pinned deferred/query-only SQLite snapshot. The source connection is
/// never migrated, repaired, or otherwise written.
pub fn compute_privacy_v6_manifests_read_only(
    connection: &Connection,
) -> Result<PrivacyV6ManifestProof, PrivacyV6ManifestError> {
    compute_privacy_v6_manifests_with_optional_exclusion(connection, None)
}

/// Computes the Privacy-v6 target manifests as they existed immediately
/// before one already-appended application-upgrade audit row. Exactly one
/// strictly validated matching lineage row is removed from the logical view;
/// all other historical lineage rows remain, and the frozen business manifest
/// exclusion is unchanged.
pub fn compute_privacy_v6_pre_audit_manifests_read_only(
    connection: &Connection,
    excluded_lineage_id: &str,
) -> Result<PrivacyV6ManifestProof, PrivacyV6ManifestError> {
    compute_privacy_v6_manifests_with_optional_exclusion(connection, Some(excluded_lineage_id))
}

fn compute_privacy_v6_manifests_with_optional_exclusion(
    connection: &Connection,
    excluded_lineage_id: Option<&str>,
) -> Result<PrivacyV6ManifestProof, PrivacyV6ManifestError> {
    if !connection.is_autocommit() {
        return Err(PrivacyV6ManifestError::Database);
    }
    require_current_v6(connection)?;
    configure_v6_connection(connection).map_err(map_store_error)?;
    let exact_schema = build_exact_privacy_v6_schema()?;

    let previous_query_only = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyV6ManifestError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV6ManifestError::Database)?;

    let proof_result = compute_from_pinned_snapshot(connection, &exact_schema, excluded_lineage_id);
    let restore_result = connection
        .pragma_update(
            None,
            "query_only",
            if previous_query_only { "ON" } else { "OFF" },
        )
        .map_err(|_| PrivacyV6ManifestError::Database);
    match (proof_result, restore_result) {
        (Ok(proof), Ok(())) => Ok(proof),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn compute_from_pinned_snapshot(
    connection: &Connection,
    exact_schema: &ExactPrivacyV6Schema,
    excluded_lineage_id: Option<&str>,
) -> Result<PrivacyV6ManifestProof, PrivacyV6ManifestError> {
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
            .map_err(|_| PrivacyV6ManifestError::Database)?;

    // This first application read pins the deferred snapshot before any
    // schema validation, integrity check, or row encoding is performed.
    require_current_v6(&transaction)?;
    let data_version_before = sqlite_data_version(&transaction)?;
    validate_quick_check(&transaction).map_err(map_source_error)?;
    validate_foreign_keys(&transaction).map_err(map_source_error)?;
    validate_v6_schema(&transaction).map_err(map_store_error)?;

    let actual_application_objects = schema_objects(&transaction).map_err(map_source_error)?;
    let actual_internal_objects =
        internal_schema_objects(&transaction).map_err(map_source_error)?;
    if actual_application_objects != exact_schema.application_objects
        || actual_internal_objects != exact_schema.internal_objects
    {
        return Err(PrivacyV6ManifestError::UnsupportedSchema);
    }

    let (logical, business) = if let Some(lineage_id) = excluded_lineage_id {
        if load_application_upgrade_lineage(&transaction, lineage_id)
            .map_err(map_store_error)?
            .is_none()
        {
            return Err(PrivacyV6ManifestError::DataBoundary);
        }
        canonical_sqlite_manifests_excluding_application_upgrade_lineage(
            &transaction,
            exact_schema.table_definitions.clone(),
            &PRIVACY_V6_BUSINESS_MANIFEST_EXCLUDED_TABLES,
            lineage_id,
        )
        .map_err(map_source_error)?
    } else {
        canonical_sqlite_manifests(
            &transaction,
            exact_schema.table_definitions.clone(),
            &PRIVACY_V6_BUSINESS_MANIFEST_EXCLUDED_TABLES,
        )
        .map_err(map_source_error)?
    };
    let data_version_after = sqlite_data_version(&transaction)?;
    if data_version_before != data_version_after {
        return Err(PrivacyV6ManifestError::SourceDrift);
    }

    let proof = PrivacyV6ManifestProof {
        schema_version: PRIVACY_STORE_SCHEMA_VERSION,
        schema_object_count: actual_application_objects.len(),
        data_version: data_version_before,
        logical_manifest: convert_logical_manifest(logical),
        business_manifest: convert_business_manifest(business),
    };
    transaction
        .commit()
        .map_err(|_| PrivacyV6ManifestError::Database)?;
    Ok(proof)
}

fn build_exact_privacy_v6_schema() -> Result<ExactPrivacyV6Schema, PrivacyV6ManifestError> {
    let mut fixture = Connection::open_in_memory().map_err(|_| PrivacyV6ManifestError::Database)?;
    PrivacyStore::initialize(&fixture).map_err(map_store_error)?;
    ProjectPrivacyCaseBindingStore::initialize(&mut fixture)
        .map_err(|_| PrivacyV6ManifestError::UnsupportedSchema)?;
    initialize_privacy_v6_application_extensions(&fixture).map_err(map_store_error)?;
    require_current_v6(&fixture)?;
    configure_v6_connection(&fixture).map_err(map_store_error)?;
    validate_v6_schema(&fixture).map_err(map_store_error)?;

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
    if table_names != PRIVACY_V6_APPLICATION_TABLES
        || table_definitions
            .windows(2)
            .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
    {
        return Err(PrivacyV6ManifestError::UnsupportedSchema);
    }
    Ok(ExactPrivacyV6Schema {
        application_objects,
        internal_objects,
        table_definitions,
    })
}

fn require_current_v6(connection: &Connection) -> Result<(), PrivacyV6ManifestError> {
    match PrivacyStore::preflight_schema(connection).map_err(map_store_error)? {
        PrivacyStoreSchemaStatus::Current => Ok(()),
        PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        }
    }
}

fn sqlite_data_version(connection: &Connection) -> Result<i64, PrivacyV6ManifestError> {
    connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| PrivacyV6ManifestError::Database)
}

fn convert_logical_manifest(manifest: PrivacyV1LogicalManifest) -> PrivacyV6LogicalManifest {
    PrivacyV6LogicalManifest {
        sha256: manifest.sha256,
        total_row_count: manifest.total_row_count,
        tables: manifest
            .tables
            .into_iter()
            .map(|table| PrivacyV6LogicalTableManifest {
                table_name: table.table_name,
                row_count: table.row_count,
                sha256: table.sha256,
            })
            .collect(),
    }
}

fn convert_business_manifest(manifest: PrivacyV1BusinessManifest) -> PrivacyV6BusinessManifest {
    PrivacyV6BusinessManifest {
        sha256: manifest.sha256,
        primary_key_sha256: manifest.primary_key_sha256,
        row_sha256: manifest.row_sha256,
        total_row_count: manifest.total_row_count,
        tables: manifest
            .tables
            .into_iter()
            .map(|table| PrivacyV6BusinessTableManifest {
                table_name: table.table_name,
                row_count: table.row_count,
                sha256: table.sha256,
                primary_key_sha256: table.primary_key_sha256,
                row_sha256: table.row_sha256,
            })
            .collect(),
    }
}

fn map_store_error(error: PrivacyStoreError) -> PrivacyV6ManifestError {
    match error {
        PrivacyStoreError::Database => PrivacyV6ManifestError::Database,
        PrivacyStoreError::UnsupportedSchema => PrivacyV6ManifestError::UnsupportedSchema,
        PrivacyStoreError::Conflict => PrivacyV6ManifestError::DataBoundary,
        PrivacyStoreError::InvalidInput
        | PrivacyStoreError::NotApproved
        | PrivacyStoreError::ProtectedBlob
        | PrivacyStoreError::InvalidReceipt
        | PrivacyStoreError::ReceiptRevoked
        | PrivacyStoreError::ReceiptExpired
        | PrivacyStoreError::ReceiptConsumed => PrivacyV6ManifestError::DataBoundary,
    }
}

fn map_source_error(error: PrivacyV1SourceValidationError) -> PrivacyV6ManifestError {
    match error {
        PrivacyV1SourceValidationError::Database => PrivacyV6ManifestError::Database,
        PrivacyV1SourceValidationError::SchemaMismatch
        | PrivacyV1SourceValidationError::SchemaVersionMismatch
        | PrivacyV1SourceValidationError::UnsafeFilesystem => {
            PrivacyV6ManifestError::UnsupportedSchema
        }
        PrivacyV1SourceValidationError::IntegrityCheckFailed => {
            PrivacyV6ManifestError::IntegrityCheckFailed
        }
        PrivacyV1SourceValidationError::ForeignKeyViolation => {
            PrivacyV6ManifestError::ForeignKeyViolation
        }
        PrivacyV1SourceValidationError::DataBoundary
        | PrivacyV1SourceValidationError::ProtectedReviewPayload => {
            PrivacyV6ManifestError::DataBoundary
        }
        PrivacyV1SourceValidationError::SourceDrift => PrivacyV6ManifestError::SourceDrift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        append_application_upgrade_lineage, ApplicationUpgradeLineageRecord,
        RegisterPrivacyMaterial, V031_TO_V040_MIGRATION_ID,
    };
    use rusqlite::params;

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn initialized_current_v6() -> Connection {
        let mut connection = Connection::open_in_memory().expect("database");
        PrivacyStore::initialize(&connection).expect("privacy schema");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection).expect("binding schema");
        initialize_privacy_v6_application_extensions(&connection)
            .expect("application-owned v6 schema");
        connection
    }

    fn lineage_record() -> ApplicationUpgradeLineageRecord {
        ApplicationUpgradeLineageRecord {
            lineage_id: digest(0xaa),
            migration_id: V031_TO_V040_MIGRATION_ID.to_owned(),
            source_profile_proof_sha256: digest(1),
            source_user_logical_manifest_sha256: digest(2),
            source_privacy_logical_manifest_sha256: digest(3),
            original_rollback_identity_sha256: digest(4),
            target_user_pre_audit_logical_manifest_sha256: digest(5),
            target_user_pre_audit_business_manifest_sha256: digest(6),
            target_privacy_pre_audit_logical_manifest_sha256: digest(7),
            target_privacy_pre_audit_business_manifest_sha256: digest(8),
            previous_receipt_sha256: digest(9),
            result_code: "ok".to_owned(),
            created_at_unix: 1_785_433_600,
        }
    }

    fn lineage_record_with_id(byte: u8) -> ApplicationUpgradeLineageRecord {
        let mut record = lineage_record();
        record.lineage_id = digest(byte);
        record.created_at_unix += i64::from(byte);
        record
    }

    fn insert_lineage_row_raw(
        connection: &Connection,
        record: &ApplicationUpgradeLineageRecord,
    ) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO application_upgrade_lineage(
                lineage_id,migration_id,source_profile_proof_sha256,
                source_user_logical_manifest_sha256,
                source_privacy_logical_manifest_sha256,
                original_rollback_identity_sha256,
                target_user_pre_audit_logical_manifest_sha256,
                target_user_pre_audit_business_manifest_sha256,
                target_privacy_pre_audit_logical_manifest_sha256,
                target_privacy_pre_audit_business_manifest_sha256,
                previous_receipt_sha256,result_code,created_at_unix
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.lineage_id,
                record.migration_id,
                record.source_profile_proof_sha256,
                record.source_user_logical_manifest_sha256,
                record.source_privacy_logical_manifest_sha256,
                record.original_rollback_identity_sha256,
                record.target_user_pre_audit_logical_manifest_sha256,
                record.target_user_pre_audit_business_manifest_sha256,
                record.target_privacy_pre_audit_logical_manifest_sha256,
                record.target_privacy_pre_audit_business_manifest_sha256,
                record.previous_receipt_sha256,
                record.result_code,
                record.created_at_unix,
            ],
        )
    }

    #[test]
    fn lineage_changes_logical_manifest_but_not_business_manifest() {
        let connection = initialized_current_v6();
        let before = compute_privacy_v6_manifests_read_only(&connection).expect("before manifest");
        append_application_upgrade_lineage(&connection, &lineage_record()).expect("append lineage");
        let after = compute_privacy_v6_manifests_read_only(&connection).expect("after manifest");

        assert_ne!(
            before.logical_manifest.sha256,
            after.logical_manifest.sha256
        );
        assert_eq!(
            after.logical_manifest.total_row_count,
            before.logical_manifest.total_row_count + 1
        );
        assert_eq!(before.business_manifest, after.business_manifest);
        let before_lineage = before
            .logical_manifest
            .tables
            .iter()
            .find(|table| table.table_name == "application_upgrade_lineage")
            .expect("lineage logical table");
        let after_lineage = after
            .logical_manifest
            .tables
            .iter()
            .find(|table| table.table_name == "application_upgrade_lineage")
            .expect("lineage logical table after append");
        assert_eq!((before_lineage.row_count, after_lineage.row_count), (0, 1));
        assert!(after
            .business_manifest
            .tables
            .iter()
            .all(|table| table.table_name != "application_upgrade_lineage"
                && table.table_name != "privacy_schema_metadata"));
    }

    #[test]
    fn pre_audit_manifest_excludes_exactly_the_matching_lineage_row() {
        let connection = initialized_current_v6();
        let record = lineage_record();
        let before = compute_privacy_v6_manifests_read_only(&connection).expect("before manifest");
        append_application_upgrade_lineage(&connection, &record).expect("append lineage");

        let current =
            compute_privacy_v6_manifests_read_only(&connection).expect("current manifest");
        let pre_audit =
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, &record.lineage_id)
                .expect("pre-audit manifest");

        assert_eq!(pre_audit.logical_manifest, before.logical_manifest);
        assert_eq!(pre_audit.business_manifest, before.business_manifest);
        assert_eq!(pre_audit.business_manifest, current.business_manifest);
        assert_eq!(
            current.logical_manifest.total_row_count,
            pre_audit.logical_manifest.total_row_count + 1
        );
    }

    #[test]
    fn pre_audit_manifest_retains_every_other_historical_lineage_row() {
        let connection = initialized_current_v6();
        let first = lineage_record_with_id(0xa1);
        let second = lineage_record_with_id(0xa2);
        append_application_upgrade_lineage(&connection, &first).expect("append first lineage");
        let after_first =
            compute_privacy_v6_manifests_read_only(&connection).expect("first-only manifest");
        append_application_upgrade_lineage(&connection, &second).expect("append second lineage");

        let excluding_second =
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, &second.lineage_id)
                .expect("exclude second lineage");
        assert_eq!(
            excluding_second.logical_manifest,
            after_first.logical_manifest
        );
        assert_eq!(
            excluding_second.business_manifest,
            after_first.business_manifest
        );

        let excluding_first =
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, &first.lineage_id)
                .expect("exclude first lineage");
        let retained_lineage = excluding_first
            .logical_manifest
            .tables
            .iter()
            .find(|table| table.table_name == "application_upgrade_lineage")
            .expect("lineage table remains");
        assert_eq!(retained_lineage.row_count, 1);
        assert_ne!(
            excluding_first.logical_manifest,
            after_first.logical_manifest
        );
        assert_eq!(
            excluding_first.business_manifest,
            after_first.business_manifest
        );
    }

    #[test]
    fn pre_audit_manifest_rejects_no_row_wrong_id_and_invalid_id() {
        let connection = initialized_current_v6();
        let missing = digest(0xb1);
        assert_eq!(
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, &missing),
            Err(PrivacyV6ManifestError::DataBoundary)
        );
        assert!(!connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("query-only restored after missing row"));

        let record = lineage_record_with_id(0xb2);
        append_application_upgrade_lineage(&connection, &record).expect("append lineage");
        assert_eq!(
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, &digest(0xb3)),
            Err(PrivacyV6ManifestError::DataBoundary)
        );
        assert_eq!(
            compute_privacy_v6_pre_audit_manifests_read_only(&connection, "not-a-sha256"),
            Err(PrivacyV6ManifestError::DataBoundary)
        );
    }

    #[test]
    fn pre_audit_manifest_cannot_hide_tampered_or_duplicate_matching_rows() {
        let tampered = initialized_current_v6();
        let mut invalid = lineage_record_with_id(0xc1);
        invalid.result_code = "tampered".to_owned();
        tampered
            .pragma_update(None, "ignore_check_constraints", "ON")
            .expect("enable corruption fixture");
        insert_lineage_row_raw(&tampered, &invalid).expect("insert invalid lineage fixture");
        assert_eq!(
            compute_privacy_v6_pre_audit_manifests_read_only(&tampered, &invalid.lineage_id),
            Err(PrivacyV6ManifestError::DataBoundary)
        );

        let duplicate = initialized_current_v6();
        let record = lineage_record_with_id(0xc2);
        append_application_upgrade_lineage(&duplicate, &record).expect("append lineage");
        duplicate
            .execute_batch(
                "DROP INDEX idx_application_upgrade_lineage_id;
                 DROP TRIGGER trg_application_upgrade_lineage_no_replace;",
            )
            .expect("weaken duplicate fixture schema");
        insert_lineage_row_raw(&duplicate, &record).expect("insert duplicate lineage fixture");
        assert_eq!(
            compute_privacy_v6_pre_audit_manifests_read_only(&duplicate, &record.lineage_id),
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        );
    }

    #[test]
    fn ordinary_business_data_changes_every_corresponding_digest() {
        let connection = initialized_current_v6();
        let before = compute_privacy_v6_manifests_read_only(&connection).expect("before manifest");
        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id: "material-current-manifest",
                project_id: None,
                attachment_id: None,
                source_sha256: &digest(10),
                source_name_sha256: &digest(11),
                media_type: "application/pdf",
                page_count: Some(1),
            },
        )
        .expect("insert material");
        let after = compute_privacy_v6_manifests_read_only(&connection).expect("after manifest");

        assert_ne!(
            before.logical_manifest.sha256,
            after.logical_manifest.sha256
        );
        assert_ne!(
            before.business_manifest.sha256,
            after.business_manifest.sha256
        );
        assert_ne!(
            before.business_manifest.primary_key_sha256,
            after.business_manifest.primary_key_sha256
        );
        assert_ne!(
            before.business_manifest.row_sha256,
            after.business_manifest.row_sha256
        );
        assert_eq!(
            after.business_manifest.total_row_count,
            before.business_manifest.total_row_count + 1
        );
    }

    #[test]
    fn missing_extra_internal_and_weak_schema_objects_fail_closed() {
        let missing = Connection::open_in_memory().expect("missing binding database");
        PrivacyStore::initialize(&missing).expect("base privacy schema");
        assert_eq!(
            compute_privacy_v6_manifests_read_only(&missing),
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        );

        let extra = initialized_current_v6();
        extra
            .execute_batch("CREATE TABLE unexpected_private_rows(id TEXT PRIMARY KEY);")
            .expect("extra table");
        assert_eq!(
            compute_privacy_v6_manifests_read_only(&extra),
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        );

        let internal = initialized_current_v6();
        internal
            .execute_batch("ANALYZE;")
            .expect("sqlite stat object");
        assert_eq!(
            compute_privacy_v6_manifests_read_only(&internal),
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        );

        let weak = initialized_current_v6();
        weak.execute_batch(
            "DROP TRIGGER trg_project_privacy_case_binding_no_update;
             CREATE TRIGGER trg_project_privacy_case_binding_no_update
             BEFORE UPDATE ON project_privacy_case_bindings
             WHEN 0 BEGIN SELECT 1; END;",
        )
        .expect("weak trigger");
        assert_eq!(
            compute_privacy_v6_manifests_read_only(&weak),
            Err(PrivacyV6ManifestError::UnsupportedSchema)
        );
    }

    #[test]
    fn read_only_snapshot_restores_query_only_and_rejects_foreign_key_damage() {
        let connection = initialized_current_v6();
        assert!(!connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("initial query-only"));
        let proof = compute_privacy_v6_manifests_read_only(&connection).expect("manifest");
        assert_eq!(proof.logical_manifest.tables.len(), 29);
        assert_eq!(proof.business_manifest.tables.len(), 27);
        assert!(!connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .expect("restored query-only"));

        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("disable foreign keys for corruption fixture");
        connection
            .execute(
                "INSERT INTO privacy_cleanup_candidates(
                    cleanup_id,target_kind,target_id,expected_sha256,state
                 ) VALUES('missing-cleanup','mapping','missing-mapping',?1,'pending')",
                [digest(12)],
            )
            .expect("insert orphan");
        assert_eq!(
            compute_privacy_v6_manifests_read_only(&connection),
            Err(PrivacyV6ManifestError::ForeignKeyViolation)
        );
    }

    #[cfg(windows)]
    #[test]
    fn exact_v1_upgrade_finishes_at_the_same_canonical_v6_manifest_schema() {
        let mut connection = Connection::open_in_memory().expect("v1 database");
        connection
            .execute_batch(crate::migration_source::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .expect("exact v1 schema");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value)
                 VALUES('schema_version','1')",
                [],
            )
            .expect("v1 schema marker");
        PrivacyStore::upgrade_schema_after_backup(&connection).expect("v1 to v5");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection).expect("binding schema");
        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .expect("v5 to v6");
        let proof = compute_privacy_v6_manifests_read_only(&connection)
            .expect("migrated exact current manifest");
        assert_eq!(proof.logical_manifest.tables.len(), 29);
        assert_eq!(proof.business_manifest.tables.len(), 27);
    }
}
