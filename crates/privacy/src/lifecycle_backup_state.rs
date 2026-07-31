#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProtectedBackupStateV1 {
    schema_version: String,
    backup_id: String,
    workspace_instance_id: WorkspaceInstanceId,
    envelope_sha256: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    key_epoch: u64,
    state: String,
    revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableBackupBundleV1 {
    schema_version: String,
    backup_id: String,
    envelope_sha256: String,
    protected_state_sha256: String,
    envelope_base64: String,
    protected_state_base64: String,
}

struct DecodedPortableBackupBundleV1 {
    backup_id: String,
    envelope: Vec<u8>,
    protected_state: Vec<u8>,
}

const PROTECTED_BACKUP_STATE_VERSION: &str = "protected-backup-state-v1";
const MAX_PROTECTED_BACKUP_STATE_BYTES: usize = 64 * 1024;

impl ProtectedBackupStateV1 {
    fn validate(&self) -> Result<(), LifecycleError> {
        valid_opaque_id(&self.backup_id, "bkp_")?;
        valid_hash(&self.envelope_sha256)?;
        if self.schema_version != PROTECTED_BACKUP_STATE_VERSION
            || self.created_at_unix == 0
            || self.created_at_unix >= self.expires_at_unix
            || self.key_epoch == 0
            || !matches!(self.state.as_str(), "active" | "revoked")
            || (self.state == "active" && self.revoked_at_unix.is_some())
            || (self.state == "revoked" && self.revoked_at_unix.is_none())
        {
            return Err(LifecycleError::BackupInvalid);
        }
        Ok(())
    }

    fn registry_tuple(&self) -> Result<(String, i64, i64, i64, String), LifecycleError> {
        Ok((
            self.envelope_sha256.clone(),
            sql_i64(self.created_at_unix)?,
            sql_i64(self.expires_at_unix)?,
            sql_i64(self.key_epoch)?,
            self.state.clone(),
        ))
    }
}

fn decode_portable_bundle(
    bundle_bytes: &[u8],
    context: &BackupVerificationContextV1<'_>,
) -> Result<DecodedPortableBackupBundleV1, LifecycleError> {
    if bundle_bytes.is_empty() || bundle_bytes.len() > MAX_PORTABLE_BACKUP_BYTES {
        return Err(LifecycleError::BackupInvalid);
    }
    let bundle: PortableBackupBundleV1 =
        strict_json_v1_from_slice(bundle_bytes).map_err(|_| LifecycleError::BackupInvalid)?;
    valid_opaque_id(&bundle.backup_id, "bkp_")?;
    valid_hash(&bundle.envelope_sha256)?;
    valid_hash(&bundle.protected_state_sha256)?;
    if bundle.schema_version != PORTABLE_BACKUP_SCHEMA_VERSION {
        return Err(LifecycleError::BackupInvalid);
    }
    let envelope = decode_bounded_base64(&bundle.envelope_base64, MAX_BACKUP_ENVELOPE_BYTES)?;
    let protected_state = decode_bounded_base64(
        &bundle.protected_state_base64,
        MAX_PROTECTED_BACKUP_STATE_BYTES,
    )?;
    let envelope_metadata: BackupEnvelopeV1 =
        strict_json_v1_from_slice(&envelope).map_err(|_| LifecycleError::BackupInvalid)?;
    if let (Some(maximum_envelope_bytes), Some(maximum_portable_bytes)) = (
        max_backup_envelope_bytes_for_schema(envelope_metadata.privacy_store_schema_version),
        max_portable_backup_bytes_for_schema(envelope_metadata.privacy_store_schema_version),
    ) {
        if envelope.len() > maximum_envelope_bytes || bundle_bytes.len() > maximum_portable_bytes {
            return Err(LifecycleError::BackupInvalid);
        }
    }
    if envelope.is_empty()
        || protected_state.is_empty()
        || sha256_hex(&envelope) != bundle.envelope_sha256
        || sha256_hex(&protected_state) != bundle.protected_state_sha256
    {
        return Err(LifecycleError::BackupTampered);
    }

    let plaintext = ZeroizingBytes::new(
        unprotect_local(&protected_state).map_err(|_| LifecycleError::ProtectedBlob)?,
    );
    let state: ProtectedBackupStateV1 =
        strict_json_v1_from_slice(&plaintext).map_err(|_| LifecycleError::BackupInvalid)?;
    state.validate()?;
    if state.backup_id != bundle.backup_id
        || state.workspace_instance_id != *context.expected_workspace_instance_id
        || state.key_epoch != context.expected_key_epoch
        || state.envelope_sha256 != bundle.envelope_sha256
        || state.state != "active"
        || state.revoked_at_unix.is_some()
        || context.now_unix < state.created_at_unix
        || context.now_unix >= state.expires_at_unix
    {
        return Err(LifecycleError::EnvironmentMismatch);
    }
    drop(plaintext);

    Ok(DecodedPortableBackupBundleV1 {
        backup_id: bundle.backup_id,
        envelope,
        protected_state,
    })
}

fn controlled_path_is_present(path: &Path) -> Result<bool, LifecycleError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LifecycleError::Io),
    }
}

impl EncryptedPrivacyBackupStore {
    /// Verifies a backup without requiring the source privacy database. Trust and revocation state
    /// come from a separately DPAPI-protected companion record in the fixed backup root.
    pub fn verify_detached_backup(
        &self,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let state = self.load_backup_state(backup_id)?;
        let registry = detached_registry_connection(&state)?;
        self.verify_backup(&registry, backup_id, context)
    }

    /// Detached verification for a fixed pre-migration rollback backup.
    ///
    /// This remains separate from normal detached verification so a current binary never treats a
    /// legacy snapshot as a current-schema backup by fallback.
    pub fn verify_detached_pre_migration_backup(
        &self,
        backup_id: &str,
        context: &PreMigrationBackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let state = self.load_backup_state(backup_id)?;
        let registry = detached_registry_connection(&state)?;
        self.verify_pre_migration_backup(&registry, backup_id, context)
    }

    /// Restores only after detached state, DPAPI key unwrap, AEAD authentication, SQLite
    /// integrity/foreign-key checks, schema version, workspace binding, and key epoch all pass.
    pub fn restore_detached_into_empty_database(
        &self,
        destination: &mut Connection,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let state = self.load_backup_state(backup_id)?;
        let registry = detached_registry_connection(&state)?;
        self.restore_into_empty_database(&registry, destination, backup_id, context)
    }

    /// Restores the Privacy component of a coordinated pre-migration application backup.
    ///
    /// This API is intentionally not used by standalone Privacy restore. It accepts only the
    /// current schema or an exact authenticated v1-v5 schema and restores the snapshot unchanged,
    /// leaving any legacy-to-current upgrade to the post-backup startup gate.
    pub fn restore_detached_for_coordinated_pre_migration_restore(
        &self,
        destination: &mut Connection,
        backup_id: &str,
        expected_privacy_store_schema_version: i64,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let state = self.load_backup_state(backup_id)?;
        let registry = detached_registry_connection(&state)?;
        match expected_privacy_store_schema_version {
            PRIVACY_STORE_SCHEMA_VERSION => {
                self.restore_into_empty_database(&registry, destination, backup_id, context)
            }
            MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
                ..=MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION => self
                .restore_pre_migration_into_empty_database(
                    &registry,
                    destination,
                    backup_id,
                    &PreMigrationBackupVerificationContextV1 {
                        expected_workspace_instance_id: context.expected_workspace_instance_id,
                        expected_key_epoch: context.expected_key_epoch,
                        expected_privacy_store_schema_version,
                        now_unix: context.now_unix,
                    },
                ),
            _ => Err(LifecycleError::UnsupportedSchema),
        }
    }

    /// Produces one self-contained, deterministic transfer file. Both the database data key and
    /// the companion trust record remain bound to Windows DPAPI CurrentUser; exporting the bundle
    /// does not make it portable to a different OS account and never exposes plaintext SQLite.
    pub fn export_portable_bundle(
        &self,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<Vec<u8>, LifecycleError> {
        let verified = self.verify_detached_backup(backup_id, context)?;
        self.export_portable_bundle_from_verified(backup_id, verified)
    }

    /// Produces the portable inner bundle used by the coordinated five-component migration
    /// backup. The exact expected v1-v5 schema is re-verified before any bytes are returned.
    pub fn export_pre_migration_portable_bundle(
        &self,
        backup_id: &str,
        context: &PreMigrationBackupVerificationContextV1<'_>,
    ) -> Result<Vec<u8>, LifecycleError> {
        let verified = self.verify_detached_pre_migration_backup(backup_id, context)?;
        self.export_portable_bundle_from_verified(backup_id, verified)
    }

    fn export_portable_bundle_from_verified(
        &self,
        backup_id: &str,
        verified: VerifiedBackupV1,
    ) -> Result<Vec<u8>, LifecycleError> {
        let envelope_path = self.backup_path(backup_id)?;
        let state_path = self.backup_state_path(backup_id)?;
        let maximum_envelope_bytes =
            max_backup_envelope_bytes_for_schema(verified.privacy_store_schema_version)
                .ok_or(LifecycleError::BackupInvalid)?;
        let maximum_portable_bytes =
            max_portable_backup_bytes_for_schema(verified.privacy_store_schema_version)
                .ok_or(LifecycleError::BackupInvalid)?;
        let envelope = read_safe_file(&envelope_path, maximum_envelope_bytes)?;
        let protected_state = read_safe_file(&state_path, MAX_PROTECTED_BACKUP_STATE_BYTES)?;
        if sha256_hex(&envelope) != verified.envelope_sha256 {
            return Err(LifecycleError::BackupTampered);
        }
        let bundle = PortableBackupBundleV1 {
            schema_version: PORTABLE_BACKUP_SCHEMA_VERSION.to_owned(),
            backup_id: backup_id.to_owned(),
            envelope_sha256: verified.envelope_sha256,
            protected_state_sha256: sha256_hex(&protected_state),
            envelope_base64: BASE64_STANDARD.encode(envelope),
            protected_state_base64: BASE64_STANDARD.encode(protected_state),
        };
        let bytes = canonical_json_v1(&bundle).map_err(|_| LifecycleError::BackupInvalid)?;
        if bytes.is_empty() || bytes.len() > maximum_portable_bytes {
            return Err(LifecycleError::BackupInvalid);
        }
        Ok(bytes)
    }

    /// Imports a transfer file into the fixed backup root and immediately re-verifies DPAPI,
    /// AEAD, hash, schema, workspace, key epoch, expiry and revocation. Existing backup IDs are
    /// never overwritten. Any partial install or failed verification is removed before return.
    pub fn import_portable_bundle(
        &self,
        bundle_bytes: &[u8],
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let decoded = decode_portable_bundle(bundle_bytes, context)?;
        let envelope_path = self.backup_path(&decoded.backup_id)?;
        let state_path = self.backup_state_path(&decoded.backup_id)?;
        write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &envelope_path,
            &decoded.envelope,
            &decoded.backup_id,
        )?;
        if let Err(error) = write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &state_path,
            &decoded.protected_state,
            &decoded.backup_id,
        ) {
            let _ = fs::remove_file(&envelope_path);
            return Err(error);
        }
        match self.verify_detached_backup(&decoded.backup_id, context) {
            Ok(verified) => Ok(verified),
            Err(error) => {
                let _ = fs::remove_file(envelope_path);
                let _ = fs::remove_file(state_path);
                Err(error)
            }
        }
    }

    /// Imports the Privacy component of a coordinated five-component migration rollback.
    ///
    /// Unlike normal portable import, this narrow path may authenticate an exact v1-v5 snapshot.
    /// It also accepts the current schema so the V3 application restore coordinator has one
    /// deterministic path. Future schemas are rejected, and existing IDs are accepted only when
    /// both encrypted files are byte-for-byte identical. Standalone Privacy restore must continue
    /// to call `import_portable_bundle`, which remains current-schema-only.
    pub fn import_portable_bundle_for_coordinated_pre_migration_restore(
        &self,
        bundle_bytes: &[u8],
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let decoded = decode_portable_bundle(bundle_bytes, context)?;
        let envelope: BackupEnvelopeV1 = strict_json_v1_from_slice(&decoded.envelope)
            .map_err(|_| LifecycleError::BackupInvalid)?;
        let schema_version = envelope.privacy_store_schema_version;
        if !matches!(
            schema_version,
            MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
                ..=MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
        ) && schema_version != PRIVACY_STORE_SCHEMA_VERSION
        {
            return Err(LifecycleError::UnsupportedSchema);
        }

        let envelope_path = self.backup_path(&decoded.backup_id)?;
        let state_path = self.backup_state_path(&decoded.backup_id)?;
        let envelope_present = controlled_path_is_present(&envelope_path)?;
        let state_present = controlled_path_is_present(&state_path)?;
        let installed_new = match (envelope_present, state_present) {
            (false, false) => {
                write_atomic_new_file(
                    self.root.canonical_root(),
                    &self.root,
                    &envelope_path,
                    &decoded.envelope,
                    &decoded.backup_id,
                )?;
                if let Err(error) = write_atomic_new_file(
                    self.root.canonical_root(),
                    &self.root,
                    &state_path,
                    &decoded.protected_state,
                    &decoded.backup_id,
                ) {
                    let _ = fs::remove_file(&envelope_path);
                    return Err(error);
                }
                true
            }
            (true, true)
                if read_safe_file(&envelope_path, MAX_BACKUP_ENVELOPE_BYTES)?
                    == decoded.envelope
                    && read_safe_file(&state_path, MAX_PROTECTED_BACKUP_STATE_BYTES)?
                        == decoded.protected_state =>
            {
                false
            }
            _ => return Err(LifecycleError::Conflict),
        };

        let verification = self.verify_detached_for_coordinated_pre_migration_restore(
            &decoded.backup_id,
            schema_version,
            context,
        );
        match verification {
            Ok(verified) => Ok(verified),
            Err(error) => {
                if installed_new {
                    let _ = fs::remove_file(envelope_path);
                    let _ = fs::remove_file(state_path);
                }
                Err(error)
            }
        }
    }

    fn verify_detached_for_coordinated_pre_migration_restore(
        &self,
        backup_id: &str,
        expected_privacy_store_schema_version: i64,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        match expected_privacy_store_schema_version {
            PRIVACY_STORE_SCHEMA_VERSION => self.verify_detached_backup(backup_id, context),
            MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
                ..=MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION => self
                .verify_detached_pre_migration_backup(
                    backup_id,
                    &PreMigrationBackupVerificationContextV1 {
                        expected_workspace_instance_id: context.expected_workspace_instance_id,
                        expected_key_epoch: context.expected_key_epoch,
                        expected_privacy_store_schema_version,
                        now_unix: context.now_unix,
                    },
                ),
            _ => Err(LifecycleError::UnsupportedSchema),
        }
    }

    fn backup_state_path(&self, backup_id: &str) -> Result<PathBuf, LifecycleError> {
        valid_opaque_id(backup_id, "bkp_")?;
        Ok(self
            .root
            .canonical_root()
            .join("backups")
            .join(format!("{backup_id}.state.dpapi")))
    }

    fn write_initial_backup_state(
        &self,
        verified: &VerifiedBackupV1,
    ) -> Result<(), LifecycleError> {
        let state = ProtectedBackupStateV1 {
            schema_version: PROTECTED_BACKUP_STATE_VERSION.to_owned(),
            backup_id: verified.backup_id.clone(),
            workspace_instance_id: verified.workspace_instance_id.clone(),
            envelope_sha256: verified.envelope_sha256.clone(),
            created_at_unix: verified.created_at_unix,
            expires_at_unix: verified.expires_at_unix,
            key_epoch: verified.key_epoch,
            state: "active".to_owned(),
            revoked_at_unix: None,
        };
        self.write_new_backup_state(&state)
    }

    fn write_new_backup_state(&self, state: &ProtectedBackupStateV1) -> Result<(), LifecycleError> {
        state.validate()?;
        let plaintext = ZeroizingBytes::new(
            canonical_json_v1(state).map_err(|_| LifecycleError::BackupInvalid)?,
        );
        let protected = protect_local(&plaintext).map_err(|_| LifecycleError::ProtectedBlob)?;
        if protected.len() > MAX_PROTECTED_BACKUP_STATE_BYTES {
            return Err(LifecycleError::BackupInvalid);
        }
        let path = self.backup_state_path(&state.backup_id)?;
        write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &path,
            &protected,
            &state.backup_id,
        )
    }

    fn revoke_backup_state(
        &self,
        backup_id: &str,
        revoked_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        let mut state = self.load_backup_state(backup_id)?;
        if revoked_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        match state.state.as_str() {
            "active" => {}
            // The companion state is intentionally updated before SQLite. A retry after a
            // crash between those writes must be able to finish the registry transition.
            "revoked" => return Ok(()),
            _ => return Err(LifecycleError::Conflict),
        }
        state.state = "revoked".to_owned();
        state.revoked_at_unix = Some(revoked_at_unix);
        state.validate()?;
        let plaintext = ZeroizingBytes::new(
            canonical_json_v1(&state).map_err(|_| LifecycleError::BackupInvalid)?,
        );
        let protected = protect_local(&plaintext).map_err(|_| LifecycleError::ProtectedBlob)?;
        let destination = self.backup_state_path(backup_id)?;
        let temporary = self.temporary_path(backup_id, "state.tmp")?;
        write_new_safe_file(&temporary, &protected)?;
        if let Err(error) = replace_file_atomically(&temporary, &destination) {
            let _ = remove_safe_temporary(&temporary, self.root.canonical_root());
            return Err(error);
        }
        validate_open_file_identity(&destination)
    }

    fn load_backup_state(&self, backup_id: &str) -> Result<ProtectedBackupStateV1, LifecycleError> {
        let path = self.backup_state_path(backup_id)?;
        let protected = read_safe_file(&path, MAX_PROTECTED_BACKUP_STATE_BYTES)?;
        let plaintext = ZeroizingBytes::new(
            unprotect_local(&protected).map_err(|_| LifecycleError::ProtectedBlob)?,
        );
        let state: ProtectedBackupStateV1 =
            strict_json_v1_from_slice(&plaintext).map_err(|_| LifecycleError::BackupInvalid)?;
        state.validate()?;
        if state.backup_id != backup_id {
            return Err(LifecycleError::BackupInvalid);
        }
        Ok(state)
    }
}

fn detached_registry_connection(
    state: &ProtectedBackupStateV1,
) -> Result<Connection, LifecycleError> {
    let connection = Connection::open_in_memory().map_err(|_| LifecycleError::Database)?;
    initialize_lifecycle_schema(&connection).map_err(map_store_error)?;
    connection
        .execute(
            "INSERT INTO privacy_lifecycle_meta(
               singleton,schema_version,workspace_instance_id,active_mapping_key_version,
               key_epoch,created_at_unix
             ) VALUES(1,?1,?2,1,?3,?4)",
            params![
                PRIVACY_LIFECYCLE_SCHEMA_VERSION,
                state.workspace_instance_id.as_str(),
                sql_i64(state.key_epoch)?,
                sql_i64(state.created_at_unix)?
            ],
        )
        .map_err(|_| LifecycleError::Database)?;
    let registry = state.registry_tuple()?;
    connection
        .execute(
            "INSERT INTO privacy_backup_registry(
               backup_id,envelope_sha256,created_at_unix,expires_at_unix,key_epoch,state,
               revoked_at_unix
             ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                state.backup_id,
                registry.0,
                registry.1,
                registry.2,
                registry.3,
                registry.4,
                state.revoked_at_unix.map(sql_i64).transpose()?
            ],
        )
        .map_err(|_| LifecycleError::Database)?;
    Ok(connection)
}

#[cfg(windows)]
fn replace_file_atomically(source: &Path, destination: &Path) -> Result<(), LifecycleError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    validate_open_file_identity(source)?;
    validate_open_file_identity(destination)?;
    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(LifecycleError::Io)
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file_atomically(_source: &Path, _destination: &Path) -> Result<(), LifecycleError> {
    Err(LifecycleError::PlatformUnavailable)
}
