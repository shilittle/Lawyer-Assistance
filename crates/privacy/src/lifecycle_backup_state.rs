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

    /// Produces one self-contained, deterministic transfer file. Both the database data key and
    /// the companion trust record remain bound to Windows DPAPI CurrentUser; exporting the bundle
    /// does not make it portable to a different OS account and never exposes plaintext SQLite.
    pub fn export_portable_bundle(
        &self,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<Vec<u8>, LifecycleError> {
        let verified = self.verify_detached_backup(backup_id, context)?;
        let envelope_path = self.backup_path(backup_id)?;
        let state_path = self.backup_state_path(backup_id)?;
        let envelope = read_safe_file(&envelope_path, MAX_BACKUP_ENVELOPE_BYTES)?;
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
        if bytes.is_empty() || bytes.len() > MAX_PORTABLE_BACKUP_BYTES {
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
        let envelope = BASE64_STANDARD
            .decode(bundle.envelope_base64.as_bytes())
            .map_err(|_| LifecycleError::BackupInvalid)?;
        let protected_state = BASE64_STANDARD
            .decode(bundle.protected_state_base64.as_bytes())
            .map_err(|_| LifecycleError::BackupInvalid)?;
        if envelope.is_empty()
            || envelope.len() > MAX_BACKUP_ENVELOPE_BYTES
            || protected_state.is_empty()
            || protected_state.len() > MAX_PROTECTED_BACKUP_STATE_BYTES
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

        let envelope_path = self.backup_path(&bundle.backup_id)?;
        let state_path = self.backup_state_path(&bundle.backup_id)?;
        write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &envelope_path,
            &envelope,
            &bundle.backup_id,
        )?;
        if let Err(error) = write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &state_path,
            &protected_state,
            &bundle.backup_id,
        ) {
            let _ = fs::remove_file(&envelope_path);
            return Err(error);
        }
        match self.verify_detached_backup(&bundle.backup_id, context) {
            Ok(verified) => Ok(verified),
            Err(error) => {
                let _ = fs::remove_file(envelope_path);
                let _ = fs::remove_file(state_path);
                Err(error)
            }
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

    fn load_backup_state(
        &self,
        backup_id: &str,
    ) -> Result<ProtectedBackupStateV1, LifecycleError> {
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
