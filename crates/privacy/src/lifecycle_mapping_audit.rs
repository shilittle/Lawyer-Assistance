// Included from lifecycle.rs. Audit rows contain only opaque identifiers, hashes and reason codes.

impl PrivacyLifecycle {
    pub fn verify_mapping_access_audit(
        &self,
        connection: &Connection,
    ) -> Result<u64, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT access_id,mapping_id,redaction_id,purpose_sha256,occurred_at_unix,
                        allowed,reason_code,previous_event_hash,event_hash
                 FROM privacy_mapping_access_audit ORDER BY rowid",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?;
        let mut previous = String::new();
        let mut count = 0_u64;
        for row in rows {
            let row = row.map_err(|_| LifecycleError::Database)?;
            valid_identifier(&row.0).map_err(|_| LifecycleError::CleanupIntegrity)?;
            valid_opaque_id(&row.1, "map_").map_err(|_| LifecycleError::CleanupIntegrity)?;
            valid_identifier(&row.2).map_err(|_| LifecycleError::CleanupIntegrity)?;
            valid_hash(&row.3).map_err(|_| LifecycleError::CleanupIntegrity)?;
            valid_identifier(&row.6).map_err(|_| LifecycleError::CleanupIntegrity)?;
            valid_hash(&row.8).map_err(|_| LifecycleError::CleanupIntegrity)?;
            let occurred_at_unix =
                sql_u64(row.4).map_err(|_| LifecycleError::CleanupIntegrity)?;
            let expected = sha256_hex(
                format!(
                    "mapping-access-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                    row.0, row.1, row.2, row.3, occurred_at_unix, row.5, row.6, row.7
                )
                .as_bytes(),
            );
            if row.7 != previous || row.8 != expected {
                return Err(LifecycleError::CleanupIntegrity);
            }
            previous = row.8;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}
