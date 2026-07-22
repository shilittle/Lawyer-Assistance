// Included from lifecycle.rs. Approved Provider/workflow results never store plaintext content.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveApprovedOutputV1<'a> {
    pub output_id: &'a str,
    pub redaction_id: &'a str,
    pub approval_generation_id: &'a str,
    pub receipt_id: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub purpose: &'a str,
    pub approved_payload_sha256: &'a str,
    pub content: &'a [u8],
    pub expected_content_sha256: &'a str,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LoadedApprovedOutputV1 {
    pub output_id: String,
    pub redaction_id: String,
    pub approval_generation_id: String,
    pub receipt_id: String,
    pub approved_payload_sha256: String,
    pub content_sha256: String,
    pub content: Vec<u8>,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

impl fmt::Debug for LoadedApprovedOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedApprovedOutputV1")
            .field("output_id", &self.output_id)
            .field("redaction_id", &self.redaction_id)
            .field("approval_generation_id", &self.approval_generation_id)
            .field("receipt_id", &self.receipt_id)
            .field("approved_payload_sha256", &self.approved_payload_sha256)
            .field("content_sha256", &self.content_sha256)
            .field("content", &format_args!("[PROTECTED {} BYTES]", self.content.len()))
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl Drop for LoadedApprovedOutputV1 {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.content);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedOutputAccessContextV1<'a> {
    pub redaction_id: &'a str,
    pub approval_generation_id: &'a str,
    pub receipt_id: &'a str,
    pub provider: &'a str,
    pub model: &'a str,
    pub purpose: &'a str,
    pub approved_payload_sha256: &'a str,
    pub now_unix: u64,
    pub approved_output_access_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedOutputSummaryV1 {
    pub output_id: String,
    pub redaction_id: String,
    pub approval_generation_id: String,
    pub receipt_id: String,
    pub provider_sha256: String,
    pub model_sha256: String,
    pub purpose_sha256: String,
    pub approved_payload_sha256: String,
    pub content_sha256: String,
    pub content_bytes: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

impl PrivacyLifecycle {
    pub fn save_approved_output(
        &self,
        connection: &Connection,
        input: &SaveApprovedOutputV1<'_>,
    ) -> Result<ApprovedOutputSummaryV1, LifecycleError> {
        valid_opaque_id(input.output_id, "out_")?;
        valid_identifier(input.redaction_id)?;
        valid_identifier(input.approval_generation_id)?;
        valid_identifier(input.receipt_id)?;
        valid_private_string(input.provider, 512)?;
        valid_private_string(input.model, 512)?;
        valid_private_string(input.purpose, 512)?;
        valid_hash(input.approved_payload_sha256)?;
        valid_hash(input.expected_content_sha256)?;
        if input.approval_generation_id != input.receipt_id
            || input.content.is_empty()
            || input.content.len() > crate::MAX_PROTECTED_PLAINTEXT_BYTES
            || input.created_at_unix == 0
            || input.expires_at_unix <= input.created_at_unix
            || input.expires_at_unix - input.created_at_unix > MAX_RETENTION_SECONDS
            || sha256_hex(input.content) != input.expected_content_sha256
        {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        type ReceiptBinding = (String, Option<i64>, i64, i64, String, String, String, String);
        let receipt: ReceiptBinding = connection
            .query_row(
                "SELECT redaction_id,revoked_at_unix,issued_at_unix,expires_at_unix,
                        destination_kind,destination_identifier_sha256,purpose,payload_sha256
                 FROM privacy_receipts WHERE receipt_id=?1",
                [input.receipt_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .ok_or(LifecycleError::MappingNotAvailable)?;
        let issued_at_unix = sql_u64(receipt.2)?;
        let receipt_expires_at_unix = sql_u64(receipt.3)?;
        let expected_provider_sha256 = sha256_hex(input.provider.as_bytes());
        if receipt.0 != input.redaction_id
            || receipt.1.is_some()
            || input.created_at_unix < issued_at_unix
            || input.created_at_unix >= receipt_expires_at_unix
            || input.expires_at_unix > receipt_expires_at_unix
        {
            return Err(LifecycleError::MappingRevoked);
        }
        if !matches!(
            receipt.4.as_str(),
            "external_provider" | "verified_local_provider"
        ) || receipt.5 != expected_provider_sha256
            || receipt.6 != input.purpose
            || receipt.7 != input.approved_payload_sha256
        {
            return Err(LifecycleError::MappingAccessDenied);
        }
        let protected_content =
            protect_local(input.content).map_err(|_| LifecycleError::ProtectedBlob)?;
        let summary = ApprovedOutputSummaryV1 {
            output_id: input.output_id.to_owned(),
            redaction_id: input.redaction_id.to_owned(),
            approval_generation_id: input.approval_generation_id.to_owned(),
            receipt_id: input.receipt_id.to_owned(),
            provider_sha256: expected_provider_sha256,
            model_sha256: sha256_hex(input.model.as_bytes()),
            purpose_sha256: sha256_hex(input.purpose.as_bytes()),
            approved_payload_sha256: input.approved_payload_sha256.to_owned(),
            content_sha256: input.expected_content_sha256.to_owned(),
            content_bytes: u64::try_from(input.content.len())
                .map_err(|_| LifecycleError::InvalidInput)?,
            created_at_unix: input.created_at_unix,
            expires_at_unix: input.expires_at_unix,
            revoked: false,
        };
        connection
            .execute(
                "INSERT INTO privacy_approved_outputs(
                   output_id,redaction_id,approval_generation_id,receipt_id,
                   provider_sha256,model_sha256,purpose_sha256,approved_payload_sha256,
                   content_sha256,content_bytes,protected_content,protection_scheme,
                   created_at_unix,expires_at_unix
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    input.output_id,
                    input.redaction_id,
                    input.approval_generation_id,
                    input.receipt_id,
                    summary.provider_sha256,
                    summary.model_sha256,
                    summary.purpose_sha256,
                    summary.approved_payload_sha256,
                    summary.content_sha256,
                    sql_i64(summary.content_bytes)?,
                    protected_content,
                    crate::LOCAL_PROTECTION_SCHEME,
                    sql_i64(input.created_at_unix)?,
                    sql_i64(input.expires_at_unix)?
                ],
            )
            .map_err(|_| LifecycleError::Conflict)?;
        Ok(summary)
    }

    pub fn load_approved_output(
        &self,
        connection: &Connection,
        output_id: &str,
        context: &ApprovedOutputAccessContextV1<'_>,
    ) -> Result<LoadedApprovedOutputV1, LifecycleError> {
        valid_opaque_id(output_id, "out_")?;
        valid_identifier(context.redaction_id)?;
        valid_identifier(context.approval_generation_id)?;
        valid_identifier(context.receipt_id)?;
        valid_private_string(context.provider, 512)?;
        valid_private_string(context.model, 512)?;
        valid_private_string(context.purpose, 512)?;
        valid_hash(context.approved_payload_sha256)?;
        if context.approval_generation_id != context.receipt_id || context.now_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        if !context.approved_output_access_authorized {
            return Err(LifecycleError::MappingAccessDenied);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        type Row = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            Vec<u8>,
            i64,
            i64,
            Option<i64>,
        );
        let row: Row = connection
            .query_row(
                "SELECT redaction_id,approval_generation_id,receipt_id,provider_sha256,
                        model_sha256,purpose_sha256,approved_payload_sha256,content_sha256,
                        content_bytes,protected_content,created_at_unix,expires_at_unix,
                        revoked_at_unix
                 FROM privacy_approved_outputs WHERE output_id=?1",
                [output_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .ok_or(LifecycleError::MappingNotAvailable)?;
        if row.12.is_some() {
            return Err(LifecycleError::MappingRevoked);
        }
        let created_at_unix = sql_u64(row.10)?;
        let expires_at_unix = sql_u64(row.11)?;
        if context.now_unix < created_at_unix || context.now_unix >= expires_at_unix {
            return Err(LifecycleError::MappingExpired);
        }
        let provider_sha256 = sha256_hex(context.provider.as_bytes());
        let purpose_sha256 = sha256_hex(context.purpose.as_bytes());
        if row.0 != context.redaction_id
            || row.1 != context.approval_generation_id
            || row.2 != context.receipt_id
            || row.3 != provider_sha256
            || row.4 != sha256_hex(context.model.as_bytes())
            || row.5 != purpose_sha256
            || row.6 != context.approved_payload_sha256
        {
            return Err(LifecycleError::MappingAccessDenied);
        }
        let receipt_valid: bool = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM privacy_receipts
                   WHERE receipt_id=?1 AND redaction_id=?2 AND revoked_at_unix IS NULL
                     AND issued_at_unix<=?3 AND expires_at_unix>?3
                     AND destination_kind IN('external_provider','verified_local_provider')
                     AND destination_identifier_sha256=?4 AND purpose=?5
                     AND payload_sha256=?6
                 )",
                params![
                    context.receipt_id,
                    context.redaction_id,
                    sql_i64(context.now_unix)?,
                    provider_sha256,
                    context.purpose,
                    context.approved_payload_sha256
                ],
                |row| row.get(0),
            )
            .map_err(|_| LifecycleError::Database)?;
        if !receipt_valid {
            return Err(LifecycleError::MappingRevoked);
        }
        let content = unprotect_local(&row.9).map_err(|_| LifecycleError::ProtectedBlob)?;
        if u64::try_from(content.len()).ok() != Some(sql_u64(row.8)?)
            || sha256_hex(&content) != row.7
        {
            return Err(LifecycleError::Crypto);
        }
        Ok(LoadedApprovedOutputV1 {
            output_id: output_id.to_owned(),
            redaction_id: row.0,
            approval_generation_id: row.1,
            receipt_id: row.2,
            approved_payload_sha256: row.6,
            content_sha256: row.7,
            content,
            created_at_unix,
            expires_at_unix,
        })
    }

    pub fn list_approved_outputs(
        &self,
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<Vec<ApprovedOutputSummaryV1>, LifecycleError> {
        valid_identifier(redaction_id)?;
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT output_id,approval_generation_id,receipt_id,provider_sha256,model_sha256,
                        purpose_sha256,approved_payload_sha256,content_sha256,content_bytes,
                        created_at_unix,expires_at_unix,revoked_at_unix
                 FROM privacy_approved_outputs WHERE redaction_id=?1
                 ORDER BY approval_generation_id,output_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([redaction_id], |row| {
                Ok(ApprovedOutputSummaryV1 {
                    output_id: row.get(0)?,
                    redaction_id: redaction_id.to_owned(),
                    approval_generation_id: row.get(1)?,
                    receipt_id: row.get(2)?,
                    provider_sha256: row.get(3)?,
                    model_sha256: row.get(4)?,
                    purpose_sha256: row.get(5)?,
                    approved_payload_sha256: row.get(6)?,
                    content_sha256: row.get(7)?,
                    content_bytes: u64::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
                    created_at_unix: u64::try_from(row.get::<_, i64>(9)?).unwrap_or(0),
                    expires_at_unix: u64::try_from(row.get::<_, i64>(10)?).unwrap_or(0),
                    revoked: row.get::<_, Option<i64>>(11)?.is_some(),
                })
            })
            .map_err(|_| LifecycleError::Database)?;
        let outputs = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?;
        if outputs.iter().any(|output| {
            valid_identifier(&output.approval_generation_id).is_err()
                || output.approval_generation_id != output.receipt_id
                || valid_hash(&output.provider_sha256).is_err()
                || valid_hash(&output.model_sha256).is_err()
                || valid_hash(&output.purpose_sha256).is_err()
                || valid_hash(&output.approved_payload_sha256).is_err()
                || valid_hash(&output.content_sha256).is_err()
                || output.content_bytes == 0
                || output.created_at_unix == 0
                || output.expires_at_unix <= output.created_at_unix
        }) {
            return Err(LifecycleError::Database);
        }
        Ok(outputs)
    }

    pub fn revoke_approved_output(
        &self,
        connection: &Connection,
        output_id: &str,
        revoked_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        valid_opaque_id(output_id, "out_")?;
        if revoked_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let changed = connection
            .execute(
                "UPDATE privacy_approved_outputs SET revoked_at_unix=?2
                 WHERE output_id=?1 AND revoked_at_unix IS NULL",
                params![output_id, sql_i64(revoked_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(LifecycleError::Conflict)
        }
    }
}
