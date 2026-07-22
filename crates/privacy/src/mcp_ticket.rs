//! Persistent, one-time access tickets for the approved-case MCP boundary.
//!
//! The embedding application supplies the HMAC key. There is intentionally no
//! default key, environment fallback, or implicit key generation here.

use crate::{
    sha256_hex,
    vault_crypto::fill_random,
    vault_store::{FixedLocalStorageRoot, VaultStoreError},
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, MaterialId, PublicationId, Sha256Hex,
        WorkProductId, WorkspaceInstanceId,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, Mutex,
    },
};

pub const MCP_ACCESS_TICKET_VERSION: &str = "mcp-access-ticket-v1";
pub const MCP_ACCESS_TICKET_PROFILE: &str = "approved_case_workspace";
pub const MAX_MCP_ACCESS_TICKET_BYTES: usize = 16 * 1024;
pub const MAX_MCP_ACCESS_TICKET_TTL_SECONDS: u64 = 5 * 60;
const SIGNING_ALGORITHM: &str = "hmac-sha256-v1";
const SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/mcp-access-ticket/v1\0";
const DATABASE_FILE: &str = "mcp-access-tickets.sqlite";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTicketError {
    InvalidRoot,
    UnsafeFilesystem,
    InvalidInput,
    InvalidTicket,
    TicketExpired,
    TicketRevoked,
    TicketReplayed,
    BindingMismatch,
    DatabaseFailed,
    PlatformUnavailable,
}

impl McpTicketError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRoot => "mcp_ticket_invalid_root",
            Self::UnsafeFilesystem => "mcp_ticket_unsafe_filesystem",
            Self::InvalidInput => "mcp_ticket_invalid_input",
            Self::InvalidTicket => "mcp_ticket_invalid",
            Self::TicketExpired => "mcp_ticket_expired",
            Self::TicketRevoked => "mcp_ticket_revoked",
            Self::TicketReplayed => "mcp_ticket_replayed",
            Self::BindingMismatch => "mcp_ticket_binding_mismatch",
            Self::DatabaseFailed => "mcp_ticket_database_failed",
            Self::PlatformUnavailable => "mcp_ticket_platform_unavailable",
        }
    }
}

impl fmt::Display for McpTicketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for McpTicketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportBindingV1 {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct McpAccessTargetV1 {
    pub case_id: Option<CaseId>,
    pub material_id: Option<MaterialId>,
    pub publication_id: Option<PublicationId>,
    pub work_product_id: Option<WorkProductId>,
    pub version: Option<u64>,
}

impl McpAccessTargetV1 {
    fn validate(&self) -> Result<(), McpTicketError> {
        if self.version == Some(0)
            || (self.material_id.is_some() && self.case_id.is_none())
            || (self.publication_id.is_some() && self.material_id.is_none())
            || (self.work_product_id.is_some() && self.case_id.is_none())
            || (self.version.is_some() && self.work_product_id.is_none())
        {
            return Err(McpTicketError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct McpAccessTicketClaimsV1 {
    pub schema_version: String,
    pub ticket_id: String,
    pub profile: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub server_instance_id: String,
    pub transport: McpTransportBindingV1,
    pub session_id: String,
    pub tool_name: String,
    pub purpose: String,
    pub canonical_request_sha256: Sha256Hex,
    pub target: McpAccessTargetV1,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
    pub revocation_epoch: u64,
}

impl McpAccessTicketClaimsV1 {
    fn validate(&self) -> Result<(), McpTicketError> {
        if self.schema_version != MCP_ACCESS_TICKET_VERSION
            || self.profile != MCP_ACCESS_TICKET_PROFILE
            || !opaque_hex(&self.ticket_id, "tkt_", 32)
            || !opaque_hex(&self.server_instance_id, "srv_", 32)
            || !safe_binding(&self.session_id, 16, 160)
            || !safe_name(&self.tool_name, 128)
            || !safe_name(&self.purpose, 160)
            || self.issued_at_unix == 0
            || self.issued_at_unix >= self.expires_at_unix
            || self.expires_at_unix.saturating_sub(self.issued_at_unix)
                > MAX_MCP_ACCESS_TICKET_TTL_SECONDS
            || !lower_hex(&self.nonce, 64)
        {
            return Err(McpTicketError::InvalidInput);
        }
        self.target.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedMcpAccessTicketV1 {
    pub claims: McpAccessTicketClaimsV1,
    pub canonical_claims_sha256: Sha256Hex,
    pub signing_algorithm: String,
    pub signing_key_id: String,
    pub signing_key_version: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAccessTicketRequestV1 {
    pub workspace_instance_id: WorkspaceInstanceId,
    pub server_instance_id: String,
    pub transport: McpTransportBindingV1,
    pub session_id: String,
    pub tool_name: String,
    pub purpose: String,
    pub canonical_request_sha256: Sha256Hex,
    pub target: McpAccessTargetV1,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTicketVerificationContextV1 {
    pub workspace_instance_id: WorkspaceInstanceId,
    pub server_instance_id: String,
    pub transport: McpTransportBindingV1,
    pub session_id: String,
    pub tool_name: String,
    pub purpose: String,
    pub canonical_request_sha256: Sha256Hex,
    pub target: McpAccessTargetV1,
    pub now_unix: u64,
}

pub struct McpTicketSigningKey {
    key: [u8; 32],
    key_id: String,
    key_version: u64,
}

impl McpTicketSigningKey {
    pub fn from_bytes(
        key: [u8; 32],
        key_id: impl Into<String>,
        key_version: u64,
    ) -> Result<Self, McpTicketError> {
        let key_id = key_id.into();
        if key_version == 0 || key.iter().all(|byte| *byte == 0) || !safe_binding(&key_id, 8, 128) {
            return Err(McpTicketError::InvalidInput);
        }
        Ok(Self {
            key,
            key_id,
            key_version,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn key_version(&self) -> u64 {
        self.key_version
    }

    fn sign(
        &self,
        claims: McpAccessTicketClaimsV1,
    ) -> Result<SignedMcpAccessTicketV1, McpTicketError> {
        claims.validate()?;
        let canonical = canonical_json_v1(&claims).map_err(|_| McpTicketError::InvalidInput)?;
        Ok(SignedMcpAccessTicketV1 {
            claims,
            canonical_claims_sha256: Sha256Hex::parse(sha256_hex(&canonical))
                .map_err(|_| McpTicketError::InvalidInput)?,
            signing_algorithm: SIGNING_ALGORITHM.to_owned(),
            signing_key_id: self.key_id.clone(),
            signing_key_version: self.key_version,
            signature: hmac_sha256_hex(&self.key, SIGNING_DOMAIN, &canonical),
        })
    }

    fn verify(&self, signed: &SignedMcpAccessTicketV1) -> Result<(), McpTicketError> {
        signed
            .claims
            .validate()
            .map_err(|_| McpTicketError::InvalidTicket)?;
        if signed.signing_algorithm != SIGNING_ALGORITHM
            || signed.signing_key_id != self.key_id
            || signed.signing_key_version != self.key_version
            || !lower_hex(&signed.signature, 64)
        {
            return Err(McpTicketError::InvalidTicket);
        }
        let canonical =
            canonical_json_v1(&signed.claims).map_err(|_| McpTicketError::InvalidTicket)?;
        if signed.canonical_claims_sha256.as_str() != sha256_hex(&canonical) {
            return Err(McpTicketError::InvalidTicket);
        }
        let expected = hmac_sha256_hex(&self.key, SIGNING_DOMAIN, &canonical);
        if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
            return Err(McpTicketError::InvalidTicket);
        }
        Ok(())
    }
}

impl fmt::Debug for McpTicketSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpTicketSigningKey")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for McpTicketSigningKey {
    fn drop(&mut self) {
        zeroize(&mut self.key);
    }
}

struct TicketStoreInner {
    fixed: FixedLocalStorageRoot,
    database: PathBuf,
    signer: McpTicketSigningKey,
    workspace_instance_id: WorkspaceInstanceId,
    server_instance_id: String,
    consume_lock: Mutex<()>,
}

#[derive(Clone)]
pub struct McpAccessTicketStore {
    inner: Arc<TicketStoreInner>,
}

impl fmt::Debug for McpAccessTicketStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAccessTicketStore")
            .field("workspace_instance_id", &self.inner.workspace_instance_id)
            .field("server_instance_id", &self.inner.server_instance_id)
            .field("database", &"[FIXED_LOCAL_STATE]")
            .finish()
    }
}

impl McpAccessTicketStore {
    pub fn initialize(
        root: impl AsRef<Path>,
        signer: McpTicketSigningKey,
        workspace_instance_id: WorkspaceInstanceId,
        server_instance_id: impl Into<String>,
    ) -> Result<Self, McpTicketError> {
        let server_instance_id = server_instance_id.into();
        if !opaque_hex(&server_instance_id, "srv_", 32) {
            return Err(McpTicketError::InvalidInput);
        }
        let fixed = FixedLocalStorageRoot::initialize(root.as_ref()).map_err(map_store_error)?;
        let database = fixed.canonical_root().join(DATABASE_FILE);
        let store = Self {
            inner: Arc::new(TicketStoreInner {
                fixed,
                database,
                signer,
                workspace_instance_id,
                server_instance_id,
                consume_lock: Mutex::new(()),
            }),
        };
        store.initialize_database()?;
        Ok(store)
    }

    pub fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.inner.workspace_instance_id
    }
    pub fn server_instance_id(&self) -> &str {
        &self.inner.server_instance_id
    }

    pub fn current_revocation_epoch(&self) -> Result<u64, McpTicketError> {
        let db = self.open_database()?;
        let value = db
            .query_row(
                "SELECT revocation_epoch FROM mcp_ticket_meta WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        u64::try_from(value).map_err(|_| McpTicketError::DatabaseFailed)
    }

    pub fn issue(&self, request: McpAccessTicketRequestV1) -> Result<String, McpTicketError> {
        if request.workspace_instance_id != self.inner.workspace_instance_id
            || request.server_instance_id != self.inner.server_instance_id
        {
            return Err(McpTicketError::BindingMismatch);
        }
        let claims = McpAccessTicketClaimsV1 {
            schema_version: MCP_ACCESS_TICKET_VERSION.to_owned(),
            ticket_id: random_id("tkt_", 16)?,
            profile: MCP_ACCESS_TICKET_PROFILE.to_owned(),
            workspace_instance_id: request.workspace_instance_id,
            server_instance_id: request.server_instance_id,
            transport: request.transport,
            session_id: request.session_id,
            tool_name: request.tool_name,
            purpose: request.purpose,
            canonical_request_sha256: request.canonical_request_sha256,
            target: request.target,
            issued_at_unix: request.issued_at_unix,
            expires_at_unix: request.expires_at_unix,
            nonce: random_hex(32)?,
            revocation_epoch: self.current_revocation_epoch()?,
        };
        let signed = self.inner.signer.sign(claims)?;
        let canonical = canonical_json_v1(&signed).map_err(|_| McpTicketError::InvalidInput)?;
        let token = format!("tkt_v1.{}", URL_SAFE_NO_PAD.encode(canonical));
        if token.len() > MAX_MCP_ACCESS_TICKET_BYTES {
            return Err(McpTicketError::InvalidInput);
        }
        let db = self.open_database()?;
        db.execute(
            "INSERT INTO mcp_access_tickets(ticket_id,token_sha256,nonce,revocation_epoch,issued_at_unix,expires_at_unix,state)
             VALUES(?1,?2,?3,?4,?5,?6,'issued')",
            params![signed.claims.ticket_id, sha256_hex(token.as_bytes()), signed.claims.nonce,
                sql_i64(signed.claims.revocation_epoch)?, sql_i64(signed.claims.issued_at_unix)?,
                sql_i64(signed.claims.expires_at_unix)?],
        ).map_err(|_| McpTicketError::DatabaseFailed)?;
        Ok(token)
    }

    pub fn consume(
        &self,
        token: &str,
        context: &McpTicketVerificationContextV1,
    ) -> Result<McpAccessTicketClaimsV1, McpTicketError> {
        let _consume_guard = self
            .inner
            .consume_lock
            .lock()
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        if token.is_empty() || token.len() > MAX_MCP_ACCESS_TICKET_BYTES || context.now_unix == 0 {
            return Err(McpTicketError::InvalidTicket);
        }
        let encoded = token
            .strip_prefix("tkt_v1.")
            .ok_or(McpTicketError::InvalidTicket)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| McpTicketError::InvalidTicket)?;
        if bytes.is_empty() || bytes.len() > MAX_MCP_ACCESS_TICKET_BYTES {
            return Err(McpTicketError::InvalidTicket);
        }
        let signed: SignedMcpAccessTicketV1 =
            strict_json_v1_from_slice(&bytes).map_err(|_| McpTicketError::InvalidTicket)?;
        if canonical_json_v1(&signed).map_err(|_| McpTicketError::InvalidTicket)? != bytes {
            return Err(McpTicketError::InvalidTicket);
        }
        self.inner.signer.verify(&signed)?;
        let claims = &signed.claims;
        if context.now_unix < claims.issued_at_unix || context.now_unix >= claims.expires_at_unix {
            return Err(McpTicketError::TicketExpired);
        }
        context.target.validate()?;
        if claims.workspace_instance_id != context.workspace_instance_id
            || claims.server_instance_id != context.server_instance_id
            || claims.transport != context.transport
            || claims.session_id != context.session_id
            || claims.tool_name != context.tool_name
            || claims.purpose != context.purpose
            || claims.canonical_request_sha256 != context.canonical_request_sha256
            || claims.target != context.target
            || claims.workspace_instance_id != self.inner.workspace_instance_id
            || claims.server_instance_id != self.inner.server_instance_id
        {
            return Err(McpTicketError::BindingMismatch);
        }

        let token_sha256 = sha256_hex(token.as_bytes());
        let mut db = self.open_database()?;
        let transaction = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        let epoch = transaction
            .query_row(
                "SELECT revocation_epoch FROM mcp_ticket_meta WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        if u64::try_from(epoch).ok() != Some(claims.revocation_epoch) {
            return Err(McpTicketError::TicketRevoked);
        }
        let row = transaction
            .query_row(
                "SELECT state,token_sha256,nonce,revocation_epoch,issued_at_unix,expires_at_unix
             FROM mcp_access_tickets WHERE ticket_id=?1",
                params![claims.ticket_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| McpTicketError::DatabaseFailed)?
            .ok_or(McpTicketError::InvalidTicket)?;
        if row.0 == "revoked" {
            return Err(McpTicketError::TicketRevoked);
        }
        if row.0 != "issued" {
            return Err(McpTicketError::TicketReplayed);
        }
        if row.1 != token_sha256
            || row.2 != claims.nonce
            || u64::try_from(row.3).ok() != Some(claims.revocation_epoch)
            || u64::try_from(row.4).ok() != Some(claims.issued_at_unix)
            || u64::try_from(row.5).ok() != Some(claims.expires_at_unix)
        {
            return Err(McpTicketError::InvalidTicket);
        }
        let changed = transaction
            .execute(
                "UPDATE mcp_access_tickets SET state='consumed',consumed_at_unix=?2
             WHERE ticket_id=?1 AND state='issued' AND token_sha256=?3",
                params![claims.ticket_id, sql_i64(context.now_unix)?, token_sha256],
            )
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        if changed != 1 {
            return Err(McpTicketError::TicketReplayed);
        }
        transaction
            .commit()
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        Ok(signed.claims)
    }

    pub fn revoke(&self, ticket_id: &str, revoked_at_unix: u64) -> Result<(), McpTicketError> {
        if !opaque_hex(ticket_id, "tkt_", 32) || revoked_at_unix == 0 {
            return Err(McpTicketError::InvalidInput);
        }
        let db = self.open_database()?;
        let changed = db.execute(
            "UPDATE mcp_access_tickets SET state='revoked',revoked_at_unix=?2 WHERE ticket_id=?1 AND state='issued'",
            params![ticket_id, sql_i64(revoked_at_unix)?],
        ).map_err(|_| McpTicketError::DatabaseFailed)?;
        if changed != 1 {
            return Err(McpTicketError::TicketReplayed);
        }
        Ok(())
    }

    pub fn bump_revocation_epoch(&self) -> Result<u64, McpTicketError> {
        let mut db = self.open_database()?;
        let transaction = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        let current = transaction
            .query_row(
                "SELECT revocation_epoch FROM mcp_ticket_meta WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        let next = current
            .checked_add(1)
            .ok_or(McpTicketError::DatabaseFailed)?;
        transaction
            .execute(
                "UPDATE mcp_ticket_meta SET revocation_epoch=?1 WHERE singleton=1",
                params![next],
            )
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        transaction
            .commit()
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        u64::try_from(next).map_err(|_| McpTicketError::DatabaseFailed)
    }

    fn initialize_database(&self) -> Result<(), McpTicketError> {
        let db = self.open_database()?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS mcp_ticket_meta(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
               workspace_instance_id TEXT NOT NULL, server_instance_id TEXT NOT NULL,
               signing_key_id TEXT NOT NULL, signing_key_version INTEGER NOT NULL,
               revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch>=0)) STRICT;
             CREATE TABLE IF NOT EXISTS mcp_access_tickets(
               ticket_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE,
               revocation_epoch INTEGER NOT NULL, issued_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL,
               state TEXT NOT NULL CHECK(state IN('issued','consumed','revoked')),
               consumed_at_unix INTEGER, revoked_at_unix INTEGER) STRICT;",
        ).map_err(|_| McpTicketError::DatabaseFailed)?;
        let existing = db.query_row(
            "SELECT schema_version,workspace_instance_id,server_instance_id,signing_key_id,signing_key_version
             FROM mcp_ticket_meta WHERE singleton=1", [], |row| Ok((row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?)),
        ).optional().map_err(|_| McpTicketError::DatabaseFailed)?;
        if let Some(existing) = existing {
            if existing.0 != 1
                || existing.1 != self.inner.workspace_instance_id.as_str()
                || existing.2 != self.inner.server_instance_id
                || existing.3 != self.inner.signer.key_id()
                || u64::try_from(existing.4).ok() != Some(self.inner.signer.key_version())
            {
                return Err(McpTicketError::BindingMismatch);
            }
        } else {
            db.execute(
                "INSERT INTO mcp_ticket_meta(singleton,schema_version,workspace_instance_id,server_instance_id,
                 signing_key_id,signing_key_version,revocation_epoch) VALUES(1,1,?1,?2,?3,?4,0)",
                params![self.inner.workspace_instance_id.as_str(), self.inner.server_instance_id,
                    self.inner.signer.key_id(), sql_i64(self.inner.signer.key_version())?],
            ).map_err(|_| McpTicketError::DatabaseFailed)?;
        }
        Ok(())
    }

    fn open_database(&self) -> Result<Connection, McpTicketError> {
        if self.inner.database.exists() {
            self.inner
                .fixed
                .validate_existing_file(Path::new(DATABASE_FILE))
                .map_err(map_store_error)?;
        } else {
            self.inner
                .fixed
                .validate_new_path(Path::new(DATABASE_FILE))
                .map_err(map_store_error)?;
        }
        let db =
            Connection::open(&self.inner.database).map_err(|_| McpTicketError::DatabaseFailed)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| McpTicketError::DatabaseFailed)?;
        Ok(db)
    }
}

fn random_id(prefix: &str, bytes: usize) -> Result<String, McpTicketError> {
    Ok(format!("{prefix}{}", random_hex(bytes)?))
}

fn random_hex(count: usize) -> Result<String, McpTicketError> {
    let mut bytes = vec![0_u8; count];
    fill_random(&mut bytes).map_err(|_| McpTicketError::PlatformUnavailable)?;
    let mut output = String::with_capacity(count.saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").map_err(|_| McpTicketError::InvalidInput)?;
    }
    Ok(output)
}

fn sql_i64(value: u64) -> Result<i64, McpTicketError> {
    i64::try_from(value).map_err(|_| McpTicketError::InvalidInput)
}
fn opaque_hex(value: &str, prefix: &str, digits: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|value| lower_hex(value, digits))
}
fn lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn safe_binding(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}
fn safe_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
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
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    let mut output = String::with_capacity(64);
    for byte in outer.finalize() {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    zeroize(&mut normalized);
    zeroize(&mut inner_pad);
    zeroize(&mut outer_pad);
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}
fn zeroize(bytes: &mut [u8]) {
    bytes.fill(0);
    compiler_fence(Ordering::SeqCst);
}
fn map_store_error(error: VaultStoreError) -> McpTicketError {
    match error {
        VaultStoreError::InvalidRoot => McpTicketError::InvalidRoot,
        VaultStoreError::UnsafeFilesystem => McpTicketError::UnsafeFilesystem,
        VaultStoreError::PlatformUnavailable => McpTicketError::PlatformUnavailable,
        _ => McpTicketError::DatabaseFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn workspace_id() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse(format!("ws_{}", "a".repeat(32))).expect("workspace")
    }
    fn ticket_request(now: u64) -> McpAccessTicketRequestV1 {
        McpAccessTicketRequestV1 {
            workspace_instance_id: workspace_id(),
            server_instance_id: format!("srv_{}", "b".repeat(32)),
            transport: McpTransportBindingV1::StreamableHttp,
            session_id: format!("session_{}", "c".repeat(32)),
            tool_name: "case_list".to_owned(),
            purpose: "mcp.case_list.v1".to_owned(),
            canonical_request_sha256: Sha256Hex::parse("d".repeat(64)).expect("hash"),
            target: McpAccessTargetV1::default(),
            issued_at_unix: now,
            expires_at_unix: now + 60,
        }
    }
    fn context(request: &McpAccessTicketRequestV1, now: u64) -> McpTicketVerificationContextV1 {
        McpTicketVerificationContextV1 {
            workspace_instance_id: request.workspace_instance_id.clone(),
            server_instance_id: request.server_instance_id.clone(),
            transport: request.transport,
            session_id: request.session_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: request.purpose.clone(),
            canonical_request_sha256: request.canonical_request_sha256.clone(),
            target: request.target.clone(),
            now_unix: now,
        }
    }
    fn store(root: &Path) -> McpAccessTicketStore {
        McpAccessTicketStore::initialize(
            root,
            McpTicketSigningKey::from_bytes([0x5a; 32], "ticket-key-v1", 1).expect("key"),
            workspace_id(),
            format!("srv_{}", "b".repeat(32)),
        )
        .expect("store")
    }

    #[test]
    fn exact_ticket_is_consumed_once_and_replay_fails_closed() {
        let directory = tempfile::tempdir().expect("root");
        let store = store(directory.path());
        let request = ticket_request(1_000);
        let token = store.issue(request.clone()).expect("issue");
        assert!(store.consume(&token, &context(&request, 1_001)).is_ok());
        assert_eq!(
            store.consume(&token, &context(&request, 1_002)),
            Err(McpTicketError::TicketReplayed)
        );
    }

    #[test]
    fn bindings_expiry_revocation_and_epoch_fail_closed() {
        let directory = tempfile::tempdir().expect("root");
        let store = store(directory.path());
        let request = ticket_request(2_000);
        let token = store.issue(request.clone()).expect("issue");
        let mut wrong = context(&request, 2_001);
        wrong.tool_name = "case_list_work_products".to_owned();
        assert_eq!(
            store.consume(&token, &wrong),
            Err(McpTicketError::BindingMismatch)
        );
        assert_eq!(
            store.consume(&token, &context(&request, 2_061)),
            Err(McpTicketError::TicketExpired)
        );
        let request = ticket_request(3_000);
        let token = store.issue(request.clone()).expect("issue");
        let bytes = URL_SAFE_NO_PAD
            .decode(token.strip_prefix("tkt_v1.").expect("prefix"))
            .expect("decode");
        let signed: SignedMcpAccessTicketV1 = strict_json_v1_from_slice(&bytes).expect("ticket");
        store
            .revoke(&signed.claims.ticket_id, 3_001)
            .expect("revoke");
        assert_eq!(
            store.consume(&token, &context(&request, 3_002)),
            Err(McpTicketError::TicketRevoked)
        );
        let request = ticket_request(4_000);
        let token = store.issue(request.clone()).expect("issue");
        assert_eq!(store.bump_revocation_epoch().expect("bump"), 1);
        assert_eq!(
            store.consume(&token, &context(&request, 4_001)),
            Err(McpTicketError::TicketRevoked)
        );
    }

    #[test]
    fn concurrent_consumers_have_exactly_one_winner() {
        let directory = tempfile::tempdir().expect("root");
        let store = store(directory.path());
        let request = ticket_request(5_000);
        let token = store.issue(request.clone()).expect("issue");
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let store = store.clone();
                let token = token.clone();
                let context = context(&request, 5_001);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.consume(&token, &context)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter(|result| result.is_err())
            .all(|result| matches!(result, Err(McpTicketError::TicketReplayed))));
    }
}
