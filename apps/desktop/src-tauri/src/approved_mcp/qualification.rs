use super::*;
use crate::atomic_file;
use hmac::{Hmac, Mac};
use legal_mcp::approved_backend::{
    ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError,
    ApprovedWorkspaceQualificationProvider, APPROVED_MCP_POLICY_ID, APPROVED_MCP_POLICY_VERSION,
};
use legal_mcp::release_binary::{measure_release_binary, ReleaseBinaryMeasurement};
use privacy::vnext::{canonical_json_v1, strict_json_v1_from_slice, Sha256Hex};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

type HmacSha256 = Hmac<Sha256>;

const EVIDENCE_SCHEMA: &str = "lawyer-assistance-approved-mcp-qualification-v1";
const EVIDENCE_DOMAIN: &[u8] = b"lawyer-assistance\0approved-mcp-qualification-evidence-v1\0";
const EVIDENCE_FILE: &str = "active-evidence-v1.json";
const MIN_QUALIFICATION_TTL_SECONDS: u64 = 60;
const MAX_QUALIFICATION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const BINARY_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_VERSION_OUTPUT_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QualificationEvidenceClaimsV1 {
    schema_version: String,
    evidence_id: String,
    stdio_canary_passed: bool,
    streamable_http_canary_passed: bool,
    app_version: String,
    policy_id: String,
    policy_version: u64,
    mcp_binary_path_identity_sha256: Sha256Hex,
    mcp_binary_file_identity_sha256: Sha256Hex,
    mcp_binary_sha256: Sha256Hex,
    mcp_binary_version: String,
    server_key_id: String,
    server_key_version: u64,
    revocation_epoch: u64,
    revocation_key_id: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedQualificationEvidenceV1 {
    claims: QualificationEvidenceClaimsV1,
    claims_sha256: Sha256Hex,
    mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpectedQualificationBinding {
    pub(super) server_key_id: String,
    pub(super) server_key_version: u64,
    pub(super) revocation_epoch: u64,
    pub(super) revocation_key_id: String,
    pub(super) binary_path: PathBuf,
    pub(super) binary_path_identity_sha256: Sha256Hex,
    pub(super) binary_file_identity_sha256: Sha256Hex,
    pub(super) binary_sha256: Sha256Hex,
    pub(super) binary_version: String,
}

struct LiveQualificationBinding {
    ticket_key: [u8; 32],
    expected: ExpectedQualificationBinding,
}

impl Drop for LiveQualificationBinding {
    fn drop(&mut self) {
        zeroize(&mut self.ticket_key);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovedMcpQualificationStatus {
    pub qualified: bool,
    pub reason_code: String,
    pub evidence_id: Option<String>,
    pub evidence_sha256: Option<String>,
    pub stdio_canary_passed: bool,
    pub streamable_http_canary_passed: bool,
    pub exact_app_policy_binding: bool,
    pub exact_server_key_binding: bool,
    pub mcp_binary_path_identity_sha256: Option<String>,
    pub mcp_binary_file_identity_sha256: Option<String>,
    pub mcp_binary_sha256: Option<String>,
    pub mcp_binary_version: Option<String>,
    pub app_version: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub server_key_id: Option<String>,
    pub server_key_version: u64,
    pub revocation_epoch: Option<u64>,
    pub issued_at_unix: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
}

impl ApprovedMcpQualificationStatus {
    fn unavailable(reason_code: &str) -> Self {
        Self {
            qualified: false,
            reason_code: reason_code.to_owned(),
            evidence_id: None,
            evidence_sha256: None,
            stdio_canary_passed: false,
            streamable_http_canary_passed: false,
            exact_app_policy_binding: false,
            exact_server_key_binding: false,
            mcp_binary_path_identity_sha256: None,
            mcp_binary_file_identity_sha256: None,
            mcp_binary_sha256: None,
            mcp_binary_version: None,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: APPROVED_MCP_POLICY_ID.to_owned(),
            policy_version: APPROVED_MCP_POLICY_VERSION,
            server_key_id: None,
            server_key_version: KEY_VERSION,
            revocation_epoch: None,
            issued_at_unix: None,
            expires_at_unix: None,
            revoked: false,
        }
    }

    fn from_snapshot(snapshot: ApprovedMcpQualificationSnapshotV1, now_unix: u64) -> Self {
        let qualified = snapshot.approved_workspace_qualified_at(now_unix);
        let reason_code = if qualified {
            "QUALIFIED"
        } else if snapshot.revoked {
            "REVOKED_OR_EPOCH_CHANGED"
        } else if !snapshot.exact_app_policy_binding {
            "APP_OR_POLICY_CHANGED"
        } else if !snapshot.exact_server_key_binding {
            "SERVER_KEY_CHANGED"
        } else if !snapshot.stdio_canary_passed || !snapshot.streamable_http_canary_passed {
            "CANARY_INCOMPLETE"
        } else if now_unix >= snapshot.expires_at_unix {
            "EVIDENCE_EXPIRED"
        } else {
            "EVIDENCE_NOT_CURRENT"
        };
        Self {
            qualified,
            reason_code: reason_code.to_owned(),
            evidence_id: Some(snapshot.evidence_id),
            evidence_sha256: Some(snapshot.evidence_sha256.as_str().to_owned()),
            stdio_canary_passed: snapshot.stdio_canary_passed,
            streamable_http_canary_passed: snapshot.streamable_http_canary_passed,
            exact_app_policy_binding: snapshot.exact_app_policy_binding,
            exact_server_key_binding: snapshot.exact_server_key_binding,
            mcp_binary_path_identity_sha256: Some(
                snapshot.mcp_binary_path_identity_sha256.as_str().to_owned(),
            ),
            mcp_binary_file_identity_sha256: Some(
                snapshot.mcp_binary_file_identity_sha256.as_str().to_owned(),
            ),
            mcp_binary_sha256: Some(snapshot.mcp_binary_sha256.as_str().to_owned()),
            mcp_binary_version: Some(snapshot.mcp_binary_version),
            app_version: snapshot.app_version,
            policy_id: snapshot.policy_id,
            policy_version: snapshot.policy_version,
            server_key_id: Some(snapshot.server_key_id),
            server_key_version: snapshot.server_key_version,
            revocation_epoch: Some(snapshot.revocation_epoch),
            issued_at_unix: Some(snapshot.issued_at_unix),
            expires_at_unix: Some(snapshot.expires_at_unix),
            revoked: snapshot.revoked,
        }
    }
}

pub(super) struct DesktopApprovedMcpQualificationProvider {
    root: PathBuf,
    keys: Arc<dyn ApprovedMcpKeyProvider>,
    binary_path: PathBuf,
    io: Mutex<()>,
}

impl fmt::Debug for DesktopApprovedMcpQualificationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopApprovedMcpQualificationProvider")
            .field("root", &"[FIXED_LOCAL_STATE]")
            .finish()
    }
}

impl DesktopApprovedMcpQualificationProvider {
    pub(super) fn new(
        root: PathBuf,
        keys: Arc<dyn ApprovedMcpKeyProvider>,
        binary_path: PathBuf,
    ) -> Self {
        Self {
            root,
            keys,
            binary_path,
            io: Mutex::new(()),
        }
    }

    pub(super) fn begin_run(&self) -> Result<ExpectedQualificationBinding, ApprovedMcpError> {
        let _io = self.io.lock().map_err(|_| qualification_state_error())?;
        let live = self.live_binding()?;
        Ok(live.expected.clone())
    }

    pub(super) fn persist_passed(
        &self,
        expected: &ExpectedQualificationBinding,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        let _io = self.io.lock().map_err(|_| qualification_state_error())?;
        self.persist_locked(expected, issued_at_unix, expires_at_unix, true)?;
        let snapshot = self.load_snapshot_locked(issued_at_unix)?;
        Ok(ApprovedMcpQualificationStatus::from_snapshot(
            snapshot,
            issued_at_unix,
        ))
    }

    pub(super) fn persist_candidate(
        &self,
        expected: &ExpectedQualificationBinding,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedMcpError> {
        let _io = self.io.lock().map_err(|_| qualification_state_error())?;
        self.persist_locked(expected, issued_at_unix, expires_at_unix, false)?;
        let mut snapshot = self.load_snapshot_locked(issued_at_unix)?;
        snapshot.stdio_canary_passed = true;
        snapshot.streamable_http_canary_passed = true;
        Ok(snapshot)
    }

    fn persist_locked(
        &self,
        expected: &ExpectedQualificationBinding,
        issued_at_unix: u64,
        expires_at_unix: u64,
        canaries_passed: bool,
    ) -> Result<(), ApprovedMcpError> {
        let binding = self.live_binding()?;
        if &binding.expected != expected || issued_at_unix == 0 || expires_at_unix <= issued_at_unix
        {
            return Err(qualification_changed_error());
        }
        let claims = QualificationEvidenceClaimsV1 {
            schema_version: EVIDENCE_SCHEMA.to_owned(),
            evidence_id: format!("mcpq_{}", Uuid::new_v4().simple()),
            stdio_canary_passed: canaries_passed,
            streamable_http_canary_passed: canaries_passed,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: APPROVED_MCP_POLICY_ID.to_owned(),
            policy_version: APPROVED_MCP_POLICY_VERSION,
            mcp_binary_path_identity_sha256: expected.binary_path_identity_sha256.clone(),
            mcp_binary_file_identity_sha256: expected.binary_file_identity_sha256.clone(),
            mcp_binary_sha256: expected.binary_sha256.clone(),
            mcp_binary_version: expected.binary_version.clone(),
            server_key_id: expected.server_key_id.clone(),
            server_key_version: expected.server_key_version,
            revocation_epoch: expected.revocation_epoch,
            revocation_key_id: expected.revocation_key_id.clone(),
            issued_at_unix,
            expires_at_unix,
            revoked: false,
        };
        let claims_bytes = canonical_json_v1(&claims).map_err(|_| qualification_state_error())?;
        let claims_sha256 =
            Sha256Hex::parse(sha256_hex(&claims_bytes)).map_err(|_| qualification_state_error())?;
        let mac_hex = sign(&binding.ticket_key, &claims_bytes)?;
        let envelope = SignedQualificationEvidenceV1 {
            claims,
            claims_sha256,
            mac_hex,
        };
        let bytes = canonical_json_v1(&envelope).map_err(|_| qualification_state_error())?;
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(qualification_state_error());
        }
        write_atomic(&self.root, &bytes)?;
        Ok(())
    }

    pub(super) fn status(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        let _io = self.io.lock().map_err(|_| qualification_state_error())?;
        if measure_and_verify_version(&self.binary_path).is_err() {
            return Ok(ApprovedMcpQualificationStatus::unavailable(
                "BINARY_INVALID_OR_CHANGED",
            ));
        }
        if !self.root.join(EVIDENCE_FILE).exists() {
            return Ok(ApprovedMcpQualificationStatus::unavailable("NOT_RUN"));
        }
        match self.load_snapshot_locked(now_unix) {
            Ok(snapshot) => Ok(ApprovedMcpQualificationStatus::from_snapshot(
                snapshot, now_unix,
            )),
            Err(_) => Ok(ApprovedMcpQualificationStatus::unavailable(
                "EVIDENCE_INVALID",
            )),
        }
    }

    pub(super) fn revoke(&self) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        let _io = self.io.lock().map_err(|_| qualification_state_error())?;
        let mut replacement = self.keys.rotate(KeyRole::QualificationRevocationEpoch)?;
        zeroize(&mut replacement);
        let now_unix = now_seconds()?;
        if !self.root.join(EVIDENCE_FILE).exists() {
            let mut status = ApprovedMcpQualificationStatus::unavailable("REVOKED");
            status.revoked = true;
            return Ok(status);
        }
        match self.load_snapshot_locked(now_unix) {
            Ok(snapshot) => Ok(ApprovedMcpQualificationStatus::from_snapshot(
                snapshot, now_unix,
            )),
            Err(_) => {
                let mut status =
                    ApprovedMcpQualificationStatus::unavailable("REVOKED_OR_EPOCH_CHANGED");
                status.revoked = true;
                Ok(status)
            }
        }
    }

    fn live_binding(&self) -> Result<LiveQualificationBinding, ApprovedMcpError> {
        let measured = measure_and_verify_version(&self.binary_path)?;
        let ticket_key = self.keys.load_or_create(KeyRole::McpTicket)?;
        let server_key_id = format!("mcpkey_{}", &sha256_hex(&ticket_key)[..24]);
        let mut epoch_key = self
            .keys
            .load_or_create(KeyRole::QualificationRevocationEpoch)?;
        let epoch_hash = sha256_hex(&epoch_key);
        let mut epoch_bytes = [0_u8; 8];
        epoch_bytes.copy_from_slice(&epoch_key[..8]);
        let mut revocation_epoch = u64::from_be_bytes(epoch_bytes);
        if revocation_epoch == 0 {
            revocation_epoch = 1;
        }
        zeroize(&mut epoch_key);
        Ok(LiveQualificationBinding {
            ticket_key,
            expected: ExpectedQualificationBinding {
                server_key_id,
                server_key_version: KEY_VERSION,
                revocation_epoch,
                revocation_key_id: format!("mcpqepoch_{}", &epoch_hash[..24]),
                binary_path: measured.measurement.canonical_path,
                binary_path_identity_sha256: measured.measurement.path_identity_sha256,
                binary_file_identity_sha256: measured.measurement.file_identity_sha256,
                binary_sha256: measured.measurement.binary_sha256,
                binary_version: measured.version,
            },
        })
    }

    fn load_snapshot_locked(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedMcpError> {
        let binding = self.live_binding()?;
        let path = self.root.join(EVIDENCE_FILE);
        let bytes = read_bounded_regular(&path)?;
        let envelope: SignedQualificationEvidenceV1 =
            strict_json_v1_from_slice(&bytes).map_err(|_| qualification_state_error())?;
        if canonical_json_v1(&envelope).map_err(|_| qualification_state_error())? != bytes {
            return Err(qualification_state_error());
        }
        let claims_bytes =
            canonical_json_v1(&envelope.claims).map_err(|_| qualification_state_error())?;
        if envelope.claims_sha256.as_str() != sha256_hex(&claims_bytes)
            || !verify(&binding.ticket_key, &claims_bytes, &envelope.mac_hex)
            || !valid_evidence_id(&envelope.claims.evidence_id)
            || envelope.claims.schema_version != EVIDENCE_SCHEMA
            || envelope.claims.issued_at_unix == 0
            || envelope.claims.expires_at_unix <= envelope.claims.issued_at_unix
        {
            return Err(qualification_state_error());
        }
        let exact_app_policy_binding = envelope.claims.app_version == env!("CARGO_PKG_VERSION")
            && envelope.claims.policy_id == APPROVED_MCP_POLICY_ID
            && envelope.claims.policy_version == APPROVED_MCP_POLICY_VERSION;
        let exact_server_key_binding = envelope.claims.server_key_id
            == binding.expected.server_key_id
            && envelope.claims.server_key_version == binding.expected.server_key_version;
        if envelope.claims.mcp_binary_path_identity_sha256
            != binding.expected.binary_path_identity_sha256
            || envelope.claims.mcp_binary_file_identity_sha256
                != binding.expected.binary_file_identity_sha256
            || envelope.claims.mcp_binary_sha256 != binding.expected.binary_sha256
            || envelope.claims.mcp_binary_version != binding.expected.binary_version
        {
            return Err(qualification_state_error());
        }
        let epoch_matches = envelope.claims.revocation_epoch == binding.expected.revocation_epoch
            && envelope.claims.revocation_key_id == binding.expected.revocation_key_id;
        let evidence_sha256 =
            Sha256Hex::parse(sha256_hex(&bytes)).map_err(|_| qualification_state_error())?;
        let _ = now_unix;
        Ok(ApprovedMcpQualificationSnapshotV1 {
            evidence_id: envelope.claims.evidence_id,
            evidence_sha256,
            stdio_canary_passed: envelope.claims.stdio_canary_passed,
            streamable_http_canary_passed: envelope.claims.streamable_http_canary_passed,
            exact_app_policy_binding,
            exact_server_key_binding,
            mcp_binary_path_identity_sha256: envelope.claims.mcp_binary_path_identity_sha256,
            mcp_binary_file_identity_sha256: envelope.claims.mcp_binary_file_identity_sha256,
            mcp_binary_sha256: envelope.claims.mcp_binary_sha256,
            mcp_binary_version: envelope.claims.mcp_binary_version,
            app_version: envelope.claims.app_version,
            policy_id: envelope.claims.policy_id,
            policy_version: envelope.claims.policy_version,
            server_key_id: envelope.claims.server_key_id,
            server_key_version: envelope.claims.server_key_version,
            revocation_epoch: envelope.claims.revocation_epoch,
            issued_at_unix: envelope.claims.issued_at_unix,
            expires_at_unix: envelope.claims.expires_at_unix,
            revoked: envelope.claims.revoked || !epoch_matches,
        })
    }
}

impl ApprovedWorkspaceQualificationProvider for DesktopApprovedMcpQualificationProvider {
    fn current_qualification(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError> {
        let _io = self
            .io
            .lock()
            .map_err(|_| ApprovedWorkspaceQualificationError::Unavailable)?;
        self.load_snapshot_locked(now_unix)
            .map_err(|_| ApprovedWorkspaceQualificationError::Unavailable)
    }
}

impl ApprovedMcpWorkspace {
    pub(crate) fn preflight_startup_workspace_identity(
        &self,
    ) -> Result<StartupWorkspaceIdentityPreflight, ApprovedMcpError> {
        let _operation = self.operation()?;
        let history_present = self.startup_history_present_read_only()?;
        let existing_key = self.inner.keys.load_existing(KeyRole::ApprovedManifest)?;
        match existing_key {
            Some(mut manifest_key) => {
                let identity = super::workspace_instance_id(&manifest_key);
                zeroize(&mut manifest_key);
                identity.map(StartupWorkspaceIdentityPreflight::Existing)
            }
            None if history_present => Err(startup_identity_missing_error()),
            None => Ok(StartupWorkspaceIdentityPreflight::Fresh {
                app_local_data_directory: self.inner.app_local_data_directory.clone(),
            }),
        }
    }

    pub(crate) fn workspace_instance_id_after_startup_preflight(
        &self,
        preflight: StartupWorkspaceIdentityPreflight,
    ) -> Result<WorkspaceInstanceId, ApprovedMcpError> {
        let _operation = self.operation()?;
        match preflight {
            StartupWorkspaceIdentityPreflight::Existing(identity) => Ok(identity),
            StartupWorkspaceIdentityPreflight::Fresh {
                app_local_data_directory,
            } => {
                if app_local_data_directory != self.inner.app_local_data_directory
                    || self.startup_history_present_read_only()?
                {
                    return Err(startup_identity_preflight_error());
                }
                let mut manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
                let identity = super::workspace_instance_id(&manifest_key);
                zeroize(&mut manifest_key);
                identity
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn workspace_instance_id(&self) -> Result<WorkspaceInstanceId, ApprovedMcpError> {
        let _operation = self.operation()?;
        let mut manifest_key = self.inner.keys.load_or_create(KeyRole::ApprovedManifest)?;
        let identity = super::workspace_instance_id(&manifest_key);
        zeroize(&mut manifest_key);
        identity
    }

    pub(crate) fn qualification_status(
        &self,
    ) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        let control = self
            .inner
            .qualification_control
            .as_ref()
            .ok_or_else(qualification_state_error)?;
        control.status(now_seconds()?)
    }

    pub(crate) async fn run_qualification(
        &self,
        ttl_seconds: u64,
    ) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        if !(MIN_QUALIFICATION_TTL_SECONDS..=MAX_QUALIFICATION_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(invalid_request());
        }
        let control = self
            .inner
            .qualification_control
            .as_ref()
            .ok_or_else(qualification_state_error)?;
        let expected = control.begin_run()?;
        super::qualification_canary::run(self, &expected).await?;
        let issued_at_unix = now_seconds()?;
        let expires_at_unix = issued_at_unix
            .checked_add(ttl_seconds)
            .ok_or_else(invalid_request)?;
        control.persist_passed(&expected, issued_at_unix, expires_at_unix)
    }

    pub(crate) fn revoke_qualification(
        &self,
    ) -> Result<ApprovedMcpQualificationStatus, ApprovedMcpError> {
        self.inner
            .qualification_control
            .as_ref()
            .ok_or_else(qualification_state_error)?
            .revoke()
    }
}

struct MeasuredMcpBinary {
    measurement: ReleaseBinaryMeasurement,
    version: String,
}

fn measure_and_verify_version(path: &Path) -> Result<MeasuredMcpBinary, ApprovedMcpError> {
    let before = measure_release_binary(path).map_err(|_| binary_binding_error())?;
    validate_compiled_release_hash(
        option_env!("LAWYER_ASSISTANCE_MCP_RELEASE_SHA256"),
        &before.binary_sha256,
    )?;
    let mut child = ProcessCommand::new(&before.canonical_path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LAWYER_ASSISTANCE_MCP_LOG", "off")
        .spawn()
        .map_err(|_| binary_binding_error())?;
    let stdout = bounded_capture(child.stdout.take().ok_or_else(binary_binding_error));
    let stderr = bounded_capture(child.stderr.take().ok_or_else(binary_binding_error));
    let deadline = Instant::now() + BINARY_VERSION_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(binary_binding_error());
            }
        }
    };
    let stdout = stdout
        .join()
        .map_err(|_| binary_binding_error())?
        .map_err(|_| binary_binding_error())?;
    let stderr = stderr
        .join()
        .map_err(|_| binary_binding_error())?
        .map_err(|_| binary_binding_error())?;
    let expected = format!("lawyer-assistance-mcp {}", env!("CARGO_PKG_VERSION"));
    let version_line = std::str::from_utf8(&stdout)
        .map_err(|_| binary_binding_error())?
        .trim_end_matches(['\r', '\n']);
    if !status.success()
        || !stderr.is_empty()
        || stdout.len() > usize::try_from(MAX_VERSION_OUTPUT_BYTES).unwrap_or(usize::MAX)
        || version_line != expected
    {
        return Err(binary_binding_error());
    }
    let after =
        measure_release_binary(&before.canonical_path).map_err(|_| binary_binding_error())?;
    if before != after
        || validate_compiled_release_hash(
            option_env!("LAWYER_ASSISTANCE_MCP_RELEASE_SHA256"),
            &after.binary_sha256,
        )
        .is_err()
    {
        return Err(binary_binding_error());
    }
    Ok(MeasuredMcpBinary {
        measurement: after,
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

pub(super) fn validate_compiled_release_hash(
    expected: Option<&str>,
    measured: &Sha256Hex,
) -> Result<(), ApprovedMcpError> {
    let expected = expected.filter(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if expected != Some(measured.as_str()) {
        return Err(binary_trust_anchor_error());
    }
    Ok(())
}

fn bounded_capture(
    stream: Result<impl Read + Send + 'static, ApprovedMcpError>,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let stream = stream.map_err(|_| std::io::ErrorKind::Other)?;
        let mut bytes = Vec::new();
        stream
            .take(MAX_VERSION_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn sign(key: &[u8; 32], claims: &[u8]) -> Result<String, ApprovedMcpError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| qualification_state_error())?;
    mac.update(EVIDENCE_DOMAIN);
    mac.update(claims);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn verify(key: &[u8; 32], claims: &[u8], mac_hex: &str) -> bool {
    let Some(expected) = hex_decode_32(mac_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(EVIDENCE_DOMAIN);
    mac.update(claims);
    mac.verify_slice(&expected).is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

fn valid_evidence_id(value: &str) -> bool {
    value.strip_prefix("mcpq_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, ApprovedMcpError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| qualification_state_error())?;
    let length = usize::try_from(metadata.len()).map_err(|_| qualification_state_error())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || length == 0
        || length > MAX_EVIDENCE_BYTES
    {
        return Err(qualification_state_error());
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(|_| qualification_state_error())?
        .take(u64::try_from(MAX_EVIDENCE_BYTES + 1).map_err(|_| qualification_state_error())?)
        .read_to_end(&mut bytes)
        .map_err(|_| qualification_state_error())?;
    if bytes.len() != length || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(qualification_state_error());
    }
    Ok(bytes)
}

fn write_atomic(root: &Path, bytes: &[u8]) -> Result<(), ApprovedMcpError> {
    fs::create_dir_all(root).map_err(|_| qualification_state_error())?;
    let metadata = fs::symlink_metadata(root).map_err(|_| qualification_state_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(qualification_state_error());
    }
    let incoming = root.join(format!(".incoming-{}.json", Uuid::new_v4().simple()));
    let destination = root.join(EVIDENCE_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&incoming)
        .map_err(|_| qualification_state_error())?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| {
            drop(file);
            atomic_file::install(&incoming, &destination, None)
        });
    if result.is_err() {
        let _ = fs::remove_file(&incoming);
        return Err(qualification_state_error());
    }
    Ok(())
}

fn qualification_state_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_qualification_evidence_invalid",
        "The local approved MCP qualification evidence is unavailable or invalid.",
    )
}

fn qualification_changed_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_qualification_binding_changed",
        "The approved MCP key or revocation binding changed during qualification.",
    )
}

fn binary_binding_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_release_binary_invalid",
        "The fixed installed approved MCP release binary is unavailable, unsafe, or changed.",
    )
}

fn binary_trust_anchor_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_release_binary_untrusted",
        "The installed approved MCP binary does not match the release identity compiled into this App.",
    )
}
