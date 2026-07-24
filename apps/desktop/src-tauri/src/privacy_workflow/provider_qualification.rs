use super::*;
use crate::atomic_file;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use privacy::vnext::{canonical_json_v1, strict_json_v1_from_slice};
use providers::{
    provider_endpoint_origin, ApiSecret, CredentialStore, ProviderCredentialKey, ProviderProfile,
    ProviderStoreLock,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    ptr,
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc,
    },
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

type HmacSha256 = Hmac<Sha256>;

const QUALIFICATION_SCHEMA: &str = "lawyer-assistance-provider-qualification-v1";
const QUALIFICATION_DOMAIN: &[u8] = b"lawyer-assistance\0provider-qualification-evidence-v1\0";
const QUALIFICATION_FILE: &str = "active-evidence-v1.json";
const QUALIFICATION_POLICY_ID: &str = "approved-provider-egress-v1";
const QUALIFICATION_POLICY_VERSION: u64 = 1;
const QUALIFICATION_KEY_VERSION: u64 = 1;
const QUALIFICATION_KEY_PREFIX: &str = "provider-qualification-key-v1.";
const QUALIFICATION_KEY_SERVICE: &str = "LawyerAssistanceApprovedProvider";
const MIN_QUALIFICATION_TTL_SECONDS: u64 = 5 * 60;
const MAX_QUALIFICATION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_QUALIFICATION_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderQualificationRequest {
    pub provider_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderQualificationRunRequest {
    pub provider_id: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderQualificationStatus {
    pub qualified: bool,
    pub reason_code: String,
    pub evidence_id: Option<String>,
    pub evidence_sha256: Option<String>,
    pub provider_id: Option<String>,
    pub provider_contract_sha256: Option<String>,
    pub model_id: Option<String>,
    pub endpoint_origin_sha256: Option<String>,
    pub task_contract_sha256: String,
    pub exact_workspace_app_policy_binding: bool,
    pub exact_provider_contract_binding: bool,
    pub exact_task_contract_binding: bool,
    pub prepare_canary_passed: bool,
    pub approval_restore_canary_passed: bool,
    pub real_loopback_transport_passed: bool,
    pub approved_output_persisted: bool,
    pub raw_canary_absent: bool,
    pub exactly_one_request: bool,
    pub signing_key_id: Option<String>,
    pub signing_key_version: u64,
    pub revocation_epoch: Option<u64>,
    pub issued_at_unix: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
}

impl ProviderQualificationStatus {
    fn unavailable(reason_code: &str) -> Self {
        Self {
            qualified: false,
            reason_code: reason_code.to_owned(),
            evidence_id: None,
            evidence_sha256: None,
            provider_id: None,
            provider_contract_sha256: None,
            model_id: None,
            endpoint_origin_sha256: None,
            task_contract_sha256: super::approved_provider::task_contract_sha256(),
            exact_workspace_app_policy_binding: false,
            exact_provider_contract_binding: false,
            exact_task_contract_binding: false,
            prepare_canary_passed: false,
            approval_restore_canary_passed: false,
            real_loopback_transport_passed: false,
            approved_output_persisted: false,
            raw_canary_absent: false,
            exactly_one_request: false,
            signing_key_id: None,
            signing_key_version: QUALIFICATION_KEY_VERSION,
            revocation_epoch: None,
            issued_at_unix: None,
            expires_at_unix: None,
            revoked: false,
        }
    }

    fn from_snapshot(snapshot: QualificationSnapshot, now_unix: u64) -> Self {
        let qualified = snapshot.exact_workspace_app_policy_binding
            && snapshot.exact_provider_contract_binding
            && snapshot.exact_task_contract_binding
            && snapshot.canary.all_passed()
            && !snapshot.revoked
            && now_unix >= snapshot.issued_at_unix
            && now_unix < snapshot.expires_at_unix;
        let reason_code = if qualified {
            "QUALIFIED"
        } else if snapshot.revoked {
            "REVOKED_OR_EPOCH_CHANGED"
        } else if !snapshot.exact_workspace_app_policy_binding {
            "WORKSPACE_APP_OR_POLICY_CHANGED"
        } else if !snapshot.exact_provider_contract_binding {
            "PROVIDER_CONTRACT_CHANGED"
        } else if !snapshot.exact_task_contract_binding {
            "TASK_CONTRACT_CHANGED"
        } else if !snapshot.canary.all_passed() {
            "CANARY_INCOMPLETE"
        } else if now_unix < snapshot.issued_at_unix {
            "EVIDENCE_NOT_YET_VALID"
        } else if now_unix >= snapshot.expires_at_unix {
            "EVIDENCE_EXPIRED"
        } else {
            "EVIDENCE_INVALID"
        };
        Self {
            qualified,
            reason_code: reason_code.to_owned(),
            evidence_id: Some(snapshot.evidence_id),
            evidence_sha256: Some(snapshot.evidence_sha256),
            provider_id: Some(snapshot.provider_id),
            provider_contract_sha256: Some(snapshot.provider_contract_sha256),
            model_id: Some(snapshot.model_id),
            endpoint_origin_sha256: Some(snapshot.endpoint_origin_sha256),
            task_contract_sha256: snapshot.task_contract_sha256,
            exact_workspace_app_policy_binding: snapshot.exact_workspace_app_policy_binding,
            exact_provider_contract_binding: snapshot.exact_provider_contract_binding,
            exact_task_contract_binding: snapshot.exact_task_contract_binding,
            prepare_canary_passed: snapshot.canary.prepare_canary_passed,
            approval_restore_canary_passed: snapshot.canary.approval_restore_canary_passed,
            real_loopback_transport_passed: snapshot.canary.real_loopback_transport_passed,
            approved_output_persisted: snapshot.canary.approved_output_persisted,
            raw_canary_absent: snapshot.canary.raw_canary_absent,
            exactly_one_request: snapshot.canary.exactly_one_request,
            signing_key_id: Some(snapshot.signing_key_id),
            signing_key_version: snapshot.signing_key_version,
            revocation_epoch: Some(snapshot.revocation_epoch),
            issued_at_unix: Some(snapshot.issued_at_unix),
            expires_at_unix: Some(snapshot.expires_at_unix),
            revoked: snapshot.revoked,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ProviderQualificationKeyRole {
    EvidenceSigning,
    RevocationEpoch,
}

impl ProviderQualificationKeyRole {
    const fn provider_id(self) -> &'static str {
        match self {
            Self::EvidenceSigning => "provider-qualification-signing",
            Self::RevocationEpoch => "provider-qualification-revocation-epoch",
        }
    }
}

pub(super) trait ProviderQualificationKeyProvider: Send + Sync {
    fn load_or_create(
        &self,
        role: ProviderQualificationKeyRole,
    ) -> Result<[u8; 32], PrivacyWorkflowError>;
    fn rotate(&self, role: ProviderQualificationKeyRole) -> Result<[u8; 32], PrivacyWorkflowError>;
}

#[derive(Debug)]
struct WindowsProviderQualificationKeyProvider {
    store: WindowsCredentialStore,
}

impl WindowsProviderQualificationKeyProvider {
    fn new() -> Self {
        Self {
            store: WindowsCredentialStore::with_service_prefix(QUALIFICATION_KEY_SERVICE),
        }
    }

    fn write_random_locked(
        &self,
        key: &ProviderCredentialKey,
    ) -> Result<[u8; 32], PrivacyWorkflowError> {
        let mut bytes = [0_u8; 32];
        fill_random(&mut bytes)?;
        if bytes.iter().all(|byte| *byte == 0) {
            zeroize(&mut bytes);
            return Err(key_error());
        }
        let encoded = format!(
            "{QUALIFICATION_KEY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        );
        if self
            .store
            .write_api_key(key, ApiSecret::new(encoded))
            .is_err()
        {
            zeroize(&mut bytes);
            return Err(key_error());
        }
        Ok(bytes)
    }
}

impl ProviderQualificationKeyProvider for WindowsProviderQualificationKeyProvider {
    fn load_or_create(
        &self,
        role: ProviderQualificationKeyRole,
    ) -> Result<[u8; 32], PrivacyWorkflowError> {
        let _lock = ProviderStoreLock::acquire().map_err(|_| key_error())?;
        let key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        if let Some(secret) = self.store.read_api_key(&key).map_err(|_| key_error())? {
            return decode_key(secret.expose_secret());
        }
        self.write_random_locked(&key)
    }

    fn rotate(&self, role: ProviderQualificationKeyRole) -> Result<[u8; 32], PrivacyWorkflowError> {
        let _lock = ProviderStoreLock::acquire().map_err(|_| key_error())?;
        let key = ProviderCredentialKey::new(role.provider_id(), "user-boundary-v1");
        self.write_random_locked(&key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpectedProviderQualificationBinding {
    workspace_instance_id: String,
    provider_id: String,
    provider_contract_sha256: String,
    model_id: String,
    endpoint_origin: String,
    task_contract_sha256: String,
    signing_key_id: String,
    signing_key_version: u64,
    revocation_epoch: u64,
    revocation_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderCanaryEvidence {
    prepare_canary_passed: bool,
    approval_restore_canary_passed: bool,
    real_loopback_transport_passed: bool,
    approved_output_persisted: bool,
    raw_canary_absent: bool,
    exactly_one_request: bool,
}

impl ProviderCanaryEvidence {
    fn all_passed(&self) -> bool {
        self.prepare_canary_passed
            && self.approval_restore_canary_passed
            && self.real_loopback_transport_passed
            && self.approved_output_persisted
            && self.raw_canary_absent
            && self.exactly_one_request
    }
}

impl From<super::approved_provider::ProviderQualificationCanaryEvidence>
    for ProviderCanaryEvidence
{
    fn from(value: super::approved_provider::ProviderQualificationCanaryEvidence) -> Self {
        Self {
            prepare_canary_passed: value.prepare_canary_passed,
            approval_restore_canary_passed: value.approval_restore_canary_passed,
            real_loopback_transport_passed: value.real_loopback_transport_passed,
            approved_output_persisted: value.approved_output_persisted,
            raw_canary_absent: value.raw_canary_absent,
            exactly_one_request: value.exactly_one_request,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationClaims {
    schema_version: String,
    evidence_id: String,
    workspace_instance_id: String,
    app_version: String,
    policy_id: String,
    policy_version: u64,
    detector_version: String,
    provider_id: String,
    provider_contract_sha256: String,
    model_id: String,
    endpoint_origin: String,
    task_contract_sha256: String,
    canary: ProviderCanaryEvidence,
    signing_key_id: String,
    signing_key_version: u64,
    revocation_epoch: u64,
    revocation_key_id: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedQualificationEvidence {
    claims: QualificationClaims,
    claims_sha256: String,
    mac_hex: String,
}

struct LiveBinding {
    signing_key: [u8; 32],
    expected: ExpectedProviderQualificationBinding,
}

impl Drop for LiveBinding {
    fn drop(&mut self) {
        zeroize(&mut self.signing_key);
    }
}

struct QualificationSnapshot {
    evidence_id: String,
    evidence_sha256: String,
    provider_id: String,
    provider_contract_sha256: String,
    model_id: String,
    endpoint_origin_sha256: String,
    task_contract_sha256: String,
    exact_workspace_app_policy_binding: bool,
    exact_provider_contract_binding: bool,
    exact_task_contract_binding: bool,
    canary: ProviderCanaryEvidence,
    signing_key_id: String,
    signing_key_version: u64,
    revocation_epoch: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
    revoked: bool,
}

struct ProviderQualificationStore {
    root: PathBuf,
    workspace_instance_id: String,
    keys: Arc<dyn ProviderQualificationKeyProvider>,
}

impl ProviderQualificationStore {
    fn new(
        root: PathBuf,
        workspace_instance_id: String,
        keys: Arc<dyn ProviderQualificationKeyProvider>,
    ) -> Self {
        Self {
            root,
            workspace_instance_id,
            keys,
        }
    }

    fn begin_run(
        &self,
        profile: &ProviderProfile,
    ) -> Result<ExpectedProviderQualificationBinding, PrivacyWorkflowError> {
        Ok(self.live_binding(profile)?.expected.clone())
    }

    fn persist_passed(
        &self,
        profile: &ProviderProfile,
        expected: &ExpectedProviderQualificationBinding,
        canary: super::approved_provider::ProviderQualificationCanaryEvidence,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ProviderQualificationStatus, PrivacyWorkflowError> {
        let live = self.live_binding(profile)?;
        let canary = ProviderCanaryEvidence::from(canary);
        if &live.expected != expected
            || !canary.all_passed()
            || issued_at_unix == 0
            || expires_at_unix <= issued_at_unix
            || expires_at_unix - issued_at_unix > MAX_QUALIFICATION_TTL_SECONDS
        {
            return Err(qualification_changed());
        }
        let claims = QualificationClaims {
            schema_version: QUALIFICATION_SCHEMA.to_owned(),
            evidence_id: format!("pvq_{}", Uuid::new_v4().simple()),
            workspace_instance_id: expected.workspace_instance_id.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: QUALIFICATION_POLICY_ID.to_owned(),
            policy_version: QUALIFICATION_POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            provider_id: expected.provider_id.clone(),
            provider_contract_sha256: expected.provider_contract_sha256.clone(),
            model_id: expected.model_id.clone(),
            endpoint_origin: expected.endpoint_origin.clone(),
            task_contract_sha256: expected.task_contract_sha256.clone(),
            canary,
            signing_key_id: expected.signing_key_id.clone(),
            signing_key_version: expected.signing_key_version,
            revocation_epoch: expected.revocation_epoch,
            revocation_key_id: expected.revocation_key_id.clone(),
            issued_at_unix,
            expires_at_unix,
            revoked: false,
        };
        let claims_bytes = canonical_json_v1(&claims).map_err(|_| qualification_state_error())?;
        let envelope = SignedQualificationEvidence {
            claims,
            claims_sha256: sha256_hex(&claims_bytes),
            mac_hex: sign(&live.signing_key, &claims_bytes)?,
        };
        let bytes = canonical_json_v1(&envelope).map_err(|_| qualification_state_error())?;
        if bytes.len() > MAX_QUALIFICATION_BYTES {
            return Err(qualification_state_error());
        }
        write_atomic(&self.root, &bytes)?;
        let snapshot = self.load_snapshot(profile)?;
        Ok(ProviderQualificationStatus::from_snapshot(
            snapshot,
            issued_at_unix,
        ))
    }

    fn status(&self, profile: &ProviderProfile, now_unix: u64) -> ProviderQualificationStatus {
        if !self.root.join(QUALIFICATION_FILE).exists() {
            return ProviderQualificationStatus::unavailable("NOT_RUN");
        }
        match self.load_snapshot(profile) {
            Ok(snapshot) => ProviderQualificationStatus::from_snapshot(snapshot, now_unix),
            Err(_) => ProviderQualificationStatus::unavailable("EVIDENCE_INVALID"),
        }
    }

    fn verify_current(
        &self,
        profile: &ProviderProfile,
        now_unix: u64,
    ) -> Result<(), PrivacyWorkflowError> {
        let status = self.status(profile, now_unix);
        if status.qualified {
            Ok(())
        } else {
            Err(PrivacyWorkflowError::new(
                "provider_not_qualified",
                format!(
                    "The selected Provider is not qualified for approved case egress ({})",
                    status.reason_code
                ),
            ))
        }
    }

    fn verify_expected(
        &self,
        profile: &ProviderProfile,
        expected: &ExpectedProviderQualificationBinding,
    ) -> Result<(), PrivacyWorkflowError> {
        if self.live_binding(profile)?.expected == *expected {
            Ok(())
        } else {
            Err(qualification_changed())
        }
    }

    fn revoke(
        &self,
        profile: &ProviderProfile,
        now_unix: u64,
    ) -> Result<ProviderQualificationStatus, PrivacyWorkflowError> {
        let mut replacement = self
            .keys
            .rotate(ProviderQualificationKeyRole::RevocationEpoch)?;
        zeroize(&mut replacement);
        let mut status = self.status(profile, now_unix);
        status.qualified = false;
        status.revoked = true;
        status.reason_code = "REVOKED_OR_EPOCH_CHANGED".to_owned();
        Ok(status)
    }

    fn live_binding(&self, profile: &ProviderProfile) -> Result<LiveBinding, PrivacyWorkflowError> {
        let signing_key = self
            .keys
            .load_or_create(ProviderQualificationKeyRole::EvidenceSigning)?;
        let signing_hash = sha256_hex(&signing_key);
        let mut epoch_key = self
            .keys
            .load_or_create(ProviderQualificationKeyRole::RevocationEpoch)?;
        let epoch_hash = sha256_hex(&epoch_key);
        let mut epoch_bytes = [0_u8; 8];
        epoch_bytes.copy_from_slice(&epoch_key[..8]);
        let mut revocation_epoch = u64::from_be_bytes(epoch_bytes);
        if revocation_epoch == 0 {
            revocation_epoch = 1;
        }
        zeroize(&mut epoch_key);
        let endpoint_origin = provider_endpoint_origin(profile).map_err(|error| {
            PrivacyWorkflowError::new(
                error.kind.as_str(),
                providers::redact_sensitive(&error.message),
            )
        })?;
        let profile_bytes = serde_json::to_vec(profile).map_err(|_| qualification_state_error())?;
        Ok(LiveBinding {
            signing_key,
            expected: ExpectedProviderQualificationBinding {
                workspace_instance_id: self.workspace_instance_id.clone(),
                provider_id: profile.id.clone(),
                provider_contract_sha256: sha256_hex(&profile_bytes),
                model_id: super::approved_provider::profile_model_binding(profile),
                endpoint_origin,
                task_contract_sha256: super::approved_provider::task_contract_sha256(),
                signing_key_id: format!("pvqkey_{}", &signing_hash[..24]),
                signing_key_version: QUALIFICATION_KEY_VERSION,
                revocation_epoch,
                revocation_key_id: format!("pvqepoch_{}", &epoch_hash[..24]),
            },
        })
    }

    fn load_snapshot(
        &self,
        profile: &ProviderProfile,
    ) -> Result<QualificationSnapshot, PrivacyWorkflowError> {
        let live = self.live_binding(profile)?;
        let path = self.root.join(QUALIFICATION_FILE);
        let bytes = read_bounded_regular(&path)?;
        let envelope: SignedQualificationEvidence =
            strict_json_v1_from_slice(&bytes).map_err(|_| qualification_state_error())?;
        if canonical_json_v1(&envelope).map_err(|_| qualification_state_error())? != bytes {
            return Err(qualification_state_error());
        }
        let claims_bytes =
            canonical_json_v1(&envelope.claims).map_err(|_| qualification_state_error())?;
        if envelope.claims_sha256 != sha256_hex(&claims_bytes)
            || !verify(&live.signing_key, &claims_bytes, &envelope.mac_hex)
            || !valid_evidence_id(&envelope.claims.evidence_id)
            || envelope.claims.schema_version != QUALIFICATION_SCHEMA
            || envelope.claims.issued_at_unix == 0
            || envelope.claims.expires_at_unix <= envelope.claims.issued_at_unix
            || envelope.claims.expires_at_unix - envelope.claims.issued_at_unix
                > MAX_QUALIFICATION_TTL_SECONDS
        {
            return Err(qualification_state_error());
        }
        let exact_workspace_app_policy_binding = envelope.claims.workspace_instance_id
            == self.workspace_instance_id
            && envelope.claims.app_version == env!("CARGO_PKG_VERSION")
            && envelope.claims.policy_id == QUALIFICATION_POLICY_ID
            && envelope.claims.policy_version == QUALIFICATION_POLICY_VERSION
            && envelope.claims.detector_version == REDACTION_VERSION
            && envelope.claims.signing_key_id == live.expected.signing_key_id
            && envelope.claims.signing_key_version == live.expected.signing_key_version;
        let exact_provider_contract_binding = envelope.claims.provider_id
            == live.expected.provider_id
            && envelope.claims.provider_contract_sha256 == live.expected.provider_contract_sha256
            && envelope.claims.model_id == live.expected.model_id
            && envelope.claims.endpoint_origin == live.expected.endpoint_origin;
        let exact_task_contract_binding =
            envelope.claims.task_contract_sha256 == live.expected.task_contract_sha256;
        let epoch_matches = envelope.claims.revocation_epoch == live.expected.revocation_epoch
            && envelope.claims.revocation_key_id == live.expected.revocation_key_id;
        Ok(QualificationSnapshot {
            evidence_id: envelope.claims.evidence_id,
            evidence_sha256: sha256_hex(&bytes),
            provider_id: envelope.claims.provider_id,
            provider_contract_sha256: envelope.claims.provider_contract_sha256,
            model_id: envelope.claims.model_id,
            endpoint_origin_sha256: sha256_hex(envelope.claims.endpoint_origin.as_bytes()),
            task_contract_sha256: envelope.claims.task_contract_sha256,
            exact_workspace_app_policy_binding,
            exact_provider_contract_binding,
            exact_task_contract_binding,
            canary: envelope.claims.canary,
            signing_key_id: envelope.claims.signing_key_id,
            signing_key_version: envelope.claims.signing_key_version,
            revocation_epoch: envelope.claims.revocation_epoch,
            issued_at_unix: envelope.claims.issued_at_unix,
            expires_at_unix: envelope.claims.expires_at_unix,
            revoked: envelope.claims.revoked || !epoch_matches,
        })
    }
}

impl PrivacyWorkflowManager {
    fn provider_qualification_store(&self) -> ProviderQualificationStore {
        let override_keys = self
            .shared
            .provider_qualification_key_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let keys: Arc<dyn ProviderQualificationKeyProvider> = override_keys
            .unwrap_or_else(|| Arc::new(WindowsProviderQualificationKeyProvider::new()));
        ProviderQualificationStore::new(
            self.shared.provider_qualification_root.clone(),
            self.shared.workspace_instance_id.as_str().to_owned(),
            keys,
        )
    }

    pub fn provider_qualification_status(
        &self,
        profile: &ProviderProfile,
    ) -> Result<ProviderQualificationStatus, PrivacyWorkflowError> {
        let _gate = self.gate();
        if !valid_identifier(&profile.id) {
            return Err(invalid_qualification_request());
        }
        Ok(self
            .provider_qualification_store()
            .status(profile, self.current_unix()?))
    }

    pub fn run_provider_qualification(
        &self,
        profile: ProviderProfile,
        ttl_seconds: u64,
    ) -> Result<ProviderQualificationStatus, PrivacyWorkflowError> {
        if !valid_identifier(&profile.id)
            || !(MIN_QUALIFICATION_TTL_SECONDS..=MAX_QUALIFICATION_TTL_SECONDS)
                .contains(&ttl_seconds)
        {
            return Err(invalid_qualification_request());
        }
        let expected = {
            let _gate = self.gate();
            self.provider_qualification_store().begin_run(&profile)?
        };
        let canary =
            super::approved_provider::run_provider_qualification_canary(self, &profile, &expected)?;
        let _gate = self.gate();
        let issued_at_unix = self.current_unix()?;
        let expires_at_unix = issued_at_unix
            .checked_add(ttl_seconds)
            .ok_or_else(invalid_qualification_request)?;
        self.provider_qualification_store().persist_passed(
            &profile,
            &expected,
            canary,
            issued_at_unix,
            expires_at_unix,
        )
    }

    pub fn revoke_provider_qualification(
        &self,
        profile: &ProviderProfile,
    ) -> Result<ProviderQualificationStatus, PrivacyWorkflowError> {
        let _gate = self.gate();
        self.provider_qualification_store()
            .revoke(profile, self.current_unix()?)
    }

    pub(super) fn verify_provider_qualified(
        &self,
        profile: &ProviderProfile,
        now_unix: u64,
    ) -> Result<(), PrivacyWorkflowError> {
        self.provider_qualification_store()
            .verify_current(profile, now_unix)
    }

    pub(super) fn verify_provider_canary_expected(
        &self,
        profile: &ProviderProfile,
        expected: &ExpectedProviderQualificationBinding,
    ) -> Result<(), PrivacyWorkflowError> {
        self.provider_qualification_store()
            .verify_expected(profile, expected)
    }
}

fn decode_key(value: &str) -> Result<[u8; 32], PrivacyWorkflowError> {
    let encoded = value
        .strip_prefix(QUALIFICATION_KEY_PREFIX)
        .ok_or_else(key_error)?;
    let mut decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| key_error())?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        zeroize(&mut decoded);
        return Err(key_error());
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    zeroize(&mut decoded);
    Ok(key)
}

fn fill_random(bytes: &mut [u8]) -> Result<(), PrivacyWorkflowError> {
    let length = u32::try_from(bytes.len()).map_err(|_| key_error())?;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(key_error());
    }
    Ok(())
}

fn zeroize(bytes: &mut [u8]) {
    bytes.fill(0);
    compiler_fence(Ordering::SeqCst);
}

fn sign(key: &[u8; 32], claims: &[u8]) -> Result<String, PrivacyWorkflowError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| qualification_state_error())?;
    mac.update(QUALIFICATION_DOMAIN);
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
    mac.update(QUALIFICATION_DOMAIN);
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
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(output)
}

fn valid_evidence_id(value: &str) -> bool {
    value.strip_prefix("pvq_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, PrivacyWorkflowError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| qualification_state_error())?;
    let length = usize::try_from(metadata.len()).map_err(|_| qualification_state_error())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || length == 0
        || length > MAX_QUALIFICATION_BYTES
    {
        return Err(qualification_state_error());
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(|_| qualification_state_error())?
        .take(u64::try_from(MAX_QUALIFICATION_BYTES + 1).map_err(|_| qualification_state_error())?)
        .read_to_end(&mut bytes)
        .map_err(|_| qualification_state_error())?;
    if bytes.len() != length || bytes.len() > MAX_QUALIFICATION_BYTES {
        return Err(qualification_state_error());
    }
    Ok(bytes)
}

fn write_atomic(root: &Path, bytes: &[u8]) -> Result<(), PrivacyWorkflowError> {
    fs::create_dir_all(root).map_err(|_| qualification_state_error())?;
    let metadata = fs::symlink_metadata(root).map_err(|_| qualification_state_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(qualification_state_error());
    }
    let incoming = root.join(format!(".incoming-{}.json", Uuid::new_v4().simple()));
    let destination = root.join(QUALIFICATION_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&incoming)
        .map_err(|_| qualification_state_error())?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| qualification_state_error())?;
        file.sync_all().map_err(|_| qualification_state_error())?;
        drop(file);
        atomic_file::install(&incoming, &destination, None)
            .map_err(|_| qualification_state_error())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&incoming);
    }
    result
}

fn key_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "provider_qualification_key_unavailable",
        "The user-bound Provider qualification signing identity is unavailable.",
    )
}

fn qualification_state_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "provider_qualification_state_invalid",
        "The signed Provider qualification evidence is unavailable or invalid.",
    )
}

fn qualification_changed() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "provider_qualification_changed",
        "The Provider qualification binding changed during the qualification run.",
    )
}

fn invalid_qualification_request() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "invalid_provider_qualification_request",
        "The Provider qualification request or validity period is invalid.",
    )
}
