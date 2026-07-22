//! Deterministic, local-only content redaction for model-visible boundaries.
//!
//! High-confidence identifiers and labelled legal-document fields are replaced
//! with stable placeholders. Unlabelled semantic entities still require local
//! preview and human review.

pub mod application_backup;
pub mod case_dictionary;
pub mod deterministic;
pub mod egress;
pub mod evaluation;
pub mod finding_engine;
pub mod lifecycle;
pub mod local_ner;
pub mod mcp_ticket;
pub mod protected_blob;
pub mod qualification;
pub mod receipt;
mod redaction_mapping;
pub mod residual_scan;
pub mod review_session;
pub mod risk_engine;
pub mod store;
pub mod vault_backup;
pub mod vault_crypto;
pub mod vault_store;
pub mod vnext;
pub mod work_products;
pub mod workspace;

pub use application_backup::{
    open_application_backup, seal_application_backup, seal_application_backup_v3,
    ApplicationBackupCreateRequest, ApplicationBackupCreateRequestV3, ApplicationBackupError,
    ApplicationBackupMetadata, ApplicationBackupOpenContext, OpenedApplicationBackup,
    APPLICATION_BACKUP_CHUNK_BYTES, APPLICATION_BACKUP_CRYPTO_SUITE,
    APPLICATION_BACKUP_SCHEMA_VERSION, APPLICATION_BACKUP_V3_CRYPTO_SUITE,
    APPLICATION_BACKUP_V3_SCHEMA_VERSION, MAX_APPLICATION_BACKUP_BYTES,
    MAX_APPROVED_WORKSPACE_BACKUP_BYTES, MAX_USER_DATABASE_BACKUP_BYTES,
    MAX_WORK_PRODUCTS_BACKUP_BYTES,
};
pub use egress::{
    scan_residual, ApprovedOutboundPayload, DataClassification, EgressCandidate, EgressError,
    EgressPolicyEngine, PrivacyEgressAuditRecord, ResidualScanResult,
};
pub use lifecycle::{
    ApprovedOutputAccessContextV1, ApprovedOutputSummaryV1, BackupExportRequestV1,
    BackupVerificationContextV1, CleanupReportV1, EncryptedPrivacyBackupStore, LifecycleError,
    LoadedApprovedOutputV1, MappingAccessContextV1, MappingKeySummaryV1, MappingRevisionStatusV1,
    MappingRevisionSummaryV1, PrivacyLifecycle, RetentionBindingSummaryV1, RetentionPolicyV1,
    SaveApprovedOutputV1, SensitiveMappingEntryV1, SensitiveMappingPayloadV1, VerifiedBackupV1,
    BACKUP_CRYPTO_SUITE, ENCRYPTED_BACKUP_SCHEMA_VERSION, LOGICAL_ERASURE_DISCLOSURE,
    PORTABLE_BACKUP_SCHEMA_VERSION, PRIVACY_LIFECYCLE_SCHEMA_VERSION,
    SENSITIVE_MAPPING_SCHEMA_VERSION,
};
pub use mcp_ticket::{
    McpAccessTargetV1, McpAccessTicketClaimsV1, McpAccessTicketRequestV1, McpAccessTicketStore,
    McpTicketError, McpTicketSigningKey, McpTicketVerificationContextV1, McpTransportBindingV1,
    SignedMcpAccessTicketV1, MCP_ACCESS_TICKET_PROFILE, MCP_ACCESS_TICKET_VERSION,
};
pub use protected_blob::{
    protect_local, unprotect_local, ProtectedBlobError, LOCAL_PROTECTION_SCHEME,
    MAX_PROTECTED_PLAINTEXT_BYTES,
};
pub use qualification::{
    parse_local_mineru_qualification_report, LocalMineruQualificationReportV1,
    QualificationReportError,
};
pub use receipt::{
    sha256_hex, DestinationKind, DestinationScope, ReceiptError, ReceiptSigner,
    ReceiptVerificationContext, RedactionReceiptClaims, ReviewState, SignedRedactionReceipt,
};
pub use redaction_mapping::RedactionMappingEntry;
pub use review_session::{
    HardGateViewV1, PrivacyFindingViewV1, ResidualSummaryViewV1, ReviewActionV1,
    ReviewAnalysisReplacementV1, ReviewSessionError, ReviewSessionInputV1, ReviewSessionV1,
    ReviewStateViewV1, VerifiedReviewActionContextV1, VisualRiskDecisionV1, VisualRiskResolutionV1,
    MAX_REVIEW_HISTORY, REVIEW_SESSION_SCHEMA_VERSION, REVIEW_STATE_VIEW_SCHEMA_VERSION,
};
pub use store::{
    ActiveReceiptVerification, ApproveReviewWithRiskRevision, LoadedReviewDraft,
    LoadedRiskReviewRevision, PrivacyStore, PrivacyStoreError, RegisterPrivacyMaterial,
    RiskReviewRevisionSummary, SaveReviewDraft, SaveRiskReviewRevision,
    MAX_ACTIVE_RECEIPT_TTL_SECONDS, PRIVACY_STORE_SCHEMA_VERSION,
};
pub use vault_backup::{
    export_encrypted_vault_backup, stage_encrypted_vault_backup, VaultBackupError,
    VaultBackupSummaryV1, ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION, MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES, MAX_ENCRYPTED_VAULT_BACKUP_FILES,
};
pub use vault_store::{
    fixed_local_file_identity, validate_fixed_local_directory, validate_fixed_local_regular_file,
    VaultCleanupReportV1, VaultRetentionBindingV1, VAULT_LIFECYCLE_SCHEMA_VERSION,
    VAULT_LOGICAL_ERASURE_DISCLOSURE,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const REDACTION_VERSION: &str = "lawyer-assistance-content-redaction-v3";
pub const MAX_CUSTOM_TERMS: usize = 128;
pub const MAX_CUSTOM_TERM_BYTES: usize = 256;
pub const MAX_DISCOVERED_TERMS: usize = 4_096;
pub const MAX_DISCOVERED_TERM_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    PersonName,
    OrganizationName,
    CaseName,
    MaterialName,
    CaseNumber,
    PassportNumber,
    VehiclePlate,
    IdentityNumber,
    PhoneNumber,
    EmailAddress,
    BankAccount,
    OrganizationCode,
    Address,
    Contact,
    SourceDescription,
    Custom,
}

impl SensitiveKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PersonName => "person_name",
            Self::OrganizationName => "organization_name",
            Self::CaseName => "case_name",
            Self::MaterialName => "material_name",
            Self::CaseNumber => "case_number",
            Self::PassportNumber => "passport_number",
            Self::VehiclePlate => "vehicle_plate",
            Self::IdentityNumber => "identity_number",
            Self::PhoneNumber => "phone_number",
            Self::EmailAddress => "email_address",
            Self::BankAccount => "bank_account",
            Self::OrganizationCode => "organization_code",
            Self::Address => "address",
            Self::Contact => "contact",
            Self::SourceDescription => "source_description",
            Self::Custom => "custom",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CaseNumber => "案号",
            Self::PassportNumber => "护照号",
            Self::VehiclePlate => "车牌号",
            Self::PersonName => "姓名",
            Self::OrganizationName => "机构",
            Self::CaseName => "案件",
            Self::MaterialName => "材料",
            Self::IdentityNumber => "身份证号",
            Self::PhoneNumber => "电话号码",
            Self::EmailAddress => "电子邮箱",
            Self::BankAccount => "银行账号",
            Self::OrganizationCode => "统一社会信用代码",
            Self::Address => "地址",
            Self::Contact => "联系方式",
            Self::SourceDescription => "来源",
            Self::Custom => "敏感信息",
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Custom => 0,
            Self::IdentityNumber => 1,
            Self::PassportNumber => 2,
            Self::BankAccount => 3,
            Self::OrganizationCode => 4,
            Self::CaseNumber => 5,
            Self::VehiclePlate => 6,
            Self::PhoneNumber => 7,
            Self::EmailAddress => 8,
            Self::Address => 9,
            Self::OrganizationName => 10,
            Self::PersonName => 11,
            Self::CaseName | Self::MaterialName | Self::Contact | Self::SourceDescription => 12,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionOptions {
    #[serde(default = "yes")]
    pub labelled_names: bool,
    #[serde(default = "yes")]
    pub labelled_organizations: bool,
    #[serde(default = "yes")]
    pub labelled_addresses: bool,
    #[serde(default)]
    pub custom_terms: Vec<String>,
}

const fn yes() -> bool {
    true
}

impl Default for RedactionOptions {
    fn default() -> Self {
        Self {
            labelled_names: true,
            labelled_organizations: true,
            labelled_addresses: true,
            custom_terms: Vec::new(),
        }
    }
}

impl RedactionOptions {
    pub fn validated(mut self) -> Result<Self, RedactionError> {
        if self.custom_terms.len() > MAX_CUSTOM_TERMS {
            return Err(RedactionError::TooManyCustomTerms);
        }
        for term in &mut self.custom_terms {
            *term = normalize_sensitive_text(term).trim().to_owned();
            if term.is_empty()
                || term.len() > MAX_CUSTOM_TERM_BYTES
                || term.chars().any(char::is_control)
            {
                return Err(RedactionError::InvalidCustomTerm);
            }
        }
        self.custom_terms.sort();
        self.custom_terms.dedup();
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionError {
    TooManyCustomTerms,
    InvalidCustomTerm,
    DiscoveredTermLimitExceeded,
}

impl std::fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TooManyCustomTerms => "too many custom redaction terms",
            Self::InvalidCustomTerm => "a custom redaction term is invalid",
            Self::DiscoveredTermLimitExceeded => "discovered redaction term limit exceeded",
        })
    }
}

impl std::error::Error for RedactionError {}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub total: usize,
    pub counts: BTreeMap<String, usize>,
    pub changed: bool,
    pub manual_review_required: bool,
    pub redaction_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedText {
    pub text: String,
    pub summary: RedactionSummary,
}

#[derive(Debug, Clone)]
pub struct Redactor {
    options: RedactionOptions,
    aliases: HashMap<(SensitiveKind, [u8; 32]), String>,
    ordinals: BTreeMap<SensitiveKind, usize>,
    counts: BTreeMap<SensitiveKind, usize>,
    known_terms: Vec<(String, SensitiveKind)>,
    detected_values: BTreeSet<String>,
    known_term_bytes: usize,
    discovered_term_limit_exceeded: bool,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(RedactionOptions::default())
    }
}

impl Redactor {
    pub fn new(options: RedactionOptions) -> Self {
        let known_terms = options
            .custom_terms
            .iter()
            .map(|term| (normalize_sensitive_text(term), SensitiveKind::Custom))
            .collect::<Vec<_>>();
        let known_term_bytes = known_terms.iter().map(|(term, _)| term.len()).sum();
        Self {
            known_terms,
            detected_values: BTreeSet::new(),
            known_term_bytes,
            discovered_term_limit_exceeded: false,
            options,
            aliases: HashMap::new(),
            ordinals: BTreeMap::new(),
            counts: BTreeMap::new(),
        }
    }
    pub fn try_new(options: RedactionOptions) -> Result<Self, RedactionError> {
        Ok(Self::new(options.validated()?))
    }

    /// Discover sensitive aliases without producing output, placeholders, or
    /// summary counts. Run this across every page before redacting any page so
    /// a value labelled later in a document is also removed from earlier pages.
    pub fn discover(&mut self, input: &str) -> Result<(), RedactionError> {
        for span in self.detect_spans(input) {
            if span.start < span.end
                && input.is_char_boundary(span.start)
                && input.is_char_boundary(span.end)
            {
                let sensitive = &input[span.start..span.end];
                self.mark_detected(sensitive);
                self.remember(sensitive, span.kind);
                if self.discovered_term_limit_exceeded {
                    return Err(RedactionError::DiscoveredTermLimitExceeded);
                }
            }
        }
        Ok(())
    }

    pub fn discover_across<'a>(
        &mut self,
        inputs: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), RedactionError> {
        for input in inputs {
            self.discover(input)?;
        }
        Ok(())
    }

    pub const fn discovered_term_limit_exceeded(&self) -> bool {
        self.discovered_term_limit_exceeded
    }

    pub fn redact(&mut self, input: &str) -> String {
        let spans = self.detect_spans(input);
        self.apply(input, spans)
    }

    fn detect_spans(&self, input: &str) -> Vec<Span> {
        let mut spans = self.detect_spans_raw(input);
        if let Some(view) = NormalizedView::new(input) {
            spans.extend(
                self.detect_spans_raw(&view.text)
                    .into_iter()
                    .filter_map(|span| view.map_span(span)),
            );
        }
        spans
    }

    fn detect_spans_raw(&self, input: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (term, kind) in &self.known_terms {
            add_matches(input, term, *kind, &mut spans);
        }
        find_ascii_identifiers(input, &mut spans);
        find_emails(input, &mut spans);
        if self.options.labelled_names {
            find_people(input, &mut spans);
        }
        if self.options.labelled_organizations {
            find_organizations(input, &mut spans);
        }
        if self.options.labelled_addresses {
            find_addresses(input, &mut spans);
        }
        find_labelled_identifiers_and_metadata(input, &mut spans);
        find_case_numbers(input, &mut spans);
        expand_aliases(input, &mut spans);
        spans
    }
    pub fn redact_whole(&mut self, input: &str, kind: SensitiveKind) -> String {
        if input.trim().is_empty() || is_valid_redaction_placeholder(input) {
            return input.to_owned();
        }
        self.mark_detected(input);
        self.remember(input, kind);
        self.record(kind);
        self.placeholder(kind, input)
    }

    pub fn redact_json(&mut self, value: &mut Value) {
        self.collect_structured_terms(None, value);
        self.redact_json_inner(None, value);
    }

    pub fn summary(&self) -> RedactionSummary {
        let counts = self
            .counts
            .iter()
            .map(|(kind, count)| (kind.code().to_owned(), *count))
            .collect::<BTreeMap<_, _>>();
        let total = counts.values().sum();
        RedactionSummary {
            total,
            counts,
            changed: total > 0,
            manual_review_required: true,
            redaction_version: REDACTION_VERSION.to_owned(),
        }
    }

    /// Original values that actually matched this local redaction session.
    /// Configured-but-absent custom terms are deliberately excluded so they
    /// cannot fabricate an export canary. Keep this list only in protected
    /// local review state for irreversible output scans.
    pub fn detected_sensitive_values(&self) -> Vec<String> {
        self.detected_values.iter().cloned().collect()
    }

    /// Returns an owned, deterministic snapshot of only aliases that were
    /// actually emitted during this redaction session. Configured-but-absent
    /// terms and values seen only during discovery are excluded.
    ///
    /// The returned type does not implement serialization, redacts its
    /// sensitive field from `Debug`, and zeroizes that field on drop. Callers
    /// must persist it only through the encrypted mapping lifecycle API.
    #[must_use]
    pub fn detected_alias_mappings(&self) -> Vec<RedactionMappingEntry> {
        let mut mappings = BTreeMap::new();
        for (sensitive_value, kind) in &self.known_terms {
            let detected_value = sensitive_value.trim();
            if detected_value.is_empty() || !self.detected_values.contains(detected_value) {
                continue;
            }
            let digest: [u8; 32] = Sha256::digest(sensitive_value.as_bytes()).into();
            if let Some(alias) = self.aliases.get(&(*kind, digest)) {
                mappings
                    .entry(alias.clone())
                    .or_insert_with(|| sensitive_value.clone());
            }
        }
        mappings
            .into_iter()
            .map(|(alias, sensitive_value)| RedactionMappingEntry::new(alias, sensitive_value))
            .collect()
    }

    fn apply(&mut self, input: &str, mut spans: Vec<Span>) -> String {
        spans.retain(|span| {
            span.start < span.end
                && input.is_char_boundary(span.start)
                && input.is_char_boundary(span.end)
        });
        spans.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| right.end.cmp(&left.end))
                .then_with(|| left.kind.priority().cmp(&right.kind.priority()))
        });
        let mut selected = Vec::new();
        let mut cursor = 0;
        for span in spans {
            if span.start >= cursor && !is_valid_redaction_placeholder(&input[span.start..span.end])
            {
                cursor = span.end;
                selected.push(span);
            }
        }
        if selected.is_empty() {
            return input.to_owned();
        }
        let mut output = String::with_capacity(input.len());
        cursor = 0;
        for span in selected {
            output.push_str(&input[cursor..span.start]);
            let sensitive = &input[span.start..span.end];
            output.push_str(&self.placeholder(span.kind, sensitive));
            self.mark_detected(sensitive);
            self.remember(sensitive, span.kind);
            self.record(span.kind);
            cursor = span.end;
        }
        output.push_str(&input[cursor..]);
        output
    }

    fn placeholder(&mut self, kind: SensitiveKind, sensitive: &str) -> String {
        let normalized = normalize_sensitive_text(sensitive);
        let digest: [u8; 32] = Sha256::digest(normalized.as_bytes()).into();
        if let Some(value) = self.aliases.get(&(kind, digest)) {
            return value.clone();
        }
        let ordinal = self.ordinals.entry(kind).or_insert(0);
        *ordinal += 1;
        let value = format!("[{}{}]", kind.label(), ordinal);
        self.aliases.insert((kind, digest), value.clone());
        value
    }

    fn mark_detected(&mut self, sensitive: &str) {
        let sensitive = normalize_sensitive_text(sensitive).trim().to_owned();
        if !sensitive.is_empty() && sensitive.len() <= MAX_CUSTOM_TERM_BYTES {
            self.detected_values.insert(sensitive);
        }
    }

    fn remember(&mut self, sensitive: &str, kind: SensitiveKind) {
        let sensitive = normalize_sensitive_text(sensitive);
        if sensitive.is_empty()
            || sensitive.len() > MAX_CUSTOM_TERM_BYTES
            || self
                .known_terms
                .iter()
                .any(|(value, existing)| value == &sensitive && *existing == kind)
        {
            return;
        }
        let Some(next_bytes) = self.known_term_bytes.checked_add(sensitive.len()) else {
            self.discovered_term_limit_exceeded = true;
            return;
        };
        if self.known_terms.len() >= MAX_DISCOVERED_TERMS || next_bytes > MAX_DISCOVERED_TERM_BYTES
        {
            self.discovered_term_limit_exceeded = true;
            return;
        }
        self.known_terms.push((sensitive, kind));
        self.known_term_bytes = next_bytes;
    }
    fn record(&mut self, kind: SensitiveKind) {
        *self.counts.entry(kind).or_insert(0) += 1;
    }

    fn collect_structured_terms(&mut self, key: Option<&str>, value: &Value) {
        match value {
            Value::Object(object) => {
                for (child_key, child) in object {
                    self.collect_structured_terms(Some(child_key), child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.collect_structured_terms(key, child);
                }
            }
            Value::String(text) => {
                if let Some(kind) = key.and_then(whole_field_kind) {
                    if matches!(
                        kind,
                        SensitiveKind::PersonName | SensitiveKind::OrganizationName
                    ) {
                        self.remember(text, kind);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn redact_json_inner(&mut self, key: Option<&str>, value: &mut Value) {
        match value {
            Value::Object(object) => {
                for (child_key, child) in object {
                    self.redact_json_inner(Some(child_key), child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    self.redact_json_inner(key, child);
                }
            }
            Value::String(text) => {
                *text = match key.and_then(whole_field_kind) {
                    Some(kind) => self.redact_whole(text, kind),
                    None => self.redact(text),
                };
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

pub fn redact_text(input: &str) -> RedactedText {
    let mut redactor = Redactor::default();
    let text = redactor.redact(input);
    RedactedText {
        text,
        summary: redactor.summary(),
    }
}

pub fn redact_text_with_options(
    input: &str,
    options: RedactionOptions,
) -> Result<RedactedText, RedactionError> {
    let mut redactor = Redactor::try_new(options)?;
    let text = redactor.redact(input);
    Ok(RedactedText {
        text,
        summary: redactor.summary(),
    })
}

/// Canonical form used only for sensitive-value detection, aliasing, and
/// canary comparison. It folds full-width ASCII and removes invisible format
/// controls while preserving all other visible content.
pub fn normalize_sensitive_text(input: &str) -> String {
    input
        .chars()
        .filter_map(|character| {
            if is_ignored_format_character(character) {
                None
            } else {
                Some(fold_full_width_ascii(character))
            }
        })
        .collect()
}

fn fold_full_width_ascii(character: char) -> char {
    match character {
        '\u{3000}' => ' ',
        '\u{ff01}'..='\u{ff5e}' => char::from_u32(character as u32 - 0xfee0).unwrap_or(character),
        _ => character,
    }
}

fn is_ignored_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
    )
}
fn whole_field_kind(key: &str) -> Option<SensitiveKind> {
    match key.trim().to_ascii_lowercase().as_str() {
        "当事人" | "姓名" | "当事人姓名" | "联系人姓名" | "person_name" | "party_name" => {
            Some(SensitiveKind::PersonName)
        }
        "单位名称" | "机构名称" | "公司名称" | "organization_name" => {
            Some(SensitiveKind::OrganizationName)
        }
        "案件名称" | "case_name" | "case_title" => Some(SensitiveKind::CaseName),
        "材料名称" | "原始文件名" | "material_name" | "original_name" => {
            Some(SensitiveKind::MaterialName)
        }
        "案号" | "case_number" | "docket_number" => Some(SensitiveKind::CaseNumber),
        "护照号" | "护照号码" | "passport" | "passport_number" => {
            Some(SensitiveKind::PassportNumber)
        }
        "车牌号" | "车牌号码" | "vehicle_plate" => Some(SensitiveKind::VehiclePlate),
        "联系方式" | "联系人" | "微信" | "qq" | "contact" => Some(SensitiveKind::Contact),
        "身份证号" | "证件号码" | "identity_number" | "id_number" => {
            Some(SensitiveKind::IdentityNumber)
        }
        "手机号" | "联系电话" | "电话号码" | "phone" | "phone_number" => {
            Some(SensitiveKind::PhoneNumber)
        }
        "电子邮箱" | "邮箱" | "email" => Some(SensitiveKind::EmailAddress),
        "银行卡号" | "银行账号" | "收款账号" | "bank_account" => {
            Some(SensitiveKind::BankAccount)
        }
        "统一社会信用代码" | "organization_code" => Some(SensitiveKind::OrganizationCode),
        "住址" | "地址" | "住所地" | "户籍地址" | "送达地址" | "address" => {
            Some(SensitiveKind::Address)
        }
        "事实来源" | "证据来源" | "source_description" => {
            Some(SensitiveKind::SourceDescription)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    kind: SensitiveKind,
}

#[derive(Debug)]
struct NormalizedView {
    text: String,
    original_boundaries: Vec<Option<usize>>,
}

impl NormalizedView {
    fn new(input: &str) -> Option<Self> {
        let mut text = String::with_capacity(input.len());
        let mut original_boundaries = vec![Some(0)];
        let mut changed = false;
        for (original_start, character) in input.char_indices() {
            let original_end = original_start + character.len_utf8();
            if is_ignored_format_character(character) {
                changed = true;
                original_boundaries[text.len()] = Some(original_end);
                continue;
            }
            let folded = fold_full_width_ascii(character);
            changed |= folded != character;
            let normalized_start = text.len();
            original_boundaries[normalized_start] = Some(original_start);
            text.push(folded);
            original_boundaries.resize(text.len() + 1, None);
            original_boundaries[text.len()] = Some(original_end);
        }
        changed.then_some(Self {
            text,
            original_boundaries,
        })
    }

    fn map_span(&self, span: Span) -> Option<Span> {
        let start = self
            .original_boundaries
            .get(span.start)
            .copied()
            .flatten()?;
        let end = self.original_boundaries.get(span.end).copied().flatten()?;
        (start < end).then_some(Span::new(start, end, span.kind))
    }
}
impl Span {
    const fn new(start: usize, end: usize, kind: SensitiveKind) -> Self {
        Self { start, end, kind }
    }
}

fn is_valid_redaction_placeholder(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    let Some(digit_start) = inner.find(|character: char| character.is_ascii_digit()) else {
        return false;
    };
    let (label, ordinal) = inner.split_at(digit_start);
    const LABELS: &[&str] = &[
        "案号",
        "护照号",
        "车牌号",
        "姓名",
        "机构",
        "案件",
        "材料",
        "身份证号",
        "电话号码",
        "电子邮箱",
        "银行账号",
        "统一社会信用代码",
        "地址",
        "联系方式",
        "来源",
        "敏感信息",
    ];
    LABELS.contains(&label)
        && ordinal
            .as_bytes()
            .first()
            .is_some_and(|first| matches!(first, b'1'..=b'9'))
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
}

fn add_matches(input: &str, term: &str, kind: SensitiveKind, spans: &mut Vec<Span>) {
    if term.is_empty() {
        return;
    }
    for (start, _) in input.match_indices(term) {
        spans.push(Span::new(start, start + term.len(), kind));
    }
}

fn expand_aliases(input: &str, spans: &mut Vec<Span>) {
    let aliases = spans
        .iter()
        .filter(|span| {
            span.start < span.end
                && input.is_char_boundary(span.start)
                && input.is_char_boundary(span.end)
        })
        .map(|span| (input[span.start..span.end].to_owned(), span.kind))
        .collect::<Vec<_>>();
    for (value, kind) in aliases {
        add_matches(input, &value, kind, spans);
    }
}

fn find_ascii_identifiers(input: &str, spans: &mut Vec<Span>) {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphanumeric() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
            index += 1;
        }
        let token = &input[start..index];
        let kind = if valid_identity(token) {
            Some(SensitiveKind::IdentityNumber)
        } else if valid_passport(token) {
            Some(SensitiveKind::PassportNumber)
        } else if valid_organization_code(token) {
            Some(SensitiveKind::OrganizationCode)
        } else if valid_mobile(token) {
            Some(SensitiveKind::PhoneNumber)
        } else if valid_bank_account(token) {
            Some(SensitiveKind::BankAccount)
        } else {
            None
        };
        if let Some(kind) = kind {
            spans.push(Span::new(start, index, kind));
        }
    }

    let mut start = None;
    for (index, character) in input
        .char_indices()
        .chain(std::iter::once((input.len(), '\0')))
    {
        if character.is_ascii_digit() || matches!(character, '-' | ' ' | '\u{00a0}') {
            start.get_or_insert(index);
            continue;
        }
        if let Some(token_start) = start.take() {
            let token = &input[token_start..index];
            let digits = token
                .chars()
                .filter(char::is_ascii_digit)
                .collect::<String>();
            let has_whitespace = token.chars().any(char::is_whitespace);
            if (token.contains('-') && valid_landline(&digits))
                || (has_whitespace && valid_mobile(&digits))
            {
                spans.push(Span::new(token_start, index, SensitiveKind::PhoneNumber));
            } else if has_whitespace && valid_bank_account(&digits) {
                spans.push(Span::new(token_start, index, SensitiveKind::BankAccount));
            }
        }
    }
}

fn find_case_numbers(input: &str, spans: &mut Vec<Span>) {
    for (start, opening) in input.char_indices() {
        let expected_close = match opening {
            '(' => ')',
            '\u{ff08}' => '\u{ff09}',
            _ => continue,
        };
        let after_open = start + opening.len_utf8();
        let Some(close_relative) = input[after_open..].find(expected_close) else {
            continue;
        };
        let close = after_open + close_relative;
        let year = &input[after_open..close];
        if year.len() != 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let body_start = close + expected_close.len_utf8();
        let mut has_digit = false;
        let mut has_case_marker = false;
        let mut end = None;
        for (count, (offset, character)) in input[body_start..].char_indices().enumerate() {
            if count >= 48
                || character.is_whitespace()
                || matches!(
                    character,
                    ',' | '.' | ':' | ';' | '\n' | '\r' | '\u{ff0c}' | '\u{3002}' | '\u{ff1b}'
                )
            {
                break;
            }
            if character == '\u{53f7}' {
                end = Some(body_start + offset + character.len_utf8());
                break;
            }
            has_digit |= character.is_ascii_digit();
            has_case_marker |= matches!(
                character,
                '\u{6c11}'
                    | '\u{5211}'
                    | '\u{884c}'
                    | '\u{6267}'
                    | '\u{8d54}'
                    | '\u{77e5}'
                    | '\u{5546}'
                    | '\u{7834}'
                    | '\u{7533}'
                    | '\u{518d}'
                    | '\u{6297}'
                    | '\u{4fdd}'
                    | '\u{8d22}'
            );
        }
        if has_digit && has_case_marker {
            if let Some(end) = end {
                spans.push(Span::new(start, end, SensitiveKind::CaseNumber));
            }
        }
    }
}

fn find_emails(input: &str, spans: &mut Vec<Span>) {
    let bytes = input.as_bytes();
    for at in bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'@').then_some(index))
    {
        let mut start = at;
        while start > 0 && email_local(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len() && email_domain(bytes[end]) {
            end += 1;
        }
        let domain = input[start..end]
            .split_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or_default();
        if start < at
            && end > at + 1
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
        {
            spans.push(Span::new(start, end, SensitiveKind::EmailAddress));
        }
    }
}

fn email_local(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn email_domain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn find_people(input: &str, spans: &mut Vec<Span>) {
    for label in [
        "姓名",
        "原告",
        "被告",
        "申请人",
        "被申请人",
        "上诉人",
        "被上诉人",
        "联系人",
        "法定代表人",
        "负责人",
        "委托诉讼代理人",
        "收款人",
        "付款人",
        "户名",
    ] {
        find_han_field(input, label, true, 8, SensitiveKind::PersonName, spans);
    }
    for label in ["原告", "被告", "申请人", "被申请人", "上诉人", "被上诉人"] {
        find_han_field(input, label, false, 4, SensitiveKind::PersonName, spans);
    }
    // The explicit label is the confidence signal. Capture the complete field
    // so ethnic-minority, transliterated and foreign names are not silently
    // dropped by the narrower Han-name heuristic above.
    for label in [
        "姓名",
        "当事人姓名",
        "原告",
        "被告",
        "申请人",
        "被申请人",
        "上诉人",
        "被上诉人",
        "联系人",
        "法定代表人",
        "负责人",
        "委托诉讼代理人",
        "收款人",
        "付款人",
        "户名",
    ] {
        find_colon_field(input, label, SensitiveKind::PersonName, 64, spans);
    }
}

fn find_organizations(input: &str, spans: &mut Vec<Span>) {
    for label in [
        "单位名称",
        "公司名称",
        "机构名称",
        "原告",
        "被告",
        "申请人",
        "被申请人",
    ] {
        let mut search = 0;
        while let Some(relative) = input[search..].find(label) {
            let label_end = search + relative + label.len();
            let (start, _) = separator_end(input, label_end);
            let end = take_organization(input, start);
            if end > start && organization_suffix(&input[start..end]) {
                spans.push(Span::new(start, end, SensitiveKind::OrganizationName));
            }
            search = label_end;
        }
    }
    // Party-role labels may name a person or an organization, so only the
    // unambiguous organization labels use conservative whole-field capture.
    for label in ["单位名称", "公司名称", "机构名称"] {
        find_colon_field(input, label, SensitiveKind::OrganizationName, 128, spans);
    }
}

fn find_addresses(input: &str, spans: &mut Vec<Span>) {
    for label in [
        "住址",
        "地址",
        "住所地",
        "户籍地址",
        "送达地址",
        "经常居住地",
    ] {
        find_colon_field(input, label, SensitiveKind::Address, 128, spans);
    }
}

fn find_labelled_identifiers_and_metadata(input: &str, spans: &mut Vec<Span>) {
    for (labels, kind, max_chars) in [
        (
            &["身份证号", "身份证号码", "证件号码", "证件号"][..],
            SensitiveKind::IdentityNumber,
            64,
        ),
        (
            &["手机号", "手机号码", "联系电话", "电话号码", "电话"][..],
            SensitiveKind::PhoneNumber,
            64,
        ),
        (
            &["电子邮箱", "邮箱", "电子邮件"][..],
            SensitiveKind::EmailAddress,
            128,
        ),
        (
            &["银行卡号", "银行账号", "收款账号", "付款账号", "账户"][..],
            SensitiveKind::BankAccount,
            128,
        ),
        (
            &["统一社会信用代码", "组织机构代码"][..],
            SensitiveKind::OrganizationCode,
            64,
        ),
        (
            &["护照号", "护照号码"][..],
            SensitiveKind::PassportNumber,
            64,
        ),
        (&["车牌号", "车牌号码"][..], SensitiveKind::VehiclePlate, 32),
        (&["案号", "案件编号"][..], SensitiveKind::CaseNumber, 96),
        (
            &["微信号", "微信", "QQ号", "QQ"][..],
            SensitiveKind::Contact,
            128,
        ),
        (&["案件名称", "案由名称"][..], SensitiveKind::CaseName, 256),
        (
            &["材料名称", "文件名称", "原始文件名"][..],
            SensitiveKind::MaterialName,
            256,
        ),
        (
            &["事实来源", "证据来源"][..],
            SensitiveKind::SourceDescription,
            256,
        ),
    ] {
        for label in labels {
            find_colon_field(input, label, kind, max_chars, spans);
        }
    }
}

fn find_han_field(
    input: &str,
    label: &str,
    require_colon: bool,
    max_chars: usize,
    kind: SensitiveKind,
    spans: &mut Vec<Span>,
) {
    let mut search = 0;
    while let Some(relative) = input[search..].find(label) {
        let label_end = search + relative + label.len();
        let (start, colon) = separator_end(input, label_end);
        if require_colon && !colon {
            search = label_end;
            continue;
        }
        let mut end = start;
        let mut count = 0;
        for (offset, character) in input[start..].char_indices() {
            if (is_han(character) || matches!(character, '·' | '•')) && count < max_chars {
                count += 1;
                end = start + offset + character.len_utf8();
            } else {
                break;
            }
        }
        let boundary =
            end == input.len() || input[end..].chars().next().is_some_and(value_boundary);
        if (2..=max_chars).contains(&count) && boundary {
            spans.push(Span::new(start, end, kind));
        }
        search = label_end;
    }
}

fn find_colon_field(
    input: &str,
    label: &str,
    kind: SensitiveKind,
    max_chars: usize,
    spans: &mut Vec<Span>,
) {
    let mut search = 0;
    while let Some(relative) = input[search..].find(label) {
        let label_end = search + relative + label.len();
        let (start, colon) = separator_end(input, label_end);
        if !colon {
            search = label_end;
            continue;
        }
        let mut end = start;
        let mut count = 0;
        for (offset, character) in input[start..].char_indices() {
            if field_end(character) || count >= max_chars {
                break;
            }
            count += 1;
            end = start + offset + character.len_utf8();
        }
        while end > start {
            let Some(character) = input[start..end].chars().next_back() else {
                break;
            };
            if character.is_whitespace() {
                end -= character.len_utf8();
            } else {
                break;
            }
        }
        if count >= 2 && end > start {
            spans.push(Span::new(start, end, kind));
        }
        search = label_end;
    }
}

fn separator_end(input: &str, mut index: usize) -> (usize, bool) {
    while let Some(character) = input[index..].chars().next() {
        if !character.is_whitespace() {
            break;
        }
        index += character.len_utf8();
    }
    let colon = input[index..]
        .chars()
        .next()
        .is_some_and(|character| matches!(character, ':' | '：'));
    if colon {
        if let Some(character) = input[index..].chars().next() {
            index += character.len_utf8();
        }
        while let Some(character) = input[index..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            index += character.len_utf8();
        }
    }
    (index, colon)
}

fn take_organization(input: &str, start: usize) -> usize {
    let mut end = start;
    let mut count = 0;
    for (offset, character) in input[start..].char_indices() {
        if (is_han(character)
            || character.is_ascii_alphanumeric()
            || matches!(character, '（' | '）' | '(' | ')' | '·'))
            && count < 48
        {
            count += 1;
            end = start + offset + character.len_utf8();
        } else {
            break;
        }
    }
    end
}

fn is_han(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF
    )
}

fn value_boundary(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            ',' | '，' | '。' | ';' | '；' | ':' | '：' | '、' | '(' | ')' | '（' | '）' | '诉'
        )
}

fn field_end(character: char) -> bool {
    matches!(character, '\n' | '\r' | ',' | '，' | '。' | ';' | '；')
}

fn organization_suffix(value: &str) -> bool {
    [
        "公司",
        "事务所",
        "中心",
        "银行",
        "委员会",
        "机关",
        "单位",
        "医院",
        "学校",
        "集团",
        "合作社",
    ]
    .iter()
    .any(|suffix| value.ends_with(suffix))
}

fn valid_passport(value: &str) -> bool {
    if value.len() != 9 {
        return false;
    }
    let bytes = value.as_bytes();
    matches!(
        bytes[0].to_ascii_uppercase(),
        b'E' | b'G' | b'D' | b'S' | b'P' | b'H'
    ) && bytes[1..].iter().all(|byte| byte.is_ascii_digit())
}

fn valid_mobile(value: &str) -> bool {
    value.len() == 11
        && value.as_bytes()[0] == b'1'
        && matches!(value.as_bytes()[1], b'3'..=b'9')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_landline(value: &str) -> bool {
    matches!(value.len(), 10..=12)
        && value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_bank_account(value: &str) -> bool {
    if !(16..=19).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let parity = value.len() % 2;
    for (index, byte) in value.bytes().enumerate() {
        let mut digit = u32::from(byte - b'0');
        if index % 2 == parity {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

fn valid_identity(value: &str) -> bool {
    if value.len() == 15 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return valid_date(&value[6..12], true);
    }
    if value.len() != 18 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[..17].iter().all(|byte| byte.is_ascii_digit())
        || !(bytes[17].is_ascii_digit() || matches!(bytes[17], b'X' | b'x'))
        || !valid_date(&value[6..14], false)
    {
        return false;
    }
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECKS: [u8; 11] = *b"10X98765432";
    let sum = bytes[..17]
        .iter()
        .zip(WEIGHTS)
        .map(|(byte, weight)| u32::from(*byte - b'0') * weight)
        .sum::<u32>();
    bytes[17].to_ascii_uppercase() == CHECKS[(sum % 11) as usize]
}

fn valid_date(value: &str, short: bool) -> bool {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let (year, month_at, day_at) = if short {
        (1900 + digits(&value[..2]), 2, 4)
    } else {
        (digits(&value[..4]), 4, 6)
    };
    let month = digits(&value[month_at..month_at + 2]);
    let day = digits(&value[day_at..day_at + 2]);
    if !(1900..=2099).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=max_day).contains(&day)
}

fn digits(value: &str) -> u32 {
    value
        .bytes()
        .fold(0, |number, byte| number * 10 + u32::from(byte - b'0'))
}

fn valid_organization_code(value: &str) -> bool {
    if value.len() != 18 {
        return false;
    }
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRTUWXY";
    const WEIGHTS: [u32; 17] = [
        1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
    ];
    let bytes = value.as_bytes();
    let mut sum = 0u32;
    for (byte, weight) in bytes[..17].iter().zip(WEIGHTS) {
        let upper = byte.to_ascii_uppercase();
        let Some(position) = ALPHABET.iter().position(|candidate| *candidate == upper) else {
            return false;
        };
        sum += position as u32 * weight;
    }
    let expected = ALPHABET[((31 - sum % 31) % 31) as usize];
    bytes[17].to_ascii_uppercase() == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_identifiers_but_preserves_dates_and_articles() {
        let input = "身份证号：11010519491231002X，手机13800138000，邮箱zhang.san@example.com，银行卡4532015112830366；日期2025-07-18，第577条。";
        let result = redact_text(input);
        assert!(!result.text.contains("11010519491231002X"));
        assert!(!result.text.contains("13800138000"));
        assert!(!result.text.contains("zhang.san@example.com"));
        assert!(!result.text.contains("4532015112830366"));
        assert!(result.text.contains("2025-07-18"));
        assert!(result.text.contains("第577条"));
        assert_eq!(result.summary.total, 4);
    }

    #[test]
    fn redacts_legal_case_numbers_passports_and_labelled_vehicle_plates() {
        let input = "案号：（2024）京0105民初1234号，护照号：E12345678，车牌号：京A12345";
        let result = redact_text(input);
        assert!(!result.text.contains("民初1234号"));
        assert!(!result.text.contains("E12345678"));
        assert!(!result.text.contains("京A12345"));
        assert_eq!(result.summary.counts.get("case_number"), Some(&1));
        assert_eq!(result.summary.counts.get("passport_number"), Some(&1));
        assert_eq!(result.summary.counts.get("vehicle_plate"), Some(&1));
    }

    #[test]
    fn explicit_high_risk_labels_cover_noncanonical_values_and_diverse_names() {
        let input = concat!(
            "原告：阿卜杜·热合曼；",
            "被告：John Smith；",
            "联系电话：01012345678；",
            "银行账号：123456789012345678；",
            "身份证号：110105 19491231 002X；",
            "证件号码：110lO5I949I23IOO2X。"
        );
        let result = redact_text(input);
        for value in [
            "阿卜杜·热合曼",
            "John Smith",
            "01012345678",
            "123456789012345678",
            "110105 19491231 002X",
            "110lO5I949I23IOO2X",
        ] {
            assert!(
                !result.text.contains(value),
                "labelled value leaked: {value}"
            );
        }
        assert_eq!(result.summary.counts.get("person_name"), Some(&2));
        assert_eq!(result.summary.counts.get("phone_number"), Some(&1));
        assert_eq!(result.summary.counts.get("bank_account"), Some(&1));
        assert_eq!(result.summary.counts.get("identity_number"), Some(&2));
    }

    #[test]
    fn labels_and_custom_terms_use_stable_pseudonyms() {
        let options = RedactionOptions {
            custom_terms: vec!["海淀秘密项目".to_owned()],
            ..RedactionOptions::default()
        };
        let result = redact_text_with_options(
            "原告：张三，被告李四；住址：北京市海淀区某路1号。张三参与海淀秘密项目。",
            options,
        )
        .expect("valid options");
        assert!(!result.text.contains("张三"));
        assert!(!result.text.contains("李四"));
        assert!(!result.text.contains("北京市海淀区某路1号"));
        assert!(!result.text.contains("海淀秘密项目"));
        assert_eq!(result.text.matches("[姓名1]").count(), 2);
        assert!(result.summary.manual_review_required);
    }

    #[test]
    fn discover_across_pages_redacts_earlier_unlabelled_alias_without_counting_discovery() {
        let pages = ["张三向法院提交证据。", "原告：张三，联系电话13800138000。"];
        let mut redactor = Redactor::default();
        redactor
            .discover_across(pages.iter().copied())
            .expect("bounded discovery");
        assert_eq!(redactor.summary().total, 0);

        let first = redactor.redact(pages[0]);
        let second = redactor.redact(pages[1]);
        assert!(!first.contains("张三"));
        assert!(!second.contains("张三"));
        assert!(!second.contains("13800138000"));
        assert_eq!(first.matches("[姓名1]").count(), 1);
        assert_eq!(second.matches("[姓名1]").count(), 1);
        assert_eq!(redactor.summary().total, 3);
    }

    #[test]
    fn discovered_terms_are_strictly_bounded_and_fail_closed() {
        let mut redactor = Redactor::default();
        for index in 0..MAX_DISCOVERED_TERMS {
            redactor.remember(&format!("term-{index}"), SensitiveKind::Custom);
        }
        assert!(!redactor.discovered_term_limit_exceeded());
        redactor.remember("one-term-too-many", SensitiveKind::Custom);
        assert!(redactor.discovered_term_limit_exceeded());
        assert_eq!(
            redactor.discover("原告：张三"),
            Err(RedactionError::DiscoveredTermLimitExceeded)
        );
        assert_eq!(redactor.known_terms.len(), MAX_DISCOVERED_TERMS);
        assert_eq!(
            redactor.detected_sensitive_values(),
            vec!["张三".to_owned()]
        );
    }
    #[test]
    fn absent_custom_term_cannot_fabricate_a_detected_canary() {
        let mut redactor = Redactor::try_new(RedactionOptions {
            custom_terms: vec!["完全不存在于原文的词".to_owned()],
            ..RedactionOptions::default()
        })
        .expect("valid custom term");
        let input = "张三今天到庭";
        redactor.discover(input).expect("discovery");
        assert_eq!(redactor.redact(input), input);
        assert!(redactor.detected_sensitive_values().is_empty());
    }

    #[test]
    fn matched_custom_and_detected_label_values_become_canaries() {
        let mut redactor = Redactor::try_new(RedactionOptions {
            custom_terms: vec!["实际秘密项目".to_owned(), "不存在的项目".to_owned()],
            ..RedactionOptions::default()
        })
        .expect("valid custom terms");
        let input = "原告：张三，备注：实际秘密项目。";
        redactor.discover(input).expect("discovery");
        let _ = redactor.redact(input);
        let values = redactor.detected_sensitive_values();
        assert!(values.contains(&"张三".to_owned()));
        assert!(values.contains(&"实际秘密项目".to_owned()));
        assert!(!values.contains(&"不存在的项目".to_owned()));
    }

    #[test]
    fn full_width_identifiers_and_zero_width_aliases_cannot_bypass_detection() {
        let input = "原告：张\u{200b}三，手机号：１３８００１３８０００，身份证号：１１０１０５１９４９１２３１００２Ｘ。张三到庭。";
        let result = redact_text(input);
        assert!(!result.text.contains("张\u{200b}三"));
        assert!(!result.text.contains("张三"));
        assert!(!result.text.contains("１３８００１３８０００"));
        assert!(!result.text.contains("１１０１０５１９４９１２３１００２Ｘ"));
        assert_eq!(result.text.matches("[姓名1]").count(), 2);
        assert_eq!(result.summary.counts.get("phone_number"), Some(&1));
        assert_eq!(result.summary.counts.get("identity_number"), Some(&1));
    }
    #[test]
    fn semantic_json_keys_mask_structured_case_fields() {
        let mut value = json!({
            "案件名称":"张三诉李四借款纠纷",
            "当事人":[{"当事人":"张三","联系方式":"微信zhangsan","事实来源":"张三陈述"}],
            "事实内容":"张三于2025年收款。",
            "法律名称":"中华人民共和国民法典"
        });
        let mut redactor = Redactor::default();
        redactor.redact_json(&mut value);
        let wire = serde_json::to_string(&value).expect("JSON serializes");
        assert!(!wire.contains("张三"));
        assert!(!wire.contains("李四借款纠纷"));
        assert!(!wire.contains("微信zhangsan"));
        assert!(wire.contains("中华人民共和国民法典"));
    }

    #[test]
    fn redaction_output_is_idempotent_but_malformed_placeholders_are_not_trusted() {
        let original = "原告：张三，联系电话：13800138000，单位名称：北京某某科技有限公司。";
        let once = redact_text(original);
        let twice = redact_text(&once.text);
        assert_eq!(twice.text, once.text);
        assert_eq!(twice.summary.total, 0);

        for malformed in ["[姓名0]", "[姓名01]", "[未知1]", "[姓名1]张三"] {
            let result = redact_text(&format!("原告：{malformed}。"));
            assert!(
                result.summary.total > 0,
                "malformed placeholder accepted: {malformed}"
            );
        }
    }

    #[test]
    fn invalid_custom_terms_fail_closed() {
        assert_eq!(
            RedactionOptions {
                custom_terms: vec![String::new()],
                ..RedactionOptions::default()
            }
            .validated(),
            Err(RedactionError::InvalidCustomTerm)
        );
    }
}
