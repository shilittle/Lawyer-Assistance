use crate::{ContractError, ContractErrorType};
use serde::{Deserialize, Serialize};

pub const MAX_TOOL_CALLS_PER_RUN: usize = 8;
pub const MAX_PROVIDER_ROUND_TRIPS_PER_RUN: usize = 2;
pub const MAX_INPUT_BODY_BYTES_PER_RUN: usize = 2 * 1024 * 1024;
pub const MAX_MODEL_VISIBLE_ATTACHMENTS_PER_RUN: usize = 2;
pub const MAX_MODEL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub const CAPABILITY_COUNT: usize = 10;
pub const MAX_CAPABILITY_VERSION_BYTES: usize = 16;
pub const MAX_AUDIT_FIELDS_PER_CAPABILITY: usize = 16;
pub const MAX_ALLOWED_ERRORS_PER_CAPABILITY: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityName {
    #[serde(rename = "legal.search")]
    LegalSearch,
    #[serde(rename = "legal.read")]
    LegalRead,
    #[serde(rename = "file.import")]
    FileImport,
    #[serde(rename = "file.extract")]
    FileExtract,
    #[serde(rename = "case.read")]
    CaseRead,
    #[serde(rename = "case.propose_changes")]
    CaseProposeChanges,
    #[serde(rename = "case.apply_changes")]
    CaseApplyChanges,
    #[serde(rename = "document.draft")]
    DocumentDraft,
    #[serde(rename = "document.render")]
    DocumentRender,
    #[serde(rename = "map.build")]
    MapBuild,
}

impl CapabilityName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegalSearch => "legal.search",
            Self::LegalRead => "legal.read",
            Self::FileImport => "file.import",
            Self::FileExtract => "file.extract",
            Self::CaseRead => "case.read",
            Self::CaseProposeChanges => "case.propose_changes",
            Self::CaseApplyChanges => "case.apply_changes",
            Self::DocumentDraft => "document.draft",
            Self::DocumentRender => "document.render",
            Self::MapBuild => "map.build",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAccess {
    pub read: bool,
    pub write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityErrorType {
    InvalidInput,
    NotFound,
    PermissionDenied,
    LimitExceeded,
    Cancelled,
    Conflict,
    Unsupported,
    ProviderFailure,
    CitationValidationFailed,
    ConfirmationRequired,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditField {
    RequestId,
    RunId,
    Capability,
    InputIds,
    InputHashes,
    InputCounts,
    OutputIds,
    OutputCounts,
    SourceRefs,
    ProviderSnapshot,
    Status,
    Timing,
    ErrorType,
    Confirmation,
}

/// Immutable whitelist entry exposed to the application orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescriptor {
    pub name: CapabilityName,
    pub version: &'static str,
    pub access: CapabilityAccess,
    pub requires_user_confirmation: bool,
    pub cancellable: bool,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_calls_per_run: usize,
    pub allowed_error_types: &'static [CapabilityErrorType],
    pub audit_fields: &'static [AuditField],
}

impl CapabilityDescriptor {
    pub fn validate_call(
        &self,
        input_bytes: usize,
        output_bytes: usize,
        calls_for_capability: usize,
        user_confirmed: bool,
    ) -> Result<(), ContractError> {
        check_limit("capability.inputBytes", input_bytes, self.max_input_bytes)?;
        check_limit(
            "capability.outputBytes",
            output_bytes,
            self.max_output_bytes,
        )?;
        check_limit(
            "capability.callsPerRun",
            calls_for_capability,
            self.max_calls_per_run,
        )?;
        if self.requires_user_confirmation && !user_confirmed {
            return Err(ContractError::new(
                ContractErrorType::ConfirmationRequired,
                "capability.userConfirmation",
                "capability requires explicit user confirmation",
            ));
        }
        Ok(())
    }
}

const COMMON_ERRORS: &[CapabilityErrorType] = &[
    CapabilityErrorType::InvalidInput,
    CapabilityErrorType::LimitExceeded,
    CapabilityErrorType::Cancelled,
    CapabilityErrorType::Internal,
];
const READ_ERRORS: &[CapabilityErrorType] = &[
    CapabilityErrorType::InvalidInput,
    CapabilityErrorType::NotFound,
    CapabilityErrorType::PermissionDenied,
    CapabilityErrorType::LimitExceeded,
    CapabilityErrorType::Cancelled,
    CapabilityErrorType::Internal,
];
const LEGAL_ERRORS: &[CapabilityErrorType] = &[
    CapabilityErrorType::InvalidInput,
    CapabilityErrorType::NotFound,
    CapabilityErrorType::LimitExceeded,
    CapabilityErrorType::Cancelled,
    CapabilityErrorType::CitationValidationFailed,
    CapabilityErrorType::Internal,
];
const WRITE_ERRORS: &[CapabilityErrorType] = &[
    CapabilityErrorType::InvalidInput,
    CapabilityErrorType::NotFound,
    CapabilityErrorType::PermissionDenied,
    CapabilityErrorType::LimitExceeded,
    CapabilityErrorType::Cancelled,
    CapabilityErrorType::Conflict,
    CapabilityErrorType::Internal,
];
const APPLY_ERRORS: &[CapabilityErrorType] = &[
    CapabilityErrorType::InvalidInput,
    CapabilityErrorType::NotFound,
    CapabilityErrorType::PermissionDenied,
    CapabilityErrorType::LimitExceeded,
    CapabilityErrorType::Conflict,
    CapabilityErrorType::ConfirmationRequired,
    CapabilityErrorType::Internal,
];

const READ_AUDIT: &[AuditField] = &[
    AuditField::RequestId,
    AuditField::RunId,
    AuditField::Capability,
    AuditField::InputIds,
    AuditField::InputCounts,
    AuditField::OutputIds,
    AuditField::OutputCounts,
    AuditField::SourceRefs,
    AuditField::Status,
    AuditField::Timing,
    AuditField::ErrorType,
];
const FILE_AUDIT: &[AuditField] = &[
    AuditField::RequestId,
    AuditField::RunId,
    AuditField::Capability,
    AuditField::InputIds,
    AuditField::InputHashes,
    AuditField::InputCounts,
    AuditField::OutputIds,
    AuditField::OutputCounts,
    AuditField::Status,
    AuditField::Timing,
    AuditField::ErrorType,
];
const MODEL_AUDIT: &[AuditField] = &[
    AuditField::RequestId,
    AuditField::RunId,
    AuditField::Capability,
    AuditField::InputIds,
    AuditField::InputCounts,
    AuditField::OutputIds,
    AuditField::OutputCounts,
    AuditField::SourceRefs,
    AuditField::ProviderSnapshot,
    AuditField::Status,
    AuditField::Timing,
    AuditField::ErrorType,
];
const APPLY_AUDIT: &[AuditField] = &[
    AuditField::RequestId,
    AuditField::RunId,
    AuditField::Capability,
    AuditField::InputIds,
    AuditField::InputCounts,
    AuditField::OutputIds,
    AuditField::OutputCounts,
    AuditField::SourceRefs,
    AuditField::Confirmation,
    AuditField::Status,
    AuditField::Timing,
    AuditField::ErrorType,
];

const READ_ONLY: CapabilityAccess = CapabilityAccess {
    read: true,
    write: false,
};
const READ_WRITE: CapabilityAccess = CapabilityAccess {
    read: true,
    write: true,
};

pub static CAPABILITY_REGISTRY: [CapabilityDescriptor; CAPABILITY_COUNT] = [
    descriptor(
        CapabilityName::LegalSearch,
        READ_ONLY,
        false,
        limits(2, 64 * 1024, 512 * 1024),
        LEGAL_ERRORS,
        READ_AUDIT,
    ),
    descriptor(
        CapabilityName::LegalRead,
        READ_ONLY,
        false,
        limits(3, 16 * 1024, 1024 * 1024),
        LEGAL_ERRORS,
        READ_AUDIT,
    ),
    descriptor(
        CapabilityName::FileImport,
        READ_WRITE,
        false,
        limits(2, 8 * 1024, 16 * 1024),
        WRITE_ERRORS,
        FILE_AUDIT,
    ),
    descriptor(
        CapabilityName::FileExtract,
        READ_ONLY,
        false,
        limits(2, 16 * 1024, 1024 * 1024),
        READ_ERRORS,
        FILE_AUDIT,
    ),
    descriptor(
        CapabilityName::CaseRead,
        READ_ONLY,
        false,
        limits(1, 16 * 1024, 1024 * 1024),
        READ_ERRORS,
        READ_AUDIT,
    ),
    descriptor(
        CapabilityName::CaseProposeChanges,
        READ_WRITE,
        false,
        limits(1, 1024 * 1024, 512 * 1024),
        WRITE_ERRORS,
        MODEL_AUDIT,
    ),
    descriptor(
        CapabilityName::CaseApplyChanges,
        READ_WRITE,
        true,
        limits(1, 512 * 1024, 64 * 1024),
        APPLY_ERRORS,
        APPLY_AUDIT,
    ),
    descriptor(
        CapabilityName::DocumentDraft,
        READ_WRITE,
        false,
        limits(1, 1024 * 1024, MAX_MODEL_RESPONSE_BYTES),
        COMMON_ERRORS,
        MODEL_AUDIT,
    ),
    descriptor(
        CapabilityName::DocumentRender,
        READ_WRITE,
        false,
        limits(1, MAX_MODEL_RESPONSE_BYTES, MAX_MODEL_RESPONSE_BYTES),
        WRITE_ERRORS,
        MODEL_AUDIT,
    ),
    descriptor(
        CapabilityName::MapBuild,
        READ_WRITE,
        false,
        limits(1, MAX_MODEL_RESPONSE_BYTES, MAX_MODEL_RESPONSE_BYTES),
        COMMON_ERRORS,
        MODEL_AUDIT,
    ),
];

#[derive(Debug, Clone, Copy)]
struct CapabilityLimits {
    max_calls_per_run: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

const fn limits(
    max_calls_per_run: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
) -> CapabilityLimits {
    CapabilityLimits {
        max_calls_per_run,
        max_input_bytes,
        max_output_bytes,
    }
}

const fn descriptor(
    name: CapabilityName,
    access: CapabilityAccess,
    requires_user_confirmation: bool,
    limits: CapabilityLimits,
    allowed_error_types: &'static [CapabilityErrorType],
    audit_fields: &'static [AuditField],
) -> CapabilityDescriptor {
    CapabilityDescriptor {
        name,
        version: "1.0.0",
        access,
        requires_user_confirmation,
        cancellable: true,
        max_input_bytes: limits.max_input_bytes,
        max_output_bytes: limits.max_output_bytes,
        max_calls_per_run: limits.max_calls_per_run,
        allowed_error_types,
        audit_fields,
    }
}

pub fn capability_registry() -> &'static [CapabilityDescriptor; CAPABILITY_COUNT] {
    &CAPABILITY_REGISTRY
}

pub fn find_capability(name: &str) -> Result<&'static CapabilityDescriptor, ContractError> {
    CAPABILITY_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name.as_str() == name)
        .ok_or_else(|| {
            ContractError::new(
                ContractErrorType::UnknownCapability,
                "capability.name",
                "capability is not present in the fixed registry",
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunBudget {
    pub max_tool_calls: usize,
    pub max_provider_round_trips: usize,
    pub max_input_body_bytes: usize,
    pub max_visible_attachments: usize,
    pub max_model_response_bytes: usize,
}

pub const DEFAULT_RUN_BUDGET: RunBudget = RunBudget {
    max_tool_calls: MAX_TOOL_CALLS_PER_RUN,
    max_provider_round_trips: MAX_PROVIDER_ROUND_TRIPS_PER_RUN,
    max_input_body_bytes: MAX_INPUT_BODY_BYTES_PER_RUN,
    max_visible_attachments: MAX_MODEL_VISIBLE_ATTACHMENTS_PER_RUN,
    max_model_response_bytes: MAX_MODEL_RESPONSE_BYTES,
};

impl Default for RunBudget {
    fn default() -> Self {
        DEFAULT_RUN_BUDGET
    }
}

impl RunBudget {
    /// Budgets are caller-reducible but may never exceed the hard product cap.
    pub fn validate(&self) -> Result<(), ContractError> {
        check_positive_and_limit(
            "budget.maxToolCalls",
            self.max_tool_calls,
            MAX_TOOL_CALLS_PER_RUN,
        )?;
        check_positive_and_limit(
            "budget.maxProviderRoundTrips",
            self.max_provider_round_trips,
            MAX_PROVIDER_ROUND_TRIPS_PER_RUN,
        )?;
        check_positive_and_limit(
            "budget.maxInputBodyBytes",
            self.max_input_body_bytes,
            MAX_INPUT_BODY_BYTES_PER_RUN,
        )?;
        check_positive_and_limit(
            "budget.maxVisibleAttachments",
            self.max_visible_attachments,
            MAX_MODEL_VISIBLE_ATTACHMENTS_PER_RUN,
        )?;
        check_positive_and_limit(
            "budget.maxModelResponseBytes",
            self.max_model_response_bytes,
            MAX_MODEL_RESPONSE_BYTES,
        )?;
        Ok(())
    }

    pub fn check_usage(&self, usage: &RunBudgetUsage) -> Result<(), ContractError> {
        self.validate()?;
        check_limit("usage.toolCalls", usage.tool_calls, self.max_tool_calls)?;
        check_limit(
            "usage.providerRoundTrips",
            usage.provider_round_trips,
            self.max_provider_round_trips,
        )?;
        check_limit(
            "usage.inputBodyBytes",
            usage.input_body_bytes,
            self.max_input_body_bytes,
        )?;
        check_limit(
            "usage.visibleAttachments",
            usage.visible_attachments,
            self.max_visible_attachments,
        )?;
        check_limit(
            "usage.modelResponseBytes",
            usage.model_response_bytes,
            self.max_model_response_bytes,
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunBudgetUsage {
    pub tool_calls: usize,
    pub provider_round_trips: usize,
    pub input_body_bytes: usize,
    pub visible_attachments: usize,
    pub model_response_bytes: usize,
}

fn check_positive_and_limit(path: &str, actual: usize, limit: usize) -> Result<(), ContractError> {
    if actual == 0 {
        return Err(ContractError::new(
            ContractErrorType::BudgetExceeded,
            path,
            "budget limit must be positive",
        ));
    }
    check_limit(path, actual, limit)
}

fn check_limit(path: &str, actual: usize, limit: usize) -> Result<(), ContractError> {
    if actual > limit {
        Err(ContractError::limit(
            ContractErrorType::BudgetExceeded,
            path,
            "budget limit exceeded",
            limit,
            actual,
        ))
    } else {
        Ok(())
    }
}
