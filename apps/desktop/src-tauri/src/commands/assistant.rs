use assistant::{CapabilityDescriptor, RunBudget};
use domain::qa::{CitationInvalidReason, CitationStatus, LegalSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};
use tauri::State;
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::state::AppState;

const MAX_ASSISTANT_ID_BYTES: usize = 128;
const MAX_CONVERSATION_TITLE_BYTES: usize = 256;
const MAX_CONVERSATION_LIST_LIMIT: u32 = 100;
const MAX_FILES_PER_IMPORT: usize = 2;
const MAX_RUN_ID_BYTES: usize = 128;
const ARTIFACT_EXPORT_MARKER_PREFIX: &str = "pending-assistant-artifact-export-";
const ARTIFACT_EXPORT_STAGING_PREFIX: &str = ".lawyer-assistance-artifact-export-";
const MAX_ARTIFACT_EXPORT_MARKER_BYTES: u64 = 64 * 1024;
const MAX_RECOVERABLE_ARTIFACT_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantIpcError {
    pub error_type: String,
    pub message: String,
}

impl AssistantIpcError {
    pub(crate) fn new(error_type: &str, message: impl AsRef<str>) -> Self {
        let error_type = error_type
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
            .take(64)
            .collect::<String>();
        Self {
            error_type: if error_type.is_empty() {
                "internal".to_owned()
            } else {
                error_type
            },
            message: providers::redact_sensitive(message.as_ref()),
        }
    }

    pub(super) fn invalid_request(message: &'static str) -> Self {
        Self::new("invalid_request", message)
    }
}

impl From<database::DatabaseInitError> for AssistantIpcError {
    fn from(error: database::DatabaseInitError) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<rusqlite::Error> for AssistantIpcError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<citations::CitationError> for AssistantIpcError {
    fn from(error: citations::CitationError) -> Self {
        Self::new("citation", error.to_string())
    }
}

impl From<assistant::ContractError> for AssistantIpcError {
    fn from(error: assistant::ContractError) -> Self {
        Self::new("invalid_contract", error.to_string())
    }
}

impl From<assistant::ArtifactRenderError> for AssistantIpcError {
    fn from(error: assistant::ArtifactRenderError) -> Self {
        Self::new("artifact_render", error.to_string())
    }
}

impl From<file_ingest::IngestError> for AssistantIpcError {
    fn from(error: file_ingest::IngestError) -> Self {
        Self::new(error.code(), error.message())
    }
}

impl From<serde_json::Error> for AssistantIpcError {
    fn from(_: serde_json::Error) -> Self {
        Self::new("serialization", "structured data could not be processed")
    }
}

impl From<providers::ProviderError> for AssistantIpcError {
    fn from(error: providers::ProviderError) -> Self {
        Self::new(error.kind.as_str(), error.to_string())
    }
}

impl From<legal_services::ServiceError> for AssistantIpcError {
    fn from(error: legal_services::ServiceError) -> Self {
        // Preserve the desktop IPC categories consumed by the existing UI and
        // tests while MCP keeps the service's more specific stable error code.
        let error_type = match error.code.as_str() {
            "entity_id_conflict"
            | "transfer_conflict"
            | "revision_conflict"
            | "idempotency_conflict"
            | "operation_in_progress"
            | "proposal_scope_mismatch"
            | "audit_conflict"
            | "case_apply_no_effect" => "conflict",
            "database_operation_failed"
            | "user_database_missing"
            | "user_database_incompatible" => "database",
            "invalid_proposal" | "proposal_hash_mismatch" | "unsupported_schema_version" => {
                "invalid_contract"
            }
            code => code,
        };
        Self::new(error_type, error.message)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantCapabilitiesResponse {
    pub capabilities: Vec<CapabilityDescriptor>,
    pub default_budget: RunBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelAssistantRunRequest {
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelAssistantRunResponse {
    pub run_id: String,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantConversation {
    pub conversation_id: String,
    pub project_id: Option<String>,
    pub title: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub role: String,
    pub kind: String,
    pub text_summary: String,
    pub artifact_id: Option<String>,
    pub run_id: Option<String>,
    pub created_at: String,
    pub attachments: Vec<AssistantAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttachment {
    pub attachment_id: String,
    pub project_id: Option<String>,
    pub original_name: String,
    pub extension: String,
    pub detected_mime: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub extraction_status: String,
    pub error_code: Option<String>,
    pub segment_count: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantConversationSource {
    pub source_id: String,
    pub source: Option<LegalSource>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantArtifact {
    pub artifact_id: String,
    pub conversation_id: Option<String>,
    pub project_id: Option<String>,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub current_version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantArtifactVersion {
    pub version_id: String,
    pub artifact_id: String,
    pub version_number: i64,
    pub content: serde_json::Value,
    pub rendered_text: String,
    pub source_refs: Vec<String>,
    pub citation_report: serde_json::Value,
    pub provider_snapshot: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantRun {
    pub run_id: String,
    pub conversation_id: String,
    pub user_message_id: String,
    pub assistant_message_id: Option<String>,
    pub provider_id: Option<String>,
    pub provider_snapshot: serde_json::Value,
    pub intent: String,
    pub status: String,
    pub budget: RunBudget,
    pub error_type: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub tool_calls: Vec<AssistantToolCall>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantToolCall {
    pub tool_call_id: String,
    pub run_id: String,
    pub ordinal: i64,
    pub capability_name: String,
    pub status: String,
    pub access_mode: String,
    pub requires_confirmation: bool,
    pub input_audit: serde_json::Value,
    pub output_audit: serde_json::Value,
    pub source_audit: serde_json::Value,
    pub error_type: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantCaseChangeProposal {
    pub proposal_id: String,
    pub conversation_id: String,
    pub project_id: String,
    pub run_id: Option<String>,
    pub base_case_digest: String,
    pub status: String,
    pub changes: assistant::CaseChangeSpec,
    pub source_refs: Vec<String>,
    pub created_at: String,
    pub decided_at: Option<String>,
    pub applied_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAssistantCaseChangeProposalRequest {
    pub conversation_id: String,
    pub project_id: String,
    pub changes: assistant::CaseChangeSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantCaseChangeProposalResponse {
    pub proposal: AssistantCaseChangeProposal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RejectAssistantCaseChangeProposalRequest {
    pub proposal_id: String,
    pub project_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyAssistantCaseChangeProposalRequest {
    pub proposal_id: String,
    pub project_id: String,
    pub user_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyAssistantCaseChangeProposalResponse {
    pub proposal: AssistantCaseChangeProposal,
    pub applied: bool,
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantConversationDetail {
    pub conversation: AssistantConversation,
    pub messages: Vec<AssistantMessage>,
    pub sources: Vec<AssistantConversationSource>,
    pub artifacts: Vec<AssistantArtifact>,
    pub runs: Vec<AssistantRun>,
    pub proposals: Vec<AssistantCaseChangeProposal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAssistantConversationsRequest {
    pub project_id: Option<String>,
    pub include_archived: Option<bool>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssistantConversationsResponse {
    pub conversations: Vec<AssistantConversation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAssistantConversationRequest {
    pub title: String,
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantConversationResponse {
    pub conversation: AssistantConversation,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssistantConversationIdRequest {
    pub conversation_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssistantConversationResponse {
    pub detail: AssistantConversationDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindAssistantConversationRequest {
    pub conversation_id: String,
    pub project_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddAssistantLegalSourceRequest {
    pub conversation_id: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposeAssistantLegalBasisRequest {
    pub conversation_id: String,
    pub project_id: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantConversationSourceResponse {
    pub source: AssistantConversationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAssistantArtifactsRequest {
    pub conversation_id: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssistantArtifactsResponse {
    pub artifacts: Vec<AssistantArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetAssistantArtifactRequest {
    pub artifact_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssistantArtifactResponse {
    pub artifact: AssistantArtifact,
    pub versions: Vec<AssistantArtifactVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindAssistantArtifactRequest {
    pub artifact_id: String,
    pub project_id: String,
    pub user_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantArtifactResponse {
    pub artifact: AssistantArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchArtifactSpec {
    pub schema_version: u16,
    pub title: String,
    pub answer: String,
    pub source_refs: Vec<String>,
    pub assumptions: Vec<String>,
    pub missing_information: Vec<String>,
    pub risk_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "spec",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AssistantArtifactDraft {
    Research(ResearchArtifactSpec),
    Document(assistant::DocumentSpec),
    Map(assistant::MapSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveAssistantArtifactRequest {
    pub conversation_id: String,
    pub artifact_id: Option<String>,
    pub expected_current_version: Option<i64>,
    pub title: String,
    pub draft: AssistantArtifactDraft,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveAssistantArtifactResponse {
    pub detail: GetAssistantArtifactResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantArtifactExportFormat {
    ResearchMarkdown,
    DocumentMarkdown,
    DocumentDocx,
    /// Retained only so older clients receive an explicit safe rejection.
    #[serde(rename = "map_json")]
    LegacyMapJson,
    MapSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportAssistantArtifactRequest {
    pub artifact_id: String,
    pub version_number: i64,
    pub format: AssistantArtifactExportFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportAssistantArtifactResponse {
    pub cancelled: bool,
    pub file_name: Option<String>,
    pub format: AssistantArtifactExportFormat,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportAssistantFilesRequest {
    pub conversation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportAssistantFilesResponse {
    pub cancelled: bool,
    pub duplicate_count: usize,
    pub message: Option<AssistantMessage>,
    pub attachments: Vec<AssistantAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteAssistantAttachmentRequest {
    pub conversation_id: String,
    pub attachment_id: String,
    pub user_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAssistantAttachmentResponse {
    pub attachment_id: String,
    pub deleted: bool,
}

#[tauri::command]
pub fn get_assistant_capabilities() -> AssistantCapabilitiesResponse {
    AssistantCapabilitiesResponse {
        capabilities: assistant::capability_registry().to_vec(),
        default_budget: RunBudget::default(),
    }
}

#[tauri::command]
pub fn list_assistant_conversations(
    state: State<'_, AppState>,
    request: ListAssistantConversationsRequest,
) -> Result<ListAssistantConversationsResponse, AssistantIpcError> {
    list_assistant_conversations_inner(state.inner(), request)
}

fn list_assistant_conversations_inner(
    state: &AppState,
    request: ListAssistantConversationsRequest,
) -> Result<ListAssistantConversationsResponse, AssistantIpcError> {
    let limit = request.limit.unwrap_or(50);
    if limit == 0 || limit > MAX_CONVERSATION_LIST_LIMIT {
        return Err(AssistantIpcError::invalid_request(
            "limit must be between 1 and 100",
        ));
    }
    if let Some(project_id) = request.project_id.as_deref() {
        validate_identifier("projectId", project_id)?;
    }

    let connection = database::open_user_database(state.user_database_path())?;
    let rows = if let Some(project_id) = request.project_id.as_deref() {
        if !database::case_project_exists(&connection, project_id)? {
            return Err(AssistantIpcError::new(
                "not_found",
                "case project not found",
            ));
        }
        database::list_conversations_for_project(&connection, project_id, limit)?
    } else {
        database::list_conversations(&connection, limit)?
    };
    let include_archived = request.include_archived.unwrap_or(false);
    let conversations = rows
        .into_iter()
        .filter(|row| include_archived || row.status == "open")
        .map(conversation_from_row)
        .collect();
    Ok(ListAssistantConversationsResponse { conversations })
}

#[tauri::command]
pub fn create_assistant_conversation(
    state: State<'_, AppState>,
    request: CreateAssistantConversationRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    create_assistant_conversation_inner(state.inner(), request)
}

fn create_assistant_conversation_inner(
    state: &AppState,
    request: CreateAssistantConversationRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    validate_bounded_text("title", &request.title, MAX_CONVERSATION_TITLE_BYTES, false)?;
    if let Some(project_id) = request.project_id.as_deref() {
        validate_identifier("projectId", project_id)?;
    }

    let connection = database::open_user_database(state.user_database_path())?;
    if let Some(project_id) = request.project_id.as_deref() {
        if !database::case_project_exists(&connection, project_id)? {
            return Err(AssistantIpcError::new(
                "not_found",
                "case project not found",
            ));
        }
    }
    let row = database::create_conversation(
        &connection,
        &format!("conversation:{}", Uuid::new_v4()),
        request.project_id.as_deref(),
        request.title.trim(),
    )?;
    Ok(AssistantConversationResponse {
        conversation: conversation_from_row(row),
    })
}

#[tauri::command]
pub fn get_assistant_conversation(
    state: State<'_, AppState>,
    request: AssistantConversationIdRequest,
) -> Result<GetAssistantConversationResponse, AssistantIpcError> {
    get_assistant_conversation_inner(state.inner(), request)
}

fn get_assistant_conversation_inner(
    state: &AppState,
    request: AssistantConversationIdRequest,
) -> Result<GetAssistantConversationResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    let conversation = database::get_conversation(&connection, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;

    let messages = database::list_messages(&connection, &request.conversation_id)?
        .into_iter()
        .map(|row| message_from_row(&connection, row))
        .collect::<Result<Vec<_>, _>>()?;
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let sources = database::list_conversation_sources(&connection, &request.conversation_id)?
        .into_iter()
        .map(|row| {
            Ok(AssistantConversationSource {
                source: citations::source_by_citation_id(&legal_connection, &row.source_id)?,
                source_id: row.source_id,
                created_at: row.created_at,
            })
        })
        .collect::<Result<Vec<_>, AssistantIpcError>>()?;
    let artifacts = database::list_artifacts(&connection, Some(&request.conversation_id), 100)?
        .into_iter()
        .map(artifact_from_row)
        .collect();
    let runs = database::list_agent_runs(&connection, &request.conversation_id)?
        .into_iter()
        .map(|row| run_from_row(&connection, row))
        .collect::<Result<Vec<_>, _>>()?;
    let proposals = database::list_case_change_proposals(&connection, &request.conversation_id)?
        .into_iter()
        .map(proposal_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GetAssistantConversationResponse {
        detail: AssistantConversationDetail {
            conversation: conversation_from_row(conversation),
            messages,
            sources,
            artifacts,
            runs,
            proposals,
        },
    })
}

#[tauri::command]
pub fn bind_assistant_conversation(
    state: State<'_, AppState>,
    request: BindAssistantConversationRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    bind_assistant_conversation_inner(state.inner(), request)
}

fn bind_assistant_conversation_inner(
    state: &AppState,
    request: BindAssistantConversationRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_identifier("projectId", &request.project_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    if !database::case_project_exists(&connection, &request.project_id)? {
        return Err(AssistantIpcError::new(
            "not_found",
            "case project not found",
        ));
    }
    if !database::bind_conversation_to_case(
        &connection,
        &request.conversation_id,
        &request.project_id,
    )? {
        return Err(AssistantIpcError::new(
            "conflict",
            "conversation is missing, archived, or already belongs to another case",
        ));
    }
    let conversation = database::get_conversation(&connection, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    Ok(AssistantConversationResponse {
        conversation: conversation_from_row(conversation),
    })
}

#[tauri::command]
pub fn archive_assistant_conversation(
    state: State<'_, AppState>,
    request: AssistantConversationIdRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    archive_assistant_conversation_inner(state.inner(), request)
}

fn archive_assistant_conversation_inner(
    state: &AppState,
    request: AssistantConversationIdRequest,
) -> Result<AssistantConversationResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    if !database::archive_conversation(&connection, &request.conversation_id)? {
        return Err(AssistantIpcError::new(
            "conflict",
            "conversation is missing or already archived",
        ));
    }
    let conversation = database::get_conversation(&connection, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    Ok(AssistantConversationResponse {
        conversation: conversation_from_row(conversation),
    })
}

#[tauri::command]
pub fn add_assistant_legal_source(
    state: State<'_, AppState>,
    request: AddAssistantLegalSourceRequest,
) -> Result<AssistantConversationSourceResponse, AssistantIpcError> {
    add_assistant_legal_source_inner(state.inner(), request)
}

fn add_assistant_legal_source_inner(
    state: &AppState,
    request: AddAssistantLegalSourceRequest,
) -> Result<AssistantConversationSourceResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_bounded_text("sourceId", &request.source_id, 1_024, false)?;
    let mut user_connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        user_connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let conversation = database::get_conversation(&transaction, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    if conversation.status != "open" {
        return Err(AssistantIpcError::new(
            "conflict",
            "archived conversations cannot accept sources",
        ));
    }
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let source = citations::source_by_citation_id(&legal_connection, &request.source_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "legal source not found"))?;
    let row = database::add_conversation_source(
        &transaction,
        &request.conversation_id,
        &request.source_id,
    )?;
    transaction.commit()?;
    Ok(AssistantConversationSourceResponse {
        source: AssistantConversationSource {
            source_id: row.source_id,
            source: Some(source),
            created_at: row.created_at,
        },
    })
}

#[tauri::command]
pub fn propose_assistant_legal_basis(
    state: State<'_, AppState>,
    request: ProposeAssistantLegalBasisRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    propose_assistant_legal_basis_inner(state.inner(), request)
}

pub(super) fn public_law_citation(source: &LegalSource) -> Result<String, AssistantIpcError> {
    let title = source.document_title.trim();
    let year = source
        .effective_from
        .get(..4)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()));
    let locator = public_law_locator(source);
    if !title.is_empty()
        && year.is_some()
        && locator.is_none()
        && has_multiple_unlocated_paragraphs(source)
    {
        return Err(AssistantIpcError::new(
            "legal_paragraph_unresolved",
            "legal source contains multiple paragraphs without an explicit paragraph locator",
        ));
    }
    match (title.is_empty(), locator, year) {
        (false, Some(locator), Some(year)) => Ok(format!("《{title}》{locator}（{year}年起施行）")),
        _ => Err(AssistantIpcError::new(
            "invalid_legal_source",
            "legal source lacks a complete public citation",
        )),
    }
}

fn has_multiple_unlocated_paragraphs(source: &LegalSource) -> bool {
    let article_number = source.article_number.trim();
    let Some(article_end) = article_number
        .find('条')
        .map(|index| index + '条'.len_utf8())
    else {
        return false;
    };
    let Some(article) = article_number.get(..article_end) else {
        return false;
    };
    if !article.starts_with('第') || article.chars().count() < 3 {
        return false;
    }
    if explicit_paragraph_label(article_number.get(article_end..).unwrap_or_default()).is_some()
        || explicit_paragraph_label(&source.canonical_label).is_some()
    {
        return false;
    }

    source
        .content
        .split(['\n', '\u{2028}', '\u{2029}'])
        .filter(|paragraph| !paragraph.trim().is_empty())
        .take(2)
        .count()
        > 1
}

fn public_law_locator(source: &LegalSource) -> Option<String> {
    let article_number = source.article_number.trim();
    let article_end = article_number.find('条')? + '条'.len_utf8();
    let article = article_number.get(..article_end)?;
    if !article.starts_with('第') || article.chars().count() < 3 {
        return None;
    }

    let paragraph = explicit_paragraph_label(article_number.get(article_end..).unwrap_or_default())
        .or_else(|| explicit_paragraph_label(&source.canonical_label))
        .or_else(|| verified_single_full_paragraph(&source.content).then_some("第一款"))?;
    Some(format!("{article}{paragraph}"))
}

fn explicit_paragraph_label(value: &str) -> Option<&str> {
    let paragraph_end = value.find('款')? + '款'.len_utf8();
    let before = value.get(..paragraph_end)?;
    let paragraph_start = before.rfind('第')?;
    let label = before.get(paragraph_start..paragraph_end)?;
    (label.chars().count() >= 3).then_some(label)
}

/// A paragraph number may be inferred only from the complete legal-library
/// article body. An excerpt is never sufficient. Newlines and Unicode
/// paragraph separators are treated as statutory paragraph boundaries, while
/// omission/truncation markers and a missing terminal full stop make the body
/// unsuitable for inference.
fn verified_single_full_paragraph(content: &str) -> bool {
    let content = content.trim();
    if content.is_empty()
        || !content.ends_with('。')
        || content.contains('\u{fffd}')
        || ["…", "...", "省略", "节选", "截断", "未完", "（略）", "[略]"]
            .iter()
            .any(|marker| content.contains(marker))
    {
        return false;
    }

    content
        .split(['\n', '\u{2028}', '\u{2029}'])
        .filter(|paragraph| !paragraph.trim().is_empty())
        .take(2)
        .count()
        == 1
}

fn propose_assistant_legal_basis_inner(
    state: &AppState,
    request: ProposeAssistantLegalBasisRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_identifier("projectId", &request.project_id)?;
    validate_bounded_text("sourceId", &request.source_id, 1_024, false)?;
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let source = citations::source_by_citation_id(&legal_connection, &request.source_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "legal source not found"))?;
    let citation = public_law_citation(&source)?;

    let mut user_connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        user_connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let conversation = database::get_conversation(&transaction, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    database::add_conversation_source(&transaction, &request.conversation_id, &request.source_id)?;
    let changes = assistant::CaseChangeSpec {
        schema_version: assistant::CONTRACT_SCHEMA_VERSION,
        facts: Vec::new(),
        evidence: Vec::new(),
        issues: Vec::new(),
        legal_basis: vec![assistant::LegalBasisAddition {
            id: format!("basis:legal-library:{}", Uuid::new_v4()),
            issue_ids: Vec::new(),
            source_ref: source.source_id.clone(),
            marker: format!("[SRC:{}]", source.source_id),
            citation,
            proposition: "该条规定可作为案件法律依据，具体适用仍须结合案件事实和证据核对。"
                .to_owned(),
        }],
        attachment_transfers: Vec::new(),
        artifact_transfers: Vec::new(),
    };
    let proposal = create_assistant_case_change_proposal_with_connection(
        state,
        &transaction,
        &conversation,
        &CreateAssistantCaseChangeProposalRequest {
            conversation_id: request.conversation_id,
            project_id: request.project_id,
            changes,
        },
        None,
    )?;
    transaction.commit()?;
    Ok(AssistantCaseChangeProposalResponse {
        proposal: proposal_from_row(proposal)?,
    })
}

#[tauri::command]
pub fn list_assistant_artifacts(
    state: State<'_, AppState>,
    request: ListAssistantArtifactsRequest,
) -> Result<ListAssistantArtifactsResponse, AssistantIpcError> {
    let limit = request.limit.unwrap_or(100);
    if limit == 0 || limit > 100 {
        return Err(AssistantIpcError::invalid_request(
            "limit must be between 1 and 100",
        ));
    }
    if let Some(conversation_id) = request.conversation_id.as_deref() {
        validate_identifier("conversationId", conversation_id)?;
    }
    let connection = database::open_user_database(state.user_database_path())?;
    if let Some(conversation_id) = request.conversation_id.as_deref() {
        if database::get_conversation(&connection, conversation_id)?.is_none() {
            return Err(AssistantIpcError::new(
                "not_found",
                "conversation not found",
            ));
        }
    }
    let artifacts =
        database::list_artifacts(&connection, request.conversation_id.as_deref(), limit)?
            .into_iter()
            .map(artifact_from_row)
            .collect();
    Ok(ListAssistantArtifactsResponse { artifacts })
}

#[tauri::command]
pub fn get_assistant_artifact(
    state: State<'_, AppState>,
    request: GetAssistantArtifactRequest,
) -> Result<GetAssistantArtifactResponse, AssistantIpcError> {
    get_assistant_artifact_inner(state.inner(), request)
}

fn get_assistant_artifact_inner(
    state: &AppState,
    request: GetAssistantArtifactRequest,
) -> Result<GetAssistantArtifactResponse, AssistantIpcError> {
    validate_identifier("artifactId", &request.artifact_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    let artifact = database::get_artifact(&connection, &request.artifact_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "artifact not found"))?;
    let versions = database::list_artifact_versions(&connection, &request.artifact_id)?
        .into_iter()
        .map(artifact_version_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GetAssistantArtifactResponse {
        artifact: artifact_from_row(artifact),
        versions,
    })
}

#[tauri::command]
pub fn bind_assistant_artifact(
    state: State<'_, AppState>,
    request: BindAssistantArtifactRequest,
) -> Result<AssistantArtifactResponse, AssistantIpcError> {
    bind_assistant_artifact_inner(state.inner(), request)
}

fn bind_assistant_artifact_inner(
    state: &AppState,
    request: BindAssistantArtifactRequest,
) -> Result<AssistantArtifactResponse, AssistantIpcError> {
    validate_identifier("artifactId", &request.artifact_id)?;
    validate_identifier("projectId", &request.project_id)?;
    if !request.user_confirmed {
        return Err(AssistantIpcError::new(
            "confirmation_required",
            "explicit user confirmation is required before binding an artifact to a case",
        ));
    }
    let mut connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !database::case_project_exists(&transaction, &request.project_id)? {
        return Err(AssistantIpcError::new(
            "not_found",
            "case project not found",
        ));
    }
    let existing = database::get_artifact(&transaction, &request.artifact_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "artifact not found"))?;
    if let Some(conversation_id) = existing.conversation_id.as_deref() {
        let conversation = database::get_conversation(&transaction, conversation_id)?
            .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
        if conversation.status != "open" {
            return Err(AssistantIpcError::new(
                "conflict",
                "artifacts in archived conversations are read-only",
            ));
        }
    }
    if !database::bind_artifact_to_case(&transaction, &request.artifact_id, &request.project_id)? {
        return Err(AssistantIpcError::new(
            "conflict",
            "artifact is missing, archived, or belongs to another case",
        ));
    }
    let artifact = database::get_artifact(&transaction, &request.artifact_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "artifact not found"))?;
    transaction.commit()?;
    Ok(AssistantArtifactResponse {
        artifact: artifact_from_row(artifact),
    })
}

#[tauri::command]
pub fn save_assistant_artifact(
    state: State<'_, AppState>,
    request: SaveAssistantArtifactRequest,
) -> Result<SaveAssistantArtifactResponse, AssistantIpcError> {
    save_assistant_artifact_inner(state.inner(), request, serde_json::Value::Null)
}

pub(super) fn save_assistant_artifact_inner(
    state: &AppState,
    request: SaveAssistantArtifactRequest,
    provider_snapshot: serde_json::Value,
) -> Result<SaveAssistantArtifactResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_bounded_text("title", &request.title, MAX_CONVERSATION_TITLE_BYTES, false)?;
    match request.artifact_id.as_deref() {
        Some(artifact_id) => {
            validate_identifier("artifactId", artifact_id)?;
            if request.expected_current_version.is_none() {
                return Err(AssistantIpcError::invalid_request(
                    "expectedCurrentVersion is required when updating an artifact",
                ));
            }
        }
        None if request.expected_current_version.is_some() => {
            return Err(AssistantIpcError::invalid_request(
                "expectedCurrentVersion is only valid when updating an artifact",
            ));
        }
        None => {}
    }

    let mut connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let conversation = database::get_conversation(&transaction, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    if conversation.status != "open" {
        return Err(AssistantIpcError::new(
            "conflict",
            "archived conversations cannot save artifacts",
        ));
    }
    let validation_scope = build_assistant_validation_scope(&transaction, &conversation)?;
    let rendered = prepare_artifact_version(
        &request.title,
        &request.draft,
        &validation_scope,
        provider_snapshot,
    )?;

    let artifact_id = if let Some(artifact_id) = request.artifact_id {
        let artifact = database::get_artifact(&transaction, &artifact_id)?
            .ok_or_else(|| AssistantIpcError::new("not_found", "artifact not found"))?;
        if artifact.conversation_id.as_deref() != Some(request.conversation_id.as_str())
            || artifact.kind != rendered.kind
            || artifact.title != request.title.trim()
        {
            return Err(AssistantIpcError::new(
                "conflict",
                "artifact ownership, kind, or title does not match this update",
            ));
        }
        let expected = request
            .expected_current_version
            .expect("validated update has expected version");
        let version = database::NewArtifactVersionRow {
            version_id: format!("artifact-version:{}", Uuid::new_v4()),
            artifact_id: artifact_id.clone(),
            content_json: rendered.content_json,
            rendered_text: rendered.rendered_text,
            source_refs_json: rendered.source_refs_json,
            citation_report_json: rendered.citation_report_json,
            provider_snapshot_json: rendered.provider_snapshot_json,
        };
        match database::create_artifact_version(&transaction, &version, expected)? {
            database::ArtifactVersionCreateResult::Created(_) => artifact_id,
            database::ArtifactVersionCreateResult::Conflict => {
                return Err(AssistantIpcError::new(
                    "conflict",
                    "artifact version changed; reload before saving",
                ));
            }
            database::ArtifactVersionCreateResult::NotFound => {
                return Err(AssistantIpcError::new("not_found", "artifact not found"));
            }
        }
    } else {
        let artifact_id = format!("artifact:{}", Uuid::new_v4());
        database::create_artifact(
            &transaction,
            &database::NewArtifactRow {
                artifact_id: artifact_id.clone(),
                conversation_id: Some(request.conversation_id),
                project_id: conversation.project_id,
                kind: rendered.kind,
                title: request.title.trim().to_owned(),
                status: "draft".to_owned(),
            },
            &database::NewArtifactVersionRow {
                version_id: format!("artifact-version:{}", Uuid::new_v4()),
                artifact_id: artifact_id.clone(),
                content_json: rendered.content_json,
                rendered_text: rendered.rendered_text,
                source_refs_json: rendered.source_refs_json,
                citation_report_json: rendered.citation_report_json,
                provider_snapshot_json: rendered.provider_snapshot_json,
            },
        )?;
        artifact_id
    };
    transaction.commit()?;
    let detail = get_assistant_artifact_inner(state, GetAssistantArtifactRequest { artifact_id })?;
    Ok(SaveAssistantArtifactResponse { detail })
}

pub(super) struct AssistantValidationScope {
    pub(super) context: assistant::ValidationContext,
    pub(super) source_refs: std::collections::HashSet<String>,
}

pub(super) struct PreparedArtifactVersion {
    pub(super) kind: String,
    pub(super) content_json: String,
    pub(super) rendered_text: String,
    pub(super) source_refs_json: String,
    pub(super) citation_report_json: String,
    pub(super) provider_snapshot_json: String,
}

pub(super) fn build_assistant_validation_scope(
    connection: &rusqlite::Connection,
    conversation: &database::ConversationRow,
) -> Result<AssistantValidationScope, AssistantIpcError> {
    let mut context = assistant::ValidationContext::default();
    let mut source_refs = std::collections::HashSet::new();
    for source in database::list_conversation_sources(connection, &conversation.conversation_id)? {
        context.allow_validated_legal_source(source.source_id.clone());
        source_refs.insert(source.source_id);
    }
    for message in database::list_messages(connection, &conversation.conversation_id)? {
        for attachment in database::list_attachments_for_message(connection, &message.message_id)? {
            context.allow_source_ref(attachment.attachment_id.clone());
            context.allow_attachment(attachment.attachment_id.clone());
            source_refs.insert(attachment.attachment_id);
        }
    }
    for artifact in database::list_artifacts(connection, Some(&conversation.conversation_id), 500)?
    {
        context.allow_source_ref(artifact.artifact_id.clone());
        context.allow_artifact(artifact.artifact_id.clone());
        source_refs.insert(artifact.artifact_id);
    }
    if let Some(project_id) = conversation.project_id.as_deref() {
        if connection.is_autocommit() {
            let workspace = database::get_case_workspace_rows(connection, project_id)?
                .ok_or_else(|| AssistantIpcError::new("not_found", "case project not found"))?;
            for file in workspace.files {
                context.allow_source_ref(file.file_id.clone());
                source_refs.insert(file.file_id);
            }
            for party in workspace.parties {
                context.allow_source_ref(party.party_id.clone());
                source_refs.insert(party.party_id);
            }
            for fact in workspace.facts {
                if fact.confirmation_status == "confirmed" {
                    context.allow_case_fact(fact.fact_id.clone());
                    context.allow_source_ref(fact.fact_id.clone());
                    source_refs.insert(fact.fact_id);
                }
            }
            for evidence in workspace.evidence {
                if evidence.confirmation_status == "confirmed" {
                    context.allow_source_ref(evidence.evidence_id.clone());
                    source_refs.insert(evidence.evidence_id);
                }
            }
            for issue in workspace.legal_issues {
                if issue.confirmation_status == "confirmed" {
                    context.allow_case_issue(issue.issue_id.clone());
                    context.allow_source_ref(issue.issue_id.clone());
                    source_refs.insert(issue.issue_id);
                }
            }
            for basis in workspace.legal_basis {
                if basis.status == "valid" {
                    context.allow_validated_legal_source(basis.source_id.clone());
                    source_refs.insert(basis.source_id);
                }
            }
        } else {
            add_transactional_case_scope(connection, project_id, &mut context, &mut source_refs)?;
        }
    }
    Ok(AssistantValidationScope {
        context,
        source_refs,
    })
}

fn add_transactional_case_scope(
    connection: &rusqlite::Connection,
    project_id: &str,
    context: &mut assistant::ValidationContext,
    source_refs: &mut std::collections::HashSet<String>,
) -> Result<(), AssistantIpcError> {
    if !database::case_project_exists(connection, project_id)? {
        return Err(AssistantIpcError::new(
            "not_found",
            "case project not found",
        ));
    }
    for id in query_project_ids(
        connection,
        "SELECT file_id FROM case_files WHERE project_id = ?1",
        project_id,
    )? {
        context.allow_source_ref(id.clone());
        source_refs.insert(id);
    }
    for id in query_project_ids(
        connection,
        "SELECT party_id FROM case_parties WHERE project_id = ?1",
        project_id,
    )? {
        context.allow_source_ref(id.clone());
        source_refs.insert(id);
    }
    for id in query_project_ids(
        connection,
        "SELECT fact_id FROM case_facts WHERE project_id = ?1 AND confirmation_status = 'confirmed'",
        project_id,
    )? {
        context.allow_case_fact(id.clone());
        context.allow_source_ref(id.clone());
        source_refs.insert(id);
    }
    for id in query_project_ids(
        connection,
        "SELECT evidence_id FROM evidence_items WHERE project_id = ?1 AND confirmation_status = 'confirmed'",
        project_id,
    )? {
        context.allow_source_ref(id.clone());
        source_refs.insert(id);
    }
    for id in query_project_ids(
        connection,
        "SELECT issue_id FROM legal_issues WHERE project_id = ?1 AND confirmation_status = 'confirmed'",
        project_id,
    )? {
        context.allow_case_issue(id.clone());
        context.allow_source_ref(id.clone());
        source_refs.insert(id);
    }
    for id in query_project_ids(
        connection,
        "SELECT source_id FROM legal_basis WHERE project_id = ?1 AND status = 'valid'",
        project_id,
    )? {
        context.allow_validated_legal_source(id.clone());
        source_refs.insert(id);
    }
    Ok(())
}

fn query_project_ids(
    connection: &rusqlite::Connection,
    sql: &str,
    project_id: &str,
) -> Result<Vec<String>, AssistantIpcError> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement
        .query_map([project_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(super) fn prepare_artifact_version(
    title: &str,
    draft: &AssistantArtifactDraft,
    scope: &AssistantValidationScope,
    provider_snapshot: serde_json::Value,
) -> Result<PreparedArtifactVersion, AssistantIpcError> {
    let (kind, rendered_text, source_refs) = match draft {
        AssistantArtifactDraft::Research(spec) => {
            validate_research_spec(spec, title, scope)?;
            (
                "research",
                render_research_markdown(spec),
                spec.source_refs
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        }
        AssistantArtifactDraft::Document(spec) => {
            if spec.title != title.trim() {
                return Err(AssistantIpcError::invalid_request(
                    "artifact title must match document spec title",
                ));
            }
            let rendered = assistant::render_document_markdown(spec, &scope.context)?;
            let source_refs = spec
                .source_materials
                .iter()
                .map(|source| source.id.clone())
                .chain(
                    spec.legal_citations
                        .iter()
                        .map(|citation| citation.source_ref.clone()),
                )
                .collect::<std::collections::BTreeSet<_>>();
            (
                "document",
                rendered
                    .as_text()
                    .expect("document markdown renderer returns text")
                    .to_owned(),
                source_refs,
            )
        }
        AssistantArtifactDraft::Map(spec) => {
            if spec.title != title.trim() {
                return Err(AssistantIpcError::invalid_request(
                    "artifact title must match map spec title",
                ));
            }
            let rendered = assistant::render_map_summary(spec, &scope.context)?;
            let source_refs = spec
                .nodes
                .iter()
                .flat_map(|node| node.source_refs.iter().cloned())
                .chain(
                    spec.edges
                        .iter()
                        .flat_map(|edge| edge.source_refs.iter().cloned()),
                )
                .collect::<std::collections::BTreeSet<_>>();
            (
                "map",
                rendered
                    .as_text()
                    .expect("map summary renderer returns text")
                    .to_owned(),
                source_refs,
            )
        }
    };
    if provider_snapshot != serde_json::Value::Null && !provider_snapshot.is_object() {
        return Err(AssistantIpcError::new(
            "invalid_provider_snapshot",
            "provider snapshot must be a closed object or null",
        ));
    }
    let source_refs = source_refs.into_iter().collect::<Vec<_>>();
    Ok(PreparedArtifactVersion {
        kind: kind.to_owned(),
        content_json: serde_json::to_string(draft)?,
        rendered_text,
        source_refs_json: serde_json::to_string(&source_refs)?,
        citation_report_json: serde_json::to_string(&serde_json::json!({
            "validation": "rust_contract",
            "sourceRefs": source_refs,
            "semanticSupportVerified": false
        }))?,
        provider_snapshot_json: serde_json::to_string(&provider_snapshot)?,
    })
}

fn validate_research_spec(
    spec: &ResearchArtifactSpec,
    title: &str,
    scope: &AssistantValidationScope,
) -> Result<(), AssistantIpcError> {
    if spec.schema_version != assistant::CONTRACT_SCHEMA_VERSION || spec.title != title.trim() {
        return Err(AssistantIpcError::invalid_request(
            "research schema version and title must match the artifact",
        ));
    }
    validate_bounded_text("answer", &spec.answer, 1024 * 1024, true)?;
    assistant::validate_public_output_text("research.title", &spec.title)?;
    assistant::validate_public_output_text("research.answer", &spec.answer)?;
    if spec.source_refs.len() > 128
        || spec.assumptions.len() > 64
        || spec.missing_information.len() > 64
        || spec.risk_warnings.len() > 64
    {
        return Err(AssistantIpcError::new(
            "limit_exceeded",
            "research artifact exceeds its array limits",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for source_ref in &spec.source_refs {
        validate_identifier("sourceRef", source_ref)?;
        if !seen.insert(source_ref) || !scope.source_refs.contains(source_ref) {
            return Err(AssistantIpcError::new(
                "unknown_reference",
                "research source is duplicated or is not owned by this conversation",
            ));
        }
    }
    for (index, text) in spec.assumptions.iter().enumerate() {
        validate_bounded_text("researchItem", text, 2 * 1024, true)?;
        assistant::validate_public_output_text(&format!("research.assumptions[{index}]"), text)?;
    }
    for (index, text) in spec.missing_information.iter().enumerate() {
        validate_bounded_text("researchItem", text, 2 * 1024, true)?;
        assistant::validate_public_output_text(
            &format!("research.missingInformation[{index}]"),
            text,
        )?;
    }
    for (index, text) in spec.risk_warnings.iter().enumerate() {
        validate_bounded_text("researchItem", text, 2 * 1024, true)?;
        assistant::validate_public_output_text(&format!("research.riskWarnings[{index}]"), text)?;
    }
    Ok(())
}

fn render_research_markdown(spec: &ResearchArtifactSpec) -> String {
    super::research_output::render_research_markdown(
        &spec.title,
        &spec.answer,
        &spec.assumptions,
        &spec.missing_information,
        &spec.risk_warnings,
    )
}

fn require_privacy_safe_artifact_export() -> Result<(), AssistantIpcError> {
    Err(AssistantIpcError::new(
        "privacy_required",
        "Legacy assistant artifact export is disabled; use the privacy workbench and an active exact redaction receipt.",
    ))
}
#[tauri::command]
pub async fn export_assistant_artifact(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    request: ExportAssistantArtifactRequest,
) -> Result<ExportAssistantArtifactResponse, AssistantIpcError> {
    require_privacy_safe_artifact_export()?;
    let payload = prepare_artifact_export(state.inner(), &request)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("导出助理产物")
            .set_file_name(&payload.suggested_file_name)
            .add_filter(payload.filter_name, &[payload.extension])
            .blocking_save_file();
        let Some(selected) = selected else {
            return Ok(ExportAssistantArtifactResponse {
                cancelled: true,
                file_name: None,
                format: request.format,
                byte_len: 0,
            });
        };
        let mut destination = selected.into_path().map_err(|_| {
            AssistantIpcError::new("invalid_path", "selected destination is not a local file")
        })?;
        if !destination
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(payload.extension))
        {
            destination.set_extension(payload.extension);
        }
        validate_artifact_export_destination(&state, &destination)?;
        write_artifact_export_atomically(&state, &destination, &payload.bytes)?;
        let file_name = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                AssistantIpcError::new("invalid_file_name", "export file name is not valid UTF-8")
            })?
            .to_owned();
        Ok(ExportAssistantArtifactResponse {
            cancelled: false,
            file_name: Some(file_name),
            format: request.format,
            byte_len: payload.bytes.len(),
        })
    })
    .await
    .map_err(|_| AssistantIpcError::new("runtime", "artifact export worker failed"))?
}

#[derive(Debug)]
struct ArtifactExportPayload {
    suggested_file_name: String,
    filter_name: &'static str,
    extension: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactExportMarker {
    format_version: u8,
    export_id: String,
    destination_path: PathBuf,
    byte_len: u64,
    sha256: String,
}

#[derive(Debug)]
struct PreparedArtifactExport {
    marker_path: PathBuf,
    staging_path: PathBuf,
}

fn prepare_artifact_export(
    state: &AppState,
    request: &ExportAssistantArtifactRequest,
) -> Result<ArtifactExportPayload, AssistantIpcError> {
    validate_identifier("artifactId", &request.artifact_id)?;
    if request.version_number <= 0 {
        return Err(AssistantIpcError::invalid_request(
            "versionNumber must be positive",
        ));
    }
    if request.format == AssistantArtifactExportFormat::LegacyMapJson {
        return Err(AssistantIpcError::new(
            "unsupported",
            "关系图仅支持导出用户可直接阅读的文字摘要。",
        ));
    }
    let connection = database::open_user_database(state.user_database_path())?;
    let artifact = database::get_artifact(&connection, &request.artifact_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "artifact not found"))?;
    let version =
        database::get_artifact_version(&connection, &request.artifact_id, request.version_number)?
            .ok_or_else(|| AssistantIpcError::new("not_found", "artifact version not found"))?;
    let conversation_id = artifact.conversation_id.as_deref().ok_or_else(|| {
        AssistantIpcError::new(
            "unsupported",
            "artifacts without a conversation cannot be exported by this workflow",
        )
    })?;
    let conversation = database::get_conversation(&connection, conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    let scope = build_assistant_validation_scope(&connection, &conversation)?;
    let draft: AssistantArtifactDraft = serde_json::from_str(&version.content_json)?;
    let (filter_name, extension, bytes) = match (&draft, request.format) {
        (
            AssistantArtifactDraft::Research(spec),
            AssistantArtifactExportFormat::ResearchMarkdown,
        ) if artifact.kind == "research" => {
            validate_research_spec(spec, &artifact.title, &scope)?;
            (
                "Markdown",
                "md",
                render_research_markdown(spec).into_bytes(),
            )
        }
        (
            AssistantArtifactDraft::Document(spec),
            AssistantArtifactExportFormat::DocumentMarkdown,
        ) if artifact.kind == "document" => {
            let rendered = assistant::render_document_markdown(spec, &scope.context)?;
            (
                "Markdown",
                "md",
                rendered
                    .as_text()
                    .expect("document markdown renderer returns text")
                    .as_bytes()
                    .to_vec(),
            )
        }
        (AssistantArtifactDraft::Document(spec), AssistantArtifactExportFormat::DocumentDocx)
            if artifact.kind == "document" =>
        {
            let rendered = assistant::render_document_docx(spec, &scope.context)?;
            (
                "Word 文档",
                "docx",
                rendered
                    .as_bytes()
                    .expect("document DOCX renderer returns bytes")
                    .to_vec(),
            )
        }
        (AssistantArtifactDraft::Map(spec), AssistantArtifactExportFormat::MapSummary)
            if artifact.kind == "map" =>
        {
            let rendered = assistant::render_map_summary(spec, &scope.context)?;
            (
                "Markdown",
                "md",
                rendered
                    .as_text()
                    .expect("map summary renderer returns text")
                    .as_bytes()
                    .to_vec(),
            )
        }
        _ => {
            return Err(AssistantIpcError::new(
                "invalid_format",
                "export format does not match the artifact kind",
            ));
        }
    };
    Ok(ArtifactExportPayload {
        suggested_file_name: format!("{}.{}", safe_export_file_stem(&artifact.title), extension),
        filter_name,
        extension,
        bytes,
    })
}

fn safe_export_file_stem(title: &str) -> String {
    let mut value = title
        .chars()
        .take(80)
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    value = value.trim_matches([' ', '.']).to_owned();
    if value.is_empty() {
        "assistant-artifact".to_owned()
    } else {
        value
    }
}

fn validate_artifact_export_destination(
    state: &AppState,
    destination: &Path,
) -> Result<(), AssistantIpcError> {
    if !path_is_normal_absolute(destination) {
        return Err(AssistantIpcError::new(
            "invalid_path",
            "export destination must be an absolute path without relative components",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        AssistantIpcError::new("invalid_path", "export destination has no parent directory")
    })?;
    if !parent.is_dir() {
        return Err(AssistantIpcError::new(
            "invalid_path",
            "export parent directory does not exist",
        ));
    }
    let app_data_directory = state.user_database_path().parent().ok_or_else(|| {
        AssistantIpcError::new("invalid_path", "application data directory is unavailable")
    })?;
    if path_is_within_directory(parent, app_data_directory) {
        return Err(AssistantIpcError::new(
            "protected_path",
            "artifacts cannot be exported into application-managed storage",
        ));
    }
    for protected in [
        state.user_database_path(),
        state.legal_core_path(),
        state.crash_log_path(),
    ] {
        if super::release::paths_refer_to_same_file(protected, destination) {
            return Err(AssistantIpcError::new(
                "protected_path",
                "export destination aliases protected application state",
            ));
        }
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(AssistantIpcError::new(
                "destination_exists",
                "artifact export never overwrites an existing destination",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(AssistantIpcError::new(
                "invalid_path",
                "export destination metadata is unavailable",
            ));
        }
    }
    Ok(())
}

fn path_is_normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn path_is_within_directory(path: &Path, directory: &Path) -> bool {
    let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canonical_directory =
        fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    let path = canonical_path.to_string_lossy().to_lowercase();
    let mut directory = canonical_directory.to_string_lossy().to_lowercase();
    if !directory.ends_with(std::path::MAIN_SEPARATOR) {
        directory.push(std::path::MAIN_SEPARATOR);
    }
    path == directory.trim_end_matches(std::path::MAIN_SEPARATOR) || path.starts_with(&directory)
}

fn write_artifact_export_atomically(
    state: &AppState,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), AssistantIpcError> {
    write_artifact_export_atomically_with_installer(state, destination, bytes, |staging, target| {
        install_artifact_export_without_overwrite(staging, target)
    })
}

fn write_artifact_export_atomically_with_installer<F>(
    state: &AppState,
    destination: &Path,
    bytes: &[u8],
    installer: F,
) -> Result<(), AssistantIpcError>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    validate_artifact_export_destination(state, destination)?;
    let prepared = prepare_artifact_export_staging(state, destination, bytes)?;
    if let Err(error) = installer(&prepared.staging_path, destination) {
        let primary = AssistantIpcError::new(
            "file_write",
            format!("artifact export could not be installed atomically: {error}"),
        );
        return Err(combine_artifact_export_cleanup_error(
            primary,
            cleanup_prepared_artifact_export(&prepared),
        ));
    }
    remove_artifact_export_file_if_exists(&prepared.marker_path).map_err(|error| {
        AssistantIpcError::new(
            "artifact_export_cleanup",
            format!(
                "artifact export completed, but its recovery marker could not be removed: {error}"
            ),
        )
    })
}

fn prepare_artifact_export_staging(
    state: &AppState,
    destination: &Path,
    bytes: &[u8],
) -> Result<PreparedArtifactExport, AssistantIpcError> {
    validate_artifact_export_destination(state, destination)?;
    let byte_len = u64::try_from(bytes.len())
        .map_err(|_| AssistantIpcError::new("limit_exceeded", "artifact export is too large"))?;
    if byte_len == 0 || byte_len > MAX_RECOVERABLE_ARTIFACT_EXPORT_BYTES {
        return Err(AssistantIpcError::new(
            "limit_exceeded",
            "artifact export exceeds the recoverable file-size limit",
        ));
    }
    let app_data_directory = state.user_database_path().parent().ok_or_else(|| {
        AssistantIpcError::new("invalid_path", "application data directory is unavailable")
    })?;
    let export_id = Uuid::new_v4().to_string();
    let marker_path = artifact_export_marker_path(app_data_directory, &export_id);
    let staging_path = artifact_export_staging_path(destination, &export_id)?;
    let marker = ArtifactExportMarker {
        format_version: 1,
        export_id,
        destination_path: destination.to_path_buf(),
        byte_len,
        sha256: artifact_export_bytes_sha256(bytes),
    };
    write_artifact_export_marker(&marker_path, &marker)?;
    let prepared = PreparedArtifactExport {
        marker_path,
        staging_path,
    };
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&prepared.staging_path)
    {
        Ok(file) => file,
        Err(error) => {
            let primary = AssistantIpcError::new(
                "file_write",
                format!("artifact export staging could not be created: {error}"),
            );
            return Err(combine_artifact_export_cleanup_error(
                primary,
                remove_artifact_export_file_if_exists(&prepared.marker_path).map_err(|error| {
                    AssistantIpcError::new("artifact_export_cleanup", error.to_string())
                }),
            ));
        }
    };
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let primary = AssistantIpcError::new(
            "file_write",
            format!("artifact export staging could not be completed: {error}"),
        );
        return Err(combine_artifact_export_cleanup_error(
            primary,
            cleanup_prepared_artifact_export(&prepared),
        ));
    }
    Ok(prepared)
}

fn artifact_export_marker_path(app_data_directory: &Path, export_id: &str) -> PathBuf {
    app_data_directory.join(format!("{ARTIFACT_EXPORT_MARKER_PREFIX}{export_id}.json"))
}

fn artifact_export_staging_path(
    destination: &Path,
    export_id: &str,
) -> Result<PathBuf, AssistantIpcError> {
    let parent = destination.parent().ok_or_else(|| {
        AssistantIpcError::new("invalid_path", "export destination has no parent directory")
    })?;
    Ok(parent.join(format!(
        "{ARTIFACT_EXPORT_STAGING_PREFIX}{export_id}.staging"
    )))
}

fn write_artifact_export_marker(
    marker_path: &Path,
    marker: &ArtifactExportMarker,
) -> Result<(), AssistantIpcError> {
    let bytes = serde_json::to_vec(marker)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)
        .map_err(|error| AssistantIpcError::new("file_write", error.to_string()))?;
    let result = (|| -> Result<(), AssistantIpcError> {
        file.write_all(&bytes)
            .map_err(|error| AssistantIpcError::new("file_write", error.to_string()))?;
        file.sync_all()
            .map_err(|error| AssistantIpcError::new("file_write", error.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(marker_path);
    }
    result
}

fn install_artifact_export_without_overwrite(
    staging: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    if staging.parent() != destination.parent() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact export staging and destination must be siblings",
        ));
    }
    let staging = staging
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let succeeded = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(
            staging.as_ptr(),
            destination.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cleanup_prepared_artifact_export(
    prepared: &PreparedArtifactExport,
) -> Result<(), AssistantIpcError> {
    remove_artifact_export_file_if_exists(&prepared.staging_path)
        .map_err(|error| AssistantIpcError::new("artifact_export_cleanup", error.to_string()))?;
    remove_artifact_export_file_if_exists(&prepared.marker_path)
        .map_err(|error| AssistantIpcError::new("artifact_export_cleanup", error.to_string()))
}

fn remove_artifact_export_file_if_exists(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn combine_artifact_export_cleanup_error(
    primary: AssistantIpcError,
    cleanup: Result<(), AssistantIpcError>,
) -> AssistantIpcError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => AssistantIpcError::new(
            "artifact_export_cleanup",
            format!(
                "{}; recovery marker retained because cleanup failed: {}",
                primary.message, cleanup.message
            ),
        ),
    }
}

fn artifact_export_bytes_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Removes only an application-namespaced staging path derived from a validated
/// marker; complete files must also match their recorded length and hash. The
/// destination is never deleted or replaced during recovery.
pub fn recover_pending_assistant_artifact_exports(
    app_local_data_dir: &Path,
) -> Result<usize, AssistantIpcError> {
    if !app_local_data_dir.is_dir() {
        return Ok(0);
    }
    let mut recovered = 0usize;
    for entry in fs::read_dir(app_local_data_dir)
        .map_err(|error| AssistantIpcError::new("artifact_export_recovery", error.to_string()))?
    {
        let entry = entry.map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(ARTIFACT_EXPORT_MARKER_PREFIX) || !file_name.ends_with(".json") {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export marker must be an ordinary file",
            ));
        }
        let metadata = entry.metadata().map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        if metadata.len() > MAX_ARTIFACT_EXPORT_MARKER_BYTES {
            return Err(AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export marker is too large",
            ));
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).unwrap_or(MAX_ARTIFACT_EXPORT_MARKER_BYTES as usize),
        );
        File::open(entry.path())
            .map_err(|error| AssistantIpcError::new("artifact_export_recovery", error.to_string()))?
            .take(MAX_ARTIFACT_EXPORT_MARKER_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AssistantIpcError::new("artifact_export_recovery", error.to_string())
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARTIFACT_EXPORT_MARKER_BYTES {
            return Err(AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export marker is too large",
            ));
        }
        let marker = serde_json::from_slice::<ArtifactExportMarker>(&bytes).map_err(|_| {
            AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export marker is invalid",
            )
        })?;
        let staging_path =
            validate_artifact_export_marker(&marker, &entry.path(), app_local_data_dir)?;
        match fs::symlink_metadata(&staging_path) {
            Ok(staging_metadata) => {
                if staging_metadata.file_type().is_symlink()
                    || !staging_metadata.file_type().is_file()
                    || staging_metadata.len() > marker.byte_len
                {
                    return Err(AssistantIpcError::new(
                        "artifact_export_recovery",
                        "artifact export staging file could not be verified",
                    ));
                }
                // A shorter file is a recognizable interrupted write because
                // its random name is derived from the validated marker id. A
                // full-length file must additionally match the recorded hash.
                if staging_metadata.len() == marker.byte_len
                    && artifact_export_file_sha256(&staging_path)? != marker.sha256
                {
                    return Err(AssistantIpcError::new(
                        "artifact_export_recovery",
                        "artifact export staging file hash does not match its marker",
                    ));
                }
                remove_artifact_export_file_if_exists(&staging_path).map_err(|error| {
                    AssistantIpcError::new("artifact_export_recovery", error.to_string())
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(AssistantIpcError::new(
                    "artifact_export_recovery",
                    error.to_string(),
                ));
            }
        }
        remove_artifact_export_file_if_exists(&entry.path()).map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        recovered = recovered.saturating_add(1);
    }
    Ok(recovered)
}

pub(crate) fn pending_assistant_artifact_export_marker_count_read_only(
    app_local_data_dir: &Path,
) -> Result<u64, AssistantIpcError> {
    if !app_local_data_dir.is_dir() {
        return Ok(0);
    }
    let mut count = 0_u64;
    for entry in fs::read_dir(app_local_data_dir)
        .map_err(|error| AssistantIpcError::new("artifact_export_recovery", error.to_string()))?
    {
        let entry = entry.map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(ARTIFACT_EXPORT_MARKER_PREFIX) || !file_name.ends_with(".json") {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export marker must be an ordinary file",
            ));
        }
        count = count.checked_add(1).ok_or_else(|| {
            AssistantIpcError::new("artifact_export_recovery", "marker count overflow")
        })?;
    }
    Ok(count)
}

fn validate_artifact_export_marker(
    marker: &ArtifactExportMarker,
    marker_path: &Path,
    app_local_data_dir: &Path,
) -> Result<PathBuf, AssistantIpcError> {
    let parsed_id = Uuid::parse_str(&marker.export_id).map_err(|_| {
        AssistantIpcError::new(
            "artifact_export_recovery",
            "artifact export marker id is invalid",
        )
    })?;
    let valid_digest = marker.sha256.len() == 64
        && marker
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let valid_extension = marker
        .destination_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "md" | "docx" | "json"
            )
        });
    if marker.format_version != 1
        || parsed_id.to_string() != marker.export_id
        || marker.byte_len == 0
        || marker.byte_len > MAX_RECOVERABLE_ARTIFACT_EXPORT_BYTES
        || !valid_digest
        || !valid_extension
        || !path_is_normal_absolute(&marker.destination_path)
    {
        return Err(AssistantIpcError::new(
            "artifact_export_recovery",
            "artifact export marker contract is invalid",
        ));
    }
    if artifact_export_marker_path(app_local_data_dir, &marker.export_id) != marker_path {
        return Err(AssistantIpcError::new(
            "artifact_export_recovery",
            "artifact export marker filename does not match its id",
        ));
    }
    let destination_parent = marker.destination_path.parent().ok_or_else(|| {
        AssistantIpcError::new(
            "artifact_export_recovery",
            "artifact export destination has no parent",
        )
    })?;
    if !destination_parent.is_dir()
        || path_is_within_directory(destination_parent, app_local_data_dir)
    {
        return Err(AssistantIpcError::new(
            "artifact_export_recovery",
            "artifact export destination directory is invalid",
        ));
    }
    artifact_export_staging_path(&marker.destination_path, &marker.export_id)
}

fn artifact_export_file_sha256(path: &Path) -> Result<String, AssistantIpcError> {
    let mut file = File::open(path)
        .map_err(|error| AssistantIpcError::new("artifact_export_recovery", error.to_string()))?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            AssistantIpcError::new("artifact_export_recovery", error.to_string())
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).expect("buffer read length fits u64"));
        if total > MAX_RECOVERABLE_ARTIFACT_EXPORT_BYTES {
            return Err(AssistantIpcError::new(
                "artifact_export_recovery",
                "artifact export staging file is too large",
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[tauri::command]
pub async fn import_assistant_files(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    request: ImportAssistantFilesRequest,
) -> Result<ImportAssistantFilesResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    let conversation = database::get_conversation(&connection, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    if conversation.status != "open" {
        return Err(AssistantIpcError::new(
            "conflict",
            "archived conversations cannot accept attachments",
        ));
    }
    drop(connection);

    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("选择要交给助理的材料（最多 2 个）")
            .add_filter("支持的材料", &["pdf", "docx", "txt", "md", "markdown"])
            .blocking_pick_files();
        let Some(selected) = selected else {
            return Ok(ImportAssistantFilesResponse {
                cancelled: true,
                duplicate_count: 0,
                message: None,
                attachments: Vec::new(),
            });
        };
        if selected.is_empty() {
            return Ok(ImportAssistantFilesResponse {
                cancelled: true,
                duplicate_count: 0,
                message: None,
                attachments: Vec::new(),
            });
        }
        if selected.len() > MAX_FILES_PER_IMPORT {
            return Err(AssistantIpcError::new(
                "limit_exceeded",
                "at most two files can be imported in one assistant action",
            ));
        }
        let files = selected
            .into_iter()
            .map(|file_path| {
                let path = file_path.into_path().map_err(|_| {
                    AssistantIpcError::new("invalid_path", "selected file is not a local file")
                })?;
                read_bounded_selected_file(&path)
            })
            .collect::<Result<Vec<_>, _>>()?;
        import_assistant_files_inner(&state, request, files)
    })
    .await
    .map_err(|_| AssistantIpcError::new("runtime", "file import worker failed"))?
}

#[derive(Debug)]
struct SelectedFileBytes {
    file_name: String,
    bytes: Vec<u8>,
}

fn read_bounded_selected_file(path: &Path) -> Result<SelectedFileBytes, AssistantIpcError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AssistantIpcError::new("invalid_file_name", "file name is not valid UTF-8"))?
        .to_owned();
    file_ingest::detect_format(&file_name)?;
    let mut file = File::open(path)
        .map_err(|_| AssistantIpcError::new("file_read", "selected file could not be opened"))?;
    let metadata = file.metadata().map_err(|_| {
        AssistantIpcError::new("file_read", "selected file metadata is unavailable")
    })?;
    if !metadata.is_file() {
        return Err(AssistantIpcError::new(
            "invalid_path",
            "selected item is not a regular file",
        ));
    }
    if metadata.len() > file_ingest::MAX_FILE_BYTES as u64 {
        return Err(file_ingest::IngestError::FileTooLarge.into());
    }
    let read_limit = u64::try_from(file_ingest::MAX_FILE_BYTES)
        .expect("file ingest byte limit fits u64")
        .saturating_add(1);
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(file_ingest::MAX_FILE_BYTES));
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| AssistantIpcError::new("file_read", "selected file could not be read"))?;
    if bytes.len() > file_ingest::MAX_FILE_BYTES {
        return Err(file_ingest::IngestError::FileTooLarge.into());
    }
    Ok(SelectedFileBytes { file_name, bytes })
}

fn import_assistant_files_inner(
    state: &AppState,
    request: ImportAssistantFilesRequest,
    files: Vec<SelectedFileBytes>,
) -> Result<ImportAssistantFilesResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    if files.is_empty() || files.len() > MAX_FILES_PER_IMPORT {
        return Err(AssistantIpcError::invalid_request(
            "one or two files are required",
        ));
    }
    let extracted = files
        .into_iter()
        .map(|file| {
            let document = file_ingest::ingest_bytes(&file.file_name, &file.bytes)?;
            Ok((file.bytes, document))
        })
        .collect::<Result<Vec<_>, AssistantIpcError>>()?;

    let mut connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let conversation = database::get_conversation(&transaction, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    if conversation.status != "open" {
        return Err(AssistantIpcError::new(
            "conflict",
            "archived conversations cannot accept attachments",
        ));
    }
    let mut duplicate_count = 0usize;
    let mut rows = Vec::new();
    let mut seen_attachment_ids = std::collections::HashSet::new();
    for (bytes, document) in extracted {
        let segments_json = serde_json::to_string(
            &document
                .segments
                .iter()
                .map(|segment| {
                    serde_json::json!({
                        "locator": segment.locator,
                        "text": segment.text,
                    })
                })
                .collect::<Vec<_>>(),
        )?;
        let new_attachment = database::NewAttachmentRow {
            attachment_id: format!("attachment:{}", Uuid::new_v4()),
            project_id: conversation.project_id.clone(),
            original_name: document.file_name,
            extension: document.format.as_str().to_owned(),
            detected_mime: document.mime_type,
            sha256: document.sha256_hex,
            size_bytes: i64::try_from(document.size_bytes).map_err(|_| {
                AssistantIpcError::new("limit_exceeded", "attachment size is unsupported")
            })?,
            content_blob: bytes,
            extraction_status: "succeeded".to_owned(),
            extracted_text: Some(document.text),
            segments_json,
            error_code: None,
        };
        let row = match database::insert_attachment(&transaction, &new_attachment)? {
            database::AttachmentInsertResult::Inserted(row) => row,
            database::AttachmentInsertResult::Existing(row) => {
                duplicate_count = duplicate_count.saturating_add(1);
                row
            }
        };
        if seen_attachment_ids.insert(row.attachment_id.clone()) {
            rows.push(row);
        }
    }

    let message = database::create_message(
        &transaction,
        &database::NewMessageRow {
            message_id: format!("message:{}", Uuid::new_v4()),
            conversation_id: request.conversation_id,
            role: "user".to_owned(),
            kind: "text".to_owned(),
            text_summary: if rows.len() == 1 {
                format!("已导入材料：{}", rows[0].original_name)
            } else {
                format!("已导入 {} 份材料", rows.len())
            },
            artifact_id: None,
            run_id: None,
        },
    )?;
    for (ordinal, row) in rows.iter().enumerate() {
        database::attach_to_message(
            &transaction,
            &message.message_id,
            &row.attachment_id,
            i64::try_from(ordinal).expect("two-file ordinal fits i64"),
        )?;
    }
    let message = message_from_row(&transaction, message)?;
    let attachments = rows
        .into_iter()
        .map(attachment_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit()?;
    Ok(ImportAssistantFilesResponse {
        cancelled: false,
        duplicate_count,
        message: Some(message),
        attachments,
    })
}

#[tauri::command]
pub fn delete_assistant_attachment(
    state: State<'_, AppState>,
    request: DeleteAssistantAttachmentRequest,
) -> Result<DeleteAssistantAttachmentResponse, AssistantIpcError> {
    delete_assistant_attachment_inner(state.inner(), request)
}

fn delete_assistant_attachment_inner(
    state: &AppState,
    request: DeleteAssistantAttachmentRequest,
) -> Result<DeleteAssistantAttachmentResponse, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_identifier("attachmentId", &request.attachment_id)?;
    if !request.user_confirmed {
        return Err(AssistantIpcError::new(
            "confirmation_required",
            "explicit user confirmation is required before permanently deleting an attachment",
        ));
    }
    let mut connection = database::open_user_database(state.user_database_path())?;
    match database::delete_attachment_from_conversation(
        &mut connection,
        &request.conversation_id,
        &request.attachment_id,
    )? {
        database::AttachmentDeleteResult::Deleted => {
            Ok(DeleteAssistantAttachmentResponse {
                attachment_id: request.attachment_id,
                deleted: true,
            })
        }
        database::AttachmentDeleteResult::InUse => Err(AssistantIpcError::new(
            "conflict",
            "attachment is still referenced by another message, artifact, proposal, or case file",
        )),
        database::AttachmentDeleteResult::NotFound => Err(AssistantIpcError::new(
            "not_found",
            "attachment is missing, the conversation is archived, or the attachment is not linked to this conversation",
        )),
    }
}

#[tauri::command]
pub fn create_assistant_case_change_proposal(
    state: State<'_, AppState>,
    request: CreateAssistantCaseChangeProposalRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    create_assistant_case_change_proposal_inner(state.inner(), request)
}

pub(super) fn create_assistant_case_change_proposal_inner(
    state: &AppState,
    request: CreateAssistantCaseChangeProposalRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    let mut connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let conversation = database::get_conversation(&transaction, &request.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    let row = create_assistant_case_change_proposal_with_connection(
        state,
        &transaction,
        &conversation,
        &request,
        None,
    )?;
    transaction.commit()?;
    Ok(AssistantCaseChangeProposalResponse {
        proposal: proposal_from_row(row)?,
    })
}

/// Shared by the direct IPC command and the run finalizer. Passing a
/// transaction keeps proposal creation atomic with the assistant message and
/// run CAS performed by the orchestrator.
pub(super) fn create_assistant_case_change_proposal_with_connection(
    state: &AppState,
    connection: &rusqlite::Connection,
    conversation: &database::ConversationRow,
    request: &CreateAssistantCaseChangeProposalRequest,
    trusted_run_id: Option<&str>,
) -> Result<database::CaseChangeProposalRow, AssistantIpcError> {
    validate_identifier("conversationId", &request.conversation_id)?;
    validate_identifier("projectId", &request.project_id)?;
    if let Some(run_id) = trusted_run_id {
        validate_run_id(run_id)?;
    }
    if conversation.conversation_id != request.conversation_id {
        return Err(AssistantIpcError::new(
            "conflict",
            "conversation does not match the proposal request",
        ));
    }
    if conversation.status != "open"
        || conversation.project_id.as_deref() != Some(request.project_id.as_str())
    {
        return Err(AssistantIpcError::new(
            "conflict",
            "conversation must be open and bound to the requested case",
        ));
    }
    if let Some(run_id) = trusted_run_id {
        let run = database::get_agent_run(connection, run_id)?
            .ok_or_else(|| AssistantIpcError::new("not_found", "assistant run not found"))?;
        if run.conversation_id != request.conversation_id
            || run.intent != "case_analysis"
            || !matches!(run.status.as_str(), "running" | "succeeded")
        {
            return Err(AssistantIpcError::new(
                "conflict",
                "assistant run is not eligible to originate this case proposal",
            ));
        }
    }

    let scope = build_assistant_validation_scope(connection, conversation)?;
    validate_case_change_spec(state, &request.changes, &scope)?;
    let base_case_digest = database::case_workspace_digest(connection, &request.project_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "case project not found"))?;
    let allowed_source_refs = scope.source_refs.iter().cloned().collect::<Vec<_>>();
    let service_proposal = state
        .legal_services()?
        .case_propose_patch_with_allowed_sources_in_transaction(
            connection,
            legal_services::CaseProposePatchRequest {
                schema_version: legal_services::SERVICE_SCHEMA_VERSION,
                project_id: request.project_id.clone(),
                base_revision: base_case_digest.clone(),
                changes: request.changes.clone(),
                project_bootstrap: None,
                material_imports: Vec::new(),
            },
            &allowed_source_refs,
        )?;
    let canonical_proposal = serde_json::from_str::<legal_services::CanonicalCaseProposal>(
        &service_proposal.canonical_proposal,
    )?;
    Ok(database::create_case_change_proposal(
        connection,
        &database::NewCaseChangeProposalRow {
            proposal_id: format!("proposal:{}", Uuid::new_v4()),
            conversation_id: request.conversation_id.clone(),
            project_id: request.project_id.clone(),
            run_id: trusted_run_id.map(str::to_owned),
            base_case_digest,
            changes_json: serde_json::to_string(&request.changes)?,
            source_refs_json: serde_json::to_string(&canonical_proposal.source_refs)?,
        },
    )?)
}

#[tauri::command]
pub fn reject_assistant_case_change_proposal(
    state: State<'_, AppState>,
    request: RejectAssistantCaseChangeProposalRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    reject_assistant_case_change_proposal_inner(state.inner(), request)
}

fn reject_assistant_case_change_proposal_inner(
    state: &AppState,
    request: RejectAssistantCaseChangeProposalRequest,
) -> Result<AssistantCaseChangeProposalResponse, AssistantIpcError> {
    validate_identifier("proposalId", &request.proposal_id)?;
    validate_identifier("projectId", &request.project_id)?;
    let connection = database::open_user_database(state.user_database_path())?;
    let row = database::get_case_change_proposal(&connection, &request.proposal_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "case change proposal not found"))?;
    if row.project_id != request.project_id {
        return Err(proposal_conflict_error());
    }
    match database::compare_and_set_case_change_proposal_status(
        &connection,
        &request.proposal_id,
        &request.project_id,
        &row.base_case_digest,
        "rejected",
    )? {
        database::CaseChangeProposalStatusUpdateResult::Updated(row) => {
            Ok(AssistantCaseChangeProposalResponse {
                proposal: proposal_from_row(row)?,
            })
        }
        database::CaseChangeProposalStatusUpdateResult::Conflict(_) => {
            Err(proposal_conflict_error())
        }
        database::CaseChangeProposalStatusUpdateResult::NotFound => Err(AssistantIpcError::new(
            "not_found",
            "case change proposal not found",
        )),
    }
}

#[tauri::command]
pub fn apply_assistant_case_change_proposal(
    state: State<'_, AppState>,
    request: ApplyAssistantCaseChangeProposalRequest,
) -> Result<ApplyAssistantCaseChangeProposalResponse, AssistantIpcError> {
    apply_assistant_case_change_proposal_inner(state.inner(), request)
}

fn apply_assistant_case_change_proposal_inner(
    state: &AppState,
    request: ApplyAssistantCaseChangeProposalRequest,
) -> Result<ApplyAssistantCaseChangeProposalResponse, AssistantIpcError> {
    validate_identifier("proposalId", &request.proposal_id)?;
    validate_identifier("projectId", &request.project_id)?;
    if !request.user_confirmed {
        return Err(AssistantIpcError::new(
            "confirmation_required",
            "explicit user confirmation is required before applying case changes",
        ));
    }

    let mut connection = database::open_user_database(state.user_database_path())?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let row = database::get_case_change_proposal(&transaction, &request.proposal_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "case change proposal not found"))?;
    if row.project_id != request.project_id || row.status != "pending" {
        return Err(proposal_conflict_error());
    }
    let conversation = database::get_conversation(&transaction, &row.conversation_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "conversation not found"))?;
    if conversation.status != "open"
        || conversation.project_id.as_deref() != Some(request.project_id.as_str())
    {
        return Err(proposal_conflict_error());
    }

    let current_digest = database::case_workspace_digest(&transaction, &request.project_id)?
        .ok_or_else(|| AssistantIpcError::new("not_found", "case project not found"))?;
    if current_digest != row.base_case_digest {
        let updated = database::compare_and_set_case_change_proposal_status(
            &transaction,
            &request.proposal_id,
            &request.project_id,
            &row.base_case_digest,
            "stale",
        )?;
        let proposal = match updated {
            database::CaseChangeProposalStatusUpdateResult::Updated(row) => proposal_from_row(row)?,
            database::CaseChangeProposalStatusUpdateResult::Conflict(_) => {
                return Err(proposal_conflict_error());
            }
            database::CaseChangeProposalStatusUpdateResult::NotFound => {
                return Err(AssistantIpcError::new(
                    "not_found",
                    "case change proposal not found",
                ));
            }
        };
        transaction.commit()?;
        return Ok(ApplyAssistantCaseChangeProposalResponse {
            proposal,
            applied: false,
            stale: true,
        });
    }

    let changes = serde_json::from_str::<assistant::CaseChangeSpec>(&row.changes_json)?;
    let expected_source_refs = collect_case_change_source_refs(&changes);
    let persisted_source_refs = serde_json::from_str::<Vec<String>>(&row.source_refs_json)?;
    let persisted_user_source_refs = persisted_source_refs
        .iter()
        .filter(|source_ref| !legal_services::is_case_proposal_snapshot_ref(source_ref))
        .cloned()
        .collect::<Vec<_>>();
    if persisted_user_source_refs != expected_source_refs {
        return Err(AssistantIpcError::new(
            "invalid_proposal",
            "case change proposal source audit is inconsistent",
        ));
    }
    let scope = build_assistant_validation_scope(&transaction, &conversation)?;
    validate_case_change_spec(state, &changes, &scope)?;
    let canonical_proposal = serde_json::to_string(&legal_services::CanonicalCaseProposal {
        schema_version: legal_services::SERVICE_SCHEMA_VERSION,
        project_id: request.project_id.clone(),
        base_revision: row.base_case_digest.clone(),
        changes,
        source_refs: persisted_source_refs,
        project_bootstrap: None,
        material_imports: Vec::new(),
    })?;
    let proposal_hash = format!("{:x}", Sha256::digest(canonical_proposal.as_bytes()));
    let allowed_source_refs = scope.source_refs.iter().cloned().collect::<Vec<_>>();
    state
        .legal_services()?
        .case_apply_patch_with_allowed_sources_in_transaction(
            &transaction,
            legal_services::CaseApplyPatchRequest {
                schema_version: legal_services::SERVICE_SCHEMA_VERSION,
                project_id: request.project_id.clone(),
                canonical_proposal,
                proposal_hash,
                expected_revision: row.base_case_digest.clone(),
                confirmed: request.user_confirmed,
                idempotency_key: format!("desktop:assistant:{}", row.proposal_id),
            },
            legal_services::ServiceOrigin::Desktop,
            &allowed_source_refs,
        )?;

    let updated = database::compare_and_set_case_change_proposal_status(
        &transaction,
        &request.proposal_id,
        &request.project_id,
        &row.base_case_digest,
        "applied",
    )?;
    let proposal = match updated {
        database::CaseChangeProposalStatusUpdateResult::Updated(row) => proposal_from_row(row)?,
        database::CaseChangeProposalStatusUpdateResult::Conflict(_) => {
            return Err(proposal_conflict_error());
        }
        database::CaseChangeProposalStatusUpdateResult::NotFound => {
            return Err(AssistantIpcError::new(
                "not_found",
                "case change proposal not found",
            ));
        }
    };
    transaction.commit()?;
    Ok(ApplyAssistantCaseChangeProposalResponse {
        proposal,
        applied: true,
        stale: false,
    })
}

fn proposal_conflict_error() -> AssistantIpcError {
    AssistantIpcError::new(
        "conflict",
        "case change proposal is terminal, missing from this case, or was already decided",
    )
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct ValidatedLegalBasisSource {
    source: LegalSource,
    status: CitationStatus,
    invalid_reason: Option<CitationInvalidReason>,
    case_date: Option<String>,
}

pub(super) fn validate_case_change_spec(
    state: &AppState,
    changes: &assistant::CaseChangeSpec,
    scope: &AssistantValidationScope,
) -> Result<std::collections::BTreeMap<String, ValidatedLegalBasisSource>, AssistantIpcError> {
    changes.validate(&scope.context)?;
    for fact in &changes.facts {
        if fact
            .occurred_on
            .as_deref()
            .is_some_and(|date| !domain::date::is_iso_calendar_date(date))
        {
            return Err(AssistantIpcError::invalid_request(
                "occurredOn must be a valid YYYY-MM-DD calendar date",
            ));
        }
    }
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let current_date =
        legal_connection.query_row("SELECT date('now', 'localtime')", [], |row| {
            row.get::<_, String>(0)
        })?;
    let mut legal_sources = std::collections::BTreeMap::new();
    for basis in &changes.legal_basis {
        if legal_sources.contains_key(&basis.source_ref) {
            continue;
        }
        let source = citations::source_by_citation_id(&legal_connection, &basis.source_ref)?
            .ok_or_else(|| {
                AssistantIpcError::new(
                    "unvalidated_legal_source",
                    "legal basis is not present in the local legal source set",
                )
            })?;
        let validation = citations::validate_answer_citations(
            &legal_connection,
            &basis.marker,
            std::slice::from_ref(&source),
            None,
            false,
        )?;
        let mut citations = validation.citations.into_iter();
        let citation = citations.next().ok_or_else(|| {
            AssistantIpcError::new(
                "unvalidated_legal_source",
                "legal basis citation did not produce a validation result",
            )
        })?;
        if citations.next().is_some()
            || citation.source_id != basis.source_ref
            || citation.status != CitationStatus::Valid
        {
            return Err(AssistantIpcError::new(
                "unvalidated_legal_source",
                "legal basis is not a currently valid local legal source",
            ));
        }
        let source = citation.source.ok_or_else(|| {
            AssistantIpcError::new(
                "unvalidated_legal_source",
                "validated legal basis is missing its local source snapshot",
            )
        })?;
        if !domain::date::is_iso_calendar_date(&source.effective_from)
            || source
                .effective_to
                .as_deref()
                .is_some_and(|effective_to| !domain::date::is_iso_calendar_date(effective_to))
            || source.effective_from.as_str() > current_date.as_str()
            || source
                .effective_to
                .as_deref()
                .is_some_and(|effective_to| effective_to < current_date.as_str())
        {
            return Err(AssistantIpcError::new(
                "unvalidated_legal_source",
                "legal basis is outside its current effective date range",
            ));
        }
        legal_sources.insert(
            basis.source_ref.clone(),
            ValidatedLegalBasisSource {
                source,
                status: citation.status,
                invalid_reason: citation.reason,
                case_date: None,
            },
        );
    }
    Ok(legal_sources)
}

fn collect_case_change_source_refs(changes: &assistant::CaseChangeSpec) -> Vec<String> {
    changes
        .facts
        .iter()
        .flat_map(|fact| fact.source_refs.iter().cloned())
        .chain(
            changes
                .evidence
                .iter()
                .flat_map(|evidence| evidence.source_refs.iter().cloned()),
        )
        .chain(
            changes
                .issues
                .iter()
                .flat_map(|issue| issue.source_refs.iter().cloned()),
        )
        .chain(
            changes
                .legal_basis
                .iter()
                .map(|basis| basis.source_ref.clone()),
        )
        .chain(
            changes
                .attachment_transfers
                .iter()
                .map(|transfer| transfer.attachment_id.clone()),
        )
        .chain(
            changes
                .artifact_transfers
                .iter()
                .map(|transfer| transfer.artifact_id.clone()),
        )
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[tauri::command]
pub fn cancel_assistant_run(
    state: State<'_, AppState>,
    request: CancelAssistantRunRequest,
) -> Result<CancelAssistantRunResponse, AssistantIpcError> {
    cancel_assistant_run_inner(state.inner(), request)
}

fn cancel_assistant_run_inner(
    state: &AppState,
    request: CancelAssistantRunRequest,
) -> Result<CancelAssistantRunResponse, AssistantIpcError> {
    validate_run_id(&request.run_id)?;
    let cancelled = state.cancel_assistant_run(&request.run_id);
    Ok(CancelAssistantRunResponse {
        run_id: request.run_id,
        cancelled,
    })
}

fn validate_run_id(run_id: &str) -> Result<(), AssistantIpcError> {
    if run_id.is_empty()
        || run_id.len() > MAX_RUN_ID_BYTES
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(AssistantIpcError::invalid_request(
            "runId must be a bounded opaque identifier",
        ));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), AssistantIpcError> {
    if value.is_empty()
        || value.len() > MAX_ASSISTANT_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(AssistantIpcError::invalid_request(match field {
            "conversationId" => "conversationId must be a bounded opaque identifier",
            "projectId" => "projectId must be a bounded opaque identifier",
            "artifactId" => "artifactId must be a bounded opaque identifier",
            "proposalId" => "proposalId must be a bounded opaque identifier",
            _ => "identifier must be a bounded opaque identifier",
        }));
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    multiline: bool,
) -> Result<(), AssistantIpcError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(AssistantIpcError::invalid_request(match field {
            "title" => "title must be non-empty and within its byte limit",
            "sourceId" => "sourceId must be non-empty and within its byte limit",
            _ => "text must be non-empty and within its byte limit",
        }));
    }
    if value.chars().any(|character| {
        character.is_control() && !(multiline && matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(AssistantIpcError::invalid_request(
            "text contains a disallowed control character",
        ));
    }
    Ok(())
}

fn conversation_from_row(row: database::ConversationRow) -> AssistantConversation {
    AssistantConversation {
        conversation_id: row.conversation_id,
        project_id: row.project_id,
        title: row.title,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn message_from_row(
    connection: &rusqlite::Connection,
    row: database::MessageRow,
) -> Result<AssistantMessage, AssistantIpcError> {
    let attachments = database::list_attachments_for_message(connection, &row.message_id)?
        .into_iter()
        .map(attachment_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AssistantMessage {
        message_id: row.message_id,
        conversation_id: row.conversation_id,
        role: row.role,
        kind: row.kind,
        text_summary: row.text_summary,
        artifact_id: row.artifact_id,
        run_id: row.run_id,
        created_at: row.created_at,
        attachments,
    })
}

fn attachment_from_row(
    row: database::AttachmentRow,
) -> Result<AssistantAttachment, AssistantIpcError> {
    let segments = serde_json::from_str::<Vec<serde_json::Value>>(&row.segments_json)?;
    Ok(AssistantAttachment {
        attachment_id: row.attachment_id,
        project_id: row.project_id,
        original_name: row.original_name,
        extension: row.extension,
        detected_mime: row.detected_mime,
        sha256: row.sha256,
        size_bytes: row.size_bytes,
        extraction_status: row.extraction_status,
        error_code: row.error_code,
        segment_count: segments.len(),
        created_at: row.created_at,
    })
}

pub(super) fn artifact_from_row(row: database::ArtifactRow) -> AssistantArtifact {
    AssistantArtifact {
        artifact_id: row.artifact_id,
        conversation_id: row.conversation_id,
        project_id: row.project_id,
        kind: row.kind,
        title: row.title,
        status: row.status,
        current_version: row.current_version,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn artifact_version_from_row(
    row: database::ArtifactVersionRow,
) -> Result<AssistantArtifactVersion, AssistantIpcError> {
    Ok(AssistantArtifactVersion {
        version_id: row.version_id,
        artifact_id: row.artifact_id,
        version_number: row.version_number,
        content: serde_json::from_str(&row.content_json)?,
        rendered_text: row.rendered_text,
        source_refs: serde_json::from_str(&row.source_refs_json)?,
        citation_report: serde_json::from_str(&row.citation_report_json)?,
        provider_snapshot: serde_json::from_str(&row.provider_snapshot_json)?,
        created_at: row.created_at,
    })
}

pub(super) fn run_from_row(
    connection: &rusqlite::Connection,
    row: database::AgentRunRow,
) -> Result<AssistantRun, AssistantIpcError> {
    let tool_calls = database::list_tool_calls(connection, &row.run_id)?
        .into_iter()
        .map(tool_call_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AssistantRun {
        run_id: row.run_id,
        conversation_id: row.conversation_id,
        user_message_id: row.user_message_id,
        assistant_message_id: row.assistant_message_id,
        provider_id: row.provider_id,
        provider_snapshot: serde_json::from_str(&row.provider_snapshot_json)?,
        intent: row.intent,
        status: row.status,
        budget: serde_json::from_str(&row.budget_json)?,
        error_type: row.error_type,
        created_at: row.created_at,
        finished_at: row.finished_at,
        tool_calls,
    })
}

fn tool_call_from_row(row: database::ToolCallRow) -> Result<AssistantToolCall, AssistantIpcError> {
    Ok(AssistantToolCall {
        tool_call_id: row.tool_call_id,
        run_id: row.run_id,
        ordinal: row.ordinal,
        capability_name: row.capability_name,
        status: row.status,
        access_mode: row.access_mode,
        requires_confirmation: row.requires_confirmation,
        input_audit: serde_json::from_str(&row.input_audit_json)?,
        output_audit: serde_json::from_str(&row.output_audit_json)?,
        source_audit: serde_json::from_str(&row.source_audit_json)?,
        error_type: row.error_type,
        started_at: row.started_at,
        finished_at: row.finished_at,
    })
}

pub(super) fn proposal_from_row(
    row: database::CaseChangeProposalRow,
) -> Result<AssistantCaseChangeProposal, AssistantIpcError> {
    let source_refs = serde_json::from_str::<Vec<String>>(&row.source_refs_json)?
        .into_iter()
        .filter(|source_ref| !legal_services::is_case_proposal_snapshot_ref(source_ref))
        .collect();
    Ok(AssistantCaseChangeProposal {
        proposal_id: row.proposal_id,
        conversation_id: row.conversation_id,
        project_id: row.project_id,
        run_id: row.run_id,
        base_case_digest: row.base_case_digest,
        status: row.status,
        changes: serde_json::from_str(&row.changes_json)?,
        source_refs,
        created_at: row.created_at,
        decided_at: row.decided_at,
        applied_at: row.applied_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn legacy_assistant_artifact_export_is_disabled_without_exact_privacy_receipt() {
        let error = require_privacy_safe_artifact_export().unwrap_err();
        assert_eq!(error.error_type, "privacy_required");
        assert!(error.message.contains("privacy workbench"));
        assert!(!error.message.contains("artifact_id"));
    }
    fn state() -> AppState {
        AppState::new(PathBuf::from("legal.sqlite"), PathBuf::from("user.sqlite"))
    }

    fn initialized_state() -> (TempDir, AppState) {
        let directory = tempfile::tempdir().expect("temporary directory exists");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("user database initializes");
        let legal_core_path = directory.path().join("legal-core.sqlite");
        let legal_connection =
            rusqlite::Connection::open(&legal_core_path).expect("legal fixture opens");
        database::initialize_legal_core_database(&legal_connection)
            .expect("legal fixture schema initializes");
        legal_connection
            .execute_batch(include_str!(
                "../../../../../data/fixtures/legal_core_retrieval_fixture.sql"
            ))
            .expect("legal retrieval fixture loads");
        drop(legal_connection);
        (
            directory,
            AppState::new(legal_core_path, user_database_path),
        )
    }

    fn insert_project(state: &AppState, project_id: &str) {
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::upsert_case_project(
            &connection,
            &database::CaseProjectRow {
                project_id: project_id.to_owned(),
                title: format!("案件 {project_id}"),
                case_type: "合同纠纷".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("project inserts");
    }

    fn insert_case_material(state: &AppState, project_id: &str, file_id: &str) {
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::upsert_case_file(
            &connection,
            &database::CaseFileRow {
                file_id: file_id.to_owned(),
                project_id: project_id.to_owned(),
                title: "source material".to_owned(),
                file_type: "txt".to_owned(),
                storage_reference: "fixture".to_owned(),
                summary: "fixture provenance".to_owned(),
                created_at: String::new(),
            },
        )
        .expect("case material inserts");
    }

    fn create_bound_conversation(state: &AppState, project_id: &str) -> AssistantConversation {
        create_assistant_conversation_inner(
            state,
            CreateAssistantConversationRequest {
                title: "case analysis".to_owned(),
                project_id: Some(project_id.to_owned()),
            },
        )
        .expect("bound conversation creates")
        .conversation
    }

    #[test]
    fn public_law_citation_infers_first_paragraph_only_from_a_complete_single_paragraph_article() {
        const ARTICLE_577: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        const ARTICLE_509: &str = "law:cn-civil-code:cn-civil-code-20210101:art:509";
        let (_directory, state) = initialized_state();
        let connection =
            database::open_legal_core_read_only(state.legal_core_path()).expect("legal core opens");
        let source = citations::source_by_citation_id(&connection, ARTICLE_577)
            .expect("source reads")
            .expect("source exists");
        assert_eq!(
            public_law_citation(&source).expect("complete article 577 has one paragraph"),
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）"
        );

        let mut source = citations::source_by_citation_id(&connection, ARTICLE_509)
            .expect("source reads")
            .expect("source exists");
        source.content = "当事人应当按照约定全面履行自己的义务。\n当事人应当遵循诚信原则履行通知、协助等义务。\n当事人在履行合同过程中应当避免浪费资源。".to_owned();
        let error = public_law_citation(&source)
            .expect_err("three-paragraph article 509 cannot imply the first paragraph");
        assert_eq!(error.error_type, "legal_paragraph_unresolved");

        let document_title = source.document_title.clone();
        source.document_title.clear();
        let error = public_law_citation(&source)
            .expect_err("a source without a public law title remains generally invalid");
        assert_eq!(error.error_type, "invalid_legal_source");
        source.document_title = document_title;

        source.canonical_label = "《中华人民共和国民法典》第五百七十七条第二款".to_owned();
        source.article_number = "第五百七十七条".to_owned();
        assert_eq!(
            public_law_citation(&source).expect("explicit second paragraph is citable"),
            "《中华人民共和国民法典》第五百七十七条第二款（2021年起施行）"
        );
    }

    fn fact_only_changes(fact_id: &str, source_id: &str) -> assistant::CaseChangeSpec {
        assistant::CaseChangeSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            facts: vec![assistant::FactAddition {
                id: fact_id.to_owned(),
                statement: "The delivery record shows timely performance.".to_owned(),
                occurred_on: Some("2026-07-16".to_owned()),
                source_refs: vec![source_id.to_owned()],
            }],
            evidence: Vec::new(),
            issues: Vec::new(),
            legal_basis: Vec::new(),
            attachment_transfers: Vec::new(),
            artifact_transfers: Vec::new(),
        }
    }

    fn legal_basis_only_changes(basis_id: &str, source_id: &str) -> assistant::CaseChangeSpec {
        let citation = if source_id.contains("cn-contract-law-1999") {
            "《中华人民共和国合同法》第一百零七条第一款（1999年起施行）"
        } else {
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）"
        };
        assistant::CaseChangeSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            facts: Vec::new(),
            evidence: Vec::new(),
            issues: Vec::new(),
            legal_basis: vec![assistant::LegalBasisAddition {
                id: basis_id.to_owned(),
                issue_ids: Vec::new(),
                source_ref: source_id.to_owned(),
                marker: format!("[SRC:{source_id}]"),
                citation: citation.to_owned(),
                proposition: "该条规定涉及合同义务不履行或履行不符合约定时的违约责任。".to_owned(),
            }],
            attachment_transfers: Vec::new(),
            artifact_transfers: Vec::new(),
        }
    }

    #[test]
    fn capabilities_expose_the_fixed_registry_and_default_budget() {
        let response = get_assistant_capabilities();

        assert_eq!(response.capabilities.len(), assistant::CAPABILITY_COUNT);
        assert_eq!(response.default_budget, RunBudget::default());
        assert!(response
            .capabilities
            .iter()
            .any(
                |capability| capability.name.as_str() == "case.apply_changes"
                    && capability.requires_user_confirmation
            ));
    }

    #[test]
    fn cancel_validates_the_run_id_and_obeys_lifecycle_authority() {
        let state = state();
        let guard = state
            .begin_assistant_run("run-1")
            .expect("assistant run registers");
        let response = cancel_assistant_run_inner(
            &state,
            CancelAssistantRunRequest {
                run_id: "run-1".to_owned(),
            },
        )
        .expect("cancel succeeds");
        assert!(response.cancelled);
        assert!(guard.token().is_cancelled());

        let invalid = cancel_assistant_run_inner(
            &state,
            CancelAssistantRunRequest {
                run_id: "../run".to_owned(),
            },
        )
        .expect_err("path-like identifiers fail closed");
        assert_eq!(invalid.error_type, "invalid_request");
        assert!(!invalid.message.contains("../run"));
    }

    #[test]
    fn cancel_request_denies_unknown_fields() {
        assert!(
            serde_json::from_value::<CancelAssistantRunRequest>(serde_json::json!({
                "runId": "run-1",
                "command": "delete_all"
            }))
            .is_err()
        );
    }

    #[test]
    fn ipc_errors_normalize_categories_and_redact_sensitive_values() {
        let error = AssistantIpcError::new(
            "bad category!?",
            "Authorization: Bearer not-a-real-token-1234",
        );

        assert_eq!(error.error_type, "badcategory");
        assert!(!error.message.contains("not-a-real-token-1234"));
        assert!(error.message.contains("<redacted>"));
    }

    #[test]
    fn conversation_lifecycle_is_case_optional_bind_once_and_archive_visible_on_request() {
        let (_directory, state) = initialized_state();
        let created = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "独立合同咨询".to_owned(),
                project_id: None,
            },
        )
        .expect("case-free conversation creates")
        .conversation;
        assert_eq!(created.project_id, None);
        assert_eq!(created.status, "open");

        let listed = list_assistant_conversations_inner(
            &state,
            ListAssistantConversationsRequest {
                project_id: None,
                include_archived: None,
                limit: Some(10),
            },
        )
        .expect("conversation lists");
        assert_eq!(listed.conversations, vec![created.clone()]);

        let detail = get_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: created.conversation_id.clone(),
            },
        )
        .expect("conversation detail loads")
        .detail;
        assert!(detail.messages.is_empty());
        assert!(detail.artifacts.is_empty());
        assert!(detail.runs.is_empty());

        insert_project(&state, "case-1");
        insert_project(&state, "case-2");
        let bound = bind_assistant_conversation_inner(
            &state,
            BindAssistantConversationRequest {
                conversation_id: created.conversation_id.clone(),
                project_id: "case-1".to_owned(),
            },
        )
        .expect("conversation binds once")
        .conversation;
        assert_eq!(bound.project_id.as_deref(), Some("case-1"));

        let conflict = bind_assistant_conversation_inner(
            &state,
            BindAssistantConversationRequest {
                conversation_id: created.conversation_id.clone(),
                project_id: "case-2".to_owned(),
            },
        )
        .expect_err("cross-case rebinding fails closed");
        assert_eq!(conflict.error_type, "conflict");

        archive_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: created.conversation_id,
            },
        )
        .expect("conversation archives");
        let open_only = list_assistant_conversations_inner(
            &state,
            ListAssistantConversationsRequest {
                project_id: None,
                include_archived: Some(false),
                limit: None,
            },
        )
        .expect("open-only list loads");
        assert!(open_only.conversations.is_empty());
        let with_archived = list_assistant_conversations_inner(
            &state,
            ListAssistantConversationsRequest {
                project_id: None,
                include_archived: Some(true),
                limit: None,
            },
        )
        .expect("archive-inclusive list loads");
        assert_eq!(with_archived.conversations.len(), 1);
        assert_eq!(with_archived.conversations[0].status, "archived");
    }

    #[test]
    fn archived_conversations_are_read_only_across_assistant_write_paths() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-archived");
        let conversation = create_bound_conversation(&state, "case-archived");
        add_assistant_legal_source_inner(
            &state,
            AddAssistantLegalSourceRequest {
                conversation_id: conversation.conversation_id.clone(),
                source_id: SOURCE_ID.to_owned(),
            },
        )
        .expect("source adds before archive");
        let attachment = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![SelectedFileBytes {
                file_name: "archived.txt".to_owned(),
                bytes: b"archived source".to_vec(),
            }],
        )
        .expect("attachment imports before archive")
        .attachments
        .remove(0);
        let artifact = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "归档前产物".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "归档前产物".to_owned(),
                    answer: "归档后只读。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("artifact saves before archive")
        .detail
        .artifact;
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-archived".to_owned(),
                changes: fact_only_changes("fact:archived", &attachment.attachment_id),
            },
        )
        .expect("proposal creates before archive")
        .proposal;
        archive_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
        )
        .expect("conversation archives");

        let source_error = add_assistant_legal_source_inner(
            &state,
            AddAssistantLegalSourceRequest {
                conversation_id: conversation.conversation_id.clone(),
                source_id: SOURCE_ID.to_owned(),
            },
        )
        .expect_err("archived source add is blocked");
        assert_eq!(source_error.error_type, "conflict");
        let import_error = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![SelectedFileBytes {
                file_name: "late.txt".to_owned(),
                bytes: b"late".to_vec(),
            }],
        )
        .expect_err("archived import is blocked");
        assert_eq!(import_error.error_type, "conflict");
        let save_error = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: Some(artifact.artifact_id),
                expected_current_version: Some(1),
                title: "归档前产物".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "归档前产物".to_owned(),
                    answer: "不应保存。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect_err("archived artifact save is blocked");
        assert_eq!(save_error.error_type, "conflict");
        let delete_error = delete_assistant_attachment_inner(
            &state,
            DeleteAssistantAttachmentRequest {
                conversation_id: conversation.conversation_id.clone(),
                attachment_id: attachment.attachment_id.clone(),
                user_confirmed: true,
            },
        )
        .expect_err("archived attachment delete is blocked");
        assert_eq!(delete_error.error_type, "not_found");
        let apply_error = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-archived".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("archived proposal apply is blocked");
        assert_eq!(apply_error.error_type, "conflict");

        let connection =
            database::open_user_database(state.user_database_path()).expect("database opens");
        assert!(
            database::get_attachment(&connection, &attachment.attachment_id)
                .expect("attachment reads")
                .is_some()
        );
        assert_eq!(
            database::get_case_change_proposal(&connection, &proposal.proposal_id)
                .expect("proposal reads")
                .expect("proposal exists")
                .status,
            "pending"
        );
        assert!(
            database::get_case_workspace_rows(&connection, "case-archived")
                .expect("workspace reads")
                .expect("case exists")
                .facts
                .is_empty()
        );

        let free = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "归档独立会话".to_owned(),
                project_id: None,
            },
        )
        .expect("free conversation creates")
        .conversation;
        let free_artifact = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: free.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "独立产物".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "独立产物".to_owned(),
                    answer: "独立。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("free artifact saves")
        .detail
        .artifact;
        archive_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: free.conversation_id,
            },
        )
        .expect("free conversation archives");
        let bind_error = bind_assistant_artifact_inner(
            &state,
            BindAssistantArtifactRequest {
                artifact_id: free_artifact.artifact_id,
                project_id: "case-archived".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("archived artifact bind is blocked");
        assert_eq!(bind_error.error_type, "conflict");
    }

    #[test]
    fn artifact_detail_versions_and_case_binding_use_typed_json() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-1");
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "文书拟定".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::create_artifact(
            &connection,
            &database::NewArtifactRow {
                artifact_id: "artifact:1".to_owned(),
                conversation_id: Some(conversation.conversation_id),
                project_id: None,
                kind: "document".to_owned(),
                title: "合同草案".to_owned(),
                status: "draft".to_owned(),
            },
            &database::NewArtifactVersionRow {
                version_id: "artifact-version:1".to_owned(),
                artifact_id: "artifact:1".to_owned(),
                content_json: r#"{"schemaVersion":1,"title":"合同草案"}"#.to_owned(),
                rendered_text: "# 合同草案".to_owned(),
                source_refs_json: r#"["source-1"]"#.to_owned(),
                citation_report_json: r#"{"validCount":0}"#.to_owned(),
                provider_snapshot_json: "null".to_owned(),
            },
        )
        .expect("artifact creates");
        drop(connection);

        let detail = get_assistant_artifact_inner(
            &state,
            GetAssistantArtifactRequest {
                artifact_id: "artifact:1".to_owned(),
            },
        )
        .expect("artifact detail loads");
        assert_eq!(detail.artifact.current_version, 1);
        assert_eq!(detail.versions.len(), 1);
        assert_eq!(detail.versions[0].content["schemaVersion"], 1);

        let confirmation_error = bind_assistant_artifact_inner(
            &state,
            BindAssistantArtifactRequest {
                artifact_id: "artifact:1".to_owned(),
                project_id: "case-1".to_owned(),
                user_confirmed: false,
            },
        )
        .expect_err("unconfirmed direct artifact binding fails");
        assert_eq!(confirmation_error.error_type, "confirmation_required");

        let bound = bind_assistant_artifact_inner(
            &state,
            BindAssistantArtifactRequest {
                artifact_id: "artifact:1".to_owned(),
                project_id: "case-1".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("artifact binds")
        .artifact;
        assert_eq!(bound.project_id.as_deref(), Some("case-1"));
    }

    #[test]
    fn assistant_requests_deny_unknown_fields_and_bounded_list_values() {
        assert!(
            serde_json::from_value::<CreateAssistantConversationRequest>(serde_json::json!({
                "title": "咨询",
                "projectId": null,
                "sql": "DROP TABLE conversations"
            }))
            .is_err()
        );
        let (_directory, state) = initialized_state();
        let error = list_assistant_conversations_inner(
            &state,
            ListAssistantConversationsRequest {
                project_id: None,
                include_archived: None,
                limit: Some(101),
            },
        )
        .expect_err("oversized list fails");
        assert_eq!(error.error_type, "invalid_request");
    }

    #[test]
    fn file_import_persists_original_bytes_extraction_locators_and_message_links() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "材料分析".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let response = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![
                SelectedFileBytes {
                    file_name: "证据.txt".to_owned(),
                    bytes: b"first\r\nsecond".to_vec(),
                },
                SelectedFileBytes {
                    file_name: "说明.md".to_owned(),
                    bytes: b"# heading\nbody".to_vec(),
                },
            ],
        )
        .expect("files import");
        assert!(!response.cancelled);
        assert_eq!(response.duplicate_count, 0);
        assert_eq!(response.attachments.len(), 2);
        assert_eq!(response.message.as_ref().unwrap().attachments.len(), 2);

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let first = database::get_attachment(&connection, &response.attachments[0].attachment_id)
            .expect("attachment reads")
            .expect("attachment exists");
        assert_eq!(first.content_blob, b"first\r\nsecond");
        assert_eq!(first.extracted_text.as_deref(), Some("first\nsecond"));
        let segments: Vec<serde_json::Value> =
            serde_json::from_str(&first.segments_json).expect("segments parse");
        assert_eq!(segments[0]["locator"], "line:1-2");

        let detail = get_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: conversation.conversation_id,
            },
        )
        .expect("detail loads")
        .detail;
        assert_eq!(detail.messages.len(), 1);
        assert_eq!(detail.messages[0].attachments.len(), 2);
    }

    #[test]
    fn assistant_attachment_import_never_registers_a_case_material() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-chat-attachment");
        let conversation = create_bound_conversation(&state, "case-chat-attachment");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let before = database::get_case_workspace_rows(&connection, "case-chat-attachment")
            .expect("case workspace reads")
            .expect("case workspace exists")
            .files
            .len();
        drop(connection);

        let response = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id,
            },
            vec![SelectedFileBytes {
                file_name: "ordinary-chat.txt".to_owned(),
                bytes: b"explicit ordinary attachment".to_vec(),
            }],
        )
        .expect("ordinary attachment imports");
        assert_eq!(response.attachments.len(), 1);

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let after = database::get_case_workspace_rows(&connection, "case-chat-attachment")
            .expect("case workspace reads")
            .expect("case workspace exists")
            .files
            .len();
        assert_eq!(after, before);
    }

    #[test]
    fn duplicate_file_import_deduplicates_and_invalid_batch_rolls_back() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "重复材料".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let request = ImportAssistantFilesRequest {
            conversation_id: conversation.conversation_id.clone(),
        };
        let duplicate = import_assistant_files_inner(
            &state,
            request,
            vec![
                SelectedFileBytes {
                    file_name: "one.txt".to_owned(),
                    bytes: b"same".to_vec(),
                },
                SelectedFileBytes {
                    file_name: "two.md".to_owned(),
                    bytes: b"same".to_vec(),
                },
            ],
        )
        .expect("duplicate batch imports once");
        assert_eq!(duplicate.duplicate_count, 1);
        assert_eq!(duplicate.attachments.len(), 1);
        assert_eq!(duplicate.message.unwrap().attachments.len(), 1);

        let failed = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id,
            },
            vec![
                SelectedFileBytes {
                    file_name: "new.txt".to_owned(),
                    bytes: b"new material".to_vec(),
                },
                SelectedFileBytes {
                    file_name: "broken.pdf".to_owned(),
                    bytes: b"%PDF-1.7\nbroken".to_vec(),
                },
            ],
        )
        .expect_err("invalid batch fails before persistence");
        assert_eq!(failed.error_type, "corrupt_pdf");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let attachment_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM attachments", [], |row| row.get(0))
            .expect("attachment count reads");
        assert_eq!(attachment_count, 1);
        let message_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .expect("message count reads");
        assert_eq!(message_count, 1);
    }

    #[test]
    fn attachment_delete_is_confirmed_conversation_scoped_and_reference_safe() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "附件删除".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let import = |name: &str, body: &[u8]| {
            import_assistant_files_inner(
                &state,
                ImportAssistantFilesRequest {
                    conversation_id: conversation.conversation_id.clone(),
                },
                vec![SelectedFileBytes {
                    file_name: name.to_owned(),
                    bytes: body.to_vec(),
                }],
            )
            .expect("attachment imports")
            .attachments
            .remove(0)
        };
        let removable = import("removable.txt", b"removable");
        let missing_confirmation = delete_assistant_attachment_inner(
            &state,
            DeleteAssistantAttachmentRequest {
                conversation_id: conversation.conversation_id.clone(),
                attachment_id: removable.attachment_id.clone(),
                user_confirmed: false,
            },
        )
        .expect_err("confirmation is mandatory");
        assert_eq!(missing_confirmation.error_type, "confirmation_required");
        let deleted = delete_assistant_attachment_inner(
            &state,
            DeleteAssistantAttachmentRequest {
                conversation_id: conversation.conversation_id.clone(),
                attachment_id: removable.attachment_id.clone(),
                user_confirmed: true,
            },
        )
        .expect("unreferenced attachment deletes");
        assert!(deleted.deleted);
        let connection =
            database::open_user_database(state.user_database_path()).expect("database opens");
        assert!(
            database::get_attachment(&connection, &removable.attachment_id)
                .expect("attachment lookup works")
                .is_none()
        );
        drop(connection);

        let retained = import("retained.txt", b"retained");
        save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "引用附件的研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "引用附件的研究".to_owned(),
                    answer: "保留来源。".to_owned(),
                    source_refs: vec![retained.attachment_id.clone()],
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("referencing artifact saves");
        let in_use = delete_assistant_attachment_inner(
            &state,
            DeleteAssistantAttachmentRequest {
                conversation_id: conversation.conversation_id.clone(),
                attachment_id: retained.attachment_id.clone(),
                user_confirmed: true,
            },
        )
        .expect_err("referenced attachment is retained");
        assert_eq!(in_use.error_type, "conflict");
        let detail = get_assistant_conversation_inner(
            &state,
            AssistantConversationIdRequest {
                conversation_id: conversation.conversation_id,
            },
        )
        .expect("conversation reloads")
        .detail;
        assert!(detail
            .messages
            .iter()
            .flat_map(|message| &message.attachments)
            .any(|attachment| attachment.attachment_id == retained.attachment_id));
    }

    #[test]
    fn artifact_save_creates_versions_and_rejects_stale_or_unowned_sources() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "研究结果".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let created = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "合同研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "合同研究".to_owned(),
                    answer: "结论需要结合具体合同审阅。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: vec!["尚未看到合同附件".to_owned()],
                    missing_information: vec!["履行时间".to_owned()],
                    risk_warnings: vec!["不要把草稿直接作为最终意见".to_owned()],
                }),
            },
            serde_json::Value::Null,
        )
        .expect("research artifact creates")
        .detail;
        assert_eq!(created.artifact.kind, "research");
        assert_eq!(created.versions.len(), 1);
        assert!(created.versions[0].rendered_text.contains("待确认假设"));

        let artifact_id = created.artifact.artifact_id;
        let updated = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: Some(artifact_id.clone()),
                expected_current_version: Some(1),
                title: "合同研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "合同研究".to_owned(),
                    answer: "第二版结论。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("artifact CAS update succeeds")
        .detail;
        assert_eq!(updated.artifact.current_version, 2);
        assert_eq!(updated.versions[0].version_number, 2);

        let stale = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: Some(artifact_id),
                expected_current_version: Some(1),
                title: "合同研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "合同研究".to_owned(),
                    answer: "迟到版本。".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect_err("stale update fails");
        assert_eq!(stale.error_type, "conflict");

        let unknown_source = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id,
                artifact_id: None,
                expected_current_version: None,
                title: "越权研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "越权研究".to_owned(),
                    answer: "不应保存。".to_owned(),
                    source_refs: vec!["attachment:not-owned".to_owned()],
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect_err("unowned source fails");
        assert_eq!(unknown_source.error_type, "unknown_reference");
    }

    #[test]
    fn document_and_map_artifacts_use_closed_specs_and_rust_renderers() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "结构化产物".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let document = assistant::DocumentSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            document_type: assistant::DocumentType::Contract,
            title: "服务合同".to_owned(),
            parties: Vec::new(),
            sections: vec![assistant::DocumentSection {
                id: "section-1".to_owned(),
                heading: "服务内容".to_owned(),
                body: "双方应在补充主体信息后确认服务范围。".to_owned(),
                factual: false,
                provenance: vec![assistant::ProvenanceRef {
                    kind: assistant::ProvenanceKind::ModelWording,
                    source_ref: None,
                }],
                clauses: Vec::new(),
            }],
            assumptions: Vec::new(),
            missing_information: vec![assistant::MissingInformation {
                description: "双方主体信息".to_owned(),
            }],
            source_materials: Vec::new(),
            legal_citations: Vec::new(),
            risk_warnings: vec!["签署前由双方逐条确认".to_owned()],
        };
        let document_detail = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "服务合同".to_owned(),
                draft: AssistantArtifactDraft::Document(document),
            },
            serde_json::Value::Null,
        )
        .expect("document saves")
        .detail;
        assert_eq!(document_detail.artifact.kind, "document");
        let rendered_document = &document_detail.versions[0].rendered_text;
        assert!(rendered_document.contains("法律依据与案例引用表"));
        assert!(!rendered_document.contains("结构化文书预览"));
        assert!(!rendered_document.contains("模型措辞"));

        let map = assistant::MapSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            title: "争点导图".to_owned(),
            layout_hint: assistant::LayoutHint::Mindmap,
            nodes: vec![assistant::MapNode {
                id: "root".to_owned(),
                label: "核心争点".to_owned(),
                summary: "待结合材料继续分析".to_owned(),
                parent_id: None,
                source_refs: Vec::new(),
            }],
            edges: Vec::new(),
        };
        let map_detail = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id,
                artifact_id: None,
                expected_current_version: None,
                title: "争点导图".to_owned(),
                draft: AssistantArtifactDraft::Map(map),
            },
            serde_json::Value::Null,
        )
        .expect("map saves")
        .detail;
        assert_eq!(map_detail.artifact.kind, "map");
        assert!(map_detail.versions[0]
            .rendered_text
            .contains("案件要素与关系分析"));
        assert!(!map_detail.versions[0].rendered_text.contains("模型生成"));

        assert!(
            serde_json::from_value::<AssistantArtifactDraft>(serde_json::json!({
                "kind": "map",
                "spec": {
                    "schemaVersion": 1,
                    "title": "bad",
                    "layoutHint": "mindmap",
                    "nodes": [],
                    "edges": [],
                    "javascript": "alert(1)"
                }
            }))
            .is_err()
        );
    }

    #[test]
    fn research_rejects_non_deliverable_content_in_every_public_text_field() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "研究成果公开边界".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;

        let mutations: Vec<fn(&mut ResearchArtifactSpec)> = vec![
            |spec| spec.title = "合同研究 service-deadbeef-1".to_owned(),
            |spec| {
                spec.answer = r#"{"sourceRefs":["law:secret"],"articleId":"art-secret"}"#.to_owned()
            },
            |spec| spec.answer = "记录号 019f6e3e-6822-70c1-86a7-6f88022a815e".to_owned(),
            |spec| spec.assumptions = vec![r"材料位于 C:\Users\test\case.txt".to_owned()],
            |spec| {
                spec.missing_information =
                    vec!["接口端点 https://localhost:7777/internal".to_owned()]
            },
            |spec| {
                spec.risk_warnings =
                    vec!["模型输出 proposalHash=deadbeef0123456789abcdef".to_owned()]
            },
        ];

        for mutate in mutations {
            let mut spec = ResearchArtifactSpec {
                schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                title: "合同履行研究".to_owned(),
                answer: "应结合合同约定、履行事实及证据判断责任。".to_owned(),
                source_refs: Vec::new(),
                assumptions: Vec::new(),
                missing_information: Vec::new(),
                risk_warnings: Vec::new(),
            };
            mutate(&mut spec);
            let title = spec.title.clone();
            let error = save_assistant_artifact_inner(
                &state,
                SaveAssistantArtifactRequest {
                    conversation_id: conversation.conversation_id.clone(),
                    artifact_id: None,
                    expected_current_version: None,
                    title,
                    draft: AssistantArtifactDraft::Research(spec),
                },
                serde_json::Value::Null,
            )
            .expect_err("non-deliverable research content must fail before preview generation");
            assert_eq!(error.error_type, "invalid_contract");
        }
    }

    #[test]
    fn research_preview_and_markdown_export_never_expose_internal_source_references() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        const PUBLIC_CITATION: &str =
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）";

        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "合同履行研究".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        add_assistant_legal_source_inner(
            &state,
            AddAssistantLegalSourceRequest {
                conversation_id: conversation.conversation_id.clone(),
                source_id: SOURCE_ID.to_owned(),
            },
        )
        .expect("legal source adds");
        let attachment = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![SelectedFileBytes {
                file_name: "合同履行记录.txt".to_owned(),
                bytes: b"synthetic delivery record".to_vec(),
            }],
        )
        .expect("attachment imports")
        .attachments
        .remove(0);

        let saved = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id,
                artifact_id: None,
                expected_current_version: None,
                title: "合同履行研究".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "合同履行研究".to_owned(),
                    answer: format!(
                        "逾期交付责任应结合合同约定和履行证据判断。适用依据包括{PUBLIC_CITATION}。"
                    ),
                    source_refs: vec![SOURCE_ID.to_owned(), attachment.attachment_id.clone()],
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("research artifact saves")
        .detail;

        let preview = &saved.versions[0].rendered_text;
        assert!(preview.contains(PUBLIC_CITATION));
        assert!(!preview.contains("## 来源"));
        assert!(!preview.contains("## 法条引用"));
        for forbidden in [
            SOURCE_ID,
            attachment.attachment_id.as_str(),
            "law:",
            "attachment:",
            "source_ref",
            "sourceRef",
        ] {
            assert!(!preview.contains(forbidden), "preview leaked {forbidden}");
        }

        let artifact_id = saved.artifact.artifact_id.clone();
        let payload = prepare_artifact_export(
            &state,
            &ExportAssistantArtifactRequest {
                artifact_id: artifact_id.clone(),
                version_number: 1,
                format: AssistantArtifactExportFormat::ResearchMarkdown,
            },
        )
        .expect("research Markdown export prepares");
        let exported_path = _directory.path().join("合同履行研究.md");
        fs::write(&exported_path, &payload.bytes).expect("Markdown export writes");
        let exported = fs::read_to_string(&exported_path).expect("Markdown is UTF-8");
        assert_eq!(exported, *preview);
        assert!(exported.contains(PUBLIC_CITATION));
        assert!(!exported.contains("## 来源"));
        assert!(!exported.contains("## 法条引用"));
        for forbidden in [
            SOURCE_ID,
            attachment.attachment_id.as_str(),
            "law:",
            "attachment:",
            "source_ref",
            "sourceRef",
        ] {
            assert!(!exported.contains(forbidden), "export leaked {forbidden}");
        }

        let polluted = AssistantArtifactDraft::Research(ResearchArtifactSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            title: "合同履行研究".to_owned(),
            answer: r#"{"sourceRefs":["law:secret"],"endpoint":"http://localhost:7777"}"#
                .to_owned(),
            source_refs: Vec::new(),
            assumptions: Vec::new(),
            missing_information: Vec::new(),
            risk_warnings: Vec::new(),
        });
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        connection
            .execute(
                "UPDATE artifact_versions SET content_json = ?1 WHERE artifact_id = ?2 AND version_number = 1",
                rusqlite::params![
                    serde_json::to_string(&polluted).expect("polluted fixture serializes"),
                    artifact_id
                ],
            )
            .expect("legacy polluted fixture persists");
        let error = prepare_artifact_export(
            &state,
            &ExportAssistantArtifactRequest {
                artifact_id: saved.artifact.artifact_id.clone(),
                version_number: 1,
                format: AssistantArtifactExportFormat::ResearchMarkdown,
            },
        )
        .expect_err("legacy polluted research must fail closed at export time");
        assert_eq!(error.error_type, "invalid_contract");
    }

    #[test]
    fn artifact_export_rerenders_typed_docx_and_rejects_mismatched_formats() {
        let (_directory, state) = initialized_state();
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "导出产物".to_owned(),
                project_id: None,
            },
        )
        .expect("conversation creates")
        .conversation;
        let saved = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id,
                artifact_id: None,
                expected_current_version: None,
                title: "合同：草案/一".to_owned(),
                draft: AssistantArtifactDraft::Document(assistant::DocumentSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    document_type: assistant::DocumentType::Contract,
                    title: "合同：草案/一".to_owned(),
                    parties: Vec::new(),
                    sections: vec![assistant::DocumentSection {
                        id: "section-1".to_owned(),
                        heading: "条款".to_owned(),
                        body: "待双方确认。".to_owned(),
                        factual: false,
                        provenance: vec![assistant::ProvenanceRef {
                            kind: assistant::ProvenanceKind::ModelWording,
                            source_ref: None,
                        }],
                        clauses: Vec::new(),
                    }],
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    source_materials: Vec::new(),
                    legal_citations: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("document saves")
        .detail;
        let artifact_id = saved.artifact.artifact_id;
        let payload = prepare_artifact_export(
            &state,
            &ExportAssistantArtifactRequest {
                artifact_id: artifact_id.clone(),
                version_number: 1,
                format: AssistantArtifactExportFormat::DocumentDocx,
            },
        )
        .expect("DOCX export prepares");
        assert_eq!(payload.extension, "docx");
        assert!(payload.bytes.starts_with(b"PK\x03\x04"));
        assert_eq!(payload.suggested_file_name, "合同：草案_一.docx");

        let mismatch = prepare_artifact_export(
            &state,
            &ExportAssistantArtifactRequest {
                artifact_id,
                version_number: 1,
                format: AssistantArtifactExportFormat::LegacyMapJson,
            },
        )
        .expect_err("legacy raw map export fails closed");
        assert_eq!(mismatch.error_type, "unsupported");
        assert_eq!(
            mismatch.message,
            "关系图仅支持导出用户可直接阅读的文字摘要。"
        );
    }

    #[test]
    fn artifact_export_is_atomic_non_overwriting_and_cannot_alias_managed_state() {
        let (directory, state) = initialized_state();
        let external = tempfile::tempdir().expect("external directory exists");
        let destination = external.path().join("artifact.md");
        validate_artifact_export_destination(&state, &destination)
            .expect("ordinary external destination is allowed");
        write_artifact_export_atomically(&state, &destination, b"new")
            .expect("atomic artifact export succeeds");
        assert_eq!(fs::read(&destination).unwrap(), b"new");

        let existing = external.path().join("existing.md");
        fs::write(&existing, b"old").expect("existing destination writes");
        let existing_error = validate_artifact_export_destination(&state, &existing)
            .expect_err("an existing destination is never accepted for overwrite");
        assert_eq!(existing_error.error_type, "destination_exists");
        let write_error = write_artifact_export_atomically(&state, &existing, b"replacement")
            .expect_err("the writer independently enforces no-overwrite");
        assert_eq!(write_error.error_type, "destination_exists");
        assert_eq!(fs::read(&existing).unwrap(), b"old");

        let managed = directory.path().join("artifact.md");
        let managed_error = validate_artifact_export_destination(&state, &managed)
            .expect_err("managed directory is protected");
        assert_eq!(managed_error.error_type, "protected_path");

        let hardlink = external.path().join("database-alias.sqlite");
        fs::hard_link(state.user_database_path(), &hardlink).expect("hardlink creates");
        let hardlink_error = validate_artifact_export_destination(&state, &hardlink)
            .expect_err("hardlink alias is protected");
        assert_eq!(hardlink_error.error_type, "protected_path");
    }

    #[test]
    fn artifact_export_install_failure_cleans_marker_and_staging() {
        let (directory, state) = initialized_state();
        let external = tempfile::tempdir().expect("external directory exists");
        let destination = external.path().join("failed.md");

        let error = write_artifact_export_atomically_with_installer(
            &state,
            &destination,
            b"staged bytes",
            |staging, _| {
                assert!(staging.is_file());
                Err(std::io::Error::other("simulated install failure"))
            },
        )
        .expect_err("simulated installation failure is returned");

        assert_eq!(error.error_type, "file_write");
        assert!(!destination.exists());

        let raced_destination = external.path().join("raced.md");
        let race_error = write_artifact_export_atomically_with_installer(
            &state,
            &raced_destination,
            b"assistant bytes",
            |staging, target| {
                fs::write(target, b"concurrent file")?;
                install_artifact_export_without_overwrite(staging, target)
            },
        )
        .expect_err("a destination created during export is not overwritten");
        assert_eq!(race_error.error_type, "file_write");
        assert_eq!(fs::read(&raced_destination).unwrap(), b"concurrent file");

        assert!(!fs::read_dir(external.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ARTIFACT_EXPORT_STAGING_PREFIX)
        }));
        assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ARTIFACT_EXPORT_MARKER_PREFIX)
        }));
    }

    #[test]
    fn artifact_export_crash_recovery_cleans_staging_and_preserves_installed_output() {
        let (directory, state) = initialized_state();
        let external = tempfile::tempdir().expect("external directory exists");

        let before_install = external.path().join("before-install.md");
        let prepared = prepare_artifact_export_staging(&state, &before_install, b"prepared")
            .expect("staging prepares");
        assert!(prepared.marker_path.is_file());
        assert!(prepared.staging_path.is_file());
        fs::write(&prepared.staging_path, b"part")
            .expect("simulate a crash during the staging write");
        assert_eq!(
            recover_pending_assistant_artifact_exports(directory.path()).unwrap(),
            1
        );
        assert!(!prepared.marker_path.exists());
        assert!(!prepared.staging_path.exists());
        assert!(!before_install.exists());

        let after_install = external.path().join("after-install.md");
        let prepared = prepare_artifact_export_staging(&state, &after_install, b"installed")
            .expect("second staging prepares");
        install_artifact_export_without_overwrite(&prepared.staging_path, &after_install)
            .expect("atomic install completes before the simulated crash");
        assert!(prepared.marker_path.is_file());
        assert!(!prepared.staging_path.exists());
        assert_eq!(
            recover_pending_assistant_artifact_exports(directory.path()).unwrap(),
            1
        );
        assert_eq!(fs::read(&after_install).unwrap(), b"installed");
        assert!(!prepared.marker_path.exists());
    }

    #[test]
    fn artifact_export_recovery_refuses_tampered_staging_without_deleting_it() {
        let (directory, state) = initialized_state();
        let external = tempfile::tempdir().expect("external directory exists");
        let destination = external.path().join("tampered.md");
        let prepared = prepare_artifact_export_staging(&state, &destination, b"expected")
            .expect("staging prepares");
        fs::write(&prepared.staging_path, b"tampered").expect("staging is tampered");

        let error = recover_pending_assistant_artifact_exports(directory.path())
            .expect_err("a hash-mismatched staging file is never deleted");

        assert_eq!(error.error_type, "artifact_export_recovery");
        assert_eq!(fs::read(&prepared.staging_path).unwrap(), b"tampered");
        assert!(prepared.marker_path.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn artifact_export_recovery_refuses_out_of_bounds_marker_without_deleting_destination() {
        let (directory, _state) = initialized_state();
        let external = tempfile::tempdir().expect("external directory exists");
        let nested = external.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let victim = external.path().join("victim.md");
        fs::write(&victim, b"keep me").unwrap();
        let export_id = Uuid::new_v4().to_string();
        let marker_path = artifact_export_marker_path(directory.path(), &export_id);
        let marker = ArtifactExportMarker {
            format_version: 1,
            export_id,
            destination_path: nested.join("..").join("victim.md"),
            byte_len: 7,
            sha256: artifact_export_bytes_sha256(b"keep me"),
        };
        write_artifact_export_marker(&marker_path, &marker).unwrap();

        let error = recover_pending_assistant_artifact_exports(directory.path())
            .expect_err("relative path components make the marker invalid");

        assert_eq!(error.error_type, "artifact_export_recovery");
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        assert!(marker_path.exists());
    }

    #[test]
    fn legal_library_source_creates_only_a_pending_case_basis_proposal() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-legal-library");
        let conversation = create_bound_conversation(&state, "case-legal-library");

        let response = propose_assistant_legal_basis_inner(
            &state,
            ProposeAssistantLegalBasisRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-legal-library".to_owned(),
                source_id: SOURCE_ID.to_owned(),
            },
        )
        .expect("legal source proposal creates");
        assert_eq!(response.proposal.status, "pending");
        assert_eq!(response.proposal.source_refs, vec![SOURCE_ID.to_owned()]);
        assert_eq!(response.proposal.changes.legal_basis.len(), 1);
        assert_eq!(
            response.proposal.changes.legal_basis[0].citation,
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）"
        );
        assert_eq!(
            response.proposal.changes.legal_basis[0].source_ref,
            SOURCE_ID
        );

        let connection =
            database::open_user_database(state.user_database_path()).expect("database opens");
        let before = database::get_case_workspace_rows(&connection, "case-legal-library")
            .expect("workspace reads")
            .expect("case exists");
        assert!(
            before.legal_basis.is_empty(),
            "pending proposal never writes case data"
        );
        assert_eq!(
            database::list_conversation_sources(&connection, &conversation.conversation_id)
                .expect("conversation sources read")
                .len(),
            1
        );
        drop(connection);

        let applied = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: response.proposal.proposal_id,
                project_id: "case-legal-library".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("explicit confirmation applies the basis");
        assert!(applied.applied);
        let connection =
            database::open_user_database(state.user_database_path()).expect("database reopens");
        let after = database::get_case_workspace_rows(&connection, "case-legal-library")
            .expect("workspace reads")
            .expect("case exists");
        assert_eq!(after.legal_basis.len(), 1);
        assert_eq!(after.legal_basis[0].source_id, SOURCE_ID);
    }

    #[test]
    fn proposal_create_is_no_write_requires_confirmation_and_applies_once() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-proposal");
        insert_case_material(&state, "case-proposal", "material:proposal");
        let conversation = create_bound_conversation(&state, "case-proposal");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let digest_before = database::case_workspace_digest(&connection, "case-proposal")
            .expect("digest reads")
            .expect("case exists");
        drop(connection);

        let created = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-proposal".to_owned(),
                changes: fact_only_changes("fact:proposed", "material:proposal"),
            },
        )
        .expect("pending proposal creates")
        .proposal;
        assert_eq!(created.status, "pending");
        assert_eq!(created.base_case_digest, digest_before);

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        assert_eq!(
            database::case_workspace_digest(&connection, "case-proposal")
                .expect("digest reads")
                .as_deref(),
            Some(digest_before.as_str())
        );
        assert!(
            database::get_case_workspace_rows(&connection, "case-proposal")
                .expect("workspace reads")
                .expect("workspace exists")
                .facts
                .is_empty()
        );
        drop(connection);

        let confirmation_error = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: created.proposal_id.clone(),
                project_id: "case-proposal".to_owned(),
                user_confirmed: false,
            },
        )
        .expect_err("unconfirmed apply fails");
        assert_eq!(confirmation_error.error_type, "confirmation_required");

        let applied = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: created.proposal_id.clone(),
                project_id: "case-proposal".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("confirmed proposal applies");
        assert!(applied.applied);
        assert!(!applied.stale);
        assert_eq!(applied.proposal.status, "applied");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let workspace = database::get_case_workspace_rows(&connection, "case-proposal")
            .expect("workspace reads")
            .expect("workspace exists");
        assert_eq!(workspace.facts.len(), 1);
        assert_eq!(workspace.facts[0].fact_id, "fact:proposed");
        assert_eq!(workspace.facts[0].confirmation_status, "confirmed");
        drop(connection);

        let repeated = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: created.proposal_id,
                project_id: "case-proposal".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("terminal proposal cannot apply twice");
        assert_eq!(repeated.error_type, "conflict");
    }

    #[test]
    fn proposal_reject_and_cross_case_requests_never_write_case_state() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-owner");
        insert_project(&state, "case-other");
        insert_case_material(&state, "case-owner", "material:owner");
        let conversation = create_bound_conversation(&state, "case-owner");

        let cross_create = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-other".to_owned(),
                changes: fact_only_changes("fact:cross-create", "material:owner"),
            },
        )
        .expect_err("conversation cannot create a proposal for another case");
        assert_eq!(cross_create.error_type, "conflict");

        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-owner".to_owned(),
                changes: fact_only_changes("fact:rejected", "material:owner"),
            },
        )
        .expect("proposal creates")
        .proposal;

        let cross_apply = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-other".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("proposal cannot apply to another case");
        assert_eq!(cross_apply.error_type, "conflict");

        let rejected = reject_assistant_case_change_proposal_inner(
            &state,
            RejectAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-owner".to_owned(),
            },
        )
        .expect("proposal rejects")
        .proposal;
        assert_eq!(rejected.status, "rejected");

        let repeated = reject_assistant_case_change_proposal_inner(
            &state,
            RejectAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id,
                project_id: "case-owner".to_owned(),
            },
        )
        .expect_err("terminal proposal cannot reject twice");
        assert_eq!(repeated.error_type, "conflict");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        assert!(database::get_case_workspace_rows(&connection, "case-owner")
            .expect("workspace reads")
            .expect("workspace exists")
            .facts
            .is_empty());
    }

    #[test]
    fn proposal_apply_marks_digest_mismatch_stale_without_partial_writes() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-stale");
        insert_case_material(&state, "case-stale", "material:stale");
        let conversation = create_bound_conversation(&state, "case-stale");
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-stale".to_owned(),
                changes: fact_only_changes("fact:stale-proposal", "material:stale"),
            },
        )
        .expect("proposal creates")
        .proposal;

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::upsert_case_fact(
            &connection,
            &database::CaseFactRow {
                fact_id: "fact:user-edit".to_owned(),
                project_id: "case-stale".to_owned(),
                occurred_on: None,
                title: "user edit".to_owned(),
                description: "changed after review".to_owned(),
                source: "user".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            },
        )
        .expect("user edit inserts");
        drop(connection);

        let response = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id,
                project_id: "case-stale".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("stale proposal returns explicit state");
        assert!(!response.applied);
        assert!(response.stale);
        assert_eq!(response.proposal.status, "stale");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let workspace = database::get_case_workspace_rows(&connection, "case-stale")
            .expect("workspace reads")
            .expect("workspace exists");
        assert_eq!(workspace.facts.len(), 1);
        assert_eq!(workspace.facts[0].fact_id, "fact:user-edit");
    }

    #[test]
    fn proposal_apply_rejects_new_ids_that_collide_with_any_existing_case_entity() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-id-owner");
        insert_project(&state, "case-id-other");
        insert_case_material(&state, "case-id-owner", "material:id-owner");
        let conversation = create_bound_conversation(&state, "case-id-owner");
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-id-owner".to_owned(),
                changes: fact_only_changes("fact:global-collision", "material:id-owner"),
            },
        )
        .expect("proposal creates")
        .proposal;

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::upsert_case_fact(
            &connection,
            &database::CaseFactRow {
                fact_id: "fact:global-collision".to_owned(),
                project_id: "case-id-other".to_owned(),
                occurred_on: None,
                title: "existing global id".to_owned(),
                description: String::new(),
                source: "user".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            },
        )
        .expect("cross-case collision fixture inserts");
        drop(connection);

        let error = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-id-owner".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("existing entity id blocks apply");
        assert_eq!(error.error_type, "conflict");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        assert!(
            database::get_case_workspace_rows(&connection, "case-id-owner")
                .expect("workspace reads")
                .expect("workspace exists")
                .facts
                .is_empty()
        );
        assert_eq!(
            database::get_case_change_proposal(&connection, &proposal.proposal_id)
                .expect("proposal reads")
                .expect("proposal exists")
                .status,
            "pending"
        );
    }

    #[test]
    fn proposal_create_prechecks_explicit_and_deterministically_expanded_ids() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-create-id-owner");
        insert_project(&state, "case-create-id-other");
        insert_case_material(&state, "case-create-id-owner", "material:create-id-owner");
        let conversation = create_bound_conversation(&state, "case-create-id-owner");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        for fact_id in ["fact:create-collision", "basis:derived:issue:1"] {
            database::upsert_case_fact(
                &connection,
                &database::CaseFactRow {
                    fact_id: fact_id.to_owned(),
                    project_id: "case-create-id-other".to_owned(),
                    occurred_on: None,
                    title: "existing global id".to_owned(),
                    description: String::new(),
                    source: "user".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("collision fixture inserts");
        }
        database::add_conversation_source(&connection, &conversation.conversation_id, SOURCE_ID)
            .expect("legal source links");
        drop(connection);

        let explicit = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-create-id-owner".to_owned(),
                changes: fact_only_changes("fact:create-collision", "material:create-id-owner"),
            },
        )
        .expect_err("existing explicit id blocks proposal creation");
        assert_eq!(explicit.error_type, "conflict");

        let mut derived = fact_only_changes("fact:derived", "material:create-id-owner");
        derived.issues = vec![
            assistant::IssueAddition {
                id: "issue:derived:0".to_owned(),
                title: "first issue".to_owned(),
                analysis: "first analysis".to_owned(),
                related_fact_ids: vec!["fact:derived".to_owned()],
                source_refs: Vec::new(),
            },
            assistant::IssueAddition {
                id: "issue:derived:1".to_owned(),
                title: "second issue".to_owned(),
                analysis: "second analysis".to_owned(),
                related_fact_ids: vec!["fact:derived".to_owned()],
                source_refs: Vec::new(),
            },
        ];
        derived.legal_basis = vec![assistant::LegalBasisAddition {
            id: "basis:derived".to_owned(),
            issue_ids: vec!["issue:derived:0".to_owned(), "issue:derived:1".to_owned()],
            source_ref: SOURCE_ID.to_owned(),
            marker: format!("[SRC:{SOURCE_ID}]"),
            citation: "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）".to_owned(),
            proposition: "该条规定涉及合同义务不履行或履行不符合约定时的违约责任。".to_owned(),
        }];
        let derived_error = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-create-id-owner".to_owned(),
                changes: derived,
            },
        )
        .expect_err("existing deterministic expansion id blocks proposal creation");
        assert_eq!(derived_error.error_type, "conflict");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let proposal_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM case_change_proposals", [], |row| {
                row.get(0)
            })
            .expect("proposal count reads");
        assert_eq!(proposal_count, 0);
    }

    #[test]
    fn trusted_run_provenance_requires_same_case_analysis_run_in_eligible_status() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-run-provenance");
        insert_case_material(&state, "case-run-provenance", "material:run-provenance");
        let conversation = create_bound_conversation(&state, "case-run-provenance");
        let request = CreateAssistantCaseChangeProposalRequest {
            conversation_id: conversation.conversation_id.clone(),
            project_id: "case-run-provenance".to_owned(),
            changes: fact_only_changes("fact:run-provenance", "material:run-provenance"),
        };

        let mut connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        for (message_id, run_id, intent, status) in [
            (
                "message:queued-run",
                "run:queued",
                "case_analysis",
                "queued",
            ),
            (
                "message:wrong-intent",
                "run:wrong-intent",
                "file_analysis",
                "running",
            ),
            (
                "message:eligible-run",
                "run:eligible",
                "case_analysis",
                "running",
            ),
        ] {
            database::create_message(
                &connection,
                &database::NewMessageRow {
                    message_id: message_id.to_owned(),
                    conversation_id: conversation.conversation_id.clone(),
                    role: "user".to_owned(),
                    kind: "text".to_owned(),
                    text_summary: "run provenance fixture".to_owned(),
                    artifact_id: None,
                    run_id: None,
                },
            )
            .expect("user message creates");
            database::create_agent_run(
                &connection,
                &database::NewAgentRunRow {
                    run_id: run_id.to_owned(),
                    conversation_id: conversation.conversation_id.clone(),
                    user_message_id: message_id.to_owned(),
                    provider_id: None,
                    provider_snapshot_json: "{}".to_owned(),
                    intent: intent.to_owned(),
                    status: status.to_owned(),
                    budget_json: "{}".to_owned(),
                },
            )
            .expect("run creates");
        }

        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("proposal transaction starts");
        for run_id in ["run:missing", "run:queued", "run:wrong-intent"] {
            let error = create_assistant_case_change_proposal_with_connection(
                &state,
                &transaction,
                &database::get_conversation(&transaction, &conversation.conversation_id)
                    .expect("conversation reads")
                    .expect("conversation exists"),
                &request,
                Some(run_id),
            )
            .expect_err("untrusted or ineligible run provenance is rejected");
            assert!(matches!(
                error.error_type.as_str(),
                "not_found" | "conflict"
            ));
        }
        let proposal = create_assistant_case_change_proposal_with_connection(
            &state,
            &transaction,
            &database::get_conversation(&transaction, &conversation.conversation_id)
                .expect("conversation reads")
                .expect("conversation exists"),
            &request,
            Some("run:eligible"),
        )
        .expect("eligible internal run creates proposal");
        assert_eq!(proposal.run_id.as_deref(), Some("run:eligible"));
        transaction.commit().expect("proposal commits");
    }

    #[test]
    fn proposal_apply_rolls_back_all_entities_and_leaves_pending_on_write_failure() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-rollback");
        insert_case_material(&state, "case-rollback", "material:rollback");
        let conversation = create_bound_conversation(&state, "case-rollback");
        let changes = assistant::CaseChangeSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            facts: fact_only_changes("fact:rollback", "material:rollback").facts,
            evidence: vec![assistant::EvidenceAddition {
                id: "evidence:rollback".to_owned(),
                title: "delivery record".to_owned(),
                summary: "supports the proposed delivery fact".to_owned(),
                proves_fact_ids: vec!["fact:rollback".to_owned()],
                source_refs: vec!["material:rollback".to_owned()],
            }],
            issues: Vec::new(),
            legal_basis: Vec::new(),
            attachment_transfers: Vec::new(),
            artifact_transfers: Vec::new(),
        };
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-rollback".to_owned(),
                changes,
            },
        )
        .expect("proposal creates")
        .proposal;
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        connection
            .execute_batch(
                "CREATE TRIGGER fixture_fail_assistant_evidence
                 BEFORE INSERT ON evidence_items
                 BEGIN
                   SELECT RAISE(ABORT, 'fixture evidence failure');
                 END;",
            )
            .expect("failure trigger installs");
        drop(connection);

        let failure = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-rollback".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("write failure aborts apply");
        assert_eq!(failure.error_type, "database");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let workspace = database::get_case_workspace_rows(&connection, "case-rollback")
            .expect("workspace reads")
            .expect("workspace exists");
        assert!(workspace.facts.is_empty());
        assert!(workspace.evidence.is_empty());
        assert_eq!(
            database::get_case_change_proposal(&connection, &proposal.proposal_id)
                .expect("proposal reads")
                .expect("proposal exists")
                .status,
            "pending"
        );
    }

    #[test]
    fn proposal_rejects_repealed_future_and_expired_legal_sources() {
        const CURRENT_SOURCE: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        const REPEALED_SOURCE: &str = "law:cn-contract-law-1999:cn-contract-law-19991001:art:107";

        for scenario in [
            "repealed_with_end",
            "repealed_without_end",
            "future_in_force",
            "expired_in_force",
        ] {
            let (_directory, state) = initialized_state();
            let project_id = format!("case-{scenario}");
            insert_project(&state, &project_id);
            let conversation = create_bound_conversation(&state, &project_id);
            let source_id = if scenario.starts_with("repealed") {
                REPEALED_SOURCE
            } else {
                CURRENT_SOURCE
            };

            let legal_connection = rusqlite::Connection::open(state.legal_core_path())
                .expect("legal fixture opens writable for mutation");
            match scenario {
                "repealed_with_end" => {}
                "repealed_without_end" => {
                    legal_connection
                        .execute(
                            "UPDATE law_versions SET effective_to = NULL
                             WHERE id = 'cn-contract-law-19991001'",
                            [],
                        )
                        .expect("repealed open-ended fixture mutates");
                }
                "future_in_force" => {
                    legal_connection
                        .execute(
                            "UPDATE law_versions
                             SET status = 'in_force', effective_from = '2999-01-01',
                                 effective_to = NULL
                             WHERE id = 'cn-civil-code-20210101'",
                            [],
                        )
                        .expect("future fixture mutates");
                }
                "expired_in_force" => {
                    legal_connection
                        .execute(
                            "UPDATE law_versions
                             SET status = 'in_force', effective_from = '1999-01-01',
                                 effective_to = '2000-01-01'
                             WHERE id = 'cn-civil-code-20210101'",
                            [],
                        )
                        .expect("expired fixture mutates");
                }
                _ => unreachable!(),
            }
            drop(legal_connection);

            let connection = database::open_user_database(state.user_database_path())
                .expect("user database opens");
            database::add_conversation_source(
                &connection,
                &conversation.conversation_id,
                source_id,
            )
            .expect("source links to conversation");
            drop(connection);

            let error = create_assistant_case_change_proposal_inner(
                &state,
                CreateAssistantCaseChangeProposalRequest {
                    conversation_id: conversation.conversation_id,
                    project_id,
                    changes: legal_basis_only_changes(&format!("basis:{scenario}"), source_id),
                },
            )
            .expect_err("non-current legal source is rejected");
            assert_eq!(error.error_type, "unvalidated_legal_source", "{scenario}");

            let connection = database::open_user_database(state.user_database_path())
                .expect("user database opens");
            let proposal_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM case_change_proposals", [], |row| {
                    row.get(0)
                })
                .expect("proposal count reads");
            assert_eq!(proposal_count, 0, "{scenario}");
        }
    }

    #[test]
    fn artifact_only_duplicate_proposals_become_stale_after_atomic_transfer() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-artifact-stale");
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "artifact transfer".to_owned(),
                project_id: None,
            },
        )
        .expect("unbound conversation creates")
        .conversation;
        let artifact = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "transfer memo".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "transfer memo".to_owned(),
                    answer: "bounded research".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("artifact creates")
        .detail
        .artifact;
        bind_assistant_conversation_inner(
            &state,
            BindAssistantConversationRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-artifact-stale".to_owned(),
            },
        )
        .expect("conversation binds");

        let artifact_changes = |title: &str| assistant::CaseChangeSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            facts: Vec::new(),
            evidence: Vec::new(),
            issues: Vec::new(),
            legal_basis: Vec::new(),
            attachment_transfers: Vec::new(),
            artifact_transfers: vec![assistant::ArtifactTransfer {
                artifact_id: artifact.artifact_id.clone(),
                title: title.to_owned(),
            }],
        };
        let mismatch = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-artifact-stale".to_owned(),
                changes: artifact_changes("renamed by proposal"),
            },
        )
        .expect_err("artifact title mismatch is rejected");
        assert_eq!(mismatch.error_type, "conflict");

        let first = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-artifact-stale".to_owned(),
                changes: artifact_changes(&artifact.title),
            },
        )
        .expect("first proposal creates")
        .proposal;
        let second = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-artifact-stale".to_owned(),
                changes: artifact_changes(&artifact.title),
            },
        )
        .expect("duplicate proposal creates before either is applied")
        .proposal;
        assert_eq!(first.base_case_digest, second.base_case_digest);

        let applied = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: first.proposal_id,
                project_id: "case-artifact-stale".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("first artifact transfer applies");
        assert!(applied.applied);
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let digest_after = database::case_workspace_digest(&connection, "case-artifact-stale")
            .expect("digest reads")
            .expect("case exists");
        assert_ne!(first.base_case_digest, digest_after);
        drop(connection);

        let stale = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: second.proposal_id,
                project_id: "case-artifact-stale".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("duplicate proposal resolves as stale");
        assert!(stale.stale);
        assert!(!stale.applied);

        let already_bound = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-artifact-stale".to_owned(),
                changes: artifact_changes(&artifact.title),
            },
        )
        .expect_err("already assigned artifact cannot form a new transfer proposal");
        assert_eq!(already_bound.error_type, "conflict");
    }

    #[test]
    fn attachment_claim_and_case_file_roll_back_when_later_artifact_transfer_fails() {
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-transfer-rollback");
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "rollback transfer".to_owned(),
                project_id: None,
            },
        )
        .expect("unbound conversation creates")
        .conversation;
        let imported = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![SelectedFileBytes {
                file_name: "rollback.txt".to_owned(),
                bytes: b"rollback attachment".to_vec(),
            }],
        )
        .expect("attachment imports");
        let attachment_id = imported.attachments[0].attachment_id.clone();
        let artifact = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "rollback memo".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "rollback memo".to_owned(),
                    answer: "rollback research".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("artifact creates")
        .detail
        .artifact;
        bind_assistant_conversation_inner(
            &state,
            BindAssistantConversationRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-transfer-rollback".to_owned(),
            },
        )
        .expect("conversation binds");

        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-transfer-rollback".to_owned(),
                changes: assistant::CaseChangeSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    facts: Vec::new(),
                    evidence: Vec::new(),
                    issues: Vec::new(),
                    legal_basis: Vec::new(),
                    attachment_transfers: vec![assistant::AttachmentTransfer {
                        attachment_id: attachment_id.clone(),
                        title: "rollback attachment".to_owned(),
                    }],
                    artifact_transfers: vec![assistant::ArtifactTransfer {
                        artifact_id: artifact.artifact_id.clone(),
                        title: artifact.title.clone(),
                    }],
                },
            },
        )
        .expect("transfer proposal creates")
        .proposal;
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER fixture_fail_artifact_transfer
                 BEFORE UPDATE OF project_id ON artifacts
                 WHEN OLD.artifact_id = '{}'
                 BEGIN
                   SELECT RAISE(ABORT, 'fixture artifact transfer failure');
                 END;",
                artifact.artifact_id
            ))
            .expect("failure trigger installs");
        drop(connection);

        let error = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id.clone(),
                project_id: "case-transfer-rollback".to_owned(),
                user_confirmed: true,
            },
        )
        .expect_err("later artifact failure rolls back attachment writes");
        assert_eq!(error.error_type, "database");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        assert_eq!(
            database::get_attachment(&connection, &attachment_id)
                .expect("attachment reads")
                .expect("attachment exists")
                .project_id,
            None
        );
        assert!(
            database::get_case_workspace_rows(&connection, "case-transfer-rollback")
                .expect("workspace reads")
                .expect("workspace exists")
                .files
                .is_empty()
        );
        assert_eq!(
            database::get_artifact(&connection, &artifact.artifact_id)
                .expect("artifact reads")
                .expect("artifact exists")
                .project_id,
            None
        );
        assert_eq!(
            database::get_case_change_proposal(&connection, &proposal.proposal_id)
                .expect("proposal reads")
                .expect("proposal exists")
                .status,
            "pending"
        );
    }

    #[test]
    fn multi_issue_legal_basis_uses_deterministic_prechecked_row_ids() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-multi-basis");
        insert_case_material(&state, "case-multi-basis", "material:multi-basis");
        let conversation = create_bound_conversation(&state, "case-multi-basis");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::add_conversation_source(&connection, &conversation.conversation_id, SOURCE_ID)
            .expect("source links");
        drop(connection);

        let mut changes = fact_only_changes("fact:multi-basis", "material:multi-basis");
        changes.issues = vec![
            assistant::IssueAddition {
                id: "issue:multi-basis:0".to_owned(),
                title: "first issue".to_owned(),
                analysis: "first issue analysis".to_owned(),
                related_fact_ids: vec!["fact:multi-basis".to_owned()],
                source_refs: Vec::new(),
            },
            assistant::IssueAddition {
                id: "issue:multi-basis:1".to_owned(),
                title: "second issue".to_owned(),
                analysis: "second issue analysis".to_owned(),
                related_fact_ids: vec!["fact:multi-basis".to_owned()],
                source_refs: Vec::new(),
            },
        ];
        changes.legal_basis = vec![assistant::LegalBasisAddition {
            id: "basis:multi".to_owned(),
            issue_ids: vec![
                "issue:multi-basis:0".to_owned(),
                "issue:multi-basis:1".to_owned(),
            ],
            source_ref: SOURCE_ID.to_owned(),
            marker: format!("[SRC:{SOURCE_ID}]"),
            citation: "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）".to_owned(),
            proposition: "该条规定涉及两个争议焦点中的合同违约责任。".to_owned(),
        }];
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-multi-basis".to_owned(),
                changes,
            },
        )
        .expect("multi-issue proposal creates")
        .proposal;
        apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id,
                project_id: "case-multi-basis".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("multi-issue proposal applies");

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let mut basis = database::get_case_workspace_rows(&connection, "case-multi-basis")
            .expect("workspace reads")
            .expect("workspace exists")
            .legal_basis;
        basis.sort_by(|left, right| left.basis_id.cmp(&right.basis_id));
        assert_eq!(basis.len(), 2);
        assert_eq!(basis[0].basis_id, "basis:multi");
        assert_eq!(basis[0].issue_id.as_deref(), Some("issue:multi-basis:0"));
        assert_eq!(basis[1].basis_id, "basis:multi:issue:1");
        assert_eq!(basis[1].issue_id.as_deref(), Some("issue:multi-basis:1"));
    }

    #[test]
    fn proposal_applies_all_confirmed_entities_and_hydrates_local_legal_metadata() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-complete");
        insert_case_material(&state, "case-complete", "material:complete");
        let conversation = create_assistant_conversation_inner(
            &state,
            CreateAssistantConversationRequest {
                title: "complete case proposal".to_owned(),
                project_id: None,
            },
        )
        .expect("unbound conversation creates")
        .conversation;
        let imported = import_assistant_files_inner(
            &state,
            ImportAssistantFilesRequest {
                conversation_id: conversation.conversation_id.clone(),
            },
            vec![SelectedFileBytes {
                file_name: "delivery.txt".to_owned(),
                bytes: b"delivered on time".to_vec(),
            }],
        )
        .expect("attachment imports");
        let attachment_id = imported.attachments[0].attachment_id.clone();
        let artifact = save_assistant_artifact_inner(
            &state,
            SaveAssistantArtifactRequest {
                conversation_id: conversation.conversation_id.clone(),
                artifact_id: None,
                expected_current_version: None,
                title: "research memo".to_owned(),
                draft: AssistantArtifactDraft::Research(ResearchArtifactSpec {
                    schema_version: assistant::CONTRACT_SCHEMA_VERSION,
                    title: "research memo".to_owned(),
                    answer: "reviewed research".to_owned(),
                    source_refs: Vec::new(),
                    assumptions: Vec::new(),
                    missing_information: Vec::new(),
                    risk_warnings: Vec::new(),
                }),
            },
            serde_json::Value::Null,
        )
        .expect("artifact saves")
        .detail
        .artifact;
        bind_assistant_conversation_inner(
            &state,
            BindAssistantConversationRequest {
                conversation_id: conversation.conversation_id.clone(),
                project_id: "case-complete".to_owned(),
            },
        )
        .expect("conversation binds");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        database::add_conversation_source(&connection, &conversation.conversation_id, SOURCE_ID)
            .expect("validated source links to conversation");
        drop(connection);

        let changes = assistant::CaseChangeSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            facts: vec![assistant::FactAddition {
                id: "fact:complete".to_owned(),
                statement: "Delivery occurred on the agreed date.".to_owned(),
                occurred_on: Some("2026-07-16".to_owned()),
                source_refs: vec!["material:complete".to_owned()],
            }],
            evidence: vec![assistant::EvidenceAddition {
                id: "evidence:complete".to_owned(),
                title: "delivery record".to_owned(),
                summary: "The imported record supports timely delivery.".to_owned(),
                proves_fact_ids: vec!["fact:complete".to_owned()],
                source_refs: vec![attachment_id.clone()],
            }],
            issues: vec![assistant::IssueAddition {
                id: "issue:complete".to_owned(),
                title: "timely performance".to_owned(),
                analysis: "The delivery date must be compared with the agreement.".to_owned(),
                related_fact_ids: vec!["fact:complete".to_owned()],
                source_refs: Vec::new(),
            }],
            legal_basis: vec![assistant::LegalBasisAddition {
                id: "basis:complete".to_owned(),
                issue_ids: vec!["issue:complete".to_owned()],
                source_ref: SOURCE_ID.to_owned(),
                marker: format!("[SRC:{SOURCE_ID}]"),
                citation: "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）".to_owned(),
                proposition: "认定合同违约责任时，应当结合该条规定与案件事实进行审查。".to_owned(),
            }],
            attachment_transfers: vec![assistant::AttachmentTransfer {
                attachment_id: attachment_id.clone(),
                title: "delivery record".to_owned(),
            }],
            artifact_transfers: vec![assistant::ArtifactTransfer {
                artifact_id: artifact.artifact_id.clone(),
                title: artifact.title.clone(),
            }],
        };
        let proposal = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-complete".to_owned(),
                changes,
            },
        )
        .expect("complete proposal creates")
        .proposal;
        assert!(proposal.source_refs.contains(&SOURCE_ID.to_owned()));
        let response = apply_assistant_case_change_proposal_inner(
            &state,
            ApplyAssistantCaseChangeProposalRequest {
                proposal_id: proposal.proposal_id,
                project_id: "case-complete".to_owned(),
                user_confirmed: true,
            },
        )
        .expect("complete proposal applies");
        assert!(response.applied);

        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let workspace = database::get_case_workspace_rows(&connection, "case-complete")
            .expect("workspace reads")
            .expect("workspace exists");
        assert_eq!(workspace.facts[0].confirmation_status, "confirmed");
        assert_eq!(workspace.evidence[0].confirmation_status, "confirmed");
        assert_eq!(workspace.legal_issues[0].confirmation_status, "confirmed");
        assert_eq!(workspace.evidence_links.len(), 1);
        assert_eq!(workspace.fact_issue_links.len(), 1);
        assert!(workspace
            .files
            .iter()
            .any(|file| { file.storage_reference == attachment_id }));
        assert_eq!(
            database::get_attachment(&connection, &attachment_id)
                .expect("attachment reads")
                .expect("attachment exists")
                .project_id
                .as_deref(),
            Some("case-complete")
        );
        let local_connection =
            database::open_legal_core_read_only(state.legal_core_path()).expect("legal core opens");
        let local_source = citations::source_by_citation_id(&local_connection, SOURCE_ID)
            .expect("source reads")
            .expect("source exists");
        assert_eq!(workspace.legal_basis.len(), 1);
        assert_eq!(workspace.legal_basis[0].status, "valid");
        assert_eq!(workspace.legal_basis[0].invalid_reason, None);
        assert_eq!(workspace.legal_basis[0].case_date, None);
        assert_eq!(
            workspace.legal_basis[0].document_id,
            local_source.document_id
        );
        assert_eq!(workspace.legal_basis[0].version_id, local_source.version_id);
        assert_eq!(
            workspace.legal_basis[0].effective_from,
            local_source.effective_from
        );
        assert_eq!(
            workspace.legal_basis[0].effective_to,
            local_source.effective_to
        );
        assert_eq!(
            workspace.legal_basis[0].version_status,
            local_source.version_status
        );
        assert_eq!(
            workspace.legal_basis[0].article_number,
            "第五百七十七条第一款"
        );
        assert_eq!(
            workspace.legal_basis[0].canonical_label,
            "《中华人民共和国民法典》第五百七十七条第一款"
        );
        assert_ne!(
            workspace.legal_basis[0].document_title,
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）"
        );
        drop(local_connection);
        drop(connection);
        let generated = state
            .legal_services()
            .expect("legal services initialize")
            .document_generate(legal_services::DocumentGenerateRequest {
                schema_version: legal_services::SERVICE_SCHEMA_VERSION,
                project_id: "case-complete".to_owned(),
                template_id: domain::document::DocumentTemplateId::LegalResearchReport,
                model_draft: None,
            })
            .expect("confirmed paragraph citation generates a reviewed document");
        assert_eq!(
            generated.document.citations[0].locator,
            "第五百七十七条第一款"
        );
        assert!(generated
            .document
            .markdown
            .contains("| 法条 | 《中华人民共和国民法典》 | 第五百七十七条第一款 | 2021年起施行 |"));
        let connection =
            database::open_user_database(state.user_database_path()).expect("database reopens");
        assert_eq!(
            database::get_artifact(&connection, &artifact.artifact_id)
                .expect("artifact reads")
                .expect("artifact exists")
                .project_id
                .as_deref(),
            Some("case-complete")
        );
    }

    #[test]
    fn proposal_rejects_unowned_legal_basis_and_closed_wire_unknown_fields() {
        const SOURCE_ID: &str = "law:cn-civil-code:cn-civil-code-20210101:art:577";
        let (_directory, state) = initialized_state();
        insert_project(&state, "case-unvalidated");
        insert_case_material(&state, "case-unvalidated", "material:unvalidated");
        let conversation = create_bound_conversation(&state, "case-unvalidated");
        let mut changes = fact_only_changes("fact:unvalidated", "material:unvalidated");
        changes.issues.push(assistant::IssueAddition {
            id: "issue:unvalidated".to_owned(),
            title: "unvalidated issue".to_owned(),
            analysis: "This issue has a fact but no owned legal source.".to_owned(),
            related_fact_ids: vec!["fact:unvalidated".to_owned()],
            source_refs: Vec::new(),
        });
        changes.legal_basis.push(assistant::LegalBasisAddition {
            id: "basis:unvalidated".to_owned(),
            issue_ids: vec!["issue:unvalidated".to_owned()],
            source_ref: SOURCE_ID.to_owned(),
            marker: format!("[SRC:{SOURCE_ID}]"),
            citation: "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）".to_owned(),
            proposition: "未经纳入当前案件的法律依据不得直接适用。".to_owned(),
        });
        let error = create_assistant_case_change_proposal_inner(
            &state,
            CreateAssistantCaseChangeProposalRequest {
                conversation_id: conversation.conversation_id,
                project_id: "case-unvalidated".to_owned(),
                changes,
            },
        )
        .expect_err("unowned local legal basis is rejected");
        assert_eq!(error.error_type, "invalid_contract");
        let connection =
            database::open_user_database(state.user_database_path()).expect("user database opens");
        let proposal_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM case_change_proposals", [], |row| {
                row.get(0)
            })
            .expect("proposal count reads");
        assert_eq!(proposal_count, 0);

        assert!(
            serde_json::from_value::<ApplyAssistantCaseChangeProposalRequest>(serde_json::json!({
                "proposalId": "proposal:1",
                "projectId": "case:1",
                "userConfirmed": true,
                "sql": "DELETE FROM case_facts"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateAssistantCaseChangeProposalRequest>(serde_json::json!({
                "conversationId": "conversation:1",
                "projectId": "case:1",
                "runId": "run:spoofed",
                "changes": fact_only_changes("fact:wire", "material:wire")
            }))
            .is_err(),
            "public proposal creation must not accept caller-supplied run provenance"
        );
    }
}
