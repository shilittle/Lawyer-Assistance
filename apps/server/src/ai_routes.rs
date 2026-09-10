use super::*;
use axum::routing::{patch, put};
use std::collections::BTreeMap;
use workspace_service::{AiModelSelection, AiProviderRequest, AiRunRequest};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ai/usage", get(usage))
        .route("/api/v1/ai/providers", get(providers).post(save_provider))
        .route("/api/v1/ai/providers/models", post(models))
        .route("/api/v1/ai/providers/test", post(test_model))
        .route("/api/v1/ai/defaults", put(defaults))
        .route("/api/v1/ai/context/estimate", post(estimate_context))
        .route("/api/v1/ai/materials", get(materials))
        .route(
            "/api/v1/ai/attachments",
            post(attachment).layer(DefaultBodyLimit::max(21 * 1024 * 1024)),
        )
        .route("/api/v1/ai/runs", get(runs).post(start_run))
        .route("/api/v1/ai/runs/{id}", get(run).delete(delete_run))
        .route("/api/v1/ai/runs/{id}/cancel", post(cancel_run))
        .route("/api/v1/ai/runs/{id}/continue", post(continue_run))
        .route("/api/v1/ai/runs/{id}/content", put(edit_document))
        .route(
            "/api/v1/ai/runs/{id}/citations/recheck",
            post(recheck_citations),
        )
        .route("/api/v1/ai/runs/{id}/export", get(export_document))
        .route(
            "/api/v1/ai/drafts/{id}",
            get(draft).put(save_draft).delete(delete_draft),
        )
        .route(
            "/api/v1/ai/conversations",
            get(conversations).post(create_conversation),
        )
        .route(
            "/api/v1/ai/conversations/{id}",
            get(conversation).merge(patch(rename_conversation)),
        )
        .route(
            "/api/v1/ai/conversations/{id}/context",
            put(replace_conversation_context),
        )
        .route(
            "/api/v1/ai/conversations/{id}/context/prepare",
            post(prepare_conversation_context),
        )
        .route("/api/v1/legal/search/page", get(search_page))
        .route("/api/v1/legal/filters", get(search_filters))
        .route("/api/v1/legal/version-articles/{id}", get(version_articles))
}
async fn usage(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.ai_usage()?)
}
async fn providers(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.ai_providers()?)
}
async fn save_provider(State(s): State<AppState>, Input(r): Input<AiProviderRequest>) -> ApiResult {
    val(s.workspace.save_ai_provider(r)?)
}
async fn models(State(s): State<AppState>, Input(r): Input<AiProviderRequest>) -> ApiResult {
    let cancel = CancellationToken::new();
    let _permit = s
        .workspace
        .acquire_admission(workspace_service::AdmissionClass::Ai, &cancel)
        .await?;
    val(s.workspace.discover_ai_models(r).await?)
}
async fn test_model(State(s): State<AppState>, Input(r): Input<AiModelSelection>) -> ApiResult {
    let cancel = CancellationToken::new();
    let _permit = s
        .workspace
        .acquire_admission(workspace_service::AdmissionClass::Ai, &cancel)
        .await?;
    val(s.workspace.test_ai_model(r).await?)
}
async fn defaults(
    State(s): State<AppState>,
    Input(r): Input<BTreeMap<String, AiModelSelection>>,
) -> ApiResult {
    val(s.workspace.save_ai_defaults(r)?)
}
async fn estimate_context(State(s): State<AppState>, Input(r): Input<AiRunRequest>) -> ApiResult {
    val(s.workspace.estimate_ai_context(&r)?)
}
async fn materials(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let (limit, cursor) = list_page(&q)?;
    val(s.workspace.ai_materials_page(cursor, limit)?)
}
async fn attachment(State(s): State<AppState>, mut multipart: Multipart) -> ApiResult {
    let mut file = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| Error::new("invalid_upload"))?
    {
        if field.file_name().is_some() {
            if file.is_some() {
                return Err(Error::new("one_attachment_per_upload").into());
            }
            let name = field.file_name().unwrap_or_default().to_owned();
            let bytes = field
                .bytes()
                .await
                .map_err(|_| Error::new("invalid_upload"))?;
            file = Some((name, bytes.to_vec()));
        }
    }
    let (name, bytes) = file.ok_or_else(|| Error::new("attachment_required"))?;
    val(s.workspace.save_ai_attachment(name, bytes)?)
}
async fn runs(State(s): State<AppState>, Query(q): Query<HashMap<String, String>>) -> ApiResult {
    let (limit, cursor) = list_page(&q)?;
    val(s
        .workspace
        .ai_runs_page(q.get("kind").map(String::as_str), cursor, limit)?)
}
async fn start_run(State(s): State<AppState>, Input(r): Input<AiRunRequest>) -> ApiResult {
    val(s.workspace.start_ai_run(r)?)
}
async fn run(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.ai_run(&id)?)
}
async fn delete_run(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.delete_ai_run(&id)?)
}
async fn cancel_run(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.cancel_ai_run(&id)?)
}
async fn continue_run(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.continue_ai_run(&id)?)
}
fn versioned<T: DeserializeOwned>(value: Value) -> workspace_service::Result<T> {
    if value
        .get("expected_revision")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(Error::new("revision_required"));
    }
    serde_json::from_value(value).map_err(|_| Error::new("invalid_request"))
}
async fn edit_document(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(value): Input<Value>,
) -> ApiResult {
    let request = versioned::<workspace_service::AiDocumentEdit>(value)?;
    val(s.workspace.edit_ai_document(&id, request)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRevision {
    expected_revision: u64,
}
async fn recheck_citations(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(value): Input<Value>,
) -> ApiResult {
    let request = versioned::<ExpectedRevision>(value)?;
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    val(s
        .workspace
        .recheck_ai_citations(&id, request.expected_revision, &cancel)
        .await?)
}
async fn export_document(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let format = q.get("format").cloned().unwrap_or_else(|| "pdf".into());
    let expected_revision = q
        .get("expected_revision")
        .ok_or_else(|| Error::new("revision_required"))?
        .parse::<u64>()
        .map_err(|_| Error::new("revision_required"))?;
    let f = format.clone();
    let workspace = s.workspace.clone();
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    let permit = workspace
        .acquire_admission(workspace_service::AdmissionClass::Parse, &cancel)
        .await?;
    let bytes = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        workspace.export_ai_document_cancellable(&id, expected_revision, &f, &cancel)
    })
    .await
    .map_err(|_| Error::new("export_failed"))??;
    download(bytes, &format, "document")
}

async fn draft(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.ai_draft(&id)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftEdit {
    expected_revision: u64,
    content: Value,
}

async fn save_draft(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(value): Input<Value>,
) -> ApiResult {
    let r = versioned::<DraftEdit>(value)?;
    val(s
        .workspace
        .save_ai_draft(&id, r.expected_revision, r.content)?)
}

async fn delete_draft(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let expected_revision = q
        .get("expected_revision")
        .ok_or_else(|| Error::new("revision_required"))?
        .parse::<u64>()
        .map_err(|_| Error::new("revision_required"))?;
    val(s.workspace.delete_ai_draft(&id, expected_revision)?)
}
async fn conversations(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let (limit, cursor) = list_page(&q)?;
    val(s.workspace.ai_conversations_page(cursor, limit)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Title {
    title: Option<String>,
}
async fn create_conversation(State(s): State<AppState>, Input(r): Input<Title>) -> ApiResult {
    val(s.workspace.create_ai_conversation(r.title)?)
}
async fn conversation(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.ai_conversation(&id)?)
}
async fn rename_conversation(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(r): Input<Title>,
) -> ApiResult {
    val(s
        .workspace
        .rename_ai_conversation(&id, r.title.as_deref().unwrap_or_default())?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextReplace {
    expected_revision: u64,
    #[serde(default)]
    materials: Vec<workspace_service::AiMaterialReference>,
    #[serde(default)]
    attachment_ids: Vec<String>,
}

async fn replace_conversation_context(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(value): Input<Value>,
) -> ApiResult {
    let r = versioned::<ContextReplace>(value)?;
    val(s.workspace.replace_ai_conversation_context(
        &id,
        r.expected_revision,
        r.materials,
        r.attachment_ids,
    )?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPrepare {
    expected_revision: u64,
    provider_id: Option<String>,
    model: Option<String>,
}

async fn prepare_conversation_context(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(value): Input<Value>,
) -> ApiResult {
    let r = versioned::<ContextPrepare>(value)?;
    val(s.workspace.prepare_ai_conversation_context(
        &id,
        r.expected_revision,
        r.provider_id,
        r.model,
    )?)
}
async fn search_page(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let mut request = json!({"schemaVersion":1,"query":""});
    for (k, v) in q {
        if v.is_empty() {
            continue;
        }
        let name = match k.as_str() {
            "document_id" => "documentId",
            "case_date" => "caseDate",
            "document_type" => "documentType",
            "effectiveness_level" => "effectivenessLevel",
            "match_mode" => "matchMode",
            "version_scope" => "versionScope",
            "version_status" => "versionStatus",
            other => other,
        };
        if ["limit", "offset"].contains(&name) {
            request[name] = json!(v
                .parse::<u32>()
                .map_err(|_| Error::new("invalid_pagination"))?);
        } else {
            request[name] = json!(v);
        }
    }
    let request = serde_json::from_value::<legal_services::LegalPagedSearchRequest>(request)
        .map_err(|_| Error::new("invalid_search_request"))?;
    val(legal_job(&s.workspace, move |legal, cancel| {
        legal.legal_search_page_cancellable(request, &cancel)
    })
    .await?)
}
async fn version_articles(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let (version_scope, case_date) = legal_read_scope(&q)?;
    let request = legal_services::LegalVersionArticlesScopedRequest {
        schema_version: 1,
        version_id: id,
        version_scope,
        case_date,
        limit: q
            .get("limit")
            .map(|v| v.parse::<u32>())
            .transpose()
            .map_err(|_| Error::new("invalid_pagination"))?,
        offset: q
            .get("offset")
            .map(|v| v.parse::<u32>())
            .transpose()
            .map_err(|_| Error::new("invalid_pagination"))?,
    };
    val(legal_job(&s.workspace, move |legal, cancel| {
        legal.legal_version_articles_scoped_cancellable(request, &cancel)
    })
    .await?)
}
async fn search_filters(State(s): State<AppState>) -> ApiResult {
    val(legal_job(&s.workspace, move |legal, cancel| {
        legal.legal_search_facets_cancellable(&cancel)
    })
    .await?)
}
