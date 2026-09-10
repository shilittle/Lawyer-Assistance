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
        .route("/api/v1/ai/runs/{id}/export", get(export_document))
        .route(
            "/api/v1/ai/conversations",
            get(conversations).post(create_conversation),
        )
        .route(
            "/api/v1/ai/conversations/{id}",
            get(conversation).merge(patch(rename_conversation)),
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
    val(s.workspace.discover_ai_models(r).await?)
}
async fn test_model(State(s): State<AppState>, Input(r): Input<AiModelSelection>) -> ApiResult {
    val(s.workspace.test_ai_model(r).await?)
}
async fn defaults(
    State(s): State<AppState>,
    Input(r): Input<BTreeMap<String, AiModelSelection>>,
) -> ApiResult {
    val(s.workspace.save_ai_defaults(r)?)
}
async fn materials(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.ai_materials()?)
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
    val(s.workspace.ai_runs(q.get("kind").map(String::as_str))?)
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentEdit {
    content: String,
}
async fn edit_document(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(r): Input<ContentEdit>,
) -> ApiResult {
    val(s.workspace.edit_ai_document(&id, r.content)?)
}
async fn export_document(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let format = q.get("format").cloned().unwrap_or_else(|| "pdf".into());
    let f = format.clone();
    let workspace = s.workspace.clone();
    let bytes = tokio::task::spawn_blocking(move || workspace.export_ai_document(&id, &f))
        .await
        .map_err(|_| Error::new("export_failed"))??;
    download(bytes, &format, "document")
}
async fn conversations(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.ai_conversations()?)
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
    let legal = s.workspace.legal().clone();
    val(
        tokio::task::spawn_blocking(move || legal.legal_search_page(request))
            .await
            .map_err(|_| Error::new("legal_query_failed"))?
            .map_err(legal_error)?,
    )
}
async fn version_articles(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let request = legal_services::LegalVersionArticlesRequest {
        schema_version: 1,
        version_id: id,
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
    let legal = s.workspace.legal().clone();
    val(
        tokio::task::spawn_blocking(move || legal.legal_version_articles(request))
            .await
            .map_err(|_| Error::new("legal_query_failed"))?
            .map_err(legal_error)?,
    )
}
async fn search_filters(State(s): State<AppState>) -> ApiResult {
    let legal = s.workspace.legal().clone();
    val(
        tokio::task::spawn_blocking(move || legal.legal_search_facets())
            .await
            .map_err(|_| Error::new("legal_query_failed"))?
            .map_err(legal_error)?,
    )
}
