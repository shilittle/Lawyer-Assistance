mod ai_routes;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use workspace_service::{Error, Workspace};

#[derive(Clone)]
pub struct AppState {
    pub workspace: Arc<Workspace>,
    pub origin: String,
    pub bootstrap: String,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    shutdown: CancellationToken,
}
struct Session {
    csrf: String,
    expires: u64,
}
pub struct ApiError(pub Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0.code.as_str() {
            "unauthorized" | "session_required" => StatusCode::UNAUTHORIZED,
            "origin_rejected" | "csrf_rejected" => StatusCode::FORBIDDEN,
            "not_found" | "task_not_found" | "result_not_found" => StatusCode::NOT_FOUND,
            "revision_conflict" | "idempotency_conflict" | "task_busy" | "conversation_busy" => {
                StatusCode::CONFLICT
            }
            _ => StatusCode::BAD_REQUEST,
        };
        let mut response = (status, Json(json!({"error":self.0}))).into_response();
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        response
    }
}
pub struct Input<T>(T);
impl<S, T> FromRequest<S> for Input<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|_| ApiError(Error::new("invalid_request")))?;
        Ok(Self(value))
    }
}
type ApiResult = Result<Json<Value>, ApiError>;
fn val<T: serde::Serialize>(v: T) -> ApiResult {
    serde_json::to_value(v)
        .map(Json)
        .map_err(|_| ApiError(Error::new("invalid_response")))
}
fn ok() -> ApiResult {
    Ok(Json(json!({"ok":true})))
}

impl AppState {
    pub fn new(workspace: Arc<Workspace>, origin: String, bootstrap: String) -> Self {
        Self::with_shutdown(workspace, origin, bootstrap, CancellationToken::new())
    }

    pub fn with_shutdown(
        workspace: Arc<Workspace>,
        origin: String,
        bootstrap: String,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            workspace,
            origin,
            bootstrap,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            shutdown,
        }
    }
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(ai_routes::routes())
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles))
        .route("/api.js", get(api_js))
        .route("/api/v1/session", post(login).get(session))
        .route("/api/v1/shutdown", post(shutdown_server))
        .route("/api/v1/health", get(health))
        .route("/api/v1/groups", get(groups).post(create_group))
        .route(
            "/api/v1/groups/{id}/dictionary",
            get(dictionary).put(set_dictionary),
        )
        .route("/api/v1/materials", get(materials))
        .route("/api/v1/materials/{id}", get(material))
        .route("/api/v1/materials/{id}/review", post(review))
        .route("/api/v1/materials/{id}/revoke", post(revoke))
        .route(
            "/api/v1/materials/{id}/replace",
            post(replace_material).layer(DefaultBodyLimit::max(21 * 1024 * 1024)),
        )
        .route(
            "/api/v1/imports",
            post(imports).layer(DefaultBodyLimit::max(105 * 1024 * 1024)),
        )
        .route("/api/v1/tasks/{id}", get(task))
        .route("/api/v1/tasks/{id}/cancel", post(cancel))
        .route("/api/v1/tasks/{id}/retry", post(retry))
        .route(
            "/api/v1/tasks/{id}/consent",
            post(consent).delete(revoke_consent),
        )
        .route("/api/v1/results/{id}/export", get(export_result))
        .route("/api/v1/exports", post(export_batch))
        .route("/api/v1/legal/search", get(legal_search))
        .route("/api/v1/legal/cases", get(judicial_case_search))
        .route("/api/v1/legal/cases/status", get(judicial_case_status))
        .route(
            "/api/v1/legal/cases/understand",
            post(judicial_case_understand),
        )
        .route("/api/v1/legal/cases/{id}", get(judicial_case_get))
        .route("/api/v1/legal/articles/{id}", get(legal_article))
        .route("/api/v1/legal/versions/{id}", get(legal_versions))
        .route("/api/v1/legal/relations/{id}", get(legal_relations))
        .route("/api/v1/bookmarks", get(bookmarks).post(save_bookmark))
        .route(
            "/api/v1/bookmarks/{id}",
            axum::routing::delete(delete_bookmark),
        )
        .route("/api/v1/templates", get(templates))
        .route("/api/v1/templates/preview", post(template_preview))
        .route("/api/v1/templates/export", post(template_export))
        .route("/api/v1/providers", get(providers).post(save_provider))
        .route(
            "/api/v1/conversations",
            get(conversations).post(create_conversation),
        )
        .route("/api/v1/conversations/{id}", get(conversation))
        .route("/api/v1/chat", post(chat))
        .route("/api/v1/chat/{id}", axum::routing::delete(cancel_chat))
        .route("/api/v1/mcp/clients", get(clients).post(create_client))
        .route(
            "/api/v1/mcp/clients/{id}",
            axum::routing::delete(revoke_client),
        )
        .route("/api/v1/mcp/submit", post(mcp_submit))
        .route("/api/v1/mcp/status", post(mcp_status))
        .route("/api/v1/mcp/read-result", post(mcp_read))
        .fallback(|| async { ApiError(Error::new("not_found")) })
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .with_state(state)
}
async fn security(State(s): State<AppState>, request: Request, next: Next) -> Response {
    let host = s.origin.trim_start_matches("http://");
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok());
    let req_host = request.headers().get("host").and_then(|v| v.to_str().ok());
    if request.headers().get_all("host").iter().count() != 1
        || request.headers().get_all("origin").iter().count() > 1
        || (request.headers().contains_key("origin") && origin.is_none())
        || req_host != Some(host)
        || origin.is_some_and(|v| v != s.origin)
    {
        return ApiError(Error::new("origin_rejected")).into_response();
    }
    let path = request.uri().path();
    let is_private_mcp = matches!(
        path,
        "/api/v1/mcp/submit" | "/api/v1/mcp/status" | "/api/v1/mcp/read-result"
    );
    if is_private_mcp {
        if bearer(request.headers())
            .and_then(|token| s.workspace.authenticate_client(token).map(|_| ()))
            .is_err()
        {
            return ApiError(Error::new("unauthorized")).into_response();
        }
    } else if path.starts_with("/api/")
        && !(path == "/api/v1/session" && request.method() == "POST")
    {
        let Some(cookie) = session_cookie(request.headers()) else {
            return ApiError(Error::new("session_required")).into_response();
        };
        let Ok(sessions) = s.sessions.lock() else {
            return ApiError(Error::new("session_required")).into_response();
        };
        let Some(active) = sessions
            .get(cookie)
            .filter(|v| v.expires > workspace_service::now())
        else {
            return ApiError(Error::new("session_required")).into_response();
        };
        if !matches!(request.method().as_str(), "GET" | "HEAD") {
            let csrf = request
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !bool::from(csrf.as_bytes().ct_eq(active.csrf.as_bytes())) {
                return ApiError(Error::new("csrf_rejected")).into_response();
            }
        }
    }
    let mut response = next.run(request).await;
    for (key,value) in [("cache-control","no-store"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")]{response.headers_mut().insert(key,HeaderValue::from_static(value));}
    response
}
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| p.trim().strip_prefix("la_session="))
}
fn bearer(headers: &HeaderMap) -> workspace_service::Result<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Error::new("unauthorized"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    token: String,
}
async fn login(State(s): State<AppState>, Input(r): Input<Login>) -> Result<Response, ApiError> {
    if !bool::from(r.token.as_bytes().ct_eq(s.bootstrap.as_bytes())) {
        return Err(Error::new("unauthorized").into());
    }
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let csrf = uuid::Uuid::new_v4().simple().to_string();
    let mut sessions = s
        .sessions
        .lock()
        .map_err(|_| Error::new("session_required"))?;
    sessions.retain(|_, v| v.expires > workspace_service::now());
    if sessions.len() > 64 {
        return Err(Error::new("session_limit").into());
    }
    sessions.insert(
        token.clone(),
        Session {
            csrf: csrf.clone(),
            expires: workspace_service::now() + 24 * 3600,
        },
    );
    let mut response = Json(json!({"authenticated":true,"csrf_token":csrf})).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "la_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
        ))
        .map_err(|_| Error::new("session_failed"))?,
    );
    Ok(response)
}
async fn session(State(s): State<AppState>, headers: HeaderMap) -> ApiResult {
    let token = session_cookie(&headers).ok_or_else(|| Error::new("session_required"))?;
    let sessions = s
        .sessions
        .lock()
        .map_err(|_| Error::new("session_required"))?;
    let active = sessions
        .get(token)
        .ok_or_else(|| Error::new("session_required"))?;
    Ok(Json(json!({"authenticated":true,"csrf_token":active.csrf})))
}
async fn shutdown_server(State(s): State<AppState>) -> ApiResult {
    s.shutdown.cancel();
    ok()
}
async fn index() -> impl IntoResponse {
    axum::response::Html(include_str!("../../web/index.html"))
}
async fn app_js() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../web/app.js"),
    )
}
async fn api_js() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../../web/api.js"),
    )
}
async fn styles() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("../../web/styles.css"),
    )
}
async fn health(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.health())
}
async fn groups(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.groups()?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
async fn create_group(State(s): State<AppState>, Input(r): Input<Name>) -> ApiResult {
    val(s.workspace.create_group(&r.name)?)
}
async fn dictionary(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.dictionary(&id)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dictionary {
    entries: Vec<privacy_text::DictionaryEntry>,
}
async fn set_dictionary(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(r): Input<Dictionary>,
) -> ApiResult {
    val(s.workspace.set_dictionary(&id, r.entries)?)
}
#[derive(Deserialize)]
struct MaterialQuery {
    group_id: Option<String>,
}
async fn materials(State(s): State<AppState>, Query(q): Query<MaterialQuery>) -> ApiResult {
    val(s.workspace.materials(q.group_id.as_deref())?)
}
async fn material(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.material_view(&id)?)
}
async fn review(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(r): Input<workspace_service::ReviewRequest>,
) -> ApiResult {
    val(s.workspace.review(&id, r)?)
}
async fn revoke(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    s.workspace.revoke_material(&id)?;
    ok()
}
async fn replace_material(
    State(s): State<AppState>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> ApiResult {
    let mut revision = None;
    let mut encoding = None;
    let mut file = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| Error::new("invalid_upload"))?
    {
        let key = field.name().unwrap_or("").to_owned();
        let name = field.file_name().map(str::to_owned);
        let bytes = field
            .bytes()
            .await
            .map_err(|_| Error::new("invalid_upload"))?;
        match key.as_str() {
            "file" if file.is_none() => {
                file = Some(workspace_service::ImportFile {
                    name: name.ok_or_else(|| Error::new("invalid_upload"))?,
                    bytes: bytes.to_vec(),
                    encoding: None,
                })
            }
            "revision" => {
                revision = Some(
                    std::str::from_utf8(&bytes)
                        .map_err(|_| Error::new("invalid_request"))?
                        .parse::<u64>()
                        .map_err(|_| Error::new("invalid_request"))?,
                )
            }
            "encoding" => {
                encoding = Some(
                    String::from_utf8(bytes.to_vec()).map_err(|_| Error::new("invalid_request"))?,
                )
            }
            _ => return Err(Error::new("invalid_upload").into()),
        }
    }
    let mut file = file.ok_or_else(|| Error::new("file_required"))?;
    file.encoding = encoding.filter(|s| !s.is_empty());
    val(s.workspace.replace_material(
        &id,
        revision.ok_or_else(|| Error::new("revision_required"))?,
        file,
    )?)
}
async fn task(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.task_status(&id)?)
}
async fn cancel(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.cancel_task(&id)?)
}
async fn retry(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.retry_task(&id)?)
}
async fn imports(State(s): State<AppState>, mut multipart: Multipart) -> ApiResult {
    let mut group = None;
    let mut request = None;
    let mut encoding = None;
    let mut files = Vec::new();
    let mut total = 0;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| Error::new("invalid_upload"))?
    {
        let key = field.name().unwrap_or("").to_owned();
        let filename = field.file_name().map(str::to_owned);
        let bytes = field
            .bytes()
            .await
            .map_err(|_| Error::new("invalid_upload"))?;
        total += bytes.len();
        if total > 100 * 1024 * 1024 {
            return Err(Error::new("batch_too_large").into());
        }
        if key == "files" || key == "file" {
            if files.len() >= 100 {
                return Err(Error::new("batch_too_large").into());
            }
            files.push(workspace_service::ImportFile {
                name: filename.ok_or_else(|| Error::new("invalid_upload"))?,
                bytes: bytes.to_vec(),
                encoding: None,
            });
        } else {
            let value =
                String::from_utf8(bytes.to_vec()).map_err(|_| Error::new("invalid_upload"))?;
            if value.len() > 256 {
                return Err(Error::new("invalid_upload").into());
            }
            match key.as_str() {
                "group_id" => group = Some(value),
                "request_id" => request = Some(value),
                "encoding" => encoding = Some(value),
                _ => return Err(Error::new("invalid_upload").into()),
            }
        }
    }
    for file in &mut files {
        file.encoding = encoding.clone().filter(|s| !s.is_empty());
    }
    val(s.workspace.submit(
        &group.ok_or_else(|| Error::new("group_required"))?,
        &request.ok_or_else(|| Error::new("request_id_required"))?,
        files,
        None,
    )?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    provider_id: String,
    model: String,
    purpose: String,
}
async fn consent(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Input(r): Input<Consent>,
) -> ApiResult {
    val(s
        .workspace
        .consent(&id, &r.provider_id, &r.model, &r.purpose)?)
}
async fn revoke_consent(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    s.workspace.revoke_consent(&id)?;
    ok()
}
#[derive(Deserialize)]
struct Format {
    format: String,
}
fn download(bytes: Vec<u8>, format: &str, name: &str) -> Result<Response, ApiError> {
    let mime = match format {
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "zip" => "application/zip",
        _ => return Err(Error::new("unsupported_format").into()),
    };
    let mut response = Body::from(bytes).into_response();
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static(mime));
    response.headers_mut().insert(
        "content-disposition",
        HeaderValue::from_str(&format!("attachment; filename=\"{name}.{format}\""))
            .map_err(|_| Error::new("export_failed"))?,
    );
    Ok(response)
}
async fn export_result(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<Format>,
) -> Result<Response, ApiError> {
    download(
        s.workspace.export_result(&id, &q.format)?,
        &q.format,
        "redacted",
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportBatch {
    material_ids: Vec<String>,
    format: String,
}
async fn export_batch(
    State(s): State<AppState>,
    Input(r): Input<ExportBatch>,
) -> Result<Response, ApiError> {
    download(
        s.workspace.export_batch(&r.material_ids, &r.format)?,
        "zip",
        "redacted-materials",
    )
}
#[derive(Deserialize)]
struct Search {
    query: String,
    case_date: Option<String>,
}
fn legal_error(_: legal_services::ServiceError) -> ApiError {
    Error::new("legal_query_failed").into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseSearch {
    query: String,
    case_type: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
    include_withdrawn: Option<bool>,
}
fn case_error(error: legal_services::ServiceError) -> ApiError {
    // Keep errors actionable without returning database paths or diagnostics.
    Error::new(&error.code).into()
}
async fn judicial_case_search(State(s): State<AppState>, Query(q): Query<CaseSearch>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .judicial_case_search(legal_services::JudicialCaseSearchRequest {
            schema_version: 1,
            query: q.query,
            case_type: q.case_type.filter(|v| !v.is_empty()),
            limit: q.limit,
            offset: q.offset,
            include_withdrawn: q.include_withdrawn,
        })
        .map_err(case_error)?)
}
async fn judicial_case_get(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .judicial_case_get(legal_services::JudicialCaseGetRequest {
            schema_version: 1,
            case_id: id,
        })
        .map_err(case_error)?)
}
async fn judicial_case_status(State(s): State<AppState>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .judicial_case_status()
        .map_err(case_error)?)
}
async fn judicial_case_understand(
    State(s): State<AppState>,
    Input(request): Input<workspace_service::CaseUnderstandingRequest>,
) -> ApiResult {
    val(s.workspace.understand_cases(request).await?)
}
async fn legal_search(State(s): State<AppState>, Query(q): Query<Search>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .legal_search(legal_services::LegalSearchRequest {
            schema_version: 1,
            query: q.query,
            document_id: None,
            case_date: q.case_date.filter(|v| !v.is_empty()),
            limit: Some(20),
        })
        .map_err(legal_error)?)
}
async fn legal_article(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .legal_get_article(legal_services::LegalGetArticleRequest {
            schema_version: 1,
            article_id: id,
        })
        .map_err(legal_error)?)
}
async fn legal_versions(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .legal_get_versions(legal_services::LegalGetVersionsRequest {
            schema_version: 1,
            document_id: id,
        })
        .map_err(legal_error)?)
}
async fn legal_relations(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s
        .workspace
        .legal()
        .legal_get_relations(legal_services::LegalGetRelationsRequest {
            schema_version: 1,
            document_id: id,
            direction: None,
        })
        .map_err(legal_error)?)
}
async fn bookmarks(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.bookmarks()?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BookmarkRequest {
    article_id: String,
    title: String,
}
async fn save_bookmark(State(s): State<AppState>, Input(r): Input<BookmarkRequest>) -> ApiResult {
    val(s.workspace.save_bookmark(&r.article_id, &r.title)?)
}
async fn delete_bookmark(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    s.workspace.delete_bookmark(&id)?;
    ok()
}
async fn templates() -> ApiResult {
    val(json!({"templates":domain::document::template_catalog()}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateRequest {
    template_id: domain::document::DocumentTemplateId,
    input: TemplateInput,
    format: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateInput {
    title: String,
    #[serde(alias = "partyA")]
    party_a: String,
    #[serde(alias = "partyB")]
    party_b: String,
    facts: String,
    requests: String,
    evidence: String,
    requirements: String,
}
impl From<TemplateInput> for domain::document::StandaloneDocumentInput {
    fn from(r: TemplateInput) -> Self {
        Self {
            title: r.title,
            party_a: r.party_a,
            party_b: r.party_b,
            facts: r.facts,
            requests: r.requests,
            evidence: r.evidence,
            requirements: r.requirements,
        }
    }
}
async fn template_preview(
    State(s): State<AppState>,
    Input(r): Input<TemplateRequest>,
) -> ApiResult {
    val(json!({"text":s.workspace.template_preview(r.template_id,r.input.into())?}))
}
async fn template_export(
    State(s): State<AppState>,
    Input(r): Input<TemplateRequest>,
) -> Result<Response, ApiError> {
    let format = r.format.unwrap_or_else(|| "docx".into());
    let text = s
        .workspace
        .template_preview(r.template_id, r.input.into())?;
    download(
        privacy_text::export_local_document(&text, &format)
            .map_err(|_| Error::new("export_failed"))?,
        &format,
        "document",
    )
}
async fn providers(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.providers()?)
}
async fn save_provider(
    State(s): State<AppState>,
    Input(r): Input<workspace_service::SaveProviderRequest>,
) -> ApiResult {
    val(s.workspace.save_provider(r)?)
}
async fn conversations(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.conversations()?)
}
#[derive(Deserialize)]
struct Title {
    title: String,
}
async fn create_conversation(State(s): State<AppState>, Input(r): Input<Title>) -> ApiResult {
    val(s.workspace.create_conversation(&r.title)?)
}
async fn conversation(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    val(s.workspace.conversation(&id)?)
}
async fn chat(
    State(s): State<AppState>,
    Input(r): Input<workspace_service::ChatRequest>,
) -> Result<Response, ApiError> {
    let receiver = s.workspace.start_chat(r)?;
    let stream = futures_util::stream::unfold(receiver, |mut rx| async {
        rx.recv().await.map(|value| {
            (
                Ok::<_, Infallible>(Event::default().data(value.to_string())),
                rx,
            )
        })
    });
    Ok(Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response())
}
async fn cancel_chat(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    s.workspace.cancel_chat(&id)?;
    ok()
}
async fn clients(State(s): State<AppState>) -> ApiResult {
    val(s.workspace.clients()?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRequest {
    name: String,
    group_id: String,
}
async fn create_client(State(s): State<AppState>, Input(r): Input<ClientRequest>) -> ApiResult {
    val(s.workspace.create_client(&r.name, &r.group_id)?)
}
async fn revoke_client(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult {
    s.workspace.revoke_client(&id)?;
    ok()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpSubmit {
    request_id: String,
    inbox_relative_paths: Vec<String>,
}
async fn mcp_submit(
    State(s): State<AppState>,
    headers: HeaderMap,
    Input(r): Input<McpSubmit>,
) -> ApiResult {
    val(s
        .workspace
        .mcp_submit(bearer(&headers)?, &r.request_id, r.inbox_relative_paths)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpTask {
    task_id: String,
}
async fn mcp_status(
    State(s): State<AppState>,
    headers: HeaderMap,
    Input(r): Input<McpTask>,
) -> ApiResult {
    val(s.workspace.mcp_status(bearer(&headers)?, &r.task_id)?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpRead {
    result_id: String,
    cursor: Option<String>,
}
async fn mcp_read(
    State(s): State<AppState>,
    headers: HeaderMap,
    Input(r): Input<McpRead>,
) -> ApiResult {
    val(s
        .workspace
        .mcp_read(bearer(&headers)?, &r.result_id, r.cursor.as_deref())?)
}
