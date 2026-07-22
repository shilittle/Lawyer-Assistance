use super::{qualification::ExpectedQualificationBinding, *};
use legal_mcp::approved_backend::{
    ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError,
    ApprovedWorkspaceQualificationProvider,
};
#[cfg(test)]
use legal_mcp::{
    config::{BearerSecret, Command, Limits, ResolvedConfig},
    handler::LegalMcpServer,
    registry::{PrivacyProfile, ToolRegistry},
    service_adapter::ServiceAdapter,
};
#[cfg(test)]
use legal_services::{LegalServices, ServiceConfig};
use privacy::vnext::Sha256Hex;
use serde_json::{json, Value};
use std::{fs, path::Path, sync::Arc, time::Duration};
use std::{
    io::{BufRead, BufReader as StdBufReader, Read as StdRead, Write as StdWrite},
    net::{SocketAddr, TcpListener},
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::Instant,
};
#[cfg(test)]
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines};
#[cfg(test)]
use tokio_util::sync::CancellationToken;

const CANARY_CONTENT: &[u8] = b"[PERSON_001] approved MCP qualification material";
const CANARY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WIRE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct CanaryQualificationProvider(ApprovedMcpQualificationSnapshotV1);

impl ApprovedWorkspaceQualificationProvider for CanaryQualificationProvider {
    fn current_qualification(
        &self,
        _now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError> {
        Ok(self.0.clone())
    }
}

struct CanaryRoot {
    path: PathBuf,
}

impl Drop for CanaryRoot {
    fn drop(&mut self) {
        let valid_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                (name.starts_with("mcpq-canary-") && name.len() == 45)
                    || (name.starts_with("mcpqcanary_") && name.len() == 43)
            });
        let valid_parent = self
            .path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("canary-runs");
        let safe_directory = fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
        if valid_name && valid_parent && safe_directory {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct CanaryIds {
    case_id: String,
    material_id: String,
    publication_id: String,
}

pub(super) async fn run(
    production: &ApprovedMcpWorkspace,
    expected: &ExpectedQualificationBinding,
) -> Result<(), ApprovedMcpError> {
    let fixed_app_root = legal_mcp::standalone_approved::default_app_local_data_directory()
        .map_err(|_| canary_error())?;
    let production_root =
        fs::canonicalize(&production.inner.app_local_data_directory).map_err(|_| canary_error())?;
    let fixed_app_root = fs::canonicalize(fixed_app_root).map_err(|_| canary_error())?;
    if production_root != fixed_app_root {
        return Err(canary_error());
    }

    let now_unix = now_seconds()?;
    let canary_id = format!("mcpqcanary_{}", Uuid::new_v4().simple());
    let root = create_external_canary_root(production, &canary_id)?;
    let app_local = root.path.join("app-local");
    fs::create_dir(&app_local).map_err(|_| canary_error())?;
    let candidate_control = super::qualification::DesktopApprovedMcpQualificationProvider::new(
        app_local
            .join("privacy")
            .join("approved-mcp")
            .join("qualification"),
        Arc::clone(&production.inner.keys),
        expected.binary_path.clone(),
    );
    let candidate_expected = candidate_control.begin_run()?;
    if &candidate_expected != expected {
        return Err(canary_error());
    }
    let candidate = candidate_control.persist_candidate(
        &candidate_expected,
        now_unix.saturating_sub(1).max(1),
        now_unix.checked_add(10 * 60).ok_or_else(canary_error)?,
    )?;
    let canary_workspace = ApprovedMcpWorkspace::from_parts(
        app_local,
        Arc::new(CanaryQualificationProvider(candidate.clone())),
        Arc::clone(&production.inner.keys),
        None,
    );
    let ids = seed_approved_material(&canary_workspace, &candidate, now_unix)?;
    let service_root = root.path.join("legal-services");
    prepare_legal_service_files(&service_root)?;
    let host = |http_bind| StandaloneMcpHostBinding {
        legal_database_path: service_root.join("legal.sqlite"),
        user_database_path: service_root.join("user.sqlite"),
        allowed_roots: vec![service_root.join("materials")],
        output_root: service_root.join("output"),
        http_bind,
        allowed_origins: if http_bind.is_some() {
            vec!["https://local.qualification.invalid".to_owned()]
        } else {
            Vec::new()
        },
    };

    let stdio = canary_workspace.provision_standalone_session(
        "app".to_owned(),
        McpTransportBindingV1::Stdio,
        vec![
            ApprovedMcpGrantGroupV1::Read,
            ApprovedMcpGrantGroupV1::Write,
        ],
        5 * 60,
        host(None),
    )?;
    let stdio_server_id = stdio.metadata.server_instance_id.clone();
    drop(stdio);
    let binary = expected.binary_path.clone();
    let stdio_canary_id = canary_id.clone();
    let launched_stdio_server_id = stdio_server_id.clone();
    let stdio_ids = CanaryIds {
        case_id: ids.case_id.clone(),
        material_id: ids.material_id.clone(),
        publication_id: ids.publication_id.clone(),
    };
    tokio::task::spawn_blocking(move || {
        run_external_stdio(
            &binary,
            &stdio_canary_id,
            &launched_stdio_server_id,
            &stdio_ids,
        )
    })
    .await
    .map_err(|_| canary_error())??;
    canary_workspace.revoke_standalone_session(&stdio_server_id)?;

    let bind = reserve_loopback_address()?;
    let mut http = canary_workspace.provision_standalone_session(
        "app".to_owned(),
        McpTransportBindingV1::StreamableHttp,
        vec![
            ApprovedMcpGrantGroupV1::Read,
            ApprovedMcpGrantGroupV1::Write,
        ],
        5 * 60,
        host(Some(bind)),
    )?;
    let http_server_id = http.metadata.server_instance_id.clone();
    let endpoint = http.metadata.endpoint.clone().ok_or_else(canary_error)?;
    let bearer = http.take_http_bearer().ok_or_else(canary_error)?;
    drop(http);
    run_external_http(
        &expected.binary_path,
        &canary_id,
        &http_server_id,
        &endpoint,
        bearer.as_str(),
        &ids,
    )
    .await?;
    canary_workspace.revoke_standalone_session(&http_server_id)?;
    Ok(())
}

fn create_external_canary_root(
    production: &ApprovedMcpWorkspace,
    canary_id: &str,
) -> Result<CanaryRoot, ApprovedMcpError> {
    let parent = production
        .inner
        .app_local_data_directory
        .join(legal_mcp::standalone_approved::QUALIFICATION_CANARY_RUNS_RELATIVE);
    fs::create_dir_all(&parent).map_err(|_| canary_error())?;
    let metadata = fs::symlink_metadata(&parent).map_err(|_| canary_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(canary_error());
    }
    let path = parent.join(canary_id);
    fs::create_dir(&path).map_err(|_| canary_error())?;
    Ok(CanaryRoot { path })
}

fn external_command(
    binary: &Path,
    canary_id: &str,
    server_id: &str,
    subcommand: &str,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(binary);
    command
        .arg("--privacy-profile")
        .arg("approved_case_workspace")
        .arg("--approved-session-id")
        .arg(server_id)
        .arg("--approved-qualification-canary-id")
        .arg(canary_id)
        .arg(subcommand)
        .env("LAWYER_ASSISTANCE_MCP_LOG", "off");
    command
}

fn run_external_stdio(
    binary: &Path,
    canary_id: &str,
    server_id: &str,
    ids: &CanaryIds,
) -> Result<(), ApprovedMcpError> {
    let mut child = external_command(binary, canary_id, server_id, "stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| canary_error())?;
    let mut stdin = child.stdin.take().ok_or_else(canary_error)?;
    let stdout = child.stdout.take().ok_or_else(canary_error)?;
    let mut stdout = StdBufReader::new(stdout);
    let stderr = capture_process_stderr(child.stderr.take().ok_or_else(canary_error)?);

    write_process_line(&mut stdin, &initialize_request(1))?;
    let initialized = read_process_line(&mut stdout)?;
    if initialized["result"]["protocolVersion"] != "2025-11-25" {
        terminate_child(&mut child);
        return Err(canary_error());
    }
    write_process_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )?;
    let read = tool_request(
        2,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    );
    write_process_line(&mut stdin, &read)?;
    require_success(&read_process_line(&mut stdout)?, "")?;

    let write = tool_request(
        3,
        "case_write_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"task_type":"case_analysis",
            "status":"draft","source_approved_refs":[{"material_id":ids.material_id,
            "publication_id":ids.publication_id}],"content_media_type":"text/plain",
            "content":"[PERSON_001] stdio qualification work product",
            "idempotency_key":format!("idem_{}",Uuid::new_v4().simple())}),
    );
    write_process_line(&mut stdin, &write)?;
    let written = read_process_line(&mut stdout)?;
    require_success(&written, "")?;
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .ok_or_else(canary_error)?;
    let reread = tool_request(
        4,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":work_product_id,"version":1}),
    );
    write_process_line(&mut stdin, &reread)?;
    require_success(&read_process_line(&mut stdout)?, "")?;
    write_process_line(&mut stdin, &reread)?;
    require_wire_replay(&read_process_line(&mut stdout)?)?;
    drop(stdin);
    let status = wait_child(&mut child)?;
    let stderr = stderr
        .join()
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?;
    if !status.success() || !stderr.is_empty() {
        return Err(canary_error());
    }
    Ok(())
}

async fn run_external_http(
    binary: &Path,
    canary_id: &str,
    server_id: &str,
    endpoint: &str,
    bearer: &str,
    ids: &CanaryIds,
) -> Result<(), ApprovedMcpError> {
    let mut child = external_command(binary, canary_id, server_id, "serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| canary_error())?;
    let stderr = capture_process_stderr(child.stderr.take().ok_or_else(canary_error)?);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(CANARY_TIMEOUT)
        .build()
        .map_err(|_| canary_error())?;
    let mut ready = false;
    for _ in 0..50 {
        if let Ok((_, response)) = post_http(&client, endpoint, bearer, initialize_request(1)).await
        {
            if response["result"]["protocolVersion"] == "2025-11-25" {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        terminate_child(&mut child);
        return Err(canary_error());
    }
    let read = tool_request(
        2,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    );
    let (_, read_response) = post_http(&client, endpoint, bearer, read).await?;
    require_success(&read_response, "")?;
    let write = tool_request(
        3,
        "case_write_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"task_type":"case_analysis",
            "status":"draft","source_approved_refs":[{"material_id":ids.material_id,
            "publication_id":ids.publication_id}],"content_media_type":"text/plain",
            "content":"[PERSON_001] HTTP qualification work product",
            "idempotency_key":format!("idem_{}",Uuid::new_v4().simple())}),
    );
    let (_, written) = post_http(&client, endpoint, bearer, write).await?;
    require_success(&written, "")?;
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .ok_or_else(canary_error)?;
    let reread = tool_request(
        4,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":work_product_id,"version":1}),
    );
    let (_, first) = post_http(&client, endpoint, bearer, reread.clone()).await?;
    require_success(&first, "")?;
    let (_, replay) = post_http(&client, endpoint, bearer, reread).await?;
    require_wire_replay(&replay)?;
    terminate_child(&mut child);
    let stderr = stderr
        .join()
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?;
    if !stderr.is_empty() {
        return Err(canary_error());
    }
    Ok(())
}

fn initialize_request(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"lawyer-assistance-mcp-qualification",
        "version":env!("CARGO_PKG_VERSION")}}})
}

fn tool_request(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":name,"arguments":arguments}})
}

fn write_process_line(writer: &mut impl StdWrite, value: &Value) -> Result<(), ApprovedMcpError> {
    serde_json::to_writer(&mut *writer, value).map_err(|_| canary_error())?;
    writer.write_all(b"\n").map_err(|_| canary_error())?;
    writer.flush().map_err(|_| canary_error())
}

fn read_process_line(reader: &mut impl BufRead) -> Result<Value, ApprovedMcpError> {
    let mut line = String::new();
    let read = reader.read_line(&mut line).map_err(|_| canary_error())?;
    if read == 0 || read > MAX_WIRE_RESPONSE_BYTES {
        return Err(canary_error());
    }
    serde_json::from_str(&line).map_err(|_| canary_error())
}

fn require_wire_replay(response: &Value) -> Result<(), ApprovedMcpError> {
    if response["result"]["isError"] != true
        || response["result"]["structuredContent"]["reason_code"] != "WIRE_REQUEST_REPLAYED"
    {
        return Err(canary_error());
    }
    Ok(())
}

fn capture_process_stderr(
    stream: impl std::io::Read + Send + 'static,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .take(u64::try_from(MAX_WIRE_RESPONSE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn wait_child(child: &mut Child) -> Result<std::process::ExitStatus, ApprovedMcpError> {
    let deadline = Instant::now() + CANARY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                terminate_child(child);
                return Err(canary_error());
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn reserve_loopback_address() -> Result<SocketAddr, ApprovedMcpError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| canary_error())?;
    listener.local_addr().map_err(|_| canary_error())
}

#[cfg(test)]
pub(super) async fn run_in_process(
    production: &ApprovedMcpWorkspace,
    expected: &ExpectedQualificationBinding,
) -> Result<(), ApprovedMcpError> {
    let now_unix = now_seconds()?;
    let evidence_id = format!("mcpq_{}", Uuid::new_v4().simple());
    let qualification = ApprovedMcpQualificationSnapshotV1 {
        evidence_id,
        evidence_sha256: canary_hash(b"in-process qualification bootstrap")?,
        stdio_canary_passed: true,
        streamable_http_canary_passed: true,
        exact_app_policy_binding: true,
        exact_server_key_binding: true,
        mcp_binary_path_identity_sha256: expected.binary_path_identity_sha256.clone(),
        mcp_binary_file_identity_sha256: expected.binary_file_identity_sha256.clone(),
        mcp_binary_sha256: expected.binary_sha256.clone(),
        mcp_binary_version: expected.binary_version.clone(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        policy_id: "approved-mcp-local-egress-v1".to_owned(),
        policy_version: 1,
        server_key_id: expected.server_key_id.clone(),
        server_key_version: expected.server_key_version,
        revocation_epoch: expected.revocation_epoch,
        issued_at_unix: now_unix.saturating_sub(1),
        expires_at_unix: now_unix.checked_add(10 * 60).ok_or_else(canary_error)?,
        revoked: false,
    };
    let root = create_canary_root(production)?;
    let canary_workspace = ApprovedMcpWorkspace::from_parts(
        root.path.join("app-local"),
        Arc::new(CanaryQualificationProvider(qualification.clone())),
        Arc::clone(&production.inner.keys),
        None,
    );
    let ids = seed_approved_material(&canary_workspace, &qualification, now_unix)?;
    let service_root = root.path.join("legal-services");
    prepare_legal_service_files(&service_root)?;

    let stdio_session =
        canary_workspace.prepare_required_session_at(McpTransportBindingV1::Stdio, now_unix)?;
    run_stdio(&stdio_session, &ids, &service_root).await?;
    stdio_session.revoke_all()?;

    let http_session = canary_workspace
        .prepare_required_session_at(McpTransportBindingV1::StreamableHttp, now_unix)?;
    if http_session.backend.server_instance_id() == stdio_session.backend.server_instance_id()
        || http_session.backend.session_id() == stdio_session.backend.session_id()
    {
        return Err(canary_error());
    }
    run_http(&http_session, &ids, &service_root).await?;
    http_session.revoke_all()?;
    Ok(())
}

#[cfg(test)]
fn create_canary_root(production: &ApprovedMcpWorkspace) -> Result<CanaryRoot, ApprovedMcpError> {
    let approved_parent = production
        .inner
        .approved_root
        .parent()
        .ok_or_else(canary_error)?;
    let parent = approved_parent.join("qualification").join("canary-runs");
    fs::create_dir_all(&parent).map_err(|_| canary_error())?;
    let metadata = fs::symlink_metadata(&parent).map_err(|_| canary_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(canary_error());
    }
    let path = parent.join(format!("mcpq-canary-{}", Uuid::new_v4().simple()));
    fs::create_dir(&path).map_err(|_| canary_error())?;
    Ok(CanaryRoot { path })
}

fn seed_approved_material(
    workspace: &ApprovedMcpWorkspace,
    qualification: &ApprovedMcpQualificationSnapshotV1,
    now_unix: u64,
) -> Result<CanaryIds, ApprovedMcpError> {
    let manifest_key = workspace
        .inner
        .keys
        .load_or_create(KeyRole::ApprovedManifest)?;
    let workspace_instance_id = workspace_instance_id(&manifest_key)?;
    let signer =
        ManifestSigningKey::from_bytes(manifest_key, KEY_VERSION).map_err(|_| canary_error())?;
    let publisher = WorkspacePublisher::initialize(&workspace.inner.approved_root, signer)
        .map_err(|_| canary_error())?;
    let case_id =
        CaseId::parse(format!("case_{}", Uuid::new_v4().simple())).map_err(|_| canary_error())?;
    let material_id = MaterialId::parse(format!("mat_{}", Uuid::new_v4().simple()))
        .map_err(|_| canary_error())?;
    let publication_id = PublicationId::parse(format!("pub_{}", Uuid::new_v4().simple()))
        .map_err(|_| canary_error())?;
    let receipt_id =
        ReceiptId::parse(format!("rct_{}", Uuid::new_v4().simple())).map_err(|_| canary_error())?;
    let claims = ApprovedMaterialManifestV1 {
        schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
        classification: APPROVED_CLASSIFICATION.to_owned(),
        workspace_instance_id,
        case_id: case_id.clone(),
        material_id: material_id.clone(),
        document_version: 1,
        publication_id: publication_id.clone(),
        content_media_type: "text/plain".to_owned(),
        content_sha256: canary_hash(CANARY_CONTENT)?,
        content_bytes: u64::try_from(CANARY_CONTENT.len()).map_err(|_| canary_error())?,
        source_sha256: canary_hash(b"synthetic source")?,
        source_name_sha256: canary_hash(b"synthetic-source.pdf")?,
        source_revision_hash: canary_hash(b"synthetic source revision")?,
        extraction_sha256: canary_hash(b"synthetic local extraction")?,
        ocr_output_sha256: None,
        finding_summary_hash: canary_hash(b"no unresolved findings")?,
        hard_gate_evaluation_hash: canary_hash(b"all hard gates passed")?,
        policy_id: "approved-mcp-local-egress-v1".to_owned(),
        policy_version: 1,
        policy_sha256: canary_hash(b"approved-mcp-local-egress-v1:1")?,
        detector_versions: BTreeMap::from([("canary".to_owned(), "v1".to_owned())]),
        model_versions: BTreeMap::new(),
        worker_sha256: None,
        model_manifest_sha256: None,
        qualification_report_id: Some(qualification.evidence_id.clone()),
        calibration_evidence_version: Some("mcp-wire-canary-v1".to_owned()),
        dictionary_revision_hash: canary_hash(b"synthetic dictionary")?,
        mapping_revision_hash: canary_hash(b"synthetic mapping")?,
        approval_mode: ApprovalMode::Human,
        readiness_score: 100,
        unresolved_p0: 0,
        unresolved_p1: 0,
        unresolved_p2: 0,
        destination_scope: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
        purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
        workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
        issued_at_unix: now_unix.saturating_sub(1),
        expires_at_unix: now_unix.checked_add(10 * 60).ok_or_else(canary_error)?,
        receipt_id,
        receipt_nonce: format!("mcpq-canary-{}", Uuid::new_v4().simple()),
        revocation_epoch: 0,
    };
    publisher
        .publish(claims, CANARY_CONTENT)
        .map_err(|_| canary_error())?;
    Ok(CanaryIds {
        case_id: case_id.as_str().to_owned(),
        material_id: material_id.as_str().to_owned(),
        publication_id: publication_id.as_str().to_owned(),
    })
}

fn prepare_legal_service_files(root: &Path) -> Result<(), ApprovedMcpError> {
    fs::create_dir_all(root.join("materials")).map_err(|_| canary_error())?;
    fs::create_dir_all(root.join("output")).map_err(|_| canary_error())?;
    fs::write(root.join("legal.sqlite"), []).map_err(|_| canary_error())?;
    fs::write(root.join("user.sqlite"), []).map_err(|_| canary_error())?;
    Ok(())
}

#[cfg(test)]
fn build_server(
    session: &ApprovedMcpServerSession,
    root: &Path,
) -> Result<LegalMcpServer, ApprovedMcpError> {
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: root.join("legal.sqlite"),
        user_database_path: root.join("user.sqlite"),
        allowed_file_roots: vec![root.join("materials")],
        allowed_output_root: root.join("output"),
    })
    .map_err(|_| canary_error())?;
    Ok(LegalMcpServer::new(
        ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace),
        ServiceAdapter::for_approved_workspace(services, session.backend().clone()),
    ))
}

#[cfg(test)]
async fn run_stdio(
    session: &ApprovedMcpServerSession,
    ids: &CanaryIds,
    service_root: &Path,
) -> Result<(), ApprovedMcpError> {
    let server = build_server(session, service_root)?;
    let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server_task = tokio::spawn(async move {
        legal_mcp::stdio::serve_on_io(server, server_read, server_write).await
    });
    let (client_read, mut client_write) = tokio::io::split(client_io);
    let mut lines = BufReader::new(client_read).lines();
    send_line(
        &mut client_write,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"lawyer-assistance-mcp-qualification","version":env!("CARGO_PKG_VERSION")}
        }}),
    )
    .await?;
    let (_, initialized) = receive_line(&mut lines).await?;
    if initialized["result"]["protocolVersion"] != "2025-11-25" {
        return Err(canary_error());
    }
    send_line(
        &mut client_write,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await?;

    let read = prepare(
        session,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    )?;
    let read_response = stdio_call(
        &mut client_write,
        &mut lines,
        2,
        "case_read_approved_material",
        &read,
    )
    .await?;
    require_success(&read_response, &read.1)?;
    if read_response["result"]["structuredContent"]["data"]["content"].as_str()
        != Some("[PERSON_001] approved MCP qualification material")
    {
        return Err(canary_error());
    }

    let write = prepare(
        session,
        "case_write_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"task_type":"case_analysis","status":"draft",
            "source_approved_refs":[{"material_id":ids.material_id,"publication_id":ids.publication_id}],
            "content_media_type":"text/plain","content":"[PERSON_001] stdio qualification work product",
            "idempotency_key":format!("idem_{}", Uuid::new_v4().simple())}),
    )?;
    let written = stdio_call(
        &mut client_write,
        &mut lines,
        3,
        "case_write_work_product",
        &write,
    )
    .await?;
    require_success(&written, &write.1)?;
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .ok_or_else(canary_error)?
        .to_owned();

    let product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"work_product_id":work_product_id,"version":1}),
    )?;
    let first = stdio_call(
        &mut client_write,
        &mut lines,
        4,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_success(&first, &product.1)?;
    let replay = stdio_call(
        &mut client_write,
        &mut lines,
        5,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_replay_denied(&replay, &product.1)?;

    client_write.shutdown().await.map_err(|_| canary_error())?;
    drop(client_write);
    let joined = tokio::time::timeout(CANARY_TIMEOUT, server_task)
        .await
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?;
    joined.map_err(|_| canary_error())
}

#[cfg(test)]
async fn run_http(
    session: &ApprovedMcpServerSession,
    ids: &CanaryIds,
    service_root: &Path,
) -> Result<(), ApprovedMcpError> {
    let server = build_server(session, service_root)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| canary_error())?;
    let address = listener.local_addr().map_err(|_| canary_error())?;
    let token = format!("mcpq-http-{}", Uuid::new_v4().simple());
    let config = ResolvedConfig {
        legal_db: service_root.join("legal.sqlite"),
        user_db: service_root.join("user.sqlite"),
        allowed_roots: vec![service_root.join("materials")],
        output_root: service_root.join("output"),
        privacy_profile: PrivacyProfile::ApprovedCaseWorkspace,
        bind: address,
        allowed_origins: vec!["https://local.qualification.invalid".to_owned()],
        allowed_hosts: vec![address.to_string()],
        bearer: Some(
            BearerSecret::from_token_bytes(token.as_bytes().to_vec())
                .map_err(|_| canary_error())?,
        ),
        dangerously_allow_insecure_non_loopback_http: false,
        limits: Limits {
            max_body_bytes: 128 * 1024,
            request_timeout: Duration::from_secs(5),
            max_concurrency: 2,
        },
        command: Command::Serve {
            bind: Some(address),
        },
    };
    let cancellation = CancellationToken::new();
    let server_cancellation = cancellation.clone();
    let server_config = config.clone();
    let server_task = tokio::spawn(async move {
        legal_mcp::http::serve_http_on_listener(
            server,
            &server_config,
            listener,
            server_cancellation,
        )
        .await
    });
    let client = reqwest::Client::builder()
        .timeout(CANARY_TIMEOUT)
        .build()
        .map_err(|_| canary_error())?;
    let endpoint = format!("http://{address}/mcp");
    let initialized = post_http(
        &client,
        &endpoint,
        &token,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"lawyer-assistance-mcp-qualification","version":env!("CARGO_PKG_VERSION")}
        }}),
    )
    .await?;
    if initialized.1["result"]["protocolVersion"] != "2025-11-25" {
        cancellation.cancel();
        return Err(canary_error());
    }

    let read = prepare(
        session,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    )?;
    let read_response = http_call(
        &client,
        &endpoint,
        &token,
        2,
        "case_read_approved_material",
        &read,
    )
    .await?;
    require_success(&read_response, &read.1)?;

    let write = prepare(
        session,
        "case_write_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"task_type":"case_analysis","status":"draft",
            "source_approved_refs":[{"material_id":ids.material_id,"publication_id":ids.publication_id}],
            "content_media_type":"text/plain","content":"[PERSON_001] HTTP qualification work product",
            "idempotency_key":format!("idem_{}", Uuid::new_v4().simple())}),
    )?;
    let written = http_call(
        &client,
        &endpoint,
        &token,
        3,
        "case_write_work_product",
        &write,
    )
    .await?;
    require_success(&written, &write.1)?;
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .ok_or_else(canary_error)?
        .to_owned();
    let product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,"work_product_id":work_product_id,"version":1}),
    )?;
    let first = http_call(
        &client,
        &endpoint,
        &token,
        4,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_success(&first, &product.1)?;
    let replay = http_call(
        &client,
        &endpoint,
        &token,
        5,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_replay_denied(&replay, &product.1)?;

    cancellation.cancel();
    let result = tokio::time::timeout(CANARY_TIMEOUT, server_task)
        .await
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?;
    result.map_err(|_| canary_error())
}

#[cfg(test)]
fn prepare(
    session: &ApprovedMcpServerSession,
    tool_name: &str,
    business: Value,
) -> Result<(Value, String), ApprovedMcpError> {
    let arguments = business.as_object().cloned().ok_or_else(canary_error)?;
    let prepared = session.prepare_call(tool_name, arguments, 60)?;
    let ticket = prepared
        .arguments
        .get("access_ticket")
        .and_then(Value::as_str)
        .filter(|ticket| !ticket.is_empty())
        .ok_or_else(canary_error)?
        .to_owned();
    Ok((prepared.arguments, ticket))
}

#[cfg(test)]
async fn stdio_call<W, R>(
    writer: &mut W,
    lines: &mut Lines<R>,
    id: u64,
    tool_name: &str,
    prepared: &(Value, String),
) -> Result<Value, ApprovedMcpError>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
{
    send_line(
        writer,
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
            "name":tool_name,"arguments":prepared.0
        }}),
    )
    .await?;
    receive_line(lines).await.map(|(_, value)| value)
}

#[cfg(test)]
async fn send_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: Value,
) -> Result<(), ApprovedMcpError> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| canary_error())?;
    bytes.push(b'\n');
    tokio::time::timeout(CANARY_TIMEOUT, writer.write_all(&bytes))
        .await
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?;
    writer.flush().await.map_err(|_| canary_error())
}

#[cfg(test)]
async fn receive_line<R: AsyncBufRead + Unpin>(
    lines: &mut Lines<R>,
) -> Result<(String, Value), ApprovedMcpError> {
    let line = tokio::time::timeout(CANARY_TIMEOUT, lines.next_line())
        .await
        .map_err(|_| canary_error())?
        .map_err(|_| canary_error())?
        .ok_or_else(canary_error)?;
    if line.len() > MAX_WIRE_RESPONSE_BYTES {
        return Err(canary_error());
    }
    let value = serde_json::from_str(&line).map_err(|_| canary_error())?;
    Ok((line, value))
}

#[cfg(test)]
async fn http_call(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    id: u64,
    tool_name: &str,
    prepared: &(Value, String),
) -> Result<Value, ApprovedMcpError> {
    let (_, value) = post_http(
        client,
        endpoint,
        token,
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
            "name":tool_name,"arguments":prepared.0
        }}),
    )
    .await?;
    Ok(value)
}

async fn post_http(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    body: Value,
) -> Result<(String, Value), ApprovedMcpError> {
    let response = client
        .post(endpoint)
        .header("accept", "application/json, text/event-stream")
        .header("origin", "https://local.qualification.invalid")
        .header("mcp-protocol-version", "2025-11-25")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| canary_error())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(canary_error());
    }
    let bytes = response.bytes().await.map_err(|_| canary_error())?;
    if bytes.len() > MAX_WIRE_RESPONSE_BYTES {
        return Err(canary_error());
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| canary_error())?;
    let value = serde_json::from_str(&text).map_err(|_| canary_error())?;
    Ok((text, value))
}

fn require_success(response: &Value, ticket: &str) -> Result<(), ApprovedMcpError> {
    let serialized = serde_json::to_string(response).map_err(|_| canary_error())?;
    if (!ticket.is_empty() && serialized.contains(ticket))
        || response["result"]["isError"] != false
        || response["result"]["structuredContent"]["status"] != "success"
    {
        return Err(canary_error());
    }
    Ok(())
}

#[cfg(test)]
fn require_replay_denied(response: &Value, ticket: &str) -> Result<(), ApprovedMcpError> {
    let serialized = serde_json::to_string(response).map_err(|_| canary_error())?;
    if serialized.contains(ticket)
        || response["result"]["structuredContent"]["reason_code"] != "ACCESS_TICKET_REPLAYED"
    {
        return Err(canary_error());
    }
    Ok(())
}

fn canary_hash(bytes: &[u8]) -> Result<Sha256Hex, ApprovedMcpError> {
    Sha256Hex::parse(sha256_hex(bytes)).map_err(|_| canary_error())
}

fn canary_error() -> ApprovedMcpError {
    ApprovedMcpError::new(
        "approved_mcp_qualification_canary_failed",
        "The local approved MCP stdio/HTTP qualification canary failed closed.",
    )
}
