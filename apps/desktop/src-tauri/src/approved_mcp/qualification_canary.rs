use super::{qualification::ExpectedQualificationBinding, *};
use legal_mcp::approved_backend::{
    ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError,
    ApprovedWorkspaceQualificationProvider,
};
#[cfg(test)]
use legal_mcp::registry::PrivacyProfile;
use legal_mcp::registry::ToolRegistry;
#[cfg(test)]
use legal_mcp::{
    config::{BearerSecret, Command, Limits, ResolvedConfig},
    handler::LegalMcpServer,
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
const EXPECTED_APPROVED_TOOL_NAMES: [&str; 21] = [
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
    "case_list",
    "case_get_public_metadata",
    "case_list_approved_materials",
    "case_read_approved_material",
    "case_search_approved_materials",
    "case_list_work_products",
    "case_read_work_product",
    "case_write_work_product",
    "case_update_work_product",
    "case_export_work_product_manifest",
    "diagram.list_templates",
    "diagram.get_schema",
    "diagram.validate",
    "diagram.render",
    "diagram.update",
    "diagram.export",
];

#[derive(Clone, Copy)]
enum ApprovedToolSurface {
    #[cfg(test)]
    InternalTicket,
    StandaloneHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagramProductBinding {
    manifest_sha256: String,
    content_sha256: String,
    content_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagramMutationBinding {
    work_product_id: String,
    version: u64,
    manifest_sha256: String,
    content_sha256: String,
    content_bytes: usize,
    spec_hash: String,
}

const EXPECTED_DIAGRAM_TEMPLATE_IDS: [&str; 7] = [
    "legal_hierarchy_v1",
    "legal_application_chain_v1",
    "legal_conflict_priority_v1",
    "case_party_relationship_v1",
    "case_issue_evidence_law_v1",
    "case_money_flow_v1",
    "case_timeline_v1",
];

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
    external_canary_id: Option<String>,
}

impl CanaryRoot {
    fn cleanup_external(&mut self) -> Result<(), ApprovedMcpError> {
        let Some(canary_id) = self.external_canary_id.as_deref() else {
            return Ok(());
        };
        legal_mcp::standalone_approved::remove_qualification_canary_run_directory(canary_id)
            .map_err(|_| canary_error())?;
        self.external_canary_id = None;
        Ok(())
    }
}

impl Drop for CanaryRoot {
    fn drop(&mut self) {
        if let Some(canary_id) = self.external_canary_id.as_deref() {
            let _ = legal_mcp::standalone_approved::remove_qualification_canary_run_directory(
                canary_id,
            );
            return;
        }
        let valid_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("mcpq-canary-") && name.len() == 45);
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

fn approved_diagram_spec(publication_id: &str) -> Value {
    let mut spec: Value = serde_json::from_str(include_str!(
        "../../../../../crates/diagrams/examples/case_issue_evidence_law_v1.json"
    ))
    .expect("bundled approved diagram qualification fixture must remain valid JSON");
    spec["title"] = json!("[PERSON_001] approved diagram qualification");
    spec["summary"] = json!("Alias-only synthetic approved diagram qualification.");
    spec["sources"] = json!([{
        "id":publication_id,
        "kind":"case_record",
        "title":"Approved source",
        "locator":"Approved publication",
        "artifact_id":publication_id,
        "verification_status":"human_confirmed"
    }]);
    for collection in ["nodes", "edges", "groups"] {
        if let Some(items) = spec[collection].as_array_mut() {
            for item in items {
                item["source_refs"] = json!([publication_id]);
                if let Some(metadata) = item
                    .as_object_mut()
                    .and_then(|object| object.get_mut("metadata"))
                    .and_then(Value::as_object_mut)
                {
                    if metadata.contains_key("official_source") {
                        metadata.insert("official_source".to_owned(), json!(publication_id));
                    }
                }
            }
        }
    }
    spec["provenance"]["source_file_ids"] = json!([publication_id]);
    spec
}

fn diagram_validate_arguments(ids: &CanaryIds) -> Value {
    json!({
        "schema_version":1,
        "case_id":ids.case_id,
        "source_approved_refs":[{
            "material_id":ids.material_id,
            "publication_id":ids.publication_id
        }],
        "spec":approved_diagram_spec(&ids.publication_id)
    })
}

fn diagram_render_arguments(ids: &CanaryIds) -> Value {
    json!({
        "schema_version":1,
        "case_id":ids.case_id,
        "source_approved_refs":[{
            "material_id":ids.material_id,
            "publication_id":ids.publication_id
        }],
        "spec":approved_diagram_spec(&ids.publication_id),
        "status":"draft",
        "idempotency_key":format!("idem_{}",Uuid::new_v4().simple())
    })
}

fn diagram_update_arguments(ids: &CanaryIds, work_product_id: &str, spec_hash: &str) -> Value {
    json!({
        "schema_version":1,
        "case_id":ids.case_id,
        "work_product_id":work_product_id,
        "expected_parent_version":1,
        "source_approved_refs":[{
            "material_id":ids.material_id,
            "publication_id":ids.publication_id
        }],
        "base_spec":approved_diagram_spec(&ids.publication_id),
        "expected_spec_hash":spec_hash,
        "patch":{"title":"[PERSON_001] approved diagram qualification revision"},
        "status":"final",
        "idempotency_key":format!("idem_{}",Uuid::new_v4().simple())
    })
}

fn diagram_export_arguments(ids: &CanaryIds, work_product_id: &str) -> Value {
    json!({
        "schema_version":1,
        "case_id":ids.case_id,
        "work_product_id":work_product_id,
        "version":2,
        "format":"html"
    })
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
    let mut root = create_external_canary_root(&canary_id)?;
    let app_local = root.path.join("app-local");
    fs::create_dir(&app_local).map_err(|_| canary_error())?;
    let resolved =
        legal_mcp::standalone_approved::qualification_canary_app_local_data_directory(&canary_id)
            .map_err(|_| canary_error())?;
    if resolved != app_local {
        return Err(canary_error());
    }
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
            ApprovedMcpGrantGroupV1::DiagramRead,
            ApprovedMcpGrantGroupV1::DiagramWrite,
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
            ApprovedMcpGrantGroupV1::DiagramRead,
            ApprovedMcpGrantGroupV1::DiagramWrite,
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
    drop(canary_workspace);
    root.cleanup_external()?;
    Ok(())
}

fn create_external_canary_root(canary_id: &str) -> Result<CanaryRoot, ApprovedMcpError> {
    let path = legal_mcp::standalone_approved::create_qualification_canary_run_directory(canary_id)
        .map_err(|_| canary_error())?;
    let root = CanaryRoot {
        path,
        external_canary_id: Some(canary_id.to_owned()),
    };
    Ok(root)
}

fn external_command(
    binary: &Path,
    canary_id: &str,
    server_id: &str,
    subcommand: &str,
) -> Result<ProcessCommand, ApprovedMcpError> {
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
    bind_e2e_credential_prefix(&mut command)?;
    Ok(command)
}

#[cfg(feature = "standalone-mcp-e2e")]
fn bind_e2e_credential_prefix(command: &mut ProcessCommand) -> Result<(), ApprovedMcpError> {
    let prefix = legal_mcp::standalone_approved::standalone_mcp_e2e_credential_service_prefix()
        .map_err(|_| canary_error())?;
    command.env(
        legal_mcp::standalone_approved::STANDALONE_MCP_E2E_CREDENTIAL_PREFIX_ENV,
        prefix,
    );
    Ok(())
}

#[cfg(not(feature = "standalone-mcp-e2e"))]
fn bind_e2e_credential_prefix(_command: &mut ProcessCommand) -> Result<(), ApprovedMcpError> {
    Ok(())
}

fn run_external_stdio(
    binary: &Path,
    canary_id: &str,
    server_id: &str,
    ids: &CanaryIds,
) -> Result<(), ApprovedMcpError> {
    let mut child = external_command(binary, canary_id, server_id, "stdio")?
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
    write_process_line(&mut stdin, &tools_list_request(2))?;
    require_exact_approved_tools(
        &read_process_line(&mut stdout)?,
        ApprovedToolSurface::StandaloneHost,
    )?;

    let read = tool_request(
        3,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    );
    write_process_line(&mut stdin, &read)?;
    require_success(&read_process_line(&mut stdout)?, "")?;

    let write = tool_request(
        4,
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
        5,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":work_product_id,"version":1}),
    );
    write_process_line(&mut stdin, &reread)?;
    require_success(&read_process_line(&mut stdout)?, "")?;
    write_process_line(&mut stdin, &reread)?;
    require_wire_replay(&read_process_line(&mut stdout)?)?;

    write_process_line(
        &mut stdin,
        &tool_request(60, "diagram.list_templates", json!({"schema_version":1})),
    )?;
    require_diagram_templates(&read_process_line(&mut stdout)?, "")?;
    write_process_line(
        &mut stdin,
        &tool_request(
            61,
            "diagram.get_schema",
            json!({"schema_version":1,"template_id":"case_issue_evidence_law_v1"}),
        ),
    )?;
    require_diagram_schema(&read_process_line(&mut stdout)?, "")?;

    let validate = tool_request(6, "diagram.validate", diagram_validate_arguments(ids));
    write_process_line(&mut stdin, &validate)?;
    let validated_spec_hash = require_diagram_validation(&read_process_line(&mut stdout)?, "")?;
    let render = tool_request(7, "diagram.render", diagram_render_arguments(ids));
    write_process_line(&mut stdin, &render)?;
    let rendered = read_process_line(&mut stdout)?;
    let rendered_binding = require_diagram_mutation(&rendered, "", ids, "diagram.render", None, 1)?;
    if rendered_binding.spec_hash != validated_spec_hash {
        return Err(canary_error());
    }
    let diagram_work_product_id = rendered_binding.work_product_id.clone();
    let spec_hash = rendered_binding.spec_hash.clone();
    let diagram_product = tool_request(
        8,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":1}),
    );
    write_process_line(&mut stdin, &diagram_product)?;
    let diagram_product_response = read_process_line(&mut stdout)?;
    let v1_binding = require_diagram_work_product(
        &diagram_product_response,
        "",
        ids,
        &diagram_work_product_id,
        1,
        "draft",
    )?;
    require_mutation_matches_product(&rendered_binding, &v1_binding)?;

    let update = tool_request(
        9,
        "diagram.update",
        diagram_update_arguments(ids, &diagram_work_product_id, &spec_hash),
    );
    write_process_line(&mut stdin, &update)?;
    let updated_binding = require_diagram_mutation(
        &read_process_line(&mut stdout)?,
        "",
        ids,
        "diagram.update",
        Some(&diagram_work_product_id),
        2,
    )?;
    if updated_binding.spec_hash == rendered_binding.spec_hash {
        return Err(canary_error());
    }
    let updated_product = tool_request(
        10,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":2}),
    );
    write_process_line(&mut stdin, &updated_product)?;
    let updated_product_response = read_process_line(&mut stdout)?;
    let v2_binding = require_diagram_work_product(
        &updated_product_response,
        "",
        ids,
        &diagram_work_product_id,
        2,
        "final",
    )?;
    require_mutation_matches_product(&updated_binding, &v2_binding)?;
    require_distinct_diagram_versions(&v1_binding, &v2_binding)?;
    let export = tool_request(
        11,
        "diagram.export",
        diagram_export_arguments(ids, &diagram_work_product_id),
    );
    write_process_line(&mut stdin, &export)?;
    require_diagram_export(
        &read_process_line(&mut stdout)?,
        "",
        ids,
        &diagram_work_product_id,
        2,
        &v2_binding,
    )?;

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
    let mut child = external_command(binary, canary_id, server_id, "serve")?
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
    let (_, tools) = post_http(&client, endpoint, bearer, tools_list_request(2)).await?;
    require_exact_approved_tools(&tools, ApprovedToolSurface::StandaloneHost)?;

    let read = tool_request(
        3,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    );
    let (_, read_response) = post_http(&client, endpoint, bearer, read).await?;
    require_success(&read_response, "")?;
    let write = tool_request(
        4,
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
        5,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":work_product_id,"version":1}),
    );
    let (_, first) = post_http(&client, endpoint, bearer, reread.clone()).await?;
    require_success(&first, "")?;
    let (_, replay) = post_http(&client, endpoint, bearer, reread).await?;
    require_wire_replay(&replay)?;

    let (_, templates) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(60, "diagram.list_templates", json!({"schema_version":1})),
    )
    .await?;
    require_diagram_templates(&templates, "")?;
    let (_, schema) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(
            61,
            "diagram.get_schema",
            json!({"schema_version":1,"template_id":"case_issue_evidence_law_v1"}),
        ),
    )
    .await?;
    require_diagram_schema(&schema, "")?;

    let (_, validated) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(6, "diagram.validate", diagram_validate_arguments(ids)),
    )
    .await?;
    let validated_spec_hash = require_diagram_validation(&validated, "")?;
    let (_, rendered) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(7, "diagram.render", diagram_render_arguments(ids)),
    )
    .await?;
    let rendered_binding = require_diagram_mutation(&rendered, "", ids, "diagram.render", None, 1)?;
    if rendered_binding.spec_hash != validated_spec_hash {
        return Err(canary_error());
    }
    let diagram_work_product_id = rendered_binding.work_product_id.clone();
    let spec_hash = rendered_binding.spec_hash.clone();
    let (_, diagram_product) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(
            8,
            "case_read_work_product",
            json!({"schema_version":1,"case_id":ids.case_id,
                "work_product_id":diagram_work_product_id,"version":1}),
        ),
    )
    .await?;
    let v1_binding = require_diagram_work_product(
        &diagram_product,
        "",
        ids,
        &diagram_work_product_id,
        1,
        "draft",
    )?;
    require_mutation_matches_product(&rendered_binding, &v1_binding)?;
    let (_, updated) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(
            9,
            "diagram.update",
            diagram_update_arguments(ids, &diagram_work_product_id, &spec_hash),
        ),
    )
    .await?;
    let updated_binding = require_diagram_mutation(
        &updated,
        "",
        ids,
        "diagram.update",
        Some(&diagram_work_product_id),
        2,
    )?;
    if updated_binding.spec_hash == rendered_binding.spec_hash {
        return Err(canary_error());
    }
    let (_, updated_product) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(
            10,
            "case_read_work_product",
            json!({"schema_version":1,"case_id":ids.case_id,
                "work_product_id":diagram_work_product_id,"version":2}),
        ),
    )
    .await?;
    let v2_binding = require_diagram_work_product(
        &updated_product,
        "",
        ids,
        &diagram_work_product_id,
        2,
        "final",
    )?;
    require_mutation_matches_product(&updated_binding, &v2_binding)?;
    require_distinct_diagram_versions(&v1_binding, &v2_binding)?;
    let (_, exported) = post_http(
        &client,
        endpoint,
        bearer,
        tool_request(
            11,
            "diagram.export",
            diagram_export_arguments(ids, &diagram_work_product_id),
        ),
    )
    .await?;
    require_diagram_export(&exported, "", ids, &diagram_work_product_id, 2, &v2_binding)?;

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

fn tools_list_request(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}})
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
        policy_id: legal_mcp::approved_backend::APPROVED_MCP_POLICY_ID.to_owned(),
        policy_version: legal_mcp::approved_backend::APPROVED_MCP_POLICY_VERSION,
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
    Ok(CanaryRoot {
        path,
        external_canary_id: None,
    })
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
    send_line(&mut client_write, tools_list_request(2)).await?;
    let (_, tools) = receive_line(&mut lines).await?;
    require_exact_approved_tools(&tools, ApprovedToolSurface::InternalTicket)?;

    let read = prepare(
        session,
        "case_read_approved_material",
        json!({"schema_version":1,"case_id":ids.case_id,"material_id":ids.material_id,
            "publication_id":ids.publication_id}),
    )?;
    let read_response = stdio_call(
        &mut client_write,
        &mut lines,
        3,
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
        4,
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
        5,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_success(&first, &product.1)?;
    let replay = stdio_call(
        &mut client_write,
        &mut lines,
        6,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_replay_denied(&replay, &product.1)?;

    let templates = prepare(
        session,
        "diagram.list_templates",
        json!({"schema_version":1}),
    )?;
    let templates_response = stdio_call(
        &mut client_write,
        &mut lines,
        60,
        "diagram.list_templates",
        &templates,
    )
    .await?;
    require_diagram_templates(&templates_response, &templates.1)?;
    let schema = prepare(
        session,
        "diagram.get_schema",
        json!({"schema_version":1,"template_id":"case_issue_evidence_law_v1"}),
    )?;
    let schema_response = stdio_call(
        &mut client_write,
        &mut lines,
        61,
        "diagram.get_schema",
        &schema,
    )
    .await?;
    require_diagram_schema(&schema_response, &schema.1)?;

    let validate = prepare(session, "diagram.validate", diagram_validate_arguments(ids))?;
    let validated = stdio_call(
        &mut client_write,
        &mut lines,
        7,
        "diagram.validate",
        &validate,
    )
    .await?;
    let validated_spec_hash = require_diagram_validation(&validated, &validate.1)?;
    let render = prepare(session, "diagram.render", diagram_render_arguments(ids))?;
    let rendered = stdio_call(&mut client_write, &mut lines, 8, "diagram.render", &render).await?;
    let rendered_binding =
        require_diagram_mutation(&rendered, &render.1, ids, "diagram.render", None, 1)?;
    if rendered_binding.spec_hash != validated_spec_hash {
        return Err(canary_error());
    }
    let diagram_work_product_id = rendered_binding.work_product_id.clone();
    let spec_hash = rendered_binding.spec_hash.clone();
    let diagram_product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":1}),
    )?;
    let diagram_product_response = stdio_call(
        &mut client_write,
        &mut lines,
        9,
        "case_read_work_product",
        &diagram_product,
    )
    .await?;
    let v1_binding = require_diagram_work_product(
        &diagram_product_response,
        &diagram_product.1,
        ids,
        &diagram_work_product_id,
        1,
        "draft",
    )?;
    require_mutation_matches_product(&rendered_binding, &v1_binding)?;
    let update = prepare(
        session,
        "diagram.update",
        diagram_update_arguments(ids, &diagram_work_product_id, &spec_hash),
    )?;
    let updated = stdio_call(&mut client_write, &mut lines, 10, "diagram.update", &update).await?;
    let updated_binding = require_diagram_mutation(
        &updated,
        &update.1,
        ids,
        "diagram.update",
        Some(&diagram_work_product_id),
        2,
    )?;
    if updated_binding.spec_hash == rendered_binding.spec_hash {
        return Err(canary_error());
    }
    let updated_product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":2}),
    )?;
    let updated_product_response = stdio_call(
        &mut client_write,
        &mut lines,
        11,
        "case_read_work_product",
        &updated_product,
    )
    .await?;
    let v2_binding = require_diagram_work_product(
        &updated_product_response,
        &updated_product.1,
        ids,
        &diagram_work_product_id,
        2,
        "final",
    )?;
    require_mutation_matches_product(&updated_binding, &v2_binding)?;
    require_distinct_diagram_versions(&v1_binding, &v2_binding)?;
    let export = prepare(
        session,
        "diagram.export",
        diagram_export_arguments(ids, &diagram_work_product_id),
    )?;
    let exported = stdio_call(&mut client_write, &mut lines, 12, "diagram.export", &export).await?;
    require_diagram_export(
        &exported,
        &export.1,
        ids,
        &diagram_work_product_id,
        2,
        &v2_binding,
    )?;

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
    let tools = post_http(&client, &endpoint, &token, tools_list_request(2)).await?;
    require_exact_approved_tools(&tools.1, ApprovedToolSurface::InternalTicket)?;

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
        3,
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
        4,
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
        5,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_success(&first, &product.1)?;
    let replay = http_call(
        &client,
        &endpoint,
        &token,
        6,
        "case_read_work_product",
        &product,
    )
    .await?;
    require_replay_denied(&replay, &product.1)?;

    let templates = prepare(
        session,
        "diagram.list_templates",
        json!({"schema_version":1}),
    )?;
    let templates_response = http_call(
        &client,
        &endpoint,
        &token,
        60,
        "diagram.list_templates",
        &templates,
    )
    .await?;
    require_diagram_templates(&templates_response, &templates.1)?;
    let schema = prepare(
        session,
        "diagram.get_schema",
        json!({"schema_version":1,"template_id":"case_issue_evidence_law_v1"}),
    )?;
    let schema_response = http_call(
        &client,
        &endpoint,
        &token,
        61,
        "diagram.get_schema",
        &schema,
    )
    .await?;
    require_diagram_schema(&schema_response, &schema.1)?;

    let validate = prepare(session, "diagram.validate", diagram_validate_arguments(ids))?;
    let validated = http_call(&client, &endpoint, &token, 7, "diagram.validate", &validate).await?;
    let validated_spec_hash = require_diagram_validation(&validated, &validate.1)?;
    let render = prepare(session, "diagram.render", diagram_render_arguments(ids))?;
    let rendered = http_call(&client, &endpoint, &token, 8, "diagram.render", &render).await?;
    let rendered_binding =
        require_diagram_mutation(&rendered, &render.1, ids, "diagram.render", None, 1)?;
    if rendered_binding.spec_hash != validated_spec_hash {
        return Err(canary_error());
    }
    let diagram_work_product_id = rendered_binding.work_product_id.clone();
    let spec_hash = rendered_binding.spec_hash.clone();
    let diagram_product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":1}),
    )?;
    let diagram_product_response = http_call(
        &client,
        &endpoint,
        &token,
        9,
        "case_read_work_product",
        &diagram_product,
    )
    .await?;
    let v1_binding = require_diagram_work_product(
        &diagram_product_response,
        &diagram_product.1,
        ids,
        &diagram_work_product_id,
        1,
        "draft",
    )?;
    require_mutation_matches_product(&rendered_binding, &v1_binding)?;
    let update = prepare(
        session,
        "diagram.update",
        diagram_update_arguments(ids, &diagram_work_product_id, &spec_hash),
    )?;
    let updated = http_call(&client, &endpoint, &token, 10, "diagram.update", &update).await?;
    let updated_binding = require_diagram_mutation(
        &updated,
        &update.1,
        ids,
        "diagram.update",
        Some(&diagram_work_product_id),
        2,
    )?;
    if updated_binding.spec_hash == rendered_binding.spec_hash {
        return Err(canary_error());
    }
    let updated_product = prepare(
        session,
        "case_read_work_product",
        json!({"schema_version":1,"case_id":ids.case_id,
            "work_product_id":diagram_work_product_id,"version":2}),
    )?;
    let updated_product_response = http_call(
        &client,
        &endpoint,
        &token,
        11,
        "case_read_work_product",
        &updated_product,
    )
    .await?;
    let v2_binding = require_diagram_work_product(
        &updated_product_response,
        &updated_product.1,
        ids,
        &diagram_work_product_id,
        2,
        "final",
    )?;
    require_mutation_matches_product(&updated_binding, &v2_binding)?;
    require_distinct_diagram_versions(&v1_binding, &v2_binding)?;
    let export = prepare(
        session,
        "diagram.export",
        diagram_export_arguments(ids, &diagram_work_product_id),
    )?;
    let exported = http_call(&client, &endpoint, &token, 12, "diagram.export", &export).await?;
    require_diagram_export(
        &exported,
        &export.1,
        ids,
        &diagram_work_product_id,
        2,
        &v2_binding,
    )?;

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
    let prepared = session
        .prepare_call(tool_name, arguments, 60)
        .inspect_err(|error| {
            eprintln!(
                "approved MCP qualification canary failed to prepare {tool_name}: {}",
                error.code()
            );
        })?;
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

fn require_exact_approved_tools(
    response: &Value,
    surface: ApprovedToolSurface,
) -> Result<(), ApprovedMcpError> {
    let tools = response["result"]["tools"]
        .as_array()
        .ok_or_else(canary_error)?;
    if tools.len() != EXPECTED_APPROVED_TOOL_NAMES.len() {
        return Err(canary_error());
    }
    for (tool, expected_name) in tools.iter().zip(EXPECTED_APPROVED_TOOL_NAMES) {
        if tool["name"].as_str() != Some(expected_name) {
            return Err(canary_error());
        }
    }
    let expected = match surface {
        #[cfg(test)]
        ApprovedToolSurface::InternalTicket => {
            ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace).schema_snapshot()
        }
        ApprovedToolSurface::StandaloneHost => {
            ToolRegistry::for_standalone_approved().schema_snapshot()
        }
    };
    if expected.as_array() != Some(tools) {
        return Err(canary_error());
    }
    Ok(())
}

fn require_diagram_data<'a>(
    response: &'a Value,
    ticket: &str,
    expected_tool: &str,
) -> Result<&'a Value, ApprovedMcpError> {
    require_success(response, ticket)?;
    let structured = &response["result"]["structuredContent"];
    if structured["tool"].as_str() != Some(expected_tool) || !structured["data"].is_object() {
        return Err(canary_error());
    }
    Ok(&structured["data"])
}

fn has_exact_object_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn require_diagram_templates(response: &Value, ticket: &str) -> Result<(), ApprovedMcpError> {
    let data = require_diagram_data(response, ticket, "diagram.list_templates")?;
    let templates = data["templates"].as_array().ok_or_else(canary_error)?;
    if !has_exact_object_keys(data, &["schema_version", "templates"])
        || data["schema_version"] != 1
        || templates.len() != EXPECTED_DIAGRAM_TEMPLATE_IDS.len()
        || diagram_value_has_forbidden_location(data)
    {
        return Err(canary_error());
    }
    for (template, expected_id) in templates.iter().zip(EXPECTED_DIAGRAM_TEMPLATE_IDS) {
        if !has_exact_object_keys(
            template,
            &[
                "id",
                "diagram_type",
                "semantic_version",
                "name_zh",
                "scenario_zh",
                "supported_node_types",
                "required_node_types",
                "allowed_relations",
                "default_direction",
            ],
        ) || template["id"].as_str() != Some(expected_id)
            || template["semantic_version"] != "1.0.0"
            || !template["supported_node_types"].is_array()
            || !template["required_node_types"].is_array()
            || !template["allowed_relations"].is_array()
        {
            return Err(canary_error());
        }
    }
    Ok(())
}

fn require_diagram_schema(response: &Value, ticket: &str) -> Result<(), ApprovedMcpError> {
    let data = require_diagram_data(response, ticket, "diagram.get_schema")?;
    let schema = &data["diagram_spec_schema"];
    let template = &data["template"];
    if !has_exact_object_keys(data, &["schema_version", "diagram_spec_schema", "template"])
        || data["schema_version"] != 1
        || !schema.is_object()
        || schema["additionalProperties"] != false
        || schema.pointer("/$defs/source/properties/uri").is_some()
        || schema
            .pointer("/$defs/source/properties/file_name")
            .is_some()
        || schema
            .pointer("/$defs/source/properties/attachment")
            .is_some()
        || schema.pointer("/$defs/metadata/additionalProperties") != Some(&json!(false))
        || !has_exact_object_keys(
            template,
            &[
                "id",
                "diagram_type",
                "semantic_version",
                "name_zh",
                "scenario_zh",
                "supported_node_types",
                "required_node_types",
                "allowed_relations",
                "default_direction",
            ],
        )
        || template["id"] != "case_issue_evidence_law_v1"
    {
        return Err(canary_error());
    }
    Ok(())
}

fn require_validation_data(data: &Value) -> Result<String, ApprovedMcpError> {
    if !has_exact_object_keys(
        data,
        &[
            "schema_version",
            "template_id",
            "template_version",
            "valid",
            "spec_hash",
            "diagnostics",
            "warnings",
            "statistics",
        ],
    ) || data["schema_version"] != "1.0"
        || data["template_id"] != "case_issue_evidence_law_v1"
        || data["template_version"] != "1.0.0"
        || data["valid"] != true
        || !data["diagnostics"].is_array()
        || !data["warnings"].is_array()
        || !has_exact_object_keys(
            &data["statistics"],
            &[
                "nodes",
                "edges",
                "unsupported_facts",
                "disputed_facts",
                "missing_sources",
                "invalid_legal_versions",
                "performance_class",
            ],
        )
        || !data["statistics"]["nodes"].is_u64()
        || !data["statistics"]["edges"].is_u64()
        || !data["statistics"]["performance_class"].is_string()
        || diagram_value_has_forbidden_location(data)
    {
        return Err(canary_error());
    }
    data["spec_hash"]
        .as_str()
        .filter(|value| valid_prefixed_sha256(value))
        .map(str::to_owned)
        .ok_or_else(canary_error)
}

fn require_diagram_validation(response: &Value, ticket: &str) -> Result<String, ApprovedMcpError> {
    let data = require_diagram_data(response, ticket, "diagram.validate")?;
    require_validation_data(data)
}

fn require_diagram_mutation(
    response: &Value,
    ticket: &str,
    ids: &CanaryIds,
    expected_tool: &str,
    expected_work_product_id: Option<&str>,
    expected_version: u64,
) -> Result<DiagramMutationBinding, ApprovedMcpError> {
    if !matches!(expected_tool, "diagram.render" | "diagram.update") {
        return Err(canary_error());
    }
    let data = require_diagram_data(response, ticket, expected_tool)?;
    let artifact = &data["artifact"];
    if !has_exact_object_keys(
        data,
        &[
            "artifact",
            "mime_type",
            "byte_len",
            "spec_hash",
            "html_sha256",
            "validation",
        ],
    ) || !has_exact_object_keys(
        artifact,
        &[
            "case_id",
            "work_product_id",
            "version",
            "manifest_sha256",
            "content_sha256",
            "replayed",
        ],
    ) || artifact["case_id"].as_str() != Some(ids.case_id.as_str())
        || artifact["version"].as_u64() != Some(expected_version)
        || artifact["replayed"] != false
        || data["mime_type"] != "text/html"
        || !data["byte_len"]
            .as_u64()
            .is_some_and(|length| length > 0 && length <= 1024 * 1024)
        || diagram_value_has_forbidden_location(data)
    {
        return Err(canary_error());
    }
    let work_product_id = artifact["work_product_id"]
        .as_str()
        .filter(|value| value.strip_prefix("wp_").is_some_and(is_lower_hex_32))
        .ok_or_else(canary_error)?;
    if expected_work_product_id.is_some_and(|expected| expected != work_product_id) {
        return Err(canary_error());
    }
    let manifest_sha256 = artifact["manifest_sha256"]
        .as_str()
        .filter(|value| is_lower_hex_64(value))
        .ok_or_else(canary_error)?;
    let content_sha256 = artifact["content_sha256"]
        .as_str()
        .filter(|value| is_lower_hex_64(value))
        .ok_or_else(canary_error)?;
    let spec_hash = data["spec_hash"]
        .as_str()
        .filter(|value| valid_prefixed_sha256(value))
        .ok_or_else(canary_error)?;
    let validation_spec_hash = require_validation_data(&data["validation"])?;
    if validation_spec_hash != spec_hash
        || data["html_sha256"].as_str() != Some(format!("sha256:{content_sha256}").as_str())
    {
        return Err(canary_error());
    }
    Ok(DiagramMutationBinding {
        work_product_id: work_product_id.to_owned(),
        version: expected_version,
        manifest_sha256: manifest_sha256.to_owned(),
        content_sha256: content_sha256.to_owned(),
        content_bytes: data["byte_len"].as_u64().ok_or_else(canary_error)? as usize,
        spec_hash: spec_hash.to_owned(),
    })
}

fn require_mutation_matches_product(
    mutation: &DiagramMutationBinding,
    product: &DiagramProductBinding,
) -> Result<(), ApprovedMcpError> {
    if mutation.manifest_sha256 != product.manifest_sha256
        || mutation.content_sha256 != product.content_sha256
        || mutation.content_bytes != product.content_bytes
    {
        return Err(canary_error());
    }
    Ok(())
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_lower_hex_64)
}

#[cfg(test)]
fn require_opaque_diagram_response(response: &Value, ticket: &str) -> Result<(), ApprovedMcpError> {
    require_success(response, ticket)?;
    let data = &response["result"]["structuredContent"]["data"];
    if diagram_value_has_forbidden_location(data) {
        return Err(canary_error());
    }
    let serialized = serde_json::to_string(response)
        .map_err(|_| canary_error())?
        .to_ascii_lowercase();
    for forbidden in [
        "<html",
        "<!doctype",
        "\"artifact_uri\"",
        "\"file_name\"",
        "\"filename\"",
        "file://",
        "lawyer-assistance://",
        "c:\\\\",
        "c:/",
        "[person_001] approved diagram qualification",
    ] {
        if serialized.contains(forbidden) {
            return Err(canary_error());
        }
    }
    Ok(())
}

fn diagram_value_has_forbidden_location(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let diagnostic = object.len() == 4
                && ["severity", "code", "path", "message"]
                    .iter()
                    .all(|key| object.contains_key(*key));
            object.iter().any(|(key, value)| match key.as_str() {
                "artifact_uri" | "file_name" | "filename" | "content" | "locator" | "uri"
                | "attachment" => true,
                "path" => {
                    !diagnostic
                        || !value
                            .as_str()
                            .is_some_and(safe_qualification_diagnostic_pointer)
                }
                _ => diagram_value_has_forbidden_location(value),
            })
        }
        Value::Array(values) => values.iter().any(diagram_value_has_forbidden_location),
        Value::String(value) => diagram_scalar_has_forbidden_location(value),
        _ => false,
    }
}

fn safe_qualification_diagnostic_pointer(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if path.is_empty()
        || path.len() > 256
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
    {
        return false;
    }
    let mut saw_metadata = false;
    for segment in path.split('/').skip(1) {
        if saw_metadata
            || (!segment.bytes().all(|byte| byte.is_ascii_digit())
                && !safe_qualification_pointer_segment(segment))
        {
            return false;
        }
        saw_metadata = segment == "metadata";
    }
    true
}

fn safe_qualification_pointer_segment(segment: &str) -> bool {
    matches!(
        segment,
        "schema_version"
            | "spec"
            | "base_spec"
            | "patch"
            | "diagram_type"
            | "template_id"
            | "title"
            | "summary"
            | "nodes"
            | "edges"
            | "groups"
            | "sources"
            | "layout_hints"
            | "display_options"
            | "provenance"
            | "id"
            | "type"
            | "subtype"
            | "label"
            | "short_label"
            | "details"
            | "status"
            | "importance"
            | "source_refs"
            | "tags"
            | "metadata"
            | "source"
            | "target"
            | "relation"
            | "strength"
            | "node_ids"
            | "parent_group_id"
            | "collapsed_by_default"
            | "kind"
            | "locator"
            | "artifact_id"
            | "uri"
            | "file_name"
            | "page"
            | "paragraph"
            | "table"
            | "attachment"
            | "law_document"
            | "law_version"
            | "article"
            | "quote"
            | "content_hash"
            | "verification_status"
            | "generated_by"
            | "generated_at"
            | "diagram_spec_version"
            | "template_version"
            | "source_file_ids"
            | "human_confirmed"
            | "parent_spec_hash"
            | "change_summary"
            | "model_content_scope"
            | "deterministic_content_scope"
    )
}

fn diagram_scalar_has_forbidden_location(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed == "text/html"
        || trimmed.strip_prefix("sha256:").is_some_and(is_lower_hex_64)
    {
        return false;
    }
    let bytes = trimmed.as_bytes();
    trimmed.contains('\\')
        || trimmed.contains("://")
        || trimmed.starts_with('/')
        || trimmed.starts_with("../")
        || trimmed.contains("/../")
        || trimmed.ends_with("/..")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || trimmed.contains('/')
}

fn require_diagram_work_product(
    response: &Value,
    ticket: &str,
    ids: &CanaryIds,
    expected_work_product_id: &str,
    expected_version: u64,
    expected_status: &str,
) -> Result<DiagramProductBinding, ApprovedMcpError> {
    let data = require_diagram_data(response, ticket, "case_read_work_product")?;
    let content = data["content"].as_str().ok_or_else(canary_error)?;
    let content_bytes = content.len();
    let manifest_sha256 = data["manifest_sha256"]
        .as_str()
        .filter(|value| is_lower_hex_64(value))
        .ok_or_else(canary_error)?;
    let content_sha256 = data["content_sha256"]
        .as_str()
        .filter(|value| is_lower_hex_64(value))
        .ok_or_else(canary_error)?;
    let sources = data["source_approved_refs"]
        .as_array()
        .filter(|sources| sources.len() == 1)
        .ok_or_else(canary_error)?;
    let source = &sources[0];
    if !has_exact_object_keys(
        data,
        &[
            "classification",
            "case_id",
            "work_product_id",
            "version",
            "task_type",
            "status",
            "source_approved_refs",
            "content_media_type",
            "content_sha256",
            "manifest_sha256",
            "created_at_unix",
            "content",
        ],
    ) || !has_exact_object_keys(
        source,
        &[
            "material_id",
            "document_version",
            "publication_id",
            "manifest_sha256",
        ],
    ) || data["classification"] != "CASE_REDACTED_APPROVED"
        || data["case_id"].as_str() != Some(ids.case_id.as_str())
        || data["work_product_id"].as_str() != Some(expected_work_product_id)
        || data["task_type"] != "legal_diagram"
        || data["status"].as_str() != Some(expected_status)
        || data["content_media_type"] != "text/html"
        || data["version"].as_u64() != Some(expected_version)
        || !data["created_at_unix"]
            .as_u64()
            .is_some_and(|value| value > 0)
        || source["material_id"].as_str() != Some(ids.material_id.as_str())
        || source["publication_id"].as_str() != Some(ids.publication_id.as_str())
        || !source["document_version"]
            .as_u64()
            .is_some_and(|value| value > 0)
        || !source["manifest_sha256"]
            .as_str()
            .is_some_and(is_lower_hex_64)
        || sha256_hex(content.as_bytes()) != content_sha256
        || !{
            let content = content.to_ascii_lowercase();
            content.contains("<html") || content.contains("<!doctype html")
        }
    {
        return Err(canary_error());
    }
    let mut metadata = data.clone();
    let content = metadata
        .as_object_mut()
        .and_then(|object| object.remove("content"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(canary_error)?;
    if diagram_value_has_forbidden_location(&metadata) {
        return Err(canary_error());
    }
    let serialized = serde_json::to_string(&metadata)
        .map_err(|_| canary_error())?
        .to_ascii_lowercase();
    for forbidden in [
        "\"artifact_uri\"",
        "\"file_name\"",
        "\"filename\"",
        "file://",
        "lawyer-assistance://",
        "c:\\\\",
        "c:/",
    ] {
        if serialized.contains(forbidden) {
            return Err(canary_error());
        }
    }
    let content = content.to_ascii_lowercase();
    for forbidden in ["file://", "lawyer-assistance://", "c:\\\\", "c:/"] {
        if content.contains(forbidden) {
            return Err(canary_error());
        }
    }
    Ok(DiagramProductBinding {
        manifest_sha256: manifest_sha256.to_owned(),
        content_sha256: content_sha256.to_owned(),
        content_bytes,
    })
}

fn require_distinct_diagram_versions(
    v1: &DiagramProductBinding,
    v2: &DiagramProductBinding,
) -> Result<(), ApprovedMcpError> {
    if v1.manifest_sha256 == v2.manifest_sha256 || v1.content_sha256 == v2.content_sha256 {
        return Err(canary_error());
    }
    Ok(())
}

fn require_diagram_export(
    response: &Value,
    ticket: &str,
    ids: &CanaryIds,
    expected_work_product_id: &str,
    expected_version: u64,
    expected: &DiagramProductBinding,
) -> Result<(), ApprovedMcpError> {
    let data = require_diagram_data(response, ticket, "diagram.export")?;
    let expected_html_sha256 = format!("sha256:{}", expected.content_sha256);
    if !has_exact_object_keys(
        data,
        &[
            "case_id",
            "work_product_id",
            "version",
            "format",
            "mime_type",
            "byte_len",
            "html_sha256",
            "manifest_sha256",
        ],
    ) || diagram_value_has_forbidden_location(data)
        || data["case_id"].as_str() != Some(ids.case_id.as_str())
        || data["work_product_id"].as_str() != Some(expected_work_product_id)
        || data["version"].as_u64() != Some(expected_version)
        || data["format"] != "html"
        || data["mime_type"] != "text/html"
        || data["byte_len"].as_u64() != Some(expected.content_bytes as u64)
        || data["html_sha256"].as_str() != Some(expected_html_sha256.as_str())
        || data["manifest_sha256"].as_str() != Some(expected.manifest_sha256.as_str())
    {
        return Err(canary_error());
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn success(data: Value) -> Value {
        success_for("diagram.validate", data)
    }

    fn success_for(tool: &str, data: Value) -> Value {
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "result":{
                "isError":false,
                "structuredContent":{"status":"success","tool":tool,"data":data}
            }
        })
    }

    #[test]
    fn approved_tool_list_is_exactly_policy_v2_surface() {
        let tools = ToolRegistry::for_standalone_approved().schema_snapshot();
        let response = json!({"jsonrpc":"2.0","id":1,"result":{"tools":tools}});
        require_exact_approved_tools(&response, ApprovedToolSurface::StandaloneHost)
            .expect("exact 21-tool host surface");

        let internal = json!({
            "jsonrpc":"2.0","id":1,"result":{
                "tools":ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace)
                    .schema_snapshot()
            }
        });
        require_exact_approved_tools(&internal, ApprovedToolSurface::InternalTicket)
            .expect("exact 21-tool internal ticket surface");

        let mut reordered = response.clone();
        reordered["result"]["tools"]
            .as_array_mut()
            .expect("tool array")
            .swap(19, 20);
        assert!(
            require_exact_approved_tools(&reordered, ApprovedToolSurface::StandaloneHost).is_err()
        );

        let mut schema_drift = response.clone();
        schema_drift["result"]["tools"][18]["inputSchema"]["additionalProperties"] = json!(true);
        assert!(
            require_exact_approved_tools(&schema_drift, ApprovedToolSurface::StandaloneHost)
                .is_err()
        );

        let mut truncated = response;
        truncated["result"]["tools"]
            .as_array_mut()
            .expect("tool array")
            .pop();
        assert!(
            require_exact_approved_tools(&truncated, ApprovedToolSurface::StandaloneHost).is_err()
        );
    }

    #[test]
    fn diagram_descriptors_reject_content_and_location_fields() {
        let descriptor = success(json!({
            "artifact":{
                "work_product_id":format!("wp_{}", "a".repeat(32)),
                "version":1
            },
            "mime_type":"text/html",
            "html_sha256":format!("sha256:{}", "b".repeat(64))
        }));
        require_opaque_diagram_response(&descriptor, "").expect("opaque descriptor");

        for (field, value) in [
            ("artifact_uri", json!("file:///synthetic/diagram.html")),
            ("file_name", json!("diagram.html")),
            ("filename", json!("diagram.html")),
            ("path", json!("C:\\synthetic\\diagram.html")),
            ("content", json!("<!doctype html><html></html>")),
            ("note", json!("D:\\private\\matter")),
            ("note", json!("\\\\server\\private\\matter")),
            ("note", json!("private/matter")),
            ("note", json!("https://private.invalid/matter")),
        ] {
            let mut leaked = descriptor.clone();
            leaked["result"]["structuredContent"]["data"][field] = value;
            assert!(
                require_opaque_diagram_response(&leaked, "").is_err(),
                "{field} must fail the qualification descriptor assertion"
            );
        }

        let diagnostic = success(json!({
            "valid":true,
            "diagnostics":[{
                "severity":"warning",
                "code":"synthetic_warning",
                "path":"/nodes/0/metadata",
                "message":"Use the diagnostic code and JSON Pointer."
            }]
        }));
        require_opaque_diagram_response(&diagnostic, "")
            .expect("sanitized diagnostic JSON Pointers are not filesystem paths");

        let mut unsafe_diagnostic = diagnostic;
        unsafe_diagnostic["result"]["structuredContent"]["data"]["diagnostics"][0]["path"] =
            json!("C:\\synthetic\\diagram.html");
        assert!(require_opaque_diagram_response(&unsafe_diagnostic, "").is_err());

        for path in [
            "/Users/alice/secret",
            "/home/user/file",
            "/var/private",
            "/tmp/x",
        ] {
            let mut unsafe_diagnostic = success(json!({
                "valid":true,
                "diagnostics":[{
                    "severity":"warning",
                    "code":"synthetic_warning",
                    "path":path,
                    "message":"Sanitized diagnostics only."
                }]
            }));
            assert!(require_opaque_diagram_response(&unsafe_diagnostic, "").is_err());
            unsafe_diagnostic["result"]["structuredContent"]["data"]["diagnostics"][0]["path"] =
                json!("/nodes/0/metadata");
            require_opaque_diagram_response(&unsafe_diagnostic, "")
                .expect("allowlisted diagnostic pointer");
        }
    }

    #[test]
    fn diagram_work_product_requires_protected_html_metadata() {
        let ids = CanaryIds {
            case_id: format!("case_{}", "a".repeat(32)),
            material_id: format!("mat_{}", "b".repeat(32)),
            publication_id: format!("pub_{}", "c".repeat(32)),
        };
        let work_product_id = format!("wp_{}", "d".repeat(32));
        let content = "<!doctype html><html><body>Synthetic</body></html>";
        let product = success_for(
            "case_read_work_product",
            json!({
                "classification":"CASE_REDACTED_APPROVED",
                "case_id":ids.case_id,
                "work_product_id":work_product_id,
                "task_type":"legal_diagram",
                "status":"draft",
                "content_media_type":"text/html",
                "version":1,
                "source_approved_refs":[{
                    "material_id":ids.material_id,
                    "document_version":1,
                    "publication_id":ids.publication_id,
                    "manifest_sha256":"e".repeat(64)
                }],
                "manifest_sha256":"f".repeat(64),
                "content_sha256":sha256_hex(content.as_bytes()),
                "created_at_unix":1,
                "content":content
            }),
        );
        let binding =
            require_diagram_work_product(&product, "", &ids, &work_product_id, 1, "draft")
                .expect("protected HTML work product");

        let exported = success_for(
            "diagram.export",
            json!({
                "case_id":ids.case_id,
                "work_product_id":work_product_id,
                "version":1,
                "format":"html",
                "mime_type":"text/html",
                "byte_len":content.len(),
                "html_sha256":format!("sha256:{}", binding.content_sha256),
                "manifest_sha256":binding.manifest_sha256
            }),
        );
        require_diagram_export(&exported, "", &ids, &work_product_id, 1, &binding)
            .expect("export binding");

        let mut wrong_media_type = product.clone();
        wrong_media_type["result"]["structuredContent"]["data"]["content_media_type"] =
            json!("text/plain");
        assert!(require_diagram_work_product(
            &wrong_media_type,
            "",
            &ids,
            &work_product_id,
            1,
            "draft"
        )
        .is_err());

        let mut leaked_location = product;
        leaked_location["result"]["structuredContent"]["data"]["artifact_uri"] =
            json!("lawyer-assistance://diagram/wp");
        assert!(require_diagram_work_product(
            &leaked_location,
            "",
            &ids,
            &work_product_id,
            1,
            "draft"
        )
        .is_err());

        let mut wrong_export_hash = exported;
        wrong_export_hash["result"]["structuredContent"]["data"]["html_sha256"] =
            json!(format!("sha256:{}", "0".repeat(64)));
        assert!(require_diagram_export(
            &wrong_export_hash,
            "",
            &ids,
            &work_product_id,
            1,
            &binding
        )
        .is_err());
    }
}
