//! Cross-process acceptance coverage for the App-issued standalone approved MCP session.
//!
//! Only synthetic canaries are used. The separately-built executable is
//! launched instead of calling either MCP transport in-process.

use super::*;
use crate::{
    privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig},
    privacy_workflow::{
        ApplyPrivacyRiskReviewActionRequest, ApprovePrivacyReviewRequest, EditedRedactedPage,
        PrivacyReviewView, PrivacyWorkflowManager, ReceiptDestinationInput,
    },
};
use legal_mcp::standalone_approved::{
    default_app_local_data_directory, ApprovedMcpGrantGroupV1, APP_IDENTIFIER,
    STANDALONE_DESCRIPTOR_FILE, WIRE_REPLAY_DATABASE_FILE,
};
use privacy::{DestinationKind, ReviewActionV1};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command as ProcessCommand, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const RAW_PARTY: &str = "SYNTHETIC_PRIVATE_CLIENT_9482";
const RAW_PHONE: &str = "13800138000";
const HTTP_ORIGIN: &str = "https://local.approved-mcp.invalid";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_ATTEMPTS: usize = 50;
const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

struct E2eAppRoot {
    path: PathBuf,
}

impl E2eAppRoot {
    fn create() -> Self {
        let path = default_app_local_data_directory().expect("fixed E2E Known Folder root");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(APP_IDENTIFIER)
        );
        assert!(
            APP_IDENTIFIER.ends_with(".mcp-e2e"),
            "E2E feature must never target production App data"
        );
        assert!(
            !path.exists(),
            "stale E2E App root must be inspected explicitly"
        );
        fs::create_dir(&path).expect("create isolated Known Folder E2E root");
        Self { path }
    }
}

impl Drop for E2eAppRoot {
    fn drop(&mut self) {
        let safe = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == APP_IDENTIFIER && name.ends_with(".mcp-e2e"));
        if safe && self.path.is_dir() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct ServiceFixture {
    legal_database: PathBuf,
    user_database: PathBuf,
    material_root: PathBuf,
    output_root: PathBuf,
}

impl ServiceFixture {
    fn create(root: &Path) -> Self {
        let material_root = root.join("materials");
        let output_root = root.join("output");
        fs::create_dir_all(&material_root).expect("create synthetic material root");
        fs::create_dir_all(&output_root).expect("create synthetic output root");
        let legal_database = root.join("legal.sqlite");
        let user_database = root.join("user.sqlite");
        fs::write(&legal_database, []).expect("create synthetic legal database");
        fs::write(&user_database, []).expect("create synthetic user database");
        Self {
            legal_database,
            user_database,
            material_root,
            output_root,
        }
    }

    fn host_binding(&self, http_bind: Option<SocketAddr>) -> StandaloneMcpHostBinding {
        StandaloneMcpHostBinding {
            legal_database_path: self.legal_database.clone(),
            user_database_path: self.user_database.clone(),
            allowed_roots: vec![self.material_root.clone()],
            output_root: self.output_root.clone(),
            http_bind,
            allowed_origins: http_bind
                .map(|_| vec![HTTP_ORIGIN.to_owned()])
                .unwrap_or_default(),
        }
    }
}

struct SessionReaper {
    workspace: ApprovedMcpWorkspace,
    server_ids: Vec<String>,
}

impl SessionReaper {
    fn new(workspace: ApprovedMcpWorkspace) -> Self {
        Self {
            workspace,
            server_ids: Vec::new(),
        }
    }

    fn track(&mut self, server_id: &str) {
        self.server_ids.push(server_id.to_owned());
    }

    fn revoke(&mut self, server_id: &str) {
        self.workspace
            .revoke_standalone_session(server_id)
            .expect("revoke standalone session");
        self.server_ids.retain(|candidate| candidate != server_id);
    }
}

impl Drop for SessionReaper {
    fn drop(&mut self) {
        for server_id in self.server_ids.drain(..) {
            let _ = self.workspace.revoke_standalone_session(&server_id);
        }
    }
}

struct FileRestore {
    path: PathBuf,
    original: Option<Vec<u8>>,
}

impl FileRestore {
    fn new(path: PathBuf) -> Self {
        let original = fs::read(&path).expect("read protected file for restoration");
        Self {
            path,
            original: Some(original),
        }
    }

    fn restore(&mut self) {
        if let Some(original) = self.original.take() {
            fs::write(&self.path, original).expect("restore protected file");
        }
    }
}

impl Drop for FileRestore {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = fs::write(&self.path, original);
        }
    }
}

struct StdioHarness {
    child: Option<Child>,
    input: Option<ChildStdin>,
    responses: Receiver<Result<String, String>>,
    output_reader: Option<JoinHandle<()>>,
    error_reader: Option<JoinHandle<Vec<u8>>>,
}

impl StdioHarness {
    fn start(binary: &Path, local_app_data: &Path, server_id: &str) -> Self {
        let mut command = binary_command(binary, local_app_data, server_id, "stdio");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("launch standalone stdio executable");
        let input = child.stdin.take().expect("take executable stdin");
        let stdout = child.stdout.take().expect("take executable stdout");
        let stderr = child.stderr.take().expect("take executable stderr");
        let (sender, responses) = mpsc::channel();
        let output_reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        Self {
            child: Some(child),
            input: Some(input),
            responses,
            output_reader: Some(output_reader),
            error_reader: Some(capture_bytes(stderr)),
        }
    }

    fn notify(&mut self, value: Value) {
        self.send(value);
    }

    fn request(&mut self, value: Value) -> Value {
        self.send(value);
        let line = self
            .responses
            .recv_timeout(PROCESS_TIMEOUT)
            .expect("bounded standalone stdio response")
            .expect("read standalone stdio response");
        assert!(line.len() <= MAX_WIRE_BYTES, "bounded MCP response");
        serde_json::from_str(&line).expect("valid standalone MCP JSON response")
    }

    fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).expect("serialize MCP request");
        bytes.push(b'\n');
        let input = self.input.as_mut().expect("stdio input remains open");
        input.write_all(&bytes).expect("write MCP request");
        input.flush().expect("flush MCP request");
    }

    fn finish(mut self) -> Vec<u8> {
        self.input.take();
        let mut child = self.child.take().expect("stdio child remains available");
        let status = wait_for_exit(&mut child, PROCESS_TIMEOUT)
            .unwrap_or_else(|| terminate_and_panic(&mut child, "stdio executable did not exit"));
        assert!(status.success(), "stdio executable exited successfully");
        if let Some(reader) = self.output_reader.take() {
            reader.join().expect("join stdout reader");
        }
        assert!(
            self.responses.try_iter().next().is_none(),
            "stdio executable emitted no unsolicited protocol output"
        );
        self.error_reader
            .take()
            .expect("stderr reader")
            .join()
            .expect("join stderr reader")
    }
}

impl Drop for StdioHarness {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct HttpHarness {
    child: Option<Child>,
    output_reader: Option<JoinHandle<Vec<u8>>>,
    error_reader: Option<JoinHandle<Vec<u8>>>,
}

impl HttpHarness {
    fn start(binary: &Path, local_app_data: &Path, server_id: &str) -> Self {
        let mut command = binary_command(binary, local_app_data, server_id, "serve");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("launch standalone HTTP executable");
        let stdout = child.stdout.take().expect("take HTTP stdout");
        let stderr = child.stderr.take().expect("take HTTP stderr");
        Self {
            child: Some(child),
            output_reader: Some(capture_bytes(stdout)),
            error_reader: Some(capture_bytes(stderr)),
        }
    }

    fn stop(mut self) -> (Vec<u8>, Vec<u8>) {
        let mut child = self.child.take().expect("HTTP child remains available");
        child.kill().expect("terminate local HTTP executable");
        let _ = wait_for_exit(&mut child, PROCESS_TIMEOUT)
            .unwrap_or_else(|| terminate_and_panic(&mut child, "HTTP executable did not stop"));
        let stdout = self
            .output_reader
            .take()
            .expect("HTTP stdout reader")
            .join()
            .expect("join HTTP stdout reader");
        let stderr = self
            .error_reader
            .take()
            .expect("HTTP stderr reader")
            .join()
            .expect("join HTTP stderr reader");
        (stdout, stderr)
    }
}

impl Drop for HttpHarness {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "build lawyer-assistance-mcp first; exercised by scripts/test-standalone-approved-mcp.ps1"]
async fn app_approval_to_real_stdio_and_http_binary_is_fail_closed() {
    let built_binary = binary_path();
    assert!(
        built_binary.is_file(),
        "standalone MCP executable must be built"
    );
    let directory = tempfile::tempdir().expect("create synthetic service fixture parent");
    let local_app_data = directory.path().join("host-controlled-local-app-data");
    fs::create_dir_all(&local_app_data).expect("create hostile environment override root");
    let e2e_app_root = E2eAppRoot::create();
    let app_directory = e2e_app_root.path.clone();
    assert!(
        !app_directory.starts_with(&local_app_data),
        "Known Folder binding ignores host-controlled LOCALAPPDATA"
    );

    let binary_directory = directory.path().join("fixed-install");
    fs::create_dir(&binary_directory).expect("create fixed MCP install directory");
    let binary = binary_directory.join(legal_mcp::release_binary::binary_file_name());
    fs::copy(&built_binary, &binary).expect("install fixed MCP release binary");

    let wrong_directory = directory.path().join("wrong-version");
    fs::create_dir(&wrong_directory).expect("create wrong-version directory");
    let wrong_binary = wrong_directory.join(legal_mcp::release_binary::binary_file_name());
    fs::copy(
        std::env::var_os("COMSPEC").expect("Windows command interpreter"),
        &wrong_binary,
    )
    .expect("install wrong-version executable");
    let wrong_workspace =
        ApprovedMcpWorkspace::new_with_mcp_binary_for_test(app_directory.clone(), wrong_binary);
    assert_eq!(
        wrong_workspace
            .run_qualification(10 * 60)
            .await
            .expect_err("wrong-version executable must fail")
            .code(),
        "approved_mcp_release_binary_untrusted"
    );

    let corrupt_directory = directory.path().join("corrupt-binary");
    fs::create_dir(&corrupt_directory).expect("create corrupt-binary directory");
    let corrupt_binary = corrupt_directory.join(legal_mcp::release_binary::binary_file_name());
    fs::write(&corrupt_binary, b"not a Windows executable").expect("install corrupt executable");
    let corrupt_workspace =
        ApprovedMcpWorkspace::new_with_mcp_binary_for_test(app_directory.clone(), corrupt_binary);
    assert_eq!(
        corrupt_workspace
            .run_qualification(10 * 60)
            .await
            .expect_err("corrupt executable must fail")
            .code(),
        "approved_mcp_release_binary_untrusted"
    );

    let workspace =
        ApprovedMcpWorkspace::new_with_mcp_binary_for_test(app_directory.clone(), binary.clone());
    let qualification = workspace
        .run_qualification(10 * 60)
        .await
        .expect("qualify independent approved MCP profile");
    assert!(qualification.qualified);
    assert!(qualification.stdio_canary_passed);
    assert!(qualification.streamable_http_canary_passed);
    assert!(qualification.exact_app_policy_binding);
    assert!(qualification.exact_server_key_binding);
    assert_eq!(
        qualification.mcp_binary_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert!(qualification.mcp_binary_sha256.is_some());

    let fixture = ServiceFixture::create(&directory.path().join("legal-services"));
    let source_path = fixture.material_root.join("synthetic-case.txt");
    let source_text = format!("Client: {RAW_PARTY}; phone: {RAW_PHONE}.");
    let case_id = format!("case_{}", uuid::Uuid::new_v4().simple());
    fs::write(&source_path, source_text.as_bytes()).expect("write synthetic source");
    let workflow = PrivacyWorkflowManager::new(
        app_directory.clone(),
        workspace
            .workspace_instance_id()
            .expect("production workspace id"),
    )
    .expect("create App privacy workflow");
    let review = workflow
        .prepare_selected_material(
            &source_path,
            &PrivacyConfig::default(),
            &disabled_ocr_status(),
            None,
            Some(case_id.clone()),
            vec![RAW_PARTY.to_owned()],
        )
        .expect("locally redact synthetic material");
    for page in &review.pages {
        assert_no_sensitive(&page.redacted_text, &[RAW_PARTY, RAW_PHONE]);
    }
    let review = complete_case_risk_review(&workflow, &review);
    let edited_pages = review
        .pages
        .iter()
        .map(|page| EditedRedactedPage {
            page_number: page.page_number,
            redacted_text: page.redacted_text.clone(),
        })
        .collect();
    let approval = workflow
        .approve_review(ApprovePrivacyReviewRequest {
            redaction_id: review.redaction_id.clone(),
            expected_risk_revision: Some(
                review
                    .risk_review
                    .as_ref()
                    .expect("confirmed risk revision")
                    .revision,
            ),
            expected_suggested_redacted_sha256: review.suggested_redacted_content_sha256.clone(),
            edited_pages,
            reviewer: "synthetic-local-reviewer".to_owned(),
            destination: ReceiptDestinationInput {
                kind: DestinationKind::ExternalMcpHost,
                identifier: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
            },
            purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
            ttl_seconds: 10 * 60,
        })
        .expect("human approve exact redacted payload");
    assert_no_sensitive(&approval.approved_payload_json, &[RAW_PARTY, RAW_PHONE]);
    let source = workflow
        .load_approved_generation_source(&review.redaction_id, &approval.approved_payload_sha256)
        .expect("load receipt-bound approved payload");
    let published = workspace
        .publish(&case_id, source)
        .expect("publish exact App-approved payload");
    assert_eq!(published.case_id, case_id);
    assert_eq!(published.material_id, review.material_id);

    let mut reaper = SessionReaper::new(workspace.clone());
    run_real_stdio_chain(
        &binary,
        &local_app_data,
        &app_directory,
        &workspace,
        &fixture,
        &published,
        &approval.receipt_token,
        &mut reaper,
    );
    run_real_http_chain(
        &binary,
        &local_app_data,
        &app_directory,
        &workspace,
        &fixture,
        &published,
        &approval.receipt_token,
        &mut reaper,
    )
    .await;
    run_descriptor_and_revocation_negatives(
        &binary,
        &local_app_data,
        &app_directory,
        &workspace,
        &fixture,
        &mut reaper,
    );
    fs::remove_file(&binary).expect("remove measured binary before replacement");
    fs::copy(
        std::env::var_os("COMSPEC").expect("Windows command interpreter"),
        &binary,
    )
    .expect("replace measured binary");
    let replaced = workspace
        .qualification_status()
        .expect("status is fail-closed after replacement");
    assert!(!replaced.qualified);
    assert_eq!(replaced.reason_code, "BINARY_INVALID_OR_CHANGED");
    assert_eq!(
        workspace
            .provision_standalone_session(
                "app".to_owned(),
                McpTransportBindingV1::Stdio,
                vec![ApprovedMcpGrantGroupV1::Read],
                60,
                fixture.host_binding(None),
            )
            .expect_err("binary replacement blocks session issuance")
            .code(),
        "approved_mcp_not_qualified"
    );
}

#[allow(clippy::too_many_arguments)]
fn run_real_stdio_chain(
    binary: &Path,
    local_app_data: &Path,
    app_directory: &Path,
    workspace: &ApprovedMcpWorkspace,
    fixture: &ServiceFixture,
    published: &PublishedApprovedGeneration,
    receipt_token: &str,
    reaper: &mut SessionReaper,
) {
    let session = workspace
        .provision_standalone_session(
            "workbuddy".to_owned(),
            McpTransportBindingV1::Stdio,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write,
            ],
            5 * 60,
            fixture.host_binding(None),
        )
        .expect("provision App-issued stdio descriptor");
    assert!(session.metadata.endpoint.is_none());
    let server_id = session.metadata.server_instance_id.clone();
    reaper.track(&server_id);
    assert_opaque_metadata(&serde_json::to_string(&session.metadata).expect("metadata JSON"));
    drop(session);

    let mut stdio = StdioHarness::start(binary, local_app_data, &server_id);
    let initialized = stdio.request(initialize_request(1));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    stdio.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));

    let tools = stdio.request(json!({
        "jsonrpc":"2.0","id":2,"method":"tools/list","params":{}
    }));
    let names = tools["result"]["tools"]
        .as_array()
        .expect("approved tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
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
        ]
    );
    let approved_tools = tools["result"]["tools"]
        .as_array()
        .expect("approved tool list")
        .iter()
        .filter(|tool| {
            tool["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("case_"))
        })
        .collect::<Vec<_>>();
    assert_eq!(approved_tools.len(), 10);
    for tool in approved_tools {
        let schema = serde_json::to_string(&tool["inputSchema"]).expect("tool input schema");
        assert!(
            !schema.contains("access_ticket"),
            "standalone host schema must hide internal access tickets"
        );
    }
    assert_no_sensitive(
        &serde_json::to_string(&tools).expect("tools/list response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let list_arguments = json!({"schema_version":1});
    let listed_cases = stdio.request(tool_request_with_meta(
        3,
        "case_list",
        list_arguments,
        json!({
            "progressToken":"synthetic-progress-stdio-3",
            "nested":{"trace":"synthetic-trace-stdio-3"}
        }),
    ));
    require_success(&listed_cases);
    assert_eq!(
        listed_cases["result"]["structuredContent"]["data"]["items"][0]["case_id"],
        published.case_id
    );
    assert_no_sensitive(
        &serde_json::to_string(&listed_cases).expect("case list response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let metadata_arguments = json!({"schema_version":1,"case_id":published.case_id});
    let metadata = stdio.request(tool_request(
        4,
        "case_get_public_metadata",
        metadata_arguments,
    ));
    require_success(&metadata);
    assert_eq!(
        metadata["result"]["structuredContent"]["data"]["approved_material_count"],
        1
    );
    assert_no_sensitive(
        &serde_json::to_string(&metadata).expect("metadata response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let materials_arguments = json!({"schema_version":1,"case_id":published.case_id});
    let materials = stdio.request(tool_request(
        5,
        "case_list_approved_materials",
        materials_arguments,
    ));
    require_success(&materials);
    assert_eq!(
        materials["result"]["structuredContent"]["data"]["items"][0]["publication_id"],
        published.publication_id
    );
    assert_no_sensitive(
        &serde_json::to_string(&materials).expect("materials response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let search_arguments = json!({"schema_version":1,"case_id":published.case_id,"query":"pages"});
    let searched = stdio.request(tool_request(
        6,
        "case_search_approved_materials",
        search_arguments,
    ));
    require_success(&searched);
    assert_eq!(
        searched["result"]["structuredContent"]["data"]["items"][0]["publication_id"],
        published.publication_id
    );
    assert_no_sensitive(
        &serde_json::to_string(&searched).expect("search response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let read_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "material_id":published.material_id,"publication_id":published.publication_id});
    let read = stdio.request(tool_request(
        7,
        "case_read_approved_material",
        read_arguments.clone(),
    ));
    require_success(&read);
    assert_no_sensitive(
        &serde_json::to_string(&read).expect("read response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let injected_ticket = "mcp_v1_forbidden_host_input";
    let injected = stdio.request(json!({
        "jsonrpc":"2.0","id":8,"method":"tools/call","params":{
            "name":"case_read_approved_material","arguments":{
                "schema_version":1,"case_id":published.case_id,
                "material_id":published.material_id,"publication_id":published.publication_id,
                "access_ticket":injected_ticket
            }
        }
    }));
    assert_eq!(injected["error"]["code"], -32602);
    assert_no_sensitive(
        &serde_json::to_string(&injected).expect("injected ticket rejection JSON"),
        &[RAW_PARTY, RAW_PHONE, injected_ticket, receipt_token],
    );
    let injected_meta = stdio.request(json!({
        "jsonrpc":"2.0","id":80,"method":"tools/call","params":{
            "name":"case_read_approved_material",
            "arguments":read_arguments,
            "_meta":{"access_ticket":injected_ticket}
        }
    }));
    assert_eq!(injected_meta["error"]["code"], -32602);
    assert_no_sensitive(
        &serde_json::to_string(&injected_meta).expect("injected metadata rejection JSON"),
        &[RAW_PARTY, RAW_PHONE, injected_ticket, receipt_token],
    );
    let empty_products_arguments = json!({"schema_version":1,"case_id":published.case_id});
    let empty_products = stdio.request(tool_request(
        9,
        "case_list_work_products",
        empty_products_arguments,
    ));
    require_success(&empty_products);
    assert_eq!(
        empty_products["result"]["structuredContent"]["data"]["items"],
        json!([])
    );
    assert_no_sensitive(
        &serde_json::to_string(&empty_products).expect("empty products response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let work_content = "[PERSON_001] synthetic stdio work product";
    let write_arguments = json!({"schema_version":1,"case_id":published.case_id,"task_type":"case_analysis",
            "status":"draft","source_approved_refs":[{"material_id":published.material_id,
            "publication_id":published.publication_id}],"content_media_type":"text/plain",
            "content":work_content,"idempotency_key":format!("idem_{}",uuid::Uuid::new_v4().simple())});
    let written = stdio.request(tool_request(10, "case_write_work_product", write_arguments));
    require_success(&written);
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .expect("work product id")
        .to_owned();
    assert_no_sensitive(
        &serde_json::to_string(&written).expect("write response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let product_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "work_product_id":work_product_id,"version":1});
    let first = stdio.request(tool_request(
        11,
        "case_read_work_product",
        product_arguments,
    ));
    require_success(&first);
    assert_eq!(
        first["result"]["structuredContent"]["data"]["content"],
        work_content
    );
    assert_no_sensitive(
        &serde_json::to_string(&first).expect("first read response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let final_content = "[PERSON_001] final synthetic stdio work product";
    let update_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "work_product_id":work_product_id,"expected_parent_version":1,"status":"final",
            "source_approved_refs":[{"material_id":published.material_id,
            "publication_id":published.publication_id}],"content_media_type":"text/plain",
            "content":final_content,"idempotency_key":format!("idem_{}",uuid::Uuid::new_v4().simple())});
    let updated = stdio.request(tool_request(
        12,
        "case_update_work_product",
        update_arguments,
    ));
    require_success(&updated);
    assert_eq!(updated["result"]["structuredContent"]["data"]["version"], 2);
    assert_no_sensitive(
        &serde_json::to_string(&updated).expect("update response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let second_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "work_product_id":work_product_id,"version":2});
    let second = stdio.request(tool_request(13, "case_read_work_product", second_arguments));
    require_success(&second);
    assert_eq!(
        second["result"]["structuredContent"]["data"]["content"],
        final_content
    );
    assert_no_sensitive(
        &serde_json::to_string(&second).expect("second read response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let manifest_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "work_product_id":work_product_id,"version":2});
    let manifest = stdio.request(tool_request(
        14,
        "case_export_work_product_manifest",
        manifest_arguments.clone(),
    ));
    require_success(&manifest);
    assert_eq!(
        manifest["result"]["structuredContent"]["data"]["manifest"]["claims"]["version"],
        2
    );
    assert_no_sensitive(
        &serde_json::to_string(&manifest).expect("manifest response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    let replay = stdio.request(tool_request(
        14,
        "case_export_work_product_manifest",
        manifest_arguments,
    ));
    require_reason(&replay, "WIRE_REQUEST_REPLAYED");
    assert_no_sensitive(
        &serde_json::to_string(&replay).expect("replay response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );
    let different_payload_replay =
        stdio.request(tool_request(14, "case_list", json!({"schema_version":1})));
    require_reason(&different_payload_replay, "WIRE_REQUEST_REPLAYED");
    assert_no_sensitive(
        &serde_json::to_string(&different_payload_replay)
            .expect("different payload replay response JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );

    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "serve"),
        &[RAW_PARTY, RAW_PHONE],
    );

    run_read_only_grant_negative(
        binary,
        local_app_data,
        workspace,
        fixture,
        published,
        receipt_token,
        reaper,
    );

    let stderr = stdio.finish();
    assert_clean_process_output(&[], &stderr, &[RAW_PARTY, RAW_PHONE]);

    let replay_database = descriptor_path(app_directory, &server_id)
        .parent()
        .expect("standalone session directory")
        .join(WIRE_REPLAY_DATABASE_FILE);
    let mut replay_restore = FileRestore::new(replay_database.clone());
    fs::write(&replay_database, []).expect("replace replay database with empty file");
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    replay_restore.restore();

    let rollback_snapshot = fs::read(&replay_database).expect("snapshot replay database");
    let mut recovered = StdioHarness::start(binary, local_app_data, &server_id);
    let recovered_initialized = recovered.request(initialize_request(91));
    assert_eq!(
        recovered_initialized["result"]["protocolVersion"],
        "2025-11-25"
    );
    recovered.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let recovered_list =
        recovered.request(tool_request(92, "case_list", json!({"schema_version":1})));
    require_success(&recovered_list);
    let recovered_stderr = recovered.finish();
    assert_clean_process_output(&[], &recovered_stderr, &[RAW_PARTY, RAW_PHONE]);

    let mut latest_replay_restore = FileRestore::new(replay_database.clone());
    fs::write(&replay_database, rollback_snapshot).expect("roll back replay database");
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    latest_replay_restore.restore();

    let mut restored = StdioHarness::start(binary, local_app_data, &server_id);
    let restored_initialized = restored.request(initialize_request(93));
    assert_eq!(
        restored_initialized["result"]["protocolVersion"],
        "2025-11-25"
    );
    let restored_stderr = restored.finish();
    assert_clean_process_output(&[], &restored_stderr, &[RAW_PARTY, RAW_PHONE]);
    reaper.revoke(&server_id);
}

fn run_read_only_grant_negative(
    binary: &Path,
    local_app_data: &Path,
    workspace: &ApprovedMcpWorkspace,
    fixture: &ServiceFixture,
    published: &PublishedApprovedGeneration,
    receipt_token: &str,
    reaper: &mut SessionReaper,
) {
    let session = workspace
        .provision_standalone_session(
            "codex".to_owned(),
            McpTransportBindingV1::Stdio,
            vec![ApprovedMcpGrantGroupV1::Read],
            5 * 60,
            fixture.host_binding(None),
        )
        .expect("provision read-only descriptor");
    assert_eq!(
        session.metadata.grant_groups,
        vec![ApprovedMcpGrantGroupV1::Read]
    );
    assert_eq!(session.metadata.grants.len(), 8);
    assert!(session
        .metadata
        .grants
        .iter()
        .all(|grant| grant.tool_name != "case_write_work_product"));
    let server_id = session.metadata.server_instance_id.clone();
    reaper.track(&server_id);
    drop(session);

    let mut stdio = StdioHarness::start(binary, local_app_data, &server_id);
    let initialized = stdio.request(initialize_request(1));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    stdio.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let denied = stdio.request(tool_request(
        2,
        "case_write_work_product",
        json!({
            "schema_version":1,
            "case_id":published.case_id,
            "task_type":"case_analysis",
            "status":"draft",
            "source_approved_refs":[{
                "material_id":published.material_id,
                "publication_id":published.publication_id
            }],
            "content_media_type":"text/plain",
            "content":"[PERSON_001] read-only grant negative",
            "idempotency_key":format!("idem_{}",uuid::Uuid::new_v4().simple())
        }),
    ));
    require_reason(&denied, "STANDALONE_GRANT_DENIED");
    assert_no_sensitive(
        &serde_json::to_string(&denied).expect("read-only grant denial JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token],
    );
    let stderr = stdio.finish();
    assert_clean_process_output(&[], &stderr, &[RAW_PARTY, RAW_PHONE, receipt_token]);
    reaper.revoke(&server_id);
}

#[allow(clippy::too_many_arguments)]
async fn run_real_http_chain(
    binary: &Path,
    local_app_data: &Path,
    _app_directory: &Path,
    workspace: &ApprovedMcpWorkspace,
    fixture: &ServiceFixture,
    published: &PublishedApprovedGeneration,
    receipt_token: &str,
    reaper: &mut SessionReaper,
) {
    let bind = reserve_loopback_address();
    let mut session = workspace
        .provision_standalone_session(
            "opencode".to_owned(),
            McpTransportBindingV1::StreamableHttp,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write,
            ],
            5 * 60,
            fixture.host_binding(Some(bind)),
        )
        .expect("provision App-issued HTTP descriptor");
    let server_id = session.metadata.server_instance_id.clone();
    let endpoint = session
        .metadata
        .endpoint
        .clone()
        .expect("opaque HTTP endpoint");
    let bearer = session
        .take_http_bearer()
        .expect("backend-only HTTP bearer");
    reaper.track(&server_id);
    assert_opaque_metadata(&serde_json::to_string(&session.metadata).expect("HTTP metadata JSON"));
    drop(session);

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(PROCESS_TIMEOUT)
        .build()
        .expect("build loopback-only HTTP client");
    let http = HttpHarness::start(binary, local_app_data, &server_id);
    wait_for_http(&client, &endpoint, &bearer).await;

    let read_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "material_id":published.material_id,"publication_id":published.publication_id});
    let read = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(2, "case_read_approved_material", read_arguments),
    )
    .await
    .expect("HTTP approved material read");
    require_success(&read);
    assert_no_sensitive(
        &serde_json::to_string(&read).expect("HTTP read JSON"),
        &[RAW_PARTY, RAW_PHONE, receipt_token, &bearer],
    );

    let work_content = "[PERSON_001] synthetic HTTP work product";
    let write_arguments = json!({"schema_version":1,"case_id":published.case_id,"task_type":"case_analysis",
            "status":"draft","source_approved_refs":[{"material_id":published.material_id,
            "publication_id":published.publication_id}],"content_media_type":"text/plain",
            "content":work_content,"idempotency_key":format!("idem_{}",uuid::Uuid::new_v4().simple())});
    let written = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(3, "case_write_work_product", write_arguments),
    )
    .await
    .expect("HTTP work product write");
    require_success(&written);
    let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
        .as_str()
        .expect("HTTP work product id")
        .to_owned();
    assert_no_sensitive(
        &serde_json::to_string(&written).expect("HTTP write JSON"),
        &[&bearer],
    );
    let product_arguments = json!({"schema_version":1,"case_id":published.case_id,
            "work_product_id":work_product_id,"version":1});
    let first = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(4, "case_read_work_product", product_arguments.clone()),
    )
    .await
    .expect("HTTP work product read");
    require_success(&first);
    assert_eq!(
        first["result"]["structuredContent"]["data"]["content"],
        work_content
    );
    let replay = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(4, "case_read_work_product", product_arguments.clone()),
    )
    .await
    .expect("HTTP replay response");
    require_reason(&replay, "WIRE_REQUEST_REPLAYED");
    assert_no_sensitive(
        &format!(
            "{}{}",
            serde_json::to_string(&first).expect("HTTP first read JSON"),
            serde_json::to_string(&replay).expect("HTTP replay JSON")
        ),
        &[&bearer],
    );

    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "serve"),
        &[RAW_PARTY, RAW_PHONE, &bearer],
    );
    let (stdout, stderr) = http.stop();
    assert_clean_process_output(&stdout, &stderr, &[RAW_PARTY, RAW_PHONE, &bearer]);

    let restarted = HttpHarness::start(binary, local_app_data, &server_id);
    wait_for_http(&client, &endpoint, &bearer).await;
    let persisted_replay = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(4, "case_read_work_product", product_arguments.clone()),
    )
    .await
    .expect("HTTP persisted replay response");
    require_reason(&persisted_replay, "WIRE_REQUEST_REPLAYED");
    let list_arguments = json!({"schema_version":1,"case_id":published.case_id});
    let listed = post_http(
        &client,
        &endpoint,
        &bearer,
        tool_request(6, "case_list_approved_materials", list_arguments),
    )
    .await
    .expect("HTTP process-lock crash recovery call");
    require_success(&listed);
    assert_no_sensitive(
        &serde_json::to_string(&listed).expect("HTTP list JSON"),
        &[&bearer],
    );
    let (stdout, stderr) = restarted.stop();
    assert_clean_process_output(&stdout, &stderr, &[RAW_PARTY, RAW_PHONE, &bearer]);
    reaper.revoke(&server_id);
}

fn run_descriptor_and_revocation_negatives(
    binary: &Path,
    local_app_data: &Path,
    app_directory: &Path,
    workspace: &ApprovedMcpWorkspace,
    fixture: &ServiceFixture,
    reaper: &mut SessionReaper,
) {
    let session = workspace
        .provision_standalone_session(
            "app".to_owned(),
            McpTransportBindingV1::Stdio,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write,
            ],
            2 * 60,
            fixture.host_binding(None),
        )
        .expect("provision negative-test descriptor");
    let server_id = session.metadata.server_instance_id.clone();
    reaper.track(&server_id);
    drop(session);
    let descriptor = descriptor_path(app_directory, &server_id);

    let mut restore = FileRestore::new(descriptor.clone());
    let mut tampered = restore.original.as_ref().expect("descriptor bytes").clone();
    let index = tampered.len() / 2;
    tampered[index] ^= 0x5a;
    fs::write(&descriptor, tampered).expect("tamper protected descriptor");
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    restore.restore();

    let evidence = app_directory
        .join("privacy")
        .join("approved-mcp")
        .join("qualification")
        .join("active-evidence-v1.json");
    let mut evidence_restore = FileRestore::new(evidence.clone());
    let mut changed = evidence_restore
        .original
        .as_ref()
        .expect("qualification evidence bytes")
        .clone();
    changed[0] ^= 0x01;
    fs::write(&evidence, changed).expect("tamper qualification evidence");
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    evidence_restore.restore();

    let hardlink = descriptor.with_extension("hardlink-negative");
    fs::hard_link(&descriptor, &hardlink).expect("create descriptor hardlink negative");
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    fs::remove_file(&hardlink).expect("remove descriptor hardlink negative");

    let mismatched_server_id = format!("srv_{}", uuid::Uuid::new_v4().simple());
    let mismatched_root = descriptor
        .parent()
        .and_then(Path::parent)
        .expect("ticket sessions root")
        .join(&mismatched_server_id);
    fs::create_dir(&mismatched_root).expect("create mismatched server root");
    let mismatched_descriptor = mismatched_root.join(STANDALONE_DESCRIPTOR_FILE);
    fs::copy(&descriptor, &mismatched_descriptor).expect("copy descriptor to mismatched root");
    run_expected_failure(
        binary_command(binary, local_app_data, &mismatched_server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    fs::remove_file(&mismatched_descriptor).expect("remove mismatched descriptor");
    fs::remove_dir(&mismatched_root).expect("remove mismatched server root");

    let mut conflict = binary_command(binary, local_app_data, &server_id, "stdio");
    conflict.arg("--config").arg(&fixture.legal_database);
    run_expected_failure(conflict, &[RAW_PARTY, RAW_PHONE]);

    reaper.revoke(&server_id);
    run_expected_failure(
        binary_command(binary, local_app_data, &server_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );

    let expired = workspace
        .provision_standalone_session(
            "app".to_owned(),
            McpTransportBindingV1::Stdio,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write,
            ],
            1,
            fixture.host_binding(None),
        )
        .expect("provision expiring descriptor");
    let expired_id = expired.metadata.server_instance_id.clone();
    reaper.track(&expired_id);
    drop(expired);
    thread::sleep(Duration::from_secs(2));
    run_expected_failure(
        binary_command(binary, local_app_data, &expired_id, "stdio"),
        &[RAW_PARTY, RAW_PHONE],
    );
    reaper.revoke(&expired_id);
}

fn complete_case_risk_review(
    manager: &PrivacyWorkflowManager,
    review: &PrivacyReviewView,
) -> PrivacyReviewView {
    let edited_pages = review
        .pages
        .iter()
        .map(|page| EditedRedactedPage {
            page_number: page.page_number,
            redacted_text: page.redacted_text.clone(),
        })
        .collect::<Vec<_>>();
    let finding_ids = review
        .risk_review
        .as_ref()
        .expect("initial risk revision")
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    let mut current = review.clone();
    for finding_id in finding_ids {
        let revision = current
            .risk_review
            .as_ref()
            .expect("current finding revision")
            .revision;
        current = manager
            .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
                redaction_id: current.redaction_id.clone(),
                expected_revision: revision,
                actor: "synthetic-local-reviewer".to_owned(),
                edited_pages: edited_pages.clone(),
                action: ReviewActionV1::AcceptReplacement {
                    finding_id,
                    apply_cluster: false,
                },
            })
            .expect("accept detected replacement");
    }
    let revision = current
        .risk_review
        .as_ref()
        .expect("resolved finding revision")
        .revision;
    manager
        .apply_risk_review_action(ApplyPrivacyRiskReviewActionRequest {
            redaction_id: current.redaction_id.clone(),
            expected_revision: revision,
            actor: "synthetic-local-reviewer".to_owned(),
            edited_pages,
            action: ReviewActionV1::ConfirmEditedOutput,
        })
        .expect("confirm exact redacted output")
}

fn disabled_ocr_status() -> LocalOcrStatus {
    LocalOcrStatus {
        code: LocalOcrStatusCode::Disabled,
        message: "synthetic text fixture does not require OCR".to_owned(),
        worker_version: None,
        model_version: None,
        worker_sha256: None,
        model_manifest_sha256: None,
        worker_present: false,
        model_directory_present: false,
        integrity_verified: false,
        network_isolation_verified: false,
        worker_protocol_version: None,
        worker_protocol_identity_sha256: None,
        worker_health_evidence_sha256: None,
        python_version: None,
        mineru_version: None,
        pytorch_version: None,
        cuda_runtime_version: None,
        gpu_driver_version: None,
    }
}

fn binary_path() -> PathBuf {
    std::env::var_os("LAWYER_ASSISTANCE_MCP_E2E_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(3)
                .expect("workspace root")
                .join("target")
                .join("debug")
                .join("lawyer-assistance-mcp.exe")
        })
}

fn binary_command(
    binary: &Path,
    local_app_data: &Path,
    server_id: &str,
    subcommand: &str,
) -> ProcessCommand {
    let mut command = ProcessCommand::new(binary);
    command
        .arg("--privacy-profile")
        .arg("approved_case_workspace")
        .arg("--approved-session-id")
        .arg(server_id)
        .arg(subcommand)
        .env("LOCALAPPDATA", local_app_data)
        .env("LAWYER_ASSISTANCE_MCP_LOG", "off");
    command
}

fn initialize_request(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"lawyer-assistance-standalone-binary-e2e",
        "version":env!("CARGO_PKG_VERSION")}}})
}

fn tool_request(id: u64, tool_name: &str, arguments: Value) -> Value {
    let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":tool_name,"arguments":arguments}});
    let wire = serde_json::to_string(&request).expect("serialize host request");
    assert!(!wire.contains("access_ticket"));
    assert!(!wire.contains("mcp_v1"));
    request
}

fn tool_request_with_meta(id: u64, tool_name: &str, arguments: Value, metadata: Value) -> Value {
    let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":tool_name,"arguments":arguments,"_meta":metadata}});
    let wire = serde_json::to_string(&request).expect("serialize metadata host request");
    assert!(!wire.contains("access_ticket"));
    assert!(!wire.contains("mcp_v1"));
    request
}

fn require_success(response: &Value) {
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["status"], "success");
    require_matching_output_channels(response);
}

fn require_reason(response: &Value, reason_code: &str) {
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["structuredContent"]["reason_code"],
        reason_code
    );
    require_matching_output_channels(response);
}

fn require_matching_output_channels(response: &Value) {
    let blocks = response["result"]["content"]
        .as_array()
        .expect("MCP content blocks");
    assert_eq!(blocks.len(), 1, "approved response has one text block");
    assert_eq!(blocks[0]["type"], "text");
    let text = blocks[0]["text"].as_str().expect("approved text output");
    let text_envelope: Value = serde_json::from_str(text).expect("approved text JSON envelope");
    assert_eq!(
        text_envelope, response["result"]["structuredContent"],
        "content and structuredContent must carry the same scanned envelope"
    );
}

fn descriptor_path(app_directory: &Path, server_id: &str) -> PathBuf {
    app_directory
        .join("privacy")
        .join("approved-mcp")
        .join("ticket-sessions")
        .join(server_id)
        .join(STANDALONE_DESCRIPTOR_FILE)
}

fn reserve_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("read loopback port")
}

async fn wait_for_http(client: &reqwest::Client, endpoint: &str, bearer: &str) {
    for _ in 0..HTTP_ATTEMPTS {
        match post_http(client, endpoint, bearer, initialize_request(1)).await {
            Ok(value) if value["result"]["protocolVersion"] == "2025-11-25" => return,
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("standalone HTTP executable did not become ready");
}

async fn post_http(
    client: &reqwest::Client,
    endpoint: &str,
    bearer: &str,
    body: Value,
) -> Result<Value, String> {
    let response = client
        .post(endpoint)
        .header("accept", "application/json, text/event-stream")
        .header("origin", HTTP_ORIGIN)
        .header("mcp-protocol-version", "2025-11-25")
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if status != reqwest::StatusCode::OK || bytes.len() > MAX_WIRE_BYTES {
        return Err(format!("unexpected local HTTP status {status}"));
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn capture_bytes<R: Read + Send + 'static>(mut reader: R) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .expect("capture child output");
        bytes
    })
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child process") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_and_panic(child: &mut Child, message: &str) -> ! {
    let _ = child.kill();
    let _ = child.wait();
    panic!("{message}")
}

fn run_expected_failure(mut command: ProcessCommand, sensitive: &[&str]) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("launch expected-failure executable");
    let stdout = capture_bytes(child.stdout.take().expect("failure stdout"));
    let stderr = capture_bytes(child.stderr.take().expect("failure stderr"));
    let status = wait_for_exit(&mut child, PROCESS_TIMEOUT)
        .unwrap_or_else(|| terminate_and_panic(&mut child, "expected-failure process hung"));
    let stdout = stdout.join().expect("join failure stdout");
    let stderr = stderr.join().expect("join failure stderr");
    assert!(!status.success(), "negative case must fail closed");
    assert!(
        stdout.is_empty(),
        "negative case must not write protocol data"
    );
    let diagnostic = String::from_utf8(stderr).expect("ASCII-safe failure diagnostic");
    assert_eq!(diagnostic.trim(), "lawyer-assistance-mcp: startup_failed");
    assert_no_sensitive(&diagnostic, sensitive);
}

fn assert_clean_process_output(stdout: &[u8], stderr: &[u8], sensitive: &[&str]) {
    assert!(stdout.is_empty(), "standalone HTTP stdout remains empty");
    let diagnostic = String::from_utf8(stderr.to_vec()).expect("UTF-8 process diagnostic");
    assert!(diagnostic.trim().is_empty(), "logging disabled for E2E");
    assert_no_sensitive(&diagnostic, sensitive);
}

fn assert_opaque_metadata(metadata_json: &str) {
    for forbidden in [
        "accessTicket",
        "httpBearer",
        "descriptorPath",
        "legalDatabasePath",
        "userDatabasePath",
        "allowedRoots",
        "outputRoot",
        "content",
        "token",
        "secret",
    ] {
        assert!(
            !metadata_json.contains(forbidden),
            "opaque metadata excludes {forbidden}"
        );
    }
}

fn assert_no_sensitive(text: &str, sensitive: &[&str]) {
    for value in sensitive {
        assert!(
            value.is_empty() || !text.contains(value),
            "wire data and diagnostics must not contain a sensitive canary"
        );
    }
}
