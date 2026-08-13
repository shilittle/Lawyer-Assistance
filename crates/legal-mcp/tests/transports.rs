#![allow(clippy::unwrap_used)]

use axum::Router;
use legal_mcp::{
    config::{BearerSecret, Command, Limits, ResolvedConfig},
    handler::LegalMcpServer,
    http::build_router,
    registry::{PrivacyProfile, ToolRegistry, DISABLED_SENSITIVE_TOOL_NAMES, TOOL_NAMES},
    service_adapter::ServiceAdapter,
};
#[cfg(windows)]
use legal_mcp::{
    receipt_gate::{
        RedactedReceiptGate, CITATION_VALIDATE_PURPOSE, REDACTED_CASE_DESTINATION_IDENTIFIER,
    },
    registry::REDACTED_CASE_TOOL_NAMES,
    stdio::StableProtocolTransport,
};
#[cfg(windows)]
use legal_services::CitationValidateRequest;
use legal_services::{LegalServices, ServiceConfig};
#[cfg(windows)]
use privacy::{
    sha256_hex, DestinationKind, DestinationScope, PrivacyStore, ReceiptSigner,
    RedactionReceiptClaims, RegisterPrivacyMaterial, ReviewState, SaveReviewDraft,
    REDACTION_VERSION,
};
#[cfg(windows)]
use rmcp::{transport::async_rw::AsyncRwTransport, RoleServer, ServiceExt};
use serde_json::{json, Map, Value};

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
#[cfg(windows)]
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader as TokioBufReader, Lines,
};
use tokio_util::sync::CancellationToken;

const STABLE_VERSION: &str = "2025-11-25";
const UNSUPPORTED_VERSION: &str = "9999-12-31";
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";
const SENSITIVE_RESULT_CANARY: &str = "alice.case@example.com";
const INPUT_CANARY_PHONE: &str = "13800138000";
const INPUT_CANARY_NAME: &str = "原告：张三";
const MAX_TEST_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_TEST_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
struct FixturePaths {
    legal_db: PathBuf,
    user_db: PathBuf,
    output_root: PathBuf,
    material_root: PathBuf,
}

struct Fixture {
    _temporary: TempDir,
    paths: FixturePaths,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("fixture directory");
        let output_root = temporary.path().join("exports");
        std::fs::create_dir(&output_root).expect("output root");
        let material_root = temporary.path().join("materials");
        std::fs::create_dir(&material_root).expect("material root");
        let user_db = database::ensure_user_database(temporary.path()).expect("user database");
        let legal_db = temporary.path().join("legal_core.sqlite");
        let legal = rusqlite::Connection::open(&legal_db).expect("legal fixture database");
        database::initialize_legal_core_database(&legal).expect("legal fixture schema");
        legal
            .execute_batch(include_str!(
                "../../legal-services/tests/fixtures/legal_core.sql"
            ))
            .expect("legal fixture rows");
        legal
            .execute(
                "UPDATE law_articles SET content = ?1 WHERE id = 'contract-law-107'",
                [SENSITIVE_RESULT_CANARY],
            )
            .expect("inject synthetic privacy canary");
        drop(legal);
        Self {
            _temporary: temporary,
            paths: FixturePaths {
                legal_db,
                user_db,
                output_root,
                material_root,
            },
        }
    }
}

fn server(paths: &FixturePaths) -> LegalMcpServer {
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: absolute(&paths.legal_db),
        user_database_path: absolute(&paths.user_db),
        allowed_file_roots: vec![absolute(&paths.material_root)],
        allowed_output_root: absolute(&paths.output_root),
    })
    .expect("service fixture");
    LegalMcpServer::new(ToolRegistry::new(), ServiceAdapter::new(services))
}

#[cfg(windows)]
fn redacted_server(paths: &FixturePaths, gate: RedactedReceiptGate) -> LegalMcpServer {
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: absolute(&paths.legal_db),
        user_database_path: absolute(&paths.user_db),
        allowed_file_roots: vec![absolute(&paths.material_root)],
        allowed_output_root: absolute(&paths.output_root),
    })
    .expect("redacted service fixture");
    LegalMcpServer::new(
        ToolRegistry::for_profile(PrivacyProfile::RedactedCase),
        ServiceAdapter::for_profile_with_receipt_gate(services, gate),
    )
}

#[cfg(windows)]
struct TransportReceipt {
    payload: String,
    token: String,
    receipt_id: String,
}

#[cfg(windows)]
fn transport_citation_payload() -> String {
    let source = "law:civil-code:civil-code-v1:art:465";
    serde_json::to_string(&CitationValidateRequest {
        schema_version: 1,
        answer: format!("[SRC:{source}]"),
        allowed_source_ids: vec![source.to_owned()],
        case_date: Some("2026-01-01".to_owned()),
        include_expired: false,
    })
    .expect("transport citation payload")
}

#[cfg(windows)]
fn transport_receipt_signer() -> ReceiptSigner {
    ReceiptSigner::new([0x69u8; 32]).expect("transport receipt signer")
}

#[cfg(windows)]
fn privacy_database_path(paths: &FixturePaths) -> PathBuf {
    paths
        .user_db
        .parent()
        .expect("user database parent")
        .join("privacy")
        .join("privacy-workflow.sqlite")
}

#[cfg(windows)]
fn create_transport_receipt(
    paths: &FixturePaths,
    suffix: &str,
    payload: String,
    configure: impl FnOnce(&mut RedactionReceiptClaims, u64),
    persist: bool,
) -> TransportReceipt {
    let privacy_database_path = privacy_database_path(paths);
    std::fs::create_dir_all(
        privacy_database_path
            .parent()
            .expect("privacy database parent"),
    )
    .expect("privacy directory");
    let mut connection =
        rusqlite::Connection::open(&privacy_database_path).expect("privacy database");
    connection
        .execute_batch("PRAGMA foreign_keys=ON;")
        .expect("privacy foreign keys");
    PrivacyStore::initialize(&connection).expect("privacy schema");

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let source_sha256 = sha256_hex(format!("source-{suffix}").as_bytes());
    let extraction_sha256 = sha256_hex(format!("extraction-{suffix}").as_bytes());
    let redacted_content_sha256 = sha256_hex(format!("redacted-{suffix}").as_bytes());
    let mut claims = RedactionReceiptClaims {
        receipt_id: String::new(),
        source_sha256: vec![source_sha256.clone()],
        extraction_sha256: extraction_sha256.clone(),
        redacted_content_sha256: redacted_content_sha256.clone(),
        approved_payload_sha256: sha256_hex(payload.as_bytes()),
        policy_id: "cn-legal-default".to_owned(),
        policy_version: 1,
        detector_version: REDACTION_VERSION.to_owned(),
        destination: DestinationScope {
            kind: DestinationKind::ExternalMcpHost,
            identifier: REDACTED_CASE_DESTINATION_IDENTIFIER.to_owned(),
        },
        purpose: CITATION_VALIDATE_PURPOSE.to_owned(),
        unresolved_high_risk_count: 0,
        review_state: ReviewState::Approved,
        issued_at_unix: now_unix.saturating_sub(5),
        expires_at_unix: Some(now_unix + 120),
        key_version: 1,
    };
    configure(&mut claims, now_unix);

    let material_id = format!("material-{suffix}");
    let redaction_id = format!("redaction-{suffix}");
    PrivacyStore::register_material(
        &connection,
        &RegisterPrivacyMaterial {
            material_id: &material_id,
            project_id: None,
            attachment_id: None,
            source_sha256: &source_sha256,
            source_name_sha256: &sha256_hex(format!("name-{suffix}").as_bytes()),
            media_type: "application/pdf",
            page_count: Some(1),
        },
    )
    .expect("register transport material");
    PrivacyStore::save_review_draft(
        &connection,
        &SaveReviewDraft {
            redaction_id: &redaction_id,
            material_id: &material_id,
            extraction_sha256: &extraction_sha256,
            redacted_content_sha256: &redacted_content_sha256,
            policy_id: &claims.policy_id,
            policy_version: claims.policy_version,
            detector_version: &claims.detector_version,
            unresolved_high_risk_count: 0,
            review_payload_plaintext: b"transport review",
        },
    )
    .expect("save transport review");
    PrivacyStore::approve_review(
        &mut connection,
        &redaction_id,
        &redacted_content_sha256,
        &redacted_content_sha256,
        &claims.approved_payload_sha256,
        &sha256_hex(b"transport-reviewer"),
        payload.as_bytes(),
    )
    .expect("approve transport review");

    let signer = transport_receipt_signer();
    let receipt = signer.issue(claims).expect("issue transport receipt");
    let token = signer
        .encode_token(&receipt)
        .expect("encode transport receipt");
    if persist {
        PrivacyStore::persist_receipt(
            &mut connection,
            &redaction_id,
            &signer,
            &receipt,
            &token,
            payload.as_bytes(),
            receipt.claims.issued_at_unix,
        )
        .expect("persist transport receipt");
    }
    TransportReceipt {
        payload,
        token,
        receipt_id: receipt.claims.receipt_id,
    }
}

#[cfg(windows)]
fn transport_receipt_gate(paths: &FixturePaths) -> RedactedReceiptGate {
    RedactedReceiptGate::from_signer_and_database(transport_receipt_signer(), &paths.user_db)
        .expect("transport receipt gate")
}

#[cfg(windows)]
fn revoke_transport_receipt(paths: &FixturePaths, receipt: &TransportReceipt) {
    let connection =
        rusqlite::Connection::open(privacy_database_path(paths)).expect("privacy database");
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    PrivacyStore::revoke_receipt(&connection, &receipt.receipt_id, now_unix)
        .expect("revoke transport receipt");
}

fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonical fixture path")
}

#[derive(Debug)]
struct StdioResult {
    initialize: Value,
    tools: Value,
    success: Value,
    tool_error: Value,
    privacy_blocked: Value,
    hidden_tool: Value,
    stdout_lines: Vec<String>,
    stderr: String,
}

fn run_stdio(paths: FixturePaths) -> StdioResult {
    let binary = env!("CARGO_BIN_EXE_lawyer-assistance-mcp");
    let mut child = ProcessCommand::new(binary)
        .arg("--legal-db")
        .arg(absolute(&paths.legal_db))
        .arg("--user-db")
        .arg(absolute(&paths.user_db))
        .arg("--output-dir")
        .arg(absolute(&paths.output_root))
        .arg("--allowed-root")
        .arg(absolute(&paths.material_root))
        .arg("stdio")
        .env("LAWYER_ASSISTANCE_MCP_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdio MCP");
    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");
    let (line_tx, line_rx) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let _ = line_tx.send(line.map_err(|error| error.to_string()));
        }
    });
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut text);
        text
    });
    let mut stdout_lines = Vec::new();

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":UNSUPPORTED_VERSION,
                "capabilities":{},
                "clientInfo":{"name":"transport-test","version":"1"}
            }
        }),
    );
    let initialize = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(initialize["result"]["protocolVersion"], STABLE_VERSION);

    send_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let tools = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(
        tools["result"]["tools"].as_array().map(Vec::len),
        Some(TOOL_NAMES.len())
    );

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"system_status","arguments":{"schema_version":1}}
        }),
    );
    let success = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(success["result"]["isError"], false);
    assert_eq!(success["result"]["structuredContent"]["结果"], "已完成");
    assert_text_fallback_matches_structured(&success["result"]);

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{
                "name":"legal_get_article",
                "arguments":{
                    "schema_version":1,
                    "article_id":format!("missing-{INPUT_CANARY_PHONE}")
                }
            }
        }),
    );
    let tool_error = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(tool_error["result"]["isError"], true);
    assert_eq!(tool_error["result"]["structuredContent"]["结果"], "未完成");
    assert_text_fallback_matches_structured(&tool_error["result"]);

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{
                "name":"legal_get_article",
                "arguments":{"schema_version":1,"article_id":"contract-law-107"}
            }
        }),
    );
    let privacy_blocked = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(privacy_blocked["result"]["isError"], true);
    assert_eq!(
        privacy_blocked["result"]["structuredContent"]["结果"],
        "未完成"
    );
    assert!(privacy_blocked["result"]["structuredContent"]["说明"]
        .as_str()
        .is_some_and(|value| value.contains("敏感个人信息")));
    assert_text_fallback_matches_structured(&privacy_blocked["result"]);

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{
                "name":"case_get_state",
                "arguments":{"schema_version":1,"project_id":INPUT_CANARY_NAME}
            }
        }),
    );
    let hidden_tool = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(hidden_tool["error"]["code"], -32601);
    assert!(hidden_tool.get("result").is_none());

    drop(stdin);
    wait_for_child(&mut child);
    stdout_reader.join().expect("stdout reader");
    while let Ok(line) = line_rx.try_recv() {
        stdout_lines.push(line.expect("stdout line"));
    }
    let stderr = stderr_reader.join().expect("stderr reader");
    for line in &stdout_lines {
        serde_json::from_str::<Value>(line).expect("stdout contains only JSON-RPC frames");
    }
    for canary in [
        SENSITIVE_RESULT_CANARY,
        INPUT_CANARY_PHONE,
        INPUT_CANARY_NAME,
    ] {
        assert!(!stderr.contains(canary), "stderr leaked canary");
        for line in &stdout_lines {
            assert!(!line.contains(canary), "stdout leaked canary");
        }
    }
    assert!(!stderr.contains(UNSUPPORTED_VERSION));
    assert!(!stderr.contains("system_status\""));

    StdioResult {
        initialize,
        tools,
        success,
        tool_error,
        privacy_blocked,
        hidden_tool,
        stdout_lines,
        stderr,
    }
}

fn send_line(stdin: &mut impl Write, value: Value) {
    serde_json::to_writer(&mut *stdin, &value).expect("serialize MCP message");
    stdin.write_all(b"\n").expect("write newline");
    stdin.flush().expect("flush MCP message");
}

fn receive_json(
    receiver: &mpsc::Receiver<Result<String, String>>,
    stdout_lines: &mut Vec<String>,
) -> Value {
    let line = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("timely MCP response")
        .expect("read MCP response");
    stdout_lines.push(line.clone());
    serde_json::from_str(&line).expect("valid JSON-RPC response")
}

#[cfg(windows)]
async fn send_async_line(writer: &mut (impl AsyncWrite + Unpin), value: Value) {
    let mut wire = serde_json::to_vec(&value).expect("serialize async MCP message");
    wire.push(b'\n');
    writer
        .write_all(&wire)
        .await
        .expect("write async MCP message");
    writer.flush().await.expect("flush async MCP message");
}

#[cfg(windows)]
async fn receive_async_line<R>(reader: &mut Lines<TokioBufReader<R>>) -> String
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .expect("timely async MCP response")
        .expect("read async MCP response")
        .expect("MCP response line")
}

#[cfg(windows)]
async fn receive_async_json<R>(reader: &mut Lines<TokioBufReader<R>>) -> (String, Value)
where
    R: AsyncRead + Unpin,
{
    let line = receive_async_line(reader).await;
    let value = serde_json::from_str(&line).expect("valid async JSON-RPC response");
    (line, value)
}

fn wait_for_child(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().expect("poll child").is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("stdio MCP did not exit after stdin closed");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn public_law_only_stdio_hides_case_tools_and_never_returns_canaries() {
    let fixture = Fixture::new();
    let paths = fixture.paths.clone();
    let result = run_stdio(paths);

    assert_eq!(result.stdout_lines.len(), 6);
    assert!(result.stderr.len() < 16 * 1024);
    assert_eq!(
        result.initialize["result"]["protocolVersion"],
        STABLE_VERSION
    );
    assert!(result.initialize["result"]["instructions"]
        .as_str()
        .is_some_and(|value| value.contains("严禁")));

    let visible = result.tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(visible, TOOL_NAMES);
    for name in DISABLED_SENSITIVE_TOOL_NAMES {
        assert!(!visible.contains(&name), "{name}");
    }

    assert_eq!(result.success["result"]["isError"], false);
    assert_eq!(result.tool_error["result"]["isError"], true);
    assert_eq!(result.privacy_blocked["result"]["isError"], true);
    assert_eq!(result.hidden_tool["error"]["code"], -32601);

    let serialized =
        serde_json::to_string(&result.privacy_blocked).expect("serialize privacy-blocked result");
    assert!(!serialized.contains(SENSITIVE_RESULT_CANARY));
    assert_text_fallback_matches_structured(&result.privacy_blocked["result"]);

    let database = database::open_user_database_read_only(&fixture.paths.user_db)
        .expect("inspect untouched user database");
    for table in ["projects", "attachments", "operation_audit"] {
        let count: i64 = database
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("table count");
        assert_eq!(count, 0, "hidden calls must not mutate {table}");
    }
}

#[derive(Debug)]
struct RawHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawHttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, value)| {
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.as_str())
        })
    }
}

async fn spawn_http(paths: &FixturePaths) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_http_with_timeout(paths, Duration::from_secs(2)).await
}

async fn spawn_http_with_timeout(
    paths: &FixturePaths,
    request_timeout: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP fixture");
    let address = listener.local_addr().expect("HTTP fixture address");
    let config = ResolvedConfig {
        legal_db: absolute(&paths.legal_db),
        user_db: absolute(&paths.user_db),
        allowed_roots: vec![absolute(&paths.material_root)],
        output_root: absolute(&paths.output_root),
        privacy_profile: PrivacyProfile::default(),
        bind: address,
        allowed_origins: vec!["https://client.example".into()],
        allowed_hosts: vec![address.to_string()],
        bearer: Some(
            BearerSecret::from_token_bytes(TEST_TOKEN.as_bytes().to_vec()).expect("test token"),
        ),
        dangerously_allow_insecure_non_loopback_http: false,
        limits: Limits {
            max_body_bytes: 16 * 1024,
            request_timeout,
            max_concurrency: 1,
        },
        command: Command::Serve {
            bind: Some(address),
        },
    };
    let router: Router = build_router(server(paths), &config, CancellationToken::new());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (address, task)
}

#[cfg(windows)]
async fn spawn_redacted_http(
    paths: &FixturePaths,
    gate: RedactedReceiptGate,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redacted HTTP fixture");
    let address = listener.local_addr().expect("redacted HTTP address");
    let config = ResolvedConfig {
        legal_db: absolute(&paths.legal_db),
        user_db: absolute(&paths.user_db),
        allowed_roots: vec![absolute(&paths.material_root)],
        output_root: absolute(&paths.output_root),
        privacy_profile: PrivacyProfile::RedactedCase,
        bind: address,
        allowed_origins: vec!["https://client.example".into()],
        allowed_hosts: vec![address.to_string()],
        bearer: Some(
            BearerSecret::from_token_bytes(TEST_TOKEN.as_bytes().to_vec()).expect("test token"),
        ),
        dangerously_allow_insecure_non_loopback_http: false,
        limits: Limits {
            max_body_bytes: 64 * 1024,
            request_timeout: Duration::from_secs(5),
            max_concurrency: 1,
        },
        command: Command::Serve {
            bind: Some(address),
        },
    };
    let router: Router = build_router(
        redacted_server(paths, gate),
        &config,
        CancellationToken::new(),
    );
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (address, task)
}

async fn post_json(
    address: SocketAddr,
    body: Value,
    token: Option<&str>,
    origin: Option<&str>,
    protocol: Option<&str>,
) -> RawHttpResponse {
    let body = serde_json::to_vec(&body).expect("HTTP JSON body");
    let token = token.map(ToOwned::to_owned);
    let origin = origin.map(ToOwned::to_owned);
    let protocol = protocol.map(ToOwned::to_owned);
    tokio::task::spawn_blocking(move || {
        raw_http(
            address,
            body,
            token.as_deref(),
            origin.as_deref(),
            protocol.as_deref(),
        )
    })
    .await
    .expect("HTTP blocking task")
}

fn raw_http(
    address: SocketAddr,
    body: Vec<u8>,
    token: Option<&str>,
    origin: Option<&str>,
    protocol: Option<&str>,
) -> RawHttpResponse {
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    if let Some(protocol) = protocol {
        request.push_str(&format!("MCP-Protocol-Version: {protocol}\r\n"));
    }
    request.push_str("\r\n");
    let mut request = request.into_bytes();
    request.extend_from_slice(&body);
    let mut stream = TcpStream::connect(address).expect("connect HTTP fixture");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream.write_all(&request).expect("HTTP request");
    stream.flush().expect("flush HTTP request");
    read_http_response(stream)
}

fn read_http_response(stream: impl Read) -> RawHttpResponse {
    try_read_http_response(stream).expect("HTTP response")
}

fn try_read_http_response(stream: impl Read) -> io::Result<RawHttpResponse> {
    let mut reader = BufReader::new(stream);
    let mut header_bytes = 0;
    let status_line = read_crlf_line(
        &mut reader,
        &mut header_bytes,
        MAX_TEST_HTTP_HEADER_BYTES,
        "HTTP response status line",
    )?;
    let status_line = std::str::from_utf8(&status_line)
        .map_err(|_| invalid_http_response("HTTP response status line is not UTF-8"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| invalid_http_response("HTTP response status is invalid"))?;

    let mut headers = Vec::new();
    loop {
        let line = read_crlf_line(
            &mut reader,
            &mut header_bytes,
            MAX_TEST_HTTP_HEADER_BYTES,
            "HTTP response headers",
        )?;
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| invalid_http_response("HTTP response header is not UTF-8"))?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid_http_response("HTTP response header is invalid"))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let is_chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    });
    let mut content_length = None;
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = value
            .parse::<usize>()
            .map_err(|_| invalid_http_response("HTTP Content-Length is invalid"))?;
        if content_length.is_some_and(|existing| existing != parsed) {
            return Err(invalid_http_response(
                "HTTP response has conflicting Content-Length headers",
            ));
        }
        content_length = Some(parsed);
    }
    if is_chunked && content_length.is_some() {
        return Err(invalid_http_response(
            "HTTP response has both chunked encoding and Content-Length",
        ));
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(length) = content_length {
        if length > MAX_TEST_HTTP_RESPONSE_BYTES {
            return Err(invalid_http_response(
                "HTTP response body exceeds test limit",
            ));
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        body
    } else {
        let mut body = Vec::new();
        reader
            .take(
                u64::try_from(MAX_TEST_HTTP_RESPONSE_BYTES + 1)
                    .expect("test HTTP response limit fits u64"),
            )
            .read_to_end(&mut body)?;
        if body.len() > MAX_TEST_HTTP_RESPONSE_BYTES {
            return Err(invalid_http_response(
                "HTTP response body exceeds test limit",
            ));
        }
        body
    };

    Ok(RawHttpResponse {
        status,
        headers,
        body,
    })
}

fn read_crlf_line<R: BufRead>(
    reader: &mut R,
    consumed: &mut usize,
    limit: usize,
    context: &'static str,
) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let remaining = limit
            .checked_sub(*consumed)
            .ok_or_else(|| invalid_http_response("HTTP response metadata exceeds test limit"))?;
        if remaining == 0 {
            return Err(invalid_http_response(
                "HTTP response metadata exceeds test limit",
            ));
        }

        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{context} ended before CRLF"),
            ));
        }
        let examined = available.len().min(remaining);
        let newline = available[..examined].iter().position(|byte| *byte == b'\n');
        let copied = newline.map_or(examined, |position| position + 1);
        line.extend_from_slice(&available[..copied]);
        reader.consume(copied);
        *consumed = consumed
            .checked_add(copied)
            .ok_or_else(|| invalid_http_response("HTTP response line budget overflow"))?;

        if newline.is_some() {
            break;
        }
        if copied == remaining {
            return Err(invalid_http_response(
                "HTTP response metadata exceeds test limit",
            ));
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err(invalid_http_response(
            "HTTP response line is not CRLF terminated",
        ));
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut metadata_bytes = 0;
    loop {
        let size_line = read_crlf_line(
            reader,
            &mut metadata_bytes,
            MAX_TEST_HTTP_HEADER_BYTES,
            "HTTP chunk size",
        )?;
        let size_token = size_line
            .split(|byte| *byte == b';')
            .next()
            .ok_or_else(|| invalid_http_response("HTTP chunk size is missing"))?;
        let size_token = std::str::from_utf8(size_token)
            .map_err(|_| invalid_http_response("HTTP chunk size is not ASCII"))?
            .trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| invalid_http_response("HTTP chunk size is invalid"))?;
        if size == 0 {
            loop {
                let trailer = read_crlf_line(
                    reader,
                    &mut metadata_bytes,
                    MAX_TEST_HTTP_HEADER_BYTES,
                    "HTTP chunk trailers",
                )?;
                if trailer.is_empty() {
                    return Ok(body);
                }
                if !trailer.contains(&b':') {
                    return Err(invalid_http_response("HTTP chunk trailer is invalid"));
                }
            }
        }
        let new_length = body
            .len()
            .checked_add(size)
            .ok_or_else(|| invalid_http_response("HTTP chunked body length overflow"))?;
        if new_length > MAX_TEST_HTTP_RESPONSE_BYTES {
            return Err(invalid_http_response(
                "HTTP response body exceeds test limit",
            ));
        }
        let start = body.len();
        body.resize(new_length, 0);
        reader.read_exact(&mut body[start..])?;
        let mut terminator = [0; 2];
        reader.read_exact(&mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(invalid_http_response("HTTP chunk is not CRLF terminated"));
        }
    }
}

fn invalid_http_response(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug)]
struct CompleteThenAbort {
    bytes: &'static [u8],
    offset: usize,
    max_chunk_size: usize,
}

impl CompleteThenAbort {
    fn new(bytes: &'static [u8], max_chunk_size: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_chunk_size,
        }
    }
}

impl Read for CompleteThenAbort {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "synthetic peer aborted after the complete framed response",
            ));
        }
        let count = output
            .len()
            .min(self.max_chunk_size)
            .min(self.bytes.len() - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn framed_http_response_reader_stops_before_an_aborted_eof() {
    let content_length = CompleteThenAbort::new(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
        3,
    );
    let response = try_read_http_response(content_length).expect("Content-Length response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"pong");

    let chunked = CompleteThenAbort::new(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npong\r\n0\r\nX-Test: done\r\n\r\n",
        3,
    );
    let response = try_read_http_response(chunked).expect("chunked response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"pong");
}

#[test]
fn framed_http_response_reader_rejects_truncated_content_length() {
    let truncated = &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npong"[..];
    let error = try_read_http_response(truncated).expect_err("truncated response must fail");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn http_metadata_reader_enforces_budget_before_allocation() {
    const LIMIT: usize = 32;

    let mut exact = vec![b'a'; LIMIT - 2];
    exact.extend_from_slice(b"\r\n");
    let mut exact_reader = BufReader::with_capacity(7, exact.as_slice());
    let mut exact_consumed = 0;
    let exact_line = read_crlf_line(
        &mut exact_reader,
        &mut exact_consumed,
        LIMIT,
        "bounded metadata",
    )
    .expect("exact-limit CRLF line");
    assert_eq!(exact_line, vec![b'a'; LIMIT - 2]);
    assert_eq!(exact_consumed, LIMIT);

    let oversized = vec![b'a'; LIMIT + 1];
    let mut oversized_reader = BufReader::with_capacity(7, oversized.as_slice());
    let mut oversized_consumed = 0;
    let error = read_crlf_line(
        &mut oversized_reader,
        &mut oversized_consumed,
        LIMIT,
        "bounded metadata",
    )
    .expect_err("unterminated metadata must respect its budget");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(oversized_consumed, LIMIT);
}

async fn slow_body_request(
    address: SocketAddr,
    permit_acquired: tokio::sync::oneshot::Sender<()>,
) -> RawHttpResponse {
    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(address).expect("slow connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("slow read timeout");
        let headers = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAuthorization: Bearer {TEST_TOKEN}\r\nOrigin: https://client.example\r\nMCP-Protocol-Version: {STABLE_VERSION}\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n"
        );
        stream.write_all(headers.as_bytes()).expect("slow headers");
        stream.flush().expect("slow flush");

        // Hyper emits this informational response only when the service polls
        // the request body. At that point the boundary middleware has already
        // acquired the sole concurrency permit, so this is a server-side
        // synchronization point rather than a client socket-flush heuristic.
        const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
        let mut response = vec![0; CONTINUE.len()];
        stream
            .read_exact(&mut response)
            .expect("read server-side 100-continue acknowledgement");
        assert_eq!(response, CONTINUE);
        permit_acquired
            .send(())
            .expect("report acquired slow-request permit");
        read_http_response(stream)
    })
    .await
    .expect("slow request task")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_and_http_are_protocol_consistent_and_secure() {
    let fixture = Fixture::new();
    let stdio_paths = fixture.paths.clone();
    let stdio = tokio::task::spawn_blocking(move || run_stdio(stdio_paths))
        .await
        .expect("stdio task");
    assert_eq!(stdio.stdout_lines.len(), 6);
    assert!(stdio.stderr.len() < 16 * 1024);
    assert_eq!(
        stdio.initialize["result"]["protocolVersion"],
        STABLE_VERSION
    );
    assert_eq!(
        stdio.success["result"]["structuredContent"]["结果"],
        "已完成"
    );
    assert_eq!(
        stdio.tool_error["result"]["structuredContent"]["结果"],
        "未完成"
    );
    assert_text_fallback_matches_structured(&stdio.success["result"]);
    assert_text_fallback_matches_structured(&stdio.tool_error["result"]);

    let (address, http_task) = spawn_http(&fixture.paths).await;
    let initialize_body = json!({
        "jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{
            "protocolVersion":UNSUPPORTED_VERSION,
            "capabilities":{},
            "clientInfo":{"name":"transport-test","version":"1"}
        }
    });

    let unauthorized = post_json(address, initialize_body.clone(), None, None, None).await;
    assert_eq!(unauthorized.status, 401);
    assert_eq!(
        unauthorized.header("WWW-Authenticate"),
        Some("Bearer realm=\"lawyer-assistance-mcp\"")
    );
    let unauthorized_json: Value = serde_json::from_slice(&unauthorized.body).expect("401 JSON");
    assert_eq!(unauthorized_json["error"]["code"], "unauthorized");
    assert!(unauthorized_json["error"]["details"].is_object());

    let bad_origin = post_json(
        address,
        initialize_body.clone(),
        Some(TEST_TOKEN),
        Some("https://evil.example"),
        None,
    )
    .await;
    assert_eq!(bad_origin.status, 403);

    let oversized = post_json(
        address,
        Value::String("x".repeat(17 * 1024)),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        None,
    )
    .await;
    assert_eq!(oversized.status, 413);

    let initialize = post_json(
        address,
        initialize_body,
        Some(TEST_TOKEN),
        Some("https://client.example"),
        None,
    )
    .await;
    assert_eq!(initialize.status, 200);
    let initialize: Value = serde_json::from_slice(&initialize.body).expect("initialize JSON");
    assert_eq!(initialize["result"]["protocolVersion"], STABLE_VERSION);

    let rc_header = post_json(
        address,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(UNSUPPORTED_VERSION),
    )
    .await;
    assert_eq!(rc_header.status, 400);

    let tools = post_json(
        address,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(tools.status, 200);
    let tools: Value = serde_json::from_slice(&tools.body).expect("tools JSON");
    assert_eq!(tools["result"]["tools"], stdio.tools["result"]["tools"]);

    let call = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"system_status","arguments":{"schema_version":1}}
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(call.status, 200);
    let call: Value = serde_json::from_slice(&call.body).expect("call JSON");
    assert_eq!(call["result"]["structuredContent"]["结果"], "已完成");
    assert_text_fallback_matches_structured(&call["result"]);

    let invalid_call = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"legal_get_article","arguments":{}}
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(invalid_call.status, 200);
    let invalid_call: Value =
        serde_json::from_slice(&invalid_call.body).expect("invalid call JSON");
    assert_eq!(invalid_call["result"]["isError"], true);
    assert_eq!(
        invalid_call["result"]["structuredContent"]["结果"],
        "未完成"
    );
    assert_text_fallback_matches_structured(&invalid_call["result"]);

    // `100 Continue` is emitted only after Hyper polls the request body. The
    // middleware therefore already owns the only permit when this signal is
    // observed, making the following concurrency assertion deterministic.
    let (permit_acquired, slow_ready) = tokio::sync::oneshot::channel();
    let slow = tokio::spawn(slow_body_request(address, permit_acquired));
    tokio::time::timeout(Duration::from_secs(5), slow_ready)
        .await
        .expect("observe server-side slow-request admission")
        .expect("slow request admission signal");
    let concurrent = post_json(
        address,
        json!({"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(concurrent.status, 429);
    assert_eq!(concurrent.header("Retry-After"), Some("1"));
    assert_eq!(slow.await.expect("slow join").status, 408);

    http_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_law_only_http_rejects_sensitive_tools_and_blocks_sensitive_results() {
    let fixture = Fixture::new();
    let (address, http_task) =
        spawn_http_with_timeout(&fixture.paths, Duration::from_secs(5)).await;

    let initialize = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":STABLE_VERSION,
                "capabilities":{},
                "clientInfo":{"name":"privacy-http-test","version":"1"}
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        None,
    )
    .await;
    assert_eq!(initialize.status, 200);
    let initialize: Value =
        serde_json::from_slice(&initialize.body).expect("initialize response JSON");
    assert_eq!(initialize["result"]["protocolVersion"], STABLE_VERSION);

    let tools = post_json(
        address,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(tools.status, 200);
    let tools: Value = serde_json::from_slice(&tools.body).expect("tools response JSON");
    let visible = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(visible, TOOL_NAMES);

    for (index, name) in DISABLED_SENSITIVE_TOOL_NAMES.into_iter().enumerate() {
        let response = post_json(
            address,
            json!({
                "jsonrpc":"2.0",
                "id":100 + index,
                "method":"tools/call",
                "params":{
                    "name":name,
                    "arguments":{
                        "schema_version":1,
                        "project_id":INPUT_CANARY_NAME,
                        "answer":SENSITIVE_RESULT_CANARY
                    }
                }
            }),
            Some(TEST_TOKEN),
            Some("https://client.example"),
            Some(STABLE_VERSION),
        )
        .await;
        assert_eq!(response.status, 200, "{name}");
        let body: Value =
            serde_json::from_slice(&response.body).expect("hidden-tool response JSON");
        assert_eq!(body["error"]["code"], -32601, "{name}: {body:#}");
        let serialized = String::from_utf8(response.body).expect("UTF-8 hidden response");
        assert!(!serialized.contains(INPUT_CANARY_NAME), "{name}");
        assert!(!serialized.contains(SENSITIVE_RESULT_CANARY), "{name}");
    }

    let public_article = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{
                "name":"legal_get_article",
                "arguments":{"schema_version":1,"article_id":"civil-code-465"}
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(public_article.status, 200);
    let public_article: Value =
        serde_json::from_slice(&public_article.body).expect("public article JSON");
    assert_eq!(
        public_article["result"]["isError"], false,
        "{public_article:#}"
    );
    assert_text_fallback_matches_structured(&public_article["result"]);

    for (id, name, arguments) in [
        (
            20,
            "legal_search",
            json!({
                "schema_version":1,
                "query":"?".repeat(7),
                "limit":5
            }),
        ),
        (
            21,
            "legal_get_versions",
            json!({"schema_version":1,"document_id":"civil-code"}),
        ),
        (
            22,
            "legal_get_relations",
            json!({
                "schema_version":1,
                "document_id":"civil-code",
                "direction":"both"
            }),
        ),
    ] {
        let response = post_json(
            address,
            json!({
                "jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":name,"arguments":arguments}
            }),
            Some(TEST_TOKEN),
            Some("https://client.example"),
            Some(STABLE_VERSION),
        )
        .await;
        assert_eq!(response.status, 200, "{name}");
        let body: Value =
            serde_json::from_slice(&response.body).expect("public tool response JSON");
        assert_eq!(body["result"]["isError"], false, "{name}: {body:#}");
        assert_text_fallback_matches_structured(&body["result"]);
        assert!(!serde_json::to_string(&body)
            .expect("serialize public response")
            .contains(SENSITIVE_RESULT_CANARY));
    }
    let blocked = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{
                "name":"legal_get_article",
                "arguments":{"schema_version":1,"article_id":"contract-law-107"}
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(blocked.status, 200);
    let blocked: Value = serde_json::from_slice(&blocked.body).expect("blocked article JSON");
    assert_eq!(blocked["result"]["isError"], true, "{blocked:#}");
    assert_eq!(blocked["result"]["structuredContent"]["结果"], "未完成");
    assert_text_fallback_matches_structured(&blocked["result"]);
    let blocked_serialized = serde_json::to_string(&blocked).expect("serialize blocked response");
    assert!(!blocked_serialized.contains(SENSITIVE_RESULT_CANARY));
    assert!(blocked["result"]["structuredContent"]["说明"]
        .as_str()
        .is_some_and(|value| value.contains("敏感个人信息")));

    let database = database::open_user_database_read_only(&fixture.paths.user_db)
        .expect("inspect untouched user database");
    for table in ["projects", "attachments", "operation_audit"] {
        let count: i64 = database
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("table count");
        assert_eq!(count, 0, "HTTP privacy checks must not mutate {table}");
    }

    http_task.abort();
}

#[tokio::test]
async fn every_tool_error_result_is_public_and_matches_its_declared_contract() {
    let fixture = Fixture::new();
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: absolute(&fixture.paths.legal_db),
        user_database_path: absolute(&fixture.paths.user_db),
        allowed_file_roots: Vec::new(),
        allowed_output_root: absolute(&fixture.paths.output_root),
    })
    .expect("service fixture");
    let adapter = ServiceAdapter::new(services);
    let registry = ToolRegistry::new();
    for name in TOOL_NAMES {
        let result = adapter
            .call(name, Some(Map::new()))
            .await
            .expect("known tool routes");
        let structured = result
            .structured_content
            .as_ref()
            .expect("structured public error");
        assert_eq!(structured["结果"], "未完成", "{name}");
        let tool = registry.get(name).expect("registered tool");
        assert_public_result_shape(
            tool.output_schema.as_deref().expect("output schema"),
            structured,
        );
        assert_public_structured_content(structured, name);
    }

    let mut arguments = Map::new();
    arguments.insert("schema_version".into(), json!(1));
    let result = adapter
        .call("system_status", Some(arguments))
        .await
        .expect("status call");
    let structured = result
        .structured_content
        .as_ref()
        .expect("status public result");
    assert_eq!(structured["结果"], "已完成", "{structured:#}");
    let tool = registry.get("system_status").expect("status tool");
    assert_public_result_shape(
        tool.output_schema.as_deref().expect("output schema"),
        structured,
    );
    assert_public_structured_content(structured, "system_status");

    let mut camel_case_alias = Map::new();
    camel_case_alias.insert("schemaVersion".into(), json!(1));
    let alias_result = adapter
        .call("system_status", Some(camel_case_alias))
        .await
        .expect("alias call");
    let alias = alias_result
        .structured_content
        .as_ref()
        .expect("alias public error");
    assert_eq!(alias["结果"], "未完成");
    assert_public_structured_content(alias, "alias error");
}

#[tokio::test]
#[ignore = "requires the formal packaged legal database"]
async fn formal_stdio_legal_search_returns_only_public_readable_content() {
    let legal_db = PathBuf::from(
        std::env::var_os("LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE")
            .expect("formal legal database path"),
    );
    let temporary = tempfile::tempdir().expect("formal transport fixture");
    let user_db = database::ensure_user_database(temporary.path()).expect("user database");
    let output_root = temporary.path().join("exports");
    let material_root = temporary.path().join("materials");
    std::fs::create_dir(&output_root).expect("output root");
    std::fs::create_dir(&material_root).expect("material root");

    let binary = env!("CARGO_BIN_EXE_lawyer-assistance-mcp");
    let mut child = ProcessCommand::new(binary)
        .arg("--legal-db")
        .arg(absolute(&legal_db))
        .arg("--user-db")
        .arg(absolute(&user_db))
        .arg("--output-dir")
        .arg(absolute(&output_root))
        .arg("--allowed-root")
        .arg(absolute(&material_root))
        .arg("stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn formal stdio MCP");
    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");
    let (line_tx, line_rx) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let _ = line_tx.send(line.map_err(|error| error.to_string()));
        }
    });
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut text);
        text
    });
    let mut stdout_lines = Vec::new();

    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":STABLE_VERSION,
                "capabilities":{},
                "clientInfo":{"name":"workbuddy-simulation","version":"1"}
            }
        }),
    );
    let initialize = receive_json(&line_rx, &mut stdout_lines);
    assert_eq!(initialize["result"]["protocolVersion"], STABLE_VERSION);
    send_line(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send_line(
        &mut stdin,
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{
                "name":"legal_search",
                "arguments":{
                    "schema_version":1,
                    "query":"民法典 合同履行 逾期交付",
                    "limit":10
                }
            }
        }),
    );
    let result = receive_json(&line_rx, &mut stdout_lines);
    let text = result["result"]["content"][0]["text"]
        .as_str()
        .expect("public search content");
    assert_eq!(result["result"]["isError"], false, "{result:#}");
    let structured = &result["result"]["structuredContent"];
    assert_public_structured_content(structured, "formal legal search");
    assert_eq!(structured["结果"], "已完成", "{structured:#}");
    assert_eq!(structured["说明"], text, "{structured:#}");
    let structured_object = structured
        .as_object()
        .expect("public structured search object");
    assert_eq!(
        structured_object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["内容", "提示", "结果", "说明"].into_iter().collect(),
        "formal search exposed an undeclared top-level field: {structured:#}"
    );
    let articles = structured["内容"]["相关条文"]
        .as_array()
        .expect("public related articles");
    assert!(!articles.is_empty(), "{structured:#}");
    for article in articles {
        let object = article.as_object().expect("public related article");
        for key in object.keys() {
            assert!(
                key.chars()
                    .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character)),
                "formal search exposed a non-Chinese article field {key}: {article:#}"
            );
        }
        let law_name = article["法律名称"]
            .as_str()
            .expect("public law name")
            .trim();
        let article_number = article["条文"]
            .as_str()
            .expect("public article number")
            .trim();
        let summary = article["内容摘要"]
            .as_str()
            .expect("public article summary")
            .trim();
        assert!(
            law_name
                .chars()
                .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character)),
            "formal search returned an unreadable law name: {article:#}"
        );
        assert!(article_number.contains('条'), "{article:#}");
        assert!(
            summary
                .chars()
                .any(|character| ('\u{4e00}'..='\u{9fff}').contains(&character)),
            "formal search returned an unreadable content summary: {article:#}"
        );
    }
    assert!(text.contains("相关条文"), "{text}");
    assert!(text.contains("民法典"), "{text}");
    assert!(text.contains("内容摘要"), "{text}");
    assert!(text.contains("合同") || text.contains("交付"), "{text}");
    for forbidden in [
        "article_id",
        "document_id",
        "schema_version",
        "request_id",
        "snippet",
        "score",
        "无标题",
        "AppData",
        "C:\\",
    ] {
        assert!(!text.contains(forbidden), "leaked {forbidden}: {text}");
        let structured = serde_json::to_string(structured).expect("public structured search");
        assert!(
            !structured.contains(forbidden),
            "structured content leaked {forbidden}: {structured}"
        );
    }

    drop(stdin);
    wait_for_child(&mut child);
    stdout_reader.join().expect("stdout reader");
    let stderr = stderr_reader.join().expect("stderr reader");
    assert!(!stderr.contains("民法典 合同履行 逾期交付"));
}

#[cfg(windows)]
fn assert_no_case_writes(paths: &FixturePaths) {
    let database = database::open_user_database_read_only(&paths.user_db)
        .expect("inspect untouched user database");
    for table in ["projects", "attachments", "operation_audit"] {
        let count: i64 = database
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("user table count");
        assert_eq!(count, 0, "redacted citation calls must not mutate {table}");
    }
}

#[cfg(windows)]
fn assert_redacted_result_is_privacy_scanned(result: &Value) {
    assert_text_fallback_matches_structured(result);
    let text = result["content"][0]["text"]
        .as_str()
        .expect("model-visible text");
    assert!(
        privacy::scan_residual(text.as_bytes())
            .expect("scan text result")
            .passed,
        "text result contains residual sensitive content"
    );
    let structured =
        serde_json::to_vec(&result["structuredContent"]).expect("structured result bytes");
    assert!(
        privacy::scan_residual(&structured)
            .expect("scan structured result")
            .passed,
        "structured result contains residual sensitive content"
    );
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redacted_case_http_requires_exact_active_receipt_and_keeps_case_tools_hidden() {
    let fixture = Fixture::new();
    let payload = transport_citation_payload();
    let valid = create_transport_receipt(
        &fixture.paths,
        "http-valid",
        payload.clone(),
        |_, _| {},
        true,
    );
    let wrong_destination = create_transport_receipt(
        &fixture.paths,
        "http-wrong-destination",
        payload.clone(),
        |claims, _| {
            claims.destination = DestinationScope {
                kind: DestinationKind::ExternalProvider,
                identifier: "not-this-mcp".to_owned(),
            };
        },
        true,
    );
    let wrong_purpose = create_transport_receipt(
        &fixture.paths,
        "http-wrong-purpose",
        payload.clone(),
        |claims, _| claims.purpose = "local.safe_pdf".to_owned(),
        true,
    );
    let wrong_key_version = create_transport_receipt(
        &fixture.paths,
        "http-wrong-key",
        payload.clone(),
        |claims, _| claims.key_version = 2,
        true,
    );
    let expired = create_transport_receipt(
        &fixture.paths,
        "http-expired",
        payload.clone(),
        |claims, now| {
            claims.issued_at_unix = now.saturating_sub(120);
            claims.expires_at_unix = Some(now.saturating_sub(60));
        },
        true,
    );
    let unpersisted = create_transport_receipt(
        &fixture.paths,
        "http-unpersisted",
        payload.clone(),
        |_, _| {},
        false,
    );

    let (address, http_task) =
        spawn_redacted_http(&fixture.paths, transport_receipt_gate(&fixture.paths)).await;
    let initialize = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":STABLE_VERSION,
                "capabilities":{},
                "clientInfo":{"name":"redacted-http-test","version":"1"}
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        None,
    )
    .await;
    assert_eq!(initialize.status, 200);
    let initialize: Value =
        serde_json::from_slice(&initialize.body).expect("redacted initialize JSON");
    assert!(initialize["result"]["instructions"]
        .as_str()
        .is_some_and(|text| text.contains("Page-material receipts cannot be reused")));

    let tools = post_json(
        address,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(tools.status, 200);
    let tools: Value = serde_json::from_slice(&tools.body).expect("redacted tool list");
    let listed = tools["result"]["tools"]
        .as_array()
        .expect("redacted tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("redacted tool name"))
        .collect::<Vec<_>>();
    assert_eq!(listed, REDACTED_CASE_TOOL_NAMES);
    let citation_schema = tools["result"]["tools"]
        .as_array()
        .expect("redacted tools")
        .iter()
        .find(|tool| tool["name"] == "citation_validate")
        .expect("citation tool");
    let citation_properties = citation_schema["inputSchema"]["properties"]
        .as_object()
        .expect("citation input properties");
    assert_eq!(
        citation_properties
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["approved_payload_json", "redaction_receipt"]
    );

    for (index, name) in DISABLED_SENSITIVE_TOOL_NAMES[1..].iter().enumerate() {
        let hidden = post_json(
            address,
            json!({
                "jsonrpc":"2.0","id":10 + index,"method":"tools/call",
                "params":{
                    "name":name,
                    "arguments":{
                        "schema_version":1,
                        "project_id":INPUT_CANARY_NAME,
                        "answer":SENSITIVE_RESULT_CANARY
                    }
                }
            }),
            Some(TEST_TOKEN),
            Some("https://client.example"),
            Some(STABLE_VERSION),
        )
        .await;
        assert_eq!(hidden.status, 200, "{name}");
        let hidden_wire = String::from_utf8(hidden.body).expect("hidden response UTF-8");
        assert!(!hidden_wire.contains(INPUT_CANARY_NAME), "{name}");
        assert!(!hidden_wire.contains(SENSITIVE_RESULT_CANARY), "{name}");
        let hidden: Value = serde_json::from_str(&hidden_wire).expect("hidden response JSON");
        assert_eq!(hidden["error"]["code"], -32601, "{name}: {hidden:#}");
    }

    let valid_call = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":30,"method":"tools/call",
            "params":{
                "name":"citation_validate",
                "arguments":{
                    "approved_payload_json":valid.payload,
                    "redaction_receipt":valid.token
                }
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(valid_call.status, 200);
    let valid_wire = String::from_utf8(valid_call.body).expect("valid response UTF-8");
    assert!(!valid_wire.contains(&valid.payload));
    assert!(!valid_wire.contains(&valid.token));
    let valid_response: Value = serde_json::from_str(&valid_wire).expect("valid call JSON");
    assert_eq!(
        valid_response["result"]["isError"], false,
        "{valid_response:#}"
    );
    assert_redacted_result_is_privacy_scanned(&valid_response["result"]);

    let mut mutated_token = valid.token.clone().into_bytes();
    let last = mutated_token.last_mut().expect("receipt token byte");
    *last = if *last == b'a' { b'b' } else { b'a' };
    let mutated_token = String::from_utf8(mutated_token).expect("mutated token UTF-8");
    let mutated_payload =
        valid
            .payload
            .replacen("\"includeExpired\":false", "\"includeExpired\":true", 1);
    assert_ne!(mutated_payload, valid.payload);
    let rejections = vec![
        ("payload-mutation", mutated_payload, valid.token.clone()),
        ("token-mutation", valid.payload.clone(), mutated_token),
        (
            "wrong-destination",
            wrong_destination.payload,
            wrong_destination.token,
        ),
        ("wrong-purpose", wrong_purpose.payload, wrong_purpose.token),
        (
            "wrong-key-version",
            wrong_key_version.payload,
            wrong_key_version.token,
        ),
        ("expired", expired.payload, expired.token),
        ("unpersisted", unpersisted.payload, unpersisted.token),
    ];
    for (index, (case, rejected_payload, rejected_token)) in rejections.into_iter().enumerate() {
        let response = post_json(
            address,
            json!({
                "jsonrpc":"2.0","id":40 + index,"method":"tools/call",
                "params":{
                    "name":"citation_validate",
                    "arguments":{
                        "approved_payload_json":rejected_payload,
                        "redaction_receipt":rejected_token
                    }
                }
            }),
            Some(TEST_TOKEN),
            Some("https://client.example"),
            Some(STABLE_VERSION),
        )
        .await;
        assert_eq!(response.status, 200, "{case}");
        let response_wire = String::from_utf8(response.body).expect("rejection response UTF-8");
        assert!(!response_wire.contains(&rejected_payload), "{case}");
        assert!(!response_wire.contains(&rejected_token), "{case}");
        assert!(!response_wire.contains(INPUT_CANARY_NAME), "{case}");
        let response: Value =
            serde_json::from_str(&response_wire).expect("rejection response JSON");
        assert_eq!(response["error"]["code"], -32602, "{case}: {response:#}");
        assert!(response.get("result").is_none(), "{case}: {response:#}");
    }

    revoke_transport_receipt(&fixture.paths, &valid);
    let revoked = post_json(
        address,
        json!({
            "jsonrpc":"2.0","id":60,"method":"tools/call",
            "params":{
                "name":"citation_validate",
                "arguments":{
                    "approved_payload_json":valid.payload,
                    "redaction_receipt":valid.token
                }
            }
        }),
        Some(TEST_TOKEN),
        Some("https://client.example"),
        Some(STABLE_VERSION),
    )
    .await;
    assert_eq!(revoked.status, 200);
    let revoked_wire = String::from_utf8(revoked.body).expect("revoked response UTF-8");
    assert!(!revoked_wire.contains(&valid.payload));
    assert!(!revoked_wire.contains(&valid.token));
    let revoked: Value = serde_json::from_str(&revoked_wire).expect("revoked response JSON");
    assert_eq!(revoked["error"]["code"], -32602);

    assert_no_case_writes(&fixture.paths);
    http_task.abort();
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redacted_case_stdio_accepts_exact_receipt_without_echoing_secrets() {
    let fixture = Fixture::new();
    let receipt = create_transport_receipt(
        &fixture.paths,
        "stdio-valid",
        transport_citation_payload(),
        |_, _| {},
        true,
    );
    let server = redacted_server(&fixture.paths, transport_receipt_gate(&fixture.paths));
    let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let transport = StableProtocolTransport::new(AsyncRwTransport::<RoleServer, _, _>::new_server(
        server_read,
        server_write,
    ));
    let server_task = tokio::spawn(async move {
        let running = server.serve(transport).await.expect("serve redacted stdio");
        running.waiting().await.expect("wait redacted stdio");
    });
    let (client_read, mut client_write) = tokio::io::split(client_io);
    let mut client_lines = TokioBufReader::new(client_read).lines();
    let mut response_lines = Vec::new();

    send_async_line(
        &mut client_write,
        json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":UNSUPPORTED_VERSION,
                "capabilities":{},
                "clientInfo":{"name":"redacted-stdio-test","version":"1"}
            }
        }),
    )
    .await;
    let (line, initialize) = receive_async_json(&mut client_lines).await;
    response_lines.push(line);
    assert_eq!(initialize["result"]["protocolVersion"], STABLE_VERSION);
    send_async_line(
        &mut client_write,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;

    send_async_line(
        &mut client_write,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .await;
    let (line, tools) = receive_async_json(&mut client_lines).await;
    response_lines.push(line);
    let listed = tools["result"]["tools"]
        .as_array()
        .expect("stdio redacted tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("stdio tool name"))
        .collect::<Vec<_>>();
    assert_eq!(listed, REDACTED_CASE_TOOL_NAMES);

    send_async_line(
        &mut client_write,
        json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{
                "name":"citation_validate",
                "arguments":{
                    "approved_payload_json":receipt.payload,
                    "redaction_receipt":receipt.token
                }
            }
        }),
    )
    .await;
    let (line, valid) = receive_async_json(&mut client_lines).await;
    response_lines.push(line);
    assert_eq!(valid["result"]["isError"], false, "{valid:#}");
    assert_redacted_result_is_privacy_scanned(&valid["result"]);

    let mut mutated_token = receipt.token.clone().into_bytes();
    let last = mutated_token.last_mut().expect("stdio token byte");
    *last = if *last == b'a' { b'b' } else { b'a' };
    send_async_line(
        &mut client_write,
        json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{
                "name":"citation_validate",
                "arguments":{
                    "approved_payload_json":receipt.payload,
                    "redaction_receipt":String::from_utf8(mutated_token)
                        .expect("stdio mutated token")
                }
            }
        }),
    )
    .await;
    let (line, rejected) = receive_async_json(&mut client_lines).await;
    response_lines.push(line);
    assert_eq!(rejected["error"]["code"], -32602, "{rejected:#}");

    send_async_line(
        &mut client_write,
        json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{
                "name":"case_get_state",
                "arguments":{"schema_version":1,"project_id":INPUT_CANARY_NAME}
            }
        }),
    )
    .await;
    let (line, hidden) = receive_async_json(&mut client_lines).await;
    response_lines.push(line);
    assert_eq!(hidden["error"]["code"], -32601, "{hidden:#}");

    for line in response_lines {
        assert!(
            !line.contains(&receipt.payload),
            "stdio echoed approved payload"
        );
        assert!(!line.contains(&receipt.token), "stdio echoed receipt token");
        assert!(
            !line.contains(INPUT_CANARY_NAME),
            "stdio echoed hidden input"
        );
        assert!(
            !line.contains(SENSITIVE_RESULT_CANARY),
            "stdio leaked result canary"
        );
    }
    assert_no_case_writes(&fixture.paths);
    client_write
        .shutdown()
        .await
        .expect("shutdown redacted stdio client");
    drop(client_write);
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("redacted stdio shutdown timeout")
        .expect("redacted stdio task");
}

fn assert_public_result_shape(schema: &Map<String, Value>, value: &Value) {
    let object = value.as_object().expect("public result object");
    let properties = schema["properties"]
        .as_object()
        .expect("public result properties");
    let required = schema["required"].as_array().expect("public required");
    for field in required.iter().filter_map(Value::as_str) {
        assert!(
            object.contains_key(field),
            "missing required output field {field}"
        );
    }
    for field in object.keys() {
        assert!(
            properties.contains_key(field),
            "undeclared output field {field}"
        );
    }
    assert_schema_matches(&Value::Object(schema.clone()), value, "$output");
}

fn assert_text_fallback_matches_structured(result: &Value) {
    let text = result["content"][0]["text"]
        .as_str()
        .expect("user-readable text content");
    assert!(!text.trim().is_empty());
    assert!(text.len() <= 256 * 1024);
    assert!(
        serde_json::from_str::<Value>(text).is_err(),
        "readable content must not duplicate the structured JSON envelope"
    );
    for forbidden in [
        "schema_version",
        "request_id",
        "structuredContent",
        "server_version",
        "protocol_version",
    ] {
        assert!(
            !text.contains(forbidden),
            "readable content leaked {forbidden}: {text}"
        );
    }
    let structured = &result["structuredContent"];
    assert_public_structured_content(structured, "tool result");
}

fn assert_public_structured_content(value: &Value, context: &str) {
    fn walk(value: &Value, context: &str) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let lower = key.to_ascii_lowercase();
                    for forbidden in [
                        "id", "hash", "revision", "schema", "protocol", "request", "score",
                        "snippet", "path", "endpoint", "raw", "cursor", "meta",
                    ] {
                        assert!(
                            !lower.contains(forbidden),
                            "{context} exposed machine key {key}: {object:#?}"
                        );
                    }
                    walk(value, context);
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, context);
                }
            }
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                for forbidden in [
                    "schema_version",
                    "request_id",
                    "article_id",
                    "document_id",
                    "project_id",
                    "source_ref",
                    "proposal_hash",
                    "generation_hash",
                    "structuredcontent",
                    "snippet",
                    "endpoint",
                    "base_url",
                    "raw_output",
                    "appdata",
                    "file://",
                    "http://",
                    "https://",
                    "urn:",
                    "[src:",
                ] {
                    assert!(
                        !lower.contains(forbidden),
                        "{context} exposed internal text {text}"
                    );
                }
                assert!(!text.contains(":\\"), "{context} exposed a local path");
                let has_hash = text
                    .split(|character: char| !character.is_ascii_hexdigit())
                    .any(|candidate| candidate.len() >= 64);
                assert!(!has_hash, "{context} exposed a hash");
            }
            _ => {}
        }
    }

    let object = value.as_object().expect("structured public object");
    assert_eq!(
        object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["内容", "提示", "结果", "说明"].into_iter().collect(),
        "{context}"
    );
    assert!(matches!(value["结果"].as_str(), Some("已完成" | "未完成")));
    assert!(value["说明"].as_str().is_some_and(|text| !text.is_empty()));
    assert!(value["提示"].is_array());
    walk(value, context);
}

fn assert_schema_matches(schema: &Value, value: &Value, path: &str) {
    if let Some(expected) = schema.get("const") {
        assert_eq!(value, expected, "const mismatch at {path}");
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        assert!(options.contains(value), "enum mismatch at {path}: {value}");
    }
    if let Some(types) = schema.get("type") {
        let matches_type = |name: &str| match name {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true,
        };
        let valid = match types {
            Value::String(name) => matches_type(name),
            Value::Array(names) => names.iter().filter_map(Value::as_str).any(matches_type),
            _ => false,
        };
        assert!(valid, "type mismatch at {path}: {value}");
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                assert!(object.contains_key(field), "missing {path}.{field}");
            }
        }
        if schema.get("additionalProperties") == Some(&json!(false)) {
            let properties = properties.expect("closed object declares properties");
            for field in object.keys() {
                assert!(
                    properties.contains_key(field),
                    "undeclared field {path}.{field}"
                );
            }
        }
        if let Some(properties) = properties {
            for (field, child) in object {
                if let Some(child_schema) = properties.get(field) {
                    assert_schema_matches(child_schema, child, &format!("{path}.{field}"));
                }
            }
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        for (index, item) in values.iter().enumerate() {
            assert_schema_matches(items, item, &format!("{path}[{index}]"));
        }
    }
}
