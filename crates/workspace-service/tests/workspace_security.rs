use privacy_text::DictionaryEntry;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use workspace_service::{
    now, CloudConsent, ImportFile, ProviderConfig, ReviewRequest, SaveProviderRequest, Workspace,
};

const LOCAL_TEXT: &str = "请在联系时使用号码 13800138000。";
const NER_TEXT: &str = "申请人：王伟，请求依法裁判。";

fn case_fixture(fixture: &Fixture) {
    let db = Connection::open(fixture.temp.path().join("judicial_cases.sqlite")).unwrap();
    db.execute_batch(include_str!("../../../data/schema/judicial_cases.sql"))
        .unwrap();
    db.execute_batch("INSERT INTO database_metadata VALUES ('schema_version','1'), ('dataset_version','synthetic-case-test');").unwrap();
    let text = "合成公开案例：根据实际用工事实认定劳动关系。";
    db.execute(
        "INSERT INTO judicial_cases (case_id,case_type,guiding_number,title,keywords_json,status,source_url,search_text,key_points_json,basic_facts,judgment_result,reasoning,related_laws_json,full_text,fetched_at,content_sha256) VALUES ('spc-guiding-1','guiding',1,'合成劳动关系案例','[\"劳动关系\"]','published','https://www.court.gov.cn/shenpan/xiangqing/1.html',?1,'[\"根据用工事实认定劳动关系\"]','合成事实','合成结果','合成理由','[]',?1,'2026-09-09T00:00:00Z',?2)",
        rusqlite::params![text, workspace_service::hash(text.as_bytes())],
    ).unwrap();
}

#[tokio::test]
async fn case_understanding_sends_only_explicit_input_and_returns_local_cases() {
    let fixture = Fixture::new();
    case_fixture(&fixture);
    let group = fixture.create_group();
    submit_single(
        &fixture.workspace,
        &group,
        "case-context-isolation",
        "PRIVATE_CASE_CANARY 13800138000",
    );
    let mock = CloudMock::start(r#"{"query":"劳动关系","issues":["是否建立劳动关系"]}"#);
    let provider_id = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
    let request = || workspace_service::CaseUnderstandingRequest {
        query: "外卖骑手和平台是不是劳动关系".into(),
        provider_id: provider_id.clone(),
        model: "workspace-test-model".into(),
        case_type: Some("guiding".into()),
        include_withdrawn: false,
    };
    let result = fixture.workspace.understand_cases(request()).await.unwrap();
    assert_eq!(result["interpreted_query"], "劳动关系");
    assert_eq!(result["results"]["cases"][0]["caseId"], "spc-guiding-1");
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    let sent = String::from_utf8_lossy(&requests[0]);
    assert!(!sent.contains("PRIVATE_CASE_CANARY"));
    assert!(!sent.contains("13800138000"));
    assert!(sent.contains("外卖骑手和平台是不是劳动关系"));
    let mut mismatched = request();
    mismatched.model = "unapproved-model".into();
    assert_eq!(
        fixture
            .workspace
            .understand_cases(mismatched)
            .await
            .unwrap_err()
            .code,
        "provider_changed"
    );
    assert_eq!(mock.request_count(), 1);
}

#[tokio::test]
async fn case_understanding_rejects_generated_cases_and_credential_echo() {
    for (reply, expected) in [
        (
            r#"{"query":"劳动关系","issues":[],"cases":["invented"]}"#,
            "case_understanding_invalid",
        ),
        (
            r#"{"query":"temporary-test-key-not-a-user-secret","issues":[]}"#,
            "provider_secret_echo_blocked",
        ),
    ] {
        let fixture = Fixture::new();
        case_fixture(&fixture);
        let mock = CloudMock::start(reply);
        let provider_id = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
        let error = fixture
            .workspace
            .understand_cases(workspace_service::CaseUnderstandingRequest {
                query: "劳动关系".into(),
                provider_id,
                model: "workspace-test-model".into(),
                case_type: None,
                include_withdrawn: false,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, expected);
        assert_eq!(mock.request_count(), 1);
    }
}

struct Fixture {
    root: PathBuf,
    workspace: Arc<Workspace>,
    credential_ids: Mutex<Vec<String>>,
    // Drop the database/lock before asking Windows to remove the test directory.
    temp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary test directory exists");
        let root = temp.path().join("workspace");
        let workspace = Workspace::open(root.clone(), temp.path().join("missing-legal.sqlite"))
            .expect("workspace opens without a legal database");
        Self {
            temp,
            root,
            workspace,
            credential_ids: Mutex::new(Vec::new()),
        }
    }

    fn create_group(&self) -> String {
        field(
            &self
                .workspace
                .create_group("synthetic test group")
                .expect("group creates"),
            "id",
        )
    }

    fn save_mock_provider(&self, base_url: String, model: &str) -> String {
        // Credential Manager targets can be shared across independent test processes on Windows.
        // A unique synthetic provider ID prevents one fixture's cleanup from removing another
        // fixture's test-only credential when the integration suite runs in parallel.
        let provider_id = workspace_service::id("provider_workspace_test");
        self.workspace
            .save_provider(SaveProviderRequest {
                id: Some(provider_id.clone()),
                name: "Synthetic local provider".to_owned(),
                base_url,
                model: model.to_owned(),
                api_key: Some("temporary-test-key-not-a-user-secret".to_owned()),
                allow_private_network: true,
            })
            .expect("temporary provider credential saves");
        self.credential_ids
            .lock()
            .expect("credential list lock")
            .push(provider_id.clone());
        provider_id
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let ids = self
            .credential_ids
            .get_mut()
            .expect("credential list is not shared during fixture cleanup");
        for id in ids.drain(..) {
            let _ = self.workspace.save_provider(SaveProviderRequest {
                id: Some(id),
                name: "credential cleanup".to_owned(),
                base_url: "https://cleanup.invalid/v1".to_owned(),
                model: "cleanup-model".to_owned(),
                api_key: Some(String::new()),
                allow_private_network: false,
            });
        }
        // Keep the TempDir alive through credential deletion and workspace-drop.
        let _ = self.temp.path();
    }
}

struct CloudMock {
    base_url: String,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CloudMock {
    fn start(completion_content: &str) -> Self {
        let response = json!({"model":"workspace-test-model","choices":[{"message":{"content":completion_content}}]}).to_string();
        Self::serve(response, "application/json")
    }
    fn stream(parts: &[&str], done: bool) -> Self {
        let mut response = String::new();
        for content in parts {
            response.push_str(&format!(
                "data: {}\n\n",
                json!({"choices":[{"delta":{"content":content}}]})
            ));
        }
        if done {
            response.push_str("data: [DONE]\n\n");
        }
        Self::serve(response, "text/event-stream")
    }
    fn serve(response: String, content_type: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock provider binds");
        listener
            .set_nonblocking(true)
            .expect("mock provider becomes nonblocking");
        let base_url = format!(
            "http://{}/v1",
            listener.local_addr().expect("mock provider has address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let collector = Arc::clone(&requests);
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::spawn(move || loop {
            match shutdown_receiver.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Some(request) = read_http_request(&mut stream) {
                        collector.lock().expect("mock request lock").push(request);
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            response.len()
                        );
                        let _ = stream
                            .write_all(header.as_bytes())
                            .and_then(|_| stream.write_all(response.as_bytes()))
                            .and_then(|_| stream.flush())
                            .and_then(|_| stream.shutdown(Shutdown::Write));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        });
        Self {
            base_url,
            requests,
            shutdown,
            thread: Some(thread),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("mock request lock").len()
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("mock request lock").clone()
    }
}

impl Drop for CloudMock {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    // Windows accepted sockets inherit the listener's nonblocking mode.
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    let header_end = loop {
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        request.extend_from_slice(&buffer[..count]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        if request.len() > 128 * 1024 {
            return None;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end]).ok()?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })?
        .trim()
        .parse::<usize>()
        .ok()?;
    while request.len() < header_end.saturating_add(content_length) {
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        request.extend_from_slice(&buffer[..count]);
    }
    Some(request)
}

fn field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing non-sensitive field {key}"))
        .to_owned()
}

fn first_material(value: &Value) -> Value {
    value
        .get("materials")
        .and_then(Value::as_array)
        .and_then(|materials| materials.first())
        .cloned()
        .expect("task includes one material")
}

fn submit_single(workspace: &Workspace, group_id: &str, request_id: &str, text: &str) -> Value {
    workspace
        .submit(
            group_id,
            request_id,
            vec![ImportFile {
                name: "synthetic.txt".to_owned(),
                bytes: text.as_bytes().to_vec(),
                encoding: Some("utf-8".to_owned()),
            }],
            None,
        )
        .expect("synthetic import submits")
}

async fn wait_for_status(workspace: &Workspace, task_id: &str, expected: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let value = workspace
            .task_status(task_id)
            .expect("task remains readable");
        if value.get("status").and_then(Value::as_str) == Some(expected) {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("task did not reach expected state: {value:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn stop_worker(worker: tokio::task::JoinHandle<()>) {
    worker.abort();
    let _ = worker.await;
}

fn seal_for_test(kind: &str, id: &str, bytes: &[u8]) -> Vec<u8> {
    let prefix = format!("{kind}/{id}/0/1\0");
    let mut protected_input = prefix.into_bytes();
    protected_input.extend_from_slice(bytes);
    let protected = privacy::protect_local(&protected_input).expect("test row protects locally");
    let mut output = b"LAWEB1".to_vec();
    output.extend_from_slice(&1_u32.to_le_bytes());
    output.extend_from_slice(&(protected.len() as u32).to_le_bytes());
    output.extend_from_slice(&protected);
    output
}

fn replace_expired_consent(
    root: &Path,
    task_id: &str,
    material: &workspace_service::Material,
    config: &ProviderConfig,
) {
    let consent = CloudConsent {
        id: "consent_synthetic_expired".to_owned(),
        provider_id: config.id.clone(),
        model: config.model.clone(),
        profile_hash: privacy::sha256_hex(
            &serde_json::to_vec(config).expect("provider config serializes"),
        ),
        source_hashes: vec![(
            material.id.clone(),
            material.revision,
            material.source_sha256.clone(),
        )],
        expires_at: now().saturating_sub(1),
        used_materials: Vec::new(),
    };
    let body = seal_for_test(
        "consent",
        task_id,
        &serde_json::to_vec(&consent).expect("expired consent serializes"),
    );
    let connection = Connection::open(root.join("workspace.sqlite")).expect("test sqlite opens");
    connection
        .execute(
            "INSERT INTO objects(kind,id,body) VALUES('consent',?1,?2) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",
            rusqlite::params![task_id, body],
        )
        .expect("expired consent writes as an encrypted test record");
}

#[tokio::test]
async fn automatic_txt_reaches_ready_mcp_read_and_revoke() {
    let fixture = Fixture::new();
    let group_id = fixture.create_group();
    let client = fixture
        .workspace
        .create_client("synthetic mcp", &group_id)
        .expect("mcp client creates");
    let client_id = field(&client["client"], "id");
    let token = field(&client, "token");
    let inbox_file = fixture.root.join("inbox").join(client_id).join("note.txt");
    fs::write(&inbox_file, LOCAL_TEXT.as_bytes()).expect("synthetic inbox file writes");

    let submitted = fixture
        .workspace
        .mcp_submit(
            &token,
            "request_automatic_0001",
            vec!["note.txt".to_owned()],
        )
        .expect("mcp submit accepts configured inbox file");
    let task_id = field(&submitted, "task_id");
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task_id, "ready").await;
    let material = first_material(&ready);
    let material_id = field(&material, "id");
    let result_id = field(&material, "result_id");

    let mcp_status = fixture
        .workspace
        .mcp_status(&token, &task_id)
        .expect("mcp sees own task status");
    assert_eq!(mcp_status["status"], "ready");
    let read = fixture
        .workspace
        .mcp_read(&token, &result_id, None)
        .expect("mcp reads ready result");
    let text = read["text"].as_str().expect("redacted text is present");
    assert!(!text.contains("13800138000"));
    assert!(read.get("original").is_none());
    assert!(read.get("path").is_none());

    fixture
        .workspace
        .revoke_material(&material_id)
        .expect("material revokes");
    let error = fixture
        .workspace
        .mcp_read(&token, &result_id, None)
        .expect_err("revoked result is not readable through mcp");
    assert_eq!(error.code, "result_revoked");
    stop_worker(worker).await;
}

#[tokio::test]
async fn cloud_is_never_called_without_current_consent() {
    let expected_ner = privacy_text::analyze(NER_TEXT, "synthetic-ner", &[], &[], &[])
        .expect("synthetic text analyzes");
    assert!(
        expected_ner.needs_review,
        "fixture requires cloud corroboration"
    );

    let fixture = Fixture::new();
    let mock = CloudMock::start(r#"{"findings":[{"text":"王伟","kind":"person_name"}]}"#);
    let group_id = fixture.create_group();
    let provider_id = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
    let config = ProviderConfig {
        id: provider_id.clone(),
        name: "Synthetic local provider".to_owned(),
        base_url: mock.base_url.clone(),
        model: "workspace-test-model".to_owned(),
        allow_private_network: true,
        revision: 1,
    };

    let wrong = submit_single(
        &fixture.workspace,
        &group_id,
        "request_wrong_consent_01",
        NER_TEXT,
    );
    let wrong_task = field(&wrong, "id");
    let wrong_consent = fixture
        .workspace
        .consent(
            &wrong_task,
            &provider_id,
            "wrong-model",
            "redaction_assistance",
        )
        .expect_err("model mismatch does not create cloud consent");
    assert_eq!(wrong_consent.code, "provider_changed");

    let revoked = submit_single(
        &fixture.workspace,
        &group_id,
        "request_revoked_consent1",
        NER_TEXT,
    );
    let revoked_task = field(&revoked, "id");
    fixture
        .workspace
        .consent(
            &revoked_task,
            &provider_id,
            "workspace-test-model",
            "redaction_assistance",
        )
        .expect("current consent records");
    fixture
        .workspace
        .revoke_consent(&revoked_task)
        .expect("consent revokes before dispatch");

    let expired = submit_single(
        &fixture.workspace,
        &group_id,
        "request_expired_consent1",
        NER_TEXT,
    );
    let expired_task = field(&expired, "id");
    fixture
        .workspace
        .consent(
            &expired_task,
            &provider_id,
            "workspace-test-model",
            "redaction_assistance",
        )
        .expect("consent records before expiry fixture");
    let expired_material_id = field(&first_material(&expired), "id");
    replace_expired_consent(
        &fixture.root,
        &expired_task,
        &fixture
            .workspace
            .material(&expired_material_id)
            .expect("expired material reads"),
        &config,
    );

    let worker = fixture.workspace.start_worker();
    wait_for_status(&fixture.workspace, &wrong_task, "awaiting_consent").await;
    wait_for_status(&fixture.workspace, &revoked_task, "awaiting_consent").await;
    wait_for_status(&fixture.workspace, &expired_task, "awaiting_consent").await;
    stop_worker(worker).await;
    assert_eq!(
        mock.request_count(),
        0,
        "invalid cloud grants make no request"
    );

    let changed = submit_single(
        &fixture.workspace,
        &group_id,
        "request_profile_changed1",
        NER_TEXT,
    );
    let changed_task = field(&changed, "id");
    fixture
        .workspace
        .consent(
            &changed_task,
            &provider_id,
            "workspace-test-model",
            "redaction_assistance",
        )
        .expect("consent records before profile change");
    fixture
        .workspace
        .save_provider(SaveProviderRequest {
            id: Some(provider_id),
            name: "Synthetic local provider changed".to_owned(),
            base_url: mock.base_url.clone(),
            model: "workspace-test-model-v2".to_owned(),
            api_key: None,
            allow_private_network: true,
        })
        .expect("provider change persists");
    let worker = fixture.workspace.start_worker();
    wait_for_status(&fixture.workspace, &changed_task, "awaiting_consent").await;
    stop_worker(worker).await;
    assert_eq!(mock.request_count(), 0, "profile drift makes no request");
}

#[tokio::test]
async fn matching_local_ner_and_cloud_candidate_are_automatically_resolved() {
    let local_only = privacy_text::analyze(NER_TEXT, "synthetic-ner", &[], &[], &[])
        .expect("synthetic local ner analyzes");
    assert!(
        local_only.needs_review,
        "fixture exercises uncorroborated local ner"
    );
    let fixture = Fixture::new();
    let mock = CloudMock::start(r#"{"findings":[{"text":"王伟","kind":"person_name"}]}"#);
    let group_id = fixture.create_group();
    let provider_id = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
    let submitted = submit_single(
        &fixture.workspace,
        &group_id,
        "request_cloud_corroborated",
        NER_TEXT,
    );
    let task_id = field(&submitted, "id");
    fixture
        .workspace
        .consent(
            &task_id,
            &provider_id,
            "workspace-test-model",
            "redaction_assistance",
        )
        .expect("current explicit consent records");

    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task_id, "ready").await;
    stop_worker(worker).await;
    let material = first_material(&ready);
    let result_id = field(&material, "result_id");
    let result = fixture
        .workspace
        .read_result(&result_id)
        .expect("cloud-corroborated result is readable");
    assert!(!result.text.contains("王伟"));
    let requests = mock.requests();
    assert_eq!(requests.len(), 1, "one authorized cloud request is made");
    assert!(
        requests[0]
            .windows(NER_TEXT.len())
            .any(|window| window == NER_TEXT.as_bytes()),
        "the authorized source text reaches only the explicit redaction scope"
    );
}

#[tokio::test]
async fn dictionary_change_revokes_old_result_and_review_rejects_stale_revision() {
    let fixture = Fixture::new();
    let group_id = fixture.create_group();
    let submitted = submit_single(
        &fixture.workspace,
        &group_id,
        "request_dictionary_change",
        LOCAL_TEXT,
    );
    let task_id = field(&submitted, "id");
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task_id, "ready").await;
    let material = first_material(&ready);
    let material_id = field(&material, "id");
    let old_revision = material["revision"].as_u64().expect("revision is present");
    let old_result_id = field(&material, "result_id");

    fixture
        .workspace
        .set_dictionary(
            &group_id,
            vec![DictionaryEntry {
                text: "合成机构".to_owned(),
                kind: "organization".to_owned(),
                alias: Some("[ORG_SYNTHETIC]".to_owned()),
            }],
        )
        .expect("dictionary revision updates");
    let old_result = match fixture.workspace.read_result(&old_result_id) {
        Ok(_) => panic!("dictionary change must revoke prior output"),
        Err(error) => error,
    };
    assert_eq!(old_result.code, "result_revoked");
    let stale_review = fixture
        .workspace
        .review(
            &material_id,
            ReviewRequest {
                revision: old_revision,
                dictionary: Vec::new(),
                dismissed: Vec::new(),
            },
        )
        .expect_err("review must compare the material revision");
    assert_eq!(stale_review.code, "revision_conflict");
    stop_worker(worker).await;
}

#[tokio::test]
async fn source_idempotency_cancel_and_restart_have_determinate_results() {
    let temp = tempfile::tempdir().expect("temporary restart directory exists");
    let root = temp.path().join("workspace");
    let legal = temp.path().join("missing-legal.sqlite");
    let workspace = Workspace::open(root.clone(), legal.clone()).expect("workspace opens");
    let group_id = field(
        &workspace
            .create_group("restart test group")
            .expect("group creates"),
        "id",
    );
    let first = submit_single(&workspace, &group_id, "request_idempotent_001", LOCAL_TEXT);
    let task_id = field(&first, "id");
    let replay = submit_single(&workspace, &group_id, "request_idempotent_001", LOCAL_TEXT);
    assert_eq!(field(&replay, "id"), task_id);
    let conflict = workspace
        .submit(
            &group_id,
            "request_idempotent_001",
            vec![ImportFile {
                name: "synthetic.txt".to_owned(),
                bytes: b"different synthetic content".to_vec(),
                encoding: Some("utf-8".to_owned()),
            }],
            None,
        )
        .expect_err("same idempotency key cannot name a different source");
    assert_eq!(conflict.code, "idempotency_conflict");
    workspace
        .cancel_task(&task_id)
        .expect("queued task cancels");
    let worker = workspace.start_worker();
    wait_for_status(&workspace, &task_id, "cancelled").await;
    stop_worker(worker).await;

    let restart = submit_single(&workspace, &group_id, "request_restart_queue01", LOCAL_TEXT);
    let restart_task_id = field(&restart, "id");
    drop(workspace);
    let reopened = Workspace::open(root, legal).expect("queued workspace reopens after clean stop");
    let worker = reopened.start_worker();
    wait_for_status(&reopened, &restart_task_id, "ready").await;
    stop_worker(worker).await;
}

#[test]
fn original_source_and_private_workspace_records_are_encrypted_at_rest() {
    let fixture = Fixture::new();
    let group_id = fixture.create_group();
    let marker = "SYNTHETIC_AT_REST_MARKER_4eeadf5e";
    let source = format!("测试内容 {marker} 13800138000");
    submit_single(
        &fixture.workspace,
        &group_id,
        "request_encryption_atrest",
        &source,
    );
    let connection =
        Connection::open(fixture.root.join("workspace.sqlite")).expect("workspace sqlite opens");
    let mut statement = connection
        .prepare("SELECT body FROM objects ORDER BY kind,id")
        .expect("encrypted object query prepares");
    let mut rows = statement.query([]).expect("encrypted object query runs");
    let mut stored = Vec::new();
    while let Some(row) = rows.next().expect("encrypted object row reads") {
        let body: Vec<u8> = row.get(0).expect("encrypted object body reads");
        stored.extend_from_slice(&body);
    }
    assert!(
        !stored
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()),
        "private source marker must not appear in workspace files"
    );
    assert!(
        !stored
            .windows("13800138000".len())
            .any(|window| window == b"13800138000"),
        "private contact value must not appear in workspace files"
    );
}

#[tokio::test]
async fn invalid_cloud_candidates_remain_reviewable_and_never_publish() {
    for reply in [
        "not JSON",
        r#"{"findings":[{"text":"absent synthetic entity","kind":"person"}]}"#,
    ] {
        let fixture = Fixture::new();
        let group = fixture.create_group();
        let mock = CloudMock::start(reply);
        let provider = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
        let submitted = submit_single(&fixture.workspace, &group, "invalid_cloud", NER_TEXT);
        let task = field(&submitted, "id");
        fixture
            .workspace
            .consent(
                &task,
                &provider,
                "workspace-test-model",
                "redaction_assistance",
            )
            .expect("grant synthetic source");
        let worker = fixture.workspace.start_worker();
        let status = wait_for_status(&fixture.workspace, &task, "needs_review").await;
        let material = fixture
            .workspace
            .material(&field(&first_material(&status), "id"))
            .expect("reviewable material");
        assert_eq!(material.original_text, NER_TEXT);
        assert!(material.analysis.is_some());
        assert!(material.result_id.is_none());
        assert_eq!(mock.request_count(), 1);
        stop_worker(worker).await;
    }
}

#[tokio::test]
async fn replacement_invalidates_consent_and_partial_batch_exports_only_ready_files() {
    let fixture = Fixture::new();
    let group = fixture.create_group();
    let mock = CloudMock::start(r#"{"findings":[]}"#);
    let provider = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
    let submitted = submit_single(
        &fixture.workspace,
        &group,
        "replace_before_dispatch",
        NER_TEXT,
    );
    let task = field(&submitted, "id");
    let mid = field(&first_material(&submitted), "id");
    fixture
        .workspace
        .consent(
            &task,
            &provider,
            "workspace-test-model",
            "redaction_assistance",
        )
        .expect("grant synthetic source");
    fixture
        .workspace
        .replace_material(
            &mid,
            1,
            ImportFile {
                name: "replacement.txt".into(),
                bytes: LOCAL_TEXT.as_bytes().into(),
                encoding: None,
            },
        )
        .expect("replace source");
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task, "ready").await;
    assert_eq!(mock.request_count(), 0);
    let rid = field(&first_material(&ready), "result_id");
    fixture
        .workspace
        .replace_material(
            &mid,
            2,
            ImportFile {
                name: "replacement.txt".into(),
                bytes: NER_TEXT.as_bytes().into(),
                encoding: None,
            },
        )
        .expect("replace ready source");
    assert!(fixture.workspace.read_result(&rid).is_err());
    wait_for_status(&fixture.workspace, &task, "awaiting_consent").await;
    assert_eq!(mock.request_count(), 0);
    let batch = fixture
        .workspace
        .submit(
            &group,
            "partial_batch",
            vec![
                ImportFile {
                    name: "good.txt".into(),
                    bytes: LOCAL_TEXT.as_bytes().into(),
                    encoding: None,
                },
                ImportFile {
                    name: "broken.docx".into(),
                    bytes: b"bad zip".to_vec(),
                    encoding: None,
                },
            ],
            None,
        )
        .expect("partial batch");
    let partial = wait_for_status(&fixture.workspace, &field(&batch, "id"), "partial").await;
    let mids = partial["materials"]
        .as_array()
        .expect("materials")
        .iter()
        .map(|m| field(m, "id"))
        .collect::<Vec<_>>();
    let bytes = fixture
        .workspace
        .export_batch(&mids, "docx")
        .expect("partial export");
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("export archive");
    assert_eq!(zip.len(), 2);
    let mut report = String::new();
    zip.by_name("report.json")
        .expect("report")
        .read_to_string(&mut report)
        .expect("read report");
    let report: Vec<Value> = serde_json::from_str(&report).expect("parse report");
    assert_eq!(
        report.iter().filter(|r| r["status"] == "exported").count(),
        1
    );
    assert_eq!(report.iter().filter(|r| r["status"] == "failed").count(), 1);
    stop_worker(worker).await;
}

async fn chat_events(
    workspace: &Arc<Workspace>,
    provider: &str,
    conversation: &str,
    results: Vec<String>,
) -> Vec<Value> {
    let mut rx = workspace
        .start_chat(workspace_service::ChatRequest {
            conversation_id: conversation.into(),
            provider_id: provider.into(),
            message: "summarize synthetic context".into(),
            result_ids: results,
            article_ids: vec![],
        })
        .expect("start synthetic chat");
    let mut events = Vec::new();
    while let Some(event) = tokio::time::timeout(Duration::from_secs(8), rx.recv())
        .await
        .expect("chat timeout")
    {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn streaming_chat_uses_redacted_context_and_blocks_revoked_history() {
    let fixture = Fixture::new();
    let group = fixture.create_group();
    let batch = submit_single(&fixture.workspace, &group, "chat_context", LOCAL_TEXT);
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &field(&batch, "id"), "ready").await;
    let material = first_material(&ready);
    let rid = field(&material, "result_id");
    let mock = CloudMock::stream(&["合成", "回答"], true);
    let provider = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
    let conversation = field(
        &fixture
            .workspace
            .create_conversation("Synthetic chat")
            .expect("conversation"),
        "id",
    );
    let events = chat_events(&fixture.workspace, &provider, &conversation, vec![rid]).await;
    assert!(events.iter().any(|e| e["type"] == "done"));
    assert_eq!(
        fixture
            .workspace
            .conversation(&conversation)
            .expect("history")
            .messages
            .len(),
        2
    );
    let sent = mock.requests();
    assert_eq!(sent.len(), 1);
    assert!(!sent[0].windows(11).any(|w| w == b"13800138000"));
    fixture
        .workspace
        .revoke_material(&field(&material, "id"))
        .expect("revoke selected result");
    let events = chat_events(&fixture.workspace, &provider, &conversation, vec![]).await;
    assert!(events.iter().any(|e| e["type"] == "error"));
    assert_eq!(mock.request_count(), 1);
    stop_worker(worker).await;
}

#[tokio::test]
async fn streaming_chat_rejects_truncation_and_split_credential_echo() {
    for (parts, done, code) in [
        (
            vec!["partial answer"],
            false,
            "provider_response_incomplete",
        ),
        (
            vec!["temporary-test-", "key-not-a-user-secret"],
            true,
            "provider_secret_echo_blocked",
        ),
    ] {
        let fixture = Fixture::new();
        let mock = CloudMock::stream(&parts, done);
        let provider = fixture.save_mock_provider(mock.base_url.clone(), "workspace-test-model");
        let conversation = field(
            &fixture
                .workspace
                .create_conversation("Synthetic chat")
                .expect("conversation"),
            "id",
        );
        let events = chat_events(&fixture.workspace, &provider, &conversation, vec![]).await;
        assert!(events.iter().any(|e| e["code"] == code));
        assert!(!events.iter().any(|e| e["type"] == "done"));
        assert!(fixture
            .workspace
            .conversation(&conversation)
            .expect("history")
            .messages
            .is_empty());
        if done {
            assert!(!events.iter().any(|e| e["type"] == "delta"));
        }
    }
}

#[tokio::test]
async fn expired_result_is_hidden_from_mcp_status_and_retry_creates_a_new_version() {
    let fixture = Fixture::new();
    let group = fixture.create_group();
    let client = fixture
        .workspace
        .create_client("expiry test", &group)
        .expect("client");
    let token = field(&client, "token");
    let path = fixture
        .root
        .join("inbox")
        .join(field(&client["client"], "id"))
        .join("expiry.txt");
    fs::write(path, LOCAL_TEXT).expect("synthetic source");
    let submitted = fixture
        .workspace
        .mcp_submit(&token, "expiry_test", vec!["expiry.txt".into()])
        .expect("submit");
    let task = field(&submitted, "task_id");
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task, "ready").await;
    stop_worker(worker).await;
    let rid = field(&first_material(&ready), "result_id");
    let mut expired = fixture.workspace.read_result(&rid).expect("ready result");
    expired.expires_at = now() - 1;
    let body = seal_for_test(
        "result",
        &rid,
        &serde_json::to_vec(&expired).expect("serialize test result"),
    );
    let connection = Connection::open(fixture.root.join("workspace.sqlite")).expect("test DB");
    connection
        .execute(
            "UPDATE objects SET body=?1 WHERE kind='result' AND id=?2",
            rusqlite::params![body, rid],
        )
        .expect("simulate clock expiry");
    drop(connection);
    assert_eq!(
        fixture
            .workspace
            .mcp_read(&token, &rid, None)
            .expect_err("expired is unreadable")
            .code,
        "result_expired"
    );
    let status = fixture
        .workspace
        .mcp_status(&token, &task)
        .expect("safe status");
    assert!(first_material(&status)["result_id"].is_null());
    assert_eq!(status["status"], "needs_review");
    fixture
        .workspace
        .retry_task(&task)
        .expect("refresh expired result");
    let worker = fixture.workspace.start_worker();
    let ready = wait_for_status(&fixture.workspace, &task, "ready").await;
    assert_ne!(field(&first_material(&ready), "result_id"), rid);
    stop_worker(worker).await;
}

#[test]
fn inbox_rejects_traversal_links_and_revoked_clients() {
    let fixture = Fixture::new();
    let group = fixture.create_group();
    let client = fixture
        .workspace
        .create_client("inbox test", &group)
        .expect("client");
    let cid = field(&client["client"], "id");
    let token = field(&client, "token");
    let inbox = fixture.root.join("inbox").join(&cid);
    fs::write(inbox.join("safe.txt"), LOCAL_TEXT).expect("test source");
    for path in [
        "../safe.txt",
        "C:/safe.txt",
        "/safe.txt",
        "a/../../safe.txt",
        "safe.txt:stream",
        "a\\safe.txt",
    ] {
        assert!(fixture
            .workspace
            .mcp_submit(&token, "bad_path", vec![path.into()])
            .is_err());
    }
    #[cfg(windows)]
    {
        let outside = fixture.temp.path().join("outside");
        fs::create_dir(&outside).expect("outside test directory");
        fs::write(outside.join("outside.txt"), LOCAL_TEXT).expect("outside synthetic source");
        let junction = inbox.join("link");
        let status = std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("create test junction");
        assert!(status.success());
        assert!(fixture
            .workspace
            .mcp_submit(&token, "linked_path", vec!["link/outside.txt".into()])
            .is_err());
        fs::remove_dir(junction).expect("remove only test junction");
    }
    fixture.workspace.revoke_client(&cid).expect("revoke");
    assert!(fixture
        .workspace
        .mcp_submit(&token, "revoked_client", vec!["safe.txt".into()])
        .is_err());
}
