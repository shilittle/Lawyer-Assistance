use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use workspace_service::{
    ai_tools, AiCaseDateUpdate, AiDocumentEdit, AiMaterialReference, AiModelCapabilities,
    AiModelSelection, AiProviderRequest, AiRunRequest, ImportFile, SaveProviderRequest, Workspace,
};

struct Mock {
    url: String,
    stop: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}
impl Mock {
    fn new(response: fn(Value) -> Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let workers = Arc::new(Mutex::new(Vec::new()));
        let accepting_workers = workers.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        // The provider transport can establish and abandon a probe connection
                        // before it writes request headers. Serve each socket independently so
                        // that one such probe cannot block the listener for its read timeout.
                        let worker_stop = stopped.clone();
                        let worker_count = count.clone();
                        let worker_recorded = recorded.clone();
                        let worker = std::thread::spawn(move || {
                            serve_mock_connection(
                                socket,
                                response,
                                &worker_stop,
                                &worker_count,
                                &worker_recorded,
                            )
                        });
                        accepting_workers.lock().unwrap().push(worker);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            stop,
            calls,
            requests,
            thread: Some(thread),
            workers,
        }
    }
    fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
    }
}

fn serve_mock_connection(
    mut socket: TcpStream,
    response: fn(Value) -> Value,
    stopped: &AtomicBool,
    count: &AtomicUsize,
    recorded: &Mutex<Vec<Value>>,
) {
    const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
    // Do not make accept-loop throughput depend on this deadline. A real local POST may arrive
    // in several scheduler-separated reads, while a transport probe may never write at all.
    let _ = socket.set_nonblocking(true);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buffer = Vec::new();
    let mut chunk = [0; 8192];
    let mut header_end = None;
    let mut length = 0usize;
    while !stopped.load(Ordering::Relaxed) {
        let n = match socket.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => return,
        };
        if buffer
            .len()
            .checked_add(n)
            .is_none_or(|size| size > MAX_REQUEST_BYTES)
        {
            return;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if header_end.is_none() {
            if let Some(index) = buffer.windows(4).position(|value| value == b"\r\n\r\n") {
                header_end = Some(index + 4);
                let header = String::from_utf8_lossy(&buffer[..index]);
                length = header
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if header
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("expect: 100-continue"))
                {
                    let _ = socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
            }
        }
        if header_end.is_some_and(|index| buffer.len() >= index.saturating_add(length)) {
            break;
        }
    }

    // A cancelled request or a connection probe can close before any HTTP headers arrive. It is
    // not a model call and must not reach the responder.
    let Some(header_end) = header_end else {
        return;
    };
    let Some(request_end) = header_end.checked_add(length) else {
        return;
    };
    if buffer.len() < request_end {
        return;
    }
    let is_get = buffer.starts_with(b"GET ");
    let data = if is_get {
        Value::Null
    } else {
        let Ok(data) = serde_json::from_slice::<Value>(&buffer[header_end..request_end]) else {
            return;
        };
        data
    };
    count.fetch_add(1, Ordering::Relaxed);
    recorded.lock().unwrap().push(data.clone());
    let body = if is_get {
        json!({"data":[{"id":"mock-model"},{"id":"mock-vision"}]})
    } else {
        response(data)
    };
    let status = body["_status"].as_u64().unwrap_or(200);
    let extra = body["_truncated"].as_bool().unwrap_or(false) as usize;
    let body = body["_raw"]
        .as_str()
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_else(|| serde_json::to_vec(&body).unwrap());
    let header = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len() + extra
    );
    let _ = socket.write_all(header.as_bytes());
    let _ = socket.write_all(&body);
}
struct Fixture {
    workspace: Arc<Workspace>,
    provider: String,
    credential_target: String,
    legal_path: PathBuf,
    _temp: tempfile::TempDir,
}

static SYNTHETIC_CREDENTIAL_TARGETS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

fn synthetic_credential_target(root: &Path, provider: &str) -> String {
    format!(
        "LawyerAssistanceWeb/{}/provider/{provider}/account/web-v1",
        &workspace_service::hash(root.to_string_lossy().as_bytes())[..16]
    )
}

impl Fixture {
    fn new(mock: &Mock, trusted: bool) -> Self {
        Self::new_with_legal(mock, trusted, |_| {})
    }
    fn new_with_legal(mock: &Mock, trusted: bool, configure_legal: impl FnOnce(&Path)) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let legal = temp.path().join("legal.sqlite");
        configure_legal(&legal);
        let root = temp.path().join("workspace");
        let workspace = Workspace::open(root.clone(), legal.clone()).unwrap();
        let saved = workspace
            .save_ai_provider(AiProviderRequest {
                preset: "custom".into(),
                name: "mock".into(),
                base_url: mock.url.clone(),
                enabled_models: vec!["mock-model".into(), "mock-vision".into()],
                api_key: Some("synthetic-secret-only".into()),
                trust_raw: Some(trusted),
                allow_private_network: true,
                ..Default::default()
            })
            .unwrap();
        let provider = saved["id"].as_str().unwrap().to_owned();
        let credential_target = synthetic_credential_target(&root, &provider);
        assert!(
            SYNTHETIC_CREDENTIAL_TARGETS
                .get_or_init(|| Mutex::new(BTreeSet::new()))
                .lock()
                .unwrap()
                .insert(credential_target.clone()),
            "every AI workflow fixture must use a distinct synthetic credential target"
        );
        Self {
            workspace,
            provider,
            credential_target,
            legal_path: legal,
            _temp: temp,
        }
    }
}

fn legal_fixture(path: &Path) {
    let database = rusqlite::Connection::open(path).unwrap();
    database
        .execute_batch(include_str!("../../../data/schema/legal_core.sql"))
        .unwrap();
    database
        .execute_batch(include_str!(
            "../../../data/fixtures/legal_core_retrieval_fixture.sql"
        ))
        .unwrap();
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(
            SYNTHETIC_CREDENTIAL_TARGETS
                .get_or_init(|| Mutex::new(BTreeSet::new()))
                .lock()
                .unwrap()
                .contains(&self.credential_target),
            "fixture cleanup must retain its registered synthetic credential target"
        );
        let _ = self.workspace.save_provider(SaveProviderRequest {
            id: Some(self.provider.clone()),
            name: "cleanup".into(),
            base_url: "https://cleanup.invalid".into(),
            model: "cleanup".into(),
            api_key: Some(String::new()),
            allow_private_network: false,
        });
    }
}
fn completion(message: Value) -> Value {
    json!({"model":"mock-model","choices":[{"finish_reason":"stop","message":message}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}})
}
fn good_reply(body: Value) -> Value {
    if body.get("tools").is_none() {
        return completion(json!({"role":"assistant","content":"合成会话标题"}));
    }
    std::thread::sleep(Duration::from_millis(70));
    completion(
        json!({"role":"assistant","content":serde_json::to_string(&json!({"title":"合成回答","content":"## 材料整理\n\n**金额**为126800元，日期为2026年8月11日。","citations":[]})).unwrap()}),
    )
}
async fn wait_done(w: &Workspace, id: &str) -> Value {
    for _ in 0..200 {
        let r = w.ai_run(id).unwrap();
        if !["queued", "running"].contains(&r["status"].as_str().unwrap_or_default()) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("AI run timeout")
}

fn raw_material(fixture: &Fixture, request_id: &str) -> (String, u64) {
    let group = fixture.workspace.create_group("AI 原文回归").unwrap();
    let status = fixture
        .workspace
        .submit(
            group["id"].as_str().unwrap(),
            request_id,
            vec![ImportFile {
                name: "synthetic.txt".into(),
                bytes: b"SYNTHETIC ORIGINAL MATERIAL 13800138000".to_vec(),
                encoding: Some("utf-8".into()),
            }],
            None,
        )
        .unwrap();
    let material = &status["materials"][0];
    (
        material["id"].as_str().unwrap().into(),
        material["revision"].as_u64().unwrap(),
    )
}

fn original_run(fixture: &Fixture, material_id: &str, prompt: &str) -> Value {
    fixture
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: prompt.into(),
            provider_id: Some(fixture.provider.clone()),
            model: Some("mock-model".into()),
            materials: vec![AiMaterialReference {
                id: material_id.into(),
                source: "original".into(),
            }],
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn case_search_tool_exposes_an_optional_case_type_filter() {
    let tools = ai_tools();
    let function = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["function"]["name"] == "legal_search_cases")
        .unwrap();
    let parameters = &function["function"]["parameters"];
    assert_eq!(
        parameters["properties"]["case_type"]["enum"],
        json!(["guiding", "reference", "typical"])
    );
    assert!(parameters["required"]
        .as_array()
        .unwrap()
        .iter()
        .all(|field| field != "case_type"));
    assert!(function["function"]["description"]
        .as_str()
        .unwrap()
        .contains("典型案例合集"));
}

#[tokio::test]
async fn discovered_models_defaults_and_detached_chat_are_persisted() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, true);
    let models = f
        .workspace
        .discover_ai_models(AiProviderRequest {
            provider_id: Some(f.provider.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(models["models"].as_array().unwrap().len(), 2);
    assert!(f
        .workspace
        .ai_provider_is_trusted(&AiModelSelection {
            provider_id: f.provider.clone(),
            model: "mock-model".into()
        })
        .unwrap());
    let c = f.workspace.create_ai_conversation(None).unwrap();
    let cid = c["id"].as_str().unwrap();
    let prepared = f
        .workspace
        .prepare_ai_conversation_context(cid, 1, None, None)
        .unwrap();
    let r = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "整理这段合成描述".into(),
            conversation_id: Some(cid.into()),
            context_revision: Some(1),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let rid = r["id"].as_str().unwrap().to_owned();
    drop(r);
    let done = wait_done(&f.workspace, &rid).await;
    assert_eq!(done["status"], "completed");
    assert!(done["html"].as_str().unwrap().contains("<strong>"));
    for _ in 0..100 {
        if f.workspace.ai_conversation(cid).unwrap()["title"] != "新会话" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let c = f.workspace.ai_conversation(cid).unwrap();
    assert_eq!(c["messages"].as_array().unwrap().len(), 2);
    assert_eq!(c["title"], "合成会话标题");
    f.workspace.rename_ai_conversation(cid, "手动标题").unwrap();
    assert_eq!(
        f.workspace.ai_conversation(cid).unwrap()["title"],
        "手动标题"
    );
    assert!(mock.calls.load(Ordering::Relaxed) >= 3);
}

#[tokio::test]
async fn ai_system_prompt_requires_fact_status_and_open_conditions() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, true);
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "期限争议".into(),
            ..Default::default()
        })
        .unwrap();
    let completed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(completed["status"], "completed");
    let system = mock
        .requests()
        .into_iter()
        .find_map(|request| {
            request["messages"]
                .as_array()
                .and_then(|messages| messages.first())
                .and_then(|message| message["content"].as_str())
                .map(str::to_owned)
        })
        .expect("AI request system prompt");
    assert!(system.contains("用户陈述、当事人主张、已核验材料、法律推断和待核实事项"));
    assert!(system.contains("不得因未提供材料就推定法律要件已满足"));
    assert!(system.contains("期限起算的事实或触发条件不明时应列为待核实"));
}

#[tokio::test]
async fn unwritten_probe_connection_does_not_block_the_next_mock_request() {
    let mock = Mock::new(good_reply);
    let address = mock
        .url
        .strip_prefix("http://")
        .and_then(|url| url.strip_suffix("/v1"))
        .expect("mock loopback address");
    let probe = TcpStream::connect(address).expect("unwritten transport probe");
    // Give the accept loop time to hand the probe to its own bounded worker. The subsequent
    // provider request must not wait for this connection's read timeout.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let f = Fixture::new(&mock, true);
    let started_at = Instant::now();
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "probe isolation".into(),
            ..Default::default()
        })
        .unwrap();
    let completed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "an unwritten probe must not serialize the actual request"
    );
    drop(probe);
}

#[tokio::test]
async fn untrusted_provider_cannot_receive_original_attachment() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, false);
    let a = f
        .workspace
        .save_ai_attachment(
            "synthetic.txt".into(),
            b"SYNTHETIC PRIVATE MATERIAL".to_vec(),
        )
        .unwrap();
    let err = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "search".into(),
            prompt: "test".into(),
            attachment_ids: vec![a["id"].as_str().unwrap().into()],
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(err.code, "attachment_requires_trusted_provider");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn invented_citation_never_becomes_completed() {
    fn invented(_: Value) -> Value {
        completion(
            json!({"role":"assistant","content":"{\"title\":\"wrong\",\"content\":\"测试\",\"citations\":[{\"article_id\":\"invented\"}]}"}),
        )
    }
    let mock = Mock::new(invented);
    let f = Fixture::new(&mock, true);
    let r = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "search".into(),
            prompt: "test".into(),
            ..Default::default()
        })
        .unwrap();
    let r = wait_done(&f.workspace, r["id"].as_str().unwrap()).await;
    assert_eq!(r["status"], "failed");
    assert_eq!(r["error_code"], "citation_not_retrieved");
    assert!(r["citations"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn body_article_without_matching_retrieved_citation_enters_the_existing_repair_loop() {
    fn reply(body: Value) -> Value {
        let messages = body["messages"].as_array().expect("messages");
        let has_article = messages.iter().any(|message| message["role"] == "tool");
        let repaired = messages.iter().any(|message| {
            message["role"] == "user"
                && message["content"]
                    .as_str()
                    .is_some_and(|content| content.contains("unverified_law_article_in_answer"))
        });
        if !has_article {
            return json!({"model":"mock-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"read-577","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-civil-code-20210101-577\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}});
        }
        let content = if repaired {
            "材料编号504；依据《民法典》第577条，违约责任仍须结合待核实事实判断。"
        } else {
            "依据《民法典》第504条，违约责任当然成立。"
        };
        completion(
            json!({"role":"assistant","content":serde_json::to_string(&json!({
            "title":"法条核验",
            "content":content,
            "citations":[{"article_id":"cn-civil-code-20210101-577","reason":"合同责任"}]
        })).unwrap()}),
        )
    }

    let mock = Mock::new(reply);
    let f = Fixture::new_with_legal(&mock, true, legal_fixture);
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "合同责任分析".into(),
            ..Default::default()
        })
        .unwrap();
    let completed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert!(completed["content"].as_str().unwrap().contains("第577条"));
    assert_eq!(
        completed["citations"][0]["article_number"],
        "第五百七十七条"
    );
    assert!(mock.requests().iter().any(|request| {
        request["messages"].as_array().is_some_and(|messages| {
            messages.iter().any(|message| {
                message["content"]
                    .as_str()
                    .is_some_and(|content| content.contains("unverified_law_article_in_answer"))
            })
        })
    }));
}

fn legal_fixture_with_cross_law_reference_in_quote(path: &Path) {
    legal_fixture(path);
    let database = rusqlite::Connection::open(path).unwrap();
    database
        .execute(
            "UPDATE law_articles SET content=?1 WHERE id='cn-civil-code-20210101-577'",
            ["当事人一方不履行合同义务的，应承担相应责任。参见《中华人民共和国劳动合同法》第十条。"],
        )
        .unwrap();
}

#[tokio::test]
async fn citation_quote_cross_reference_is_not_treated_as_an_uncited_answer_proposition() {
    fn reply(body: Value) -> Value {
        let has_article = body["messages"]
            .as_array()
            .is_some_and(|messages| messages.iter().any(|message| message["role"] == "tool"));
        if !has_article {
            return json!({"model":"mock-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"read-577","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-civil-code-20210101-577\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}});
        }
        completion(
            json!({"role":"assistant","content":serde_json::to_string(&json!({
            "title":"引用交叉法条",
            "content":"依据《民法典》第577条分析，期限起算条件仍待核实。",
            "citations":[{
                "article_id":"cn-civil-code-20210101-577",
                "reason":"违约责任依据",
                "quote":"参见《中华人民共和国劳动合同法》第十条。"
            }]
        })).unwrap()}),
        )
    }

    let mock = Mock::new(reply);
    let f = Fixture::new_with_legal(&mock, true, legal_fixture_with_cross_law_reference_in_quote);
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "引用交叉法条".into(),
            ..Default::default()
        })
        .unwrap();
    let completed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(
        completed["citations"][0]["quote"],
        "参见《中华人民共和国劳动合同法》第十条。"
    );
    assert_eq!(
        completed["citation_verification"]["state"], "pending",
        "an omitted case date cannot be mechanically treated as time-verified"
    );
    assert!(completed["citation_verification"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "case_date_unknown"));
    assert_eq!(
        completed["citation_verification"]["sources"][0]["citation_match"],
        "matched"
    );
    assert_eq!(
        completed["citation_verification"]["sources"][0]["relevance"],
        "manual_review_required"
    );
}

fn legal_fixture_with_same_article_number(path: &Path) {
    legal_fixture(path);
    let database = rusqlite::Connection::open(path).unwrap();
    database
        .execute(
            "INSERT INTO law_articles (id, document_id, version_id, article_number, article_order, title, content, updated_on) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "cn-labor-contract-law-20130701-577",
                "cn-labor-contract-law",
                "cn-labor-contract-law-20130701",
                "第五百七十七条",
                577,
                "同号测试条文",
                "用于验证不同法律的相同条号不能互相替代。",
                "2026-09-10",
            ],
        )
        .unwrap();
}

#[tokio::test]
async fn same_article_number_from_a_different_law_cannot_verify_the_answer() {
    fn reply(body: Value) -> Value {
        let messages = body["messages"].as_array().expect("messages");
        let tool_results = messages
            .iter()
            .filter(|message| message["role"] == "tool")
            .count();
        if tool_results == 0 {
            return json!({"model":"mock-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
                {"id":"read-civil-577","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-civil-code-20210101-577\"}"}},
                {"id":"read-labor-577","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-labor-contract-law-20130701-577\"}"}}
            ]}}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}});
        }
        completion(
            json!({"role":"assistant","content":serde_json::to_string(&json!({
            "title":"错误对应",
            "content":"依据《中华人民共和国民法典》第五百七十七条提出意见。",
            "citations":[{"article_id":"cn-labor-contract-law-20130701-577","reason":"故意选择同号不同法条"}]
        })).unwrap()}),
        )
    }

    let mock = Mock::new(reply);
    let f = Fixture::new_with_legal(&mock, true, legal_fixture_with_same_article_number);
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "同条号法律核验".into(),
            ..Default::default()
        })
        .unwrap();
    let failed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(failed["status"], "failed", "{failed}");
    assert_eq!(failed["error_code"], "unverified_law_article_in_answer");
    assert!(failed["citations"].as_array().unwrap().is_empty());
}
#[tokio::test]
async fn document_edits_create_versions_and_exports_do_not_generate_again() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, true);
    let r = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "test".into(),
            ..Default::default()
        })
        .unwrap();
    let r = wait_done(&f.workspace, r["id"].as_str().unwrap()).await;
    assert_eq!(r["status"], "completed");
    let id = r["id"].as_str().unwrap();
    let revision = r["revision"].as_u64().unwrap();
    let before = mock.calls.load(Ordering::Relaxed);
    let txt = f.workspace.export_ai_document(id, revision, "txt").unwrap();
    assert!(!String::from_utf8(txt).unwrap().contains("**金额**"));
    assert!(f
        .workspace
        .export_ai_document(id, revision, "docx")
        .unwrap()
        .starts_with(b"PK"));
    assert_eq!(before, mock.calls.load(Ordering::Relaxed));
    let edited = f
        .workspace
        .edit_ai_document(
            id,
            AiDocumentEdit {
                expected_revision: revision,
                content: "# 修改稿\n\n金额仍为126800元。".into(),
                case_date: AiCaseDateUpdate::Inherit,
            },
        )
        .unwrap();
    assert_ne!(edited["id"], r["id"]);
    assert_eq!(edited["parent_id"], r["id"]);
    assert_eq!(edited["revision"], revision + 1);
    assert!(edited["case_date"].is_null(), "omitted date inherits null");
    assert_eq!(edited["version_scope"], "current");
    let stale = f
        .workspace
        .export_ai_document(edited["id"].as_str().unwrap(), revision, "txt")
        .unwrap_err();
    assert_eq!(stale.code, "revision_conflict");
    assert_eq!(f.workspace.ai_run(id).unwrap()["content"], r["content"]);

    let as_of = f
        .workspace
        .edit_ai_document(
            edited["id"].as_str().unwrap(),
            AiDocumentEdit {
                expected_revision: edited["revision"].as_u64().unwrap(),
                content: edited["content"].as_str().unwrap().to_owned(),
                case_date: AiCaseDateUpdate::Set(Some("2026-08-11".into())),
            },
        )
        .unwrap();
    assert_eq!(as_of["case_date"], "2026-08-11");
    assert_eq!(as_of["version_scope"], "as_of");
    assert_eq!(
        f.workspace.ai_run(edited["id"].as_str().unwrap()).unwrap()["version_scope"],
        "current",
        "an explicit date edit must leave the parent run unchanged"
    );

    let cleared = f
        .workspace
        .edit_ai_document(
            as_of["id"].as_str().unwrap(),
            AiDocumentEdit {
                expected_revision: as_of["revision"].as_u64().unwrap(),
                content: as_of["content"].as_str().unwrap().to_owned(),
                case_date: AiCaseDateUpdate::Set(None),
            },
        )
        .unwrap();
    assert!(cleared["case_date"].is_null());
    assert_eq!(cleared["version_scope"], "current");
}

#[tokio::test]
async fn citation_recheck_binds_body_date_source_hash_and_revision() {
    const QUOTE: &str = "当事人一方不履行合同义务或者履行合同义务不符合约定的";
    fn reply(body: Value) -> Value {
        let has_article = body["messages"]
            .as_array()
            .is_some_and(|messages| messages.iter().any(|message| message["role"] == "tool"));
        if !has_article {
            return json!({"model":"mock-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"read-577","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-civil-code-20210101-577\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}});
        }
        completion(
            json!({"role":"assistant","content":serde_json::to_string(&json!({
            "title":"引用证据",
            "content":"依据《民法典》第577条分析，是否违约仍取决于待核实事实。",
            "citations":[{"article_id":"cn-civil-code-20210101-577","reason":"违约责任","quote":QUOTE}]
        })).unwrap()}),
        )
    }

    let mock = Mock::new(reply);
    let f = Fixture::new_with_legal(&mock, true, legal_fixture);
    let started = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "引用证据回归".into(),
            case_date: Some("2026-08-11".into()),
            ..Default::default()
        })
        .unwrap();
    let completed = wait_done(&f.workspace, started["id"].as_str().unwrap()).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    let id = completed["id"].as_str().unwrap();
    let revision = completed["revision"].as_u64().unwrap();
    let evidence = &completed["citation_verification"];
    assert_eq!(evidence["state"], "passed", "{evidence}");
    assert_eq!(evidence["run_revision"], revision);
    assert_eq!(evidence["case_date"], "2026-08-11");
    assert_eq!(evidence["sources"][0]["source_exists"], "passed");
    assert_eq!(evidence["sources"][0]["full_text_read"], "passed");
    assert_eq!(evidence["sources"][0]["citation_match"], "matched");
    assert_eq!(evidence["sources"][0]["time_check"], "passed");
    assert_eq!(
        evidence["sources"][0]["relevance"],
        "manual_review_required"
    );
    assert!(evidence["sources"][0]["source_full_text_sha256"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
    assert!(evidence["sources"][0]["matched_ranges"]
        .as_array()
        .is_some_and(|ranges| ranges.len() == 1));
    assert!(!evidence.to_string().contains(QUOTE));

    let cancelled = tokio_util::sync::CancellationToken::new();
    let conflict = f
        .workspace
        .recheck_ai_citations(id, revision + 1, &cancelled)
        .await
        .unwrap_err();
    assert_eq!(conflict.code, "revision_conflict");

    let database = rusqlite::Connection::open(&f.legal_path).unwrap();
    database
        .execute(
            "UPDATE law_articles SET content = ?1 WHERE id = 'cn-civil-code-20210101-577'",
            [format!("{QUOTE}。修订后的权威正文。")],
        )
        .unwrap();
    drop(database);
    let token = tokio_util::sync::CancellationToken::new();
    let drifted = f
        .workspace
        .recheck_ai_citations(id, revision, &token)
        .await
        .unwrap();
    assert_eq!(drifted["citation_verification"]["state"], "pending");
    assert_eq!(
        drifted["citation_verification"]["sources"][0]["source_content"],
        "changed"
    );
    assert!(drifted["citation_verification"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "citation_source_changed"));

    // A corpus read failure is not proof that the citation vanished. The
    // recheck must publish only the explicit unavailable/unknown state.
    let offline = f.legal_path.with_extension("offline");
    std::fs::rename(&f.legal_path, &offline).unwrap();
    let unavailable = f
        .workspace
        .recheck_ai_citations(id, revision, &tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(unavailable["citation_verification"]["state"], "pending");
    assert_eq!(
        unavailable["citation_verification"]["sources"][0]["source_exists"],
        "unknown"
    );
    assert_eq!(
        unavailable["citation_verification"]["sources"][0]["full_text_read"],
        "unavailable"
    );
    assert_eq!(
        unavailable["citation_verification"]["sources"][0]["error_category"],
        "citation_source_unavailable"
    );
    let reasons = unavailable["citation_verification"]["reasons"]
        .as_array()
        .expect("explicit aggregate verification reasons");
    assert!(reasons
        .iter()
        .any(|reason| reason == "citation_source_unavailable"));
    assert!(!reasons
        .iter()
        .any(|reason| reason == "citation_source_missing"));
    std::fs::rename(&offline, &f.legal_path).unwrap();

    let edited = f
        .workspace
        .edit_ai_document(
            id,
            AiDocumentEdit {
                expected_revision: revision,
                content: format!(
                    "{}\n\n补充事实待核实。",
                    completed["content"].as_str().unwrap()
                ),
                case_date: AiCaseDateUpdate::Set(Some("2026-08-12".into())),
            },
        )
        .unwrap();
    assert_eq!(edited["citation_verification"]["state"], "stale");
    assert_eq!(edited["citation_verification"]["case_date"], "2026-08-12");
    assert!(edited["citation_verification"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "case_date_changed"));
}

#[test]
fn encrypted_writing_draft_is_revision_bound_and_survives_workspace_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let legal = temp.path().join("absent.sqlite");
    let workspace = Workspace::open(root.clone(), legal.clone()).unwrap();
    let content = json!({
        "document_type":"民事起诉状",
        "prompt":"合成案情",
        "requirements":"列出待补事实",
        "case_date":"2026-09-10",
        "provider_id":"provider_synthetic",
        "model":"model_synthetic",
        "materials":[],
        "attachment_ids":[],
        "run_id":"run_synthetic",
        "run_revision":7,
        "content":"# 未提交修改\n\nSYNTHETIC DRAFT ONLY",
        "dirty":true
    });
    let saved = workspace
        .save_ai_draft("writing-current", 0, content.clone())
        .unwrap();
    assert_eq!(saved["revision"], 1);
    let mut normalized_content = content.clone();
    normalized_content["context_ranges"] = json!([]);
    assert_eq!(saved["content"], normalized_content);
    assert_eq!(
        workspace
            .save_ai_draft("writing-current", 0, content.clone())
            .unwrap_err()
            .code,
        "revision_conflict"
    );
    drop(workspace);

    let reopened = Workspace::open(root, legal).unwrap();
    let restored = reopened.ai_draft("writing-current").unwrap();
    assert_eq!(restored["revision"], 1);
    assert_eq!(restored["content"]["context_ranges"], json!([]));
    assert_eq!(
        restored["content"]["content"],
        "# 未提交修改\n\nSYNTHETIC DRAFT ONLY"
    );
    assert_eq!(
        reopened
            .delete_ai_draft("writing-current", 0)
            .unwrap_err()
            .code,
        "revision_conflict"
    );
    assert_eq!(
        reopened.delete_ai_draft("writing-current", 1).unwrap()["deleted"],
        true
    );
}

#[tokio::test]
async fn replacing_chat_context_cancels_affected_run_and_requires_current_revision() {
    fn delayed(body: Value) -> Value {
        std::thread::sleep(Duration::from_millis(600));
        good_reply(body)
    }
    let mock = Mock::new(delayed);
    let f = Fixture::new(&mock, true);
    let (material_id, _) = raw_material(&f, "context_replacement");
    let conversation = f.workspace.create_ai_conversation(None).unwrap();
    let conversation_id = conversation["id"].as_str().unwrap();
    let replacement = f
        .workspace
        .replace_ai_conversation_context(
            conversation_id,
            1,
            vec![AiMaterialReference {
                id: material_id.clone(),
                source: "original".into(),
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    assert_eq!(replacement["manifest"]["revision"], 2);
    assert_eq!(replacement["manifest"]["context_ranges"][0]["mode"], "all");
    let prepared = f
        .workspace
        .prepare_ai_conversation_context(
            conversation_id,
            2,
            Some(f.provider.clone()),
            Some("mock-model".into()),
        )
        .unwrap();
    assert_eq!(prepared["manifest"]["materials"][0]["id"], material_id);
    assert_eq!(prepared["manifest"]["context_ranges"][0]["mode"], "all");

    let run = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "first message".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            conversation_id: Some(conversation_id.into()),
            context_revision: Some(2),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let run_id = run["id"].as_str().unwrap().to_owned();
    while mock.calls.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let removed = f
        .workspace
        .replace_ai_conversation_context(conversation_id, 2, Vec::new(), Vec::new(), Vec::new())
        .unwrap();
    assert_eq!(removed["manifest"]["revision"], 3);
    assert!(removed["cancelled_run_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == &run_id));
    tokio::time::sleep(Duration::from_millis(700)).await;
    let cancelled = f.workspace.ai_run(&run_id).unwrap();
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(cancelled["error_code"], "context_source_removed");

    let stale = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "stale context".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            conversation_id: Some(conversation_id.into()),
            context_revision: Some(2),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(stale.code, "revision_conflict");
}

#[tokio::test]
async fn removed_context_excludes_the_entire_prior_turn_from_followup_history() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, true);
    let (material_id, _) = raw_material(&f, "history_context_removal");
    let conversation = f.workspace.create_ai_conversation(None).unwrap();
    let conversation_id = conversation["id"].as_str().unwrap();
    let updated = f
        .workspace
        .replace_ai_conversation_context(
            conversation_id,
            1,
            vec![AiMaterialReference {
                id: material_id,
                source: "original".into(),
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    let prepared = f
        .workspace
        .prepare_ai_conversation_context(
            conversation_id,
            updated["manifest"]["revision"].as_u64().unwrap(),
            Some(f.provider.clone()),
            Some("mock-model".into()),
        )
        .unwrap();
    let first = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "first turn uses removable material".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            conversation_id: Some(conversation_id.into()),
            context_revision: Some(2),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let _ = wait_done(&f.workspace, first["id"].as_str().unwrap()).await;
    for _ in 0..100 {
        if f.workspace.ai_conversation(conversation_id).unwrap()["messages"]
            .as_array()
            .is_some_and(|messages| messages.len() == 2)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let removed = f
        .workspace
        .replace_ai_conversation_context(conversation_id, 2, Vec::new(), Vec::new(), Vec::new())
        .unwrap();
    let prepared = f
        .workspace
        .prepare_ai_conversation_context(
            conversation_id,
            removed["manifest"]["revision"].as_u64().unwrap(),
            Some(f.provider.clone()),
            Some("mock-model".into()),
        )
        .unwrap();
    let followup = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "followup without removed material".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            conversation_id: Some(conversation_id.into()),
            context_revision: Some(3),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let _ = wait_done(&f.workspace, followup["id"].as_str().unwrap()).await;
    let latest_model_call = mock
        .requests()
        .into_iter()
        .rev()
        .find(|body| body.get("tools").is_some())
        .expect("followup completion request");
    let sent = latest_model_call.to_string();
    assert!(!sent.contains("SYNTHETIC ORIGINAL MATERIAL"));
    assert!(!sent.contains("first turn uses removable material"));
}

#[tokio::test]
async fn context_removal_before_model_slot_prevents_a_queued_dispatch() {
    fn delayed(body: Value) -> Value {
        std::thread::sleep(Duration::from_millis(650));
        good_reply(body)
    }
    let mock = Mock::new(delayed);
    let f = Fixture::new(&mock, true);
    let (material_id, _) = raw_material(&f, "context_remove_before_dispatch");
    let conversation = f.workspace.create_ai_conversation(None).unwrap();
    let conversation_id = conversation["id"].as_str().unwrap();
    let updated = f
        .workspace
        .replace_ai_conversation_context(
            conversation_id,
            1,
            vec![AiMaterialReference {
                id: material_id,
                source: "original".into(),
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    let prepared = f
        .workspace
        .prepare_ai_conversation_context(
            conversation_id,
            updated["manifest"]["revision"].as_u64().unwrap(),
            Some(f.provider.clone()),
            Some("mock-model".into()),
        )
        .unwrap();

    for prompt in ["hold model slot one", "hold model slot two"] {
        f.workspace
            .start_ai_run(AiRunRequest {
                kind: "writing".into(),
                prompt: prompt.into(),
                provider_id: Some(f.provider.clone()),
                model: Some("mock-model".into()),
                ..Default::default()
            })
            .unwrap();
    }
    while mock.calls.load(Ordering::Relaxed) < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let queued = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "must not reach provider".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            conversation_id: Some(conversation_id.into()),
            context_revision: Some(2),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let removed = f
        .workspace
        .replace_ai_conversation_context(conversation_id, 2, Vec::new(), Vec::new(), Vec::new())
        .unwrap();
    assert!(removed["cancelled_run_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == &queued["id"]));
    tokio::time::sleep(Duration::from_millis(850)).await;
    assert_eq!(mock.calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        f.workspace.ai_run(queued["id"].as_str().unwrap()).unwrap()["status"],
        "cancelled"
    );
}

#[test]
fn v1_upgrade_backs_up_objects_and_migrates_single_model() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let legal = temp.path().join("absent.sqlite");
    let workspace = Workspace::open(root.clone(), legal.clone()).unwrap();
    let group = workspace.create_group("升级保留分组").unwrap();
    let provider = workspace
        .save_provider(SaveProviderRequest {
            id: None,
            name: "旧模型".into(),
            base_url: "https://open.bigmodel.cn/api/paas/v4".into(),
            model: "glm-5.3-flash".into(),
            api_key: None,
            allow_private_network: false,
        })
        .unwrap();
    drop(workspace);
    {
        let database = rusqlite::Connection::open(root.join("workspace.sqlite")).unwrap();
        database
            .execute(
                "UPDATE web_metadata SET value='web-workspace-v1' WHERE key='schema'",
                [],
            )
            .unwrap();
    }
    let upgraded = Workspace::open(root.clone(), legal).unwrap();
    assert!(root.join("workspace.pre-ai-v1.sqlite").is_file());
    assert!(upgraded.groups().unwrap()["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["id"] == group["id"] && g["name"] == "升级保留分组"));
    let defaults = upgraded.ai_defaults().unwrap();
    assert_eq!(defaults.len(), 4);
    assert_eq!(defaults["ocr"].model, "glm-5.3-flash");
    assert_eq!(defaults["chat"].provider_id, provider["id"]);
    let backup = rusqlite::Connection::open(root.join("workspace.pre-ai-v1.sqlite")).unwrap();
    let schema: String = backup
        .query_row(
            "SELECT value FROM web_metadata WHERE key='schema'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(schema, "web-workspace-v1");
}

#[tokio::test]
async fn provider_faults_are_persisted_without_publishing_partial_answers() {
    fn fault(body: Value) -> Value {
        let prompt = body["messages"].as_array().unwrap().last().unwrap()["content"]
            .as_str()
            .unwrap_or_default();
        if prompt.contains("RATE_LIMIT") {
            json!({"_status":429})
        } else if prompt.contains("TIMEOUT") {
            json!({"_status":408})
        } else if prompt.contains("TRUNCATED") {
            json!({"_raw":"{\"choices\":", "_truncated":true})
        } else if prompt.contains("ILLEGAL_JSON") {
            json!({"_raw":"not-json"})
        } else {
            json!({"choices":[{"finish_reason":"length","message":{"role":"assistant","content":"partial"}}]})
        }
    }
    let mock = Mock::new(fault);
    let f = Fixture::new(&mock, true);
    for (prompt, expected) in [
        ("RATE_LIMIT", "provider_rate_limited"),
        ("TIMEOUT", "provider_request_failed"),
        ("TRUNCATED", "provider_network_failed"),
        ("ILLEGAL_JSON", "provider_response_invalid"),
        ("INCOMPLETE", "provider_response_incomplete"),
    ] {
        let r = f
            .workspace
            .start_ai_run(AiRunRequest {
                kind: "writing".into(),
                prompt: prompt.into(),
                ..Default::default()
            })
            .unwrap();
        let done = wait_done(&f.workspace, r["id"].as_str().unwrap()).await;
        assert_eq!(done["status"], "failed", "{prompt}");
        assert_eq!(done["error_code"], expected, "{prompt}");
        assert_eq!(done["content"], "");
    }
}

#[tokio::test]
async fn cancellation_stops_waiting_and_late_provider_result_cannot_publish() {
    fn delayed(body: Value) -> Value {
        std::thread::sleep(Duration::from_millis(600));
        good_reply(body)
    }
    let mock = Mock::new(delayed);
    let f = Fixture::new(&mock, true);
    let r = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "delayed".into(),
            ..Default::default()
        })
        .unwrap();
    let id = r["id"].as_str().unwrap();
    while mock.calls.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.workspace.cancel_ai_run(id).unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    let done = f.workspace.ai_run(id).unwrap();
    assert_eq!(done["status"], "cancelled");
    assert_eq!(done["content"], "");
}

#[tokio::test]
async fn ai_submission_queue_rejects_the_ninth_run_before_provider_or_context_work() {
    fn delayed(body: Value) -> Value {
        std::thread::sleep(Duration::from_millis(400));
        good_reply(body)
    }

    let mock = Mock::new(delayed);
    let fixture = Fixture::new(&mock, true);
    let mut accepted = Vec::new();
    for number in 0..8 {
        let run = fixture
            .workspace
            .start_ai_run(AiRunRequest {
                kind: "writing".into(),
                prompt: format!("bounded-run-{number}"),
                ..Default::default()
            })
            .expect("two active and six waiting runs are accepted");
        accepted.push(run["id"].as_str().expect("run id").to_owned());
    }

    // start_ai_run reserves AI capacity before resolving this request's
    // provider or material policy.  A nonexistent provider would otherwise
    // produce a provider error rather than a capacity rejection.
    let error = fixture
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "must-fail-before-work".into(),
            provider_id: Some("nonexistent-provider".into()),
            model: Some("nonexistent-model".into()),
            ..Default::default()
        })
        .expect_err("the ninth AI submission exceeds two active plus six waiting");
    assert_eq!(error.code, "capacity_exceeded");

    for id in accepted {
        fixture.workspace.cancel_ai_run(&id).expect("run cancels");
    }
}

#[tokio::test]
async fn revoked_or_replaced_original_never_starts_or_continues_an_ai_run() {
    let mock = Mock::new(good_reply);
    let f = Fixture::new(&mock, true);

    let (revoked_id, _) = raw_material(&f, "revoked_original_start");
    f.workspace.revoke_material(&revoked_id).unwrap();
    let error = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "do not dispatch".into(),
            provider_id: Some(f.provider.clone()),
            model: Some("mock-model".into()),
            materials: vec![AiMaterialReference {
                id: revoked_id,
                source: "original".into(),
            }],
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(error.code, "material_revoked");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);

    let (replaced_id, revision) = raw_material(&f, "replaced_original_continue");
    let original = original_run(&f, &replaced_id, "replace before continue");
    let original_id = original["id"].as_str().unwrap();
    let _ = wait_done(&f.workspace, original_id).await;
    f.workspace
        .replace_material(
            &replaced_id,
            revision,
            ImportFile {
                name: "replacement.txt".into(),
                bytes: b"SYNTHETIC REPLACEMENT".to_vec(),
                encoding: Some("utf-8".into()),
            },
        )
        .unwrap();
    let before = mock.calls.load(Ordering::Relaxed);
    let error = f.workspace.continue_ai_run(original_id).unwrap_err();
    assert_eq!(error.code, "source_changed");
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(mock.calls.load(Ordering::Relaxed), before);

    let (revoked_continue_id, _) = raw_material(&f, "revoked_original_continue");
    let original = original_run(&f, &revoked_continue_id, "revoke before continue");
    let original_id = original["id"].as_str().unwrap();
    let _ = wait_done(&f.workspace, original_id).await;
    f.workspace.revoke_material(&revoked_continue_id).unwrap();
    let before = mock.calls.load(Ordering::Relaxed);
    let error = f.workspace.continue_ai_run(original_id).unwrap_err();
    assert_eq!(error.code, "material_revoked");
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(mock.calls.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn provider_profile_change_cannot_continue_raw_material_to_a_new_endpoint() {
    let first = Mock::new(good_reply);
    let second = Mock::new(good_reply);
    let f = Fixture::new(&first, true);
    let (material_id, _) = raw_material(&f, "provider_profile_binding");
    let original = original_run(&f, &material_id, "bind this provider");
    let original_id = original["id"].as_str().unwrap();
    let _ = wait_done(&f.workspace, original_id).await;
    assert!(first
        .requests()
        .iter()
        .any(|body| body.to_string().contains("SYNTHETIC ORIGINAL MATERIAL")));

    f.workspace
        .save_ai_provider(AiProviderRequest {
            id: Some(f.provider.clone()),
            preset: "custom".into(),
            name: "new endpoint".into(),
            base_url: second.url.clone(),
            model: "mock-model".into(),
            enabled_models: vec!["mock-model".into()],
            trust_raw: Some(true),
            allow_private_network: true,
            ..Default::default()
        })
        .unwrap();
    let error = f.workspace.continue_ai_run(original_id).unwrap_err();
    assert_eq!(error.code, "provider_changed");
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(second.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn cancellation_continuation_creates_an_isolated_successor_attempt() {
    fn delayed(body: Value) -> Value {
        std::thread::sleep(Duration::from_millis(500));
        good_reply(body)
    }
    let mock = Mock::new(delayed);
    let f = Fixture::new(&mock, true);
    let original = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "cancel then continue".into(),
            ..Default::default()
        })
        .unwrap();
    let original_id = original["id"].as_str().unwrap().to_owned();
    while mock.calls.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.workspace.cancel_ai_run(&original_id).unwrap();
    let successor = f.workspace.continue_ai_run(&original_id).unwrap();
    let successor_id = successor["id"].as_str().unwrap().to_owned();
    assert_ne!(successor_id, original_id);
    assert_eq!(successor["parent_id"], original_id);
    assert_eq!(original["document_id"], original_id);
    assert_eq!(successor["document_id"], original["document_id"]);

    let successor_done = wait_done(&f.workspace, &successor_id).await;
    assert_eq!(successor_done["status"], "completed");
    assert_eq!(successor_done["document_id"], original["document_id"]);
    assert_eq!(
        f.workspace.ai_run(&original_id).unwrap()["status"],
        "cancelled"
    );
}

#[tokio::test]
async fn paused_continue_clones_verified_tool_context_without_repeating_completed_reads() {
    fn tool_until_paused_then_cite(body: Value) -> Value {
        let tool_results = body["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|message| message["role"] == "tool")
            .count();
        if tool_results >= 8 {
            return completion(
                json!({"role":"assistant","content":serde_json::to_string(&json!({
                "title":"恢复完成",
                "content":"已依据本地检索结果完成核验。",
                "citations":[{"article_id":"cn-civil-code-20210101-577","reason":"合同履行争点"}]
            })).unwrap()}),
            );
        }
        json!({"model":"mock-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"read-contract","type":"function","function":{"name":"legal_get_article","arguments":"{\"article_id\":\"cn-civil-code-20210101-577\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}})
    }

    let mock = Mock::new(tool_until_paused_then_cite);
    let f = Fixture::new_with_legal(&mock, true, legal_fixture);
    let original = f
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "检索合同责任".into(),
            ..Default::default()
        })
        .unwrap();
    let original_id = original["id"].as_str().unwrap();
    let paused = wait_done(&f.workspace, original_id).await;
    assert_eq!(paused["status"], "paused", "{paused}");
    assert_eq!(paused["tool_steps"].as_array().unwrap().len(), 8);
    assert_eq!(paused["usage"]["total_tokens"], 160);
    assert_eq!(mock.calls.load(Ordering::Relaxed), 8);

    let resumed = f.workspace.continue_ai_run(original_id).unwrap();
    let resumed_id = resumed["id"].as_str().unwrap();
    assert_ne!(resumed_id, original_id);
    assert_eq!(resumed["parent_id"], original_id);
    assert_eq!(resumed["document_id"], original["document_id"]);
    assert_eq!(resumed["tool_steps"].as_array().unwrap().len(), 8);
    assert_eq!(resumed["usage"]["total_tokens"], 160);

    let completed = wait_done(&f.workspace, resumed_id).await;
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["document_id"], original["document_id"]);
    assert_eq!(completed["tool_steps"].as_array().unwrap().len(), 8);
    assert_eq!(
        completed["citations"][0]["article_id"],
        "cn-civil-code-20210101-577"
    );
    assert_eq!(mock.calls.load(Ordering::Relaxed), 9);
}

#[test]
fn v1_upgrade_preserves_a_corrupt_backup_and_creates_a_verified_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let legal = temp.path().join("absent.sqlite");
    let workspace = Workspace::open(root.clone(), legal.clone()).unwrap();
    let group = workspace.create_group("损坏备份回归").unwrap();
    drop(workspace);
    {
        let database = rusqlite::Connection::open(root.join("workspace.sqlite")).unwrap();
        database
            .execute(
                "UPDATE web_metadata SET value='web-workspace-v1' WHERE key='schema'",
                [],
            )
            .unwrap();
    }
    let corrupt = root.join("workspace.pre-ai-v1.sqlite");
    std::fs::write(&corrupt, b"not a sqlite database").unwrap();

    let upgraded = Workspace::open(root.clone(), legal).unwrap();
    assert!(upgraded.groups().unwrap()["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == group["id"]));
    assert_eq!(std::fs::read(&corrupt).unwrap(), b"not a sqlite database");
    let verified = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("workspace.pre-ai-v1.") && name.ends_with(".sqlite")
                })
        })
        .expect("a unique replacement backup is created");
    let backup = rusqlite::Connection::open(verified).unwrap();
    let integrity: String = backup
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert_eq!(
        backup
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn context_budget_rejects_oversized_prompt_before_any_model_dispatch() {
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    let error = fixture
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "x".repeat(30_000),
            ..Default::default()
        })
        .expect_err("30k conservative bytes exceed legacy 16k input budget");
    assert_eq!(error.code, "context_budget_exceeded");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn explicit_tool_capability_rejects_run_before_source_or_transport() {
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    fixture
        .workspace
        .save_ai_provider(AiProviderRequest {
            id: Some(fixture.provider.clone()),
            preset: "custom".into(),
            name: "capability mock".into(),
            base_url: mock.url.clone(),
            model: "mock-model".into(),
            enabled_models: vec!["mock-model".into()],
            model_capabilities: std::collections::BTreeMap::from([(
                "mock-model".into(),
                AiModelCapabilities {
                    context_window_tokens: Some(20_480),
                    max_output_tokens: Some(4_096),
                    supports_tools: Some(false),
                    supports_structured_output: None,
                    supports_vision: None,
                },
            )]),
            trust_raw: Some(true),
            allow_private_network: true,
            ..Default::default()
        })
        .expect("capability declaration persists");
    let error = fixture
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "writing".into(),
            prompt: "must not dispatch".into(),
            provider_id: Some(fixture.provider.clone()),
            model: Some("mock-model".into()),
            ..Default::default()
        })
        .expect_err("explicit false tools cannot enter the provider transport");
    assert_eq!(error.code, "model_tools_unsupported");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn estimate_returns_safe_scope_and_stale_plan_hash_is_not_advisory() {
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    let (material_id, _) = raw_material(&fixture, "context_estimate_safe");
    let request = AiRunRequest {
        kind: "writing".into(),
        prompt: "核对材料".into(),
        provider_id: Some(fixture.provider.clone()),
        model: Some("mock-model".into()),
        materials: vec![AiMaterialReference {
            id: material_id.clone(),
            source: "original".into(),
        }],
        ..Default::default()
    };
    let estimate = fixture
        .workspace
        .estimate_ai_context(&request)
        .expect("summary-only estimate");
    assert_eq!(estimate["schema_version"], 2);
    assert_eq!(estimate["plan"]["schema_version"], 2);
    assert_eq!(estimate["capabilities"]["verified"], false);
    assert_eq!(estimate["capabilities"]["max_input_tokens"], 16_384);
    assert_eq!(estimate["capabilities"]["max_output_tokens"], 4_096);
    assert_eq!(
        estimate["selected_scope"]["materials"][0]["source_id"],
        material_id
    );
    assert!(!estimate.to_string().contains("SYNTHETIC ORIGINAL MATERIAL"));
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);

    let mut stale = request;
    stale.context_plan_hash = Some("not-the-current-summary-plan".into());
    let error = fixture
        .workspace
        .start_ai_run(stale)
        .expect_err("reviewed plan hash must be checked on start");
    assert_eq!(error.code, "context_prepare_required");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn visual_preflight_requires_scope_before_any_raw_or_model_work() {
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    let attachment = fixture
        .workspace
        .save_ai_attachment("large-scan.png".into(), vec![0_u8; 1_000_000])
        .expect("metadata-only attachment save");
    let request = AiRunRequest {
        kind: "writing".into(),
        prompt: "核对扫描件".into(),
        attachment_ids: vec![attachment["id"].as_str().unwrap().into()],
        ..Default::default()
    };
    let estimate = fixture
        .workspace
        .estimate_ai_context(&request)
        .expect("summary-only visual preflight");
    assert_eq!(estimate["stage"], "scope_required");
    assert_eq!(
        estimate["omitted_scope"][0]["reason"],
        "ocr_page_scope_required"
    );
    let error = fixture
        .workspace
        .start_ai_run(request)
        .expect_err("oversized visual source must reject before a worker/model can start");
    assert_eq!(error.code, "context_budget_exceeded");
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn visual_preflight_uses_full_estimate_instead_of_the_text_segment_cap() {
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    let attachment = fixture
        .workspace
        .save_ai_attachment("medium-scan.png".into(), vec![0_u8; 300_000])
        .expect("metadata-only attachment save");
    let estimate = fixture
        .workspace
        .estimate_ai_context(&AiRunRequest {
            kind: "writing".into(),
            prompt: "核对扫描件".into(),
            attachment_ids: vec![attachment["id"].as_str().unwrap().into()],
            ..Default::default()
        })
        .expect("visual estimate stays summary-only");
    assert_eq!(estimate["stage"], "conservative");
    assert!(
        estimate["selected_scope"]["attachments"][0]["estimated_tokens"]
            .as_u64()
            .unwrap()
            > 4_096,
        "visual sources reserve their complete conservative estimate"
    );
    assert_eq!(mock.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn completed_history_records_actual_hash_and_history_budget_without_replacing_preflight_hash()
{
    let mock = Mock::new(good_reply);
    let fixture = Fixture::new(&mock, true);
    let conversation = fixture.workspace.create_ai_conversation(None).unwrap();
    let conversation_id = conversation["id"].as_str().unwrap().to_owned();

    let prepared = fixture
        .workspace
        .prepare_ai_conversation_context(&conversation_id, 1, None, None)
        .unwrap();
    let first = fixture
        .workspace
        .start_ai_run(AiRunRequest {
            kind: "chat".into(),
            prompt: "第一轮：合同解除条件".into(),
            conversation_id: Some(conversation_id.clone()),
            context_revision: Some(1),
            context_preparation_hash: Some(
                prepared["preparation_hash"].as_str().unwrap().to_owned(),
            ),
            ..Default::default()
        })
        .unwrap();
    let first_id = first["id"].as_str().unwrap().to_owned();
    assert_eq!(
        wait_done(&fixture.workspace, &first_id).await["status"],
        "completed"
    );

    let prepared = fixture
        .workspace
        .prepare_ai_conversation_context(&conversation_id, 1, None, None)
        .unwrap();
    let follow_up = AiRunRequest {
        kind: "chat".into(),
        prompt: "第二轮：补充违约责任".into(),
        conversation_id: Some(conversation_id.clone()),
        context_revision: Some(1),
        context_preparation_hash: Some(prepared["preparation_hash"].as_str().unwrap().to_owned()),
        ..Default::default()
    };
    let estimate = fixture.workspace.estimate_ai_context(&follow_up).unwrap();
    let mut bound = follow_up;
    bound.context_plan_hash = Some(estimate["plan_hash"].as_str().unwrap().to_owned());
    let second = fixture.workspace.start_ai_run(bound).unwrap();
    let second_id = second["id"].as_str().unwrap().to_owned();
    let done = wait_done(&fixture.workspace, &second_id).await;
    assert_eq!(done["status"], "completed");
    let plan = &done["context_plan"];
    assert_eq!(plan["plan_hash"], estimate["plan_hash"]);
    assert!(plan["actual_plan_hash"].as_str().is_some());
    assert_ne!(plan["actual_plan_hash"], plan["plan_hash"]);
    assert!(plan["estimate"]["history_tokens"].as_u64().unwrap() > 0);
    assert!(plan["selected_scope"]["history_run_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id.as_str() == Some(first_id.as_str())));
}
