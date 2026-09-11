mod admission;
mod ai_context;
mod ai_legal_tools;
pub use admission::{AdmissionClass, AdmissionPermit};
mod ai_provider;
mod ai_runs;
mod case_search;
mod diagnostics;
mod document_render;
mod document_worker;
pub(crate) use diagnostics::supervisor::Supervisor;
mod ocr;
mod redaction_ai;
pub(crate) use ai_context::{
    estimate_image_tokens, estimate_text_tokens, ContextExtractionPlan, DEFAULT_TOOL_RESERVE_TOKENS,
};
pub use ai_context::{
    AiContextCapabilities, AiContextEstimate, AiContextInspectRequest, AiContextInspectResponse,
    AiContextOmission, AiContextPlan, AiContextRange, AiContextRangeSelection, AiContextScope,
    AiContextUnitRange,
};
pub use ai_provider::*;
pub use ai_runs::*;
mod error;
pub mod filesystem;
mod provider;
mod store;
mod tasks;
mod types;
pub use document_worker::run_internal_document_worker;
#[cfg(feature = "document-worker-fault-injection")]
pub use document_worker::run_internal_document_worker_fault;
pub use error::{Error, Result};
use privacy_text::DictionaryEntry;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use store::Store;
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
pub use types::*;

pub struct Workspace {
    pub(crate) root: PathBuf,
    pub(crate) store: Store,
    pub(crate) gate: Mutex<()>,
    pub(crate) wake: Notify,
    pub(crate) cancellations: Mutex<HashMap<String, CancellationToken>>,
    pub(crate) chat_cancellations: Mutex<HashMap<String, CancellationToken>>,
    pub(crate) ai_slots: tokio::sync::Semaphore,
    pub(crate) admission: Arc<admission::Admission>,
    pub(crate) supervisor: Arc<Supervisor>,
    pub(crate) credentials: providers::windows_credentials::WindowsCredentialStore,
    legal: legal_services::LegalServices,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or(0)
}
pub fn id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}
pub fn hash(bytes: &[u8]) -> String {
    privacy::sha256_hex(bytes)
}
pub fn valid_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::new("invalid_identifier"));
    }
    Ok(())
}
fn bounded(value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        Err(Error::new("invalid_request"))
    } else {
        Ok(())
    }
}

impl Workspace {
    pub fn open(root: PathBuf, legal_db: PathBuf) -> Result<Arc<Self>> {
        if !root.is_absolute() || !legal_db.is_absolute() {
            return Err(Error::new("absolute_path_required"));
        }
        let store = Store::open(&root)?;
        let legal = legal_services::LegalServices::new_public(legal_db)
            .map_err(|_| Error::new("legal_configuration_invalid"))?;
        let prefix = format!(
            "LawyerAssistanceWeb/{}",
            &hash(root.to_string_lossy().as_bytes())[..16]
        );
        let this = Arc::new(Self {
            supervisor: Supervisor::new(root.clone()),
            root,
            store,
            gate: Mutex::new(()),
            wake: Notify::new(),
            cancellations: Mutex::new(HashMap::new()),
            chat_cancellations: Mutex::new(HashMap::new()),
            ai_slots: tokio::sync::Semaphore::new(2),
            admission: admission::Admission::new(),
            credentials:
                providers::windows_credentials::WindowsCredentialStore::with_service_prefix(prefix),
            legal,
        });
        // Never replay a raw cloud dispatch after a crash. Query the status
        // index first so startup opens only interrupted material records.
        for material_id in this
            .store
            .indexed_ids_with_status("material", &["running"])?
        {
            let mut material: Material = this.store.get("material", &material_id)?;
            let consent = this
                .store
                .maybe::<CloudConsent>("consent", &material.task_id)?;
            if consent.is_some_and(|c| c.used_materials.contains(&material.id)) {
                material.status = "needs_review".into();
                material.reason_code = Some("cloud_dispatch_interrupted".into());
            } else {
                material.status = "queued".into();
            }
            this.store.save("material", &material.id, &material)?;
        }
        this.migrate_ai_settings()?;
        // Legacy conversation bodies are opened exactly once during recovery.
        // Normal paged conversation lists use only their protected summaries.
        this.migrate_legacy_ai_conversations()?;
        this.recover_ai_runs()?;
        redaction_ai::recover_ai_stages(&this)?;
        Ok(this)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn legal(&self) -> &legal_services::LegalServices {
        &self.legal
    }
    pub async fn acquire_admission(
        &self,
        class: AdmissionClass,
        cancel: &CancellationToken,
    ) -> Result<AdmissionPermit> {
        self.admission.acquire(class, cancel).await
    }
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.gate
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))
    }
    pub fn health(&self) -> Value {
        let supervision = self.supervisor.health();
        let storage = self
            .storage_health()
            .unwrap_or_else(|error| json!({"error_code":error.code}));
        let storage_ready = storage["corrupt_count"] == 0 && storage.get("error_code").is_none();
        let defaults = self.ai_defaults().unwrap_or_default();
        let purposes = defaults.keys().cloned().collect::<Vec<_>>();
        json!({
            "status":if supervision.material_worker.ready && supervision.diagnostics.ready && storage_ready { "ready" } else { "degraded" },
            "supervision":supervision,
            "storage":storage,
            "resources":self.admission.snapshot(),
            "version":env!("CARGO_PKG_VERSION"),
            "legal_ready":self.legal.system_status().map(|s|s.legal_database.available).unwrap_or(false),
            "ai":{"configured":!defaults.is_empty(),"purposes":purposes},
            "ocr":ocr::health_status(self),
            "formats":["txt","docx","pdf","png","jpeg","webp"]
        })
    }
    pub fn storage_health(&self) -> Result<Value> {
        Ok(json!({"corrupt_count":self.store.corrupt_count(None)?}))
    }
    pub fn groups(&self) -> Result<Value> {
        self.groups_page(None, 50)
    }
    pub fn groups_page(&self, cursor: Option<&str>, limit: usize) -> Result<Value> {
        let page = self
            .store
            .summary_page("group", None, None, cursor, limit)?;
        Ok(
            json!({"groups":page.items,"next_cursor":page.next_cursor,"total":page.total,"corrupt_count":page.corrupt_count}),
        )
    }
    pub fn create_group(&self, name: &str) -> Result<Value> {
        bounded(name, 160)?;
        let _gate = self.lock()?;
        let group = Group {
            id: id("grp"),
            name: name.trim().into(),
            dictionary_revision: 1,
            namespace: id("salt"),
            entries: Vec::new(),
        };
        self.store.save("group", &group.id, &group)?;
        Ok(json!({"id":group.id,"name":group.name,"dictionary_revision":1}))
    }
    pub fn dictionary(&self, group_id: &str) -> Result<Value> {
        let g: Group = self.store.get("group", group_id)?;
        Ok(json!({"entries":g.entries,"revision":g.dictionary_revision}))
    }
    pub fn set_dictionary(&self, group_id: &str, entries: Vec<DictionaryEntry>) -> Result<Value> {
        let _gate = self.lock()?;
        self.update_dictionary_locked(group_id, entries)?;
        self.dictionary(group_id)
    }
    fn update_dictionary_locked(
        &self,
        group_id: &str,
        entries: Vec<DictionaryEntry>,
    ) -> Result<()> {
        if entries.len() > 2000 {
            return Err(Error::new("dictionary_too_large"));
        }
        for e in &entries {
            bounded(&e.text, 1024)?;
            bounded(&e.kind, 64)?;
            if let Some(a) = &e.alias {
                bounded(a, 128)?;
            }
        }
        let mut group: Group = self.store.get("group", group_id)?;
        privacy_text::analyze(
            "dictionary validation",
            &group.namespace,
            &entries,
            &[],
            &[],
        )
        .map_err(|_| Error::new("dictionary_invalid"))?;
        group.entries = entries;
        group.dictionary_revision += 1;
        let mut rows = vec![Store::encoded("group", group_id, &group)?];
        for mut material in self
            .store
            .list::<Material>("material")?
            .into_iter()
            .filter(|m| m.group_id == group_id)
        {
            self.cancel_cloud_task(&material.task_id)?;
            if let Some(result_id) = material.result_id.take() {
                let mut r: ReadyResult = self.store.get("result", &result_id)?;
                r.revoked = true;
                rows.push(Store::encoded("result", &r.id, &r)?);
            }
            if !matches!(material.status.as_str(), "cancelled" | "revoked") {
                material.status = "queued".into();
                material.reason_code = Some("dictionary_changed".into());
                material.revision += 1;
                material.analysis = None;
                material.dismissed.clear();
            }
            rows.push(Store::encoded("material", &material.id, &material)?);
        }
        self.store.put_many(rows)?;
        self.cancel_active_chats()?;
        self.wake.notify_one();
        Ok(())
    }
    pub fn materials(&self, group_id: Option<&str>) -> Result<Value> {
        self.materials_page(group_id, None, 50)
    }
    pub fn materials_page(
        &self,
        group_id: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Value> {
        let page = self
            .store
            .summary_page("material", None, group_id, cursor, limit)?;
        let materials = page
            .items
            .iter()
            .map(|summary| self.with_material_summary_progress(summary, summary.clone()))
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"materials":materials,"next_cursor":page.next_cursor,"total":page.total,"corrupt_count":page.corrupt_count}),
        )
    }
    pub fn material(&self, material_id: &str) -> Result<Material> {
        self.store.get("material", material_id)
    }
    pub fn material_view(&self, material_id: &str) -> Result<Value> {
        let m = self.display_material(self.material(material_id)?);
        self.with_material_progress(&m, serde_json::to_value(&m)?)
    }
    fn with_material_progress(&self, material: &Material, mut value: Value) -> Result<Value> {
        let stage = self
            .store
            .maybe::<Value>("ai_stage", &material.id)?
            .filter(|record| {
                record["revision"] == material.revision
                    && record["source_sha256"] == material.source_sha256
            });
        if let Some(stage) = stage {
            value["processing_method"] = json!("llm");
            value["processing_method_label"] = json!("大模型识别与本地核验");
            value["stage"] = stage["stage"].clone();
            value["stage_updated_at"] = stage["updated_at"].clone();
            value["stage_error_code"] = stage["error_code"].clone();
        } else {
            value["processing_method"] = json!("local");
            value["processing_method_label"] = json!("本地算法处理");
            value["stage"] = json!(if material.analysis.is_some() {
                "本地识别与残留检查"
            } else {
                "等待材料处理"
            });
        }
        Ok(value)
    }
    fn with_material_summary_progress(&self, material: &Value, mut value: Value) -> Result<Value> {
        let stage = match material["id"].as_str() {
            Some(id) => self.store.maybe_summary("ai_stage", id)?,
            None => None,
        }
        .filter(|record| {
            record["revision"] == material["revision"]
                && record["source_sha256"] == material["source_sha256"]
        });
        if let Some(stage) = stage {
            value["processing_method"] = json!("llm");
            value["processing_method_label"] = json!("大模型识别与本地核验");
            value["stage"] = stage["stage"].clone();
            value["stage_updated_at"] = stage["updated_at"].clone();
            value["stage_error_code"] = stage["error_code"].clone();
        } else {
            value["processing_method"] = json!("local");
            value["processing_method_label"] = json!("本地算法处理");
            value["stage"] = json!(if material["has_analysis"] == true {
                "本地识别与残留检查"
            } else {
                "等待材料处理"
            });
        }
        Ok(value)
    }
    pub fn task_status(&self, task_id: &str) -> Result<Value> {
        let task: Task = self.store.get("task", task_id)?;
        let materials = task
            .material_ids
            .iter()
            .map(|i| self.material(i).map(|m| self.display_material(m)))
            .collect::<Result<Vec<_>>>()?;
        let status = aggregate(&materials);
        let summaries = materials
            .iter()
            .map(|m| self.with_material_progress(m, material_summary(m)))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"id":task.id,"task_id":task.id,"status":status,"materials":summaries}))
    }
    fn display_material(&self, mut m: Material) -> Material {
        if m.status == "ready" {
            let invalid = m
                .result_id
                .as_deref()
                .and_then(|rid| self.store.get::<ReadyResult>("result", rid).ok())
                .map(|r| {
                    if r.expires_at <= now() {
                        Some("result_expired")
                    } else if r.revoked {
                        Some("result_revoked")
                    } else {
                        None
                    }
                })
                .unwrap_or(Some("result_not_ready"));
            if let Some(code) = invalid {
                m.status = "needs_review".into();
                m.reason_code = Some(code.into());
                m.result_id = None;
            }
        }
        m
    }
    pub fn read_result(&self, result_id: &str) -> Result<ReadyResult> {
        let _gate = self.lock()?;
        self.read_result_locked(result_id)
    }
    pub(crate) fn read_result_locked(&self, result_id: &str) -> Result<ReadyResult> {
        let result: ReadyResult = self.store.get("result", result_id)?;
        let material: Material = self.store.get("material", &result.material_id)?;
        let group: Group = self.store.get("group", &result.group_id)?;
        if result.revoked {
            return Err(Error::new("result_revoked"));
        }
        if result.expires_at <= now() {
            return Err(Error::new("result_expired"));
        }
        if material.status != "ready"
            || material.result_id.as_deref() != Some(result_id)
            || material.revision != result.revision
            || group.dictionary_revision != result.dictionary_revision
        {
            return Err(Error::new("result_not_ready"));
        }
        if hash(result.text.as_bytes()) != result.output_sha256 {
            return Err(Error::new("result_integrity_failed"));
        }
        let analysis = privacy_text::Analysis {
            text: result.text.clone(),
            findings: result.findings.clone(),
            ai_findings: None,
            replacements: result.replacements.clone(),
            needs_review: false,
            source_sha256: result.source_sha256.clone(),
            output_sha256: result.output_sha256.clone(),
        };
        privacy_text::validate_analysis(&analysis)
            .map_err(|_| Error::new("sensitive_content_blocked"))?;
        privacy_text::verify_analysis_source(&material.original_text, &analysis)
            .map_err(|_| Error::new("result_integrity_failed"))?;
        Ok(result)
    }
    pub fn revoke_material(&self, material_id: &str) -> Result<()> {
        let _gate = self.lock()?;
        let mut m = self.material(material_id)?;
        let mut rows = Vec::new();
        if let Some(rid) = m.result_id.take() {
            let mut r: ReadyResult = self.store.get("result", &rid)?;
            r.revoked = true;
            rows.push(Store::encoded("result", &rid, &r)?);
        }
        m.status = "revoked".into();
        m.revision += 1;
        m.reason_code = Some("result_revoked".into());
        rows.push(Store::encoded("material", &m.id, &m)?);
        self.store.put_many(rows)?;
        self.cancel_cloud_task(&m.task_id)?;
        self.cancel_active_chats()
    }
    pub(crate) fn cancel_active_chats(&self) -> Result<()> {
        for c in self
            .chat_cancellations
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))?
            .values()
        {
            c.cancel();
        }
        Ok(())
    }
    pub(crate) fn cancel_cloud_task(&self, task_id: &str) -> Result<()> {
        if let Some(c) = self
            .cancellations
            .lock()
            .map_err(|_| Error::new("workspace_unavailable"))?
            .get(task_id)
        {
            c.cancel();
        }
        Ok(())
    }
    pub fn export_result(&self, result_id: &str, format: &str) -> Result<Vec<u8>> {
        let _gate = self.lock()?;
        let result = self.read_result_locked(result_id)?;
        privacy_text::export(&result.text, format).map_err(|_| Error::new("export_failed"))
    }
    pub fn export_batch(&self, ids: &[String], format: &str) -> Result<Vec<u8>> {
        use std::io::{Cursor, Write};
        if ids.is_empty() || ids.len() > 100 || !matches!(format, "txt" | "md" | "docx") {
            return Err(Error::new("invalid_request"));
        }
        let _gate = self.lock()?;
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let mut report = Vec::new();
        for (index, id) in ids.iter().enumerate() {
            let material = self.material(id)?;
            let exported = material
                .result_id
                .as_deref()
                .ok_or_else(|| Error::new("result_not_ready"))
                .and_then(|r| self.read_result_locked(r))
                .and_then(|r| {
                    privacy_text::export(&r.text, format).map_err(|_| Error::new("export_failed"))
                });
            match exported {
                Ok(data) => {
                    let name = format!("material-{}.{}", index + 1, format);
                    archive
                        .start_file(&name, zip::write::SimpleFileOptions::default())
                        .map_err(|_| Error::new("export_failed"))?;
                    archive.write_all(&data)?;
                    report.push(json!({"material_id":id,"status":"exported","file":name}));
                }
                Err(e) => report
                    .push(json!({"material_id":id,"status":material.status,"reason_code":e.code})),
            }
        }
        archive
            .start_file("report.json", zip::write::SimpleFileOptions::default())
            .map_err(|_| Error::new("export_failed"))?;
        archive.write_all(&serde_json::to_vec_pretty(&report)?)?;
        Ok(archive
            .finish()
            .map_err(|_| Error::new("export_failed"))?
            .into_inner())
    }
    pub fn bookmarks(&self) -> Result<Value> {
        Ok(json!({"bookmarks":self.store.list::<Bookmark>("bookmark")?}))
    }
    pub fn save_bookmark(&self, article_id: &str, title: &str) -> Result<Value> {
        bounded(title, 500)?;
        self.legal
            .legal_get_article(legal_services::LegalGetArticleRequest {
                schema_version: 1,
                article_id: article_id.into(),
            })
            .map_err(|_| Error::new("article_not_found"))?;
        let bookmark = Bookmark {
            id: hash(article_id.as_bytes()),
            article_id: article_id.into(),
            title: title.into(),
        };
        self.store.save("bookmark", &bookmark.id, &bookmark)?;
        Ok(serde_json::to_value(bookmark)?)
    }
    pub fn delete_bookmark(&self, id: &str) -> Result<()> {
        self.store.delete("bookmark", id)
    }
    pub fn template_preview(
        &self,
        template_id: domain::document::DocumentTemplateId,
        input: domain::document::StandaloneDocumentInput,
    ) -> Result<String> {
        domain::document::generate_standalone_document(&input, template_id, None)
            .map(|d| d.markdown)
            .map_err(|_| Error::new("template_fields_invalid"))
    }
    pub fn clients(&self) -> Result<Value> {
        Ok(
            json!({"clients":self.store.list::<McpClient>("client")?.iter().map(|c|self.client_view(c)).collect::<Vec<_>>()}),
        )
    }
    fn client_view(&self, c: &McpClient) -> Value {
        json!({"id":c.id,"name":c.name,"group_id":c.group_id,"enabled":c.enabled,"inbox":self.root.join("inbox").join(&c.id).display().to_string()})
    }
    pub fn create_client(&self, name: &str, group_id: &str) -> Result<Value> {
        bounded(name, 120)?;
        let _gate = self.lock()?;
        let _: Group = self.store.get("group", group_id)?;
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let client = McpClient {
            id: id("client"),
            name: name.into(),
            group_id: group_id.into(),
            enabled: true,
            token_hash: hash(token.as_bytes()),
            created_at: now(),
        };
        std::fs::create_dir_all(self.root.join("inbox").join(&client.id))?;
        self.store.save("client", &client.id, &client)?;
        Ok(json!({"client":self.client_view(&client),"token":token}))
    }
    pub fn revoke_client(&self, id: &str) -> Result<()> {
        let _gate = self.lock()?;
        let mut c: McpClient = self.store.get("client", id)?;
        c.enabled = false;
        self.store.save("client", id, &c)
    }
    pub fn authenticate_client(&self, token: &str) -> Result<McpClient> {
        if !(32..=512).contains(&token.len()) {
            return Err(Error::new("unauthorized"));
        }
        let digest = hash(token.as_bytes());
        self.store
            .list::<McpClient>("client")?
            .into_iter()
            .find(|c| c.enabled && bool::from(c.token_hash.as_bytes().ct_eq(digest.as_bytes())))
            .ok_or_else(|| Error::new("unauthorized"))
    }
    pub fn mcp_status(&self, token: &str, task_id: &str) -> Result<Value> {
        let _gate = self.lock()?;
        let client = self.authenticate_client(token)?;
        let task: Task = self.store.get("task", task_id)?;
        if task.group_id != client.group_id || task.client_id.as_deref() != Some(&client.id) {
            return Err(Error::new("task_not_found"));
        }
        let view = self.task_status(task_id)?;
        let materials=view["materials"].as_array().ok_or_else(||Error::new("storage_failed"))?.iter().map(|m|json!({"status":m["status"],"result_id":m["result_id"],"reason_code":m["reason_code"]})).collect::<Vec<_>>();
        Ok(json!({"task_id":task_id,"status":view["status"],"materials":materials}))
    }
    pub fn mcp_read(&self, token: &str, result_id: &str, cursor: Option<&str>) -> Result<Value> {
        let _gate = self.lock()?;
        let client = self.authenticate_client(token)?;
        let result = self.read_result_locked(result_id)?;
        if result.group_id != client.group_id {
            return Err(Error::new("result_not_found"));
        }
        let start = cursor
            .unwrap_or("0")
            .parse::<usize>()
            .map_err(|_| Error::new("invalid_cursor"))?;
        if start > result.text.len() || !result.text.is_char_boundary(start) {
            return Err(Error::new("invalid_cursor"));
        }
        let mut end = (start + 64 * 1024).min(result.text.len());
        while !result.text.is_char_boundary(end) {
            end -= 1;
        }
        Ok(
            json!({"result_id":result.id,"text":&result.text[start..end],"mime_type":"text/plain; charset=utf-8","sha256":result.output_sha256,"next_cursor":if end<result.text.len(){Some(end.to_string())}else{None}}),
        )
    }
}
fn material_summary(m: &Material) -> Value {
    json!({"id":m.id,"name":m.name,"group_id":m.group_id,"task_id":m.task_id,"status":m.status,"result_id":m.result_id,"reason_code":m.reason_code,"revision":m.revision})
}
fn aggregate(materials: &[Material]) -> &'static str {
    for state in ["running", "queued", "awaiting_consent", "needs_review"] {
        if materials.iter().any(|m| m.status == state) {
            return state;
        }
    }
    if materials.iter().all(|m| m.status == "ready") {
        "ready"
    } else if materials.iter().all(|m| m.status == "cancelled") {
        "cancelled"
    } else if materials.iter().any(|m| m.status == "ready") {
        "partial"
    } else {
        "failed"
    }
}
