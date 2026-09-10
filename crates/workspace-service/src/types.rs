use privacy_text::{Analysis, DictionaryEntry};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub dictionary_revision: u64,
    pub namespace: String,
    pub entries: Vec<DictionaryEntry>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Material {
    pub id: String,
    pub name: String,
    pub group_id: String,
    pub task_id: String,
    pub status: String,
    pub reason_code: Option<String>,
    pub revision: u64,
    pub source_sha256: String,
    /// Safe source descriptor recorded at ingestion.  It lets an AI preflight estimate work
    /// without opening the encrypted source body.  Legacy rows intentionally deserialize as
    /// unknown and are completed only during a bounded first use.
    #[serde(default)]
    pub source_byte_len: u64,
    #[serde(default)]
    pub source_format: String,
    pub encoding: Option<String>,
    pub original_text: String,
    pub analysis: Option<Analysis>,
    pub result_id: Option<String>,
    pub dismissed: Vec<String>,
    pub dictionary_revision: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub group_id: String,
    pub client_id: Option<String>,
    pub request_id: String,
    pub fingerprint: String,
    pub material_ids: Vec<String>,
    pub created_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReadyResult {
    pub id: String,
    pub material_id: String,
    pub group_id: String,
    pub revision: u64,
    pub dictionary_revision: u64,
    pub output_sha256: String,
    #[serde(default)]
    pub text_byte_len: u64,
    pub text: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub findings: Vec<privacy_text::Finding>,
    #[serde(default)]
    pub replacements: Vec<privacy_text::Replacement>,
    #[serde(default)]
    pub source_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CloudConsent {
    pub id: String,
    pub provider_id: String,
    pub model: String,
    pub profile_hash: String,
    pub source_hashes: Vec<(String, u64, String)>,
    pub expires_at: u64,
    pub used_materials: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub model: String,
    pub allow_private_network: bool,
    pub revision: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct McpClient {
    pub id: String,
    pub name: String,
    pub group_id: String,
    pub enabled: bool,
    pub token_hash: String,
    pub created_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: String,
    pub article_id: String,
    pub title: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub context_result_ids: Vec<String>,
}

pub struct ImportFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub encoding: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub revision: u64,
    #[serde(default)]
    pub dictionary: Vec<DictionaryEntry>,
    #[serde(default)]
    pub dismissed: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveProviderRequest {
    pub id: Option<String>,
    pub name: String,
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    #[serde(default)]
    pub allow_private_network: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatRequest {
    pub conversation_id: String,
    pub provider_id: String,
    pub message: String,
    #[serde(default)]
    pub result_ids: Vec<String>,
    #[serde(default)]
    pub article_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseUnderstandingRequest {
    pub query: String,
    pub provider_id: String,
    pub model: String,
    pub case_type: Option<String>,
    #[serde(default)]
    pub include_withdrawn: bool,
}

/// Future OCR adapters must report completeness; no production adapter is registered in v1.
pub trait OcrAdapter: Send + Sync {
    fn extract(&self, bytes: &[u8], mime: &str) -> crate::Result<OcrText>;
}
pub struct OcrText {
    pub text: String,
    pub complete: bool,
    pub warnings: Vec<String>,
}
