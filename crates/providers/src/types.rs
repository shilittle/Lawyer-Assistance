use crate::redaction::truncate_for_log;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    DeepSeek,
    Qwen,
    SiliconFlow,
    VolcengineArk,
    Custom,
}

impl ProviderKind {
    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::DeepSeek => "https://api.deepseek.com",
            Self::Qwen => "https://dashscope.aliyuncs.com/compatible-mode/v1",
            Self::SiliconFlow => "https://api.siliconflow.cn/v1",
            Self::VolcengineArk => "https://ark.cn-beijing.volces.com/api/v3",
            Self::Custom => "",
        }
    }

    pub fn default_model_id(self) -> &'static str {
        match self {
            Self::DeepSeek => "deepseek-v4-flash",
            Self::Qwen => "qwen-plus",
            Self::SiliconFlow => "deepseek-ai/DeepSeek-V3.2",
            Self::VolcengineArk => "doubao-seed-2-0-lite-260215",
            Self::Custom => "",
        }
    }

    pub fn default_options(self) -> ProviderOptions {
        match self {
            Self::DeepSeek | Self::VolcengineArk => ProviderOptions {
                thinking: Some(false),
                ..ProviderOptions::default()
            },
            Self::Qwen | Self::SiliconFlow => ProviderOptions {
                enable_thinking: Some(false),
                ..ProviderOptions::default()
            },
            Self::Custom => ProviderOptions::default(),
        }
    }

    /// Fills only provider-defined compatibility defaults while preserving
    /// every explicitly stored option.  This keeps legacy profiles whose JSON
    /// predates a newly required toggle deterministic.  In particular,
    /// DeepSeek V4 defaults thinking to enabled server-side, while this
    /// application deliberately defaults ordinary legal work to non-thinking
    /// mode for bounded, visible answers.
    pub fn options_with_defaults(self, mut options: ProviderOptions) -> ProviderOptions {
        let defaults = self.default_options();
        options.thinking = options.thinking.or(defaults.thinking);
        options.enable_thinking = options.enable_thinking.or(defaults.enable_thinking);
        options
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCapabilities {
    pub chat: bool,
    pub streaming: bool,
    pub custom_model_id: bool,
    pub custom_base_url: bool,
    pub reasoning: bool,
}

impl ProviderCapabilities {
    pub fn chat_defaults() -> Self {
        Self {
            chat: true,
            streaming: true,
            custom_model_id: true,
            custom_base_url: true,
            reasoning: true,
        }
    }

    pub fn custom_openai_compatible_defaults() -> Self {
        Self {
            reasoning: false,
            ..Self::chat_defaults()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    Max,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOptions {
    pub thinking: Option<bool>,
    pub enable_thinking: Option<bool>,
    pub thinking_budget: Option<u32>,
    pub reasoning_effort: Option<ReasoningEffort>,
    pub endpoint_id: Option<String>,
    pub workspace_id: Option<String>,
    /// Explicitly permits a custom provider to target loopback, link-local, or
    /// private-network IP literals. The default remains deny so importing a
    /// profile cannot silently turn a provider request into an SSRF primitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_private_network: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderProfile {
    pub id: String,
    pub display_name: String,
    pub kind: ProviderKind,
    pub model_id: String,
    pub base_url: String,
    pub credential_account_id: String,
    pub capabilities: ProviderCapabilities,
    pub options: ProviderOptions,
}

impl ProviderProfile {
    pub fn new_default(id: impl Into<String>, kind: ProviderKind) -> Self {
        Self {
            id: id.into(),
            display_name: format!("{kind:?}"),
            kind,
            model_id: kind.default_model_id().to_owned(),
            base_url: kind.default_base_url().to_owned(),
            credential_account_id: "default".to_owned(),
            capabilities: if kind == ProviderKind::Custom {
                ProviderCapabilities::custom_openai_compatible_defaults()
            } else {
                ProviderCapabilities::chat_defaults()
            },
            options: kind.default_options(),
        }
    }

    pub fn thinking_enabled(&self) -> bool {
        match self.kind {
            ProviderKind::DeepSeek | ProviderKind::VolcengineArk => {
                self.options.thinking.unwrap_or(false)
            }
            ProviderKind::Qwen => self.options.enable_thinking.unwrap_or(false),
            ProviderKind::SiliconFlow => self
                .options
                .enable_thinking
                .or(self.options.thinking)
                .unwrap_or(false),
            ProviderKind::Custom => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    pub role: ChatMessageRole,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub stream: bool,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    #[serde(skip, default)]
    pub data_classification: privacy::DataClassification,
}

impl ChatRequest {
    pub fn connection_probe() -> Self {
        Self {
            messages: vec![
                ChatMessage {
                    role: ChatMessageRole::System,
                    content: "Return a short connection check response.".to_owned(),
                },
                ChatMessage {
                    role: ChatMessageRole::User,
                    content: "ping".to_owned(),
                },
            ],
            stream: true,
            temperature: Some(0.0),
            max_tokens: Some(64),
            data_classification: privacy::DataClassification::ProductPublic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatUsage {
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
    pub total_tokens: Option<u32>,
}

/// Visible result of one bounded, non-stream OpenAI-compatible chat
/// completion. Reasoning fields are intentionally absent from this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatCompletion {
    pub content: String,
    pub model: Option<String>,
    pub usage: Option<ChatUsage>,
}

impl fmt::Debug for ChatCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatCompletion")
            .field("content", &"<redacted>")
            .field("content_bytes", &self.content.len())
            .field("model", &self.model.as_ref().map(|_| "<redacted-present>"))
            .field("usage", &self.usage)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTestStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTest {
    pub status: ConnectionTestStatus,
    pub provider_id: String,
    pub http_status: Option<u16>,
    pub model: Option<String>,
    pub first_token_latency_ms: Option<u128>,
    pub total_latency_ms: u128,
    pub usage: Option<ChatUsage>,
    pub error_type: Option<String>,
    pub message: String,
}

impl ConnectionTest {
    pub fn succeeded(
        provider_id: impl Into<String>,
        http_status: u16,
        model: Option<String>,
        first_token_latency_ms: Option<u128>,
        total_latency_ms: u128,
        usage: Option<ChatUsage>,
    ) -> Self {
        Self {
            status: ConnectionTestStatus::Succeeded,
            provider_id: provider_id.into(),
            http_status: Some(http_status),
            model,
            first_token_latency_ms,
            total_latency_ms,
            usage,
            error_type: None,
            message: "connection_ok".to_owned(),
        }
    }

    pub fn failed(
        provider_id: impl Into<String>,
        http_status: Option<u16>,
        first_token_latency_ms: Option<u128>,
        total_latency_ms: u128,
        error: &ProviderError,
    ) -> Self {
        Self {
            status: ConnectionTestStatus::Failed,
            provider_id: provider_id.into(),
            http_status,
            model: None,
            first_token_latency_ms,
            total_latency_ms,
            usage: None,
            error_type: Some(error.kind.as_str().to_owned()),
            message: error.message.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    MissingCredential,
    InvalidProfile,
    InvalidRequest,
    Network,
    Timeout,
    Cancelled,
    ResponseTooLarge,
    Http,
    Parse,
    Credential,
}

impl ProviderErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidProfile => "invalid_profile",
            Self::InvalidRequest => "invalid_request",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::ResponseTooLarge => "response_too_large",
            Self::Http => "http",
            Self::Parse => "parse",
            Self::Credential => "credential",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message: String,
    pub http_status: Option<u16>,
}

impl ProviderError {
    pub fn new(kind: ProviderErrorKind, message: impl AsRef<str>) -> Self {
        Self {
            kind,
            message: truncate_for_log(message.as_ref(), 280),
            http_status: None,
        }
    }

    pub fn with_status(kind: ProviderErrorKind, status: u16, message: impl AsRef<str>) -> Self {
        Self {
            kind,
            message: truncate_for_log(message.as_ref(), 280),
            http_status: Some(status),
        }
    }
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("http_status", &self.http_status)
            .finish()
    }
}

impl Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind.as_str(), self.message)
    }
}

impl Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_serde_wire_contract_is_stable_and_unknown_values_fail_closed() {
        let cases = [
            (ProviderKind::DeepSeek, "deep_seek"),
            (ProviderKind::Qwen, "qwen"),
            (ProviderKind::SiliconFlow, "silicon_flow"),
            (ProviderKind::VolcengineArk, "volcengine_ark"),
            (ProviderKind::Custom, "custom"),
        ];

        for (kind, wire_value) in cases {
            assert_eq!(
                serde_json::to_value(kind).expect("provider kind serializes"),
                serde_json::Value::String(wire_value.to_owned())
            );
            assert_eq!(
                serde_json::from_value::<ProviderKind>(serde_json::Value::String(
                    wire_value.to_owned()
                ))
                .expect("known provider kind deserializes"),
                kind
            );
        }

        assert!(
            serde_json::from_value::<ProviderKind>(serde_json::Value::String(
                "future_provider".to_owned()
            ))
            .is_err()
        );
    }

    #[test]
    fn private_network_opt_in_is_explicit_and_legacy_compatible() {
        let default_options = ProviderOptions::default();
        let serialized = serde_json::to_value(&default_options).expect("options serialize");
        assert!(serialized.get("allowPrivateNetwork").is_none());

        let legacy: ProviderOptions = serde_json::from_value(serde_json::json!({
            "thinking": false
        }))
        .expect("legacy options without the field still deserialize");
        assert_eq!(legacy.allow_private_network, None);

        let opted_in: ProviderOptions = serde_json::from_value(serde_json::json!({
            "allowPrivateNetwork": true
        }))
        .expect("explicit opt-in deserializes");
        assert_eq!(opted_in.allow_private_network, Some(true));
    }

    #[test]
    fn thinking_state_uses_each_provider_contract_and_defaults_off() {
        let deepseek = ProviderProfile::new_default("deepseek", ProviderKind::DeepSeek);
        assert!(!deepseek.thinking_enabled());

        let mut qwen = ProviderProfile::new_default("qwen", ProviderKind::Qwen);
        qwen.options.enable_thinking = Some(true);
        assert!(qwen.thinking_enabled());

        let mut silicon = ProviderProfile::new_default("silicon", ProviderKind::SiliconFlow);
        silicon.options.enable_thinking = None;
        silicon.options.thinking = Some(true);
        assert!(silicon.thinking_enabled());

        let mut custom = ProviderProfile::new_default("custom", ProviderKind::Custom);
        custom.options.thinking = Some(true);
        assert!(!custom.thinking_enabled());
    }

    #[test]
    fn provider_error_redacts_debug_and_display() {
        let error = ProviderError::new(
            ProviderErrorKind::Network,
            "Authorization: Bearer lawyer-secret-9999",
        );

        assert!(!format!("{error:?}").contains("lawyer-secret-9999"));
        assert!(!error.to_string().contains("lawyer-secret-9999"));
        assert!(error.to_string().contains("<redacted>"));
    }
}
