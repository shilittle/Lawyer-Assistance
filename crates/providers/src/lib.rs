pub mod adapter;
pub mod credentials;
mod operation_lock;
pub mod redaction;
pub mod stream;
pub mod types;
pub mod windows_credentials;

pub use adapter::{
    authorize_approved_chat, parse_chat_completion, prepare_approved_chat,
    provider_endpoint_origin, ChatTransport, OpenAiCompatibleAdapter, ProviderAdapter,
    RequestCancellation, ReqwestStreamingTransport, ReqwestTransport, StreamingTransportResponse,
    TransportHeader, TransportRequest, TransportResponse, MAX_CHAT_COMPLETION_CONTENT_BYTES,
};
pub use credentials::{ApiSecret, CredentialStore, ProviderCredentialKey};
pub use operation_lock::ProviderStoreLock;
pub use redaction::redact_sensitive;
pub use stream::{StreamEvent, StreamParser};
pub use types::{
    ApprovedChatBinding, ApprovedChatDraft, ApprovedChatRequest, ChatCompletion, ChatMessage,
    ChatMessageRole, ChatRequest, ChatUsage, ConnectionTest, ConnectionTestStatus,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderKind, ProviderOptions,
    ProviderProfile, ReasoningEffort,
};
