pub mod adapter;
pub mod credentials;
pub mod redaction;
pub mod stream;
pub mod types;
pub mod windows_credentials;

pub use adapter::{
    ChatTransport, OpenAiCompatibleAdapter, RequestCancellation, ReqwestTransport, TransportHeader,
    TransportRequest, TransportResponse,
};
pub use credentials::{ApiSecret, CredentialStore, ProviderCredentialKey};
pub use redaction::redact_sensitive;
pub use stream::{StreamEvent, StreamParser};
pub use types::{
    ChatMessage, ChatMessageRole, ChatRequest, ChatUsage, ConnectionTest, ConnectionTestStatus,
    ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderKind, ProviderOptions,
    ProviderProfile, ReasoningEffort,
};
