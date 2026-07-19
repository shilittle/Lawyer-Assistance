use rmcp::{
    model::{ClientRequest, JsonRpcMessage, ProtocolVersion},
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
    RoleServer,
};
use std::future::Future;

/// Transport boundary that prevents the SDK's broader version table from
/// advertising release candidates supported by the dependency but not by this
/// product. MCP initialization still negotiates normally; the server simply
/// presents its sole supported version to rmcp's negotiation layer.
#[derive(Debug)]
pub struct StableProtocolTransport<T> {
    inner: T,
}

impl<T> StableProtocolTransport<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> Transport<RoleServer> for StableProtocolTransport<T>
where
    T: Transport<RoleServer>,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        let mut message = self.inner.receive().await?;
        if let JsonRpcMessage::Request(request) = &mut message {
            if let ClientRequest::InitializeRequest(initialize) = &mut request.request {
                initialize.params.protocol_version = ProtocolVersion::V_2025_11_25;
            }
        }
        Some(message)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}
