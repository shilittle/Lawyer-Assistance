use crate::{
    http::HttpClientScope,
    registry::{PrivacyProfile, ToolRegistry},
    service_adapter::{InFlightOperations, ServiceAdapter},
};
use axum::http::{header::AUTHORIZATION, request::Parts};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, Implementation, InitializeRequestParams,
        InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    ErrorData, RoleServer, ServerHandler,
};
use tokio_util::sync::CancellationToken;

pub const STABLE_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug, Clone)]
pub struct LegalMcpServer {
    registry: ToolRegistry,
    adapter: ServiceAdapter,
}

impl LegalMcpServer {
    pub fn new(registry: ToolRegistry, adapter: ServiceAdapter) -> Self {
        Self { registry, adapter }
    }

    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    pub(crate) fn in_flight_operations(&self) -> InFlightOperations {
        self.adapter.in_flight_operations()
    }

    fn registry_for_context(&self, context: &RequestContext<RoleServer>) -> ToolRegistry {
        if self.registry.profile() == PrivacyProfile::PrivacyWorkspace
            && request_scope(context) == Some(HttpClientScope::Public)
        {
            ToolRegistry::for_profile(PrivacyProfile::PublicLawOnly)
        } else {
            self.registry.clone()
        }
    }
}

impl ServerHandler for LegalMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        let instructions = match self.registry.profile() {
            PrivacyProfile::PublicLawOnly => {
                "Public-law-only profile. Strict rule: never request, read, upload, or relay private case material. Seven local legal and Supreme People's Court case-research tools are available."
            }
            PrivacyProfile::PrivacyWorkspace => {
                "Privacy-workspace profile. The seven local legal and Supreme People's Court case-research tools remain available. Three workspace tools call only the local backend with the current client's bearer authorization. They accept no original-text read, mapping, manual approval, or cloud-authorization operation, and return only published redacted results."
            }
            PrivacyProfile::RedactedCase
            | PrivacyProfile::ApprovedCaseWorkspace
            | PrivacyProfile::DiagramAuthoring => "This profile is disabled.",
        };
        ServerInfo::new(capabilities)
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(
                Implementation::new("lawyer-assistance-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("Lawyer Assistance MCP")
                    .with_description("Local-first legal research and published-redaction workspace access"),
            )
            .with_instructions(
                [
                    "严禁读取、上传、转发或要求用户粘贴未经脱敏的案件材料、当事人信息或法律文书。公开法规检索不使用互联网；脱敏工作区只能读取已发布的脱敏文本。",
                    instructions,
                ]
                .join("\n\n"),
            )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        context.peer.set_peer_info(request);
        Ok(self.get_info())
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.and_then(|request| request.cursor).is_some() {
            return Err(ErrorData::invalid_params(
                "功能列表无需翻页，请移除翻页参数。",
                None,
            ));
        }
        Ok(ListToolsResult::with_all_items(
            self.registry_for_context(&context).list(),
        ))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.registry.get(name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = request.name.into_owned();
        if self.registry_for_context(&context).get(&name).is_none() {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "未识别的功能请求。",
                None,
            ));
        }
        let authorization = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.headers.get(AUTHORIZATION))
            .and_then(|value| value.to_str().ok());
        let cancellation = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<CancellationToken>())
            .cloned()
            .unwrap_or_else(CancellationToken::new);
        self.adapter
            .call_with_request_id(&name, request.arguments, authorization, cancellation)
            .await
    }
}

fn request_scope(context: &RequestContext<RoleServer>) -> Option<HttpClientScope> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<HttpClientScope>())
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_adapter::ServiceAdapter;
    use legal_services::LegalServices;
    use std::path::PathBuf;

    #[test]
    fn info_advertises_only_the_new_profile_contracts() {
        let service = LegalServices::new_public(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legal.sqlite"),
        )
        .expect("service");
        let server = LegalMcpServer::new(
            ToolRegistry::for_profile(PrivacyProfile::PublicLawOnly),
            ServiceAdapter::new(service),
        );
        let instructions = server.get_info().instructions.expect("instructions");
        assert!(instructions.contains("Seven local"));
        assert_eq!(
            server.get_info().protocol_version.as_str(),
            STABLE_PROTOCOL_VERSION
        );
    }
}
