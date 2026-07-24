use crate::{
    registry::ToolRegistry,
    service_adapter::{InFlightOperations, ServiceAdapter},
};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, Implementation, InitializeRequestParams,
        InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    ErrorData, RoleServer, ServerHandler,
};

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
}

impl ServerHandler for LegalMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        let profile_instructions = match self.registry.profile() {
            crate::registry::PrivacyProfile::PublicLawOnly => {
                "Public-law-only profile. Strict rule (\u{4e25}\u{7981}): never request, read, upload, or relay raw case material. Case and document tools are unavailable. Both MCP result channels are privacy-scanned."
            }
            crate::registry::PrivacyProfile::RedactedCase => {
                "Redacted-case profile. Only citation_validate is added, and every call requires an App-issued rct_v1 receipt bound to the exact approved CitationValidateRequest bytes, ExternalMcpHost destination, fixed purpose, and TTL. Page-material receipts cannot be reused. If the Windows receipt key or persisted receipt state is unavailable, the tool remains listed but every call fails closed. Raw OCR, paths, case state, writes, generation, and export remain unavailable. Both result channels are privacy-scanned."
            }
            crate::registry::PrivacyProfile::ApprovedCaseWorkspace => {
                "Approved-case-workspace profile. Ten opaque-ID-only case and work-product tools execute only through signed approved generations and exact App-signed read/write grants. Send only each tool's declared business arguments: access_ticket is an internal broker capability and is rejected on the host wire. The broker validates the live descriptor, qualification, revocation epoch, transport, JSON-RPC request identity, canonical request, tool and purpose before issuing and immediately consuming a one-time internal ticket. Missing qualification, grant mismatch, expiry, revocation, binding mismatch, or replay fails closed. Paths, filenames, raw OCR, pending review content, private mappings, and vault diagnostics are never accepted. Both result channels are independently privacy-scanned."
            }
        };

        ServerInfo::new(capabilities)
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(
                Implementation::new("lawyer-assistance-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("Lawyer Assistance MCP")
                    .with_description(
                        "Local-first offline public-law research with optional receipt-gated citation validation",
                    ),
            )
            .with_instructions(
                [
                "本服务当前只公开离线法规检索工具。严禁读取、上传、转发或要求用户粘贴任何未经脱敏的案件材料、当事人信息或法律文书；案件与文书工具在完成本地脱敏审核门禁前不可用。content 与 structuredContent 仍须经过本地隐私边界检查，引用结论需人工复核。",
                    profile_instructions,
                ]
                .join("\n\n"),
            )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        // This server deliberately supports only the latest stable protocol.
        // Unsupported older, future, and RC versions negotiate down to it.
        context.peer.set_peer_info(request);
        Ok(self.get_info())
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.and_then(|request| request.cursor).is_some() {
            return Err(ErrorData::invalid_params(
                "功能列表无需翻页，请移除翻页参数。",
                None,
            ));
        }
        Ok(ListToolsResult::with_all_items(self.registry.list()))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.registry.get(name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut request_params = serde_json::to_value(&request)
            .map_err(|_| ErrorData::invalid_params("Invalid tools/call params.", None))?;
        let request_meta = serde_json::to_value(&context.meta)
            .map_err(|_| ErrorData::invalid_params("Invalid tools/call metadata.", None))?;
        if request_meta
            .as_object()
            .is_some_and(|meta| !meta.is_empty())
        {
            request_params
                .as_object_mut()
                .ok_or_else(|| ErrorData::invalid_params("Invalid tools/call params.", None))?
                .insert("_meta".to_owned(), request_meta);
        }
        let name = request.name.into_owned();
        if self.registry.get(&name).is_none() {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "未识别的功能请求。",
                None,
            ));
        }
        let request_id = serde_json::to_value(context.id)
            .map_err(|_| ErrorData::invalid_params("Invalid JSON-RPC request id.", None))?;
        self.adapter
            .call_with_request_id(
                &name,
                request.arguments,
                Some(request_id),
                Some(request_params),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PrivacyProfile;

    const ABSOLUTE_RAW_CASE_BAN: &str =
        "\u{4e25}\u{7981}\u{8bfb}\u{53d6}\u{3001}\u{4e0a}\u{4f20}\u{3001}\u{8f6c}\u{53d1}";

    fn server_info_for_profile(profile: PrivacyProfile) -> ServerInfo {
        let directory = tempfile::tempdir().expect("temporary service root");
        let services = legal_services::LegalServices::new(legal_services::ServiceConfig {
            legal_core_path: directory.path().join("legal.sqlite"),
            user_database_path: directory.path().join("user.sqlite"),
            allowed_file_roots: Vec::new(),
            allowed_output_root: directory.path().to_path_buf(),
        })
        .expect("valid test service configuration");
        let server = LegalMcpServer::new(
            ToolRegistry::for_profile(profile),
            ServiceAdapter::for_profile(services, profile),
        );
        server.get_info()
    }

    #[test]
    fn public_law_only_server_info_keeps_absolute_ban_and_profile_constraints() {
        let info = server_info_for_profile(PrivacyProfile::PublicLawOnly);
        assert_eq!(info.protocol_version.as_str(), STABLE_PROTOCOL_VERSION);
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.prompts.is_none());
        assert!(info.capabilities.resources.is_none());
        assert!(info.capabilities.tasks.is_none());
        assert!(info.capabilities.experimental.is_none());

        let instructions = info.instructions.as_deref().expect("server instructions");
        assert!(instructions.contains(ABSOLUTE_RAW_CASE_BAN));
        assert!(instructions.contains("Public-law-only profile"));
        assert!(instructions.contains("never request, read, upload, or relay raw case material"));
        assert!(instructions.contains("Case and document tools are unavailable"));
        assert!(!instructions.contains("Redacted-case profile"));
    }

    #[test]
    fn redacted_case_server_info_keeps_absolute_ban_and_receipt_constraints() {
        let info = server_info_for_profile(PrivacyProfile::RedactedCase);
        let instructions = info.instructions.as_deref().expect("server instructions");

        assert!(instructions.contains(ABSOLUTE_RAW_CASE_BAN));
        assert!(instructions.contains("Redacted-case profile"));
        assert!(instructions.contains("Only citation_validate is added"));
        assert!(instructions.contains("rct_v1"));
        assert!(instructions.contains("ExternalMcpHost"));
        assert!(instructions.contains("every call fails closed"));
        assert!(instructions.contains(
            "Raw OCR, paths, case state, writes, generation, and export remain unavailable"
        ));
        assert!(!instructions.contains("Public-law-only profile"));
    }
}
