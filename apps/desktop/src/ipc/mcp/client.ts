import { invoke } from "@tauri-apps/api/core";

import type {
  DeleteMcpBearerTokenRequest,
  McpServerConfigResponse,
  McpServerStatus,
  SaveMcpServerConfigRequest,
  WriteMcpBearerTokenRequest,
} from "./types";

export function getMcpServerConfig(): Promise<McpServerConfigResponse> {
  return invoke<McpServerConfigResponse>("get_mcp_server_config");
}

export function saveMcpServerConfig(
  request: SaveMcpServerConfigRequest,
): Promise<McpServerConfigResponse> {
  return invoke<McpServerConfigResponse>("save_mcp_server_config", {
    request,
  });
}

export function getMcpServerStatus(): Promise<McpServerStatus> {
  return invoke<McpServerStatus>("get_mcp_server_status");
}

export function startMcpServer(): Promise<McpServerStatus> {
  return invoke<McpServerStatus>("start_mcp_server");
}

export function stopMcpServer(): Promise<McpServerStatus> {
  return invoke<McpServerStatus>("stop_mcp_server");
}

export function writeMcpBearerToken(
  request: WriteMcpBearerTokenRequest,
): Promise<McpServerConfigResponse> {
  return invoke<McpServerConfigResponse>("write_mcp_bearer_token", {
    request,
  });
}

export function deleteMcpBearerToken(
  request: DeleteMcpBearerTokenRequest,
): Promise<McpServerConfigResponse> {
  return invoke<McpServerConfigResponse>("delete_mcp_bearer_token", {
    request,
  });
}
