export const MCP_SERVER_CONFIG_SCHEMA_VERSION = 1;

export interface McpServerConfig {
  schemaVersion: number;
  autoStart: boolean;
  port: number;
  allowedRoots: string[];
  outputRoot: string;
  allowedOrigins: string[];
  maxBodyBytes: number;
  requestTimeoutMs: number;
  maxConcurrency: number;
}

export interface McpServerConfigResponse {
  config: McpServerConfig;
  legalDatabasePath: string;
  userDatabasePath: string;
  bearerTokenConfigured: boolean;
  bearerTokenMasked: string | null;
}

export interface SaveMcpServerConfigRequest {
  config: McpServerConfig;
}

export type McpServerPhase =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "failed";

export interface McpServerStatus {
  phase: McpServerPhase;
  endpoint: string | null;
  startedAt: string | null;
  lastError: string | null;
}

export interface WriteMcpBearerTokenRequest {
  token: string;
}

export interface DeleteMcpBearerTokenRequest {
  userConfirmed: true;
}

export interface McpServerConfigDraft {
  autoStart: boolean;
  port: string;
  allowedRoots: string;
  outputRoot: string;
  allowedOrigins: string;
  maxBodyBytes: string;
  requestTimeoutMs: string;
  maxConcurrency: string;
}
