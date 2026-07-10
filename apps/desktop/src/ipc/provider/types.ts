export type ProviderKind =
  | "deep_seek"
  | "qwen"
  | "silicon_flow"
  | "volcengine_ark";

export type ReasoningEffort = "low" | "medium" | "high";

export interface ProviderCapabilities {
  chat: boolean;
  streaming: boolean;
  customModelId: boolean;
  customBaseUrl: boolean;
  reasoning: boolean;
}

export interface ProviderOptions {
  thinking?: boolean | null;
  enableThinking?: boolean | null;
  thinkingBudget?: number | null;
  reasoningEffort?: ReasoningEffort | null;
  endpointId?: string | null;
  workspaceId?: string | null;
}

export interface ProviderProfile {
  id: string;
  displayName: string;
  kind: ProviderKind;
  modelId: string;
  baseUrl: string;
  credentialAccountId: string;
  capabilities: ProviderCapabilities;
  options: ProviderOptions;
}

export interface ProviderProfilesResponse {
  profiles: ProviderProfile[];
}

export interface UpsertProviderProfileRequest {
  profile: ProviderProfile;
}

export interface ProviderProfileResponse {
  profile: ProviderProfile;
}

export interface DeleteProviderProfileRequest {
  providerId: string;
}

export interface DeleteProviderProfileResponse {
  deleted: boolean;
  keyDeleted: boolean;
}

export interface ProviderApiKeyStatusRequest {
  providerId: string;
  accountId: string;
}

export interface ProviderApiKeyStatus {
  providerId: string;
  accountId: string;
  configured: boolean;
  maskedKey?: string | null;
}

export interface ProviderApiKeyStatusResponse {
  status: ProviderApiKeyStatus;
}

export interface WriteProviderApiKeyRequest {
  providerId: string;
  accountId: string;
  apiKey: string;
}

export interface DeleteProviderApiKeyRequest {
  providerId: string;
  accountId: string;
}

export interface TestProviderConnectionRequest {
  providerId: string;
}

export type ConnectionTestStatus = "succeeded" | "failed";

export interface ChatUsage {
  promptTokens?: number | null;
  completionTokens?: number | null;
  totalTokens?: number | null;
}

export interface ConnectionTest {
  status: ConnectionTestStatus;
  providerId: string;
  httpStatus?: number | null;
  model?: string | null;
  firstTokenLatencyMs?: number | null;
  totalLatencyMs: number;
  usage?: ChatUsage | null;
  errorType?: string | null;
  message: string;
}

export interface TestProviderConnectionResponse {
  result: ConnectionTest;
}
