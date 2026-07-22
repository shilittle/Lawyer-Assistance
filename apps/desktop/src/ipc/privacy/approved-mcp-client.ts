import { invoke } from "@tauri-apps/api/core";

export type ApprovedMcpConnectorId = "workbuddy" | "codex" | "opencode";
export type ApprovedMcpTransport = "stdio" | "streamable_http";
export type ApprovedMcpGrantGroup = "read" | "write";

export interface ApprovedPrivacyReviewSelection {
  redactionId: string;
  materialId: string;
  mcpPublishApproved: boolean;
  mcpPublishApprovalExpiresAtUnix: number | null;
  caseId: string;
  approvedPayloadSha256: string;
}

export interface ApproveReviewForApprovedWorkspaceRequest {
  redactionId: string;
  expectedApprovedPayloadSha256: string;
  reviewer: string;
  ttlSeconds: number;
  confirmed: boolean;
}

export interface ApproveReviewForApprovedWorkspaceResponse {
  receiptId: string;
  approvedPayloadSha256: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  destinationIdentifier: string;
  purpose: string;
  mcpPublishApproved: boolean;
}

export interface ApprovedMcpToolGrant {
  toolName: string;
  purpose: string;
}

export interface PublishApprovedGenerationRequest {
  redactionId: string;
  caseId: string;
  expectedApprovedPayloadSha256: string;
}

export interface PublishedApprovedGeneration {
  caseId: string;
  materialId: string;
  documentVersion: number;
  publicationId: string;
  contentSha256: string;
  manifestSha256: string;
}

export interface ApprovedGenerationHistory {
  caseId: string;
  materialId: string;
  documentVersion: number;
  publicationId: string;
  manifestSha256: string;
  contentSha256: string;
  createdAtUnix: number;
  committedAtUnix: number;
  revokedAtUnix: number | null;
  revocationEpoch: number;
}

export interface ApprovedMcpQualificationStatus {
  qualified: boolean;
  reasonCode: string;
  evidenceId: string | null;
  evidenceSha256: string | null;
  stdioCanaryPassed: boolean;
  streamableHttpCanaryPassed: boolean;
  exactAppPolicyBinding: boolean;
  exactServerKeyBinding: boolean;
  appVersion: string;
  policyId: string;
  policyVersion: number;
  serverKeyId: string | null;
  serverKeyVersion: number;
  revocationEpoch: number | null;
  issuedAtUnix: number | null;
  expiresAtUnix: number | null;
  revoked: boolean;
}

export interface StandaloneApprovedMcpSessionMetadata {
  descriptorId: string;
  connectorId: string;
  workspaceInstanceId: string;
  serverInstanceId: string;
  sessionId: string;
  transport: ApprovedMcpTransport;
  grantGroups: ApprovedMcpGrantGroup[];
  grants: ApprovedMcpToolGrant[];
  endpoint: string | null;
  qualificationEvidenceId: string;
  qualificationEvidenceSha256: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  active: boolean;
  reasonCode: string;
}

export interface ProvisionedStandaloneApprovedMcpSession {
  session: StandaloneApprovedMcpSessionMetadata;
  oneTimeHttpBearer?: string;
}

export interface CreateStandaloneApprovedMcpSessionRequest {
  connectorId: ApprovedMcpConnectorId;
  transport: ApprovedMcpTransport;
  grantGroups: ApprovedMcpGrantGroup[];
  ttlSeconds: number;
  httpPort: number | null;
  allowedOrigins: string[];
}

export function listApprovedPrivacyReviewSelections(): Promise<
  ApprovedPrivacyReviewSelection[]
> {
  return invoke<ApprovedPrivacyReviewSelection[]>("list_approved_privacy_review_selections");
}

export function publishApprovedGeneration(
  request: PublishApprovedGenerationRequest,
): Promise<PublishedApprovedGeneration> {
  return invoke<PublishedApprovedGeneration>("publish_approved_generation", { request });
}

export function approveReviewForApprovedWorkspace(
  request: ApproveReviewForApprovedWorkspaceRequest,
): Promise<ApproveReviewForApprovedWorkspaceResponse> {
  return invoke<ApproveReviewForApprovedWorkspaceResponse>(
    "approve_review_for_approved_workspace",
    { request },
  );
}

export function listApprovedGenerations(
  caseId?: string,
): Promise<ApprovedGenerationHistory[]> {
  return invoke<ApprovedGenerationHistory[]>("list_approved_generations", {
    request: { caseId: caseId || null },
  });
}

export function revokeApprovedGeneration(
  generation: Pick<
    ApprovedGenerationHistory,
    "caseId" | "materialId" | "documentVersion" | "publicationId"
  >,
): Promise<void> {
  return invoke<void>("revoke_approved_generation", {
    request: {
      caseId: generation.caseId,
      materialId: generation.materialId,
      documentVersion: generation.documentVersion,
      publicationId: generation.publicationId,
    },
  });
}

export function runApprovedMcpQualification(
  ttlSeconds: number,
): Promise<ApprovedMcpQualificationStatus> {
  return invoke<ApprovedMcpQualificationStatus>("run_approved_mcp_qualification", {
    request: { ttlSeconds },
  });
}

export function getApprovedMcpQualificationStatus(): Promise<ApprovedMcpQualificationStatus> {
  return invoke<ApprovedMcpQualificationStatus>("get_approved_mcp_qualification_status");
}

export function revokeApprovedMcpQualification(): Promise<ApprovedMcpQualificationStatus> {
  return invoke<ApprovedMcpQualificationStatus>("revoke_approved_mcp_qualification");
}

export function createStandaloneApprovedMcpSession(
  request: CreateStandaloneApprovedMcpSessionRequest,
): Promise<ProvisionedStandaloneApprovedMcpSession> {
  return invoke<ProvisionedStandaloneApprovedMcpSession>(
    "create_standalone_approved_mcp_session",
    { request },
  );
}

export function listStandaloneApprovedMcpSessions(): Promise<
  StandaloneApprovedMcpSessionMetadata[]
> {
  return invoke<StandaloneApprovedMcpSessionMetadata[]>(
    "list_standalone_approved_mcp_sessions",
  );
}

export function revokeStandaloneApprovedMcpSession(
  serverInstanceId: string,
): Promise<void> {
  return invoke<void>("revoke_standalone_approved_mcp_session", {
    request: { serverInstanceId },
  });
}
