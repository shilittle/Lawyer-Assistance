import type {
  AssistantArtifact,
  AssistantCaseChangeProposal,
  AssistantRun,
  AssistantRunBudget,
  AssistantRunEvent,
} from "../assistant/types";

export type CaseAssistantConversationStatus = "open" | "archived";

export interface CaseAssistantConversation {
  conversationId: string;
  projectId: string;
  title: string;
  status: CaseAssistantConversationStatus;
  createdAt: string;
  updatedAt: string;
}

export interface CaseAssistantMessage {
  messageId: string;
  conversationId: string;
  role: "user" | "assistant";
  textSummary: string;
  runId: string | null;
  createdAt: string;
}

export type CaseAssistantOutputKind =
  | "case_analysis"
  | "case_document"
  | "case_diagram";

export type CaseAssistantPendingOutputStatus =
  | "pending"
  | "confirmed";

export interface CaseAssistantPendingOutput {
  pendingOutputId: string;
  projectId: string;
  conversationId: string;
  runId: string;
  outputKind: CaseAssistantOutputKind;
  preview: string;
  outputSha256: string;
  version: number;
  workspaceDigest: string;
  status: CaseAssistantPendingOutputStatus;
  createdAt: string;
  confirmedAt: string | null;
  artifactId: string | null;
  proposalId: string | null;
}

/**
 * Case-facing metadata projection. The authoritative hashes, risk head,
 * Privacy identity and approved payload never cross into the frontend.
 */
export interface CaseAssistantGeneration {
  redactionGenerationId: string;
  materialId: string;
  generationNumber: number;
  mediaType: string;
  pageCount: number;
  approvedAt: string;
  selected: boolean;
  displayName: string;
}

export interface CaseAssistantConversationDetail {
  conversation: CaseAssistantConversation;
  messages: CaseAssistantMessage[];
  runs: AssistantRun[];
  pendingOutputs: CaseAssistantPendingOutput[];
}

export interface CreateCaseAssistantConversationRequest {
  projectId: string;
  title: string;
}

export interface CreateCaseAssistantConversationResponse {
  conversation: CaseAssistantConversation;
}

export interface ListCaseAssistantConversationsRequest {
  projectId: string;
  limit?: number | null;
}

export interface ListCaseAssistantConversationsResponse {
  conversations: CaseAssistantConversation[];
}

export interface GetCaseAssistantConversationRequest {
  projectId: string;
  conversationId: string;
}

export interface GetCaseAssistantConversationResponse {
  detail: CaseAssistantConversationDetail;
}

export interface ListCaseAssistantGenerationsRequest {
  projectId: string;
}

export interface ListCaseAssistantGenerationsResponse {
  generations: CaseAssistantGeneration[];
}

export interface StartCaseAssistantRunRequest {
  runId: string;
  conversationId: string;
  projectId: string;
  providerId: string;
  prompt: string;
  redactionGenerationIds: string[];
  outputKind: CaseAssistantOutputKind;
  budget?: AssistantRunBudget | null;
}

export interface StartCaseAssistantRunResponse {
  run: AssistantRun;
  pendingOutput: CaseAssistantPendingOutput;
}

export interface CancelCaseAssistantRunRequest {
  runId: string;
}

export interface CancelCaseAssistantRunResponse {
  runId: string;
  cancelled: boolean;
}

export interface ListCaseAssistantPendingOutputsRequest {
  projectId: string;
  conversationId?: string | null;
}

export interface ListCaseAssistantPendingOutputsResponse {
  pendingOutputs: CaseAssistantPendingOutput[];
}

export interface ConfirmCaseAssistantOutputRequest {
  projectId: string;
  pendingOutputId: string;
  expectedVersion: number;
  expectedOutputSha256: string;
  expectedWorkspaceDigest: string;
  userConfirmed: true;
}

export interface ConfirmCaseAssistantOutputResponse {
  pendingOutput: CaseAssistantPendingOutput;
  artifact?: AssistantArtifact | null;
  proposal?: AssistantCaseChangeProposal | null;
  applied: true;
}

export type CaseAssistantRunEvent = AssistantRunEvent;
export type CaseAssistantRunBudget = AssistantRunBudget;
