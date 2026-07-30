import type { CitationValidationReport } from "../legal/types";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

export type AssistantCapabilityName =
  | "assistant.interactive_chat"
  | "legal.search"
  | "legal.read"
  | "file.import"
  | "file.extract"
  | "case.read"
  | "case.propose_changes"
  | "case.apply_changes"
  | "document.draft"
  | "document.render"
  | "map.build";

export type AssistantCapabilityErrorType =
  | "invalid_input"
  | "not_found"
  | "permission_denied"
  | "limit_exceeded"
  | "cancelled"
  | "conflict"
  | "unsupported"
  | "provider_failure"
  | "citation_validation_failed"
  | "confirmation_required"
  | "internal";

export type AssistantAuditField =
  | "request_id"
  | "run_id"
  | "capability"
  | "input_ids"
  | "input_hashes"
  | "input_counts"
  | "output_ids"
  | "output_counts"
  | "source_refs"
  | "provider_snapshot"
  | "status"
  | "timing"
  | "error_type"
  | "confirmation";

export interface AssistantCapabilityDescriptor {
  name: AssistantCapabilityName;
  version: string;
  access: { read: boolean; write: boolean };
  requiresUserConfirmation: boolean;
  cancellable: boolean;
  maxInputBytes: number;
  maxOutputBytes: number;
  maxCallsPerRun: number;
  allowedErrorTypes: AssistantCapabilityErrorType[];
  auditFields: AssistantAuditField[];
}

export interface AssistantRunBudget {
  maxToolCalls: number;
  maxProviderRoundTrips: number;
  maxInputBodyBytes: number;
  maxVisibleAttachments: number;
  maxModelResponseBytes: number;
}

export interface AssistantCapabilitiesResponse {
  capabilities: AssistantCapabilityDescriptor[];
  defaultBudget: AssistantRunBudget;
}

export type AssistantConversationStatus = "open" | "archived";

export interface AssistantConversation {
  conversationId: string;
  projectId: string | null;
  title: string;
  status: AssistantConversationStatus;
  createdAt: string;
  updatedAt: string;
}

export type AssistantMessageRole = "user" | "assistant" | "system" | "tool";
export type AssistantMessageKind = "text" | "artifact_ref" | "proposal_ref";
export type AssistantAttachmentExtractionStatus =
  | "pending"
  | "succeeded"
  | "failed"
  | "unsupported";

export interface AssistantAttachment {
  attachmentId: string;
  projectId: string | null;
  originalName: string;
  extension: string;
  detectedMime: string;
  sha256: string;
  sizeBytes: number;
  extractionStatus: AssistantAttachmentExtractionStatus;
  errorCode: string | null;
  segmentCount: number;
  createdAt: string;
}

export interface AssistantMessage {
  messageId: string;
  conversationId: string;
  role: AssistantMessageRole;
  kind: AssistantMessageKind;
  textSummary: string;
  artifactId: string | null;
  runId: string | null;
  createdAt: string;
  attachments: AssistantAttachment[];
}

export interface AssistantLegalSource {
  sourceId: string;
  articleId: string;
  documentId: string;
  versionId: string;
  documentTitle: string;
  versionLabel: string;
  articleNumber: string;
  articleTitle: string | null;
  canonicalLabel: string;
  content: string;
  snippet: string;
  effectiveFrom: string;
  effectiveTo: string | null;
  versionStatus: string;
}

export interface AssistantConversationSource {
  sourceId: string;
  source: AssistantLegalSource | null;
  createdAt: string;
}

export type AssistantArtifactKind = "research" | "document" | "map";
export type AssistantArtifactStatus = "draft" | "final" | "archived";

export interface AssistantArtifact {
  artifactId: string;
  conversationId: string | null;
  projectId: string | null;
  kind: AssistantArtifactKind;
  title: string;
  status: AssistantArtifactStatus;
  currentVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface AssistantArtifactVersion {
  versionId: string;
  artifactId: string;
  versionNumber: number;
  content: JsonValue;
  renderedText: string;
  sourceRefs: string[];
  citationReport: JsonValue;
  providerSnapshot: JsonValue;
  createdAt: string;
}

export type AssistantRunStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface AssistantToolCall {
  toolCallId: string;
  runId: string;
  ordinal: number;
  capabilityName: AssistantCapabilityName;
  status: AssistantRunStatus;
  accessMode: "read" | "write";
  requiresConfirmation: boolean;
  inputAudit: JsonValue;
  outputAudit: JsonValue;
  sourceAudit: JsonValue;
  errorType: string | null;
  startedAt: string;
  finishedAt: string | null;
}

export interface AssistantRun {
  runId: string;
  conversationId: string;
  userMessageId: string;
  assistantMessageId: string | null;
  providerId: string | null;
  providerSnapshot: JsonValue;
  intent: string;
  status: AssistantRunStatus;
  budget: AssistantRunBudget;
  errorType: string | null;
  createdAt: string;
  finishedAt: string | null;
  toolCalls: AssistantToolCall[];
}

export interface FactAddition {
  id: string;
  statement: string;
  occurredOn: string | null;
  sourceRefs: string[];
}

export interface EvidenceAddition {
  id: string;
  title: string;
  summary: string;
  provesFactIds: string[];
  sourceRefs: string[];
}

export interface IssueAddition {
  id: string;
  title: string;
  analysis: string;
  relatedFactIds: string[];
  sourceRefs: string[];
}

export interface LegalBasisAddition {
  id: string;
  issueIds: string[];
  sourceRef: string;
  marker: string;
  citation: string;
  proposition: string;
}

export interface AttachmentTransfer {
  attachmentId: string;
  title: string;
}

export interface ArtifactTransfer {
  artifactId: string;
  title: string;
}

export interface CaseChangeSpec {
  schemaVersion: number;
  facts: FactAddition[];
  evidence: EvidenceAddition[];
  issues: IssueAddition[];
  legalBasis: LegalBasisAddition[];
  attachmentTransfers: AttachmentTransfer[];
  artifactTransfers: ArtifactTransfer[];
}

export type AssistantProposalStatus =
  | "pending"
  | "applied"
  | "rejected"
  | "stale";

export interface AssistantCaseChangeProposal {
  proposalId: string;
  conversationId: string;
  projectId: string;
  runId: string | null;
  baseCaseDigest: string;
  status: AssistantProposalStatus;
  changes: CaseChangeSpec;
  sourceRefs: string[];
  createdAt: string;
  decidedAt: string | null;
  appliedAt: string | null;
}

export interface AssistantConversationDetail {
  conversation: AssistantConversation;
  messages: AssistantMessage[];
  sources: AssistantConversationSource[];
  artifacts: AssistantArtifact[];
  runs: AssistantRun[];
  proposals: AssistantCaseChangeProposal[];
}

export interface ListAssistantConversationsRequest {
  projectId?: string | null;
  includeArchived?: boolean | null;
  limit?: number | null;
}

export interface ListAssistantConversationsResponse {
  conversations: AssistantConversation[];
}

export interface CreateAssistantConversationRequest {
  title: string;
  projectId?: string | null;
}

export interface AssistantConversationResponse {
  conversation: AssistantConversation;
}

export interface AssistantConversationIdRequest {
  conversationId: string;
}

export interface GetAssistantConversationResponse {
  detail: AssistantConversationDetail;
}

export interface BindAssistantConversationRequest {
  conversationId: string;
  projectId: string;
}

export interface AddAssistantLegalSourceRequest {
  conversationId: string;
  sourceId: string;
}

export interface ProposeAssistantLegalBasisRequest {
  conversationId: string;
  projectId: string;
  sourceId: string;
}

export interface AssistantConversationSourceResponse {
  source: AssistantConversationSource;
}

export interface ListAssistantArtifactsRequest {
  conversationId?: string | null;
  limit?: number | null;
}

export interface ListAssistantArtifactsResponse {
  artifacts: AssistantArtifact[];
}

export interface GetAssistantArtifactRequest {
  artifactId: string;
}

export interface GetAssistantArtifactResponse {
  artifact: AssistantArtifact;
  versions: AssistantArtifactVersion[];
}

export interface BindAssistantArtifactRequest {
  artifactId: string;
  projectId: string;
  userConfirmed: boolean;
}

export interface AssistantArtifactResponse {
  artifact: AssistantArtifact;
}

export interface ResearchArtifactSpec {
  schemaVersion: number;
  title: string;
  answer: string;
  sourceRefs: string[];
  assumptions: string[];
  missingInformation: string[];
  riskWarnings: string[];
}

export type DocumentType =
  | "contract"
  | "complaint"
  | "defence"
  | "evidence_schedule"
  | "fact_timeline"
  | "legal_research_report"
  | "lawyer_letter";
export type SourceMaterialKind = "user_material" | "confirmed_case";
export type ProvenanceKind =
  | "user_material"
  | "confirmed_case"
  | "model_wording"
  | "local_legal_source";

export interface ProvenanceRef {
  kind: ProvenanceKind;
  sourceRef: string | null;
}

export interface DocumentParty {
  id: string;
  name: string;
  role: string;
  details: string | null;
  provenance: ProvenanceRef[];
}

export interface DocumentClause {
  id: string;
  heading: string | null;
  body: string;
  factual: boolean;
  provenance: ProvenanceRef[];
}

export interface DocumentSection {
  id: string;
  heading: string;
  body: string;
  factual: boolean;
  provenance: ProvenanceRef[];
  clauses: DocumentClause[];
}

export interface DocumentAssumption {
  text: string;
  provenance: ProvenanceRef[];
}

export interface MissingInformation {
  description: string;
}

export interface SourceMaterial {
  id: string;
  kind: SourceMaterialKind;
  label: string;
  locator: string | null;
}

export interface LegalCitation {
  id: string;
  sourceRef: string;
  marker: string;
  citation: string;
  proposition: string;
}

export interface DocumentSpec {
  schemaVersion: number;
  documentType: DocumentType;
  title: string;
  parties: DocumentParty[];
  sections: DocumentSection[];
  assumptions: DocumentAssumption[];
  missingInformation: MissingInformation[];
  sourceMaterials: SourceMaterial[];
  legalCitations: LegalCitation[];
  riskWarnings: string[];
}

export type MapLayoutHint = "mindmap" | "layered" | "radial";

export interface MapNode {
  id: string;
  label: string;
  summary: string;
  parentId: string | null;
  sourceRefs: string[];
}

export interface MapEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  relation: string;
  sourceRefs: string[];
}

export interface MapSpec {
  schemaVersion: number;
  title: string;
  layoutHint: MapLayoutHint;
  nodes: MapNode[];
  edges: MapEdge[];
}

export type AssistantArtifactDraft =
  | { kind: "research"; spec: ResearchArtifactSpec }
  | { kind: "document"; spec: DocumentSpec }
  | { kind: "map"; spec: MapSpec };

export interface SaveAssistantArtifactRequest {
  conversationId: string;
  artifactId?: string | null;
  expectedCurrentVersion?: number | null;
  title: string;
  draft: AssistantArtifactDraft;
}

export interface SaveAssistantArtifactResponse {
  detail: GetAssistantArtifactResponse;
}

export type AssistantArtifactExportFormat =
  | "research_markdown"
  | "document_markdown"
  | "document_docx"
  | "map_summary";

export interface ExportAssistantArtifactRequest {
  artifactId: string;
  versionNumber: number;
  format: AssistantArtifactExportFormat;
}

export interface ExportAssistantArtifactResponse {
  cancelled: boolean;
  fileName: string | null;
  format: AssistantArtifactExportFormat;
  byteLen: number;
}

export interface ImportAssistantFilesRequest {
  conversationId: string;
}

export interface ImportAssistantFilesResponse {
  cancelled: boolean;
  duplicateCount: number;
  message: AssistantMessage | null;
  attachments: AssistantAttachment[];
}

export interface DeleteAssistantAttachmentRequest {
  conversationId: string;
  attachmentId: string;
  userConfirmed: boolean;
}

export interface DeleteAssistantAttachmentResponse {
  attachmentId: string;
  deleted: boolean;
}

export interface CancelAssistantRunRequest {
  runId: string;
}

export interface CancelAssistantRunResponse {
  runId: string;
  cancelled: boolean;
}

export type AssistantRunIntent =
  | "legal_research"
  | "file_analysis"
  | "document_draft"
  | "map_build"
  | "case_analysis";

export interface StartAssistantRunRequest {
  runId: string;
  conversationId: string;
  providerId: string;
  intent: AssistantRunIntent;
  prompt: string;
  attachmentIds: string[];
  budget?: AssistantRunBudget | null;
  saveResearchArtifact?: boolean | null;
  regenerationTarget?: AssistantRegenerationTarget | null;
}

/**
 * Closed ordinary-chat boundary. Case, approval, authority, classification,
 * artifact and MCP fields are deliberately absent and cannot cross IPC.
 */
export interface StartInteractiveAssistantRunRequest {
  runId: string;
  conversationId: string;
  providerId: string;
  prompt: string;
  attachmentIds: string[];
  budget?: AssistantRunBudget | null;
}

export interface AssistantRegenerationTarget {
  artifactId: string;
  sourceVersionNumber: number;
  expectedCurrentVersion: number;
}

export interface AssistantRunStreamUsage {
  promptTokens?: number | null;
  completionTokens?: number | null;
  totalTokens?: number | null;
}

export type AssistantRunStreamStatus =
  | "accepted"
  | "preparing"
  | "running"
  | "finalizing"
  | "completed"
  | "cancelled";

export type AssistantRunToolEventStatus =
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

interface AssistantRunEventBase {
  runId: string;
  /** Strictly increases within one backend run channel. */
  sequence: number;
}

export type AssistantRunEvent =
  | (AssistantRunEventBase & {
      eventType: "status";
      status: AssistantRunStreamStatus;
    })
  | (AssistantRunEventBase & {
      eventType: "tool";
      toolCallId: string;
      capabilityName: AssistantCapabilityName;
      status: AssistantRunToolEventStatus;
    })
  | (AssistantRunEventBase & {
      eventType: "delta";
      content: string;
    })
  | (AssistantRunEventBase & {
      eventType: "usage";
      usage: AssistantRunStreamUsage;
    })
  | (AssistantRunEventBase & {
      eventType: "error";
      errorType: string;
      message: string;
    });

export interface StartAssistantRunResponse {
  run: AssistantRun;
  artifact: AssistantArtifact | null;
  proposal: AssistantCaseChangeProposal | null;
  citationReport: CitationValidationReport | null;
}

export interface StartInteractiveAssistantRunResponse {
  run: AssistantRun;
}

export interface CreateAssistantCaseChangeProposalRequest {
  conversationId: string;
  projectId: string;
  changes: CaseChangeSpec;
}

export interface RejectAssistantCaseChangeProposalRequest {
  proposalId: string;
  projectId: string;
}

export interface ApplyAssistantCaseChangeProposalRequest {
  proposalId: string;
  projectId: string;
  userConfirmed: boolean;
}

export interface AssistantCaseChangeProposalResponse {
  proposal: AssistantCaseChangeProposal;
}

export interface ApplyAssistantCaseChangeProposalResponse {
  proposal: AssistantCaseChangeProposal;
  applied: boolean;
  stale: boolean;
}
