import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  AddAssistantLegalSourceRequest,
  ApplyAssistantCaseChangeProposalRequest,
  ApplyAssistantCaseChangeProposalResponse,
  AssistantArtifactDraft,
  AssistantArtifactResponse,
  AssistantCapabilitiesResponse,
  AssistantCaseChangeProposalResponse,
  AssistantConversationIdRequest,
  AssistantConversationResponse,
  AssistantConversationSourceResponse,
  BindAssistantArtifactRequest,
  BindAssistantConversationRequest,
  CancelAssistantRunRequest,
  CancelAssistantRunResponse,
  CaseChangeSpec,
  CreateAssistantCaseChangeProposalRequest,
  CreateAssistantConversationRequest,
  DeleteAssistantAttachmentRequest,
  DeleteAssistantAttachmentResponse,
  DocumentSpec,
  ExportAssistantArtifactRequest,
  ExportAssistantArtifactResponse,
  GetAssistantArtifactRequest,
  GetAssistantArtifactResponse,
  GetAssistantConversationResponse,
  ImportAssistantFilesRequest,
  ImportAssistantFilesResponse,
  ListAssistantArtifactsRequest,
  ListAssistantArtifactsResponse,
  ListAssistantConversationsRequest,
  ListAssistantConversationsResponse,
  MapSpec,
  ProvenanceRef,
  ProposeAssistantLegalBasisRequest,
  RejectAssistantCaseChangeProposalRequest,
  SaveAssistantArtifactRequest,
  SaveAssistantArtifactResponse,
  StartInteractiveAssistantRunRequest,
  StartInteractiveAssistantRunResponse,
  AssistantRunEvent,
} from "./types";

/** A single stable error shape for every assistant invoke rejection. */
export class AssistantIpcClientError extends Error {
  readonly errorType: string;

  constructor(errorType: string, message: string) {
    super(message);
    this.name = "AssistantIpcClientError";
    this.errorType = errorType;
  }
}

const GENERIC_ERROR_MESSAGE = "Assistant operation failed. Please try again.";

function errorRecord(value: unknown): { errorType: string; message: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.errorType === "string" &&
    typeof candidate.message === "string"
  ) {
    return { errorType: candidate.errorType, message: candidate.message };
  }
  return null;
}

function parseErrorText(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function safeErrorType(value: string): string {
  const normalized = [...value]
    .filter(
      (character) =>
        /[A-Za-z0-9]/.test(character) || character === "_" || character === "-",
    )
    .join("")
    .slice(0, 64);
  return normalized || "assistant_ipc";
}

function safeErrorMessage(value: string): string {
  return value.trim().slice(0, 2048) || GENERIC_ERROR_MESSAGE;
}

export function normalizeAssistantIpcError(
  error: unknown,
): AssistantIpcClientError {
  if (error instanceof AssistantIpcClientError) return error;

  const direct = errorRecord(error);
  if (direct) {
    return new AssistantIpcClientError(
      safeErrorType(direct.errorType),
      safeErrorMessage(direct.message),
    );
  }

  const text = error instanceof Error ? error.message : error;
  if (typeof text === "string") {
    const parsed = errorRecord(parseErrorText(text));
    if (parsed) {
      return new AssistantIpcClientError(
        safeErrorType(parsed.errorType),
        safeErrorMessage(parsed.message),
      );
    }
    return new AssistantIpcClientError(
      "assistant_ipc",
      safeErrorMessage(text),
    );
  }

  return new AssistantIpcClientError("assistant_ipc", GENERIC_ERROR_MESSAGE);
}

async function invokeAssistant<T>(
  command: string,
  args?: { request: unknown; onEvent?: Channel<AssistantRunEvent> },
): Promise<T> {
  try {
    return args === undefined
      ? await invoke<T>(command)
      : await invoke<T>(command, args);
  } catch (error: unknown) {
    throw normalizeAssistantIpcError(error);
  }
}

function copyStrings(values: readonly string[]): string[] {
  return [...values];
}

function closeProvenance(value: ProvenanceRef): ProvenanceRef {
  return { kind: value.kind, sourceRef: value.sourceRef };
}

function closeDocumentSpec(value: DocumentSpec): DocumentSpec {
  return {
    schemaVersion: value.schemaVersion,
    documentType: value.documentType,
    title: value.title,
    parties: value.parties.map((party) => ({
      id: party.id,
      name: party.name,
      role: party.role,
      details: party.details,
      provenance: party.provenance.map(closeProvenance),
    })),
    sections: value.sections.map((section) => ({
      id: section.id,
      heading: section.heading,
      body: section.body,
      factual: section.factual,
      provenance: section.provenance.map(closeProvenance),
      clauses: section.clauses.map((clause) => ({
        id: clause.id,
        heading: clause.heading,
        body: clause.body,
        factual: clause.factual,
        provenance: clause.provenance.map(closeProvenance),
      })),
    })),
    assumptions: value.assumptions.map((assumption) => ({
      text: assumption.text,
      provenance: assumption.provenance.map(closeProvenance),
    })),
    missingInformation: value.missingInformation.map((missing) => ({
      description: missing.description,
    })),
    sourceMaterials: value.sourceMaterials.map((source) => ({
      id: source.id,
      kind: source.kind,
      label: source.label,
      locator: source.locator,
    })),
    legalCitations: value.legalCitations.map((citation) => ({
      id: citation.id,
      sourceRef: citation.sourceRef,
      marker: citation.marker,
      citation: citation.citation,
      proposition: citation.proposition,
    })),
    riskWarnings: copyStrings(value.riskWarnings),
  };
}

function closeMapSpec(value: MapSpec): MapSpec {
  return {
    schemaVersion: value.schemaVersion,
    title: value.title,
    layoutHint: value.layoutHint,
    nodes: value.nodes.map((node) => ({
      id: node.id,
      label: node.label,
      summary: node.summary,
      parentId: node.parentId,
      sourceRefs: copyStrings(node.sourceRefs),
    })),
    edges: value.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      relation: edge.relation,
      sourceRefs: copyStrings(edge.sourceRefs),
    })),
  };
}

function closeArtifactDraft(value: AssistantArtifactDraft): AssistantArtifactDraft {
  switch (value.kind) {
    case "research":
      return {
        kind: "research",
        spec: {
          schemaVersion: value.spec.schemaVersion,
          title: value.spec.title,
          answer: value.spec.answer,
          sourceRefs: copyStrings(value.spec.sourceRefs),
          assumptions: copyStrings(value.spec.assumptions),
          missingInformation: copyStrings(value.spec.missingInformation),
          riskWarnings: copyStrings(value.spec.riskWarnings),
        },
      };
    case "document":
      return { kind: "document", spec: closeDocumentSpec(value.spec) };
    case "map":
      return { kind: "map", spec: closeMapSpec(value.spec) };
  }
}

function closeCaseChangeSpec(value: CaseChangeSpec): CaseChangeSpec {
  return {
    schemaVersion: value.schemaVersion,
    facts: value.facts.map((fact) => ({
      id: fact.id,
      statement: fact.statement,
      occurredOn: fact.occurredOn,
      sourceRefs: copyStrings(fact.sourceRefs),
    })),
    evidence: value.evidence.map((evidence) => ({
      id: evidence.id,
      title: evidence.title,
      summary: evidence.summary,
      provesFactIds: copyStrings(evidence.provesFactIds),
      sourceRefs: copyStrings(evidence.sourceRefs),
    })),
    issues: value.issues.map((issue) => ({
      id: issue.id,
      title: issue.title,
      analysis: issue.analysis,
      relatedFactIds: copyStrings(issue.relatedFactIds),
      sourceRefs: copyStrings(issue.sourceRefs),
    })),
    legalBasis: value.legalBasis.map((basis) => ({
      id: basis.id,
      issueIds: copyStrings(basis.issueIds),
      sourceRef: basis.sourceRef,
      marker: basis.marker,
      citation: basis.citation,
      proposition: basis.proposition,
    })),
    attachmentTransfers: value.attachmentTransfers.map((transfer) => ({
      attachmentId: transfer.attachmentId,
      title: transfer.title,
    })),
    artifactTransfers: value.artifactTransfers.map((transfer) => ({
      artifactId: transfer.artifactId,
      title: transfer.title,
    })),
  };
}

export function getAssistantCapabilities(): Promise<AssistantCapabilitiesResponse> {
  return invokeAssistant("get_assistant_capabilities");
}

export function listAssistantConversations(
  request: ListAssistantConversationsRequest = {},
): Promise<ListAssistantConversationsResponse> {
  const closedRequest: ListAssistantConversationsRequest = {};
  if (request.projectId !== undefined) closedRequest.projectId = request.projectId;
  if (request.includeArchived !== undefined) {
    closedRequest.includeArchived = request.includeArchived;
  }
  if (request.limit !== undefined) closedRequest.limit = request.limit;
  return invokeAssistant("list_assistant_conversations", {
    request: closedRequest,
  });
}

export function createAssistantConversation(
  request: CreateAssistantConversationRequest,
): Promise<AssistantConversationResponse> {
  const closedRequest: CreateAssistantConversationRequest = {
    title: request.title,
  };
  if (request.projectId !== undefined) closedRequest.projectId = request.projectId;
  return invokeAssistant("create_assistant_conversation", {
    request: closedRequest,
  });
}

export function getAssistantConversation(
  request: AssistantConversationIdRequest,
): Promise<GetAssistantConversationResponse> {
  return invokeAssistant("get_assistant_conversation", {
    request: { conversationId: request.conversationId },
  });
}

export function bindAssistantConversation(
  request: BindAssistantConversationRequest,
): Promise<AssistantConversationResponse> {
  return invokeAssistant("bind_assistant_conversation", {
    request: {
      conversationId: request.conversationId,
      projectId: request.projectId,
    },
  });
}

export function archiveAssistantConversation(
  request: AssistantConversationIdRequest,
): Promise<AssistantConversationResponse> {
  return invokeAssistant("archive_assistant_conversation", {
    request: { conversationId: request.conversationId },
  });
}

export function addAssistantLegalSource(
  request: AddAssistantLegalSourceRequest,
): Promise<AssistantConversationSourceResponse> {
  return invokeAssistant("add_assistant_legal_source", {
    request: {
      conversationId: request.conversationId,
      sourceId: request.sourceId,
    },
  });
}

export function proposeAssistantLegalBasis(
  request: ProposeAssistantLegalBasisRequest,
): Promise<AssistantCaseChangeProposalResponse> {
  return invokeAssistant("propose_assistant_legal_basis", {
    request: {
      conversationId: request.conversationId,
      projectId: request.projectId,
      sourceId: request.sourceId,
    },
  });
}

export function listAssistantArtifacts(
  request: ListAssistantArtifactsRequest = {},
): Promise<ListAssistantArtifactsResponse> {
  const closedRequest: ListAssistantArtifactsRequest = {};
  if (request.conversationId !== undefined) {
    closedRequest.conversationId = request.conversationId;
  }
  if (request.limit !== undefined) closedRequest.limit = request.limit;
  return invokeAssistant("list_assistant_artifacts", { request: closedRequest });
}

export function getAssistantArtifact(
  request: GetAssistantArtifactRequest,
): Promise<GetAssistantArtifactResponse> {
  return invokeAssistant("get_assistant_artifact", {
    request: { artifactId: request.artifactId },
  });
}

export function bindAssistantArtifact(
  request: BindAssistantArtifactRequest,
): Promise<AssistantArtifactResponse> {
  return invokeAssistant("bind_assistant_artifact", {
    request: {
      artifactId: request.artifactId,
      projectId: request.projectId,
      userConfirmed: request.userConfirmed,
    },
  });
}

export function saveAssistantArtifact(
  request: SaveAssistantArtifactRequest,
): Promise<SaveAssistantArtifactResponse> {
  const closedRequest: SaveAssistantArtifactRequest = {
    conversationId: request.conversationId,
    title: request.title,
    draft: closeArtifactDraft(request.draft),
  };
  if (request.artifactId !== undefined) {
    closedRequest.artifactId = request.artifactId;
  }
  if (request.expectedCurrentVersion !== undefined) {
    closedRequest.expectedCurrentVersion = request.expectedCurrentVersion;
  }
  return invokeAssistant("save_assistant_artifact", { request: closedRequest });
}

export function exportAssistantArtifact(
  request: ExportAssistantArtifactRequest,
): Promise<ExportAssistantArtifactResponse> {
  return invokeAssistant("export_assistant_artifact", {
    request: {
      artifactId: request.artifactId,
      versionNumber: request.versionNumber,
      format: request.format,
    },
  });
}

export function importAssistantFiles(
  request: ImportAssistantFilesRequest,
): Promise<ImportAssistantFilesResponse> {
  return invokeAssistant("import_assistant_files", {
    request: { conversationId: request.conversationId },
  });
}

export function deleteAssistantAttachment(
  request: DeleteAssistantAttachmentRequest,
): Promise<DeleteAssistantAttachmentResponse> {
  return invokeAssistant("delete_assistant_attachment", {
    request: {
      conversationId: request.conversationId,
      attachmentId: request.attachmentId,
      userConfirmed: request.userConfirmed,
    },
  });
}

export function cancelAssistantRun(
  request: CancelAssistantRunRequest,
): Promise<CancelAssistantRunResponse> {
  return invokeAssistant("cancel_assistant_run", {
    request: { runId: request.runId },
  });
}

export function startInteractiveAssistantRun(
  request: StartInteractiveAssistantRunRequest,
  onEvent: (event: AssistantRunEvent) => void,
): Promise<StartInteractiveAssistantRunResponse> {
  const closedRequest: StartInteractiveAssistantRunRequest = {
    runId: request.runId,
    conversationId: request.conversationId,
    providerId: request.providerId,
    prompt: request.prompt,
    attachmentIds: copyStrings(request.attachmentIds),
  };
  if (request.budget !== undefined) {
    closedRequest.budget = request.budget === null
      ? null
      : {
          maxToolCalls: request.budget.maxToolCalls,
          maxProviderRoundTrips: request.budget.maxProviderRoundTrips,
          maxInputBodyBytes: request.budget.maxInputBodyBytes,
          maxVisibleAttachments: request.budget.maxVisibleAttachments,
          maxModelResponseBytes: request.budget.maxModelResponseBytes,
        };
  }
  const eventChannel = new Channel<AssistantRunEvent>(onEvent);
  return invokeAssistant("start_interactive_assistant_run", {
    request: closedRequest,
    onEvent: eventChannel,
  });
}

export function createAssistantCaseChangeProposal(
  request: CreateAssistantCaseChangeProposalRequest,
): Promise<AssistantCaseChangeProposalResponse> {
  return invokeAssistant("create_assistant_case_change_proposal", {
    request: {
      conversationId: request.conversationId,
      projectId: request.projectId,
      changes: closeCaseChangeSpec(request.changes),
    },
  });
}

export function rejectAssistantCaseChangeProposal(
  request: RejectAssistantCaseChangeProposalRequest,
): Promise<AssistantCaseChangeProposalResponse> {
  return invokeAssistant("reject_assistant_case_change_proposal", {
    request: {
      proposalId: request.proposalId,
      projectId: request.projectId,
    },
  });
}

export function applyAssistantCaseChangeProposal(
  request: ApplyAssistantCaseChangeProposalRequest,
): Promise<ApplyAssistantCaseChangeProposalResponse> {
  return invokeAssistant("apply_assistant_case_change_proposal", {
    request: {
      proposalId: request.proposalId,
      projectId: request.projectId,
      userConfirmed: request.userConfirmed,
    },
  });
}
