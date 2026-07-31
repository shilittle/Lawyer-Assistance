import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  CancelCaseAssistantRunRequest,
  CancelCaseAssistantRunResponse,
  ConfirmCaseAssistantOutputRequest,
  ConfirmCaseAssistantOutputResponse,
  CreateCaseAssistantConversationRequest,
  CreateCaseAssistantConversationResponse,
  GetCaseAssistantConversationRequest,
  GetCaseAssistantConversationResponse,
  ListCaseAssistantConversationsRequest,
  ListCaseAssistantConversationsResponse,
  ListCaseAssistantGenerationsRequest,
  ListCaseAssistantGenerationsResponse,
  ListCaseAssistantPendingOutputsRequest,
  ListCaseAssistantPendingOutputsResponse,
  StartCaseAssistantRunRequest,
  StartCaseAssistantRunResponse,
  CaseAssistantRunEvent,
} from "./types";

const FORBIDDEN_CASE_IDENTITY_KEYS = new Set([
  "caseId",
  "case_id",
  "privacyCaseId",
  "privacy_case_id",
]);
const ERROR_TYPE_PATTERN = /[^a-z0-9_]/gu;
const MAX_ERROR_MESSAGE_BYTES = 4_096;

function stripForbiddenCaseIdentity<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map(stripForbiddenCaseIdentity) as T;
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !FORBIDDEN_CASE_IDENTITY_KEYS.has(key))
      .map(([key, item]) => [key, stripForbiddenCaseIdentity(item)]),
  ) as T;
}
function boundedMessage(value: string): string {
  const trimmed = value.trim();
  if (new TextEncoder().encode(trimmed).byteLength <= MAX_ERROR_MESSAGE_BYTES) {
    return trimmed;
  }
  let output = "";
  for (const character of trimmed) {
    const candidate = `${output}${character}`;
    if (
      new TextEncoder().encode(candidate).byteLength > MAX_ERROR_MESSAGE_BYTES
    ) {
      break;
    }
    output = candidate;
  }
  return output;
}

function parsedError(value: unknown): {
  errorType?: unknown;
  message?: unknown;
} | null {
  if (typeof value === "string") {
    try {
      return parsedError(JSON.parse(value));
    } catch {
      return { message: value };
    }
  }
  if (typeof value === "object" && value !== null) {
    return value as { errorType?: unknown; message?: unknown };
  }
  return null;
}

export class CaseAssistantIpcClientError extends Error {
  readonly errorType: string;

  constructor(errorType: string, message: string) {
    super(message);
    this.name = "CaseAssistantIpcClientError";
    this.errorType = errorType;
  }
}

export function normalizeCaseAssistantIpcError(
  value: unknown,
): CaseAssistantIpcClientError {
  if (value instanceof CaseAssistantIpcClientError) {
    return value;
  }
  const parsed = parsedError(value);
  const errorType =
    typeof parsed?.errorType === "string"
      ? parsed.errorType
          .toLowerCase()
          .replace(ERROR_TYPE_PATTERN, "")
          .slice(0, 64) || "case_assistant_ipc"
      : "case_assistant_ipc";
  const message =
    typeof parsed?.message === "string" && parsed.message.trim()
      ? boundedMessage(parsed.message)
      : "Case Assistant operation failed. Please try again.";
  return new CaseAssistantIpcClientError(errorType, message);
}

function invokeCaseAssistant<T>(
  command: string,
  args: Record<string, unknown>,
): Promise<T> {
  return invoke<T>(command, args)
    .then(stripForbiddenCaseIdentity)
    .catch((error: unknown) => {
      throw normalizeCaseAssistantIpcError(error);
    });
}

function closedBudget(
  budget: StartCaseAssistantRunRequest["budget"],
): StartCaseAssistantRunRequest["budget"] {
  if (budget === undefined || budget === null) {
    return budget;
  }
  return {
    maxToolCalls: budget.maxToolCalls,
    maxProviderRoundTrips: budget.maxProviderRoundTrips,
    maxInputBodyBytes: budget.maxInputBodyBytes,
    maxVisibleAttachments: budget.maxVisibleAttachments,
    maxModelResponseBytes: budget.maxModelResponseBytes,
  };
}

export function createCaseAssistantConversation(
  request: CreateCaseAssistantConversationRequest,
): Promise<CreateCaseAssistantConversationResponse> {
  return invokeCaseAssistant("create_case_assistant_conversation", {
    request: {
      projectId: request.projectId,
      title: request.title,
    },
  });
}

export function listCaseAssistantConversations(
  request: ListCaseAssistantConversationsRequest,
): Promise<ListCaseAssistantConversationsResponse> {
  const closedRequest: ListCaseAssistantConversationsRequest = {
    projectId: request.projectId,
  };
  if (request.limit !== undefined) {
    closedRequest.limit = request.limit;
  }
  return invokeCaseAssistant("list_case_assistant_conversations", {
    request: closedRequest,
  });
}

export function getCaseAssistantConversation(
  request: GetCaseAssistantConversationRequest,
): Promise<GetCaseAssistantConversationResponse> {
  return invokeCaseAssistant("get_case_assistant_conversation", {
    request: {
      projectId: request.projectId,
      conversationId: request.conversationId,
    },
  });
}

export function listCaseAssistantGenerations(
  request: ListCaseAssistantGenerationsRequest,
): Promise<ListCaseAssistantGenerationsResponse> {
  return invokeCaseAssistant("list_case_assistant_generations", {
    request: { projectId: request.projectId },
  });
}

export function startCaseAssistantRun(
  request: StartCaseAssistantRunRequest,
  onEvent: (event: CaseAssistantRunEvent) => void,
): Promise<StartCaseAssistantRunResponse> {
  const closedRequest: StartCaseAssistantRunRequest = {
    runId: request.runId,
    conversationId: request.conversationId,
    projectId: request.projectId,
    providerId: request.providerId,
    prompt: request.prompt,
    redactionGenerationIds: [...request.redactionGenerationIds],
    outputKind: request.outputKind,
  };
  if (request.budget !== undefined) {
    closedRequest.budget = closedBudget(request.budget);
  }
  const eventChannel = new Channel<CaseAssistantRunEvent>((event) => {
    onEvent(stripForbiddenCaseIdentity(event));
  });
  return invokeCaseAssistant("start_case_assistant_run", {
    request: closedRequest,
    onEvent: eventChannel,
  });
}

export function cancelCaseAssistantRun(
  request: CancelCaseAssistantRunRequest,
): Promise<CancelCaseAssistantRunResponse> {
  return invokeCaseAssistant("cancel_assistant_run", {
    request: { runId: request.runId },
  });
}

export function listCaseAssistantPendingOutputs(
  request: ListCaseAssistantPendingOutputsRequest,
): Promise<ListCaseAssistantPendingOutputsResponse> {
  const closedRequest: ListCaseAssistantPendingOutputsRequest = {
    projectId: request.projectId,
  };
  if (request.conversationId !== undefined) {
    closedRequest.conversationId = request.conversationId;
  }
  return invokeCaseAssistant("list_case_assistant_pending_outputs", {
    request: closedRequest,
  });
}

export function confirmCaseAssistantOutput(
  request: ConfirmCaseAssistantOutputRequest,
): Promise<ConfirmCaseAssistantOutputResponse> {
  if (request.userConfirmed !== true) {
    return Promise.reject(
      new CaseAssistantIpcClientError(
        "confirmation_required",
        "Explicit confirmation is required.",
      ),
    );
  }
  return invokeCaseAssistant("confirm_case_assistant_output", {
    request: {
      projectId: request.projectId,
      pendingOutputId: request.pendingOutputId,
      expectedVersion: request.expectedVersion,
      expectedOutputSha256: request.expectedOutputSha256,
      expectedWorkspaceDigest: request.expectedWorkspaceDigest,
      userConfirmed: true,
    },
  });
}
