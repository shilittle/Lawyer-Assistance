import type {
  AssistantConversation,
  AssistantConversationDetail,
} from "../../ipc/assistant/types";

export type AssistantDetailPhase = "idle" | "loading" | "ready" | "error";

export interface AssistantWorkspaceState {
  conversations: AssistantConversation[];
  selectedConversationId: string | null;
  detail: AssistantConversationDetail | null;
  detailPhase: AssistantDetailPhase;
  detailError: string;
  detailEpoch: number;
}

export type AssistantWorkspaceAction =
  | { type: "replace_conversations"; conversations: AssistantConversation[] }
  | { type: "upsert_conversation"; conversation: AssistantConversation }
  | { type: "remove_conversation"; conversationId: string }
  | { type: "select_conversation"; conversationId: string | null; epoch: number }
  | {
      type: "detail_loaded";
      conversationId: string;
      epoch: number;
      detail: AssistantConversationDetail;
    }
  | {
      type: "detail_failed";
      conversationId: string;
      epoch: number;
      message: string;
    }
  | { type: "replace_detail"; detail: AssistantConversationDetail };

export const INITIAL_ASSISTANT_WORKSPACE_STATE: AssistantWorkspaceState = {
  conversations: [],
  selectedConversationId: null,
  detail: null,
  detailPhase: "idle",
  detailError: "",
  detailEpoch: 0,
};

function newestFirst(
  conversations: readonly AssistantConversation[],
): AssistantConversation[] {
  return [...conversations].sort((left, right) =>
    right.updatedAt.localeCompare(left.updatedAt),
  );
}

function upsertConversation(
  conversations: readonly AssistantConversation[],
  conversation: AssistantConversation,
): AssistantConversation[] {
  return newestFirst([
    conversation,
    ...conversations.filter(
      (candidate) => candidate.conversationId !== conversation.conversationId,
    ),
  ]);
}

export function assistantWorkspaceReducer(
  state: AssistantWorkspaceState,
  action: AssistantWorkspaceAction,
): AssistantWorkspaceState {
  switch (action.type) {
    case "replace_conversations":
      return { ...state, conversations: newestFirst(action.conversations) };
    case "upsert_conversation":
      return {
        ...state,
        conversations: upsertConversation(
          state.conversations,
          action.conversation,
        ),
      };
    case "remove_conversation": {
      const conversations = state.conversations.filter(
        (conversation) => conversation.conversationId !== action.conversationId,
      );
      if (state.selectedConversationId !== action.conversationId) {
        return { ...state, conversations };
      }
      return {
        ...state,
        conversations,
        selectedConversationId: null,
        detail: null,
        detailPhase: "idle",
        detailError: "",
      };
    }
    case "select_conversation":
      return {
        ...state,
        selectedConversationId: action.conversationId,
        detail: null,
        detailPhase: action.conversationId === null ? "idle" : "loading",
        detailError: "",
        detailEpoch: action.epoch,
      };
    case "detail_loaded":
      if (
        state.selectedConversationId !== action.conversationId ||
        state.detailEpoch !== action.epoch ||
        action.detail.conversation.conversationId !== action.conversationId
      ) {
        return state;
      }
      return {
        ...state,
        detail: action.detail,
        detailPhase: "ready",
        detailError: "",
        conversations: upsertConversation(
          state.conversations,
          action.detail.conversation,
        ),
      };
    case "detail_failed":
      if (
        state.selectedConversationId !== action.conversationId ||
        state.detailEpoch !== action.epoch
      ) {
        return state;
      }
      return {
        ...state,
        detail: null,
        detailPhase: "error",
        detailError: action.message,
      };
    case "replace_detail":
      if (
        state.selectedConversationId !==
        action.detail.conversation.conversationId
      ) {
        return state;
      }
      return {
        ...state,
        detail: action.detail,
        detailPhase: "ready",
        detailError: "",
        conversations: upsertConversation(
          state.conversations,
          action.detail.conversation,
        ),
      };
  }
}

export function toggleAttachmentSelection(
  selected: readonly string[],
  attachmentId: string,
  maximum = 2,
): string[] {
  if (selected.includes(attachmentId)) {
    return selected.filter((candidate) => candidate !== attachmentId);
  }
  if (selected.length >= maximum) return [...selected];
  return [...selected, attachmentId];
}

export function clearPromptDraftIfUnchanged(
  drafts: Readonly<Record<string, string>>,
  conversationId: string,
  submittedDraft: string,
): Record<string, string> {
  if (drafts[conversationId] !== submittedDraft) return drafts;
  const updated = { ...drafts };
  delete updated[conversationId];
  return updated;
}

export function replaceRunIfCurrent<T extends { runId: string }>(
  current: T | null,
  runId: string,
  replacement: T | null,
): T | null {
  return current?.runId === runId ? replacement : current;
}
