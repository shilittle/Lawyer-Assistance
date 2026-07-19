import { describe, expect, it } from "vitest";

import type {
  AssistantConversation,
  AssistantConversationDetail,
} from "../../ipc/assistant/types";
import {
  INITIAL_ASSISTANT_WORKSPACE_STATE,
  assistantWorkspaceReducer,
  clearPromptDraftIfUnchanged,
  replaceRunIfCurrent,
  toggleAttachmentSelection,
} from "./workspaceState";

function conversation(
  conversationId: string,
  updatedAt = "2026-07-17T00:00:00Z",
): AssistantConversation {
  return {
    conversationId,
    projectId: null,
    title: conversationId,
    status: "open",
    createdAt: "2026-07-16T00:00:00Z",
    updatedAt,
  };
}

function detail(conversationId: string): AssistantConversationDetail {
  return {
    conversation: conversation(conversationId),
    messages: [],
    sources: [],
    artifacts: [],
    runs: [],
    proposals: [],
  };
}

describe("assistantWorkspaceReducer", () => {
  it("rejects an old conversation response after the user switches", () => {
    const selectedA = assistantWorkspaceReducer(
      INITIAL_ASSISTANT_WORKSPACE_STATE,
      { type: "select_conversation", conversationId: "a", epoch: 1 },
    );
    const selectedB = assistantWorkspaceReducer(selectedA, {
      type: "select_conversation",
      conversationId: "b",
      epoch: 2,
    });
    const afterLateA = assistantWorkspaceReducer(selectedB, {
      type: "detail_loaded",
      conversationId: "a",
      epoch: 1,
      detail: detail("a"),
    });

    expect(afterLateA).toBe(selectedB);
    expect(afterLateA.detail).toBeNull();

    const afterB = assistantWorkspaceReducer(afterLateA, {
      type: "detail_loaded",
      conversationId: "b",
      epoch: 2,
      detail: detail("b"),
    });
    expect(afterB.detail?.conversation.conversationId).toBe("b");
    expect(afterB.detailPhase).toBe("ready");
  });

  it("rejects an older refresh response for the same conversation", () => {
    const state = assistantWorkspaceReducer(
      assistantWorkspaceReducer(INITIAL_ASSISTANT_WORKSPACE_STATE, {
        type: "select_conversation",
        conversationId: "same",
        epoch: 3,
      }),
      { type: "select_conversation", conversationId: "same", epoch: 4 },
    );
    const stale = assistantWorkspaceReducer(state, {
      type: "detail_loaded",
      conversationId: "same",
      epoch: 3,
      detail: detail("same"),
    });
    expect(stale).toBe(state);
  });

  it("sorts recent conversations without losing the selected identity", () => {
    const state = assistantWorkspaceReducer(
      {
        ...INITIAL_ASSISTANT_WORKSPACE_STATE,
        selectedConversationId: "older",
      },
      {
        type: "replace_conversations",
        conversations: [
          conversation("older", "2026-07-16T00:00:00Z"),
          conversation("newer", "2026-07-17T00:00:00Z"),
        ],
      },
    );
    expect(state.conversations.map((item) => item.conversationId)).toEqual([
      "newer",
      "older",
    ]);
    expect(state.selectedConversationId).toBe("older");
  });
});

describe("toggleAttachmentSelection", () => {
  it("enforces the explicit two-attachment range", () => {
    expect(toggleAttachmentSelection(["a", "b"], "c")).toEqual(["a", "b"]);
    expect(toggleAttachmentSelection(["a", "b"], "a")).toEqual(["b"]);
    expect(toggleAttachmentSelection(["a"], "b")).toEqual(["a", "b"]);
  });
});

describe("assistant async race guards", () => {
  it("keeps a new prompt typed while the submitted draft is running", () => {
    const drafts = { conversation: "next task" };
    expect(
      clearPromptDraftIfUnchanged(drafts, "conversation", "submitted task"),
    ).toBe(drafts);
    expect(
      clearPromptDraftIfUnchanged(
        { conversation: "submitted task" },
        "conversation",
        "submitted task",
      ),
    ).toEqual({});
  });

  it("does not resurrect a cancelled run after the start promise settled", () => {
    const run = { runId: "run-a", cancelling: false };
    expect(replaceRunIfCurrent(null, "run-a", run)).toBeNull();
    expect(
      replaceRunIfCurrent(
        { runId: "run-b", cancelling: false },
        "run-a",
        run,
      ),
    ).toEqual({ runId: "run-b", cancelling: false });
  });
});
