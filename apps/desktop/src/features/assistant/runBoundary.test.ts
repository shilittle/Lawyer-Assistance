import { beforeEach, describe, expect, it, vi } from "vitest";

const { cancelAssistantRun, startInteractiveAssistantRun } = vi.hoisted(() => ({
  cancelAssistantRun: vi.fn(),
  startInteractiveAssistantRun: vi.fn(),
}));
vi.mock("../../ipc/assistant/client", () => ({
  cancelAssistantRun,
  startInteractiveAssistantRun,
}));

import {
  advanceAssistantRunEventCursor,
  applyAssistantCancellationResult,
  assistantAttachmentPolicy,
  defaultAssistantRunBoundary,
} from "./runBoundary";

describe("defaultAssistantRunBoundary", () => {
  beforeEach(() => {
    cancelAssistantRun.mockReset();
    startInteractiveAssistantRun.mockReset();
    startInteractiveAssistantRun.mockResolvedValue({
      run: { runId: "run-1", status: "succeeded" },
    });
    cancelAssistantRun.mockResolvedValue({ runId: "run-1", cancelled: true });
  });

  it("delegates ordinary messages to the interactive client and preserves streaming", async () => {
    const events: string[] = [];
    const request = {
      runId: "run-1",
      conversationId: "conversation-1",
      providerId: "provider-1",
      prompt: "合同解除的一般条件是什么？",
      attachmentIds: [],
    };
    startInteractiveAssistantRun.mockImplementationOnce(
      async (_request, onEvent) => {
        onEvent({
          runId: "run-1",
          sequence: 1,
          eventType: "delta",
          content: "第一段",
        });
        onEvent({
          runId: "run-1",
          sequence: 2,
          eventType: "delta",
          content: "第二段",
        });
        return { run: { runId: "run-1", status: "succeeded" } };
      },
    );

    await defaultAssistantRunBoundary.start(request, (event) => {
      if (event.eventType === "delta") events.push(event.content);
    });

    expect(startInteractiveAssistantRun).toHaveBeenCalledWith(
      request,
      expect.any(Function),
    );
    expect(events).toEqual(["第一段", "第二段"]);
    await expect(defaultAssistantRunBoundary.cancel("run-1")).resolves.toBe(true);
  });
});

describe("assistantAttachmentPolicy", () => {
  it.each([
    ["legal_research", false, { accepts: false, requires: false }],
    ["file_analysis", false, { accepts: true, requires: true }],
    ["document_draft", false, { accepts: true, requires: true }],
    ["map_build", true, { accepts: true, requires: false }],
    ["case_analysis", true, { accepts: false, requires: false }],
  ] as const)(
    "matches the fixed Rust plan for %s (hasProject=%s)",
    (intent, hasProject, expected) => {
      expect(assistantAttachmentPolicy(intent, hasProject)).toEqual(expected);
    },
  );

  it("requires material for document and map work only when no case is bound", () => {
    expect(assistantAttachmentPolicy("document_draft", true).requires).toBe(false);
    expect(assistantAttachmentPolicy("map_build", false).requires).toBe(true);
  });
});

describe("applyAssistantCancellationResult", () => {
  it("reenables cancellation when the backend has not registered the run yet", () => {
    const active = { runId: "run-current", cancelling: true, epoch: 1 };
    expect(applyAssistantCancellationResult(active, "run-current", false)).toEqual({
      ...active,
      cancelling: false,
    });
    expect(applyAssistantCancellationResult(active, "run-current", true)).toBe(active);
    expect(applyAssistantCancellationResult(active, "run-other", false)).toBe(active);
  });
});

describe("advanceAssistantRunEventCursor", () => {
  const active = { runId: "run-current", epoch: 7, lastSequence: 2 };

  it("accepts only the next ordered event for the active run and epoch", () => {
    expect(
      advanceAssistantRunEventCursor(active, 7, {
        runId: "run-current",
        sequence: 3,
        eventType: "delta",
        content: "next",
      }),
    ).toEqual({ ...active, lastSequence: 3 });
  });

  it("drops late, duplicate, foreign-run, and stale-epoch events", () => {
    expect(
      advanceAssistantRunEventCursor(active, 7, {
        runId: "run-current",
        sequence: 2,
        eventType: "status",
        status: "running",
      }),
    ).toBeNull();
    expect(
      advanceAssistantRunEventCursor(active, 7, {
        runId: "run-old",
        sequence: 3,
        eventType: "delta",
        content: "late",
      }),
    ).toBeNull();
    expect(
      advanceAssistantRunEventCursor(active, 6, {
        runId: "run-current",
        sequence: 3,
        eventType: "delta",
        content: "stale callback",
      }),
    ).toBeNull();
  });
});
