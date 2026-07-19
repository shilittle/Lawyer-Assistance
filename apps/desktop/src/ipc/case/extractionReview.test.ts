import { describe, expect, it } from "vitest";

import {
  buildConfirmationRequest,
  createExtractionContext,
  drainPendingExtractionSaves,
  extractionMutationBlocksClose,
  extractionReviewNeedsCloseFlush,
  extractionLocksSources,
  extractionReducer,
  extractionBusinessTextIsPublic,
  guardExtractionClose,
  pendingExtractionUpdateAtRevision,
  structuredCaseExtractionIsPublic,
  type ExtractionState,
} from "./extractionReview";
import type { StructuredCaseExtraction } from "./types";
import type { ProviderAuditSnapshot } from "../provider/types";

const draft: StructuredCaseExtraction = {
  parties: [],
  facts: [
    {
      occurredOn: null,
      title: "模型标题",
      description: "描述",
      evidenceNumbers: [],
    },
  ],
  evidence: [],
  legalIssues: [],
  uncertainties: [],
};

describe("case extraction review state", () => {
  it("rejects machine details before a draft can enter review or autosave", () => {
    const unsafeValues = [
      'fileId=file-secret-1 sourceRefs=["file-secret-1"]',
      '{"proposalHash":"deadbeef0123456789abcdef01234567"}',
      "C:\\Users\\operator\\private\\material.pdf",
      "https://internal.invalid/material/1",
      "service-deadbeef01234567-7",
      "550e8400-e29b-41d4-a716-446655440000",
      "模型输出中的内部字段",
    ];
    unsafeValues.forEach((value) => {
      expect(extractionBusinessTextIsPublic(value)).toBe(false);
    });

    const polluted: StructuredCaseExtraction = {
      ...draft,
      facts: [
        {
          ...draft.facts[0],
          description: unsafeValues[0],
        },
      ],
    };
    expect(structuredCaseExtractionIsPublic(polluted)).toBe(false);

    const context = createExtractionContext(
      "request-safe-boundary",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    const generating: ExtractionState = { kind: "generating", context };
    const rejected = extractionReducer(generating, {
      type: "generated",
      requestId: "request-safe-boundary",
      reviewId: "review-1",
      draft: polluted,
      revision: 0,
      repaired: false,
    });
    expect(rejected.kind).toBe("failed");
    expect(buildConfirmationRequest(rejected)).toBeNull();

    const rejectedRestore = extractionReducer(
      { kind: "idle" },
      {
        type: "restore",
        context,
        reviewId: "review-restored",
        draft: polluted,
        revision: 2,
        createdAt: "2026-07-18T10:00:00Z",
        expiresAt: "2026-07-19T10:00:00Z",
      },
    );
    expect(rejectedRestore.kind).toBe("failed");

    const reviewing = extractionReducer(generating, {
      type: "generated",
      requestId: "request-safe-boundary",
      reviewId: "review-1",
      draft,
      revision: 0,
      repaired: false,
    });
    const afterUnsafeEdit = extractionReducer(reviewing, {
      type: "edit",
      draft: polluted,
    });
    expect(afterUnsafeEdit).toBe(reviewing);
  });

  it("freezes generation provenance and confirms the reviewed edit", () => {
    const providerSnapshot: ProviderAuditSnapshot = {
      kind: "deep_seek",
      modelId: "deepseek-v4-flash",
      baseUrl: "https://api.deepseek.com",
      capabilities: {
        chat: true,
        streaming: true,
        customModelId: true,
        customBaseUrl: false,
        reasoning: true,
      },
      options: {},
    };
    const selected = ["file-a"];
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      selected,
    );
    selected[0] = "file-b";
    let state: ExtractionState = extractionReducer(
      { kind: "idle" },
      { type: "start", context },
    );
    expect(extractionLocksSources(state)).toBe(true);
    state = extractionReducer(state, {
      type: "generated",
      requestId: "request-1",
      reviewId: "review-1",
      draft,
      revision: 0,
      repaired: true,
      providerSnapshot,
    });
    state = extractionReducer(state, {
      type: "edit",
      draft: {
        ...draft,
        facts: [{ ...draft.facts[0], title: "用户修改后的标题" }],
      },
    });

    expect(buildConfirmationRequest(state)).toMatchObject({
      reviewId: "review-1",
      projectId: "project-1",
      providerId: "provider-1",
      fileIds: ["file-a"],
      confirmed: true,
      expectedRevision: 0,
      extraction: { facts: [{ title: "用户修改后的标题" }] },
    });
    expect("context" in state ? state.context.providerSnapshot : null).toEqual(
      providerSnapshot,
    );
  });

  it("cancel clears the draft and stale provider responses cannot restore it", () => {
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    let state = extractionReducer(
      { kind: "idle" } satisfies ExtractionState,
      { type: "start", context },
    );
    state = extractionReducer(state, { type: "cancel" });
    state = extractionReducer(state, {
      type: "generated",
      requestId: "request-1",
      reviewId: "review-1",
      draft,
      revision: 0,
      repaired: false,
    });

    expect(state).toEqual({ kind: "idle" });
    expect(buildConfirmationRequest(state)).toBeNull();
  });

  it("keeps a reviewed draft and readable error after commit rollback", () => {
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    let state = extractionReducer(
      { kind: "generating", context } satisfies ExtractionState,
      {
        type: "generated",
        requestId: "request-1",
        reviewId: "review-1",
        draft,
        revision: 0,
        repaired: false,
      },
    );
    state = extractionReducer(state, { type: "begin_commit" });
    state = extractionReducer(state, {
      type: "commit_failed",
      message: "事务已回滚",
    });

    expect(state.kind).toBe("reviewing");
    expect(state).toMatchObject({ commitError: "事务已回滚", draft });
  });

  it("removes a rejected model suggestion from the confirmation payload", () => {
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    let state = extractionReducer(
      { kind: "generating", context } satisfies ExtractionState,
      {
        type: "generated",
        requestId: "request-1",
        reviewId: "review-1",
        draft,
        revision: 0,
        repaired: false,
      },
    );
    state = extractionReducer(state, {
      type: "edit",
      draft: { ...draft, facts: [] },
    });

    expect(buildConfirmationRequest(state)?.extraction.facts).toEqual([]);
  });

  it("does not overwrite an active review with another generation start", () => {
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    const reviewing = extractionReducer(
      { kind: "generating", context } satisfies ExtractionState,
      {
        type: "generated",
        requestId: "request-1",
        reviewId: "review-1",
        draft,
        revision: 0,
        repaired: false,
      },
    );

    expect(
      extractionReducer(reviewing, {
        type: "start",
        context: createExtractionContext(
          "request-2",
          "project-1",
          "provider-1",
          ["file-b"],
        ),
      }),
    ).toBe(reviewing);
  });

  it("restores a persisted review but never overwrites an active dirty review", () => {
    const context = createExtractionContext(
      "restore-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    const restored = extractionReducer(
      { kind: "idle" } satisfies ExtractionState,
      {
        type: "restore",
        context,
        reviewId: "review-restored",
        draft,
        revision: 7,
        createdAt: "2026-07-14T10:00:00Z",
        expiresAt: "2026-07-15T10:00:00Z",
      },
    );

    expect(restored).toMatchObject({
      kind: "reviewing",
      reviewId: "review-restored",
      restored: true,
      revision: 7,
    });
    expect(
      extractionReducer(restored, {
        type: "restore",
        context,
        reviewId: "review-other",
        draft: { ...draft, facts: [] },
        revision: 8,
        createdAt: "2026-07-14T11:00:00Z",
        expiresAt: "2026-07-15T11:00:00Z",
      }),
    ).toBe(restored);
  });

  it("advances the carried server revision after a successful autosave", () => {
    const context = createExtractionContext(
      "request-1",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    const reviewing = extractionReducer(
      { kind: "generating", context } satisfies ExtractionState,
      {
        type: "generated",
        requestId: "request-1",
        reviewId: "review-1",
        draft,
        revision: 4,
        repaired: false,
      },
    );
    const saved = extractionReducer(reviewing, {
      type: "saved",
      reviewId: "review-1",
      revision: 5,
      expiresAt: "2026-07-16T10:00:00Z",
    });

    expect(buildConfirmationRequest(saved)).toMatchObject({
      expectedRevision: 5,
    });
  });

  it("binds consecutive queued saves to the revision current at send time", () => {
    const queued = {
      reviewId: "review-1",
      projectId: "project-1",
      providerId: "provider-1",
      fileIds: ["file-a"],
      extraction: draft,
    };
    let currentServerRevision = 3;

    const firstSend = pendingExtractionUpdateAtRevision(
      queued,
      currentServerRevision,
    );
    currentServerRevision = 4;
    const secondSend = pendingExtractionUpdateAtRevision(
      queued,
      currentServerRevision,
    );

    expect(firstSend.expectedRevision).toBe(3);
    expect(secondSend.expectedRevision).toBe(4);
  });

  it("waits for an edit queued while an earlier save is in flight before confirming", async () => {
    type Queued = { sequence: number; title: string };
    let resolveFirstSave: ((saved: boolean) => void) | undefined;
    const firstSave = new Promise<boolean>((resolve) => {
      resolveFirstSave = resolve;
    });
    let savedSequence = 0;
    let targetSequence = 1;
    let pending: Queued | null = null;
    const sent: Queued[] = [];

    const flushed = drainPendingExtractionSaves<Queued>({
      targetSequence: () => targetSequence,
      isBlocked: () => false,
      savedSequence: () => savedSequence,
      hasPending: () => pending !== null,
      takePending: () => {
        const queued = pending;
        pending = null;
        return queued;
      },
      waitForCurrent: async () => {
        const saved = await firstSave;
        if (saved) {
          savedSequence = 1;
        }
        return saved;
      },
      enqueue: async (queued) => {
        sent.push(queued);
        savedSequence = queued.sequence;
        return true;
      },
    });

    targetSequence = 2;
    pending = { sequence: 2, title: "edit while save 1 is in flight" };
    resolveFirstSave?.(true);

    await expect(flushed).resolves.toBe(true);
    expect(sent).toEqual([
      { sequence: 2, title: "edit while save 1 is in flight" },
    ]);
    expect(savedSequence).toBe(2);
  });

  it("fails closed instead of spinning when a resolved save cannot advance", async () => {
    let waits = 0;
    await expect(
      drainPendingExtractionSaves<never>({
        targetSequence: () => 1,
        isBlocked: () => false,
        savedSequence: () => 0,
        hasPending: () => false,
        takePending: () => null,
        waitForCurrent: async () => {
          waits += 1;
          return true;
        },
        enqueue: async () => true,
      }),
    ).resolves.toBe(false);
    expect(waits).toBe(1);
  });

  it("flushes a queued review edit before allowing the native window to close", async () => {
    const calls: string[] = [];
    const result = await guardExtractionClose({
      needsFlush: true,
      preventDefault: () => calls.push("prevent"),
      flush: async () => {
        calls.push("flush");
        return true;
      },
      destroyWindow: async () => {
        calls.push("destroy");
      },
      onBlocked: (message) => calls.push(`blocked:${message}`),
    });

    expect(result).toBe("saved_and_closed");
    expect(calls).toEqual(["prevent", "flush", "destroy"]);
  });

  it("uses the controlled destroy path after an explicit dirty-draft close approval", async () => {
    const calls: string[] = [];
    const result = await guardExtractionClose({
      needsFlush: false,
      forceControlledClose: true,
      preventDefault: () => calls.push("prevent"),
      flush: async () => {
        calls.push("flush");
        return true;
      },
      destroyWindow: async () => {
        calls.push("destroy");
      },
      onBlocked: (message) => calls.push(`blocked:${message}`),
    });

    expect(result).toBe("saved_and_closed");
    expect(calls).toEqual(["prevent", "destroy"]);
  });

  it("keeps the window open when the close-time review save fails", async () => {
    const calls: string[] = [];
    const result = await guardExtractionClose({
      needsFlush: true,
      preventDefault: () => calls.push("prevent"),
      flush: async () => false,
      destroyWindow: async () => {
        calls.push("destroy");
      },
      onBlocked: (message) => calls.push(`blocked:${message}`),
    });

    expect(result).toBe("blocked");
    expect(calls[0]).toBe("prevent");
    expect(calls[1]).toBe("blocked:审阅修改尚未安全保存，已阻止关闭窗口。请检查提示并重试。");
    expect(calls).not.toContain("destroy");
  });

  it("only marks an active review with unsaved sequences for close-time flush", () => {
    const context = createExtractionContext(
      "request-close",
      "project-1",
      "provider-1",
      ["file-a"],
    );
    const reviewing = extractionReducer(
      { kind: "generating", context } satisfies ExtractionState,
      {
        type: "generated",
        requestId: "request-close",
        reviewId: "review-close",
        draft,
        revision: 0,
        repaired: false,
      },
    );

    expect(extractionReviewNeedsCloseFlush(reviewing, 0, 1, false)).toBe(
      true,
    );
    expect(extractionReviewNeedsCloseFlush(reviewing, 1, 1, false)).toBe(
      false,
    );
    expect(extractionReviewNeedsCloseFlush(reviewing, 0, 1, true)).toBe(
      true,
    );
    expect(
      extractionReviewNeedsCloseFlush({ kind: "idle" }, 0, 1, true),
    ).toBe(false);
  });

  it("blocks window close until confirm or discard IPC has a known result", () => {
    expect(extractionMutationBlocksClose(true, false)).toBe(true);
    expect(extractionMutationBlocksClose(false, true)).toBe(true);
    expect(extractionMutationBlocksClose(false, false)).toBe(false);
  });
});
