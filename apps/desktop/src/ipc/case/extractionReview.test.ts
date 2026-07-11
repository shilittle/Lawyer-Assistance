import { describe, expect, it } from "vitest";

import {
  buildConfirmationRequest,
  createExtractionContext,
  extractionLocksSources,
  extractionReducer,
  type ExtractionState,
} from "./extractionReview";
import type { StructuredCaseExtraction } from "./types";

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
  it("freezes generation provenance and confirms the reviewed edit", () => {
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
      repaired: true,
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
      extraction: { facts: [{ title: "用户修改后的标题" }] },
    });
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
});
