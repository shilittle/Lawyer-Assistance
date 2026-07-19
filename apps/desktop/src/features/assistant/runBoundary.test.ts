import { describe, expect, it } from "vitest";

import {
  advanceAssistantRunEventCursor,
  applyAssistantCancellationResult,
  assistantAttachmentPolicy,
} from "./runBoundary";

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
