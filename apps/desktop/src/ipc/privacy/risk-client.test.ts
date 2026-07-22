import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  applyPrivacyRiskReviewAction,
  loadPrivacyRiskReview,
  redoPrivacyRiskReview,
  undoPrivacyRiskReview,
} from "./risk-client";

describe("privacy risk review IPC", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses revision-bound persisted commands and sends only edited redacted pages", async () => {
    const redactionId = `red_${"a".repeat(32)}`;
    const editedPages = [{ pageNumber: 1, redactedText: "[PERSON_A]" }];
    await loadPrivacyRiskReview({ redactionId });
    await applyPrivacyRiskReviewAction({
      redactionId,
      expectedRevision: 7,
      actor: "local-reviewer",
      editedPages,
      action: {
        kind: "resolve_visual_risk",
        pageIndex: 0,
        riskCode: "seal_text_unresolved",
        decision: "confirmed_redacted",
        reason: "印章文字已经在当前脱敏页中替换",
      },
    });
    await undoPrivacyRiskReview({ redactionId, expectedRevision: 8 });
    await redoPrivacyRiskReview({ redactionId, expectedRevision: 9 });

    expect(invoke).toHaveBeenNthCalledWith(1, "load_privacy_risk_review", {
      request: { redactionId },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "apply_privacy_risk_review_action", {
      request: {
        redactionId,
        expectedRevision: 7,
        actor: "local-reviewer",
        editedPages,
        action: {
          kind: "resolve_visual_risk",
          pageIndex: 0,
          riskCode: "seal_text_unresolved",
          decision: "confirmed_redacted",
          reason: "印章文字已经在当前脱敏页中替换",
        },
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "undo_privacy_risk_review", {
      request: { redactionId, expectedRevision: 8 },
    });
    expect(invoke).toHaveBeenNthCalledWith(4, "redo_privacy_risk_review", {
      request: { redactionId, expectedRevision: 9 },
    });
    expect(JSON.stringify(invoke.mock.calls)).not.toMatch(/original|path|privateValue/iu);
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("rerun_privacy_detection");
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("rerun_privacy_ocr");
  });
});
