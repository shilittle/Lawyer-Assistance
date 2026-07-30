import { describe, expect, it, vi } from "vitest";

import {
  allowRiskFindingSwitch,
  cloneRiskReviewDraftSnapshot,
  riskReviewActionSucceeded,
  riskReviewDraftIsDirty,
  type RiskReviewDraftSnapshot,
} from "./riskReviewDraftState";

const baseline: RiskReviewDraftSnapshot = {
  entityType: "person_name",
  replacement: "[PERSON_A]",
  dictionaryCategory: "custom",
  dictionaryRequired: false,
  mergeTarget: "",
  visualReasons: {},
};

describe("risk review draft state", () => {
  it.each([
    [
      "entity type",
      (draft: RiskReviewDraftSnapshot) => {
        draft.entityType = "organization_name";
      },
    ],
    [
      "replacement",
      (draft: RiskReviewDraftSnapshot) => {
        draft.replacement = "[PERSON_B]";
      },
    ],
    [
      "dictionary category",
      (draft: RiskReviewDraftSnapshot) => {
        draft.dictionaryCategory = "party";
      },
    ],
    [
      "dictionary required",
      (draft: RiskReviewDraftSnapshot) => {
        draft.dictionaryRequired = true;
      },
    ],
    [
      "merge target",
      (draft: RiskReviewDraftSnapshot) => {
        draft.mergeTarget = "clu_target";
      },
    ],
    [
      "visual reason",
      (draft: RiskReviewDraftSnapshot) => {
        draft.visualReasons = {
          "0:seal_text_unresolved": "已逐像素复核",
        };
      },
    ],
  ])("tracks the unsaved %s field", (_label, edit) => {
    const current = cloneRiskReviewDraftSnapshot(baseline);
    edit(current);
    expect(riskReviewDraftIsDirty(baseline, current)).toBe(true);
  });

  it("treats an emptied visual-reason field as its clean absent baseline", () => {
    const current = cloneRiskReviewDraftSnapshot(baseline);
    current.visualReasons = { "0:seal_text_unresolved": "" };
    expect(riskReviewDraftIsDirty(baseline, current)).toBe(false);
  });

  it("does not clear a failed submission baseline", () => {
    const current = cloneRiskReviewDraftSnapshot(baseline);
    current.replacement = "[PERSON_REVIEWED]";
    expect(riskReviewDraftIsDirty(baseline, current)).toBe(true);

    const successfulBaseline =
      cloneRiskReviewDraftSnapshot(current);
    expect(
      riskReviewDraftIsDirty(successfulBaseline, current),
    ).toBe(false);
    expect(riskReviewDraftIsDirty(baseline, current)).toBe(true);
  });

  it("guards every finding switch with the complete dirty result", () => {
    const confirmDiscard = vi.fn(() => false);
    expect(allowRiskFindingSwitch(false, confirmDiscard)).toBe(true);
    expect(confirmDiscard).not.toHaveBeenCalled();

    expect(allowRiskFindingSwitch(true, confirmDiscard)).toBe(false);
    expect(confirmDiscard).toHaveBeenCalledOnce();
    confirmDiscard.mockReturnValue(true);
    expect(allowRiskFindingSwitch(true, confirmDiscard)).toBe(true);
  });

  it("clears a submitted draft only after an explicit successful result", () => {
    expect(riskReviewActionSucceeded(true)).toBe(true);
    expect(riskReviewActionSucceeded(false)).toBe(false);
    expect(riskReviewActionSucceeded(undefined)).toBe(false);
  });
});
