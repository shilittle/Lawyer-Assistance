import { describe, expect, it, vi } from "vitest";

import type { CaseRedactionReview } from "../../../ipc/privacy/case-material-types";
import {
  caseRedactionDraftIsDirty,
  caseRedactionNonCustomDraftIsDirty,
  caseRedactionPagesAreDirty,
  cloneCaseRedactionDraftSnapshot,
  executeCaseRedactionHistoryIfClean,
  type CaseRedactionDraftSnapshot,
} from "./redactionWorkbenchState";

const review = {
  pages: [
    { pageNumber: 1, redactedText: "第 1 页" },
    { pageNumber: 2, redactedText: "第 2 页" },
  ],
} as CaseRedactionReview;

const baseline: CaseRedactionDraftSnapshot = {
  customTerms: "",
  editedPages: [
    { pageNumber: 1, redactedText: "第 1 页" },
    { pageNumber: 2, redactedText: "第 2 页" },
  ],
  approvalDraft: {
    reviewer: "",
    ttlSeconds: "3600",
    target: { kind: "local_safe_export", format: "pdf" },
  },
};

describe("case redaction draft state", () => {
  it("marks only an exact complete page set as clean", () => {
    expect(
      caseRedactionPagesAreDirty(review, [
        { pageNumber: 1, redactedText: "第 1 页" },
        { pageNumber: 2, redactedText: "第 2 页" },
      ]),
    ).toBe(false);
    expect(
      caseRedactionPagesAreDirty(review, [
        { pageNumber: 1, redactedText: "已修改" },
        { pageNumber: 2, redactedText: "第 2 页" },
      ]),
    ).toBe(true);
    expect(
      caseRedactionPagesAreDirty(review, [
        { pageNumber: 1, redactedText: "第 1 页" },
      ]),
    ).toBe(true);
    expect(caseRedactionPagesAreDirty(null, [])).toBe(false);
  });

  it.each([
    [
      "custom terms",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.customTerms = "客户姓名";
      },
    ],
    [
      "edited pages",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.editedPages = [
          { pageNumber: 1, redactedText: "已修改" },
          { pageNumber: 2, redactedText: "第 2 页" },
        ];
      },
    ],
    [
      "reviewer",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.approvalDraft.reviewer = "复核律师";
      },
    ],
    [
      "TTL",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.approvalDraft.ttlSeconds = "7200";
      },
    ],
    [
      "approval target",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.approvalDraft.target = {
          kind: "local_safe_export",
          format: "docx",
        };
      },
    ],
  ])("tracks %s as an unsaved draft", (_label, edit) => {
    const current = cloneCaseRedactionDraftSnapshot(baseline);
    edit(current);
    expect(
      caseRedactionDraftIsDirty(baseline, current, false),
    ).toBe(true);
  });

  it("includes risk-panel drafts and can exclude only submitted custom terms", () => {
    const current = cloneCaseRedactionDraftSnapshot(baseline);
    current.customTerms = "本次导入词";

    expect(
      caseRedactionDraftIsDirty(baseline, current, false),
    ).toBe(true);
    expect(
      caseRedactionNonCustomDraftIsDirty(
        baseline,
        current,
        false,
      ),
    ).toBe(false);
    expect(
      caseRedactionNonCustomDraftIsDirty(
        baseline,
        current,
        true,
      ),
    ).toBe(true);
  });

  it("becomes clean only after the successful values become the new baseline", () => {
    const current = cloneCaseRedactionDraftSnapshot(baseline);
    current.approvalDraft.reviewer = "复核律师";
    current.editedPages = [
      { pageNumber: 1, redactedText: "已人工复核" },
      { pageNumber: 2, redactedText: "第 2 页" },
    ];

    expect(
      caseRedactionDraftIsDirty(baseline, current, false),
    ).toBe(true);
    const successfulBaseline =
      cloneCaseRedactionDraftSnapshot(current);
    expect(
      caseRedactionDraftIsDirty(
        successfulBaseline,
        current,
        false,
      ),
    ).toBe(false);
    expect(
      caseRedactionDraftIsDirty(baseline, current, false),
    ).toBe(true);
  });

  it.each([
    [
      "edited page",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.editedPages = [
          { pageNumber: 1, redactedText: "尚未提交的页编辑" },
          { pageNumber: 2, redactedText: "第 2 页" },
        ];
      },
    ],
    [
      "approval draft",
      (draft: CaseRedactionDraftSnapshot) => {
        draft.approvalDraft.ttlSeconds = "7200";
      },
    ],
  ])(
    "performs zero history IPC for an unsaved %s",
    async (_label, edit) => {
      const current =
        cloneCaseRedactionDraftSnapshot(baseline);
      edit(current);
      const invokeHistory = vi.fn(async () => "history");
      const result =
        await executeCaseRedactionHistoryIfClean(
          caseRedactionDraftIsDirty(
            baseline,
            current,
            false,
          ),
          invokeHistory,
        );

      expect(result).toEqual({ executed: false });
      expect(invokeHistory).not.toHaveBeenCalled();
    },
  );

  it("executes history IPC only for a fully clean workbench", async () => {
    const invokeHistory = vi.fn(async () => "history");
    const result = await executeCaseRedactionHistoryIfClean(
      false,
      invokeHistory,
    );
    expect(result).toEqual({
      executed: true,
      value: "history",
    });
    expect(invokeHistory).toHaveBeenCalledOnce();
  });
});
