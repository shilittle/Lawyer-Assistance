import type { CaseRedactionReview } from "../../../ipc/privacy/case-material-types";
import type { EditedRedactedPage } from "../../../ipc/privacy/types";
import type { ApprovalDraft } from "../../privacy/PrivacyReviewWorkbench";

export interface CaseRedactionDraftSnapshot {
  customTerms: string;
  editedPages: readonly EditedRedactedPage[];
  approvalDraft: ApprovalDraft;
}

export function cloneCaseRedactionDraftSnapshot(
  snapshot: CaseRedactionDraftSnapshot,
): CaseRedactionDraftSnapshot {
  return {
    customTerms: snapshot.customTerms,
    editedPages: snapshot.editedPages.map((page) => ({ ...page })),
    approvalDraft: {
      reviewer: snapshot.approvalDraft.reviewer,
      ttlSeconds: snapshot.approvalDraft.ttlSeconds,
      target: { ...snapshot.approvalDraft.target },
    },
  };
}

export function caseRedactionPagesAreDirty(
  review: CaseRedactionReview | null,
  editedPages: readonly EditedRedactedPage[],
): boolean {
  if (!review) return false;
  if (review.pages.length !== editedPages.length) return true;
  const editedByNumber = new Map(
    editedPages.map((page) => [page.pageNumber, page.redactedText]),
  );
  return review.pages.some(
    (page) => editedByNumber.get(page.pageNumber) !== page.redactedText,
  );
}

function editedPagesMatch(
  left: readonly EditedRedactedPage[],
  right: readonly EditedRedactedPage[],
): boolean {
  if (left.length !== right.length) return false;
  const rightByNumber = new Map(
    right.map((page) => [page.pageNumber, page.redactedText]),
  );
  return left.every(
    (page) => rightByNumber.get(page.pageNumber) === page.redactedText,
  );
}

function approvalDraftsMatch(
  left: ApprovalDraft,
  right: ApprovalDraft,
): boolean {
  return (
    left.reviewer === right.reviewer &&
    left.ttlSeconds === right.ttlSeconds &&
    left.target.kind === right.target.kind &&
    left.target.format === right.target.format
  );
}

export function caseRedactionDraftIsDirty(
  baseline: CaseRedactionDraftSnapshot,
  current: CaseRedactionDraftSnapshot,
  riskReviewDraftDirty: boolean,
): boolean {
  return (
    riskReviewDraftDirty ||
    baseline.customTerms !== current.customTerms ||
    !editedPagesMatch(baseline.editedPages, current.editedPages) ||
    !approvalDraftsMatch(
      baseline.approvalDraft,
      current.approvalDraft,
    )
  );
}

export function caseRedactionNonCustomDraftIsDirty(
  baseline: CaseRedactionDraftSnapshot,
  current: CaseRedactionDraftSnapshot,
  riskReviewDraftDirty: boolean,
): boolean {
  return (
    riskReviewDraftDirty ||
    !editedPagesMatch(baseline.editedPages, current.editedPages) ||
    !approvalDraftsMatch(
      baseline.approvalDraft,
      current.approvalDraft,
    )
  );
}

export type GuardedCaseRedactionHistoryResult<T> =
  | { executed: false }
  | { executed: true; value: T };

export async function executeCaseRedactionHistoryIfClean<T>(
  draftDirty: boolean,
  execute: () => Promise<T>,
): Promise<GuardedCaseRedactionHistoryResult<T>> {
  if (draftDirty) return { executed: false };
  return {
    executed: true,
    value: await execute(),
  };
}
