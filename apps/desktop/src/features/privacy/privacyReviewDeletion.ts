import type {
  DeletePrivacyReviewRequest,
  DeletePrivacyReviewResponse,
} from "../../ipc/privacy/types";

export const PRIVACY_REVIEW_DELETION_CONFIRMATION =
  "确认撤销当前审阅的全部回执，并删除应用内加密复核数据吗？这不会删除所选原始文书或已另存的 PDF；不含正文的哈希审计会保留。";

export interface PrivacyReviewDeletionDependencies {
  confirm: (message: string) => boolean;
  deleteReview: (
    request: DeletePrivacyReviewRequest,
  ) => Promise<DeletePrivacyReviewResponse>;
  onConfirmed?: () => void;
}

export type PrivacyReviewDeletionOutcome =
  | { cancelled: true; deleted: false }
  | { cancelled: false; deleted: boolean };

export async function deletePrivacyReviewAfterConfirmation(
  request: DeletePrivacyReviewRequest,
  dependencies: PrivacyReviewDeletionDependencies,
): Promise<PrivacyReviewDeletionOutcome> {
  if (!dependencies.confirm(PRIVACY_REVIEW_DELETION_CONFIRMATION)) {
    return { cancelled: true, deleted: false };
  }
  dependencies.onConfirmed?.();
  const response = await dependencies.deleteReview(request);
  return { cancelled: false, deleted: response.deleted };
}
