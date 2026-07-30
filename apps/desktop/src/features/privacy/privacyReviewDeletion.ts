import type {
  DeletePrivacyReviewRequest,
  DeletePrivacyReviewResponse,
} from "../../ipc/privacy/types";

export const PRIVACY_REVIEW_DELETION_CONFIRMATION =
  "确认将该材料标记为已删除，并撤销全部脱敏代次、回执、发布与派生工作能力吗？版本、加密复核记录和哈希审计会按保留策略留存；所选外部原始文书与已另存的 PDF 不会被删除。";

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
