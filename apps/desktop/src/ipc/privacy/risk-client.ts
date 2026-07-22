import { invoke } from "@tauri-apps/api/core";

import type {
  ApplyPrivacyRiskReviewActionRequest,
  LoadPrivacyRiskReviewRequest,
  PrivacyRiskReviewRevisionRequest,
  PrivacyRiskReviewState,
} from "./risk-types";
import type { PrivacyReview } from "./types";

export function loadPrivacyRiskReview(
  request: LoadPrivacyRiskReviewRequest,
): Promise<PrivacyRiskReviewState> {
  return invoke("load_privacy_risk_review", { request });
}

export function applyPrivacyRiskReviewAction(
  request: ApplyPrivacyRiskReviewActionRequest,
): Promise<PrivacyReview> {
  return invoke("apply_privacy_risk_review_action", { request });
}

export function undoPrivacyRiskReview(
  request: PrivacyRiskReviewRevisionRequest,
): Promise<PrivacyReview> {
  return invoke("undo_privacy_risk_review", { request });
}

export function redoPrivacyRiskReview(
  request: PrivacyRiskReviewRevisionRequest,
): Promise<PrivacyReview> {
  return invoke("redo_privacy_risk_review", { request });
}
