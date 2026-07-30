import type { PrivacyRiskReviewState } from "../../ipc/privacy/risk-types";
import type { PrivacyReview } from "../../ipc/privacy/types";

export type PrivacyRiskReviewDisplayState = Omit<
  PrivacyRiskReviewState,
  "caseId"
>;

/**
 * The reusable review view does not need the Privacy/Vault case identity.
 * The optional project fields let the case-scoped workflow show its public
 * application identity without widening the legacy Privacy IPC contract.
 */
export type PrivacyReviewDisplay = Omit<
  PrivacyReview,
  "caseId" | "riskReview"
> & {
  projectId?: string;
  generationNumber?: number;
  riskReview: PrivacyRiskReviewDisplayState | null;
};
