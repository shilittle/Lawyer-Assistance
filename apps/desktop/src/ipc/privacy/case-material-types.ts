import type {
  ApprovePrivacyReviewRequest,
  ApprovePrivacyReviewResponse,
  DeletePrivacyReviewRequest,
  DeletePrivacyReviewResponse,
  ExportApprovedPrivacyReviewRequest,
  ExportApprovedPrivacyReviewResponse,
  PrivacyBackendTrace,
  PrivacyInputTransformTrace,
  PrivacyReviewPage,
  PrivacyVaultIsolationStatus,
  RedactionSummary,
} from "./types";
import type {
  ApplyPrivacyRiskReviewActionRequest,
  PrivacyRiskReviewRevisionRequest,
  PrivacyRiskReviewState,
} from "./risk-types";

export interface CaseMaterialSummary {
  projectId: string;
  materialId: string;
  displayName: string;
  mediaType: string | null;
  sourceKind: string;
  extractionStatus: string;
  migrationStatus: string;
  state: string;
  latestReviewState: string | null;
  latestGenerationStatus: string | null;
  latestRevocationState: string | null;
  generationCount: number;
  updatedAt: string;
  deletedAt: string | null;
}

export interface CaseRedactionGenerationSummary {
  projectId: string;
  materialId: string;
  redactionId: string;
  generationNumber: number;
  generationStatus: string;
  reviewState: string;
  riskRevision: number;
  approvedPayloadSha256: string | null;
  approvedAt: string | null;
  revocationState: string;
  revokedAt: string | null;
  createdAt: string;
}

/**
 * Case-facing risk state deliberately excludes the Privacy/Vault identity.
 * Project ownership is supplied by the outer review and revalidated by Rust.
 */
export type CaseRedactionRiskReviewState = Omit<
  PrivacyRiskReviewState,
  "caseId"
> & {
  projectId: string;
};

export interface CaseRedactionReview {
  projectId: string;
  generationNumber: number;
  redactionId: string;
  materialId: string;
  vaultObjectId: string | null;
  vaultObjectVersion: number | null;
  vaultIsolation: PrivacyVaultIsolationStatus | null;
  sourceDisplayName: string;
  sourceSha256: string;
  extractionSha256: string;
  suggestedRedactedContentSha256: string;
  processingVersion: string;
  mediaType: string;
  pageCount: number;
  backendTrace: PrivacyBackendTrace[];
  inputTransform?: PrivacyInputTransformTrace | null;
  summary: RedactionSummary;
  reviewState: "review_required" | "approved" | "revoked";
  pages: PrivacyReviewPage[];
  riskReview: CaseRedactionRiskReviewState | null;
}

export interface PrepareCaseMaterialRequest {
  projectId: string;
  customTerms: string[];
}

export interface PrepareCaseMaterialResponse {
  cancelled: boolean;
  review: CaseRedactionReview | null;
}

export interface ListCaseMaterialsRequest {
  projectId: string;
}

export interface UnassignedCaseMaterialSummary {
  materialId: string;
  displayName: string;
  mediaType: string | null;
  sourceKind: string;
  extractionStatus: string;
  migrationStatus: string;
  state: string;
  generationCount: number;
  historicalIdentity: "preserved" | "missing";
  assignable: boolean;
  rowVersion: number;
  updatedAt: string;
  deletedAt: string | null;
}

export interface ListUnassignedCaseMaterialsRequest {
  projectId: string;
}

export interface AssignUnassignedCaseMaterialRequest {
  projectId: string;
  materialId: string;
  expectedRowVersion: number;
  actor: string;
}

export interface AssignUnassignedCaseMaterialResponse {
  assignmentId: string;
  projectId: string;
  materialId: string;
  assignmentMode:
    | "initialize_null_case"
    | "preserve_historical_case";
  bindingAction: "created" | "reused";
  materialRowVersion: number;
  idempotentReplay: boolean;
}

export interface ListCaseRedactionGenerationsRequest {
  projectId: string;
  materialId: string;
}

export interface LoadCaseRedactionReviewRequest {
  projectId: string;
  redactionId: string;
}

export type ApplyCaseRedactionRiskReviewActionRequest = {
  projectId: string;
} & ApplyPrivacyRiskReviewActionRequest;

export type CaseRedactionRiskReviewRevisionRequest = {
  projectId: string;
} & PrivacyRiskReviewRevisionRequest;

export type ApproveCaseRedactionReviewRequest = {
  projectId: string;
} & ApprovePrivacyReviewRequest;

export type ApproveCaseRedactionReviewResponse =
  ApprovePrivacyReviewResponse;

export type ExportApprovedCaseRedactionRequest = {
  projectId: string;
} & ExportApprovedPrivacyReviewRequest;

export type ExportApprovedCaseRedactionResponse =
  ExportApprovedPrivacyReviewResponse;

export type DeleteCaseRedactionReviewRequest = {
  projectId: string;
} & DeletePrivacyReviewRequest;

export type DeleteCaseRedactionReviewResponse =
  DeletePrivacyReviewResponse;
