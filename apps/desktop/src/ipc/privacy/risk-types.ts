export type PrivacyEntityType =
  | "person_name"
  | "organization_name"
  | "case_number"
  | "identity_number"
  | "passport_number"
  | "phone_number"
  | "landline_number"
  | "bank_account"
  | "email_address"
  | "address"
  | "organization_code"
  | "business_license_number"
  | "vehicle_plate"
  | "ip_address"
  | "social_account"
  | "payment_account"
  | "account_name"
  | "contract_number"
  | "tracking_number"
  | "property_certificate_number"
  | "custom";

export type PrivacyFindingSeverity =
  | "p0_blocking"
  | "p1_high"
  | "p2_medium"
  | "p3_resolved"
  | "informational";

export type PrivacyReviewResolution =
  | "unresolved"
  | "accepted"
  | "modified"
  | "not_sensitive"
  | "cluster_merged"
  | "cluster_split"
  | "revoked";

export type PrivacyDocumentRoute =
  | "auto_approval_eligible"
  | "quick_review_required"
  | "full_review_required"
  | "blocked";

export type AutoApprovalPolicyMode =
  | "strict"
  | "balanced"
  | "batch"
  | "shadow"
  | "disabled";

export interface PrivacyFindingView {
  findingId: string;
  pageIndex: number;
  blockId: string;
  startOffset: number;
  endOffset: number;
  entityType: PrivacyEntityType;
  detectorSources: string[];
  detectorVersions: Record<string, string>;
  modelVersions: Record<string, string>;
  calibratedConfidencePpm: number | null;
  ocrConfidencePpm: number | null;
  layoutConfidencePpm: number | null;
  caseDictionaryMatch: boolean;
  clusterId: string | null;
  clusterOccurrenceCount: number;
  detectorAgreement: boolean;
  severity: PrivacyFindingSeverity;
  reviewPriority: number;
  reasonCodes: string[];
  proposedReplacement: string;
  resolutionState: PrivacyReviewResolution;
}

export interface PrivacyPageRiskView {
  pageIndex: number;
  p0Count: number;
  p1Count: number;
  p2Count: number;
  p3Count: number;
  ocrMinPpm: number | null;
  ocrMeanPpm: number | null;
  ocrP10Ppm: number | null;
  coveragePpm: number;
  unknownLongNumberCount: number;
  visualRisks: string[];
  completenessPassed: boolean;
  detectorConflictCount: number;
  clusterInconsistencyCount: number;
  visualReviewRequired: boolean;
  readinessScore: number;
  reasonCodes: string[];
}

export interface PrivacyDocumentRiskView {
  route: PrivacyDocumentRoute;
  readinessScore: number;
  pageRisks: PrivacyPageRiskView[];
  totalP0: number;
  totalP1: number;
  totalP2: number;
  policyId: string;
  policyVersion: number;
  calibrationEvidenceVersion: string | null;
  qualificationReportId: string | null;
  autoApprovalPolicyMode: AutoApprovalPolicyMode;
  productionAutomaticEnabled: boolean;
  shadowWouldAutoApprove: boolean;
  automaticPublishAllowed: boolean;
  reasonCodes: string[];
}

export interface PrivacyHardGateView {
  gateId: string;
  passed: boolean;
  blocking: boolean;
  reasonCodes: string[];
}

export interface PrivacyResidualSummaryView {
  passed: boolean;
  evidenceHash: string;
  blockingHitCount: number;
  reviewHitCount: number;
  reasonCodes: string[];
}

export type PrivacyVisualRiskDecision =
  | "confirmed_redacted"
  | "confirmed_reviewed_non_sensitive";

export interface PrivacyVisualRiskResolution {
  pageIndex: number;
  riskCode: string;
  decision: PrivacyVisualRiskDecision;
  reason: string;
  actorHash: string;
  provenanceHash: string;
  redactedContentSha256: string;
  resolvedAtUnix: number;
  evidenceHash: string;
}

export interface PrivacyRiskReviewState {
  schemaVersion: "privacy-risk-review-state-v1";
  redactionId: string;
  caseId: string;
  materialId: string;
  documentVersion: number;
  detectorRunCompleted: boolean;
  revision: number;
  documentRisk: PrivacyDocumentRiskView;
  hardGates: PrivacyHardGateView[];
  findings: PrivacyFindingView[];
  residualScan: PrivacyResidualSummaryView;
  visualRiskResolutions: PrivacyVisualRiskResolution[];
  canUndo: boolean;
  canRedo: boolean;
  rejected: boolean;
}

export type PrivacyDictionaryCategory =
  | "party"
  | "agent"
  | "legal_representative"
  | "contact"
  | "witness"
  | "company"
  | "agency"
  | "court"
  | "address"
  | "contact_information"
  | "account"
  | "custom";

export type PrivacyRiskReviewAction =
  | { kind: "accept_replacement"; findingId: string; applyCluster: boolean }
  | { kind: "change_entity_type"; findingId: string; entityType: PrivacyEntityType }
  | { kind: "change_placeholder"; findingId: string; replacement: string; applyCluster: boolean }
  | { kind: "mark_not_sensitive"; findingId: string }
  | { kind: "add_to_dictionary"; findingId: string; category: PrivacyDictionaryCategory; required: boolean }
  | { kind: "merge_clusters"; clusterIds: string[] }
  | { kind: "split_cluster"; findingId: string }
  | { kind: "resolve_visual_risk"; pageIndex: number; riskCode: string; decision: PrivacyVisualRiskDecision; reason: string }
  | { kind: "confirm_edited_output" }
  | { kind: "batch_accept_p3" }
  | { kind: "reject_publication" };

export interface LoadPrivacyRiskReviewRequest { redactionId: string }
export interface ApplyPrivacyRiskReviewActionRequest {
  redactionId: string;
  expectedRevision: number;
  actor: string;
  editedPages: Array<{ pageNumber: number; redactedText: string }>;
  action: PrivacyRiskReviewAction;
}
export interface PrivacyRiskReviewRevisionRequest {
  redactionId: string;
  expectedRevision: number;
}
