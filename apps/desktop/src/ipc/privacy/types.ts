export const PRIVACY_CONFIG_SCHEMA_VERSION = 1;

export type PrivacyMode = "raw_native" | "external_redacted";
export type LocalOcrMode = "off" | "auto_local" | "force_local";

export interface LocalOcrConfig {
  mode: LocalOcrMode;
  workerPath: string | null;
  modelDirectory: string | null;
  device: string;
  languages: string[];
  timeoutSeconds: number;
  maxPages: number;
  strictOffline: true;
  forbidCloudFallback: true;
  forbidRemoteUpload: true;
  forbidTelemetry: true;
}

export interface PrivacyConfig {
  schemaVersion: number;
  privacyMode: PrivacyMode;
  ocr: LocalOcrConfig;
}

export type LocalOcrStatusCode =
  | "disabled"
  | "not_configured"
  | "unavailable"
  | "configured_unverified";

export interface LocalOcrStatus {
  code: LocalOcrStatusCode;
  message: string;
  workerVersion: string | null;
  modelVersion: string | null;
  workerSha256: string | null;
  modelManifestSha256: string | null;
  workerPresent: boolean;
  modelDirectoryPresent: boolean;
  integrityVerified: boolean;
  networkIsolationVerified: boolean;
}

export interface PrivacyVNextQualificationStatus {
  qualificationReportId: string | null;
  qualificationReportSha256: string | null;
  processingChainQualified: boolean;
  exactWorkerModelMatch: boolean;
  networkIsolationEnforced: boolean;
  modelManifestTrustEstablished: boolean;
  appAutoEnableAuthorized: boolean;
  productionCaseOcrAuthorized: boolean;
}

export interface PrivacyVNextCapabilityMatrix {
  localGpuPreferenceConfigurable: boolean;
  scannedCaseOcrEnabled: boolean;
  automaticApprovalEnabled: boolean;
  approvedCaseMcpEnabled: boolean;
  remoteOcrFallbackAllowed: boolean;
  telemetryAllowed: boolean;
  rawMaterialUploadAllowed: boolean;
  blockingReasonCodes: string[];
}

export interface PrivacyConfigResponse {
  config: PrivacyConfig;
  configValid: boolean;
  loadError: string | null;
  enforcementState:
    | "configuration_only"
    | "local_review_safe_pdf_ready_case_provider_production_mcp_fail_closed_public_legal_tools_only";
  ocrStatus: LocalOcrStatus;
  qualification: PrivacyVNextQualificationStatus;
  capabilities: PrivacyVNextCapabilityMatrix;
}

export interface SavePrivacyConfigRequest {
  config: PrivacyConfig;
}

export interface InspectLocalMineruQualificationReportRequest {
  reportJson: string;
}

export interface PrivacyConfigDraft {
  privacyMode: PrivacyMode;
  ocrMode: LocalOcrMode;
  workerPath: string;
  modelDirectory: string;
  device: string;
  languages: string;
  timeoutSeconds: string;
  maxPages: string;
}
export type DestinationKind =
  | "external_provider"
  | "external_mcp_host"
  | "verified_local_provider";

export interface ReceiptDestination {
  kind: DestinationKind;
  identifier: string;
}

export type PageExtractionDecision =
  | "native_accepted"
  | "local_ocr_required"
  | "blocked";

export type QualityReasonCode =
  | "native_text_healthy"
  | "too_little_text"
  | "low_printable_ratio"
  | "excess_replacement_characters"
  | "suspicious_reading_order"
  | "forced_local_ocr"
  | "ocr_disabled";

export interface TextLayerAssessment {
  pageNumber: number;
  nonWhitespaceChars: number;
  printableRatio: number;
  replacementCharRatio: number;
  cjkRatio: number;
  readingOrderScore: number;
  decision: PageExtractionDecision;
  reasonCodes: QualityReasonCode[];
}

export type ExtractionBackend = "native_text" | "mineru_local";

export interface PrivacyBackendTrace {
  backend: ExtractionBackend;
  workerSha256: string | null;
  modelManifestSha256: string | null;
  configSha256: string | null;
  device: string;
  pageNumbers: number[];
  isolationVerified: boolean;
  isolationMechanism: string | null;
}

export interface RedactionSummary {
  total: number;
  counts: Record<string, number>;
  changed: boolean;
  manualReviewRequired: boolean;
  redactionVersion: string;
}

export interface PrivacyReviewPage {
  pageNumber: number;
  locator: string;
  assessment: TextLayerAssessment;
  originalText: string;
  redactedText: string;
}

export interface PrivacyReview {
  redactionId: string;
  materialId: string;
  sourceDisplayName: string;
  sourceSha256: string;
  extractionSha256: string;
  suggestedRedactedContentSha256: string;
  processingVersion: string;
  mediaType: string;
  pageCount: number;
  backendTrace: PrivacyBackendTrace[];
  summary: RedactionSummary;
  reviewState: "review_required" | "approved" | "revoked";
  pages: PrivacyReviewPage[];
}

export interface PreparePrivacyMaterialRequest {
  customTerms: string[];
}

export interface PreparePrivacyMaterialResponse {
  cancelled: boolean;
  review: PrivacyReview | null;
}

export interface LoadPrivacyReviewRequest {
  redactionId: string;
}

export interface DeletePrivacyReviewRequest {
  redactionId: string;
  expectedSourceSha256: string;
  expectedExtractionSha256: string;
}

export interface DeletePrivacyReviewResponse {
  deleted: boolean;
}

export interface EditedRedactedPage {
  pageNumber: number;
  redactedText: string;
}

export interface ApprovePrivacyReviewRequest {
  redactionId: string;
  expectedSuggestedRedactedSha256: string;
  editedPages: EditedRedactedPage[];
  reviewer: string;
  destination: ReceiptDestination;
  purpose: string;
  ttlSeconds: number;
}

export interface ApprovePrivacyReviewResponse {
  receiptId: string;
  receiptToken: string;
  approvedPayloadJson: string;
  approvedPayloadSha256: string;
  redactedContentSha256: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  destination: ReceiptDestination;
  purpose: string;
  transportEnforcement:
    "local_receipt_issued_provider_transport_not_fully_gated";
}

export interface ExportApprovedReviewPdfRequest {
  redactionId: string;
  receiptToken: string;
  approvedPayloadJson: string;
  destination: ReceiptDestination;
  purpose: string;
}

export interface ExportApprovedReviewPdfResponse {
  cancelled: boolean;
  fileName: string | null;
  pdfSha256: string | null;
  approvedTextSha256: string | null;
  extractedTextSha256: string | null;
  outputPageCount: number;
}
