import type { PrivacyRiskReviewState } from "./risk-types";

export const PRIVACY_CONFIG_SCHEMA_VERSION = 1;

export type PrivacyMode = "raw_native" | "external_redacted";
export type LocalOcrMode = "off" | "auto_local" | "force_local";

export interface LocalOcrConfig {
  mode: LocalOcrMode;
  workerPath: string | null;
  modelDirectory: string | null;
  toolsConfigPath: string | null;
  runtimeExecutablePaths: string[];
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
  | "configured_unverified"
  | "ready";

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
  workerProtocolVersion?: string | null;
  workerProtocolIdentitySha256?: string | null;
  workerHealthEvidenceSha256?: string | null;
  pythonVersion?: string | null;
  mineruVersion?: string | null;
  pytorchVersion?: string | null;
  cudaRuntimeVersion?: string | null;
  gpuDriverVersion?: string | null;
}
export type LocalMineruDiscoverySource = "uv_tool" | "common_local";

export interface LocalMineruDiscoveryResult {
  source: LocalMineruDiscoverySource;
  ocrConfig: LocalOcrConfig;
  appManagedToolsConfig: boolean;
  requiresUserSave: boolean;
  trustInstalled: boolean;
  networkIsolationInstalled: boolean;
  qualified: boolean;
}

export interface PrivacyVNextQualificationStatus {
  qualificationId: string | null;
  qualificationReportId: string | null;
  qualificationReportSha256: string | null;
  syntheticCanaryQualified: boolean;
  processingChainQualified: boolean;
  exactWorkerModelMatch: boolean;
  networkIsolationEnforced: boolean;
  modelManifestTrustEstablished: boolean;
  appAutoEnableAuthorized: boolean;
  productionCaseOcrAuthorized: boolean;
  expiresAtUnix: number | null;
  revoked: boolean;
  reasonCodes: string[];
  selectedCudaDevice?: number | null;
  selectedGpuMemoryMib?: number | null;
  selectedGpuName?: string | null;
}

export interface PrivacyVNextCapabilityMatrix {
  localGpuPreferenceConfigurable: boolean;
  scannedCaseOcrEnabled: boolean;
  automaticApprovalEnabled: boolean;
  appAutoOcrEnabled: boolean;
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
    | "local_review_safe_pdf_ready_case_provider_production_mcp_fail_closed_public_legal_tools_only"
    | "local_review_safe_exports_approved_paths_qualification_gated";
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

export interface TrustInstallationStatus {
  installationId: string;
  workerSha256: string;
  toolsConfigSha256: string;
  modelManifestSha256: string;
  modelFileCount: number;
  runtimeExecutableCount: number;
}

export interface RunLocalMineruQualificationRequest {
  ttlSeconds: number;
  productionCaseOcrAuthorized: boolean;
  appAutoEnableAuthorized: boolean;
}

export interface PrivacyConfigDraft {
  privacyMode: PrivacyMode;
  ocrMode: LocalOcrMode;
  workerPath: string;
  modelDirectory: string;
  toolsConfigPath: string;
  runtimeExecutablePaths: string;
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
  | "visual_content_present"
  | "page_annotations_present"
  | "interactive_form_present"
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

export interface PrivacyInputTransformTrace {
  schemaVersion: number;
  transformVersion: string;
  sourceMediaType: string;
  sourceSha256: string;
  processingMediaType: string;
  processingSha256: string;
  pixelWidth: number;
  pixelHeight: number;
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

export interface PrivacyVaultIsolationStatus {
  isolationLevel: string;
  privateAclEnforced: boolean;
  contentIndexingDisabled: boolean;
  encryptedAtRest: boolean;
  brokerBoundary: string;
  strongServiceIdentityBoundary: boolean;
  sameUserProcessLimitation: string;
}

export interface PrivacyReview {
  redactionId: string;
  materialId: string;
  caseId: string | null;
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
  riskReview: PrivacyRiskReviewState | null;
}

export interface PreparePrivacyMaterialRequest {
  caseId?: string | null;
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
  expectedRiskRevision?: number | null;
  expectedSuggestedRedactedSha256: string;
  editedPages: EditedRedactedPage[];
  reviewer: string;
  destination: ReceiptDestination;
  purpose: string;
  ttlSeconds: number;
}

export interface ApprovePrivacyReviewResponse {
  receiptId: string;
  approvedPayloadSha256: string;
  redactedContentSha256: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  destination: ReceiptDestination;
  purpose: string;
  transportEnforcement:
    "active_receipt_persisted_exact_destination";
}

export type SafeExportFormat = "pdf" | "txt" | "markdown" | "docx";

export interface ExportApprovedPrivacyReviewRequest {
  redactionId: string;
  format: SafeExportFormat;
}

export interface ExportApprovedPrivacyReviewResponse {
  cancelled: boolean;
  format: SafeExportFormat;
  fileName: string | null;
  mediaType: string;
  artifactSha256: string | null;
  approvedTextSha256: string | null;
  reopenedTextSha256: string | null;
  sourcePageCount: number;
  outputPageCount: number;
}

export interface RetentionPolicyView {
  policyId: string;
  reviewRetentionSeconds: number;
  mappingRetentionSeconds: number;
  receiptGraceSeconds: number;
  backupRetentionSeconds: number;
  revision: number;
  updatedAtUnix: number;
}

export interface RetentionBindingView {
  redactionId: string;
  expiresAtUnix: number;
  legalHold: boolean;
  boundAtUnix: number;
  policyRevision: number;
  holdChangedAtUnix: number | null;
}

export interface MappingRevisionView {
  mappingId: string;
  redactionId: string;
  revision: number;
  keyVersion: number;
  mappingRevisionSha256: string;
  createdAtUnix: number;
  expiresAtUnix: number;
  revoked: boolean;
}

export interface MappingKeyView {
  keyVersion: number;
  protectedKeySha256: string;
  state: string;
  createdAtUnix: number;
  retiredAtUnix: number | null;
  revokedAtUnix: number | null;
  destroyedAtUnix: number | null;
}

export interface LifecycleStatusView {
  workspaceInstanceId: string;
  keyEpoch: number;
  retentionPolicy: RetentionPolicyView;
  retentionBindings: RetentionBindingView[];
  mappingRevisions: MappingRevisionView[];
  mappingKeys: MappingKeyView[];
  cleanupJournalEvents: number;
  mappingAccessEvents: number;
  erasureDisclosure: string;
}

export interface LifecycleStatusRequest {
  redactionId: string | null;
}

export interface SetRetentionPolicyRequest {
  reviewRetentionSeconds: number;
  mappingRetentionSeconds: number;
  receiptGraceSeconds: number;
  backupRetentionSeconds: number;
}

export interface SetLegalHoldRequest {
  redactionId: string;
  enabled: boolean;
}

export interface RevealMappingRequest {
  mappingId: string;
  redactionId: string;
}

export interface RevealedMappingEntryView {
  alias: string;
  sensitiveValue: string;
}

export interface RevealMappingResponse {
  mappingId: string;
  redactionId: string;
  entries: RevealedMappingEntryView[];
}

export interface RevokeMappingRequest {
  mappingId: string;
  confirmation: string;
}

export interface RotateMappingKeyRequest {
  confirmation: string;
}

export interface DestroyMappingKeyRequest {
  keyVersion: number;
  expectedProtectedKeySha256: string;
  confirmation: string;
}

export interface RunRetentionSweepRequest {
  confirmation: string;
}

export interface CleanupReportView {
  cleanupId: string;
  state: string;
  candidates: number;
  removed: number;
  keysDestroyed: number;
  startedAtUnix: number;
  completedAtUnix: number;
  eventHash: string;
  erasureDisclosure: string;
}

export interface BackupIdRequest {
  backupId: string;
}

export interface StagePrivacyRestoreRequest {
  backupId: string;
  confirmation: string;
}

export interface VerifiedBackupView {
  backupId: string;
  workspaceInstanceId: string;
  createdAtUnix: number;
  expiresAtUnix: number;
  keyEpoch: number;
  databaseSha256: string;
  envelopeSha256: string;
  restartRequired: boolean;
}

export interface PortablePrivacyBackupExportResponse {
  cancelled: boolean;
  backupId: string;
  bundleSha256: string | null;
  bytesWritten: number;
}

export interface PortablePrivacyBackupImportResponse {
  cancelled: boolean;
  bundleSha256: string | null;
  backup: VerifiedBackupView | null;
}

export interface ApplicationBackupMetadata {
  backupId: string;
  privacyBackupId: string;
  workspaceInstanceId: string;
  appVersion: string;
  userSchemaVersion: number;
  createdAtUnix: number;
  expiresAtUnix: number;
  userDatabaseBytes: number;
  userDatabaseSha256: string;
  encryptedPrivacyBundleBytes: number;
  encryptedPrivacyBundleSha256: string;
  encryptedVaultBundleBytes: number;
  encryptedVaultBundleSha256: string;
  vaultManifestSha256: string;
  userDatabaseChunkCount: number;
  privacyBundleChunkCount: number;
  vaultBundleChunkCount: number;
  chunkCount: number;
  bundleSha256: string;
}

export interface ApplicationBackupResponse {
  cancelled: boolean;
  metadata: ApplicationBackupMetadata | null;
  restartRequired: boolean;
}

export interface StageApplicationRestoreRequest {
  confirmation: string;
}

export type ApprovedProviderTask =
  | "summary"
  | "legal_analysis"
  | "chronology"
  | "document_outline"
  | "structured_extraction"
  | "assistant"
  | "case_organization"
  | "case_legal_qa"
  | "relationship_graph"
  | "document_generation"
  | "regenerate"
  | "repair";

export interface ApprovedProviderPriorOutputRef {
  outputId: string;
  task: ApprovedProviderTask;
}

export interface ApproveApprovedProviderTaskRequest {
  redactionId: string;
  expectedRiskRevision: number | null;
  expectedSuggestedRedactedSha256: string;
  editedPages: EditedRedactedPage[];
  reviewer: string;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderPriorOutputRef | null;
  maxTokens: number;
  ttlSeconds: number;
  confirmed: boolean;
}

export interface ApproveApprovedProviderTaskResponse {
  receiptId: string;
  approvedPayloadSha256: string;
  redactedContentSha256: string;
  taskBindingSha256: string;
  providerId: string;
  modelId: string;
  purpose: string;
  task: ApprovedProviderTask;
  issuedAtUnix: number;
  expiresAtUnix: number;
  transportEnforcement: string;
}

export interface ProviderQualificationRequest {
  providerId: string;
}

export interface ProviderQualificationRunRequest {
  providerId: string;
  ttlSeconds: number;
}

export interface ProviderQualificationStatus {
  qualified: boolean;
  reasonCode: string;
  evidenceId: string | null;
  evidenceSha256: string | null;
  providerId: string | null;
  providerContractSha256: string | null;
  modelId: string | null;
  endpointOriginSha256: string | null;
  taskContractSha256: string;
  exactWorkspaceAppPolicyBinding: boolean;
  exactProviderContractBinding: boolean;
  exactTaskContractBinding: boolean;
  prepareCanaryPassed: boolean;
  approvalRestoreCanaryPassed: boolean;
  realLoopbackTransportPassed: boolean;
  approvedOutputPersisted: boolean;
  rawCanaryAbsent: boolean;
  exactlyOneRequest: boolean;
  signingKeyId: string | null;
  signingKeyVersion: number;
  revocationEpoch: number | null;
  issuedAtUnix: number | null;
  expiresAtUnix: number | null;
  revoked: boolean;
}

export interface DispatchApprovedProviderRequest {
  redactionId: string;
  providerId: string;
  task: ApprovedProviderTask;
  instruction: string;
  priorOutput: ApprovedProviderPriorOutputRef | null;
  maxTokens: number;
}

export interface DispatchApprovedProviderResponse {
  resultId: string;
  providerId: string;
  modelId: string;
  purpose: string;
  task: ApprovedProviderTask;
  taskBindingSha256: string;
  content: string;
  contentSha256: string;
  approvalGenerationId: string;
}

export interface ListApprovedProviderOutputsRequest {
  redactionId: string;
  providerId: string;
}

export interface ApprovedProviderOutputSummary {
  outputId: string;
  redactionId: string;
  approvalGenerationId: string;
  task: ApprovedProviderTask;
  taskBindingSha256: string;
  providerSha256: string;
  modelSha256: string;
  purposeSha256: string;
  approvedPayloadSha256: string;
  contentSha256: string;
  contentBytes: number;
  createdAtUnix: number;
  expiresAtUnix: number;
  revoked: boolean;
  eligibleAsPrior: boolean;
}

export interface LoadApprovedProviderOutputRequest {
  outputId: string;
  redactionId: string;
  providerId: string;
  modelId: string;
  task: ApprovedProviderTask;
}

export interface ApprovedProviderOutput {
  outputId: string;
  redactionId: string;
  approvalGenerationId: string;
  content: string;
  contentSha256: string;
  createdAtUnix: number;
  expiresAtUnix: number;
}

export interface RevokeApprovedProviderOutputRequest {
  outputId: string;
  redactionId: string;
}
