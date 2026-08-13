import { invoke } from "@tauri-apps/api/core";

import type {
  ApplicationBackupResponse,
  ApprovedProviderOutput,
  ApprovedProviderOutputSummary,
  ApproveApprovedProviderTaskRequest,
  ApproveApprovedProviderTaskResponse,
  ApprovePrivacyReviewRequest,
  ApprovePrivacyReviewResponse,
  BackupIdRequest,
  CleanupReportView,
  DeletePrivacyReviewRequest,
  DeletePrivacyReviewResponse,
  DestroyMappingKeyRequest,
  DispatchApprovedProviderRequest,
  DispatchApprovedProviderResponse,
  ExportApprovedPrivacyReviewRequest,
  ExportApprovedPrivacyReviewResponse,
  InspectLocalMineruQualificationReportRequest,
  LifecycleStatusRequest,
  LifecycleStatusView,
  ListApprovedProviderOutputsRequest,
  LoadApprovedProviderOutputRequest,
  LoadPrivacyReviewRequest,
  PreparePrivacyMaterialRequest,
  PreparePrivacyMaterialResponse,
  PrivacyReview,
  LocalOcrStatus,
  LocalMineruDiscoveryResult,
  PortablePrivacyBackupExportResponse,
  PortablePrivacyBackupImportResponse,
  PrivacyConfigResponse,
  ProviderQualificationRequest,
  ProviderQualificationRunRequest,
  ProviderQualificationStatus,
  RevealMappingRequest,
  RevealMappingResponse,
  RevokeApprovedProviderOutputRequest,
  RevokeMappingRequest,
  RotateMappingKeyRequest,
  RunRetentionSweepRequest,
  SavePrivacyConfigRequest,
  RunLocalMineruQualificationRequest,
  SetLegalHoldRequest,
  SetRetentionPolicyRequest,
  StageApplicationRestoreRequest,
  StagePrivacyRestoreRequest,
  StageV031MigrationRecoveryRequest,
  TrustInstallationStatus,
  VerifiedBackupView,
} from "./types";

export function getPrivacyConfig(): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>("get_privacy_config");
}

export function savePrivacyConfig(
  request: SavePrivacyConfigRequest,
): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>("save_privacy_config", { request });
}

export function getLocalOcrStatus(): Promise<LocalOcrStatus> {
  return invoke<LocalOcrStatus>("get_local_ocr_status");
}
export function discoverLocalMineru(): Promise<LocalMineruDiscoveryResult> {
  return invoke<LocalMineruDiscoveryResult>("discover_local_mineru");
}

export function installLocalMineruTrust(): Promise<TrustInstallationStatus> {
  return invoke<TrustInstallationStatus>("install_local_mineru_trust");
}

export function installLocalMineruNetworkIsolation(): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>("install_local_mineru_network_isolation");
}

export function runLocalMineruQualification(
  request: RunLocalMineruQualificationRequest,
): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>("run_local_mineru_qualification", { request });
}

export function revokeLocalMineruQualification(): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>("revoke_local_mineru_qualification");
}
export function inspectLocalMineruQualificationReport(
  request: InspectLocalMineruQualificationReportRequest,
): Promise<PrivacyConfigResponse> {
  return invoke<PrivacyConfigResponse>(
    "inspect_local_mineru_qualification_report",
    { request },
  );
}
export function preparePrivacyMaterial(
  request: PreparePrivacyMaterialRequest,
): Promise<PreparePrivacyMaterialResponse> {
  return invoke<PreparePrivacyMaterialResponse>("prepare_privacy_material", {
    request,
  });
}

export function loadPrivacyReview(
  request: LoadPrivacyReviewRequest,
): Promise<PrivacyReview> {
  return invoke<PrivacyReview>("load_privacy_review", { request });
}

export function loadLatestPrivacyReview(): Promise<PrivacyReview | null> {
  return invoke<PrivacyReview | null>("load_latest_privacy_review");
}
export function deletePrivacyReview(
  request: DeletePrivacyReviewRequest,
): Promise<DeletePrivacyReviewResponse> {
  return invoke<DeletePrivacyReviewResponse>("delete_privacy_review", {
    request,
  });
}

export function approvePrivacyReview(
  request: ApprovePrivacyReviewRequest,
): Promise<ApprovePrivacyReviewResponse> {
  return invoke<ApprovePrivacyReviewResponse>("approve_privacy_review", {
    request,
  });
}

export function exportApprovedPrivacyReview(
  request: ExportApprovedPrivacyReviewRequest,
): Promise<ExportApprovedPrivacyReviewResponse> {
  return invoke<ExportApprovedPrivacyReviewResponse>(
    "export_approved_privacy_review",
    { request },
  );
}

export function getPrivacyLifecycleStatus(
  request: LifecycleStatusRequest,
): Promise<LifecycleStatusView> {
  return invoke<LifecycleStatusView>("get_privacy_lifecycle_status", { request });
}

export function setPrivacyRetentionPolicy(
  request: SetRetentionPolicyRequest,
): Promise<LifecycleStatusView["retentionPolicy"]> {
  return invoke<LifecycleStatusView["retentionPolicy"]>(
    "set_privacy_retention_policy",
    { request },
  );
}

export function setPrivacyLegalHold(request: SetLegalHoldRequest): Promise<void> {
  return invoke<void>("set_privacy_legal_hold", { request });
}

export function revealPrivacyMapping(
  request: RevealMappingRequest,
): Promise<RevealMappingResponse> {
  return invoke<RevealMappingResponse>("reveal_privacy_mapping", { request });
}

export function revokePrivacyMapping(request: RevokeMappingRequest): Promise<void> {
  return invoke<void>("revoke_privacy_mapping", { request });
}

export function rotatePrivacyMappingKey(
  request: RotateMappingKeyRequest,
): Promise<number> {
  return invoke<number>("rotate_privacy_mapping_key", { request });
}

export function destroyPrivacyMappingKey(
  request: DestroyMappingKeyRequest,
): Promise<void> {
  return invoke<void>("destroy_privacy_mapping_key", { request });
}

export function runPrivacyRetentionSweep(
  request: RunRetentionSweepRequest,
): Promise<CleanupReportView> {
  return invoke<CleanupReportView>("run_privacy_retention_sweep", { request });
}

export function createPrivacyBackup(): Promise<VerifiedBackupView> {
  return invoke<VerifiedBackupView>("create_privacy_backup");
}

export function verifyPrivacyBackup(
  request: BackupIdRequest,
): Promise<VerifiedBackupView> {
  return invoke<VerifiedBackupView>("verify_privacy_backup", { request });
}

export function exportPrivacyBackupBundle(
  request: BackupIdRequest,
): Promise<PortablePrivacyBackupExportResponse> {
  return invoke<PortablePrivacyBackupExportResponse>(
    "export_privacy_backup_bundle",
    { request },
  );
}

export function importPrivacyBackupBundle(): Promise<PortablePrivacyBackupImportResponse> {
  return invoke<PortablePrivacyBackupImportResponse>("import_privacy_backup_bundle");
}

export function revokePrivacyBackup(request: BackupIdRequest): Promise<void> {
  return invoke<void>("revoke_privacy_backup", { request });
}

export function stagePrivacyRestore(
  request: StagePrivacyRestoreRequest,
): Promise<VerifiedBackupView> {
  return invoke<VerifiedBackupView>("stage_privacy_restore", { request });
}

export function exportApplicationBackup(): Promise<ApplicationBackupResponse> {
  return invoke<ApplicationBackupResponse>("export_application_backup");
}

export function verifyApplicationBackup(): Promise<ApplicationBackupResponse> {
  return invoke<ApplicationBackupResponse>("verify_application_backup");
}

export function stageApplicationRestore(
  request: StageApplicationRestoreRequest,
): Promise<ApplicationBackupResponse> {
  return invoke<ApplicationBackupResponse>("stage_application_restore", {
    request,
  });
}

export function stageV031MigrationRecovery(
  request: StageV031MigrationRecoveryRequest,
): Promise<void> {
  return invoke<void>("stage_v031_migration_recovery", { request });
}

export function getProviderQualificationStatus(
  request: ProviderQualificationRequest,
): Promise<ProviderQualificationStatus> {
  return invoke<ProviderQualificationStatus>("get_provider_qualification_status", {
    request,
  });
}

export function runProviderQualification(
  request: ProviderQualificationRunRequest,
): Promise<ProviderQualificationStatus> {
  return invoke<ProviderQualificationStatus>("run_provider_qualification", {
    request,
  });
}

export function revokeProviderQualification(
  request: ProviderQualificationRequest,
): Promise<ProviderQualificationStatus> {
  return invoke<ProviderQualificationStatus>("revoke_provider_qualification", {
    request,
  });
}

export function approveApprovedProviderTask(
  request: ApproveApprovedProviderTaskRequest,
): Promise<ApproveApprovedProviderTaskResponse> {
  return invoke<ApproveApprovedProviderTaskResponse>(
    "approve_approved_provider_task",
    { request },
  );
}

export function dispatchApprovedProvider(
  request: DispatchApprovedProviderRequest,
): Promise<DispatchApprovedProviderResponse> {
  return invoke<DispatchApprovedProviderResponse>("dispatch_approved_provider", {
    request,
  });
}

export function listApprovedProviderOutputs(
  request: ListApprovedProviderOutputsRequest,
): Promise<ApprovedProviderOutputSummary[]> {
  return invoke<ApprovedProviderOutputSummary[]>("list_approved_provider_outputs", {
    request,
  });
}

export function loadApprovedProviderOutput(
  request: LoadApprovedProviderOutputRequest,
): Promise<ApprovedProviderOutput> {
  return invoke<ApprovedProviderOutput>("load_approved_provider_output", {
    request,
  });
}

export function revokeApprovedProviderOutput(
  request: RevokeApprovedProviderOutputRequest,
): Promise<void> {
  return invoke<void>("revoke_approved_provider_output", { request });
}
