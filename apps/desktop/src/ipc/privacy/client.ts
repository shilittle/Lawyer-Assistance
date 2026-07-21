import { invoke } from "@tauri-apps/api/core";

import type {
  ApprovePrivacyReviewRequest,
  ApprovePrivacyReviewResponse,
  DeletePrivacyReviewRequest,
  DeletePrivacyReviewResponse,
  ExportApprovedReviewPdfRequest,
  ExportApprovedReviewPdfResponse,
  InspectLocalMineruQualificationReportRequest,
  LoadPrivacyReviewRequest,
  PreparePrivacyMaterialRequest,
  PreparePrivacyMaterialResponse,
  PrivacyReview,
  LocalOcrStatus,
  PrivacyConfigResponse,
  SavePrivacyConfigRequest,
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

export function exportApprovedReviewPdf(
  request: ExportApprovedReviewPdfRequest,
): Promise<ExportApprovedReviewPdfResponse> {
  return invoke<ExportApprovedReviewPdfResponse>(
    "export_approved_review_pdf",
    { request },
  );
}
