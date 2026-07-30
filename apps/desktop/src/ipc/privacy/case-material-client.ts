import { invoke } from "@tauri-apps/api/core";

import type {
  ApplyCaseRedactionRiskReviewActionRequest,
  ApproveCaseRedactionReviewRequest,
  ApproveCaseRedactionReviewResponse,
  AssignUnassignedCaseMaterialRequest,
  AssignUnassignedCaseMaterialResponse,
  CaseMaterialSummary,
  CaseRedactionGenerationSummary,
  CaseRedactionReview,
  CaseRedactionRiskReviewRevisionRequest,
  DeleteCaseRedactionReviewRequest,
  DeleteCaseRedactionReviewResponse,
  ExportApprovedCaseRedactionRequest,
  ExportApprovedCaseRedactionResponse,
  ListCaseMaterialsRequest,
  ListCaseRedactionGenerationsRequest,
  ListUnassignedCaseMaterialsRequest,
  LoadCaseRedactionReviewRequest,
  PrepareCaseMaterialRequest,
  PrepareCaseMaterialResponse,
  UnassignedCaseMaterialSummary,
} from "./case-material-types";

const FORBIDDEN_CASE_IDENTITY_KEYS = new Set([
  "caseId",
  "case_id",
  "privacyCaseId",
  "privacy_case_id",
]);

function stripForbiddenCaseIdentity<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map(stripForbiddenCaseIdentity) as T;
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !FORBIDDEN_CASE_IDENTITY_KEYS.has(key))
      .map(([key, item]) => [
        key,
        stripForbiddenCaseIdentity(item),
      ]),
  ) as T;
}

function invokeCaseMaterial<T>(
  command: string,
  request: object,
): Promise<T> {
  return invoke<T>(command, { request }).then(
    stripForbiddenCaseIdentity,
  );
}

export function prepareCaseMaterial(
  request: PrepareCaseMaterialRequest,
): Promise<PrepareCaseMaterialResponse> {
  return invokeCaseMaterial("prepare_case_material", request);
}

export function listCaseMaterials(
  request: ListCaseMaterialsRequest,
): Promise<CaseMaterialSummary[]> {
  return invokeCaseMaterial("list_case_materials", request);
}

export function listUnassignedCaseMaterials(
  request: ListUnassignedCaseMaterialsRequest,
): Promise<UnassignedCaseMaterialSummary[]> {
  return invokeCaseMaterial(
    "list_unassigned_case_materials",
    request,
  );
}

export function assignUnassignedCaseMaterial(
  request: AssignUnassignedCaseMaterialRequest,
): Promise<AssignUnassignedCaseMaterialResponse> {
  return invokeCaseMaterial(
    "assign_unassigned_case_material",
    request,
  );
}

export function listCaseRedactionGenerations(
  request: ListCaseRedactionGenerationsRequest,
): Promise<CaseRedactionGenerationSummary[]> {
  return invokeCaseMaterial(
    "list_case_redaction_generations",
    request,
  );
}

export function loadCaseRedactionReview(
  request: LoadCaseRedactionReviewRequest,
): Promise<CaseRedactionReview> {
  return invokeCaseMaterial("load_case_redaction_review", request);
}

export function applyCaseRedactionRiskReviewAction(
  request: ApplyCaseRedactionRiskReviewActionRequest,
): Promise<CaseRedactionReview> {
  return invokeCaseMaterial(
    "apply_case_redaction_risk_review_action",
    request,
  );
}

export function undoCaseRedactionRiskReview(
  request: CaseRedactionRiskReviewRevisionRequest,
): Promise<CaseRedactionReview> {
  return invokeCaseMaterial(
    "undo_case_redaction_risk_review",
    request,
  );
}

export function redoCaseRedactionRiskReview(
  request: CaseRedactionRiskReviewRevisionRequest,
): Promise<CaseRedactionReview> {
  return invokeCaseMaterial(
    "redo_case_redaction_risk_review",
    request,
  );
}

export function approveCaseRedactionReview(
  request: ApproveCaseRedactionReviewRequest,
): Promise<ApproveCaseRedactionReviewResponse> {
  return invokeCaseMaterial("approve_case_redaction_review", request);
}

export function exportApprovedCaseRedaction(
  request: ExportApprovedCaseRedactionRequest,
): Promise<ExportApprovedCaseRedactionResponse> {
  return invokeCaseMaterial(
    "export_approved_case_redaction",
    request,
  );
}

export function deleteCaseRedactionReview(
  request: DeleteCaseRedactionReviewRequest,
): Promise<DeleteCaseRedactionReviewResponse> {
  return invokeCaseMaterial("delete_case_redaction_review", request);
}
