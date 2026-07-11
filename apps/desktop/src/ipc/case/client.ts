import { invoke } from "@tauri-apps/api/core";

import type {
  AddCaseLegalBasisRequest,
  AddCaseLegalBasisResponse,
  AnalyzeCaseGapsRequest,
  AnalyzeCaseGapsResponse,
  CaseProjectResponse,
  CaseProjectsResponse,
  ConfirmStructuredCaseExtractionRequest,
  ConfirmStructuredCaseExtractionResponse,
  DeleteCaseEntityRequest,
  DeleteCaseEntityResponse,
  DeleteCaseProjectRequest,
  DeleteCaseProjectResponse,
  DiscardStructuredCaseExtractionRequest,
  DiscardStructuredCaseExtractionResponse,
  EntitySavedResponse,
  GetCaseWorkspaceRequest,
  GetCaseWorkspaceResponse,
  GenerateStructuredCaseExtractionResponse,
  StructuredCaseExtractionRequest,
  UpsertCaseFileRequest,
  UpsertCaseFactRequest,
  UpsertCasePartyRequest,
  UpsertCaseProjectRequest,
  UpsertEvidenceItemRequest,
  UpsertEvidenceLinkRequest,
  UpsertLegalIssueRequest,
} from "./types";

export function listCaseProjects(): Promise<CaseProjectsResponse> {
  return invoke<CaseProjectsResponse>("list_case_projects");
}

export function getCaseWorkspace(
  request: GetCaseWorkspaceRequest,
): Promise<GetCaseWorkspaceResponse> {
  return invoke<GetCaseWorkspaceResponse>("get_case_workspace", { request });
}

export function upsertCaseProject(
  request: UpsertCaseProjectRequest,
): Promise<CaseProjectResponse> {
  return invoke<CaseProjectResponse>("upsert_case_project", { request });
}

export function upsertCaseFile(
  request: UpsertCaseFileRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_case_file", { request });
}

export function deleteCaseProject(
  request: DeleteCaseProjectRequest,
): Promise<DeleteCaseProjectResponse> {
  return invoke<DeleteCaseProjectResponse>("delete_case_project", { request });
}

export function upsertCaseParty(
  request: UpsertCasePartyRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_case_party", { request });
}

export function upsertCaseFact(
  request: UpsertCaseFactRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_case_fact", { request });
}

export function upsertEvidenceItem(
  request: UpsertEvidenceItemRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_evidence_item", { request });
}

export function upsertEvidenceLink(
  request: UpsertEvidenceLinkRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_evidence_link", { request });
}

export function upsertLegalIssue(
  request: UpsertLegalIssueRequest,
): Promise<EntitySavedResponse> {
  return invoke<EntitySavedResponse>("upsert_legal_issue", { request });
}

export function addCaseLegalBasis(
  request: AddCaseLegalBasisRequest,
): Promise<AddCaseLegalBasisResponse> {
  return invoke<AddCaseLegalBasisResponse>("add_case_legal_basis", { request });
}

export function deleteCaseEntity(
  request: DeleteCaseEntityRequest,
): Promise<DeleteCaseEntityResponse> {
  return invoke<DeleteCaseEntityResponse>("delete_case_entity", { request });
}

export function analyzeCaseGaps(
  request: AnalyzeCaseGapsRequest,
): Promise<AnalyzeCaseGapsResponse> {
  return invoke<AnalyzeCaseGapsResponse>("analyze_case_gaps_command", {
    request,
  });
}

export function generateStructuredCaseExtraction(
  request: StructuredCaseExtractionRequest,
): Promise<GenerateStructuredCaseExtractionResponse> {
  return invoke<GenerateStructuredCaseExtractionResponse>(
    "generate_structured_case_extraction",
    { request },
  );
}

export function confirmStructuredCaseExtraction(
  request: ConfirmStructuredCaseExtractionRequest,
): Promise<ConfirmStructuredCaseExtractionResponse> {
  return invoke<ConfirmStructuredCaseExtractionResponse>(
    "confirm_structured_case_extraction",
    { request },
  );
}

export function discardStructuredCaseExtraction(
  request: DiscardStructuredCaseExtractionRequest,
): Promise<DiscardStructuredCaseExtractionResponse> {
  return invoke<DiscardStructuredCaseExtractionResponse>(
    "discard_structured_case_extraction",
    { request },
  );
}
