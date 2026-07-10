export type CaseProjectStatus = "active" | "archived";
export type PartyRole =
  | "plaintiff"
  | "defendant"
  | "claimant"
  | "respondent"
  | "third_party"
  | "other";
export type ConfirmationStatus = "model_suggested" | "confirmed";
export type LegalIssueStatus = "open" | "resolved";
export type CitationStatus = "valid" | "invalid";
export type CitationInvalidReason =
  | "invalid_syntax"
  | "duplicate"
  | "not_found"
  | "not_in_context"
  | "version_mismatch"
  | "date_out_of_range"
  | "paragraph_not_found";

export interface CaseProject {
  projectId: string;
  title: string;
  caseType: string;
  status: CaseProjectStatus;
  openedOn?: string | null;
  summary: string;
  createdAt: string;
  updatedAt: string;
}

export interface CaseFile {
  fileId: string;
  projectId: string;
  title: string;
  fileType: string;
  storageReference: string;
  summary: string;
  createdAt: string;
}

export interface CaseParty {
  partyId: string;
  projectId: string;
  name: string;
  normalizedName: string;
  role: PartyRole;
  contact: string;
  notes: string;
}

export interface CaseFact {
  factId: string;
  projectId: string;
  occurredOn?: string | null;
  title: string;
  description: string;
  source: string;
  confirmationStatus: ConfirmationStatus;
}

export interface EvidenceItem {
  evidenceId: string;
  projectId: string;
  evidenceNumber: string;
  title: string;
  source: string;
  formedOn?: string | null;
  summary: string;
  storageReference: string;
  confirmationStatus: ConfirmationStatus;
}

export interface EvidenceLink {
  linkId: string;
  projectId: string;
  factId: string;
  evidenceId: string;
}

export interface LegalIssue {
  issueId: string;
  projectId: string;
  title: string;
  description: string;
  claim: string;
  status: LegalIssueStatus;
  confirmationStatus: ConfirmationStatus;
}

export interface LegalBasis {
  basisId: string;
  projectId: string;
  issueId?: string | null;
  sourceId: string;
  status: CitationStatus;
  invalidReason?: CitationInvalidReason | null;
  caseDate?: string | null;
  articleId: string;
  documentId: string;
  versionId: string;
  documentTitle: string;
  versionLabel: string;
  articleNumber: string;
  articleTitle?: string | null;
  canonicalLabel: string;
  effectiveFrom: string;
  effectiveTo?: string | null;
  versionStatus: string;
  excerpt: string;
  note: string;
  createdAt: string;
}

export type CaseGapKind =
  | "timeline_conflict"
  | "party_name_inconsistent"
  | "evidence_missing_source"
  | "fact_missing_evidence"
  | "evidence_missing_formed_on"
  | "invalid_evidence_id"
  | "legal_issue_missing_basis";

export type CaseGapSeverity = "warning" | "blocking";

export interface CaseGap {
  gapId: string;
  projectId: string;
  kind: CaseGapKind;
  severity: CaseGapSeverity;
  entityId: string;
  message: string;
}

export interface CaseWorkspace {
  project: CaseProject;
  files: CaseFile[];
  parties: CaseParty[];
  facts: CaseFact[];
  evidence: EvidenceItem[];
  evidenceLinks: EvidenceLink[];
  legalIssues: LegalIssue[];
  legalBasis: LegalBasis[];
  gaps: CaseGap[];
}

export interface CaseProjectsResponse {
  projects: CaseProject[];
}

export interface GetCaseWorkspaceRequest {
  projectId: string;
}

export interface GetCaseWorkspaceResponse {
  workspace?: CaseWorkspace | null;
}

export interface UpsertCaseProjectRequest {
  project: CaseProject;
}

export interface UpsertCaseFileRequest {
  file: CaseFile;
}

export interface CaseProjectResponse {
  project: CaseProject;
}

export interface DeleteCaseProjectRequest {
  projectId: string;
}

export interface DeleteCaseProjectResponse {
  deleted: boolean;
}

export interface UpsertCasePartyRequest {
  party: CaseParty;
}

export interface UpsertCaseFactRequest {
  fact: CaseFact;
}

export interface UpsertEvidenceItemRequest {
  evidence: EvidenceItem;
}

export interface UpsertEvidenceLinkRequest {
  link: EvidenceLink;
}

export interface UpsertLegalIssueRequest {
  issue: LegalIssue;
}

export interface AddCaseLegalBasisRequest {
  projectId: string;
  issueId?: string | null;
  sourceId: string;
  caseDate?: string | null;
  includeExpired: boolean;
  note: string;
}

export interface AddCaseLegalBasisResponse {
  basis: LegalBasis;
}

export interface EntitySavedResponse {
  saved: boolean;
}

export type CaseEntityType =
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "evidence_link"
  | "legal_issue"
  | "legal_basis";

export interface DeleteCaseEntityRequest {
  entityType: CaseEntityType;
  id: string;
}

export interface DeleteCaseEntityResponse {
  deleted: boolean;
}

export interface AnalyzeCaseGapsRequest {
  projectId: string;
}

export interface AnalyzeCaseGapsResponse {
  gaps: CaseGap[];
}

export interface ParseStructuredCaseExtractionRequest {
  rawOutput: string;
  repairedOutput?: string | null;
}

export type StructuredCaseExtractionStatus = "parsed" | "failed";

export interface StructuredCaseExtractionResponse {
  status: StructuredCaseExtractionStatus;
  extraction?: unknown | null;
  error?: { errorType: string; message: string } | null;
  rawOutput: string;
  repaired: boolean;
}

export interface ParseStructuredCaseExtractionResponse {
  result: StructuredCaseExtractionResponse;
}
