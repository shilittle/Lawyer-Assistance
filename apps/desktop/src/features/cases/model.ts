import type { CaseDraftKind } from "../../app/navigationGuards";
import type { PendingExtractionDraftSaveRequest } from "../../ipc/case/extractionReview";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  EvidenceItem,
  FactIssueLink,
  LegalBasis,
  LegalIssue,
} from "../../ipc/case/types";
import { formatEffectiveWindow } from "../../ipc/legal/format";
import type { GraphNode } from "../../ipc/graph/types";
import {
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";

export type ExtractionDraftSaveState =
  | { kind: "idle" }
  | { kind: "pending" }
  | { kind: "saving" }
  | { kind: "saved"; expiresAt: string }
  | { kind: "conflict"; message: string };

export interface PendingReviewRecoveryBlock {
  reviewId: string;
  projectId: string;
  revision: number;
  message: string;
  reloadRequired?: boolean;
}

export interface QueuedExtractionDraftSave {
  request: PendingExtractionDraftSaveRequest;
  sequence: number;
}

export interface MutableEpoch {
  current: number;
}

export interface MutableLock {
  current: boolean;
}

export type DeletableCaseEntityType =
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "evidence_link"
  | "fact_issue_link"
  | "legal_issue"
  | "legal_basis"
  | "uncertainty";

export function advanceRequestEpoch(epoch: MutableEpoch): number {
  epoch.current += 1;
  return epoch.current;
}

export function isCurrentRequestEpoch(
  epoch: MutableEpoch,
  requestEpoch: number,
): boolean {
  return epoch.current === requestEpoch;
}

export function advanceCaseWorkspaceEpoch(epoch: MutableEpoch): number {
  return advanceRequestEpoch(epoch);
}

export function isCurrentCaseWorkspaceEpoch(
  epoch: MutableEpoch,
  requestEpoch: number,
): boolean {
  return isCurrentRequestEpoch(epoch, requestEpoch);
}

export function tryAcquireCaseMutation(
  lock: MutableLock,
  epoch: MutableEpoch,
): number | null {
  if (lock.current) {
    return null;
  }

  lock.current = true;
  return advanceCaseWorkspaceEpoch(epoch);
}

export function releaseCaseMutation(lock: MutableLock): void {
  lock.current = false;
}

export function isPersistedCaseWorkspace(
  workspace: CaseWorkspace | null,
  selectedProjectId: string | null,
  draftProjectId: string,
): boolean {
  return (
    workspace !== null &&
    selectedProjectId === draftProjectId &&
    workspace.project.projectId === draftProjectId
  );
}

export type CaseDraftDirtyState = Record<CaseDraftKind, boolean>;

export interface CaseDraftComparisonState {
  project: { draft: CaseProject; baseline: CaseProject };
  file: { draft: CaseFile; baseline: CaseFile };
  party: { draft: CaseParty; baseline: CaseParty };
  fact: { draft: CaseFact; baseline: CaseFact };
  evidence: { draft: EvidenceItem; baseline: EvidenceItem };
  legalIssue: { draft: LegalIssue; baseline: LegalIssue };
  evidenceLink: {
    factId: string;
    evidenceId: string;
    baselineFactId: string;
    baselineEvidenceId: string;
  };
  factIssueLink: {
    factId: string;
    issueId: string;
    baselineFactId: string;
    baselineIssueId: string;
  };
  legalBasis: {
    sourceId: string;
    issueId: string;
    caseDate: string;
    includeExpired: boolean;
    note: string;
    baselineIssueId: string;
    baselineCaseDate: string;
  };
}

function fieldsDiffer<T extends object>(
  draft: T,
  baseline: T,
  fields: readonly (keyof T)[],
): boolean {
  return fields.some((field) => draft[field] !== baseline[field]);
}

export function detectDirtyCaseDrafts(
  state: CaseDraftComparisonState,
): CaseDraftDirtyState {
  return {
    project: fieldsDiffer(state.project.draft, state.project.baseline, [
      "title",
      "caseType",
      "status",
      "openedOn",
      "summary",
    ]),
    file: fieldsDiffer(state.file.draft, state.file.baseline, [
      "title",
      "fileType",
      "storageReference",
      "summary",
    ]),
    party: fieldsDiffer(state.party.draft, state.party.baseline, [
      "name",
      "normalizedName",
      "role",
      "contact",
      "notes",
    ]),
    fact: fieldsDiffer(state.fact.draft, state.fact.baseline, [
      "occurredOn",
      "title",
      "description",
      "source",
      "confirmationStatus",
    ]),
    evidence: fieldsDiffer(state.evidence.draft, state.evidence.baseline, [
      "evidenceNumber",
      "title",
      "source",
      "formedOn",
      "summary",
      "storageReference",
      "confirmationStatus",
    ]),
    legal_issue: fieldsDiffer(
      state.legalIssue.draft,
      state.legalIssue.baseline,
      ["title", "description", "claim", "status", "confirmationStatus"],
    ),
    evidence_link:
      state.evidenceLink.factId !== state.evidenceLink.baselineFactId ||
      state.evidenceLink.evidenceId !==
        state.evidenceLink.baselineEvidenceId,
    fact_issue_link:
      state.factIssueLink.factId !== state.factIssueLink.baselineFactId ||
      state.factIssueLink.issueId !== state.factIssueLink.baselineIssueId,
    legal_basis:
      state.legalBasis.sourceId.trim().length > 0 ||
      state.legalBasis.note.trim().length > 0 ||
      state.legalBasis.issueId !== state.legalBasis.baselineIssueId ||
      state.legalBasis.caseDate !== state.legalBasis.baselineCaseDate ||
      state.legalBasis.includeExpired,
  };
}

export function blockingDirtyCaseDrafts(
  dirty: CaseDraftDirtyState,
  allowed: readonly CaseDraftKind[],
): CaseDraftKind[] {
  const allowedKinds = new Set(allowed);
  return (Object.keys(dirty) as CaseDraftKind[]).filter(
    (kind) => dirty[kind] && !allowedKinds.has(kind),
  );
}

export type GraphNodeDestination = "case" | "law" | "unsupported";

export function graphNodeDestination(node: GraphNode): GraphNodeDestination {
  if (node.sourceKind === "legal_core") return "law";
  if (
    node.sourceKind === "case_fact" ||
    node.sourceKind === "evidence_item" ||
    node.sourceKind === "legal_issue" ||
    node.sourceKind === "verified_citation"
  ) {
    return "case";
  }
  return "unsupported";
}

export function caseGraphNodeDomId(sourceKind: string, sourceId: string): string {
  return `case-graph-source-${encodeURIComponent(sourceKind)}-${encodeURIComponent(sourceId)}`;
}

export function caseWorkspaceWritesAreSafe(
  workspace: CaseWorkspace | null,
  selectedProjectId: string | null,
  draftProjectId: string,
  writeBlocked: boolean,
): boolean {
  return (
    !writeBlocked &&
    isPersistedCaseWorkspace(workspace, selectedProjectId, draftProjectId)
  );
}

export type FactIssueLinkSelectionValidation =
  | { valid: true }
  | { valid: false; targetId: string; message: string };

export function validateFactIssueLinkSelection(
  factId: string,
  issueId: string,
  existingLinks: readonly FactIssueLink[],
): FactIssueLinkSelectionValidation {
  if (!factId) {
    return {
      valid: false,
      targetId: "case-fact-issue-fact",
      message: "请选择要关联的事实。",
    };
  }
  if (!issueId) {
    return {
      valid: false,
      targetId: "case-fact-issue-issue",
      message: "请选择要关联的争点。",
    };
  }
  if (
    existingLinks.some(
      (link) => link.factId === factId && link.issueId === issueId,
    )
  ) {
    return {
      valid: false,
      targetId: "case-fact-issue-issue",
      message: "该事实与争点已经存在显式关联，无需重复添加。",
    };
  }
  return { valid: true };
}

export const CASE_PROJECTS_PER_PAGE = 8;

export function clampCaseProjectPage(
  requestedPage: number,
  projectCount: number,
  pageSize = CASE_PROJECTS_PER_PAGE,
): number {
  const safePageSize = Math.max(1, Math.floor(pageSize));
  const totalPages = Math.max(1, Math.ceil(projectCount / safePageSize));
  return Math.min(Math.max(1, Math.floor(requestedPage) || 1), totalPages);
}

export function paginateCaseProjects(
  projects: readonly CaseProject[],
  requestedPage: number,
  pageSize = CASE_PROJECTS_PER_PAGE,
): { page: number; totalPages: number; projects: CaseProject[] } {
  const safePageSize = Math.max(1, Math.floor(pageSize));
  const page = clampCaseProjectPage(
    requestedPage,
    projects.length,
    safePageSize,
  );
  const totalPages = Math.max(1, Math.ceil(projects.length / safePageSize));
  const start = (page - 1) * safePageSize;

  return {
    page,
    totalPages,
    projects: projects.slice(start, start + safePageSize),
  };
}

export function caseProjectPageForId(
  projects: readonly CaseProject[],
  projectId: string,
  pageSize = CASE_PROJECTS_PER_PAGE,
): number {
  const safePageSize = Math.max(1, Math.floor(pageSize));
  const index = projects.findIndex((project) => project.projectId === projectId);
  return index < 0 ? 1 : Math.floor(index / safePageSize) + 1;
}

export function caseProjectToLoadAfterRefresh(
  projects: readonly CaseProject[],
  preferredProjectId: string | undefined,
  recoverAfterPersistedMutation: boolean,
): CaseProject | undefined {
  const preferredProject = projects.find(
    (project) => project.projectId === preferredProjectId,
  );
  return (
    preferredProject ??
    (recoverAfterPersistedMutation ? undefined : projects[0])
  );
}

export function pendingReviewFilesStillExist(
  workspaceFileIds: readonly string[],
  pendingFileIds: readonly string[],
): boolean {
  const available = new Set(workspaceFileIds);
  return pendingFileIds.every((fileId) => available.has(fileId));
}

export type EditableCaseEntityType =
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "legal_issue";

export interface ActiveCaseEntityEditor {
  entityType: EditableCaseEntityType;
  entityId: string;
}

type EditableCaseEntity =
  | CaseFile
  | CaseParty
  | CaseFact
  | EvidenceItem
  | LegalIssue;

export type CaseEntityEditTarget =
  | { entityType: "file"; entity: CaseFile }
  | { entityType: "party"; entity: CaseParty }
  | { entityType: "fact"; entity: CaseFact }
  | { entityType: "evidence"; entity: EvidenceItem }
  | { entityType: "legal_issue"; entity: LegalIssue };

export function caseEntityEditorMatches(
  editor: ActiveCaseEntityEditor | null,
  entityType: EditableCaseEntityType,
  entityId?: string,
): boolean {
  return (
    editor?.entityType === entityType &&
    (entityId === undefined || editor.entityId === entityId)
  );
}

export function caseEntityEditorAllows(
  editor: ActiveCaseEntityEditor | null,
  entityType: EditableCaseEntityType,
  entityId?: string,
): boolean {
  return (
    editor === null || caseEntityEditorMatches(editor, entityType, entityId)
  );
}

export function copyCaseEntityForEditing<T extends EditableCaseEntity>(
  entity: T,
): T {
  return { ...entity };
}

const LEGACY_GENERATED_EVIDENCE_NUMBER = /^service-[0-9a-f]{8,64}-\d+$/iu;

export function publicCaseBusinessText(
  value: string | null | undefined,
  fallback = "",
): string {
  if (!value?.trim()) return fallback;
  return sanitizePublicGeneratedText(value, fallback);
}

export function publicEvidenceNumber(
  value: string | null | undefined,
  fallback = "待编号",
): string {
  const normalized = value?.trim() ?? "";
  if (!normalized || LEGACY_GENERATED_EVIDENCE_NUMBER.test(normalized)) {
    return fallback;
  }
  const publicValue = sanitizePublicGeneratedText(normalized, "").trim();
  return publicTitle(publicValue, fallback);
}

export function createId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 7)}`;
}

export function createCaseProject(): CaseProject {
  return {
    projectId: createId("case"),
    title: "新案件",
    caseType: "民事",
    status: "active",
    openedOn: new Date().toISOString().slice(0, 10),
    summary: "",
    createdAt: "",
    updatedAt: "",
  };
}

export function createParty(projectId: string): CaseParty {
  return {
    partyId: createId("party"),
    projectId,
    name: "",
    normalizedName: "",
    role: "plaintiff",
    contact: "",
    notes: "",
  };
}

export function createCaseFile(projectId: string): CaseFile {
  return {
    fileId: createId("file"),
    projectId,
    title: "",
    fileType: "材料",
    storageReference: "",
    summary: "",
    createdAt: "",
  };
}

export function createFact(projectId: string): CaseFact {
  return {
    factId: createId("fact"),
    projectId,
    occurredOn: null,
    title: "",
    description: "",
    source: "",
    confirmationStatus: "confirmed",
  };
}

export function createEvidence(
  projectId: string,
  nextIndex: number,
): EvidenceItem {
  return {
    evidenceId: createId("evidence"),
    projectId,
    evidenceNumber: `E-${nextIndex}`,
    title: "",
    source: "",
    formedOn: null,
    summary: "",
    storageReference: "",
    confirmationStatus: "confirmed",
  };
}

export function createIssue(projectId: string): LegalIssue {
  return {
    issueId: createId("issue"),
    projectId,
    title: "",
    description: "",
    claim: "",
    status: "open",
    confirmationStatus: "confirmed",
  };
}

export function formatLegalBasisTitle(basis: LegalBasis): string {
  if (!basis.documentTitle || !basis.articleNumber) {
    return publicTitle(basis.canonicalLabel, "法律条文");
  }
  const year = /^(\d{4})/u.exec(basis.effectiveFrom)?.[1];
  return `《${publicTitle(basis.documentTitle, "法律文件")}》${publicTitle(
    basis.articleNumber,
    "相关条文",
  )}${year ? `（${year}年起施行）` : ""}`;
}

export function formatLegalBasisWindow(basis: LegalBasis): string {
  if (!basis.effectiveFrom) {
    return "未校验效力";
  }

  return formatEffectiveWindow(basis.effectiveFrom, basis.effectiveTo);
}

const CASE_ENTITY_DELETE_LABELS: Record<DeletableCaseEntityType, string> = {
  file: "案件材料",
  party: "当事人",
  fact: "案件事实",
  evidence: "证据",
  evidence_link: "事实—证据关联",
  fact_issue_link: "事实—争点关联",
  legal_issue: "法律争点",
  legal_basis: "法源关联",
  uncertainty: "待核实事项",
};

export function caseProjectDeletionConfirmation(title: string): string {
  return `确定永久删除案件“${title}”吗？这会同时删除该案件的材料、当事人、事实、证据及关联、法律争点、法源关联、待核实事项、抽取审阅草稿和法律问答历史。此操作不可撤销。`;
}

export function caseEntityDeletionConfirmation(
  entityType: DeletableCaseEntityType,
  displayName: string,
): string {
  return `确定永久删除${CASE_ENTITY_DELETE_LABELS[entityType]}“${displayName}”吗？其关联数据（如有）也会一并删除，此操作不可撤销。`;
}

export function extractionReviewDiscardConfirmation(): string {
  return "确定永久放弃当前材料信息审阅草稿吗？已保存的修改和待确认内容都会删除，且不会写入案件；此操作不可撤销。";
}

export function unrestorableExtractionDiscardConfirmation(): string {
  return "该待审草稿已无法安全载入。确定永久删除该草稿并解锁案件吗？此操作不可撤销。";
}

export function caseEntityDeletionDisplayName(
  workspace: CaseWorkspace,
  entityType: DeletableCaseEntityType,
  id: string,
): string {
  switch (entityType) {
    case "file":
      return publicTitle(
        workspace.files.find((item) => item.fileId === id)?.title,
        "案件材料",
      );
    case "party":
      return publicTitle(
        workspace.parties.find((item) => item.partyId === id)?.name,
        "当事人",
      );
    case "fact":
      return publicTitle(
        workspace.facts.find((item) => item.factId === id)?.title,
        "案件事实",
      );
    case "evidence": {
      const item = workspace.evidence.find((entry) => entry.evidenceId === id);
      return item
        ? `${publicEvidenceNumber(item.evidenceNumber)} ${publicTitle(item.title, "案件证据")}`.trim()
        : "案件证据";
    }
    case "evidence_link": {
      const link = workspace.evidenceLinks.find((item) => item.linkId === id);
      if (!link) {
        return "事实与证据关联";
      }
      const fact = workspace.facts.find((item) => item.factId === link.factId);
      const evidence = workspace.evidence.find(
        (item) => item.evidenceId === link.evidenceId,
      );
      return `${publicTitle(fact?.title, "相关事实")} ↔ ${publicEvidenceNumber(evidence?.evidenceNumber, "相关证据")}`;
    }
    case "fact_issue_link": {
      const link = workspace.factIssueLinks.find((item) => item.linkId === id);
      if (!link) {
        return "事实与争点关联";
      }
      const fact = workspace.facts.find((item) => item.factId === link.factId);
      const issue = workspace.legalIssues.find(
        (item) => item.issueId === link.issueId,
      );
      return `${publicTitle(fact?.title, "相关事实")} ↔ ${publicTitle(issue?.title, "相关法律争点")}`;
    }
    case "legal_issue":
      return publicTitle(
        workspace.legalIssues.find((item) => item.issueId === id)?.title,
        "法律争点",
      );
    case "legal_basis": {
      const basis = workspace.legalBasis.find((item) => item.basisId === id);
      return basis ? formatLegalBasisTitle(basis) : "法律依据";
    }
    case "uncertainty":
      return publicCaseBusinessText(
        workspace.uncertainties.find((item) => item.uncertaintyId === id)
          ?.description,
        "待核实事项",
      );
  }
}
