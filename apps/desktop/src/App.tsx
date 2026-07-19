import {
  FormEvent,
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import {
  addCaseLegalBasis,
  confirmStructuredCaseExtraction,
  discardStructuredCaseExtraction,
  deleteCaseEntity,
  deleteCaseProject,
  getPendingStructuredCaseExtraction,
  getCaseWorkspace,
  listCaseProjects,
  generateStructuredCaseExtraction,
  updatePendingStructuredCaseExtraction,
  upsertCaseFile,
  upsertCaseFact,
  upsertCaseParty,
  upsertCaseProject,
  upsertEvidenceItem,
  upsertEvidenceLink,
  upsertFactIssueLink,
  upsertLegalIssue,
} from "./ipc/case/client";
import {
  formatConfirmationStatus,
  formatGapKind,
  formatGapSeverity,
  formatLegalBasisInvalidReason,
  formatLegalBasisStatus,
  formatLegalIssueStatus,
  formatPartyRole,
} from "./ipc/case/format";
import {
  buildConfirmationRequest,
  createExtractionContext,
  drainPendingExtractionSaves,
  extractionMutationBlocksClose,
  extractionReviewNeedsCloseFlush,
  extractionLocksSources,
  extractionReducer,
  guardExtractionClose,
  pendingExtractionUpdateAtRevision,
  structuredCaseExtractionIsPublic,
} from "./ipc/case/extractionReview";
import type { PendingExtractionDraftSaveRequest } from "./ipc/case/extractionReview";
import type {
  CaseFact,
  CaseFile,
  CaseParty,
  CaseProject,
  CaseWorkspace,
  ConfirmationStatus,
  EvidenceItem,
  FactIssueLink,
  LegalBasis,
  LegalIssue,
  LegalIssueStatus,
  PartyRole,
  StructuredCaseExtraction,
} from "./ipc/case/types";
import { formatHealthCheck } from "./ipc/health/format";
import { healthCheck } from "./ipc/health/client";
import type { HealthCheckResponse } from "./ipc/health/types";
import {
  answerLegalQuestion,
  cancelLegalAnswer,
  findLegalAnswerCandidates,
  getArticle,
  getLawDocument,
  getLawRelations,
  getLawVersions,
  listLegalAnswerRecords,
  searchArticles,
  searchLaws,
} from "./ipc/legal/client";
import {
  formatArticleLabel,
  formatCitationInvalidReason,
  formatEffectiveWindow,
  formatLegalContextWarning,
  formatLegalSourceLabel,
  formatStatus,
  segmentLegalAnswer,
} from "./ipc/legal/format";
import {
  buildLegalAnswerCandidateRequest as createLegalAnswerCandidateRequest,
  EFFECTIVENESS_LEVEL_OPTIONS,
} from "./ipc/legal/query";
import {
  formatLegalAnswerStreamStatus,
  INITIAL_LEGAL_ANSWER_STREAM_STATE,
  isLegalAnswerStreamActive,
  isLegalAnswerStreamCancellable,
  markLegalAnswerCancelling,
  reduceLegalAnswerStreamEvent,
  restoreLegalAnswerAfterRejectedCancellation,
  settleLegalAnswerCancellation,
  shouldCancelLegalAnswerOnPageLeave,
  startLegalAnswerStream,
} from "./ipc/legal/stream";
import type {
  ArticleSearchResult,
  CitationValidationReport,
  LawArticleDetail,
  LawRelationInfo,
  LawSearchResult,
  LawVersionInfo,
  LegalAnswerContext,
  LegalAnswerRecord,
  LegalAnswerResponse,
  LegalSource,
  ValidatedCitation,
} from "./ipc/legal/types";
import type { GraphMode, GraphNode } from "./ipc/graph/types";
import type { DocumentCitation } from "./ipc/document/types";
import {
  addAssistantLegalSource,
  proposeAssistantLegalBasis,
} from "./ipc/assistant/client";
import type { AssistantConversation } from "./ipc/assistant/types";
import {
  deleteProviderApiKey,
  deleteProviderProfile,
  getProviderApiKeyStatus,
  listProviderProfiles,
  testProviderConnection,
  upsertProviderProfile,
  writeProviderApiKey,
} from "./ipc/provider/client";
import {
  createProviderProfileDraft,
  DEFAULT_PROVIDER_KIND,
  defaultProviderOptions,
  providerCapabilities,
  providerDefaults,
  SELECTABLE_PROVIDER_KINDS,
} from "./ipc/provider/catalog";
import { ProviderCreateMenu } from "./ipc/provider/ProviderCreateMenu";
import {
  formatConnectionResult,
  formatHttpStatus,
  formatKeyStatus,
  formatLatency,
  formatProviderKind,
} from "./ipc/provider/format";
import {
  loadProviderKeyStatusesSettled,
  normalizeProviderProfile,
  providerKeyStatusForSavedDraft,
  providerProfilesEqual,
} from "./ipc/provider/profile";
import type {
  ConnectionTest,
  ProviderApiKeyStatus,
  ProviderKind,
  ProviderOptions,
  ProviderProfile,
  ReasoningEffort,
} from "./ipc/provider/types";
import { AppShell } from "./app/AppShell";
import { VIEW_METADATA, type ViewMode } from "./app/views";
import { AssistantWorkspace } from "./features/assistant/AssistantWorkspace";
import { CasesWorkspace } from "./features/cases/CasesWorkspace";
import { LegalLibraryWorkspace } from "./features/legal-library/LegalLibraryWorkspace";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import {
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "./publicOutput";

const DocumentWorkspace = lazy(() => import("./DocumentWorkspace").then((module) => ({ default: module.DocumentWorkspace })));
const GraphWorkspace = lazy(() => import("./GraphWorkspace").then((module) => ({ default: module.GraphWorkspace })));
const McpWorkspace = lazy(() => import("./features/mcp/McpWorkspace").then((module) => ({ default: module.McpWorkspace })));
const PrivacyWorkspace = lazy(() => import("./features/privacy/PrivacyWorkspace").then((module) => ({ default: module.PrivacyWorkspace })));
const ReleaseWorkspace = lazy(() => import("./ReleaseWorkspace").then((module) => ({ default: module.ReleaseWorkspace })));

type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; response: HealthCheckResponse }
  | { kind: "error"; message: string };

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string };

type ExtractionDraftSaveState =
  | { kind: "idle" }
  | { kind: "pending" }
  | { kind: "saving" }
  | { kind: "saved"; expiresAt: string }
  | { kind: "conflict"; message: string };

interface QaFormDraft {
  question: string;
  lawName: string;
  articleNumber: string;
  keywords: string;
  caseDate: string;
  effectivenessLevels: string[];
  includeExpired: boolean;
}

interface PendingReviewRecoveryBlock {
  reviewId: string;
  projectId: string;
  revision: number;
  message: string;
  reloadRequired?: boolean;
}

interface QueuedExtractionDraftSave {
  request: PendingExtractionDraftSaveRequest;
  sequence: number;
}

interface MutableEpoch {
  current: number;
}

interface MutableValue<T> {
  current: T;
}

interface MutableLock {
  current: boolean;
}

type DeletableCaseEntityType =
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "evidence_link"
  | "fact_issue_link"
  | "legal_issue"
  | "legal_basis"
  | "uncertainty";

// eslint-disable-next-line react-refresh/only-export-components
export function advanceRequestEpoch(epoch: MutableEpoch): number {
  epoch.current += 1;
  return epoch.current;
}

// eslint-disable-next-line react-refresh/only-export-components
export function isCurrentRequestEpoch(
  epoch: MutableEpoch,
  requestEpoch: number,
): boolean {
  return epoch.current === requestEpoch;
}

// eslint-disable-next-line react-refresh/only-export-components
export function currentLawSearchCriteria(
  query: MutableValue<string>,
  caseDate: MutableValue<string>,
): { query: string; caseDate: string | null } {
  return {
    query: query.current.trim(),
    caseDate: caseDate.current || null,
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function advanceCaseWorkspaceEpoch(epoch: MutableEpoch): number {
  return advanceRequestEpoch(epoch);
}

// eslint-disable-next-line react-refresh/only-export-components
export function isCurrentCaseWorkspaceEpoch(
  epoch: MutableEpoch,
  requestEpoch: number,
): boolean {
  return isCurrentRequestEpoch(epoch, requestEpoch);
}

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function releaseCaseMutation(lock: MutableLock): void {
  lock.current = false;
}

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function resolveSelectedQaSource(
  context: LegalAnswerContext | null,
  selectedSourceId: string | null,
): LegalSource | null {
  if (!context) {
    return null;
  }

  if (selectedSourceId === null) {
    return context.sources[0] ?? null;
  }

  return (
    context.sources.find((source) => source.sourceId === selectedSourceId) ??
    null
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function resolveLegalAnswerQuestion(
  context: LegalAnswerContext | null,
  submittedQuestion: string | null,
): string | null {
  const contextQuestion = context?.query.legalIssue.trim();
  if (contextQuestion) {
    return contextQuestion;
  }

  const normalizedSubmittedQuestion = submittedQuestion?.trim();
  return normalizedSubmittedQuestion || null;
}

// eslint-disable-next-line react-refresh/only-export-components
export function citationHasTrustedSource(
  citation: ValidatedCitation,
): citation is ValidatedCitation & {
  status: "valid";
  source: LegalSource;
} {
  return citation.status === "valid" && citation.source != null;
}

export type CaseDraftKind =
  | "project"
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "legal_issue"
  | "evidence_link"
  | "fact_issue_link"
  | "legal_basis";

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

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function caseGraphNodeDomId(sourceKind: string, sourceId: string): string {
  return `case-graph-source-${encodeURIComponent(sourceKind)}-${encodeURIComponent(sourceId)}`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function articleMatchesDocumentCitation(
  article: Pick<
    LawArticleDetail,
    "articleId" | "documentId" | "versionId" | "citationId"
  > | null | undefined,
  citation: Pick<
    DocumentCitation,
    "articleId" | "documentId" | "versionId" | "sourceId"
  >,
): article is Pick<
  LawArticleDetail,
  "articleId" | "documentId" | "versionId" | "citationId"
> {
  return (
    article != null &&
    article.articleId === citation.articleId &&
    article.documentId === citation.documentId &&
    article.versionId === citation.versionId &&
    article.citationId === citation.sourceId
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function exactLawDocumentMatchesRequest(
  document: LawSearchResult | null | undefined,
  requestedDocumentId: string,
): document is LawSearchResult {
  return document != null && document.documentId === requestedDocumentId;
}

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function legalAnswerContextFromRecord(
  record: LegalAnswerRecord,
): LegalAnswerContext {
  return {
    query: {
      ...record.query,
      lawNames: [...record.query.lawNames],
      articleNumbers: [...record.query.articleNumbers],
      keywords: [...record.query.keywords],
      effectivenessLevels: [...record.query.effectivenessLevels],
    },
    sources: record.sources.map((source) => ({ ...source })),
    prompt: "",
    warnings: [
      "这是已保存的历史回答；已恢复当时的检索条件、候选来源和法条依据。",
      ...(record.missingSourceIds.length > 0
        ? [
            `当前本地法律库有 ${record.missingSourceIds.length} 项历史来源暂不可用；回答已保留，引用需重新核对。`,
          ]
        : []),
    ],
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function qaFormDraftFromLegalAnswerRecord(
  record: LegalAnswerRecord,
): QaFormDraft {
  const { query } = record;
  return {
    question: query.legalIssue,
    // The request form is single-valued for these explicit filters. When an
    // old query inferred multiple values from its question, leave the explicit
    // field empty so replay re-parses the original question instead of joining
    // independent values into a new, invalid hard filter.
    lawName: query.lawNames.length === 1 ? query.lawNames[0] : "",
    articleNumber:
      query.articleNumbers.length === 1 ? query.articleNumbers[0] : "",
    keywords: query.keywords.join("、"),
    caseDate: query.caseDate ?? "",
    effectivenessLevels: [...query.effectivenessLevels],
    includeExpired: query.includeExpired,
  };
}

// eslint-disable-next-line react-refresh/only-export-components
export function providerNavigationHasUnsavedChanges(
  baseline: ProviderProfile,
  draft: ProviderProfile,
  apiKeyInput: string,
): boolean {
  return (
    !providerProfilesEqual(baseline, normalizeProviderProfile(draft)) ||
    apiKeyInput.trim().length > 0
  );
}

export const CASE_PROJECTS_PER_PAGE = 8;

// eslint-disable-next-line react-refresh/only-export-components
export function clampCaseProjectPage(
  requestedPage: number,
  projectCount: number,
  pageSize = CASE_PROJECTS_PER_PAGE,
): number {
  const safePageSize = Math.max(1, Math.floor(pageSize));
  const totalPages = Math.max(1, Math.ceil(projectCount / safePageSize));
  return Math.min(Math.max(1, Math.floor(requestedPage) || 1), totalPages);
}

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function caseProjectPageForId(
  projects: readonly CaseProject[],
  projectId: string,
  pageSize = CASE_PROJECTS_PER_PAGE,
): number {
  const safePageSize = Math.max(1, Math.floor(pageSize));
  const index = projects.findIndex((project) => project.projectId === projectId);
  return index < 0 ? 1 : Math.floor(index / safePageSize) + 1;
}

// eslint-disable-next-line react-refresh/only-export-components
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

export const LEGAL_ANSWER_HISTORY_PAGE_SIZE = 25;

const DEFAULT_QA_FORM_DRAFT: Readonly<QaFormDraft> = {
  question: "",
  lawName: "",
  articleNumber: "",
  keywords: "",
  caseDate: "",
  effectivenessLevels: [],
  includeExpired: false,
};

function copyQaFormDraft(draft: Readonly<QaFormDraft>): QaFormDraft {
  return { ...draft, effectivenessLevels: [...draft.effectivenessLevels] };
}

// eslint-disable-next-line react-refresh/only-export-components
export function legalAnswerRequestStillOwnsCurrentCase(
  requestProjectId: string | null,
  selectedProjectId: string | null,
): boolean {
  return requestProjectId !== null && requestProjectId === selectedProjectId;
}

// eslint-disable-next-line react-refresh/only-export-components
export function legalAnswerPreviewStillOwnsCurrentScope(
  requestProjectId: string | null,
  selectedProjectId: string | null,
): boolean {
  return requestProjectId === selectedProjectId;
}

// eslint-disable-next-line react-refresh/only-export-components
export function pendingReviewFilesStillExist(
  workspaceFileIds: readonly string[],
  pendingFileIds: readonly string[],
): boolean {
  const available = new Set(workspaceFileIds);
  return pendingFileIds.every((fileId) => available.has(fileId));
}

// eslint-disable-next-line react-refresh/only-export-components
export function mergeLegalAnswerHistory(
  current: readonly LegalAnswerRecord[],
  incoming: readonly LegalAnswerRecord[],
): LegalAnswerRecord[] {
  const records = new Map(current.map((record) => [record.recordId, record]));
  incoming.forEach((record) => records.set(record.recordId, record));
  return [...records.values()];
}

// eslint-disable-next-line react-refresh/only-export-components
export function legalAnswerHistoryBelongsToProject(
  records: readonly LegalAnswerRecord[],
  projectId: string,
): boolean {
  return records.every((record) => record.projectId === projectId);
}

// eslint-disable-next-line react-refresh/only-export-components
export function formatCitationValidationSummary(
  report: CitationValidationReport,
): string {
  if (report.citations.length === 0 || report.validCount + report.invalidCount === 0) {
    return "未列出法条依据";
  }
  return report.invalidCount > 0
    ? `${report.invalidCount} 条依据需要核对`
    : `${report.validCount} 条法条依据`;
}

const CASE_DRAFT_LABELS: Record<CaseDraftKind, string> = {
  project: "案件基本信息",
  file: "案件材料",
  party: "当事人",
  fact: "事实",
  evidence: "证据",
  legal_issue: "争点",
  evidence_link: "事实—证据关联",
  fact_issue_link: "事实—争点关联",
  legal_basis: "法律依据",
};

export interface WorkspaceCloseProtectionState {
  dirtyCaseDrafts: readonly CaseDraftKind[];
  providerDraftDirty: boolean;
  caseMutationInFlight: boolean;
  providerMutationInFlight: boolean;
  extractionMutationInFlight: boolean;
  assistantRunActive?: boolean;
  assistantMutationInFlight?: boolean;
  assistantDraftDirty?: boolean;
  mcpMutationInFlight?: boolean;
  mcpDraftDirty?: boolean;
  privacyMutationInFlight?: boolean;
  privacyDraftDirty?: boolean;
}

export type WorkspaceCloseDecision =
  | { kind: "proceed" }
  | { kind: "block"; message: string }
  | { kind: "confirm_discard"; message: string };

// eslint-disable-next-line react-refresh/only-export-components
export function decideWorkspaceClose(
  state: WorkspaceCloseProtectionState,
): WorkspaceCloseDecision {
  if (state.assistantRunActive) {
    return {
      kind: "block",
      message:
        "助理任务仍在运行。请先等待完成或在助理工作区取消，再关闭窗口。",
    };
  }

  const activeWrites = [
    state.caseMutationInFlight ? "案件数据写入" : null,
    state.providerMutationInFlight ? "Provider 或 API Key 写入" : null,
    state.extractionMutationInFlight ? "材料审阅保存" : null,
    state.assistantMutationInFlight
      ? "助理保存、导入、导出、法律库桥接或已确认建议写入"
      : null,
    state.mcpMutationInFlight ? "MCP 服务配置或生命周期变更" : null,
    state.privacyMutationInFlight ? "隐私与本地处理配置写入" : null,
  ].filter((item): item is string => item !== null);
  if (activeWrites.length > 0) {
    return {
      kind: "block",
      message: `${activeWrites.join("、")}尚未完成；为避免结果不明，已阻止关闭窗口。请等待当前操作完成后重试。`,
    };
  }

  const unsaved = state.dirtyCaseDrafts.map(
    (kind) => CASE_DRAFT_LABELS[kind],
  );
  if (state.providerDraftDirty) {
    unsaved.push("Provider Profile 或 API Key 输入");
  }
  if (state.assistantDraftDirty) {
    unsaved.push("助理中未发送的任务草稿");
  }
  if (state.mcpDraftDirty) {
    unsaved.push("MCP 服务配置或待写入 Bearer Token");
  }
  if (state.privacyDraftDirty) {
    unsaved.push("隐私与本地 OCR 配置");
  }
  if (unsaved.length > 0) {
    return {
      kind: "confirm_discard",
      message: `关闭窗口将永久丢弃这些未保存内容：${unsaved.join("、")}。确定继续关闭吗？`,
    };
  }

  return { kind: "proceed" };
}

// eslint-disable-next-line react-refresh/only-export-components
export function decideMcpWorkspaceNavigation(
  currentView: ViewMode,
  nextView: ViewMode,
  mutationInFlight: boolean,
  draftDirty: boolean,
): WorkspaceCloseDecision {
  if (currentView === nextView) {
    return { kind: "proceed" };
  }
  if (mutationInFlight) {
    return {
      kind: "block",
      message:
        "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    };
  }
  if (draftDirty) {
    return {
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的 MCP 服务配置或待写入 Bearer Token。确定继续吗？",
    };
  }
  return { kind: "proceed" };
}

// eslint-disable-next-line react-refresh/only-export-components
export function decidePrivacyWorkspaceNavigation(
  currentView: ViewMode,
  nextView: ViewMode,
  mutationInFlight: boolean,
  draftDirty: boolean,
): WorkspaceCloseDecision {
  if (currentView === nextView) {
    return { kind: "proceed" };
  }
  if (currentView !== "privacy") {
    return { kind: "proceed" };
  }
  if (mutationInFlight) {
    return {
      kind: "block",
      message:
        "隐私与本地处理配置正在写入；为避免结果不明，已阻止切换工作区。请等待保存完成后重试。",
    };
  }
  if (draftDirty) {
    return {
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的隐私与本地 OCR 配置。确定继续吗？",
    };
  }
  return { kind: "proceed" };
}

// eslint-disable-next-line react-refresh/only-export-components
export function assistantWritesBlockClose(
  workspaceMutationActive: boolean,
  legalSourceBridgeMutationActive: boolean,
): boolean {
  return workspaceMutationActive || legalSourceBridgeMutationActive;
}

// eslint-disable-next-line react-refresh/only-export-components
export function workspaceCloseWasApproved(
  decision: WorkspaceCloseDecision,
  confirmDiscard: (message: string) => boolean,
): boolean {
  if (decision.kind === "proceed") {
    return true;
  }
  return (
    decision.kind === "confirm_discard" &&
    confirmDiscard(decision.message)
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function canBypassDirtyDraftsForWorkspaceRecovery(
  targetProjectId: string,
  selectedProjectId: string | null,
  workspaceWriteBlocked: boolean,
  persistedMutationRecoveryProjectId: string | null,
): boolean {
  return (
    workspaceWriteBlocked &&
    targetProjectId === selectedProjectId &&
    targetProjectId === persistedMutationRecoveryProjectId
  );
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

type CaseEntityEditTarget =
  | { entityType: "file"; entity: CaseFile }
  | { entityType: "party"; entity: CaseParty }
  | { entityType: "fact"; entity: CaseFact }
  | { entityType: "evidence"; entity: EvidenceItem }
  | { entityType: "legal_issue"; entity: LegalIssue };

// eslint-disable-next-line react-refresh/only-export-components
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

// eslint-disable-next-line react-refresh/only-export-components
export function caseEntityEditorAllows(
  editor: ActiveCaseEntityEditor | null,
  entityType: EditableCaseEntityType,
  entityId?: string,
): boolean {
  return (
    editor === null || caseEntityEditorMatches(editor, entityType, entityId)
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function copyCaseEntityForEditing<T extends EditableCaseEntity>(
  entity: T,
): T {
  return { ...entity };
}

const LEGACY_GENERATED_EVIDENCE_NUMBER = /^service-[0-9a-f]{8,64}-\d+$/iu;

// eslint-disable-next-line react-refresh/only-export-components
export function publicCaseBusinessText(
  value: string | null | undefined,
  fallback = "",
): string {
  if (!value?.trim()) return fallback;
  return sanitizePublicGeneratedText(value, fallback);
}

// eslint-disable-next-line react-refresh/only-export-components
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

const INITIAL_QUERY = "合同";

function createId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 7)}`;
}

function createProviderProfile(kind: ProviderKind): ProviderProfile {
  return createProviderProfileDraft(kind, createId(kind));
}

function createCaseProject(): CaseProject {
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

function createParty(projectId: string): CaseParty {
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

function createCaseFile(projectId: string): CaseFile {
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

function createFact(projectId: string): CaseFact {
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

function createEvidence(projectId: string, nextIndex: number): EvidenceItem {
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

function createIssue(projectId: string): LegalIssue {
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

function formatLegalBasisTitle(basis: LegalBasis): string {
  if (!basis.documentTitle || !basis.articleNumber) {
    return publicTitle(basis.canonicalLabel, "法律条文");
  }
  const year = /^(\d{4})/u.exec(basis.effectiveFrom)?.[1];
  return `《${publicTitle(basis.documentTitle, "法律文件")}》${publicTitle(
    basis.articleNumber,
    "相关条文",
  )}${year ? `（${year}年起施行）` : ""}`;
}

function formatLegalBasisWindow(basis: LegalBasis): string {
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

// eslint-disable-next-line react-refresh/only-export-components
export function caseProjectDeletionConfirmation(title: string): string {
  return `确定永久删除案件“${title}”吗？这会同时删除该案件的材料、当事人、事实、证据及关联、法律争点、法源关联、待核实事项、抽取审阅草稿和法律问答历史。此操作不可撤销。`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function caseEntityDeletionConfirmation(
  entityType: DeletableCaseEntityType,
  displayName: string,
): string {
  return `确定永久删除${CASE_ENTITY_DELETE_LABELS[entityType]}“${displayName}”吗？其关联数据（如有）也会一并删除，此操作不可撤销。`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function providerDeletionConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `确定永久删除 Provider“${displayName}”吗？对应配置和已保存的访问凭据会一并删除；既有结果不受影响。`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function providerApiKeyDeletionConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `确定删除 Provider“${displayName}”的访问凭据吗？删除后需重新录入才能调用该服务。`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function providerApiKeyOverwriteConfirmation(
  displayName: string,
  accountId: string,
): string {
  void accountId;
  return `Provider“${displayName}”已经保存访问凭据。确定用当前输入覆盖旧凭据吗？旧凭据无法恢复。`;
}

// eslint-disable-next-line react-refresh/only-export-components
export function extractionReviewDiscardConfirmation(): string {
  return "确定永久放弃当前材料信息审阅草稿吗？已保存的修改和待确认内容都会删除，且不会写入案件；此操作不可撤销。";
}

// eslint-disable-next-line react-refresh/only-export-components
export function unrestorableExtractionDiscardConfirmation(): string {
  return "该待审草稿已无法安全载入。确定永久删除该草稿并解锁案件吗？此操作不可撤销。";
}

export type ConfirmedDestructiveActionResult<T> =
  | { executed: false }
  | { executed: true; value: T };

// eslint-disable-next-line react-refresh/only-export-components
export async function runConfirmedDestructiveAction<T>(
  message: string,
  confirmAction: (message: string) => boolean,
  action: () => Promise<T>,
): Promise<ConfirmedDestructiveActionResult<T>> {
  if (!confirmAction(message)) {
    return { executed: false };
  }
  return { executed: true, value: await action() };
}

function caseEntityDeletionDisplayName(
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
      return (
        publicCaseBusinessText(
          workspace.uncertainties.find((item) => item.uncertaintyId === id)
            ?.description,
          "待核实事项",
        )
      );
  }
}

function errorMessage(error: unknown): string {
  return publicErrorMessage(error);
}

function createLegalAnswerRequestId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `answer-${crypto.randomUUID()}`;
  }

  return `answer-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function App() {
  const [viewMode, setViewMode] = useState<ViewMode>("assistant");
  const [health, setHealth] = useState<HealthState>({ kind: "loading" });
  const [closeProtectionMessage, setCloseProtectionMessage] = useState<
    string | null
  >(null);
  const [assistantConversation, setAssistantConversation] =
    useState<AssistantConversation | null>(null);
  const [assistantRefreshKey, setAssistantRefreshKey] = useState(0);
  const [assistantCaseHandoff, setAssistantCaseHandoff] = useState<
    { projectId: string; title: string; requestId: number } | null
  >(null);
  const assistantCaseHandoffSequence = useRef(0);
  const assistantDraftDirty = useRef(false);
  const assistantMutationActive = useRef(false);
  const assistantRunActive = useRef(false);
  const mcpDraftDirty = useRef(false);
  const mcpMutationActive = useRef(false);
  const privacyDraftDirty = useRef(false);
  const privacyMutationActive = useRef(false);
  const legalSourceBridgeMutationActive = useRef(false);
  const [legalSourceBridgeState, setLegalSourceBridgeState] = useState<
    | { kind: "idle" | "loading" }
    | { kind: "success" | "error"; message: string }
  >({ kind: "idle" });
  const handleAssistantConversationChange = useCallback(
    (conversation: AssistantConversation | null) => {
      setAssistantConversation(conversation);
    },
    [],
  );
  const handleAssistantRunActivityChange = useCallback((active: boolean) => {
    assistantRunActive.current = active;
  }, []);
  const handleAssistantDraftDirtyChange = useCallback((dirty: boolean) => {
    assistantDraftDirty.current = dirty;
  }, []);
  const handleAssistantMutationActivityChange = useCallback((active: boolean) => {
    assistantMutationActive.current = active;
  }, []);
  const handleMcpDraftDirtyChange = useCallback((dirty: boolean) => {
    mcpDraftDirty.current = dirty;
  }, []);
  const handleMcpMutationActivityChange = useCallback((active: boolean) => {
    mcpMutationActive.current = active;
  }, []);
  const handlePrivacyDraftDirtyChange = useCallback((dirty: boolean) => {
    privacyDraftDirty.current = dirty;
  }, []);
  const handlePrivacyMutationActivityChange = useCallback((active: boolean) => {
    privacyMutationActive.current = active;
  }, []);
  const [query, setQuery] = useState(INITIAL_QUERY);
  const [caseDate, setCaseDate] = useState("");
  const queryRef = useRef(query);
  queryRef.current = query;
  const caseDateRef = useRef(caseDate);
  caseDateRef.current = caseDate;
  const [searchState, setSearchState] = useState<LoadState>({ kind: "idle" });
  const [detailState, setDetailState] = useState<LoadState>({ kind: "idle" });
  const [documentState, setDocumentState] = useState<LoadState>({
    kind: "idle",
  });
  const [laws, setLaws] = useState<LawSearchResult[]>([]);
  const [articles, setArticles] = useState<ArticleSearchResult[]>([]);
  const searchRequestEpoch = useRef(0);
  const articleDetailRequestEpoch = useRef(0);
  const documentContextRequestEpoch = useRef(0);
  const [selectedDocument, setSelectedDocument] =
    useState<LawSearchResult | null>(null);
  const selectedDocumentIdRef = useRef<string | null>(null);
  selectedDocumentIdRef.current = selectedDocument?.documentId ?? null;
  const [versions, setVersions] = useState<LawVersionInfo[]>([]);
  const [relations, setRelations] = useState<LawRelationInfo[]>([]);
  const [selectedArticleId, setSelectedArticleId] = useState<string | null>(
    null,
  );
  const [selectedArticle, setSelectedArticle] =
    useState<LawArticleDetail | null>(null);
  useEffect(() => {
    setLegalSourceBridgeState({ kind: "idle" });
  }, [selectedArticleId]);
  const [graphMode, setGraphMode] = useState<GraphMode>("case");
  const [graphDocumentId, setGraphDocumentId] = useState<string | null>(null);
  const [graphCaseTarget, setGraphCaseTarget] = useState<{
    sourceKind: string;
    sourceId: string;
  } | null>(null);

  const [qaState, setQaState] = useState<LoadState>({ kind: "idle" });
  const [qaQuestion, setQaQuestion] = useState(DEFAULT_QA_FORM_DRAFT.question);
  const [qaLawName, setQaLawName] = useState(DEFAULT_QA_FORM_DRAFT.lawName);
  const [qaArticleNumber, setQaArticleNumber] = useState(
    DEFAULT_QA_FORM_DRAFT.articleNumber,
  );
  const [qaKeywords, setQaKeywords] = useState(DEFAULT_QA_FORM_DRAFT.keywords);
  const [qaCaseDate, setQaCaseDate] = useState(DEFAULT_QA_FORM_DRAFT.caseDate);
  const [qaEffectivenessLevels, setQaEffectivenessLevels] = useState<string[]>(
    [...DEFAULT_QA_FORM_DRAFT.effectivenessLevels],
  );
  const [qaIncludeExpired, setQaIncludeExpired] = useState(
    DEFAULT_QA_FORM_DRAFT.includeExpired,
  );
  const [qaProviderId, setQaProviderId] = useState("");
  const [qaContext, setQaContext] = useState<LegalAnswerContext | null>(null);
  const [qaAnswer, setQaAnswer] = useState<LegalAnswerResponse | null>(null);
  const [qaHistoryState, setQaHistoryState] = useState<LoadState>({
    kind: "idle",
  });
  const [qaHistoryRecords, setQaHistoryRecords] = useState<
    LegalAnswerRecord[]
  >([]);
  const [qaHistoryHasMore, setQaHistoryHasMore] = useState(false);
  const qaDraftsByProject = useRef(new Map<string, QaFormDraft>());
  const qaDraftProjectId = useRef<string | null>(null);
  const [qaSubmittedQuestion, setQaSubmittedQuestion] = useState<string | null>(
    null,
  );
  const [qaStream, setQaStream] = useState(
    INITIAL_LEGAL_ANSWER_STREAM_STATE,
  );
  const activeQaRequestId = useRef<string | null>(null);
  const activeQaRequestProjectId = useRef<string | null>(null);
  const qaPreviewEpoch = useRef(0);
  const qaStreamRef = useRef(qaStream);
  qaStreamRef.current = qaStream;
  const qaLeaveCancellationRequestId = useRef<string | null>(null);
  const [selectedQaSourceId, setSelectedQaSourceId] = useState<string | null>(
    null,
  );

  const [providerState, setProviderState] = useState<LoadState>({
    kind: "idle",
  });
  const [providerProfiles, setProviderProfiles] = useState<ProviderProfile[]>(
    [],
  );
  const [providerDraft, setProviderDraft] = useState<ProviderProfile>(() =>
    createProviderProfile(DEFAULT_PROVIDER_KIND),
  );
  const providerDraftRef = useRef(providerDraft);
  providerDraftRef.current = providerDraft;
  const providerDraftBaseline = useRef(providerDraft);
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
    null,
  );
  const [apiKeyInput, setApiKeyInput] = useState("");
  const apiKeyInputRef = useRef(apiKeyInput);
  apiKeyInputRef.current = apiKeyInput;
  const providerMutationInFlight = useRef(false);
  const [keyStatuses, setKeyStatuses] = useState<
    Record<string, ProviderApiKeyStatus>
  >({});
  const [connectionResults, setConnectionResults] = useState<
    Record<string, ConnectionTest>
  >({});

  const [caseState, setCaseState] = useState<LoadState>({ kind: "idle" });
  const [caseProjects, setCaseProjects] = useState<CaseProject[]>([]);
  const [caseProjectPage, setCaseProjectPage] = useState(1);
  const [selectedCaseProjectId, setSelectedCaseProjectId] = useState<
    string | null
  >(null);
  const selectedCaseProjectIdRef = useRef<string | null>(null);
  selectedCaseProjectIdRef.current = selectedCaseProjectId;
  const qaHistoryLoadEpoch = useRef(0);
  const [caseWorkspace, setCaseWorkspace] = useState<CaseWorkspace | null>(
    null,
  );
  const [caseWorkspaceWriteBlocked, setCaseWorkspaceWriteBlocked] =
    useState(false);
  const persistedMutationRecoveryProjectId = useRef<string | null>(null);
  const dirtyCaseDraftsForClose = useRef<CaseDraftKind[]>([]);
  const [caseValidationTargetId, setCaseValidationTargetId] = useState<
    string | null
  >(null);
  const caseWorkspaceEpoch = useRef(0);
  const caseMutationLock = useRef(false);
  const [caseMutationInFlight, setCaseMutationInFlight] = useState(false);
  const extractionLifecycleLock = useRef(false);
  const [activeCaseEntityEditor, setActiveCaseEntityEditor] =
    useState<ActiveCaseEntityEditor | null>(null);
  const [caseProjectDraft, setCaseProjectDraft] = useState<CaseProject>(() =>
    createCaseProject(),
  );
  const caseProjectDraftBaseline = useRef(caseProjectDraft);
  const [fileDraft, setFileDraft] = useState<CaseFile>(() =>
    createCaseFile(caseProjectDraft.projectId),
  );
  const [partyDraft, setPartyDraft] = useState<CaseParty>(() =>
    createParty(caseProjectDraft.projectId),
  );
  const [factDraft, setFactDraft] = useState<CaseFact>(() =>
    createFact(caseProjectDraft.projectId),
  );
  const [evidenceDraft, setEvidenceDraft] = useState<EvidenceItem>(() =>
    createEvidence(caseProjectDraft.projectId, 1),
  );
  const [issueDraft, setIssueDraft] = useState<LegalIssue>(() =>
    createIssue(caseProjectDraft.projectId),
  );
  const [basisSourceId, setBasisSourceId] = useState("");
  const [basisIssueId, setBasisIssueId] = useState("");
  const [basisCaseDate, setBasisCaseDate] = useState("");
  const [basisIncludeExpired, setBasisIncludeExpired] = useState(false);
  const [basisNote, setBasisNote] = useState("");
  const [linkFactId, setLinkFactId] = useState("");
  const [linkEvidenceId, setLinkEvidenceId] = useState("");
  const [factIssueFactId, setFactIssueFactId] = useState("");
  const [factIssueIssueId, setFactIssueIssueId] = useState("");
  const [extractionProviderId, setExtractionProviderId] = useState("");
  const [extractionFileIds, setExtractionFileIds] = useState<string[]>([]);
  const [extractionState, dispatchExtraction] = useReducer(extractionReducer, {
    kind: "idle",
  });
  const extractionStateRef = useRef(extractionState);
  extractionStateRef.current = extractionState;
  const [extractionConfirmPreparing, setExtractionConfirmPreparing] =
    useState(false);
  const extractionConfirmInFlight = useRef(false);
  const [extractionDiscarding, setExtractionDiscarding] = useState(false);
  const extractionDiscardInFlight = useRef(false);
  const [extractionDiscardError, setExtractionDiscardError] = useState<
    string | null
  >(null);
  const [extractionDraftSaveState, setExtractionDraftSaveState] =
    useState<ExtractionDraftSaveState>({ kind: "idle" });
  const pendingExtractionDraftSave =
    useRef<QueuedExtractionDraftSave | null>(null);
  const extractionDraftSaveTimer = useRef<number | null>(null);
  const extractionDraftSavePromise = useRef<Promise<boolean>>(
    Promise.resolve(true),
  );
  const extractionDraftSaveSession = useRef(0);
  const extractionDraftSaveSequence = useRef(0);
  const extractionDraftSavedSequence = useRef(0);
  const extractionServerRevision = useRef<number | null>(null);
  const extractionReviewReloadRequired = useRef(false);
  const extractionCloseInProgress = useRef(false);
  const controlledCloseApproved = useRef(false);
  const [extractionClosePreparing, setExtractionClosePreparing] = useState(false);
  const [pendingReviewRecoveryBlock, setPendingReviewRecoveryBlock] =
    useState<PendingReviewRecoveryBlock | null>(null);
  const extractionReviewRef = useRef<HTMLDivElement | null>(null);
  const extractionReviewReturnFocusRef = useRef<HTMLElement | null>(null);
  const extractionSourcesLocked = extractionLocksSources(extractionState);

  function beginCaseMutation(allowDuringExtraction = false): number | null {
    if (
      (!allowDuringExtraction && extractionLifecycleLock.current) ||
      extractionDiscardInFlight.current
    ) {
      return null;
    }

    const requestEpoch = tryAcquireCaseMutation(
      caseMutationLock,
      caseWorkspaceEpoch,
    );
    if (requestEpoch !== null) {
      setCaseMutationInFlight(true);
    }
    return requestEpoch;
  }

  function finishCaseMutation() {
    releaseCaseMutation(caseMutationLock);
    setCaseMutationInFlight(false);
  }

  function caseInteractionIsLocked(): boolean {
    return (
      caseMutationLock.current ||
      extractionLifecycleLock.current ||
      extractionDiscardInFlight.current
    );
  }

  function focusElement(elementId: string) {
    requestAnimationFrame(() => {
      document.getElementById(elementId)?.focus();
    });
  }

  function showCaseValidationError(message: string, elementId: string) {
    setCaseValidationTargetId(elementId);
    setCaseState({ kind: "error", message });
    focusElement(elementId);
  }

  function clearCaseValidationError() {
    setCaseValidationTargetId(null);
  }

  function currentQaFormDraft(): QaFormDraft {
    return {
      question: qaQuestion,
      lawName: qaLawName,
      articleNumber: qaArticleNumber,
      keywords: qaKeywords,
      caseDate: qaCaseDate,
      effectivenessLevels: [...qaEffectivenessLevels],
      includeExpired: qaIncludeExpired,
    };
  }

  function applyQaFormDraft(draft: Readonly<QaFormDraft>) {
    setQaQuestion(draft.question);
    setQaLawName(draft.lawName);
    setQaArticleNumber(draft.articleNumber);
    setQaKeywords(draft.keywords);
    setQaCaseDate(draft.caseDate);
    setQaEffectivenessLevels([...draft.effectivenessLevels]);
    setQaIncludeExpired(draft.includeExpired);
  }

  function qaDraftStorageKey(projectId: string | null): string {
    return projectId ?? "__unassigned__";
  }

  async function refreshLegalAnswerHistory(
    projectId: string,
    append = false,
  ) {
    const requestEpoch = ++qaHistoryLoadEpoch.current;
    const cursor = append ? qaHistoryRecords.at(-1) : undefined;
    if (!append) {
      setQaHistoryRecords([]);
      setQaHistoryHasMore(false);
    }
    setQaHistoryState({ kind: "loading" });
    try {
      const response = await listLegalAnswerRecords({
        projectId,
        limit: LEGAL_ANSWER_HISTORY_PAGE_SIZE,
        beforeCreatedAt: cursor?.createdAt ?? null,
        beforeRecordId: cursor?.recordId ?? null,
      });
      if (
        qaHistoryLoadEpoch.current !== requestEpoch ||
        selectedCaseProjectIdRef.current !== projectId
      ) {
        return;
      }
      if (!legalAnswerHistoryBelongsToProject(response.records, projectId)) {
        setQaHistoryRecords([]);
        setQaHistoryHasMore(false);
        setQaHistoryState({
          kind: "error",
          message: "历史回答归属校验失败，已拒绝显示。",
        });
        return;
      }
      setQaHistoryRecords((current) =>
        append
          ? mergeLegalAnswerHistory(current, response.records)
          : response.records,
      );
      setQaHistoryHasMore(response.hasMore);
      setQaHistoryState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        qaHistoryLoadEpoch.current === requestEpoch &&
        selectedCaseProjectIdRef.current === projectId
      ) {
        if (!append) {
          setQaHistoryRecords([]);
          setQaHistoryHasMore(false);
        }
        setQaHistoryState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  function clearExtractionDraftSaveTimer() {
    if (extractionDraftSaveTimer.current !== null) {
      window.clearTimeout(extractionDraftSaveTimer.current);
      extractionDraftSaveTimer.current = null;
    }
  }

  function beginExtractionDraftSaveSession(
    initial: ExtractionDraftSaveState = { kind: "idle" },
    serverRevision: number | null = null,
  ) {
    extractionDraftSaveSession.current += 1;
    extractionDraftSaveSequence.current = 0;
    extractionDraftSavedSequence.current = 0;
    extractionServerRevision.current = serverRevision;
    extractionReviewReloadRequired.current = false;
    clearExtractionDraftSaveTimer();
    pendingExtractionDraftSave.current = null;
    extractionDraftSavePromise.current = Promise.resolve(true);
    setExtractionDraftSaveState(initial);
  }

  function lockExtractionReviewForServerReload(message: string) {
    extractionReviewReloadRequired.current = true;
    clearExtractionDraftSaveTimer();
    pendingExtractionDraftSave.current = null;
    setExtractionDraftSaveState({
      kind: "conflict",
      message: `${message} 已锁定本窗口的编辑、确认和取消操作；请重新加载最新草稿后核对。`,
    });
  }

  async function persistExtractionDraft(
    queued: QueuedExtractionDraftSave,
    session: number,
  ): Promise<boolean> {
    if (extractionDraftSaveSession.current !== session) {
      return false;
    }
    if (extractionReviewReloadRequired.current) {
      return false;
    }
    const expectedRevision = extractionServerRevision.current;
    if (expectedRevision === null) {
      if (extractionDraftSaveSession.current === session) {
        lockExtractionReviewForServerReload("待审阅草稿缺少可核对的版本信息。");
      }
      return false;
    }
    try {
      const response = await updatePendingStructuredCaseExtraction(
        pendingExtractionUpdateAtRevision(queued.request, expectedRevision),
      );
      if (
        !response.updated ||
        !Number.isSafeInteger(response.revision) ||
        response.revision !== expectedRevision + 1
      ) {
        throw new Error("审阅草稿的保存结果不连续");
      }
      if (extractionDraftSaveSession.current === session) {
        extractionDraftSavedSequence.current = Math.max(
          extractionDraftSavedSequence.current,
          queued.sequence,
        );
        extractionServerRevision.current = response.revision;
        dispatchExtraction({
          type: "saved",
          reviewId: queued.request.reviewId,
          revision: response.revision,
          expiresAt: response.expiresAt,
        });
        if (pendingExtractionDraftSave.current) {
          setExtractionDraftSaveState({ kind: "pending" });
        } else if (
          queued.sequence === extractionDraftSaveSequence.current
        ) {
          setExtractionDraftSaveState({
            kind: "saved",
            expiresAt: response.expiresAt,
          });
        }
      }
      return true;
    } catch (error: unknown) {
      if (extractionDraftSaveSession.current === session) {
        lockExtractionReviewForServerReload(
          `审阅修改的保存结果无法安全确认：${errorMessage(error)}`,
        );
      }
      return false;
    }
  }

  function enqueueExtractionDraftSave(
    queued: QueuedExtractionDraftSave,
  ): Promise<boolean> {
    const session = extractionDraftSaveSession.current;
    const operation = extractionDraftSavePromise.current.then(() =>
      persistExtractionDraft(queued, session),
    );
    extractionDraftSavePromise.current = operation;
    return operation;
  }

  async function flushPendingExtractionDraftSave(): Promise<boolean> {
    if (extractionReviewReloadRequired.current) {
      return false;
    }
    clearExtractionDraftSaveTimer();
    return drainPendingExtractionSaves({
      targetSequence: () => extractionDraftSaveSequence.current,
      isBlocked: () => extractionReviewReloadRequired.current,
      savedSequence: () => extractionDraftSavedSequence.current,
      hasPending: () => pendingExtractionDraftSave.current !== null,
      takePending: () => {
        clearExtractionDraftSaveTimer();
        const queued = pendingExtractionDraftSave.current;
        pendingExtractionDraftSave.current = null;
        return queued;
      },
      waitForCurrent: () => extractionDraftSavePromise.current,
      enqueue: (queued) => {
        setExtractionDraftSaveState({ kind: "saving" });
        return enqueueExtractionDraftSave(queued);
      },
    });
  }

  function scheduleExtractionDraftSave(
    request: PendingExtractionDraftSaveRequest,
  ) {
    if (
      extractionReviewReloadRequired.current ||
      extractionCloseInProgress.current ||
      extractionConfirmInFlight.current ||
      extractionDiscardInFlight.current
    ) {
      return;
    }
    extractionDraftSaveSequence.current += 1;
    pendingExtractionDraftSave.current = {
      request,
      sequence: extractionDraftSaveSequence.current,
    };
    clearExtractionDraftSaveTimer();
    setExtractionDraftSaveState({ kind: "pending" });
    extractionDraftSaveTimer.current = window.setTimeout(() => {
      extractionDraftSaveTimer.current = null;
      void flushPendingExtractionDraftSave();
    }, 400);
  }

  function currentCaseDraftDirtyState(): CaseDraftDirtyState {
    const projectId = caseProjectDraft.projectId;
    const editingFileBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "file",
    )
      ? caseWorkspace?.files.find(
          (item) => item.fileId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingPartyBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "party",
    )
      ? caseWorkspace?.parties.find(
          (item) => item.partyId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingFactBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "fact",
    )
      ? caseWorkspace?.facts.find(
          (item) => item.factId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingEvidenceBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "evidence",
    )
      ? caseWorkspace?.evidence.find(
          (item) => item.evidenceId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const editingIssueBaseline = caseEntityEditorMatches(
      activeCaseEntityEditor,
      "legal_issue",
    )
      ? caseWorkspace?.legalIssues.find(
          (item) => item.issueId === activeCaseEntityEditor?.entityId,
        )
      : undefined;
    const baselineFactId = caseWorkspace?.facts[0]?.factId ?? "";
    const baselineEvidenceId =
      caseWorkspace?.evidence[0]?.evidenceId ?? "";
    const baselineIssueId = caseWorkspace?.legalIssues[0]?.issueId ?? "";
    const baselineCaseDate = "";

    return detectDirtyCaseDrafts({
      project: {
        draft: caseProjectDraft,
        baseline: caseWorkspace?.project ?? caseProjectDraftBaseline.current,
      },
      file: {
        draft: fileDraft,
        baseline: editingFileBaseline ?? createCaseFile(projectId),
      },
      party: {
        draft: partyDraft,
        baseline: editingPartyBaseline ?? createParty(projectId),
      },
      fact: {
        draft: factDraft,
        baseline: editingFactBaseline ?? createFact(projectId),
      },
      evidence: {
        draft: evidenceDraft,
        baseline:
          editingEvidenceBaseline ??
          createEvidence(projectId, (caseWorkspace?.evidence.length ?? 0) + 1),
      },
      legalIssue: {
        draft: issueDraft,
        baseline: editingIssueBaseline ?? createIssue(projectId),
      },
      evidenceLink: {
        factId: linkFactId,
        evidenceId: linkEvidenceId,
        baselineFactId,
        baselineEvidenceId,
      },
      factIssueLink: {
        factId: factIssueFactId,
        issueId: factIssueIssueId,
        baselineFactId,
        baselineIssueId,
      },
      legalBasis: {
        sourceId: basisSourceId,
        issueId: basisIssueId,
        caseDate: basisCaseDate,
        includeExpired: basisIncludeExpired,
        note: basisNote,
        baselineIssueId,
        baselineCaseDate,
      },
    });
  }

  dirtyCaseDraftsForClose.current = blockingDirtyCaseDrafts(
    currentCaseDraftDirtyState(),
    [],
  );

  function blockWorkspaceReloadForDirtyDrafts(
    allowed: readonly CaseDraftKind[],
    action: string,
  ): boolean {
    const blocking = blockingDirtyCaseDrafts(
      currentCaseDraftDirtyState(),
      allowed,
    );
    if (blocking.length === 0) {
      return false;
    }

    setCaseState({
      kind: "error",
      message: `${action}会刷新案件工作区。请先保存或清空这些未保存内容：${blocking
        .map((kind) => CASE_DRAFT_LABELS[kind])
        .join("、")}。`,
    });
    return true;
  }

  useEffect(() => {
    let isMounted = true;

    healthCheck()
      .then((response) => {
        if (isMounted) {
          setHealth({ kind: "ready", response });
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setHealth({ kind: "error", message: errorMessage(error) });
        }
      });

    void runSearch(null);

    return () => {
      isMounted = false;
      advanceRequestEpoch(searchRequestEpoch);
      advanceRequestEpoch(articleDetailRequestEpoch);
      advanceRequestEpoch(documentContextRequestEpoch);
    };
    // The initial search is deliberately issued once per mount. Subsequent
    // searches invalidate it through request epochs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const requestId = activeQaRequestId.current;
    const stream = qaStreamRef.current;
    if (
      viewMode === "qa" ||
      !requestId ||
      !shouldCancelLegalAnswerOnPageLeave(stream, requestId) ||
      qaLeaveCancellationRequestId.current === requestId
    ) {
      return;
    }

    const previousStatus = stream.status === "streaming" ? "streaming" : "connecting";
    qaLeaveCancellationRequestId.current = requestId;
    setQaStream((current) => markLegalAnswerCancelling(current));
    void cancelLegalAnswer({ requestId })
      .then((response) => {
        if (qaLeaveCancellationRequestId.current === requestId) {
          qaLeaveCancellationRequestId.current = null;
        }
        if (activeQaRequestId.current !== requestId) {
          return;
        }
        if (response.cancelled) {
          activeQaRequestId.current = null;
          activeQaRequestProjectId.current = null;
          setQaStream((current) =>
            settleLegalAnswerCancellation(
              current,
              requestId,
              true,
              "离开问答页面，生成已取消",
            ),
          );
          setQaState({ kind: "idle" });
          return;
        }

        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      })
      .catch(() => {
        if (qaLeaveCancellationRequestId.current === requestId) {
          qaLeaveCancellationRequestId.current = null;
        }
        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      });
  }, [viewMode]);

  useEffect(
    () => () => {
      const requestId = activeQaRequestId.current;
      if (requestId) {
        activeQaRequestId.current = null;
        activeQaRequestProjectId.current = null;
        void cancelLegalAnswer({ requestId });
      }
    },
    [],
  );

  useEffect(() => {
    let disposed = false;
    let unlistenCloseRequested: (() => void) | undefined;

    const needsCloseFlush = () =>
      extractionReviewNeedsCloseFlush(
        extractionStateRef.current,
        extractionDraftSavedSequence.current,
        extractionDraftSaveSequence.current,
        pendingExtractionDraftSave.current !== null,
      );
    const currentCloseDecision = () => {
      return decideWorkspaceClose({
        dirtyCaseDrafts: dirtyCaseDraftsForClose.current,
        providerDraftDirty: providerNavigationHasUnsavedChanges(
          providerDraftBaseline.current,
          providerDraftRef.current,
          apiKeyInputRef.current,
        ),
        caseMutationInFlight: caseMutationLock.current,
        providerMutationInFlight: providerMutationInFlight.current,
        extractionMutationInFlight: extractionMutationBlocksClose(
          extractionConfirmInFlight.current,
          extractionDiscardInFlight.current,
        ),
        assistantRunActive: assistantRunActive.current,
        assistantMutationInFlight: assistantWritesBlockClose(
          assistantMutationActive.current,
          legalSourceBridgeMutationActive.current,
        ),
        assistantDraftDirty: assistantDraftDirty.current,
        mcpMutationInFlight: mcpMutationActive.current,
        mcpDraftDirty: mcpDraftDirty.current,
        privacyMutationInFlight: privacyMutationActive.current,
        privacyDraftDirty: privacyDraftDirty.current,
      });
    };
    const blockBrowserUnload = (event: BeforeUnloadEvent) => {
      if (controlledCloseApproved.current) {
        return;
      }
      if (
        !needsCloseFlush() &&
        currentCloseDecision().kind === "proceed"
      ) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    };

    window.addEventListener("beforeunload", blockBrowserUnload);
    if ("__TAURI_INTERNALS__" in window) {
      const appWindow = getCurrentWindow();
      void appWindow
        .onCloseRequested(async (event) => {
          if (extractionCloseInProgress.current) {
            event.preventDefault();
            return;
          }
          const closeDecision = currentCloseDecision();
          if (closeDecision.kind === "block") {
            event.preventDefault();
            setCloseProtectionMessage(closeDecision.message);
            return;
          }
          let forceControlledClose = false;
          if (closeDecision.kind === "confirm_discard") {
            event.preventDefault();
            if (
              !workspaceCloseWasApproved(closeDecision, (message) =>
                window.confirm(message),
              )
            ) {
              setCloseProtectionMessage(
                "已取消关闭；未保存内容仍保留在当前窗口。",
              );
              return;
            }
            forceControlledClose = true;
            controlledCloseApproved.current = true;
          }

          const needsFlush = needsCloseFlush();
          if (needsFlush || forceControlledClose) {
            extractionCloseInProgress.current = true;
            setExtractionClosePreparing(needsFlush);
            setCloseProtectionMessage(null);
          }
          const result = await guardExtractionClose({
            needsFlush,
            forceControlledClose,
            preventDefault: () => event.preventDefault(),
            flush: flushPendingExtractionDraftSave,
            destroyWindow: () => appWindow.destroy(),
            onBlocked: (message) => {
              setCaseState({ kind: "error", message });
              setCloseProtectionMessage(message);
            },
          });
          if (result === "blocked") {
            extractionCloseInProgress.current = false;
            controlledCloseApproved.current = false;
            setExtractionClosePreparing(false);
          }
        })
        .then((unlisten) => {
          if (disposed) {
            unlisten();
          } else {
            unlistenCloseRequested = unlisten;
          }
        })
        .catch((error: unknown) => {
          if (!disposed) {
            setCloseProtectionMessage(
              `无法注册关闭前草稿保护：${errorMessage(error)}`,
            );
          }
        });
    }

    return () => {
      disposed = true;
      window.removeEventListener("beforeunload", blockBrowserUnload);
      unlistenCloseRequested?.();
      clearExtractionDraftSaveTimer();
    };
    // The handler intentionally reads mutable refs so it always protects the
    // latest workspace and review without re-registering the native listener.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (extractionState.kind !== "reviewing") {
      return;
    }
    const frame = requestAnimationFrame(() => extractionReviewRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [extractionState.kind]);

  useEffect(() => {
    qaPreviewEpoch.current += 1;
    const previousProjectId = qaDraftProjectId.current;
    qaDraftsByProject.current.set(
      qaDraftStorageKey(previousProjectId),
      currentQaFormDraft(),
    );
    qaDraftProjectId.current = selectedCaseProjectId;
    applyQaFormDraft(
      copyQaFormDraft(
        qaDraftsByProject.current.get(
          qaDraftStorageKey(selectedCaseProjectId),
        ) ?? DEFAULT_QA_FORM_DRAFT,
      ),
    );

    const activeRequestId = activeQaRequestId.current;
    if (
      activeRequestId &&
      !legalAnswerRequestStillOwnsCurrentCase(
        activeQaRequestProjectId.current,
        selectedCaseProjectId,
      )
    ) {
      activeQaRequestId.current = null;
      activeQaRequestProjectId.current = null;
      qaLeaveCancellationRequestId.current = null;
      void cancelLegalAnswer({ requestId: activeRequestId });
    }

    qaHistoryLoadEpoch.current += 1;
    setQaHistoryRecords([]);
    setQaHistoryHasMore(false);
    setQaHistoryState({ kind: "idle" });
    setQaAnswer(null);
    setQaContext(null);
    setQaState({ kind: "idle" });
    setQaSubmittedQuestion(null);
    setSelectedQaSourceId(null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);

    if (!selectedCaseProjectId) {
      return;
    }
    void refreshLegalAnswerHistory(selectedCaseProjectId);
    // Only a project transition may snapshot/restore these form fields. Their
    // live values intentionally are not dependencies of this transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCaseProjectId]);

  const refreshKeyStatus = useCallback(async (profile: ProviderProfile) => {
    const response = await getProviderApiKeyStatus({
      providerId: profile.id,
      accountId: profile.credentialAccountId,
    });

    setKeyStatuses((current) => ({
      ...current,
      [profile.id]: response.status,
    }));
  }, []);

  useEffect(() => {
    let isMounted = true;
    setProviderState({ kind: "loading" });

    listProviderProfiles()
      .then(async (response) => {
        if (!isMounted) {
          return;
        }

        setProviderProfiles(response.profiles);
        if (response.profiles.length > 0) {
          setSelectedProviderId(response.profiles[0].id);
          setQaProviderId(response.profiles[0].id);
          setExtractionProviderId(response.profiles[0].id);
          setProviderDraft(response.profiles[0]);
          providerDraftBaseline.current = response.profiles[0];
        }

        const statusResult = await loadProviderKeyStatusesSettled(
          response.profiles,
          async (profile) => {
            const statusResponse = await getProviderApiKeyStatus({
              providerId: profile.id,
              accountId: profile.credentialAccountId,
            });

            return statusResponse.status;
          },
        );

        if (isMounted) {
          setKeyStatuses(statusResult.statuses);
          if (statusResult.failedCount > 0) {
            setProviderState({
              kind: "error",
              message: `${statusResult.failedCount} 个 Provider 的凭据状态读取失败，可重试对应操作。`,
            });
          } else {
            setProviderState({ kind: "idle" });
          }
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setProviderState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  function applyCaseWorkspace(workspace: CaseWorkspace) {
    setActiveCaseEntityEditor(null);
    setCaseWorkspace(workspace);
    setCaseWorkspaceWriteBlocked(false);
    persistedMutationRecoveryProjectId.current = null;
    clearCaseValidationError();
    setSelectedCaseProjectId(workspace.project.projectId);
    setCaseProjectDraft(workspace.project);
    caseProjectDraftBaseline.current = workspace.project;
    setFileDraft(createCaseFile(workspace.project.projectId));
    setPartyDraft(createParty(workspace.project.projectId));
    setFactDraft(createFact(workspace.project.projectId));
    setEvidenceDraft(
      createEvidence(workspace.project.projectId, workspace.evidence.length + 1),
    );
    setIssueDraft(createIssue(workspace.project.projectId));
    setBasisSourceId("");
    setBasisIssueId(workspace.legalIssues[0]?.issueId ?? "");
    setBasisCaseDate("");
    setBasisIncludeExpired(false);
    setBasisNote("");
    setLinkFactId(workspace.facts[0]?.factId ?? "");
    setLinkEvidenceId(workspace.evidence[0]?.evidenceId ?? "");
    setFactIssueFactId(workspace.facts[0]?.factId ?? "");
    setFactIssueIssueId(workspace.legalIssues[0]?.issueId ?? "");
    const availableFileIds = new Set(workspace.files.map((file) => file.fileId));
    setExtractionFileIds((current) =>
      current.filter((fileId) => availableFileIds.has(fileId)),
    );
  }

  async function restorePendingExtractionReview(
    workspace: CaseWorkspace,
    requestEpoch: number,
  ): Promise<string | null> {
    setPendingReviewRecoveryBlock(null);
    const active = extractionStateRef.current;
    if (
      (active.kind === "generating" ||
        active.kind === "reviewing" ||
        active.kind === "committing") &&
      active.context.projectId === workspace.project.projectId
    ) {
      return null;
    }

    extractionLifecycleLock.current = false;
    setExtractionDiscardError(null);
    dispatchExtraction({ type: "reset" });
    beginExtractionDraftSaveSession();
    try {
      const response = await getPendingStructuredCaseExtraction({
        projectId: workspace.project.projectId,
      });
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return null;
      }
      const pending = response.pending ?? null;
      if (!pending) {
        return null;
      }
      if (pending.projectId !== workspace.project.projectId) {
        return "待恢复抽取审阅的案件归属不匹配，已拒绝载入。";
      }
      if (!Number.isSafeInteger(pending.revision) || pending.revision < 0) {
        return "待恢复草稿缺少有效的版本信息，已拒绝载入。";
      }
      if (!pending.providerSnapshot) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message:
            "待恢复抽取审阅缺少可信的生成配置快照，只能永久放弃，不能确认写入。",
        });
        return "待恢复抽取审阅缺少可信的生成配置快照，已拒绝载入。";
      }
      if (!structuredCaseExtractionIsPublic(pending.extraction)) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message: "待恢复内容未通过安全检查，只能放弃后重新整理。",
        });
        return "待恢复内容未通过安全检查，已拒绝载入。";
      }

      const workspaceFileIds = workspace.files.map((file) => file.fileId);
      if (!pendingReviewFilesStillExist(workspaceFileIds, pending.fileIds)) {
        setPendingReviewRecoveryBlock({
          reviewId: pending.reviewId,
          projectId: pending.projectId,
          revision: pending.revision,
          message: "待恢复抽取审阅引用的案件材料已变化，不能安全确认。",
        });
        return "待恢复抽取审阅引用的案件材料已变化，已拒绝自动载入。";
      }
      const restorableFileIds = [...pending.fileIds];

      const context = createExtractionContext(
        createId("extraction-restore"),
        pending.projectId,
        pending.providerId,
        restorableFileIds,
        pending.providerSnapshot,
      );
      setExtractionProviderId(pending.providerId);
      setExtractionFileIds(restorableFileIds);
      extractionLifecycleLock.current = true;
      beginExtractionDraftSaveSession({
        kind: "saved",
        expiresAt: pending.expiresAt,
      }, pending.revision);
      dispatchExtraction({
        type: "restore",
        context,
        reviewId: pending.reviewId,
        draft: pending.extraction,
        revision: pending.revision,
        createdAt: pending.createdAt,
        expiresAt: pending.expiresAt,
      });
      return null;
    } catch (error: unknown) {
      return `未能恢复待审阅的材料整理结果：${errorMessage(error)}`;
    }
  }

  async function loadCaseWorkspace(
    projectId: string,
    requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch),
    recoverAfterPersistedMutation = false,
  ): Promise<boolean> {
    if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
      return false;
    }
    setCaseState({ kind: "loading" });

    try {
      const response = await getCaseWorkspace({ projectId });
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return false;
      }

      const workspace = response.workspace ?? null;
      if (!workspace || workspace.project.projectId !== projectId) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
        setCaseState({
          kind: "error",
          message:
            "目标案件未返回有效工作区；已保留原案件与草稿并锁定写操作。请重试加载案件后再继续编辑。",
        });
        return false;
      }
      applyCaseWorkspace(workspace);
      const extractionRestoreError =
        await restorePendingExtractionReview(workspace, requestEpoch);
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return false;
      }
      if (extractionRestoreError) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
      }
      setCaseState(
        extractionRestoreError
          ? {
              kind: "error",
              message: `${extractionRestoreError} 写操作已锁定；请点击当前案件重试完整加载。`,
            }
          : { kind: "idle" },
      );
      return extractionRestoreError === null;
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        if (recoverAfterPersistedMutation) {
          persistedMutationRecoveryProjectId.current = projectId;
        }
        setCaseWorkspaceWriteBlocked(true);
        setCaseState({
          kind: "error",
          message: `案件加载失败；已保留原案件与草稿并锁定写操作。请重试：${errorMessage(error)}`,
        });
      }
      return false;
    }
  }

  async function refreshCaseProjects(
    preferredProjectId: string | undefined,
    requestEpoch: number,
    recoverAfterPersistedMutation = false,
  ) {
    try {
      const response = await listCaseProjects();
      if (!isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return response.projects;
      }
      setCaseProjects(response.projects);

      // After a successful write, never fall back to some other case merely
      // because a stale list response omitted the saved project. The exact
      // persisted id remains authoritative and can still be loaded directly.
      const nextProject = caseProjectToLoadAfterRefresh(
        response.projects,
        preferredProjectId,
        recoverAfterPersistedMutation,
      );

      if (nextProject) {
        setCaseProjectPage(
          caseProjectPageForId(response.projects, nextProject.projectId),
        );
        const workspaceLoaded = await loadCaseWorkspace(
          nextProject.projectId,
          requestEpoch,
          recoverAfterPersistedMutation,
        );
        if (!workspaceLoaded) {
          return undefined;
        }
      } else if (recoverAfterPersistedMutation && preferredProjectId) {
        const workspaceLoaded = await loadCaseWorkspace(
          preferredProjectId,
          requestEpoch,
          true,
        );
        if (!workspaceLoaded) {
          return undefined;
        }
        if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
          setCaseState({
            kind: "error",
            message:
              "案件已保存并安全加载，但案件列表未返回该案件；当前编辑可继续，重启应用后列表会重新读取。",
          });
        }
      } else {
        setActiveCaseEntityEditor(null);
        setSelectedCaseProjectId(null);
        setCaseWorkspace(null);
        setCaseWorkspaceWriteBlocked(false);
        persistedMutationRecoveryProjectId.current = null;
        setCaseProjectPage(1);
        setCaseState({ kind: "idle" });
      }
      return response.projects;
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        if (recoverAfterPersistedMutation && preferredProjectId) {
          const workspaceLoaded = await loadCaseWorkspace(
            preferredProjectId,
            requestEpoch,
            true,
          );
          if (workspaceLoaded) {
            if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
              setCaseState({
                kind: "error",
                message: `案件已保存并安全加载，但案件列表刷新失败；当前编辑可继续：${errorMessage(error)}`,
              });
            }
            return caseProjects;
          }
        } else {
          setCaseState({ kind: "error", message: errorMessage(error) });
        }
      }
      return undefined;
    }
  }

  useEffect(() => {
    let isMounted = true;
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);

    listCaseProjects()
      .then(async (response) => {
        if (
          !isMounted ||
          !isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          return;
        }

        setCaseProjects(response.projects);
        const firstProject = response.projects[0];
        if (firstProject) {
          setCaseProjectPage(1);
          await loadCaseWorkspace(firstProject.projectId, requestEpoch);
        } else {
          setCaseState({ kind: "idle" });
        }
      })
      .catch((error: unknown) => {
        if (
          isMounted &&
          isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          setCaseState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => {
      isMounted = false;
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
      }
    };
    // This mount request deliberately owns one fixed epoch; later navigation
    // invalidates it instead of recreating the loader closure.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runSearch(
    documentId: string | null,
    requiredDocumentEpoch?: number,
  ) {
    const requestEpoch = advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    const criteria = currentLawSearchCriteria(queryRef, caseDateRef);

    setSearchState({ kind: "loading" });
    setSelectedArticleId(null);
    setSelectedArticle(null);
    setDetailState({ kind: "idle" });

    try {
      const [lawResponse, articleResponse] = await Promise.all([
        searchLaws({ query: criteria.query, limit: 12 }),
        searchArticles({
          query: criteria.query,
          documentId,
          caseDate: criteria.caseDate,
          limit: 24,
        }),
      ]);

      if (
        !isCurrentRequestEpoch(searchRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== documentId ||
        (requiredDocumentEpoch !== undefined &&
          !isCurrentRequestEpoch(
            documentContextRequestEpoch,
            requiredDocumentEpoch,
          ))
      ) {
        return;
      }

      setLaws(lawResponse.results);
      setArticles(articleResponse.results);
      setSearchState({ kind: "idle" });

      if (articleResponse.results[0]) {
        await loadArticleDetail(
          articleResponse.results[0].articleId,
          requestEpoch,
        );
      } else {
        setSelectedArticleId(null);
        setSelectedArticle(null);
      }
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(searchRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === documentId &&
        (requiredDocumentEpoch === undefined ||
          isCurrentRequestEpoch(
            documentContextRequestEpoch,
            requiredDocumentEpoch,
          ))
      ) {
        setSearchState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  async function loadArticleDetail(
    articleId: string,
    owningSearchEpoch?: number,
  ) {
    const requestEpoch = advanceRequestEpoch(articleDetailRequestEpoch);
    const documentId = selectedDocumentIdRef.current;
    setSelectedArticleId(articleId);
    setDetailState({ kind: "loading" });

    try {
      const response = await getArticle({ articleId });
      if (
        !isCurrentRequestEpoch(articleDetailRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== documentId ||
        (owningSearchEpoch !== undefined &&
          !isCurrentRequestEpoch(searchRequestEpoch, owningSearchEpoch))
      ) {
        return;
      }
      setSelectedArticle(response.article ?? null);
      setDetailState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(articleDetailRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === documentId &&
        (owningSearchEpoch === undefined ||
          isCurrentRequestEpoch(searchRequestEpoch, owningSearchEpoch))
      ) {
        setDetailState({ kind: "error", message: errorMessage(error) });
      }
    }
  }

  async function loadDocumentContext(document: LawSearchResult) {
    const requestEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    selectedDocumentIdRef.current = document.documentId;
    setSelectedDocument(document);
    setGraphDocumentId(document.documentId);
    setVersions([]);
    setRelations([]);
    setArticles([]);
    setSelectedArticleId(null);
    setSelectedArticle(null);
    setDocumentState({ kind: "loading" });

    try {
      const [versionResponse, relationResponse] = await Promise.all([
        getLawVersions({ documentId: document.documentId }),
        getLawRelations({ documentId: document.documentId, direction: "both" }),
      ]);

      if (
        !isCurrentRequestEpoch(documentContextRequestEpoch, requestEpoch) ||
        selectedDocumentIdRef.current !== document.documentId
      ) {
        return;
      }

      setVersions(versionResponse.versions);
      setRelations(relationResponse.relations);
      setDocumentState({ kind: "idle" });
      await runSearch(document.documentId, requestEpoch);
    } catch (error: unknown) {
      if (
        isCurrentRequestEpoch(documentContextRequestEpoch, requestEpoch) &&
        selectedDocumentIdRef.current === document.documentId
      ) {
        setDocumentState({ kind: "error", message: errorMessage(error) });
        setSearchState({ kind: "idle" });
      }
    }
  }

  async function clearDocumentFilter() {
    const requestEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    selectedDocumentIdRef.current = null;
    setSelectedDocument(null);
    setVersions([]);
    setRelations([]);
    setDocumentState({ kind: "idle" });
    await runSearch(null, requestEpoch);
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runSearch(selectedDocument?.documentId ?? null);
  }

  function openCaseGraph() {
    if (!selectedCaseProjectIdRef.current) return;
    setGraphMode("case");
    setViewMode("graph");
  }

  function openLawGraph(documentId: string) {
    setGraphDocumentId(documentId);
    setGraphMode("law");
    setViewMode("graph");
  }

  async function openLocalLawRecord(
    documentId: string,
    label: string,
    articleId?: string,
  ) {
    setViewMode("search");
    setQuery(label);
    queryRef.current = label;

    const loaded = laws.find((law) => law.documentId === documentId);
    if (loaded) {
      await loadDocumentContext(loaded);
      if (articleId && selectedDocumentIdRef.current === documentId) {
        await loadArticleDetail(articleId);
      }
      return;
    }

    const lookupEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    selectedDocumentIdRef.current = null;
    setSelectedDocument(null);
    setVersions([]);
    setRelations([]);
    setArticles([]);
    setSelectedArticle(null);
    setSelectedArticleId(null);
    setSearchState({ kind: "loading" });
    setDocumentState({ kind: "loading" });
    try {
      const response = await getLawDocument({ documentId });
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) return;
      const target = response.document;
      if (!target) {
        setSearchState({
          kind: "error",
          message: "当前本地法律库中没有找到对应法律文件。",
        });
        setDocumentState({ kind: "idle" });
        return;
      }
      if (!exactLawDocumentMatchesRequest(target, documentId)) {
        setSearchState({
          kind: "error",
          message: "法律文件校验未通过，已停止跳转，请重新检索。",
        });
        setDocumentState({ kind: "idle" });
        return;
      }
      setLaws((current) =>
        current.some((law) => law.documentId === documentId)
          ? current
          : [target, ...current],
      );
      await loadDocumentContext(target);
      if (articleId && selectedDocumentIdRef.current === documentId) {
        await loadArticleDetail(articleId);
      }
    } catch (error: unknown) {
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) return;
      setSearchState({ kind: "error", message: errorMessage(error) });
      setDocumentState({ kind: "idle" });
    }
  }

  async function openLawDocumentFromGraph(node: GraphNode) {
    await openLocalLawRecord(node.sourceId, node.label);
  }

  async function openDocumentCitation(citation: DocumentCitation) {
    const lookupEpoch = advanceRequestEpoch(documentContextRequestEpoch);
    advanceRequestEpoch(searchRequestEpoch);
    advanceRequestEpoch(articleDetailRequestEpoch);
    setViewMode("search");
    setDocumentState({ kind: "loading" });
    setDetailState({ kind: "loading" });
    try {
      const response = await getArticle({ articleId: citation.articleId });
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) return;
      const article = response.article;
      if (!articleMatchesDocumentCitation(article, citation)) {
        setDocumentState({
          kind: "error",
          message: "该文书引用无法映射到当前正式本地法律库，已拒绝跳转。",
        });
        setDetailState({ kind: "idle" });
        return;
      }
      await openLocalLawRecord(
        article.documentId,
        article.documentTitle,
        article.articleId,
      );
    } catch (error: unknown) {
      if (!isCurrentRequestEpoch(documentContextRequestEpoch, lookupEpoch)) return;
      const message = errorMessage(error);
      setDocumentState({ kind: "error", message });
      setDetailState({ kind: "error", message });
    }
  }

  function openGraphNode(node: GraphNode) {
    const destination = graphNodeDestination(node);
    if (destination === "law") {
      void openLawDocumentFromGraph(node);
      return;
    }
    if (destination === "case") {
      setGraphCaseTarget({ sourceKind: node.sourceKind, sourceId: node.sourceId });
      setViewMode("cases");
      return;
    }
    setStatusForUnsupportedGraphNode(node);
  }

  function setStatusForUnsupportedGraphNode(node: GraphNode) {
    void node;
    setCaseState({
      kind: "error",
      message: "暂不支持打开该项内容。",
    });
  }

  function buildLegalAnswerCandidateRequest() {
    return createLegalAnswerCandidateRequest({
      question: qaQuestion,
      lawName: qaLawName,
      articleNumber: qaArticleNumber,
      keywords: qaKeywords,
      caseDate: qaCaseDate,
      effectivenessLevels: qaEffectivenessLevels,
      includeExpired: qaIncludeExpired,
      limit: 8,
    });
  }

  async function previewLegalAnswerContext(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const request = buildLegalAnswerCandidateRequest();
    if (!request.question) {
      setQaState({ kind: "error", message: "请输入法律问题" });
      return;
    }
    const previewEpoch = ++qaPreviewEpoch.current;
    const previewProjectId = selectedCaseProjectIdRef.current;

    setQaState({ kind: "loading" });
    setQaAnswer(null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);

    try {
      const response = await findLegalAnswerCandidates(request);
      if (
        qaPreviewEpoch.current !== previewEpoch ||
        !legalAnswerPreviewStillOwnsCurrentScope(
          previewProjectId,
          selectedCaseProjectIdRef.current,
        )
      ) {
        return;
      }
      setQaContext(response.context);
      setSelectedQaSourceId(response.context.sources[0]?.sourceId ?? null);
      setQaState({ kind: "idle" });
    } catch (error: unknown) {
      if (
        qaPreviewEpoch.current !== previewEpoch ||
        !legalAnswerPreviewStillOwnsCurrentScope(
          previewProjectId,
          selectedCaseProjectIdRef.current,
        )
      ) {
        return;
      }
      setQaState({ kind: "error", message: errorMessage(error) });
    }
  }

  async function submitLegalAnswer(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const request = buildLegalAnswerCandidateRequest();
    if (!request.question) {
      setQaState({ kind: "error", message: "请输入法律问题" });
      return;
    }
    if (!qaProviderId) {
      setQaState({ kind: "error", message: "请先选择已保存的 Provider" });
      return;
    }
    const projectId = selectedCaseProjectId;
    if (
      !projectId ||
      caseState.kind === "loading" ||
      caseMutationInFlight ||
      !isPersistedCaseWorkspace(
        caseWorkspace,
        projectId,
        caseProjectDraft.projectId,
      ) ||
      caseWorkspaceWriteBlocked
    ) {
      setQaState({
        kind: "error",
        message: "请先在案件工作台保存并成功加载一个案件；法律回答必须归属案件。",
      });
      return;
    }

    if (activeQaRequestId.current) {
      await cancelCurrentLegalAnswer();
      if (activeQaRequestId.current) {
        setQaState({
          kind: "error",
          message: "上一轮回答仍在结束中，请等待后再发起新请求。",
        });
        return;
      }
    }

    const requestId = createLegalAnswerRequestId();
    activeQaRequestId.current = requestId;
    activeQaRequestProjectId.current = projectId;
    qaLeaveCancellationRequestId.current = null;
    setQaSubmittedQuestion(request.question);
    setQaState({ kind: "loading" });
    setQaAnswer(null);
    setQaStream(startLegalAnswerStream(requestId));

    try {
      const response = await answerLegalQuestion(
        {
          ...request,
          requestId,
          projectId,
          providerId: qaProviderId,
          temperature: 0.1,
          maxTokens: 1024,
        },
        (streamEvent) => {
          if (
            activeQaRequestId.current !== requestId ||
            activeQaRequestProjectId.current !== projectId ||
            selectedCaseProjectIdRef.current !== projectId
          ) {
            return;
          }
          setQaStream((current) =>
            reduceLegalAnswerStreamEvent(current, streamEvent),
          );
        },
      );
      if (
        activeQaRequestId.current !== requestId ||
        activeQaRequestProjectId.current !== projectId ||
        !legalAnswerRequestStillOwnsCurrentCase(
          projectId,
          selectedCaseProjectIdRef.current,
        )
      ) {
        return;
      }
      setQaAnswer(response);
      setQaContext(response.context);
      setSelectedQaSourceId(response.context.sources[0]?.sourceId ?? null);
      setQaStream((current) => ({
        ...current,
        status: "done",
        answer: response.answer,
        message: "引用已完成校验，回答已保存",
      }));
      setQaState({ kind: "idle" });
      void refreshLegalAnswerHistory(projectId);
    } catch (error: unknown) {
      if (activeQaRequestId.current === requestId) {
        if (
          !legalAnswerRequestStillOwnsCurrentCase(
            projectId,
            selectedCaseProjectIdRef.current,
          )
        ) {
          return;
        }
        const message = errorMessage(error);
        setQaStream((current) =>
          current.status === "cancelled" || current.status === "error"
            ? current
            : {
                ...current,
                status: message.toLowerCase().includes("cancel")
                  ? "cancelled"
                  : "error",
                message,
              },
        );
        setQaState({ kind: "idle" });
      }
    } finally {
      if (qaLeaveCancellationRequestId.current === requestId) {
        qaLeaveCancellationRequestId.current = null;
      }
      if (activeQaRequestId.current === requestId) {
        activeQaRequestId.current = null;
        activeQaRequestProjectId.current = null;
      }
    }
  }

  async function cancelCurrentLegalAnswer() {
    const requestId = activeQaRequestId.current;
    const stream = qaStreamRef.current;
    if (
      !requestId ||
      !shouldCancelLegalAnswerOnPageLeave(stream, requestId)
    ) {
      return;
    }

    const previousStatus = stream.status === "streaming" ? "streaming" : "connecting";
    setQaStream((current) => markLegalAnswerCancelling(current));
    try {
      const response = await cancelLegalAnswer({ requestId });
      if (activeQaRequestId.current !== requestId) {
        return;
      }
      if (response.cancelled) {
        activeQaRequestId.current = null;
        activeQaRequestProjectId.current = null;
        setQaStream((current) =>
          settleLegalAnswerCancellation(current, requestId, true),
        );
        setQaState({ kind: "idle" });
      } else {
        setQaStream((current) =>
          restoreLegalAnswerAfterRejectedCancellation(
            current,
            requestId,
            previousStatus,
          ),
        );
      }
    } catch (error: unknown) {
      setQaStream((current) => {
        const restored = restoreLegalAnswerAfterRejectedCancellation(
          current,
          requestId,
          previousStatus,
        );
        return restored === current
          ? current
          : {
              ...restored,
              message: `取消请求失败：${errorMessage(error)}；等待当前请求结束`,
            };
      });
    }
  }

  function selectQaSource(source: LegalSource) {
    setSelectedQaSourceId(source.sourceId);
  }

  function restoreLegalAnswerRecord(record: LegalAnswerRecord) {
    if (record.projectId !== selectedCaseProjectId) {
      setQaHistoryState({
        kind: "error",
        message: "该历史回答不属于当前案件，已拒绝恢复。",
      });
      return;
    }
    const context = legalAnswerContextFromRecord(record);
    const formDraft = qaFormDraftFromLegalAnswerRecord(record);
    setQaAnswer({
      providerId: record.providerId,
      answer: record.answer,
      context,
      citationReport: record.citationReport,
      recordId: record.recordId,
    });
    setQaContext(context);
    setQaSubmittedQuestion(formDraft.question);
    setQaQuestion(formDraft.question);
    setQaLawName(formDraft.lawName);
    setQaArticleNumber(formDraft.articleNumber);
    setQaKeywords(formDraft.keywords);
    setQaCaseDate(formDraft.caseDate);
    setQaEffectivenessLevels(formDraft.effectivenessLevels);
    setQaIncludeExpired(formDraft.includeExpired);
    setSelectedQaSourceId(context.sources[0]?.sourceId ?? null);
    setQaStream(INITIAL_LEGAL_ANSWER_STREAM_STATE);
    setQaState({ kind: "idle" });
  }

  function resetAllCaseEntityDrafts(
    projectId = caseProjectDraft.projectId,
    nextEvidenceNumber = (caseWorkspace?.evidence.length ?? 0) + 1,
  ) {
    setFileDraft(createCaseFile(projectId));
    setPartyDraft(createParty(projectId));
    setFactDraft(createFact(projectId));
    setEvidenceDraft(createEvidence(projectId, nextEvidenceNumber));
    setIssueDraft(createIssue(projectId));
  }

  function startCaseEntityEdit(target: CaseEntityEditTarget) {
    if (
      !caseChildrenReady ||
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "开始编辑")) {
      return;
    }

    resetAllCaseEntityDrafts(target.entity.projectId);
    switch (target.entityType) {
      case "file": {
        const draft = copyCaseEntityForEditing(target.entity);
        setFileDraft({
          ...draft,
          summary: publicCaseBusinessText(draft.summary),
        });
        setActiveCaseEntityEditor({
          entityType: "file",
          entityId: target.entity.fileId,
        });
        break;
      }
      case "party": {
        const draft = copyCaseEntityForEditing(target.entity);
        setPartyDraft({
          ...draft,
          name: publicTitle(draft.name, ""),
          normalizedName: publicCaseBusinessText(draft.normalizedName),
          contact: publicCaseBusinessText(draft.contact),
          notes: publicCaseBusinessText(draft.notes),
        });
        setActiveCaseEntityEditor({
          entityType: "party",
          entityId: target.entity.partyId,
        });
        break;
      }
      case "fact": {
        const draft = copyCaseEntityForEditing(target.entity);
        setFactDraft({
          ...draft,
          description: publicCaseBusinessText(draft.description),
          source: publicCaseBusinessText(draft.source),
        });
        setActiveCaseEntityEditor({
          entityType: "fact",
          entityId: target.entity.factId,
        });
        break;
      }
      case "evidence": {
        const draft = copyCaseEntityForEditing(target.entity);
        setEvidenceDraft({
          ...draft,
          evidenceNumber: publicEvidenceNumber(draft.evidenceNumber, ""),
          source: publicCaseBusinessText(draft.source),
          summary: publicCaseBusinessText(draft.summary),
        });
        setActiveCaseEntityEditor({
          entityType: "evidence",
          entityId: target.entity.evidenceId,
        });
        break;
      }
      case "legal_issue": {
        const draft = copyCaseEntityForEditing(target.entity);
        setIssueDraft({
          ...draft,
          title: publicTitle(draft.title, ""),
          description: publicCaseBusinessText(draft.description),
          claim: publicCaseBusinessText(draft.claim),
        });
        setActiveCaseEntityEditor({
          entityType: "legal_issue",
          entityId: target.entity.issueId,
        });
        break;
      }
    }
    setCaseState({ kind: "idle" });
  }

  function cancelCaseEntityEdit() {
    if (caseMutationLock.current) {
      return;
    }
    const editor = activeCaseEntityEditor;
    if (!editor) {
      return;
    }

    switch (editor.entityType) {
      case "file":
        setFileDraft(createCaseFile(caseProjectDraft.projectId));
        break;
      case "party":
        setPartyDraft(createParty(caseProjectDraft.projectId));
        break;
      case "fact":
        setFactDraft(createFact(caseProjectDraft.projectId));
        break;
      case "evidence":
        setEvidenceDraft(
          createEvidence(
            caseProjectDraft.projectId,
            (caseWorkspace?.evidence.length ?? 0) + 1,
          ),
        );
        break;
      case "legal_issue":
        setIssueDraft(createIssue(caseProjectDraft.projectId));
        break;
    }
    setActiveCaseEntityEditor(null);
  }

  function startNewCaseProject() {
    if (caseInteractionIsLocked()) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "新建案件")) {
      return;
    }
    advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    setActiveCaseEntityEditor(null);
    const project = createCaseProject();
    setSelectedCaseProjectId(null);
    setCaseWorkspace(null);
    setCaseWorkspaceWriteBlocked(false);
    clearCaseValidationError();
    setCaseProjectDraft(project);
    caseProjectDraftBaseline.current = project;
    setFileDraft(createCaseFile(project.projectId));
    setPartyDraft(createParty(project.projectId));
    setFactDraft(createFact(project.projectId));
    setEvidenceDraft(createEvidence(project.projectId, 1));
    setIssueDraft(createIssue(project.projectId));
    setBasisSourceId("");
    setBasisIssueId("");
    setBasisCaseDate("");
    setBasisIncludeExpired(false);
    setBasisNote("");
    setLinkFactId("");
    setLinkEvidenceId("");
    setFactIssueFactId("");
    setFactIssueIssueId("");
    setExtractionFileIds([]);
    setExtractionDiscardError(null);
    extractionLifecycleLock.current = false;
    beginExtractionDraftSaveSession();
    dispatchExtraction({ type: "reset" });
    setCaseState({ kind: "idle" });
  }

  function selectCaseProject(project: CaseProject) {
    if (caseInteractionIsLocked()) {
      return;
    }
    if (
      project.projectId === selectedCaseProjectId &&
      !caseWorkspaceWriteBlocked
    ) {
      return;
    }
    const retriesPersistedMutationReload =
      canBypassDirtyDraftsForWorkspaceRecovery(
        project.projectId,
        selectedCaseProjectId,
        caseWorkspaceWriteBlocked,
        persistedMutationRecoveryProjectId.current,
      );
    if (
      !retriesPersistedMutationReload &&
      blockWorkspaceReloadForDirtyDrafts([], "切换案件")
    ) {
      return;
    }
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    void loadCaseWorkspace(project.projectId, requestEpoch).then((loaded) => {
      if (!loaded || !isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        return;
      }
      setCaseProjectPage(caseProjectPageForId(caseProjects, project.projectId));
    });
  }

  async function saveCaseProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      setCaseState({
        kind: "error",
        message: "请先完成或取消当前子项编辑，再保存案件。",
      });
      return;
    }
    const project = {
      ...caseProjectDraft,
      title: caseProjectDraft.title.trim() || "未命名案件",
      caseType: caseProjectDraft.caseType.trim(),
      summary: caseProjectDraft.summary.trim(),
      openedOn: caseProjectDraft.openedOn || null,
    };
    if (blockWorkspaceReloadForDirtyDrafts(["project"], "保存案件")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    setCaseState({ kind: "loading" });

    try {
      const response = await upsertCaseProject({ project });
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseProjectDraft(response.project);
        caseProjectDraftBaseline.current = response.project;
        setBasisCaseDate("");
      }
      await refreshCaseProjects(response.project.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function removeCaseProject() {
    if (
      !selectedCaseProjectId ||
      caseNavigationLocked ||
      caseInteractionIsLocked() ||
      activeCaseEntityEditor !== null
    ) {
      return;
    }

    const projectId = selectedCaseProjectId;
    if (blockWorkspaceReloadForDirtyDrafts([], "删除案件")) {
      return;
    }
    const projectTitle =
      caseProjects.find((project) => project.projectId === projectId)?.title ||
      caseProjectDraft.title ||
      "当前案件";
    await runConfirmedDestructiveAction(
      caseProjectDeletionConfirmation(projectTitle),
      (message) => window.confirm(message),
      async () => {
        const requestEpoch = beginCaseMutation();
        if (requestEpoch === null) {
          return;
        }
        let startBlankProject = false;
        setCaseState({ kind: "loading" });

        try {
          await deleteCaseProject({ projectId });
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setSelectedCaseProjectId(null);
            setCaseWorkspace(null);
          }
          const projects = await refreshCaseProjects(undefined, requestEpoch);
          if (
            isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch) &&
            projects?.length === 0
          ) {
            startBlankProject = true;
          }
        } catch (error: unknown) {
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setCaseState({ kind: "error", message: errorMessage(error) });
          }
        } finally {
          finishCaseMutation();
        }

        if (
          startBlankProject &&
          isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)
        ) {
          startNewCaseProject();
        }
      },
    );
  }

  function requirePersistedCaseWorkspace(
    entityType?: EditableCaseEntityType,
    entityId?: string,
  ): boolean {
    if (caseMutationLock.current) {
      setCaseState({
        kind: "error",
        message: "案件数据正在写入，请等待当前操作完成。",
      });
      return false;
    }

    if (caseWorkspaceWriteBlocked) {
      setCaseState({
        kind: "error",
        message:
          "案件加载失败后写操作仍处于锁定状态。请点击案件列表中的案件重新加载，成功后再继续。",
      });
      return false;
    }

    if (!caseChildrenReady) {
      setCaseState({
        kind: "error",
        message: "请先保存案件，再操作案件子项。",
      });
      return false;
    }

    if (caseNavigationLocked || extractionLifecycleLock.current) {
      setCaseState({
        kind: "error",
        message: "材料信息整理进行中，请先完成或放弃当前任务。",
      });
      return false;
    }

    if (
      activeCaseEntityEditor !== null &&
      (entityType === undefined ||
        !caseEntityEditorMatches(
          activeCaseEntityEditor,
          entityType,
          entityId,
        ))
    ) {
      setCaseState({
        kind: "error",
        message: "请先完成或取消当前子项编辑。",
      });
      return false;
    }

    return true;
  }

  async function saveParty(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!requirePersistedCaseWorkspace("party")) {
      return;
    }

    const party = {
      ...partyDraft,
      projectId: caseProjectDraft.projectId,
      name: partyDraft.name.trim(),
      normalizedName: partyDraft.normalizedName.trim(),
    };

    if (!party.name) {
      showCaseValidationError("请输入当事人名称。", "case-party-name");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["party"], "保存当事人")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertCaseParty({ party });
      await loadCaseWorkspace(party.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("file")) {
      return;
    }
    const file = {
      ...fileDraft,
      projectId: caseProjectDraft.projectId,
      title: fileDraft.title.trim(),
      fileType: fileDraft.fileType.trim(),
      storageReference: fileDraft.storageReference.trim(),
      summary: fileDraft.summary.trim(),
    };

    if (!file.title) {
      showCaseValidationError("请输入案件材料标题。", "case-file-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["file"], "保存案件材料")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertCaseFile({ file });
      await loadCaseWorkspace(file.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveFact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("fact")) {
      return;
    }
    const fact = {
      ...factDraft,
      projectId: caseProjectDraft.projectId,
      title: factDraft.title.trim(),
      occurredOn: factDraft.occurredOn || null,
    };

    if (!fact.title) {
      showCaseValidationError("请输入事实标题。", "case-fact-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["fact"], "保存事实")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertCaseFact({ fact });
      await loadCaseWorkspace(fact.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveEvidence(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("evidence")) {
      return;
    }
    const evidence = {
      ...evidenceDraft,
      projectId: caseProjectDraft.projectId,
      evidenceNumber: evidenceDraft.evidenceNumber.trim(),
      title: evidenceDraft.title.trim(),
      formedOn: evidenceDraft.formedOn || null,
    };

    if (!evidence.evidenceNumber || !evidence.title) {
      showCaseValidationError(
        evidence.evidenceNumber
          ? "请输入证据标题。"
          : "请输入证据编号。",
        evidence.evidenceNumber
          ? "case-evidence-title"
          : "case-evidence-number",
      );
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["evidence"], "保存证据")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertEvidenceItem({ evidence });
      await loadCaseWorkspace(evidence.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveIssue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePersistedCaseWorkspace("legal_issue")) {
      return;
    }
    const issue = {
      ...issueDraft,
      projectId: caseProjectDraft.projectId,
      title: issueDraft.title.trim(),
    };

    if (!issue.title) {
      showCaseValidationError("请输入争点标题。", "case-issue-title");
      return;
    }
    clearCaseValidationError();
    if (blockWorkspaceReloadForDirtyDrafts(["legal_issue"], "保存争点")) {
      return;
    }
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertLegalIssue({ issue });
      await loadCaseWorkspace(issue.projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function saveLegalBasis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!requirePersistedCaseWorkspace()) {
      return;
    }
    if (!basisSourceId.trim()) {
      showCaseValidationError("请选择本地法律来源。", "case-basis-source-id");
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(["legal_basis"], "添加法律依据")
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await addCaseLegalBasis({
        projectId,
        issueId: basisIssueId || null,
        sourceId: basisSourceId.trim(),
        caseDate: basisCaseDate || null,
        includeExpired: basisIncludeExpired,
        note: basisNote.trim(),
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setBasisSourceId("");
        setBasisNote("");
      }
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function linkEvidenceToFact() {
    if (!requirePersistedCaseWorkspace()) {
      return;
    }
    if (!linkFactId || !linkEvidenceId) {
      showCaseValidationError(
        linkFactId ? "请选择要关联的证据。" : "请选择要关联的事实。",
        linkFactId ? "case-link-evidence" : "case-link-fact",
      );
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(
        ["evidence_link"],
        "保存事实—证据关联",
      )
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertEvidenceLink({
        link: {
          linkId: createId("link"),
          projectId,
          factId: linkFactId,
          evidenceId: linkEvidenceId,
        },
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function linkFactToIssue() {
    if (!requirePersistedCaseWorkspace()) {
      return;
    }
    const validation = validateFactIssueLinkSelection(
      factIssueFactId,
      factIssueIssueId,
      caseWorkspace?.factIssueLinks ?? [],
    );
    if (!validation.valid) {
      showCaseValidationError(validation.message, validation.targetId);
      return;
    }
    clearCaseValidationError();
    if (
      blockWorkspaceReloadForDirtyDrafts(
        ["fact_issue_link"],
        "保存事实—争点关联",
      )
    ) {
      return;
    }
    const projectId = caseProjectDraft.projectId;
    const requestEpoch = beginCaseMutation();
    if (requestEpoch === null) {
      return;
    }

    try {
      await upsertFactIssueLink({
        link: {
          linkId: createId("fact-issue-link"),
          projectId,
          factId: factIssueFactId,
          issueId: factIssueIssueId,
        },
      });
      await loadCaseWorkspace(projectId, requestEpoch, true);
    } catch (error: unknown) {
      if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
        setCaseState({ kind: "error", message: errorMessage(error) });
      }
    } finally {
      finishCaseMutation();
    }
  }

  async function removeCaseEntity(
    entityType: DeletableCaseEntityType,
    id: string,
  ) {
    const editableEntityType =
      entityType === "file" ||
      entityType === "party" ||
      entityType === "fact" ||
      entityType === "evidence" ||
      entityType === "legal_issue"
        ? entityType
        : undefined;
    if (!requirePersistedCaseWorkspace(editableEntityType, id)) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "删除案件子项")) {
      return;
    }
    if (!caseWorkspace) {
      return;
    }
    await runConfirmedDestructiveAction(
      caseEntityDeletionConfirmation(
        entityType,
        caseEntityDeletionDisplayName(caseWorkspace, entityType, id),
      ),
      (message) => window.confirm(message),
      async () => {
        const projectId = caseProjectDraft.projectId;
        const requestEpoch = beginCaseMutation();
        if (requestEpoch === null) {
          return;
        }
        try {
          await deleteCaseEntity({ projectId, entityType, id });
          await loadCaseWorkspace(projectId, requestEpoch, true);
        } catch (error: unknown) {
          if (isCurrentCaseWorkspaceEpoch(caseWorkspaceEpoch, requestEpoch)) {
            setCaseState({ kind: "error", message: errorMessage(error) });
          }
        } finally {
          finishCaseMutation();
        }
      },
    );
  }

  async function runStructuredExtraction() {
    if (!caseChildrenReady || !caseWorkspace) {
      showCaseValidationError(
        "请先保存并成功加载案件，再开始整理材料信息。",
        "case-project-title",
      );
      return;
    }
    if (activeCaseEntityEditor !== null) {
      setCaseState({
        kind: "error",
        message: "请先保存或取消当前案件子项编辑，再开始整理材料信息。",
      });
      return;
    }
    if (!extractionProviderId) {
      showCaseValidationError(
        "请选择用于整理材料信息的模型服务。",
        "extraction-provider",
      );
      return;
    }
    if (extractionFileIds.length === 0) {
      setCaseState({
        kind: "error",
        message: "请先在案件材料列表勾选至少一份材料。",
      });
      return;
    }
    if (extractionSourcesLocked || caseInteractionIsLocked()) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "开始整理材料信息")) {
      return;
    }

    extractionLifecycleLock.current = true;
    clearCaseValidationError();
    extractionReviewReturnFocusRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    setExtractionDiscardError(null);
    beginExtractionDraftSaveSession();
    const context = createExtractionContext(
      createId("extraction-request"),
      caseWorkspace.project.projectId,
      extractionProviderId,
      extractionFileIds,
    );
    dispatchExtraction({ type: "start", context });
    try {
      const response = await generateStructuredCaseExtraction({
        projectId: context.projectId,
        providerId: context.providerId,
        fileIds: context.sourceFileIds,
      });
      if (
        response.result.status === "review_required" &&
        response.result.extraction &&
        structuredCaseExtractionIsPublic(response.result.extraction) &&
        response.result.reviewId &&
        response.providerSnapshot &&
        Number.isSafeInteger(response.reviewRevision) &&
        (response.reviewRevision ?? -1) >= 0
      ) {
        const reviewRevision = response.reviewRevision as number;
        beginExtractionDraftSaveSession(
          { kind: "saved", expiresAt: "" },
          reviewRevision,
        );
        dispatchExtraction({
          type: "generated",
          requestId: context.requestId,
          reviewId: response.result.reviewId,
          draft: response.result.extraction,
          revision: reviewRevision,
          repaired: response.result.repaired,
          providerSnapshot: response.providerSnapshot,
        });
      } else {
        extractionLifecycleLock.current = false;
        beginExtractionDraftSaveSession();
        dispatchExtraction({
          type: "failed",
          requestId: context.requestId,
          message:
            response.result.error?.message ??
            (response.result.status === "review_required"
              ? "待审阅结果无法安全载入，请重新加载案件后重试。"
              : "材料信息整理失败"),
          repairAttempted: response.result.repairAttempted,
          rawOutput: response.result.rawOutput,
          repairOutput: response.result.repairOutput,
        });
      }
    } catch (error: unknown) {
      extractionLifecycleLock.current = false;
      beginExtractionDraftSaveSession();
      dispatchExtraction({
        type: "failed",
        requestId: context.requestId,
        message: errorMessage(error),
        repairAttempted: false,
      });
    }
  }

  function updateExtractionDraft(
    update: (draft: StructuredCaseExtraction) => StructuredCaseExtraction,
  ) {
    if (
      extractionState.kind === "reviewing" &&
      !extractionReviewReloadRequired.current &&
      !extractionCloseInProgress.current &&
      !extractionConfirmInFlight.current &&
      !extractionDiscardInFlight.current
    ) {
      const draft = update(extractionState.draft);
      if (!structuredCaseExtractionIsPublic(draft)) {
        setCaseState({
          kind: "error",
          message: "该内容不适合写入案件业务字段，请删除其中的系统信息后重试。",
        });
        return;
      }
      dispatchExtraction({
        type: "edit",
        draft,
      });
      scheduleExtractionDraftSave({
        reviewId: extractionState.reviewId,
        projectId: extractionState.context.projectId,
        providerId: extractionState.context.providerId,
        fileIds: [...extractionState.context.sourceFileIds],
        extraction: draft,
      });
    }
  }

  async function cancelExtractionReview() {
    if (
      extractionState.kind !== "reviewing" ||
      extractionConfirmPreparing ||
      extractionConfirmInFlight.current ||
      extractionDiscardInFlight.current ||
      extractionCloseInProgress.current ||
      caseMutationLock.current ||
      extractionReviewReloadRequired.current
    ) {
      return;
    }

    const reviewId = extractionState.reviewId;
    const permission = await runConfirmedDestructiveAction(
      extractionReviewDiscardConfirmation(),
      (message) => window.confirm(message),
      async () => {
        if (
          extractionDiscardInFlight.current ||
          extractionConfirmInFlight.current ||
          extractionCloseInProgress.current
        ) {
          return false;
        }
        extractionDiscardInFlight.current = true;
        setExtractionDiscarding(true);
        setExtractionDiscardError(null);
        return true;
      },
    );
    if (!permission.executed || !permission.value) {
      return;
    }
    try {
      clearExtractionDraftSaveTimer();
      pendingExtractionDraftSave.current = null;
      await extractionDraftSavePromise.current;
      if (extractionReviewReloadRequired.current) {
        return;
      }
      const expectedRevision = extractionServerRevision.current;
      if (expectedRevision === null) {
        lockExtractionReviewForServerReload(
          "取消前无法确认待审草稿的最新状态。",
        );
        return;
      }
      const response = await discardStructuredCaseExtraction({
        reviewId,
        projectId: extractionState.context.projectId,
        expectedRevision,
      });
      if (!response.discarded) {
        lockExtractionReviewForServerReload(
          "草稿已被其他窗口更新或处理，取消结果未生效。",
        );
        return;
      }
      extractionLifecycleLock.current = false;
      beginExtractionDraftSaveSession();
      dispatchExtraction({ type: "cancel" });
      requestAnimationFrame(() => extractionReviewReturnFocusRef.current?.focus());
    } catch (error: unknown) {
      const message = errorMessage(error);
      lockExtractionReviewForServerReload(
        `取消请求的结果无法安全确认：${message}`,
      );
      setExtractionDiscardError(
        `取消结果不明确，不能继续操作该草稿：${message}`,
      );
      setCaseState({ kind: "error", message });
    } finally {
      extractionDiscardInFlight.current = false;
      setExtractionDiscarding(false);
    }
  }

  async function discardUnrestorablePendingReview() {
    const blocked = pendingReviewRecoveryBlock;
    if (!blocked || extractionDiscardInFlight.current) {
      return;
    }
    const permission = await runConfirmedDestructiveAction(
      unrestorableExtractionDiscardConfirmation(),
      (message) => window.confirm(message),
      async () => {
        if (
          extractionDiscardInFlight.current ||
          extractionConfirmInFlight.current ||
          extractionCloseInProgress.current
        ) {
          return false;
        }
        extractionDiscardInFlight.current = true;
        setExtractionDiscarding(true);
        return true;
      },
    );
    if (!permission.executed || !permission.value) {
      return;
    }
    try {
      const response = await discardStructuredCaseExtraction({
        reviewId: blocked.reviewId,
        projectId: blocked.projectId,
        expectedRevision: blocked.revision,
      });
      if (!response.discarded) {
        setPendingReviewRecoveryBlock({
          ...blocked,
          reloadRequired: true,
          message:
            "草稿已被其他窗口更新或处理，本窗口不能按旧内容放弃。",
        });
        return;
      }
      if (selectedCaseProjectIdRef.current === blocked.projectId) {
        setPendingReviewRecoveryBlock(null);
        setCaseWorkspaceWriteBlocked(false);
        setCaseState({ kind: "idle" });
      }
    } catch (error: unknown) {
      setPendingReviewRecoveryBlock({
        ...blocked,
        reloadRequired: true,
        message: `放弃请求的结果无法安全确认：${errorMessage(error)}`,
      });
      setCaseState({
        kind: "error",
        message: `无法放弃不兼容的抽取审阅：${errorMessage(error)}`,
      });
    } finally {
      extractionDiscardInFlight.current = false;
      setExtractionDiscarding(false);
    }
  }

  async function reloadServerExtractionDraft(projectId: string) {
    if (
      selectedCaseProjectIdRef.current !== projectId ||
      extractionDiscardInFlight.current ||
      extractionConfirmInFlight.current ||
      extractionConfirmPreparing
    ) {
      return;
    }
    const requestEpoch = beginCaseMutation(true);
    if (requestEpoch === null) {
      return;
    }

    extractionLifecycleLock.current = false;
    setExtractionDiscardError(null);
    setPendingReviewRecoveryBlock(null);
    beginExtractionDraftSaveSession();
    dispatchExtraction({ type: "reset" });
    try {
      await loadCaseWorkspace(projectId, requestEpoch);
    } finally {
      finishCaseMutation();
    }
  }

  function resetExtractionResult() {
    if (
      extractionState.kind === "failed" ||
      extractionState.kind === "committed"
    ) {
      extractionLifecycleLock.current = false;
      setExtractionDiscardError(null);
      beginExtractionDraftSaveSession();
      dispatchExtraction({ type: "reset" });
    }
  }

  async function confirmExtractionReview() {
    if (
      extractionConfirmPreparing ||
      extractionConfirmInFlight.current ||
      buildConfirmationRequest(extractionState) === null ||
      extractionDiscardInFlight.current ||
      extractionCloseInProgress.current ||
      extractionReviewReloadRequired.current
    ) {
      return;
    }
    if (blockWorkspaceReloadForDirtyDrafts([], "确认材料整理结果")) {
      return;
    }
    extractionConfirmInFlight.current = true;
    setExtractionConfirmPreparing(true);
    let mutationStarted = false;
    try {
      if (!(await flushPendingExtractionDraftSave())) {
        setCaseState({
          kind: "error",
          message:
            "审阅修改尚未安全保存，已阻止确认写入。请重试自动保存后再确认。",
        });
        return;
      }
      const confirmation = buildConfirmationRequest(extractionStateRef.current);
      if (!confirmation) {
        return;
      }
      const expectedRevision = extractionServerRevision.current;
      if (expectedRevision === null) {
        lockExtractionReviewForServerReload(
          "确认前无法确认待审草稿的最新状态。",
        );
        return;
      }
      confirmation.expectedRevision = expectedRevision;
      const requestEpoch = beginCaseMutation(true);
      if (requestEpoch === null) {
        return;
      }
      mutationStarted = true;
      setExtractionDiscardError(null);
      dispatchExtraction({ type: "begin_commit" });
      let response: Awaited<
        ReturnType<typeof confirmStructuredCaseExtraction>
      >;
      try {
        response = await confirmStructuredCaseExtraction(confirmation);
      } catch (error: unknown) {
        const message = errorMessage(error);
        dispatchExtraction({ type: "commit_failed", message });
        lockExtractionReviewForServerReload(
          `确认请求的结果无法安全确认：${message}`,
        );
        setCaseState({ kind: "error", message });
        return;
      }
      if (!response.applied) {
        const message = "当前无法确认写入结果。";
        dispatchExtraction({ type: "commit_failed", message });
        lockExtractionReviewForServerReload(message);
        return;
      }

      extractionLifecycleLock.current = false;
      beginExtractionDraftSaveSession();
      const workspaceReloaded = await loadCaseWorkspace(
        confirmation.projectId,
        requestEpoch,
        true,
      );
      dispatchExtraction({
        type: "committed",
        message: workspaceReloaded
          ? `已保存 ${response.counts.facts} 项事实、${response.counts.evidence} 项证据和 ${response.counts.uncertainties} 项待核实事项。`
          : "审阅结果已保存，但案件内容暂未刷新。为避免重复保存，确认按钮已停用，请重新加载当前案件。",
      });
      requestAnimationFrame(() => extractionReviewReturnFocusRef.current?.focus());
    } finally {
      if (mutationStarted) {
        finishCaseMutation();
      }
      extractionConfirmInFlight.current = false;
      setExtractionConfirmPreparing(false);
    }
  }

  function providerNavigationHasDirtyDraft(): boolean {
    return providerNavigationHasUnsavedChanges(
      providerDraftBaseline.current,
      providerDraft,
      apiKeyInput,
    );
  }

  function blockProviderNavigationForDirtyDraft(action: string): boolean {
    if (!providerNavigationHasDirtyDraft()) {
      return false;
    }
    setProviderState({
      kind: "error",
      message: `${action}会丢弃未保存的 Profile 或 API Key 输入。请先保存，或手动还原当前草稿。`,
    });
    return true;
  }

  function discardProviderDraftChanges() {
    setProviderDraft(providerDraftBaseline.current);
    setApiKeyInput("");
    setProviderState({ kind: "idle" });
  }

  function applyNewProviderDraft(kind: ProviderKind) {
    const profile = createProviderProfile(kind);
    setSelectedProviderId(null);
    setProviderDraft(profile);
    providerDraftBaseline.current = profile;
    setApiKeyInput("");
    setProviderState({ kind: "idle" });
  }

  function startNewProvider(kind: ProviderKind) {
    if (blockProviderNavigationForDirtyDraft("新建 Provider")) {
      return;
    }
    applyNewProviderDraft(kind);
  }

  function selectProvider(profile: ProviderProfile) {
    if (profile.id === selectedProviderId) {
      return;
    }
    if (blockProviderNavigationForDirtyDraft("切换 Provider")) {
      return;
    }
    setSelectedProviderId(profile.id);
    setProviderDraft(profile);
    providerDraftBaseline.current = profile;
    setApiKeyInput("");
    setProviderState({ kind: "idle" });
  }

  function updateProviderKind(kind: ProviderKind) {
    const defaults = providerDefaults(kind);
    setProviderDraft((current) => ({
      ...current,
      kind,
      displayName: defaults.displayName,
      modelId: defaults.modelId,
      baseUrl: defaults.baseUrl,
      capabilities: providerCapabilities(kind),
      options: defaultProviderOptions(kind),
    }));
  }

  function updateOptions(patch: Partial<ProviderOptions>) {
    setProviderDraft((current) => ({
      ...current,
      options: {
        ...current.options,
        ...patch,
      },
    }));
  }

  function clearProviderConnectionResult(profileId: string) {
    setConnectionResults((current) => {
      if (!(profileId in current)) {
        return current;
      }

      const next = { ...current };
      delete next[profileId];
      return next;
    });
  }

  async function saveProvider(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (providerMutationInFlight.current) {
      return;
    }
    const profile = normalizeProviderProfile(providerDraft);

    providerMutationInFlight.current = true;
    setProviderState({ kind: "loading" });

    try {
      const response = await upsertProviderProfile({ profile });
      setProviderProfiles((current) => {
        const others = current.filter((item) => item.id !== response.profile.id);
        return [response.profile, ...others];
      });
      setProviderDraft(response.profile);
      providerDraftBaseline.current = response.profile;
      setSelectedProviderId(response.profile.id);
      setExtractionProviderId((current) => current || response.profile.id);
      clearProviderConnectionResult(response.profile.id);
      await refreshKeyStatus(response.profile);
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    } finally {
      providerMutationInFlight.current = false;
    }
  }

  async function saveApiKey() {
    const profile = normalizeProviderProfile(providerDraft);
    const apiKey = apiKeyInput.trim();

    if (!apiKey) {
      return;
    }

    const save = async () => {
      if (providerMutationInFlight.current) {
        return;
      }
      providerMutationInFlight.current = true;
      setProviderState({ kind: "loading" });
      try {
        const response = await writeProviderApiKey({
          providerId: profile.id,
          accountId: profile.credentialAccountId,
          apiKey,
        });
        setKeyStatuses((current) => ({
          ...current,
          [profile.id]: response.status,
        }));
        clearProviderConnectionResult(profile.id);
        setApiKeyInput("");
        setProviderState({ kind: "idle" });
      } catch (error: unknown) {
        setProviderState({ kind: "error", message: errorMessage(error) });
      } finally {
        providerMutationInFlight.current = false;
      }
    };
    const savedProfile = providerProfiles.find((item) => item.id === profile.id);
    const keyStatus = providerKeyStatusForSavedDraft(
      savedProfile,
      profile,
      keyStatuses[profile.id],
    );
    if (!keyStatus) {
      setProviderState({
        kind: "error",
        message:
          "尚未可靠读取当前凭据状态，已阻止写入以免无提示覆盖旧 Key。请先重新保存 Profile 刷新状态。",
      });
      return;
    }
    if (keyStatus.configured) {
      await runConfirmedDestructiveAction(
        providerApiKeyOverwriteConfirmation(
          profile.displayName,
          profile.credentialAccountId,
        ),
        (message) => window.confirm(message),
        save,
      );
    } else {
      await save();
    }
  }

  async function removeApiKey() {
    const profile = normalizeProviderProfile(providerDraft);
    await runConfirmedDestructiveAction(
      providerApiKeyDeletionConfirmation(
        profile.displayName,
        profile.credentialAccountId,
      ),
      (message) => window.confirm(message),
      async () => {
        if (providerMutationInFlight.current) {
          return;
        }
        providerMutationInFlight.current = true;
        setProviderState({ kind: "loading" });
        try {
          const response = await deleteProviderApiKey({
            providerId: profile.id,
            accountId: profile.credentialAccountId,
          });
          setKeyStatuses((current) => ({
            ...current,
            [profile.id]: response.status,
          }));
          clearProviderConnectionResult(profile.id);
          setProviderState({ kind: "idle" });
        } catch (error: unknown) {
          setProviderState({ kind: "error", message: errorMessage(error) });
        } finally {
          providerMutationInFlight.current = false;
        }
      },
    );
  }

  async function removeProvider() {
    if (blockProviderNavigationForDirtyDraft("删除 Provider")) {
      return;
    }
    const profileId = providerDraft.id;
    if (
      extractionSourcesLocked &&
      "context" in extractionState &&
      extractionState.context.providerId === profileId
    ) {
      setProviderState({
        kind: "error",
        message: "请先取消当前案件抽取审阅，再删除本轮使用的 Provider。",
      });
      return;
    }
    await runConfirmedDestructiveAction(
      providerDeletionConfirmation(
        providerDraft.displayName,
        providerDraft.credentialAccountId,
      ),
      (message) => window.confirm(message),
      async () => {
        if (providerMutationInFlight.current) {
          return;
        }
        providerMutationInFlight.current = true;
        setProviderState({ kind: "loading" });
        try {
          await deleteProviderProfile({ providerId: profileId });
          const remaining = providerProfiles.filter(
            (profile) => profile.id !== profileId,
          );
          setProviderProfiles(remaining);
          setKeyStatuses((current) => {
            const next = { ...current };
            delete next[profileId];
            return next;
          });
          setConnectionResults((current) => {
            const next = { ...current };
            delete next[profileId];
            return next;
          });
          setQaProviderId((current) =>
            current === profileId ? (remaining[0]?.id ?? "") : current,
          );

          if (remaining[0]) {
            setSelectedProviderId(remaining[0].id);
            setProviderDraft(remaining[0]);
            providerDraftBaseline.current = remaining[0];
            setExtractionProviderId((current) =>
              current === profileId ? remaining[0].id : current,
            );
          } else {
            setExtractionProviderId("");
            applyNewProviderDraft("deep_seek");
          }

          setProviderState({ kind: "idle" });
        } catch (error: unknown) {
          setProviderState({ kind: "error", message: errorMessage(error) });
        } finally {
          providerMutationInFlight.current = false;
        }
      },
    );
  }

  async function runProviderConnectionTest() {
    const profile = normalizeProviderProfile(providerDraft);
    setProviderState({ kind: "loading" });

    try {
      const response = await testProviderConnection({ providerId: profile.id });
      setConnectionResults((current) => ({
        ...current,
        [profile.id]: response.result,
      }));
      setProviderState({ kind: "idle" });
    } catch (error: unknown) {
      setProviderState({ kind: "error", message: errorMessage(error) });
    }
  }

  useEffect(() => {
    if (viewMode !== "cases" || !graphCaseTarget) return;
    const targetId = caseGraphNodeDomId(
      graphCaseTarget.sourceKind,
      graphCaseTarget.sourceId,
    );
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(targetId);
      target?.scrollIntoView({ behavior: "smooth", block: "center" });
      target?.focus({ preventScroll: true });
    });
    const clearHighlight = window.setTimeout(() => setGraphCaseTarget(null), 4000);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(clearHighlight);
    };
  }, [graphCaseTarget, viewMode]);

  const healthText =
    health.kind === "ready"
      ? formatHealthCheck(health.response)
      : health.kind === "error"
        ? health.message
        : "正在检查本地服务…";
  const normalizedProviderDraft = normalizeProviderProfile(providerDraft);
  const savedProviderProfile = providerProfiles.find(
    (profile) => profile.id === normalizedProviderDraft.id,
  );
  const providerIsSaved = savedProviderProfile !== undefined;
  const providerDraftIsDirty =
    savedProviderProfile !== undefined &&
    !providerProfilesEqual(savedProviderProfile, normalizedProviderDraft);
  const providerBusy = providerState.kind === "loading";
  const currentKeyStatus = providerKeyStatusForSavedDraft(
    savedProviderProfile,
    normalizedProviderDraft,
    keyStatuses[normalizedProviderDraft.id],
  );
  const currentConnectionResult = providerDraftIsDirty
    ? undefined
    : connectionResults[providerDraft.id];
  const providerHasKey = currentKeyStatus?.configured ?? false;
  const caseNavigationLocked =
    extractionSourcesLocked ||
    extractionDiscarding ||
    caseMutationInFlight ||
    caseState.kind === "loading";
  const caseProjectMutationLocked =
    caseNavigationLocked ||
    caseWorkspaceWriteBlocked ||
    activeCaseEntityEditor !== null;
  const caseChildrenReady =
    caseState.kind !== "loading" &&
    caseWorkspaceWritesAreSafe(
      caseWorkspace,
      selectedCaseProjectId,
      caseProjectDraft.projectId,
      caseWorkspaceWriteBlocked,
    );
  const editingFile = caseEntityEditorMatches(activeCaseEntityEditor, "file");
  const editingParty = caseEntityEditorMatches(activeCaseEntityEditor, "party");
  const editingFact = caseEntityEditorMatches(activeCaseEntityEditor, "fact");
  const editingEvidence = caseEntityEditorMatches(
    activeCaseEntityEditor,
    "evidence",
  );
  const editingIssue = caseEntityEditorMatches(
    activeCaseEntityEditor,
    "legal_issue",
  );
  const activeQaContext = qaAnswer?.context ?? qaContext;
  const selectedQaSource = resolveSelectedQaSource(
    activeQaContext,
    selectedQaSourceId,
  );
  const answeredQaQuestion = resolveLegalAnswerQuestion(
    qaAnswer?.context ?? null,
    qaSubmittedQuestion,
  );
  const answeredQaScope = qaAnswer
    ? [
        qaAnswer.context.query.lawNames.length > 0
          ? `法律：${qaAnswer.context.query.lawNames.join("、")}`
          : null,
        qaAnswer.context.query.articleNumbers.length > 0
          ? `条号：${qaAnswer.context.query.articleNumbers.join("、")}`
          : null,
        qaAnswer.context.query.keywords.length > 0
          ? `关键词：${qaAnswer.context.query.keywords.join("、")}`
          : null,
        qaAnswer.context.query.caseDate
          ? `案件日期：${qaAnswer.context.query.caseDate}`
          : null,
        qaAnswer.context.query.effectivenessLevels.length > 0
          ? `效力层级：${qaAnswer.context.query.effectivenessLevels.join("、")}`
          : null,
        qaAnswer.context.query.includeExpired ? "包含失效版本" : null,
      ]
        .filter((item): item is string => item !== null)
        .join("；")
    : "";
  const qaRequestLocked =
    qaState.kind === "loading" || isLegalAnswerStreamActive(qaStream);
  const paginatedCaseProjects = paginateCaseProjects(
    caseProjects,
    caseProjectPage,
  );
  const assistantActiveProject = selectedCaseProjectId
    ? caseProjects.find(
        (project) => project.projectId === selectedCaseProjectId,
      ) ?? null
    : null;
  const assistantProposalApplyBlockedReason =
    dirtyCaseDraftsForClose.current.length > 0
      ? "案件工作台仍有未保存草稿。请先保存或清空草稿，再确认写入助理建议。"
      : caseNavigationLocked || caseWorkspaceWriteBlocked
        ? "案件工作台正在处理其他操作或处于只读保护状态，请恢复后再确认写入。"
        : caseWorkspace?.project.projectId !== selectedCaseProjectId
          ? "当前案件工作区尚未完整加载，不能确认写入助理建议。"
          : null;
  const activeProductArea = VIEW_METADATA[viewMode].futureArea;

  function refreshCaseAfterAssistantProposal(projectId: string) {
    if (selectedCaseProjectIdRef.current !== projectId) return;
    const requestEpoch = advanceCaseWorkspaceEpoch(caseWorkspaceEpoch);
    void loadCaseWorkspace(projectId, requestEpoch, true);
  }

  function continueSelectedCaseInAssistant() {
    if (!assistantActiveProject) return;
    assistantCaseHandoffSequence.current += 1;
    setAssistantCaseHandoff({
      projectId: assistantActiveProject.projectId,
      title: assistantActiveProject.title,
      requestId: assistantCaseHandoffSequence.current,
    });
    setViewMode("assistant");
  }

  async function addSelectedArticleToAssistant() {
    if (
      !selectedArticle ||
      !assistantConversation ||
      legalSourceBridgeMutationActive.current
    ) {
      return;
    }
    legalSourceBridgeMutationActive.current = true;
    setLegalSourceBridgeState({ kind: "loading" });
    try {
      await addAssistantLegalSource({
        conversationId: assistantConversation.conversationId,
        sourceId: selectedArticle.citationId,
      });
      setAssistantRefreshKey((current) => current + 1);
      setLegalSourceBridgeState({
        kind: "success",
        message: `已加入助理会话“${publicTitle(assistantConversation.title, "助理会话")}”。`,
      });
    } catch (error: unknown) {
      setLegalSourceBridgeState({
        kind: "error",
        message: `加入助理会话失败：${errorMessage(error)}`,
      });
    } finally {
      legalSourceBridgeMutationActive.current = false;
    }
  }

  async function proposeSelectedArticleForCase() {
    if (
      !selectedArticle ||
      !assistantConversation ||
      !selectedCaseProjectId ||
      assistantConversation.projectId !== selectedCaseProjectId ||
      legalSourceBridgeMutationActive.current
    ) {
      return;
    }
    legalSourceBridgeMutationActive.current = true;
    setLegalSourceBridgeState({ kind: "loading" });
    try {
      await proposeAssistantLegalBasis({
        conversationId: assistantConversation.conversationId,
        projectId: selectedCaseProjectId,
        sourceId: selectedArticle.citationId,
      });
      setAssistantRefreshKey((current) => current + 1);
      setLegalSourceBridgeState({
        kind: "success",
        message: `已为案件“${assistantActiveProject?.title ?? "当前案件"}”生成待确认法律依据；请到助理右侧审阅，尚未写入案件。`,
      });
    } catch (error: unknown) {
      setLegalSourceBridgeState({
        kind: "error",
        message: `生成待确认法律依据失败：${errorMessage(error)}`,
      });
    } finally {
      legalSourceBridgeMutationActive.current = false;
    }
  }

  function navigateFromShell(nextView: ViewMode) {
    const mcpNavigation = decideMcpWorkspaceNavigation(
      viewMode,
      nextView,
      mcpMutationActive.current,
      mcpDraftDirty.current,
    );
    if (mcpNavigation.kind === "block") {
      setCloseProtectionMessage(mcpNavigation.message);
      return;
    }
    if (mcpNavigation.kind === "confirm_discard") {
      if (!window.confirm(mcpNavigation.message)) {
        setCloseProtectionMessage(
          "已取消切换；未保存的 MCP 设置仍保留在当前工作区。",
        );
        return;
      }
      // The MCP workspace is conditionally mounted. Once the user explicitly
      // approves discarding it there is no remaining draft for the global
      // close guard to protect after navigation unmounts the workspace.
      mcpDraftDirty.current = false;
    }
    const privacyNavigation = decidePrivacyWorkspaceNavigation(
      viewMode,
      nextView,
      privacyMutationActive.current,
      privacyDraftDirty.current,
    );
    if (privacyNavigation.kind === "block") {
      setCloseProtectionMessage(privacyNavigation.message);
      return;
    }
    if (privacyNavigation.kind === "confirm_discard") {
      if (!window.confirm(privacyNavigation.message)) {
        setCloseProtectionMessage(
          "已取消切换；未保存的隐私与本地 OCR 配置仍保留在当前工作区。",
        );
        return;
      }
      // PrivacyWorkspace is conditionally mounted. Once the user approves
      // discarding it, no stale dirty flag should remain in the close guard.
      privacyDraftDirty.current = false;
    }
    setCloseProtectionMessage(null);
    if (nextView === "graph") {
      if (selectedCaseProjectId) setGraphMode("case");
      else if (selectedDocument) {
        setGraphDocumentId(selectedDocument.documentId);
        setGraphMode("law");
      }
    }
    setViewMode(nextView);
  }

  return (
    <AppShell
      activeView={viewMode}
      status={{ kind: health.kind, text: healthText }}
      onNavigate={navigateFromShell}
    >

      {closeProtectionMessage ? (
        <p className="error-text" role="alert" aria-live="assertive">
          {closeProtectionMessage}
        </p>
      ) : null}

      {activeProductArea !== "legal-library" ? (
        <nav className="workspace-subnav" aria-label="当前产品区功能">
          {activeProductArea === "assistant" ? (
            <>
              <button
                aria-current={viewMode === "assistant" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("assistant")}
              >
                助理工作区
              </button>
              <button
                aria-current={viewMode === "qa" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("qa")}
              >
                兼容引用问答
              </button>
            </>
          ) : activeProductArea === "cases" ? (
            <>
              <button
                aria-current={viewMode === "cases" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("cases")}
              >
                案件工作台 β
              </button>
              <button
                aria-current={viewMode === "documents" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("documents")}
              >
                既有文书模板
              </button>
              <button
                aria-current={viewMode === "graph" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("graph")}
              >
                确定性图谱
              </button>
            </>
          ) : (
            <>
              <button
                aria-current={viewMode === "providers" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("providers")}
              >
                Provider 与凭据
              </button>
              <button
                aria-current={viewMode === "privacy" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("privacy")}
              >
                隐私与本地处理
              </button>
              <button
                aria-current={viewMode === "mcp" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("mcp")}
              >
                MCP 服务
              </button>
              <button
                aria-current={viewMode === "release" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("release")}
              >
                版本、备份与诊断
              </button>
            </>
          )}
        </nav>
      ) : null}

      <div className="assistant-workspace-host" hidden={viewMode !== "assistant"}>
        <AssistantWorkspace
          activeProject={assistantActiveProject}
          caseHandoff={assistantCaseHandoff}
          externalRefreshKey={assistantRefreshKey}
          providerProfiles={providerProfiles}
          proposalApplyBlockedReason={assistantProposalApplyBlockedReason}
          onCaseProposalApplied={refreshCaseAfterAssistantProposal}
          onConversationChange={handleAssistantConversationChange}
          onDraftDirtyChange={handleAssistantDraftDirtyChange}
          onMutationActivityChange={handleAssistantMutationActivityChange}
          onOpenProviderSettings={() => navigateFromShell("providers")}
          onRunActivityChange={handleAssistantRunActivityChange}
        />
      </div>

      {viewMode === "assistant" ? null : viewMode === "search" ? (
        <LegalLibraryWorkspace>
          <section className="query-band" aria-label="检索条件">
            <form className="search-form" onSubmit={submitSearch}>
              <label>
                <span>关键词</span>
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="法律名称、条文关键词"
                />
              </label>
              <label>
                <span>案件日期</span>
                <input
                  type="date"
                  value={caseDate}
                  onChange={(event) => setCaseDate(event.target.value)}
                />
              </label>
              <button type="submit">检索</button>
            </form>

            <div className="filter-row">
              <span>
                {selectedDocument
                  ? `当前法律：${selectedDocument.title}`
                  : "全部法律"}
              </span>
              {selectedDocument ? (
                <div className="command-row">
                  <button
                    type="button"
                    onClick={() => openLawGraph(selectedDocument.documentId)}
                  >
                    查看法律关系图
                  </button>
                  <button
                    type="button"
                    onClick={() => void clearDocumentFilter()}
                  >
                    清除筛选
                  </button>
                </div>
              ) : null}
            </div>
          </section>

          <section className="workspace-grid">
            <aside
              className="panel law-panel"
              aria-labelledby="law-panel-title"
            >
              <div className="panel-heading">
                <h2 id="law-panel-title">法律</h2>
                <span>{laws.length}</span>
              </div>
              {searchState.kind === "error" ? (
                <p className="error-text">{searchState.message}</p>
              ) : null}
              <div className="result-list">
                {laws.map((law) => (
                  <button
                    className={`law-item ${
                      selectedDocument?.documentId === law.documentId
                        ? "is-selected"
                        : ""
                    }`}
                    key={law.documentId}
                    type="button"
                    onClick={() => void loadDocumentContext(law)}
                  >
                    <span className="item-title">
                      {publicTitle(
                        law.title,
                        `${publicTitle(law.authorityName, "发布机关")}发布的${publicTitle(law.documentType, "法律文件")}`,
                      )}
                    </span>
                    <span className="item-meta">
                      {formatStatus(law.status)} · {law.authorityName}
                    </span>
                    <span className="item-summary">
                      内容摘要：{publicContentSummary(law.summary)}
                    </span>
                  </button>
                ))}
              </div>
            </aside>

            <section
              className="panel article-panel"
              aria-labelledby="article-title"
            >
              <div className="panel-heading">
                <h2 id="article-title">法条</h2>
                <span>
                  {searchState.kind === "loading" ? "检索中" : articles.length}
                </span>
              </div>
              <div className="article-list">
                {articles.map((article) => (
                  <button
                    className={`article-item ${
                      selectedArticleId === article.articleId
                        ? "is-selected"
                        : ""
                    }`}
                    key={article.articleId}
                    type="button"
                    onClick={() => void loadArticleDetail(article.articleId)}
                  >
                    <span className="item-title">
                      {formatArticleLabel(article)}
                    </span>
                    <span className="item-meta">
                      {formatStatus(article.versionStatus)} ·{" "}
                      {formatEffectiveWindow(
                        article.effectiveFrom,
                        article.effectiveTo,
                      )}
                    </span>
                    <span className="item-summary">
                      内容摘要：{publicContentSummary(article.snippet)}
                    </span>
                  </button>
                ))}
              </div>
            </section>

            <aside
              className="panel detail-panel"
              aria-labelledby="detail-title"
            >
              <div className="panel-heading">
                <h2 id="detail-title">详情</h2>
                <span>{detailState.kind === "loading" ? "读取中" : "本地"}</span>
              </div>

              {detailState.kind === "error" ? (
                <p className="error-text">{detailState.message}</p>
              ) : null}

              {selectedArticle ? (
                <article className="article-detail">
                  <p className="detail-kicker">
                    {selectedArticle.canonicalLabel}
                  </p>
                  <h3>{formatArticleLabel(selectedArticle)}</h3>
                  <p className="article-content">{selectedArticle.content}</p>
                  <div className="command-row">
                    <button
                      disabled={
                        !assistantConversation ||
                        legalSourceBridgeState.kind === "loading"
                      }
                      type="button"
                      onClick={() => void addSelectedArticleToAssistant()}
                    >
                      {legalSourceBridgeState.kind === "loading"
                        ? "正在加入…"
                        : "加入当前助理会话"}
                    </button>
                    <button
                      disabled={
                        !assistantConversation ||
                        !selectedCaseProjectId ||
                        assistantConversation.projectId !== selectedCaseProjectId ||
                        legalSourceBridgeState.kind === "loading"
                      }
                      type="button"
                      onClick={() => void proposeSelectedArticleForCase()}
                    >
                      加入当前案件（待确认）
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        assistantActiveProject
                          ? continueSelectedCaseInAssistant()
                          : navigateFromShell("assistant")
                      }
                    >
                      {assistantActiveProject ? "在案件助理中继续" : "打开助理"}
                    </button>
                  </div>
                  <p
                    className={
                      legalSourceBridgeState.kind === "error"
                        ? "error-text"
                        : "privacy-note"
                    }
                    role={
                      legalSourceBridgeState.kind === "error"
                        ? "alert"
                        : "status"
                    }
                  >
                    {legalSourceBridgeState.kind === "success" ||
                    legalSourceBridgeState.kind === "error"
                      ? legalSourceBridgeState.message
                      : assistantConversation
                        ? assistantActiveProject &&
                          assistantConversation.projectId !==
                            assistantActiveProject.projectId
                          ? `当前助理会话“${publicTitle(assistantConversation.title, "助理会话")}”未绑定所选案件；请先点“在案件助理中继续”，再返回生成待确认法律依据。`
                          : `目标会话：${publicTitle(assistantConversation.title, "助理会话")}`
                        : "请先在助理中创建或选择一个会话。"}
                  </p>
                  <dl className="meta-grid">
                    <div>
                      <dt>效力期间</dt>
                      <dd>
                        {formatEffectiveWindow(
                          selectedArticle.effectiveFrom,
                          selectedArticle.effectiveTo,
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>主题</dt>
                      <dd>
                        {selectedArticle.topics.length > 0
                          ? selectedArticle.topics.join("、")
                          : "未标注"}
                      </dd>
                    </div>
                  </dl>
                </article>
              ) : (
                <p className="empty-state">暂无法条详情</p>
              )}

              <section className="detail-section" aria-labelledby="version-title">
                <div className="section-heading">
                  <h3 id="version-title">版本</h3>
                  <span>
                    {documentState.kind === "loading"
                      ? "读取中"
                      : versions.length}
                  </span>
                </div>
                {documentState.kind === "error" ? (
                  <p className="error-text" role="alert">
                    法律版本或关系上下文加载失败：{documentState.message}
                  </p>
                ) : null}
                <div className="compact-list">
                  {versions.map((version) => (
                    <div className="compact-row" key={version.versionId}>
                      <strong>{version.versionLabel}</strong>
                      <span>
                        {formatStatus(version.status)} ·{" "}
                        {formatEffectiveWindow(
                          version.effectiveFrom,
                          version.effectiveTo,
                        )}
                      </span>
                      <span>{version.articleCount} 条</span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="detail-section" aria-labelledby="relation-title">
                <div className="section-heading">
                  <h3 id="relation-title">关系</h3>
                  <span>{relations.length}</span>
                </div>
                <div className="compact-list">
                  {relations.map((relation) => (
                    <div className="compact-row" key={relation.relationId}>
                      <strong>
                        {formatStatus(relation.relationType)} ·{" "}
                        {relation.toTitle}
                      </strong>
                      <span>
                        {sanitizePublicGeneratedText(
                          relation.description,
                          "关系说明暂不可用。",
                        )}
                      </span>
                      {relation.sourceReference ? <span>官方来源记录已保留</span> : null}
                    </div>
                  ))}
                </div>
              </section>
            </aside>
          </section>
        </LegalLibraryWorkspace>
      ) : viewMode === "qa" ? (
        <section className="qa-layout">
          <aside className="panel qa-control-panel" aria-labelledby="qa-control-title">
            <div className="panel-heading">
              <h2 id="qa-control-title">问题</h2>
              <span>{formatLegalAnswerStreamStatus(qaStream)}</span>
            </div>
            <form className="qa-form" onSubmit={submitLegalAnswer}>
              <p className="privacy-note">
                回答归属：
                {caseWorkspace && selectedCaseProjectId
                  ? publicTitle(caseWorkspace.project.title, "当前案件")
                  : "未选择已保存案件；可检索来源，但不能生成或保存回答"}
              </p>
              <fieldset
                className="qa-request-fields"
                disabled={qaRequestLocked}
              >
              <label>
                <span>法律问题</span>
                <textarea
                  value={qaQuestion}
                  onChange={(event) => setQaQuestion(event.target.value)}
                  placeholder="输入需要检索和回答的法律问题"
                />
              </label>
              <div className="form-grid">
                <label>
                  <span>法律名称</span>
                  <input
                    value={qaLawName}
                    onChange={(event) => setQaLawName(event.target.value)}
                    placeholder="如：民法典"
                  />
                </label>
                <label>
                  <span>条号</span>
                  <input
                    value={qaArticleNumber}
                    onChange={(event) => setQaArticleNumber(event.target.value)}
                    placeholder="如：第五百七十七条"
                  />
                </label>
              </div>
              <label>
                <span>关键词</span>
                <input
                  value={qaKeywords}
                  onChange={(event) => setQaKeywords(event.target.value)}
                  placeholder="空格、逗号或顿号分隔"
                />
              </label>
              <div className="form-grid">
                <label>
                  <span>案件日期</span>
                  <input
                    type="date"
                    value={qaCaseDate}
                    onChange={(event) => setQaCaseDate(event.target.value)}
                  />
                  <small>
                    留空按当前有效性检索；不会以立案/接案日期代替案件事实日期。
                  </small>
                </label>
                <label>
                  <span>Provider</span>
                  <select
                    value={qaProviderId}
                    onChange={(event) => setQaProviderId(event.target.value)}
                  >
                    <option value="">选择 Provider</option>
                    {providerProfiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.displayName}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <fieldset className="qa-effectiveness-filter">
                <legend>效力层级（可多选）</legend>
                <div className="toggle-row">
                  {EFFECTIVENESS_LEVEL_OPTIONS.map(([value, label]) => (
                    <label key={value}>
                      <input
                        type="checkbox"
                        checked={qaEffectivenessLevels.includes(value)}
                        onChange={(event) =>
                          setQaEffectivenessLevels((current) =>
                            event.target.checked
                              ? [...current, value]
                              : current.filter((level) => level !== value),
                          )
                        }
                      />
                      <span>{label}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={qaIncludeExpired}
                  onChange={(event) =>
                    setQaIncludeExpired(event.target.checked)
                  }
                />
                <span>包含失效版本</span>
              </label>
              </fieldset>
              <div className="command-row">
                <button
                  type="button"
                  disabled={qaRequestLocked}
                  onClick={() => void previewLegalAnswerContext()}
                >
                  本地检索来源
                </button>
                <button
                  type="submit"
                  disabled={!qaProviderId || qaRequestLocked}
                >
                  生成带引用回答
                </button>
                {isLegalAnswerStreamCancellable(qaStream) ? (
                  <button
                    type="button"
                    onClick={() => void cancelCurrentLegalAnswer()}
                  >
                    取消生成
                  </button>
                ) : null}
              </div>
            </form>
            {qaState.kind === "error" ? (
              <p className="error-text" role="alert">
                {qaState.message}
              </p>
            ) : null}
            {activeQaContext && activeQaContext.warnings.length > 0 ? (
              <div
                className="context-warning-list"
                role="status"
                aria-label="法律检索风险提示"
              >
                {activeQaContext.warnings.map((warning, index) => (
                  <p key={`${index}-${warning}`}>
                    {formatLegalContextWarning(warning)}
                  </p>
                ))}
              </div>
            ) : null}
            <section
              className="detail-section"
              aria-labelledby="qa-history-title"
            >
              <div className="section-heading">
                <h3 id="qa-history-title">当前案件问答历史</h3>
                <span>
                  {qaHistoryState.kind === "loading"
                    ? "读取中"
                    : qaHistoryRecords.length}
                </span>
              </div>
              {qaHistoryState.kind === "error" ? (
                <p className="error-text" role="alert">
                  历史回答读取失败：{qaHistoryState.message}
                </p>
              ) : null}
              <div className="qa-history-list">
                {qaHistoryRecords.map((record) => (
                  <button
                    className="qa-history-item"
                    disabled={qaRequestLocked}
                    key={record.recordId}
                    type="button"
                    aria-label={`恢复历史回答：${record.question}`}
                    onClick={() => restoreLegalAnswerRecord(record)}
                  >
                    <strong>{record.question}</strong>
                    <span>
                      保存于 {record.createdAt.replace("T", " ").replace("Z", "")}
                    </span>
                    <span>
                      {record.citationReport.validCount} 条法条依据
                      {record.citationReport.invalidCount > 0
                        ? ` · ${record.citationReport.invalidCount} 条需要核对`
                        : ""}
                    </span>
                  </button>
                ))}
                {selectedCaseProjectId &&
                qaHistoryState.kind !== "loading" &&
                qaHistoryRecords.length === 0 ? (
                  <p className="empty-state">当前案件暂无已保存回答</p>
                ) : null}
                {selectedCaseProjectId && qaHistoryHasMore ? (
                  <button
                    className="secondary-action"
                    disabled={
                      qaRequestLocked || qaHistoryState.kind === "loading"
                    }
                    type="button"
                    onClick={() =>
                      void refreshLegalAnswerHistory(
                        selectedCaseProjectId,
                        true,
                      )
                    }
                  >
                    {qaHistoryState.kind === "loading"
                      ? "正在读取…"
                      : "加载更早回答"}
                  </button>
                ) : null}
                {!selectedCaseProjectId ? (
                  <p className="empty-state">请先在案件工作台选择案件</p>
                ) : null}
              </div>
            </section>
            <section className="detail-section" aria-labelledby="qa-source-title">
              <div className="section-heading">
                <h3 id="qa-source-title">候选来源</h3>
                <span>{activeQaContext?.sources.length ?? 0}</span>
              </div>
              <div className="source-list">
                {activeQaContext?.sources.map((source) => (
                  <button
                    className={`source-item ${
                      selectedQaSource?.sourceId === source.sourceId
                        ? "is-selected"
                        : ""
                    }`}
                    key={source.sourceId}
                    type="button"
                    onClick={() => selectQaSource(source)}
                  >
                    <span className="item-title">
                      {formatLegalSourceLabel(source)}
                    </span>
                    <span className="item-meta">
                      {formatStatus(source.versionStatus)} ·{" "}
                      {formatEffectiveWindow(
                        source.effectiveFrom,
                        source.effectiveTo,
                      )}
                    </span>
                    <span className="item-summary">
                      内容摘要：{publicContentSummary(source.snippet)}
                    </span>
                  </button>
                ))}
                {activeQaContext && activeQaContext.sources.length === 0 ? (
                  <p className="empty-state">未找到本地候选来源</p>
                ) : null}
              </div>
            </section>
          </aside>

          <section className="panel qa-answer-panel" aria-labelledby="qa-answer-title">
            <div className="panel-heading">
              <h2 id="qa-answer-title">回答</h2>
              <span>
                {qaAnswer
                  ? `${qaAnswer.citationReport.validCount} 条法条依据`
                  : formatLegalAnswerStreamStatus(qaStream)}
              </span>
            </div>
            {answeredQaQuestion ? (
              <p className="answer-query" role="status">
                <strong>本次回答对应问题</strong>
                <span>{answeredQaQuestion}</span>
                {answeredQaScope ? (
                  <span className="answer-query-meta">{answeredQaScope}</span>
                ) : null}
              </p>
            ) : null}
            {qaStream.status === "error" || qaStream.status === "cancelled" ? (
              <p className="error-text">
                {qaStream.status === "cancelled"
                  ? "回答生成已取消。"
                  : publicErrorMessage(
                      qaStream.message,
                      "回答生成未完成，请重试。",
                    )}
              </p>
            ) : null}
            {qaAnswer ? (
              <>
                {qaAnswer.citationReport.unsupportedLegalConclusion ? (
                  <p className="risk-banner">
                    部分法律结论缺少可核对的法条依据，请补充依据后再使用。
                  </p>
                ) : !qaAnswer.citationReport.semanticSupportVerified ? (
                  <p className="risk-banner">
                    本回答依据本地法律资料生成，请结合案件事实逐条核对并由律师审定。
                  </p>
                ) : null}
                <article className="answer-box">
                  <p>
                    {segmentLegalAnswer(
                      qaAnswer.answer,
                      qaAnswer.citationReport.citations,
                    ).map((segment) =>
                      segment.kind === "text" ? (
                        <span key={segment.key}>
                          {sanitizePublicGeneratedText(segment.text, "")}
                        </span>
                      ) : citationHasTrustedSource(segment.citation) ? (
                        <button
                          className="answer-citation answer-citation--valid"
                          key={segment.key}
                          type="button"
                          title="打开本地法条原文"
                          onClick={() =>
                            setSelectedQaSourceId(
                              segment.citation.source!.sourceId,
                            )
                          }
                        >
                          {segment.text}
                        </button>
                      ) : (
                        <span
                          className="answer-citation answer-citation--invalid"
                          key={segment.key}
                          title={formatCitationInvalidReason(
                            segment.citation.reason,
                          )}
                        >
                          {segment.text}
                        </span>
                      ),
                    )}
                  </p>
                </article>
                <div className="answer-meta-row">
                  <span>{qaAnswer.recordId ? "回答已保存" : "本次回答尚未保存"}</span>
                </div>
                <section className="detail-section" aria-labelledby="qa-citation-title">
                  <div className="section-heading">
                    <h3 id="qa-citation-title">法律依据与案例引用表</h3>
                    <span>{formatCitationValidationSummary(qaAnswer.citationReport)}</span>
                  </div>
                  <p className="validation-scope-note">
                    以下列明本回答采用的法律依据；适用结论仍应结合案件事实由律师审定。
                  </p>
                  <div className="citation-list">
                    {qaAnswer.citationReport.citations.map((citation, index) => {
                      const key = `${citation.rawMarker}-${citation.sourceId}-${index}`;
                      const content = (
                        <>
                          <strong>
                            {citation.source
                              ? formatLegalSourceLabel(citation.source)
                              : `第 ${index + 1} 条依据`}
                          </strong>
                          <span>
                            {citation.status === "valid"
                              ? "查看法条原文"
                              : formatCitationInvalidReason(citation.reason)}
                          </span>
                        </>
                      );

                      return citationHasTrustedSource(citation) ? (
                        <button
                          className="citation-item citation-item--valid"
                          key={key}
                          type="button"
                          onClick={() =>
                            setSelectedQaSourceId(citation.source.sourceId)
                          }
                        >
                          {content}
                        </button>
                      ) : (
                        <div
                          className="citation-item citation-item--invalid"
                          key={key}
                        >
                          {content}
                        </div>
                      );
                    })}
                    {qaAnswer.citationReport.citations.length === 0 ? (
                      <p className="empty-state">本回答未列出法条或案例依据</p>
                    ) : null}
                  </div>
                </section>
              </>
            ) : qaStream.answer ? (
              <>
                <p className="risk-banner">
                  {qaStream.status === "finalizing"
                    ? "回答已保存，正在载入法条依据。"
                    : "回答正在生成，完成后将在此显示。"}
                </p>
              </>
            ) : (
              <p className="empty-state">
                先检索本地法律资料；完成模型服务和访问凭据设置后再生成回答。
              </p>
            )}
          </section>

          <aside className="panel qa-source-detail" aria-labelledby="qa-detail-title">
            <div className="panel-heading">
              <h2 id="qa-detail-title">本地原文</h2>
              <span>{selectedQaSource ? "可追溯" : "未选择"}</span>
            </div>
            {selectedQaSource ? (
              <article className="article-detail">
                <h3>{formatLegalSourceLabel(selectedQaSource)}</h3>
                <p className="article-content">{selectedQaSource.content}</p>
                <dl className="meta-grid">
                  <div>
                    <dt>版本</dt>
                    <dd>{selectedQaSource.versionLabel}</dd>
                  </div>
                  <div>
                    <dt>效力期间</dt>
                    <dd>
                      {formatEffectiveWindow(
                        selectedQaSource.effectiveFrom,
                        selectedQaSource.effectiveTo,
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>状态</dt>
                    <dd>{formatStatus(selectedQaSource.versionStatus)}</dd>
                  </div>
                </dl>
                <button
                  type="button"
                  onClick={() => openLawGraph(selectedQaSource.documentId)}
                >
                  查看该法律关系图
                </button>
              </article>
            ) : (
              <p className="empty-state">选择候选来源或有效引用查看原文</p>
            )}
          </aside>
        </section>
      ) : viewMode === "documents" ? (
        <Suspense fallback={<p className="empty-state">正在加载文书工作台…</p>}>
          <DocumentWorkspace
            projectId={selectedCaseProjectId}
            onOpenCitation={(citation) => void openDocumentCitation(citation)}
          />
        </Suspense>
      ) : viewMode === "graph" ? (
        <Suspense fallback={<p className="empty-state">正在加载关系图…</p>}>
          <GraphWorkspace
            documentId={graphDocumentId ?? selectedDocument?.documentId ?? null}
            mode={graphMode}
            projectId={selectedCaseProjectId}
            onModeChange={setGraphMode}
            onOpenNode={openGraphNode}
          />
        </Suspense>
      ) : viewMode === "privacy" ? (
        <SettingsWorkspace mode="privacy">
          <Suspense fallback={<p className="empty-state">正在加载隐私设置…</p>}>
            <PrivacyWorkspace
              onDraftDirtyChange={handlePrivacyDraftDirtyChange}
              onMutationActivityChange={handlePrivacyMutationActivityChange}
            />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "release" ? (
        <SettingsWorkspace mode="maintenance">
          <Suspense fallback={<p className="empty-state">正在加载版本信息…</p>}>
            <ReleaseWorkspace />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "mcp" ? (
        <SettingsWorkspace mode="mcp">
          <Suspense fallback={<p className="empty-state">正在加载 MCP 服务设置…</p>}>
            <McpWorkspace
              onDraftDirtyChange={handleMcpDraftDirtyChange}
              onMutationActivityChange={handleMcpMutationActivityChange}
            />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "cases" ? (
        <CasesWorkspace busy={caseState.kind === "loading"}>
          <aside className="panel case-list-panel" aria-labelledby="case-list-title">
            <div className="panel-heading">
              <h2 id="case-list-title">案件项目</h2>
              <span>{caseProjects.length}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={caseNavigationLocked}
                type="button"
                onClick={startNewCaseProject}
              >
                新建案件
              </button>
            </div>
            <div className="provider-list">
              {paginatedCaseProjects.projects.map((project) => (
                <button
                  className={`provider-item ${
                    selectedCaseProjectId === project.projectId
                      ? "is-selected"
                      : ""
                  }`}
                  disabled={caseNavigationLocked}
                  key={project.projectId}
                  type="button"
                  onClick={() => selectCaseProject(project)}
                >
                  <span className="item-title">
                    {publicTitle(project.title, "未命名案件")}
                  </span>
                  <span className="item-meta">
                    {project.caseType || "未分类"} ·{" "}
                    {project.openedOn ?? "未登记日期"}
                  </span>
                  <span className="item-summary">
                    {publicCaseBusinessText(project.summary, "暂无案件摘要")}
                  </span>
                </button>
              ))}
              {caseProjects.length === 0 ? (
                <p className="empty-state">暂无案件项目</p>
              ) : null}
            </div>
            {caseProjects.length > 0 ? (
              <nav className="case-pagination" aria-label="案件列表分页">
                <button
                  disabled={
                    caseNavigationLocked || paginatedCaseProjects.page <= 1
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current - 1, caseProjects.length),
                    )
                  }
                >
                  上一页
                </button>
                <span aria-live="polite">
                  第 {paginatedCaseProjects.page} / {paginatedCaseProjects.totalPages} 页
                </span>
                <button
                  disabled={
                    caseNavigationLocked ||
                    paginatedCaseProjects.page >= paginatedCaseProjects.totalPages
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current + 1, caseProjects.length),
                    )
                  }
                >
                  下一页
                </button>
              </nav>
            ) : null}
          </aside>

          <section className="panel case-workbench-panel" aria-labelledby="case-workbench-title">
            <div className="panel-heading">
              <h2 id="case-workbench-title">案件工作台 β</h2>
              <span>{caseState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={!assistantActiveProject || caseNavigationLocked}
                type="button"
                onClick={continueSelectedCaseInAssistant}
              >
                在助理中继续
              </button>
            </div>
            <div className="case-scroll">
              {caseState.kind === "error" ? (
                <p
                  className="error-text"
                  id="case-workbench-error"
                  role="alert"
                  aria-live="assertive"
                >
                  {caseState.message}
                </p>
              ) : null}
              <form className="case-form" onSubmit={saveCaseProject}>
                <fieldset
                  className="case-entity-fields"
                  disabled={caseProjectMutationLocked}
                >
                <div className="form-grid">
                  <label>
                    <span>案件名称</span>
                    <input
                      id="case-project-title"
                      value={caseProjectDraft.title}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          title: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>案件类型</span>
                    <input
                      value={caseProjectDraft.caseType}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          caseType: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>立案/接案日期</span>
                    <input
                      type="date"
                      value={caseProjectDraft.openedOn ?? ""}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          openedOn: event.target.value || null,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>状态</span>
                    <select
                      value={caseProjectDraft.status}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          status: event.target.value as "active" | "archived",
                        }))
                      }
                    >
                      <option value="active">进行中</option>
                      <option value="archived">已归档</option>
                    </select>
                  </label>
                </div>
                <label>
                  <span>摘要</span>
                  <textarea
                    value={caseProjectDraft.summary}
                    onChange={(event) =>
                      setCaseProjectDraft((current) => ({
                        ...current,
                        summary: event.target.value,
                      }))
                    }
                  />
                </label>
                <div className="command-row">
                  <button disabled={caseProjectMutationLocked} type="submit">
                    保存案件
                  </button>
                  <button
                    disabled={
                      !selectedCaseProjectId || caseProjectMutationLocked
                    }
                    type="button"
                    onClick={() => void removeCaseProject()}
                  >
                    删除案件
                  </button>
                  <button
                    disabled={!selectedCaseProjectId || caseProjectMutationLocked}
                    type="button"
                    onClick={openCaseGraph}
                  >
                    查看案件关系图
                  </button>
                </div>
                </fieldset>
              </form>
              {!caseChildrenReady ? (
                <p className="privacy-note">
                  请先保存案件；保存成功后才能录入、关联或删除案件子项。
                </p>
              ) : null}

              <section className="case-section">
                <div className="section-heading">
                  <h3>案件材料</h3>
                  <span>{caseWorkspace?.files.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFile}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                    }
                  >
                  {editingFile ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的案件材料；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>标题</span>
                      <input
                        id="case-file-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-file-title"}
                        value={fileDraft.title}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>类型</span>
                      <input
                        value={fileDraft.fileType}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            fileType: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>材料摘要</span>
                    <textarea
                      value={fileDraft.summary}
                      onChange={(event) =>
                        setFileDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                      }
                      type="submit"
                    >
                      {editingFile ? "更新材料" : "添加材料"}
                    </button>
                    {editingFile ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.files.map((file) => (
                    <div className="compact-row" key={file.fileId}>
                      <label className="material-select">
                        <input
                          checked={extractionFileIds.includes(file.fileId)}
                          disabled={caseProjectMutationLocked}
                          type="checkbox"
                          onChange={(event) =>
                            setExtractionFileIds((current) =>
                              event.target.checked
                                ? [...current, file.fileId]
                                : current.filter(
                                    (fileId) => fileId !== file.fileId,
                                  ),
                            )
                          }
                        />
                        <strong>{publicTitle(file.title, "案件材料")}</strong>
                      </label>
                      <span>{publicTitle(file.fileType, "未分类")}</span>
                      <span>
                        {publicContentSummary(file.summary, "未填写材料摘要")}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "file", entity: file })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "file",
                            file.fileId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            extractionSourcesLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "file",
                              file.fileId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("file", file.fileId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>当事人</h3>
                  <span>{caseWorkspace?.parties.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveParty}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                    }
                  >
                  {editingParty ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的当事人；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>名称</span>
                      <input
                        id="case-party-name"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-party-name"}
                        value={partyDraft.name}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            name: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标准化名称</span>
                      <input
                        value={partyDraft.normalizedName}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            normalizedName: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>角色</span>
                      <select
                        value={partyDraft.role}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            role: event.target.value as PartyRole,
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </label>
                    <label>
                      <span>联系方式</span>
                      <input
                        value={partyDraft.contact}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            contact: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                      }
                      type="submit"
                    >
                      {editingParty ? "更新当事人" : "添加当事人"}
                    </button>
                    {editingParty ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.parties.map((party) => (
                    <div className="compact-row" key={party.partyId}>
                      <strong>{publicTitle(party.name, "案件当事人")}</strong>
                      <span>{formatPartyRole(party.role)}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "party",
                              entity: party,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "party",
                            party.partyId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "party",
                              party.partyId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("party", party.partyId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实时间线</h3>
                  <span>{caseWorkspace?.facts.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFact}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                    }
                  >
                  {editingFact ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的事实；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>日期</span>
                      <input
                        type="date"
                        value={factDraft.occurredOn ?? ""}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            occurredOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>事实标题</span>
                      <input
                        id="case-fact-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-fact-title"}
                        value={factDraft.title}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>状态</span>
                      <select
                        value={factDraft.confirmationStatus}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            confirmationStatus:
                              event.target.value as ConfirmationStatus,
                          }))
                        }
                      >
                        <option value="confirmed">已确认事实</option>
                        <option value="model_suggested">待审阅建议</option>
                      </select>
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={factDraft.source}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>事实描述</span>
                    <textarea
                      value={factDraft.description}
                      onChange={(event) =>
                        setFactDraft((current) => ({
                          ...current,
                          description: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                      }
                      type="submit"
                    >
                      {editingFact ? "更新事实" : "添加事实"}
                    </button>
                    {editingFact ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.facts.map((fact) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "case_fact" &&
                        graphCaseTarget.sourceId === fact.factId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("case_fact", fact.factId)}
                      key={fact.factId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(fact.title, "案件事实")}</strong>
                      <span>
                        {fact.occurredOn ?? "未登记日期"} ·{" "}
                        {formatConfirmationStatus(fact.confirmationStatus)}
                      </span>
                      <span>
                        {publicCaseBusinessText(
                          fact.description,
                          "未填写事实描述",
                        )}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "fact", entity: fact })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "fact",
                            fact.factId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "fact",
                              fact.factId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("fact", fact.factId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>证据目录</h3>
                  <span>{caseWorkspace?.evidence.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveEvidence}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                    }
                  >
                  {editingEvidence ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的证据；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>编号</span>
                      <input
                        id="case-evidence-number"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-number"
                        }
                        value={evidenceDraft.evidenceNumber}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            evidenceNumber: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标题</span>
                      <input
                        id="case-evidence-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-title"
                        }
                        value={evidenceDraft.title}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={evidenceDraft.source}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>形成日期</span>
                      <input
                        type="date"
                        value={evidenceDraft.formedOn ?? ""}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            formedOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>摘要</span>
                    <textarea
                      value={evidenceDraft.summary}
                      onChange={(event) =>
                        setEvidenceDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                      }
                      type="submit"
                    >
                      {editingEvidence ? "更新证据" : "添加证据"}
                    </button>
                    {editingEvidence ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.evidence.map((item) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "evidence_item" &&
                        graphCaseTarget.sourceId === item.evidenceId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("evidence_item", item.evidenceId)}
                      key={item.evidenceId}
                      tabIndex={-1}
                    >
                      <strong>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </strong>
                      <span>
                        {publicCaseBusinessText(item.source, "缺少来源")} ·{" "}
                        {item.formedOn ?? "缺少形成时间"}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "evidence",
                              entity: item,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "evidence",
                            item.evidenceId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "evidence",
                              item.evidenceId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence", item.evidenceId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实-证据关联</h3>
                  <span>{caseWorkspace?.evidenceLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    id="case-link-fact"
                    aria-label="要关联的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={caseValidationTargetId === "case-link-fact"}
                    disabled={caseProjectMutationLocked}
                    value={linkFactId}
                    onChange={(event) => setLinkFactId(event.target.value)}
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-link-evidence"
                    aria-label="要关联的证据"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-link-evidence"
                    }
                    disabled={caseProjectMutationLocked}
                    value={linkEvidenceId}
                    onChange={(event) => setLinkEvidenceId(event.target.value)}
                  >
                    <option value="">选择证据</option>
                    {caseWorkspace?.evidence.map((item) => (
                      <option key={item.evidenceId} value={item.evidenceId}>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkEvidenceToFact()}
                  >
                    关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.evidenceLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const evidence = caseWorkspace.evidence.find(
                      (item) => item.evidenceId === link.evidenceId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          {publicEvidenceNumber(
                            evidence?.evidenceNumber,
                            "相关证据",
                          )}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence_link", link.linkId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>争点与主张</h3>
                  <span>{caseWorkspace?.legalIssues.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveIssue}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(
                        activeCaseEntityEditor,
                        "legal_issue",
                      )
                    }
                  >
                  {editingIssue ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的争点；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>争点</span>
                      <input
                        id="case-issue-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-issue-title"}
                        value={issueDraft.title}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>处理状态</span>
                      <select
                        value={issueDraft.status}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            status: event.target.value as LegalIssueStatus,
                          }))
                        }
                      >
                        <option value="open">待处理</option>
                        <option value="resolved">已解决</option>
                      </select>
                    </label>
                  </div>
                  <label>
                    <span>主张</span>
                    <textarea
                      value={issueDraft.claim}
                      onChange={(event) =>
                        setIssueDraft((current) => ({
                          ...current,
                          claim: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(
                          activeCaseEntityEditor,
                          "legal_issue",
                        )
                      }
                      type="submit"
                    >
                      {editingIssue ? "更新争点" : "添加争点"}
                    </button>
                    {editingIssue ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalIssues.map((issue) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "legal_issue" &&
                        graphCaseTarget.sourceId === issue.issueId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("legal_issue", issue.issueId)}
                      key={issue.issueId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(issue.title, "相关法律争点")}</strong>
                      <span>{formatLegalIssueStatus(issue.status)}</span>
                      <span>{publicCaseBusinessText(issue.claim, "尚未填写主张")}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "legal_issue",
                              entity: issue,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "legal_issue",
                            issue.issueId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "legal_issue",
                              issue.issueId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_issue", issue.issueId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <div>
                    <h3>事实—争点关联</h3>
                    <p className="muted">
                      仅保存你手动建立的关联，不会自动推断。
                    </p>
                  </div>
                  <span>{caseWorkspace?.factIssueLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    id="case-fact-issue-fact"
                    aria-label="要关联到争点的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-fact"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueFactId}
                    onChange={(event) =>
                      setFactIssueFactId(event.target.value)
                    }
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-fact-issue-issue"
                    aria-label="要关联到事实的争点"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-issue"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueIssueId}
                    onChange={(event) =>
                      setFactIssueIssueId(event.target.value)
                    }
                  >
                    <option value="">选择争点</option>
                    {caseWorkspace?.legalIssues.map((issue) => (
                      <option key={issue.issueId} value={issue.issueId}>
                        {publicTitle(issue.title, "相关法律争点")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkFactToIssue()}
                  >
                    建立显式关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.factIssueLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const issue = caseWorkspace.legalIssues.find(
                      (item) => item.issueId === link.issueId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          争点：{publicTitle(issue?.title, "相关法律争点")}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity(
                              "fact_issue_link",
                              link.linkId,
                            )
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.factIssueLinks.length === 0 ? (
                    <p className="muted">尚未手动建立事实—争点关联。</p>
                  ) : null}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>法律依据</h3>
                  <span>{caseWorkspace?.legalBasis.length ?? 0}</span>
                </div>
                <form
                  className="case-form compact-case-form"
                  onSubmit={saveLegalBasis}
                >
                  <fieldset
                    className="case-entity-fields"
                    disabled={caseProjectMutationLocked}
                  >
                  <div className="form-grid">
                    <label>
                      <span>本地法律来源</span>
                      <select
                        id="case-basis-source-id"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-basis-source-id"
                        }
                        value={basisSourceId}
                        onChange={(event) => setBasisSourceId(event.target.value)}
                      >
                        <option value="">请选择已检索的法律来源</option>
                        {(activeQaContext?.sources ?? []).map((source) => (
                          <option key={source.sourceId} value={source.sourceId}>
                            {formatLegalSourceLabel(source)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>关联争点</span>
                      <select
                        value={basisIssueId}
                        onChange={(event) => setBasisIssueId(event.target.value)}
                      >
                        <option value="">不关联争点</option>
                        {caseWorkspace?.legalIssues.map((issue) => (
                          <option key={issue.issueId} value={issue.issueId}>
                            {publicTitle(issue.title, "相关法律争点")}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>案件日期</span>
                      <input
                        type="date"
                        value={basisCaseDate}
                        onChange={(event) => setBasisCaseDate(event.target.value)}
                      />
                      <small>
                        留空将按当前有效性校验，不会使用立案/接案日期代替。
                      </small>
                    </label>
                  </div>
                  <label>
                    <span>备注</span>
                    <textarea
                      value={basisNote}
                      onChange={(event) => setBasisNote(event.target.value)}
                    />
                  </label>
                  <div className="toggle-row">
                    <label>
                      <input
                        checked={basisIncludeExpired}
                        type="checkbox"
                        onChange={(event) =>
                          setBasisIncludeExpired(event.target.checked)
                        }
                      />
                      <span>允许已失效版本</span>
                    </label>
                  </div>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="submit"
                  >
                    添加依据
                  </button>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalBasis.map((basis, basisIndex) => {
                    const linkedIssue = caseWorkspace.legalIssues.find(
                      (issue) => issue.issueId === basis.issueId,
                    );
                    const isFirstBasisForSource =
                      caseWorkspace.legalBasis.findIndex(
                        (item) => item.sourceId === basis.sourceId,
                      ) === basisIndex;

                    return (
                      <div
                        className={`compact-row legal-basis-row legal-basis-row--${basis.status} ${
                          graphCaseTarget?.sourceKind === "verified_citation" &&
                          graphCaseTarget.sourceId === basis.sourceId
                            ? "graph-jump-target"
                            : ""
                        }`}
                        id={
                          isFirstBasisForSource
                            ? caseGraphNodeDomId("verified_citation", basis.sourceId)
                            : undefined
                        }
                        key={basis.basisId}
                        tabIndex={-1}
                      >
                        <strong>{formatLegalBasisTitle(basis)}</strong>
                        <span>
                          {formatLegalBasisStatus(basis.status)}
                          {basis.status === "invalid"
                            ? ` · ${formatLegalBasisInvalidReason(
                                basis.invalidReason,
                              )}`
                            : ""}{" "}
                          ·{" "}
                          {basis.versionStatus
                            ? formatStatus(basis.versionStatus)
                            : "未校验版本"}{" "}
                          · {formatLegalBasisWindow(basis)}
                        </span>
                        <span>
                          {linkedIssue
                            ? `争点：${publicTitle(linkedIssue.title, "相关法律争点")}`
                            : "未关联争点"}{" "}
                          · {basis.caseDate ?? "未指定案件日期"}
                        </span>
                        {basis.excerpt ? (
                          <span>内容摘要：{publicContentSummary(basis.excerpt)}</span>
                        ) : null}
                        {basis.note ? (
                          <span>
                            {sanitizePublicGeneratedText(
                              basis.note,
                              "补充说明暂不可用。",
                            )}
                          </span>
                        ) : null}
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_basis", basis.basisId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.legalBasis.length === 0 ? (
                    <p className="empty-state">暂无法律依据</p>
                  ) : null}
                </div>
              </section>
            </div>
          </section>

          <aside className="panel case-gap-panel" aria-labelledby="case-gap-title">
            <div className="panel-heading">
              <h2 id="case-gap-title">缺口分析</h2>
              <span>{caseWorkspace?.gaps.length ?? 0}</span>
            </div>
            <div className="compact-list">
              {caseWorkspace?.gaps.map((gap) => (
                <div className="compact-row" key={gap.gapId}>
                  <strong>
                    {formatGapSeverity(gap.severity)} · {formatGapKind(gap.kind)}
                  </strong>
                  <span>{gap.message}</span>
                </div>
              ))}
              {caseWorkspace && caseWorkspace.gaps.length === 0 ? (
                <p className="empty-state">当前没有证据缺口</p>
              ) : null}
            </div>

            <section className="provider-subsection">
              <h3>待核实事项</h3>
              <div className="compact-list extraction-uncertainty-list">
                {caseWorkspace?.uncertainties.map((uncertainty) => (
                  <div className="compact-row" key={uncertainty.uncertaintyId}>
                    <strong>
                      {publicCaseBusinessText(
                        uncertainty.description,
                        "相关事项需要核实",
                      )}
                    </strong>
                    <span>
                      {uncertainty.status === "open" ? "待核实" : "已解决"} ·{" "}
                      {formatConfirmationStatus(uncertainty.confirmationStatus)}
                    </span>
                    <button
                      disabled={
                        caseNavigationLocked ||
                        activeCaseEntityEditor !== null
                      }
                      type="button"
                      onClick={() =>
                        void removeCaseEntity(
                          "uncertainty",
                          uncertainty.uncertaintyId,
                        )
                      }
                    >
                      删除
                    </button>
                  </div>
                ))}
                {caseWorkspace && caseWorkspace.uncertainties.length === 0 ? (
                  <p className="empty-state">暂无独立待核实事项</p>
                ) : null}
              </div>
            </section>

            <section className="provider-subsection extraction-panel">
              <h3>材料信息整理</h3>
              <p className="privacy-note">
                仅处理已勾选材料的摘要，不会读取原始文件。整理结果须经你逐项审阅，确认前不会改动案件内容。
              </p>
              {pendingReviewRecoveryBlock?.projectId ===
              selectedCaseProjectId ? (
                <div className="risk-banner" role="alert">
                  <p>{pendingReviewRecoveryBlock.message}</p>
                  <button
                    disabled={extractionDiscarding || caseMutationInFlight}
                    type="button"
                    onClick={() =>
                      pendingReviewRecoveryBlock.reloadRequired
                        ? void reloadServerExtractionDraft(
                            pendingReviewRecoveryBlock.projectId,
                          )
                        : void discardUnrestorablePendingReview()
                    }
                  >
                    {pendingReviewRecoveryBlock.reloadRequired
                      ? caseMutationInFlight
                        ? "正在重新加载…"
                        : "重新加载最新草稿"
                      : extractionDiscarding
                        ? "正在放弃…"
                        : "放弃该待审阅草稿并解锁案件"}
                  </button>
                </div>
              ) : null}
              <label>
                <span>Provider</span>
                <select
                  id="extraction-provider"
                  aria-describedby="case-workbench-error"
                  aria-invalid={
                    caseValidationTargetId === "extraction-provider"
                  }
                  disabled={caseProjectMutationLocked}
                  value={extractionProviderId}
                  onChange={(event) =>
                    setExtractionProviderId(event.target.value)
                  }
                >
                  <option value="">选择已保存 Provider</option>
                  {providerProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.displayName} · {profile.modelId}
                    </option>
                  ))}
                </select>
              </label>
              <button
                disabled={
                  !caseChildrenReady ||
                  caseProjectMutationLocked ||
                  activeCaseEntityEditor !== null ||
                  extractionLocksSources(extractionState)
                }
                type="button"
                onClick={() => void runStructuredExtraction()}
              >
                {extractionState.kind === "generating"
                  ? "正在请求并严格校验…"
                  : `生成待审阅内容（已选 ${extractionFileIds.length} 份材料）`}
              </button>

              {extractionState.kind === "reviewing" ||
              extractionState.kind === "committing" ? (
                <div
                  className="extraction-review"
                  role="region"
                  aria-labelledby="extraction-review-title"
                  aria-describedby="extraction-review-description"
                  onKeyDown={(event) => {
                    if (
                      event.key === "Escape" &&
                      extractionState.kind === "reviewing" &&
                      !extractionConfirmPreparing &&
                      !extractionDiscarding &&
                      !extractionReviewReloadRequired.current
                    ) {
                      event.preventDefault();
                      void cancelExtractionReview();
                    }
                  }}
                  ref={extractionReviewRef}
                  tabIndex={-1}
                >
                  <div className="review-banner" aria-live="polite">
                    <strong id="extraction-review-title">
                      待审阅整理结果，尚未保存
                    </strong>
                    <span>
                      <span id="extraction-review-description" className="sr-only">
                        请逐项审阅整理结果。按 Escape 可取消且不会保存。
                      </span>
                      {extractionState.restored
                        ? `已从本地恢复待审阅草稿（创建于 ${extractionState.restoredCreatedAt ?? "未知时间"}，到期于 ${extractionState.restoredExpiresAt ?? "未知时间"}）。`
                        : extractionState.repaired
                          ? "初次结果未通过校验，系统已修正并重新校验。"
                          : "整理结果已通过系统校验。"}
                    </span>
                  </div>
                  <p
                    className={
                      extractionDraftSaveState.kind === "conflict"
                        ? "error-text"
                        : "privacy-note"
                    }
                    role={
                      extractionDraftSaveState.kind === "conflict"
                        ? "alert"
                        : "status"
                    }
                  >
                    {extractionDraftSaveState.kind === "pending"
                      ? "审阅修改等待自动保存…"
                      : extractionDraftSaveState.kind === "saving"
                        ? "正在保存审阅修改…"
                        : extractionDraftSaveState.kind === "saved"
                          ? `审阅修改已保存${
                              extractionDraftSaveState.expiresAt
                                ? `；草稿到期于 ${extractionDraftSaveState.expiresAt}`
                                : ""
                            }。`
                          : extractionDraftSaveState.kind === "conflict"
                            ? extractionDraftSaveState.message
                            : "模型原始建议已保存在本地；编辑后会自动保存。"}
                  </p>
                  {extractionDraftSaveState.kind === "conflict" ? (
                    <div className="risk-banner" role="alert">
                      <p>
                        为避免覆盖其他窗口或重复提交，必须放弃本窗口尚未确认的内容并重新读取最新草稿。
                      </p>
                      <button
                        disabled={caseMutationInFlight || extractionDiscarding}
                        type="button"
                        onClick={() =>
                          void reloadServerExtractionDraft(
                            extractionState.context.projectId,
                          )
                        }
                      >
                        {caseMutationInFlight
                          ? "正在重新加载…"
                          : "重新加载最新草稿"}
                      </button>
                    </div>
                  ) : null}

                  <fieldset
                    className="review-fields"
                    disabled={
                      extractionState.kind === "committing" ||
                      extractionConfirmPreparing ||
                      extractionDiscarding ||
                      extractionClosePreparing ||
                      extractionDraftSaveState.kind === "conflict"
                    }
                  >
                  <legend className="sr-only">材料信息审阅字段</legend>
                  <h4 id="extraction-parties-title">当事人</h4>
                  {extractionState.draft.parties.map((party, index) => (
                    <div
                      className="review-card"
                      key={`party-${index}`}
                      role="group"
                      aria-label={`建议当事人 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议当事人：{party.name || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议当事人 ${index + 1}`}
                        value={party.name}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, name: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <select
                        aria-label={`建议当事人 ${index + 1} 的角色`}
                        value={party.role}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    role: event.target.value as PartyRole,
                                  }
                                : item,
                            ),
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </div>
                  ))}

                  <h4 id="extraction-facts-title">事实</h4>
                  {extractionState.draft.facts.map((fact, index) => (
                    <div
                      className="review-card"
                      key={`fact-${index}`}
                      role="group"
                      aria-label={`建议事实 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议事实：{fact.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议事实 ${index + 1} 的发生日期`}
                        type="date"
                        value={fact.occurredOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    occurredOn: event.target.value || null,
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议事实 ${index + 1} 的标题`}
                        value={fact.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, title: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议事实 ${index + 1} 的描述`}
                        value={fact.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, description: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议事实 ${index + 1} 关联的证据编号，逗号分隔`}
                        value={fact.evidenceNumbers.join(", ")}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    evidenceNumbers: event.target.value
                                      .split(/[,，]/u)
                                      .map((value) => value.trim())
                                      .filter(Boolean),
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-evidence-title">证据</h4>
                  {extractionState.draft.evidence.map((item, index) => (
                    <div
                      className="review-card"
                      key={`evidence-${index}`}
                      role="group"
                      aria-label={`建议证据 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议证据：{item.evidenceNumber || item.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议证据 ${index + 1} 的编号`}
                        value={item.evidenceNumber}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    evidenceNumber: event.target.value,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的标题`}
                        value={item.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, title: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的来源`}
                        value={item.source}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, source: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的形成日期`}
                        type="date"
                        value={item.formedOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    formedOn: event.target.value || null,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议证据 ${index + 1} 的摘要`}
                        value={item.summary}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, summary: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-issues-title">争点与主张</h4>
                  {extractionState.draft.legalIssues.map((issue, index) => (
                    <div
                      className="review-card"
                      key={`issue-${index}`}
                      role="group"
                      aria-label={`建议争点 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议争点：{issue.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议争点 ${index + 1} 的标题`}
                        value={issue.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, title: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议争点 ${index + 1} 的描述`}
                        value={issue.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? {
                                      ...item,
                                      description: event.target.value,
                                    }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议争点 ${index + 1} 的主张`}
                        value={issue.claim}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, claim: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-uncertainties-title">待核实事项</h4>
                  {extractionState.draft.uncertainties.map(
                    (uncertainty, index) => (
                      <div
                        className="review-card"
                        key={`uncertainty-${index}`}
                        role="group"
                        aria-label={`建议待核实事项 ${index + 1}`}
                      >
                        <button
                          className="review-remove"
                          type="button"
                          onClick={() =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.filter(
                                (_, itemIndex) => itemIndex !== index,
                              ),
                            }))
                          }
                        >
                          移除建议待核实事项：{uncertainty.description || `第 ${index + 1} 项`}
                        </button>
                        <textarea
                          aria-label={`建议待核实事项 ${index + 1} 的描述`}
                          value={uncertainty.description}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        description: event.target.value,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                        <select
                          aria-label={`建议待核实事项 ${index + 1} 的关联实体类型`}
                          value={uncertainty.relatedEntityType}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedEntityType: event.target.value as typeof item.relatedEntityType,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        >
                          <option value="general">一般</option>
                          <option value="party">当事人</option>
                          <option value="fact">事实</option>
                          <option value="evidence">证据</option>
                          <option value="legal_issue">争点</option>
                        </select>
                        <input
                          aria-label={`建议待核实事项 ${index + 1} 的关联名称或编号`}
                          placeholder="关联名称/标题/证据编号（可空）"
                          value={uncertainty.relatedReference ?? ""}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedReference:
                                          event.target.value || null,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                      </div>
                    ),
                  )}
                  </fieldset>

                  {extractionState.kind === "reviewing" &&
                  extractionState.commitError ? (
                    <p className="error-text" role="alert">
                      {extractionState.commitError}
                    </p>
                  ) : null}
                  {extractionDiscardError ? (
                    <p className="error-text" role="alert">
                      {extractionDiscardError}
                    </p>
                  ) : null}

                  <div className="review-actions">
                    <button
                      className="secondary-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void cancelExtractionReview()}
                    >
                      {extractionDiscarding
                        ? "正在取消…"
                        : extractionClosePreparing
                          ? "正在保存并关闭…"
                          : "取消，不写入"}
                    </button>
                    <button
                      className="confirm-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void confirmExtractionReview()}
                    >
                      {extractionClosePreparing
                        ? "正在保存并关闭窗口…"
                        : extractionState.kind === "committing"
                        ? "正在保存审阅结果…"
                        : extractionConfirmPreparing
                          ? "正在保存并准备确认…"
                        : "确认并保存审阅结果"}
                    </button>
                  </div>
                </div>
              ) : null}

              {extractionState.kind === "failed" ? (
                <div className="extraction-failure">
                  <strong>
                    材料信息整理未完成：
                    {publicErrorMessage(
                      extractionState.message,
                      "请检查模型服务和网络后重试。",
                    )}
                  </strong>
                  <span>
                    {extractionState.repairAttempted
                      ? "系统已尝试修正，但结果仍未通过校验。"
                      : "模型服务或网络异常，未生成可审阅内容。"}
                  </span>
                  <button type="button" onClick={resetExtractionResult}>
                    关闭
                  </button>
                </div>
              ) : null}

              {extractionState.kind === "committed" ? (
                <div className="connection-summary">
                  <span className="status-dot status-dot--succeeded" />
                  <strong>审阅结果已写入案件。</strong>
                </div>
              ) : null}
            </section>
          </aside>
        </CasesWorkspace>
      ) : (
        <SettingsWorkspace mode="providers" busy={providerBusy}>
          <aside className="panel provider-list-panel" aria-labelledby="provider-list-title">
            <div className="panel-heading">
              <h2 id="provider-list-title">Profiles</h2>
              <span>{providerProfiles.length}</span>
            </div>
            <ProviderCreateMenu
              disabled={providerBusy}
              onCreate={startNewProvider}
            />
            <div className="provider-list">
              {providerProfiles.map((profile) => (
                <button
                  className={`provider-item ${
                    selectedProviderId === profile.id ? "is-selected" : ""
                  }`}
                  disabled={providerBusy}
                  key={profile.id}
                  type="button"
                  onClick={() => selectProvider(profile)}
                >
                  <span className="item-title">{profile.displayName}</span>
                  <span className="item-meta">
                    {formatProviderKind(profile.kind)} · {profile.modelId}
                  </span>
                  <span className="item-summary">
                    {formatKeyStatus(keyStatuses[profile.id])}
                  </span>
                </button>
              ))}
              {providerProfiles.length === 0 ? (
                <p className="empty-state">暂无 Provider profile</p>
              ) : null}
            </div>
          </aside>

          <section className="panel provider-editor-panel" aria-labelledby="provider-editor-title">
            <div className="panel-heading">
              <h2 id="provider-editor-title">Profile</h2>
              <span>{providerState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            {providerState.kind === "error" ? (
              <p className="error-text" role="alert">
                {providerState.message}
              </p>
            ) : null}

            <form className="provider-form" onSubmit={saveProvider}>
              <fieldset
                className="provider-profile-fields"
                disabled={providerBusy}
              >
                <legend className="sr-only">Provider Profile 配置</legend>
              {providerDraft.kind === "custom" ? (
                <p className="provider-custom-hint">
                  自定义提供商使用通用 OpenAI Chat Completions 协议。请填写 HTTPS
                  Base URL 和模型 ID；地址可以是 API 根路径，也可以直接以
                  /chat/completions 结尾。
                </p>
              ) : null}
              <div className="form-grid">
                <label>
                  <span>名称</span>
                  <input
                    placeholder={
                      providerDraft.kind === "custom"
                        ? "例如：公司模型网关"
                        : undefined
                    }
                    required
                    value={providerDraft.displayName}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        displayName: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>Provider</span>
                  <select
                    value={providerDraft.kind}
                    onChange={(event) =>
                      updateProviderKind(event.target.value as ProviderKind)
                    }
                  >
                    {SELECTABLE_PROVIDER_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {formatProviderKind(kind)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>模型 ID</span>
                  <input
                    placeholder={
                      providerDraft.kind === "custom"
                        ? "例如：my-chat-model"
                        : undefined
                    }
                    required
                    value={providerDraft.modelId}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        modelId: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>Base URL</span>
                  <input
                    placeholder={
                      providerDraft.kind === "custom"
                        ? "https://api.example.com/v1"
                        : undefined
                    }
                    required
                    value={providerDraft.baseUrl}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        baseUrl: event.target.value,
                      }))
                    }
                  />
                </label>
                <label>
                  <span>凭据账户</span>
                  <input
                    required
                    value={providerDraft.credentialAccountId}
                    onChange={(event) =>
                      setProviderDraft((current) => ({
                        ...current,
                        credentialAccountId: event.target.value,
                      }))
                    }
                  />
                </label>
                {providerDraft.kind === "volcengine_ark" ? (
                  <label>
                    <span>Endpoint ID（可覆盖模型 ID）</span>
                    <input
                      value={providerDraft.options.endpointId ?? ""}
                      onChange={(event) =>
                        updateOptions({ endpointId: event.target.value })
                      }
                    />
                  </label>
                ) : null}
                {providerDraft.kind === "qwen" ? (
                  <label>
                    <span>Workspace ID（用于 Base URL 占位符）</span>
                    <input
                      value={providerDraft.options.workspaceId ?? ""}
                      onChange={(event) =>
                        updateOptions({ workspaceId: event.target.value })
                      }
                    />
                  </label>
                ) : null}
                {providerDraft.kind === "deep_seek" ||
                providerDraft.kind === "volcengine_ark" ? (
                  <label>
                    <span>Reasoning effort</span>
                    <select
                      value={
                        providerDraft.kind === "deep_seek" &&
                        (providerDraft.options.reasoningEffort === "low" ||
                          providerDraft.options.reasoningEffort === "medium")
                          ? "high"
                          : (providerDraft.options.reasoningEffort ?? "")
                      }
                      onChange={(event) =>
                        updateOptions({
                          reasoningEffort:
                            event.target.value === ""
                              ? null
                              : (event.target.value as ReasoningEffort),
                        })
                      }
                    >
                      <option value="">未设置</option>
                      {providerDraft.kind === "volcengine_ark" ? (
                        <>
                          <option value="low">low</option>
                          <option value="medium">medium</option>
                        </>
                      ) : null}
                      <option value="high">high</option>
                      {providerDraft.kind === "deep_seek" ? (
                        <option value="max">max</option>
                      ) : null}
                    </select>
                  </label>
                ) : null}
                {providerDraft.kind === "qwen" ||
                providerDraft.kind === "silicon_flow" ? (
                  <label>
                    <span>Thinking budget</span>
                    <input
                      min={providerDraft.kind === "silicon_flow" ? 128 : 1}
                      max={
                        providerDraft.kind === "silicon_flow"
                          ? 32768
                          : undefined
                      }
                      type="number"
                      value={providerDraft.options.thinkingBudget ?? ""}
                      onChange={(event) =>
                        updateOptions({
                          thinkingBudget:
                            event.target.value === ""
                              ? null
                              : Number(event.target.value),
                        })
                      }
                    />
                  </label>
                ) : null}
              </div>

              <div className="toggle-row">
                {providerDraft.kind === "custom" ? (
                  <label className="provider-private-network-toggle">
                    <input
                      checked={
                        providerDraft.options.allowPrivateNetwork ?? false
                      }
                      type="checkbox"
                      onChange={(event) =>
                        updateOptions({
                          allowPrivateNetwork: event.target.checked,
                        })
                      }
                    />
                    <span>
                      我确认允许访问 localhost、私网或链路本地地址（高风险）
                    </span>
                  </label>
                ) : null}
                {providerDraft.kind === "qwen" ||
                providerDraft.kind === "silicon_flow" ? (
                  <label>
                    <input
                      checked={providerDraft.options.enableThinking ?? false}
                      type="checkbox"
                      onChange={(event) =>
                        updateOptions({ enableThinking: event.target.checked })
                      }
                    />
                    <span>enable_thinking</span>
                  </label>
                ) : null}
                {providerDraft.kind === "deep_seek" ||
                providerDraft.kind === "volcengine_ark" ? (
                  <label>
                    <input
                      checked={providerDraft.options.thinking ?? false}
                      type="checkbox"
                      onChange={(event) =>
                        updateOptions({ thinking: event.target.checked })
                      }
                    />
                    <span>thinking</span>
                  </label>
                ) : null}
              </div>
              {providerDraft.kind === "custom" &&
              providerDraft.options.allowPrivateNetwork ? (
                <p className="provider-risk-warning" role="alert">
                  高风险：该 Provider 可访问本机及内网服务。仅在你信任目标地址并确认不会形成服务端请求伪造通道时启用。
                </p>
              ) : null}
              </fieldset>

              <div className="command-row">
                <button disabled={providerBusy} type="submit">
                  保存 Profile
                </button>
                <button
                  disabled={providerBusy || !providerIsSaved}
                  type="button"
                  onClick={() => void removeProvider()}
                >
                  删除 Profile
                </button>
                <button
                  disabled={providerBusy || !providerNavigationHasDirtyDraft()}
                  type="button"
                  onClick={discardProviderDraftChanges}
                >
                  放弃未保存修改
                </button>
              </div>
            </form>
          </section>

          <aside className="panel provider-status-panel" aria-labelledby="provider-status-title">
            <div className="panel-heading">
              <h2 id="provider-status-title">凭据与连接</h2>
              <span>{formatKeyStatus(currentKeyStatus)}</span>
            </div>
            <section className="provider-subsection">
              <h3>API Key</h3>
              <label>
                <span>Key</span>
                <input
                  autoComplete="off"
                  disabled={providerBusy}
                  type="password"
                  value={apiKeyInput}
                  onChange={(event) => setApiKeyInput(event.target.value)}
                  placeholder="API Key"
                />
              </label>
              <div className="command-row">
                <button
                  disabled={
                    providerBusy ||
                    !providerIsSaved ||
                    providerDraftIsDirty ||
                    currentKeyStatus === undefined ||
                    apiKeyInput.trim().length === 0
                  }
                  type="button"
                  onClick={() => void saveApiKey()}
                >
                  保存 Key
                </button>
                <button
                  disabled={
                    providerBusy || providerDraftIsDirty || !providerHasKey
                  }
                  type="button"
                  onClick={() => void removeApiKey()}
                >
                  删除 Key
                </button>
              </div>
            </section>

            <section className="provider-subsection">
              <h3>测试连接</h3>
              <div className="connection-summary">
                <span
                  className={`status-dot status-dot--${
                    currentConnectionResult?.status ?? "idle"
                  }`}
                />
                <strong>{formatConnectionResult(currentConnectionResult)}</strong>
              </div>
              <dl className="meta-grid">
                <div>
                  <dt>HTTP</dt>
                  <dd>{formatHttpStatus(currentConnectionResult?.httpStatus)}</dd>
                </div>
                <div>
                  <dt>模型</dt>
                  <dd>{currentConnectionResult?.model ?? "未返回"}</dd>
                </div>
                <div>
                  <dt title="从发起请求到首个非空 SSE 内容或 reasoning token 到达；不按响应头、keep-alive 或空 delta 计时">
                    首个响应 token
                  </dt>
                  <dd>
                    {formatLatency(
                      currentConnectionResult?.firstTokenLatencyMs,
                    )}
                  </dd>
                </div>
                <div>
                  <dt>总耗时</dt>
                  <dd>{formatLatency(currentConnectionResult?.totalLatencyMs)}</dd>
                </div>
                <div>
                  <dt>错误类型</dt>
                  <dd>{currentConnectionResult?.errorType ?? "无"}</dd>
                </div>
              </dl>
              <button
                disabled={
                  providerBusy ||
                  !providerIsSaved ||
                  providerDraftIsDirty ||
                  !providerHasKey
                }
                type="button"
                onClick={() => void runProviderConnectionTest()}
              >
                测试连接
              </button>
            </section>
          </aside>
        </SettingsWorkspace>
      )}
    </AppShell>
  );
}
