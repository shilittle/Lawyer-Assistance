import type { DocumentCitation } from "../../ipc/document/types";
import type {
  CitationValidationReport,
  LawArticleDetail,
  LawSearchResult,
  LegalAnswerContext,
  LegalAnswerRecord,
  LegalAnswerResponse,
  LegalSource,
  ValidatedCitation,
} from "../../ipc/legal/types";

export interface QaFormDraft {
  question: string;
  lawName: string;
  articleNumber: string;
  keywords: string;
  caseDate: string;
  effectivenessLevels: string[];
  includeExpired: boolean;
}

interface MutableValue<T> {
  current: T;
}

export const LEGAL_ANSWER_HISTORY_PAGE_SIZE = 25;

export const DEFAULT_QA_FORM_DRAFT: Readonly<QaFormDraft> = {
  question: "",
  lawName: "",
  articleNumber: "",
  keywords: "",
  caseDate: "",
  effectivenessLevels: [],
  includeExpired: false,
};

export function copyQaFormDraft(
  draft: Readonly<QaFormDraft>,
): QaFormDraft {
  return { ...draft, effectivenessLevels: [...draft.effectivenessLevels] };
}

export function currentLawSearchCriteria(
  query: MutableValue<string>,
  caseDate: MutableValue<string>,
): { query: string; caseDate: string | null } {
  return {
    query: query.current.trim(),
    caseDate: caseDate.current || null,
  };
}

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

export function citationHasTrustedSource(
  citation: ValidatedCitation,
): citation is ValidatedCitation & {
  status: "valid";
  source: LegalSource;
} {
  return citation.status === "valid" && citation.source != null;
}

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

export function exactLawDocumentMatchesRequest(
  document: LawSearchResult | null | undefined,
  requestedDocumentId: string,
): document is LawSearchResult {
  return document != null && document.documentId === requestedDocumentId;
}

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

export function legalAnswerRequestStillOwnsCurrentCase(
  requestProjectId: string | null,
  selectedProjectId: string | null,
): boolean {
  return requestProjectId !== null && requestProjectId === selectedProjectId;
}

export function legalAnswerPreviewStillOwnsCurrentScope(
  requestProjectId: string | null,
  selectedProjectId: string | null,
): boolean {
  return requestProjectId === selectedProjectId;
}

export function mergeLegalAnswerHistory(
  current: readonly LegalAnswerRecord[],
  incoming: readonly LegalAnswerRecord[],
): LegalAnswerRecord[] {
  const records = new Map(current.map((record) => [record.recordId, record]));
  incoming.forEach((record) => records.set(record.recordId, record));
  return [...records.values()];
}

export function legalAnswerHistoryBelongsToProject(
  records: readonly LegalAnswerRecord[],
  projectId: string,
): boolean {
  return records.every((record) => record.projectId === projectId);
}

export function formatCitationValidationSummary(
  report: CitationValidationReport,
): string {
  if (
    report.citations.length === 0 ||
    report.validCount + report.invalidCount === 0
  ) {
    return "未列出法条依据";
  }
  return report.invalidCount > 0
    ? `${report.invalidCount} 条依据需要核对`
    : `${report.validCount} 条法条依据`;
}

export function formatLegalAnswerScope(
  answer: LegalAnswerResponse | null,
): string {
  if (!answer) {
    return "";
  }

  return [
    answer.context.query.lawNames.length > 0
      ? `法律：${answer.context.query.lawNames.join("、")}`
      : null,
    answer.context.query.articleNumbers.length > 0
      ? `条号：${answer.context.query.articleNumbers.join("、")}`
      : null,
    answer.context.query.keywords.length > 0
      ? `关键词：${answer.context.query.keywords.join("、")}`
      : null,
    answer.context.query.caseDate
      ? `案件日期：${answer.context.query.caseDate}`
      : null,
    answer.context.query.effectivenessLevels.length > 0
      ? `效力层级：${answer.context.query.effectivenessLevels.join("、")}`
      : null,
    answer.context.query.includeExpired ? "包含失效版本" : null,
  ]
    .filter((item): item is string => item !== null)
    .join("；");
}
