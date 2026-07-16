import type {
  ArticleSearchResult,
  CitationInvalidReason,
  LawArticleDetail,
  LegalSource,
  ValidatedCitation,
} from "./types";

export type LegalAnswerSegment =
  | { kind: "text"; key: string; text: string }
  | {
      kind: "citation";
      key: string;
      text: string;
      citation: ValidatedCitation;
    };

export function formatEffectiveWindow(
  effectiveFrom: string,
  effectiveTo?: string | null,
): string {
  return effectiveTo ? `${effectiveFrom} 至 ${effectiveTo}` : `${effectiveFrom} 起`;
}

export function formatArticleLabel(
  article: Pick<
    ArticleSearchResult | LawArticleDetail,
    "documentTitle" | "articleNumber" | "articleTitle"
  >,
): string {
  const suffix = article.articleTitle ? `：${article.articleTitle}` : "";

  return `《${article.documentTitle}》${article.articleNumber}${suffix}`;
}

export function formatStatus(status: string): string {
  const labels: Record<string, string> = {
    in_force: "现行有效",
    repealed: "已废止",
    replaced_by: "被替代",
    replaces: "替代",
  };

  return labels[status] ?? status;
}

export function formatLegalSourceLabel(source: LegalSource): string {
  const title = source.articleTitle ? `：${source.articleTitle}` : "";

  return `《${source.documentTitle}》${source.articleNumber}${title}`;
}

export function formatCitationInvalidReason(
  reason?: CitationInvalidReason | null,
): string {
  const labels: Record<CitationInvalidReason, string> = {
    invalid_syntax: "引用格式无效",
    duplicate: "重复引用",
    not_found: "本地库不存在",
    not_in_context: "未在本次候选来源中",
    version_mismatch: "法律版本不匹配",
    date_out_of_range: "不适用于案件日期",
    paragraph_not_found: "条文段落不存在",
  };

  return reason ? labels[reason] : "未知原因";
}

export function segmentLegalAnswer(
  answer: string,
  citations: ValidatedCitation[],
): LegalAnswerSegment[] {
  const segments: LegalAnswerSegment[] = [];
  let cursor = 0;

  citations.forEach((citation, citationIndex) => {
    const markerIndex = answer.indexOf(citation.rawMarker, cursor);
    if (markerIndex < 0) {
      return;
    }

    if (markerIndex > cursor) {
      segments.push({
        kind: "text",
        key: `text-${cursor}-${markerIndex}`,
        text: answer.slice(cursor, markerIndex),
      });
    }

    const markerEnd = markerIndex + citation.rawMarker.length;
    segments.push({
      kind: "citation",
      key: `citation-${citationIndex}-${markerIndex}`,
      text: answer.slice(markerIndex, markerEnd),
      citation,
    });
    cursor = markerEnd;
  });

  if (cursor < answer.length || segments.length === 0) {
    segments.push({
      kind: "text",
      key: `text-${cursor}-${answer.length}`,
      text: answer.slice(cursor),
    });
  }

  return segments;
}
