import type {
  ArticleSearchResult,
  CitationInvalidReason,
  LawArticleDetail,
  LegalSource,
  ValidatedCitation,
} from "./types";
import { publicTitle } from "../../publicOutput";

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
    "documentTitle" | "articleNumber" | "articleTitle" | "effectiveFrom"
  >,
): string {
  const documentTitle = publicTitle(article.documentTitle, "法律文件");
  const articleNumber = publicTitle(article.articleNumber, "相关条文");
  const effectiveYear = /^(\d{4})/u.exec(article.effectiveFrom)?.[1];
  const effectiveLabel = effectiveYear ? `（${effectiveYear}年起施行）` : "";

  return `《${documentTitle}》${articleNumber}${effectiveLabel}`;
}

export function formatStatus(status: string): string {
  const labels: Record<string, string> = {
    in_force: "现行有效",
    repealed: "已废止",
    replaced_by: "被替代",
    replaces: "替代",
  };

  return labels[status] ?? "状态待核对";
}

export function formatLegalContextWarning(warning: string): string {
  if (warning.startsWith("source_truncated:")) {
    return "部分法条内容较长，回答将以当前显示内容为限。";
  }
  const labels: Record<string, string> = {
    ambiguous_law_article_pairing: "法律名称与条款对应关系不明确，请补充具体法律名称和条款。",
    inferred_law_name_filter_relaxed: "未按推测的法律名称找到结果，已改按问题关键词检索。",
    historical_effective_to_unknown_excluded: "部分历史版本缺少失效日期，已从候选资料中排除。",
    historical_effective_to_unknown_included_for_review:
      "部分历史版本的失效日期尚待核对，请谨慎适用。",
    no_local_sources_found: "未找到可用于回答的本地法律资料。",
    keyword_search_relaxed_for_exact_filters:
      "已优先按指定法律名称和条款检索，请核对候选资料。",
  };
  return labels[warning] ?? "请核对候选法律资料后再使用回答。";
}

export function formatLegalSourceLabel(source: LegalSource): string {
  const title = publicTitle(source.documentTitle, "法律文件");
  const locator = publicLawLocator(source);
  const effectiveYear = /^(\d{4})/u.exec(source.effectiveFrom)?.[1];
  if (!locator || !effectiveYear) {
    return formatArticleLabel(source);
  }
  return `《${title}》${locator}（${effectiveYear}年起施行）`;
}

function publicLawLocator(source: LegalSource): string | null {
  const articleEnd = source.articleNumber.indexOf("条");
  if (articleEnd < 0) return null;
  const article = source.articleNumber.slice(0, articleEnd + 1).trim();
  if (!article.startsWith("第") || [...article].length < 3) return null;
  const paragraph =
    explicitParagraphLabel(source.articleNumber.slice(articleEnd + 1)) ??
    explicitParagraphLabel(source.canonicalLabel) ??
    (sourceHasExactlyOneCompleteParagraph(source.content)
      ? "第一款"
      : null);
  return paragraph ? `${article}${paragraph}` : null;
}

function sourceHasExactlyOneCompleteParagraph(content: string): boolean {
  const trimmed = content.trim();
  if (
    !trimmed ||
    !trimmed.endsWith("。") ||
    trimmed.includes("\uFFFD") ||
    ["…", "...", "省略", "节选", "截断", "未完", "（略）", "[略]"].some(
      (marker) => trimmed.includes(marker),
    )
  ) {
    return false;
  }
  return (
    trimmed
      .split(/[\n\u2028\u2029]/u)
      .filter((paragraph) => paragraph.trim()).length === 1
  );
}

function explicitParagraphLabel(value: string): string | null {
  const paragraphEnd = value.indexOf("款");
  if (paragraphEnd < 0) return null;
  const before = value.slice(0, paragraphEnd + 1);
  const paragraphStart = before.lastIndexOf("第");
  if (paragraphStart < 0) return null;
  const label = before.slice(paragraphStart);
  return [...label].length >= 3 ? label : null;
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
    if (!citation.source) {
      return;
    }
    const publicCitation = formatLegalSourceLabel(citation.source);
    const citationIndexInAnswer = answer.indexOf(publicCitation, cursor);
    if (citationIndexInAnswer < 0) return;

    if (citationIndexInAnswer > cursor) {
      segments.push({
        kind: "text",
        key: `text-${cursor}-${citationIndexInAnswer}`,
        text: answer.slice(cursor, citationIndexInAnswer),
      });
    }

    const citationEnd = citationIndexInAnswer + publicCitation.length;
    segments.push({
      kind: "citation",
      key: `citation-${citationIndex}-${citationIndexInAnswer}`,
      text: answer.slice(citationIndexInAnswer, citationEnd),
      citation,
    });
    cursor = citationEnd;
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
