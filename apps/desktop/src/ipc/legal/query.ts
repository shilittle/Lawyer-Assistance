import type { LegalAnswerCandidatesRequest } from "./types";

export const EFFECTIVENESS_LEVEL_OPTIONS = [
  ["constitution", "宪法"],
  ["national_law", "法律"],
  ["supervision_regulation", "监察法规"],
  ["administrative_regulation", "行政法规"],
  ["judicial_interpretation", "司法解释"],
  ["department_rule", "部门规章"],
  ["local_regulation", "地方性法规"],
  ["local_government_rule", "地方政府规章"],
  ["autonomous_regulation", "自治条例/单行条例"],
  ["special_zone_regulation", "经济特区法规"],
  ["decision", "有关法律问题和重大问题的决定"],
  ["legal_document", "其他法律文件"],
] as const;

export interface LegalAnswerCandidateFormValues {
  question: string;
  lawName: string;
  articleNumber: string;
  keywords: string;
  caseDate: string;
  effectivenessLevels: string[];
  includeExpired: boolean;
  limit?: number;
}

export function buildLegalAnswerCandidateRequest(
  values: LegalAnswerCandidateFormValues,
): LegalAnswerCandidatesRequest {
  return {
    question: values.question.trim(),
    lawName: values.lawName.trim() || null,
    articleNumber: values.articleNumber.trim() || null,
    keywords: splitKeywords(values.keywords),
    caseDate: values.caseDate || null,
    effectivenessLevels: [
      ...new Set(
        values.effectivenessLevels
          .map((level) => level.trim())
          .filter(Boolean),
      ),
    ],
    includeExpired: values.includeExpired,
    limit: values.limit ?? 8,
  };
}

function splitKeywords(value: string): string[] {
  return value
    .split(/[\s,，、;；]+/u)
    .map((keyword) => keyword.trim())
    .filter(Boolean);
}
