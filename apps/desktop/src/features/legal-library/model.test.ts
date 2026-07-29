import { describe, expect, it } from "vitest";

import type {
  LegalAnswerRecord,
  LegalAnswerResponse,
  LegalSource,
} from "../../ipc/legal/types";
import {
  copyQaFormDraft,
  formatLegalAnswerScope,
  legalAnswerContextFromRecord,
  legalAnswerHistoryBelongsToProject,
  legalAnswerPreviewStillOwnsCurrentScope,
  legalAnswerRequestStillOwnsCurrentCase,
  mergeLegalAnswerHistory,
  qaFormDraftFromLegalAnswerRecord,
} from "./model";

function source(sourceId: string): LegalSource {
  return {
    sourceId,
    articleId: `article-${sourceId}`,
    documentId: "civil-code",
    versionId: "civil-code-current",
    documentTitle: "中华人民共和国民法典",
    versionLabel: "现行版本",
    articleNumber: "第五百七十七条",
    articleTitle: null,
    canonicalLabel: "《中华人民共和国民法典》第五百七十七条",
    content: "当事人一方不履行合同义务的，应当承担违约责任。",
    snippet: "当事人一方不履行合同义务",
    effectiveFrom: "2021-01-01",
    effectiveTo: null,
    versionStatus: "in_force",
  };
}

function record(
  recordId: string,
  projectId = "case-1",
): LegalAnswerRecord {
  const legalSource = source(`source-${recordId}`);
  return {
    recordId,
    projectId,
    providerId: "provider-1",
    question: "合同违约责任如何承担？",
    answer: "应结合合同约定和法定责任核对。",
    query: {
      lawNames: ["民法典"],
      articleNumbers: ["第五百七十七条"],
      keywords: ["合同", "违约"],
      legalIssue: "合同违约责任如何承担？",
      caseDate: "2026-07-30",
      effectivenessLevels: ["law"],
      includeExpired: false,
    },
    sourceIds: [legalSource.sourceId],
    sources: [legalSource],
    missingSourceIds: [],
    citationReport: {
      citations: [],
      validCount: 0,
      invalidCount: 0,
      unsupportedLegalConclusion: false,
      semanticSupportVerified: false,
    },
    createdAt: "2026-07-30T10:00:00Z",
  };
}

describe("legal-library model", () => {
  it("restores an isolated QA draft and traceable context from history", () => {
    const saved = record("record-1");
    const draft = qaFormDraftFromLegalAnswerRecord(saved);
    const copied = copyQaFormDraft(draft);
    copied.effectivenessLevels.push("regulation");

    expect(draft).toEqual({
      question: saved.query.legalIssue,
      lawName: "民法典",
      articleNumber: "第五百七十七条",
      keywords: "合同、违约",
      caseDate: "2026-07-30",
      effectivenessLevels: ["law"],
      includeExpired: false,
    });
    expect(draft.effectivenessLevels).toEqual(["law"]);
    expect(legalAnswerContextFromRecord(saved)).toMatchObject({
      query: saved.query,
      sources: saved.sources,
      prompt: "",
    });
  });

  it("keeps request, preview, and history ownership fail-closed by case", () => {
    const first = record("record-1", "case-1");
    const second = record("record-2", "case-1");
    const foreign = record("record-3", "case-2");

    expect(legalAnswerRequestStillOwnsCurrentCase("case-1", "case-1")).toBe(
      true,
    );
    expect(legalAnswerRequestStillOwnsCurrentCase(null, "case-1")).toBe(false);
    expect(legalAnswerPreviewStillOwnsCurrentScope(null, null)).toBe(true);
    expect(legalAnswerPreviewStillOwnsCurrentScope("case-1", "case-2")).toBe(
      false,
    );
    expect(legalAnswerHistoryBelongsToProject([first, second], "case-1")).toBe(
      true,
    );
    expect(legalAnswerHistoryBelongsToProject([first, foreign], "case-1")).toBe(
      false,
    );
    expect(mergeLegalAnswerHistory([first], [first, second])).toEqual([
      first,
      second,
    ]);
  });

  it("formats the exact saved answer scope without inventing case facts", () => {
    const saved = record("record-1");
    const answer: LegalAnswerResponse = {
      providerId: saved.providerId,
      answer: saved.answer,
      context: legalAnswerContextFromRecord(saved),
      citationReport: saved.citationReport,
      recordId: saved.recordId,
    };

    expect(formatLegalAnswerScope(answer)).toBe(
      "法律：民法典；条号：第五百七十七条；关键词：合同、违约；案件日期：2026-07-30；效力层级：law",
    );
    expect(formatLegalAnswerScope(null)).toBe("");
  });
});
