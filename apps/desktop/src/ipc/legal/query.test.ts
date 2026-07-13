import { describe, expect, it } from "vitest";

import { buildLegalAnswerCandidateRequest } from "./query";

describe("legal answer candidate query", () => {
  it("preserves multiple effectiveness levels and normalizes text fields", () => {
    const request = buildLegalAnswerCandidateRequest({
      question: "  合同责任如何承担？  ",
      lawName: " 民法典 ",
      articleNumber: " 第五百七十七条 ",
      keywords: "合同，责任 违约",
      caseDate: "2024-01-01",
      effectivenessLevels: [
        "national_law",
        "judicial_interpretation",
        "national_law",
      ],
      includeExpired: false,
    });

    expect(request).toEqual({
      question: "合同责任如何承担？",
      lawName: "民法典",
      articleNumber: "第五百七十七条",
      keywords: ["合同", "责任", "违约"],
      caseDate: "2024-01-01",
      effectivenessLevels: ["national_law", "judicial_interpretation"],
      includeExpired: false,
      limit: 8,
    });
  });
});
