import { describe, expect, it } from "vitest";

import {
  formatArticleLabel,
  formatCitationInvalidReason,
  formatEffectiveWindow,
  formatLegalSourceLabel,
  formatStatus,
} from "./format";

describe("legal IPC format helpers", () => {
  it("formats an open-ended effective window", () => {
    expect(formatEffectiveWindow("2021-01-01", null)).toBe("2021-01-01 起");
  });

  it("formats a bounded effective window", () => {
    expect(formatEffectiveWindow("1999-10-01", "2020-12-31")).toBe(
      "1999-10-01 至 2020-12-31",
    );
  });

  it("formats article labels with optional titles", () => {
    expect(
      formatArticleLabel({
        documentTitle: "中华人民共和国民法典",
        articleNumber: "第五百七十七条",
        articleTitle: "违约责任",
      }),
    ).toBe("《中华人民共和国民法典》第五百七十七条：违约责任");
  });

  it("maps known legal status values", () => {
    expect(formatStatus("in_force")).toBe("现行有效");
  });

  it("formats legal answer sources and invalid reasons", () => {
    expect(
      formatLegalSourceLabel({
        sourceId: "law:a:b:art:1",
        articleId: "article-1",
        documentId: "doc-1",
        versionId: "version-1",
        documentTitle: "中华人民共和国民法典",
        versionLabel: "2021年施行版本",
        articleNumber: "第五百七十七条",
        articleTitle: "违约责任",
        canonicalLabel: "《中华人民共和国民法典》第五百七十七条",
        content: "当事人一方不履行合同义务。",
        snippet: "不履行合同义务",
        effectiveFrom: "2021-01-01",
        effectiveTo: null,
        versionStatus: "in_force",
      }),
    ).toBe("《中华人民共和国民法典》第五百七十七条：违约责任");
    expect(formatCitationInvalidReason("not_in_context")).toBe(
      "未在本次候选来源中",
    );
  });
});
