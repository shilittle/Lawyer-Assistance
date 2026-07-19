import { describe, expect, it } from "vitest";

import {
  formatArticleLabel,
  formatCitationInvalidReason,
  formatEffectiveWindow,
  formatLegalContextWarning,
  formatLegalSourceLabel,
  formatStatus,
  segmentLegalAnswer,
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
        effectiveFrom: "2021-01-01",
      }),
    ).toBe("《中华人民共和国民法典》第五百七十七条（2021年起施行）");
  });

  it("maps known legal status values", () => {
    expect(formatStatus("in_force")).toBe("现行有效");
    expect(formatLegalContextWarning("source_truncated:law:secret")).toBe(
      "部分法条内容较长，回答将以当前显示内容为限。",
    );
    expect(formatLegalContextWarning("future_internal_warning")).not.toContain(
      "future_internal_warning",
    );
  });

  it("formats legal answer sources and invalid reasons", () => {
    const source = {
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
      };
    expect(formatLegalSourceLabel(source)).toBe(
      "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）",
    );
    expect(
      formatLegalSourceLabel({
        ...source,
        content: "第一款内容。\n第二款内容。\n第三款内容。",
      }),
    ).toBe("《中华人民共和国民法典》第五百七十七条（2021年起施行）");
    for (const incomplete of [
      "一行摘要但不是完整条文",
      "条文内容节选。",
      "条文内容尚未完…",
      "第一款内容。\u2028第二款内容。",
    ]) {
      expect(formatLegalSourceLabel({ ...source, content: incomplete })).toBe(
        "《中华人民共和国民法典》第五百七十七条（2021年起施行）",
      );
    }
    expect(formatCitationInvalidReason("not_in_context")).toBe(
      "未在本次候选来源中",
    );
  });

  it("segments repeated citations without losing surrounding Unicode text", () => {
    const source = {
      sourceId: "law:doc:version:art:1",
      articleId: "article-1",
      documentId: "doc-1",
      versionId: "version-1",
      documentTitle: "中华人民共和国民法典",
      versionLabel: "2021年施行版本",
      articleNumber: "第一条",
      articleTitle: "",
      canonicalLabel: "《中华人民共和国民法典》第一条",
      content: "示例原文。",
      snippet: "示例原文",
      effectiveFrom: "2021-01-01",
      effectiveTo: null,
      versionStatus: "in_force",
    };
    const marker = "[SRC:law:doc:version:art:1]";
    const publicCitation = "《中华人民共和国民法典》第一条第一款（2021年起施行）";
    const answer = `结论一${publicCitation}；结论二${publicCitation}。`;
    const segments = segmentLegalAnswer(answer, [
      {
        rawMarker: marker,
        sourceId: source.sourceId,
        status: "valid",
        source,
      },
      {
        rawMarker: marker,
        sourceId: source.sourceId,
        status: "invalid",
        reason: "duplicate",
        source,
      },
    ]);

    expect(segments.map((segment) => segment.text).join("")).toBe(answer);
    expect(segments.map((segment) => segment.text).join("")).not.toContain("[SRC:");
    expect(segments.filter((segment) => segment.kind === "citation")).toHaveLength(
      2,
    );
    expect(new Set(segments.map((segment) => segment.key)).size).toBe(
      segments.length,
    );
  });
});
