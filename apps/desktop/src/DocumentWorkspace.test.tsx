import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  DocumentCitationList,
  LegalMarkdownPreview,
  formatDocumentCitationLabel,
  formatDocumentFieldLabel,
  parseDocumentWorkspaceError,
} from "./DocumentWorkspace";
import type { DocumentCitation, GeneratedDocument } from "./ipc/document/types";

const CITATION: DocumentCitation = {
  kind: "law",
  title: "中华人民共和国民法典",
  locator: "第五百七十七条第一款",
  effectiveOrDecidedOn: "2021-01-01",
  sourceId: "law:document:version:art:577",
  canonicalLabel: "《中华人民共和国民法典》第五百七十七条",
  excerpt: "不履行合同义务的一方应当承担违约责任。",
  documentId: "document",
  versionId: "version",
  articleId: "article-577",
};

describe("document workspace validation errors", () => {
  it("extracts a structured missing-field report from a Tauri IPC error", () => {
    const problem = parseDocumentWorkspaceError({
      errorType: "document_validation",
      message: JSON.stringify({
        code: "missing_required_fields",
        missingFields: ["plaintiff", "facts"],
        invalidCitationIds: [],
      }),
    });

    expect(problem).toEqual({
      errorType: "document_validation",
      message: "生成材料不完整，补齐下列内容后才能生成文书。",
      missingFields: ["plaintiff", "facts"],
      invalidCitationIds: [],
    });
    expect(formatDocumentFieldLabel("plaintiff")).toBe("原告信息");
    expect(formatDocumentFieldLabel("custom_field")).toBe("其他必填内容");
  });

  it("keeps non-validation IPC detail behind the public error boundary", () => {
    const problem = parseDocumentWorkspaceError(
      JSON.stringify({ errorType: "io", message: "目标文件不可写" }),
    );

    expect(problem).toMatchObject({
      errorType: "io",
      message: "文书操作失败，请重试。",
      missingFields: [],
      invalidCitationIds: [],
    });
  });

  it("also unwraps a serialized IPC error carried by Error.message", () => {
    const problem = parseDocumentWorkspaceError(
      new Error(
        JSON.stringify({
          errorType: "document_validation",
          message: JSON.stringify({
            code: "missing_required_fields",
            missingFields: ["valid_citations"],
            invalidCitationIds: [],
          }),
        }),
      ),
    );

    expect(problem.missingFields).toEqual(["valid_citations"]);
    expect(problem.message).toContain("补齐下列内容");
  });

  it("turns a case-backed complaint validation result into Chinese field labels", () => {
    const problem = parseDocumentWorkspaceError({
      errorType: "document_validation",
      message: JSON.stringify({
        code: "missing_required_fields",
        missingFields: ["claims", "facts"],
        invalidCitationIds: [],
      }),
    });

    const labels = problem.missingFields.map(formatDocumentFieldLabel);
    expect(problem.message).toBe("生成材料不完整，补齐下列内容后才能生成文书。");
    expect(labels).toEqual(["诉讼请求、答辩主张或办理要求", "案件事实"]);
    expect(`${problem.message}${labels.join("，")}`).not.toMatch(
      /missing_required_fields|claims|facts|document_validation/u,
    );
  });
});

describe("document citation traceability", () => {
  it("renders an exact local-law navigation action for every verified citation", () => {
    const markup = renderToStaticMarkup(
      <DocumentCitationList citations={[CITATION]} onOpenCitation={vi.fn()} />,
    );

    expect(markup).toContain("打开条文");
    expect(markup).toContain("内容摘要");
    expect(markup).not.toContain('data-document-id="document"');
    expect(markup).not.toContain('data-article-id="article-577"');
    expect(markup).not.toContain("law:document:version:art:577");
    expect(markup).toContain("《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）");
  });

  it("formats judicial-case references without exposing record identifiers", () => {
    expect(
      formatDocumentCitationLabel({
        ...CITATION,
        kind: "judicialCase",
        title: "某公司与某银行合同纠纷案",
        locator: "（2023）最高法民再88号",
        effectiveOrDecidedOn: "2024-06-03",
        canonicalLabel: "",
      }),
    ).toBe("某公司与某银行合同纠纷案（案号：（2023）最高法民再88号；2024年裁判）");
  });

  it("renders headings, lists, and GFM tables as semantic legal-document HTML", () => {
    const markup = renderToStaticMarkup(
      <LegalMarkdownPreview
        markdown={[
          "# 民事起诉状",
          "",
          "## 诉讼请求",
          "",
          "1. 判令被告支付货款。",
          "",
          "| 序号 | 证据名称 |",
          "| --- | --- |",
          "| 1 | 采购合同 |",
        ].join("\n")}
      />,
    );

    expect(markup).toContain("<h1>民事起诉状</h1>");
    expect(markup).toContain("<h2>诉讼请求</h2>");
    expect(markup).toContain("<ol>");
    expect(markup).toContain("<table>");
    expect(markup).toContain("<th>证据名称</th>");
    expect(markup).not.toContain("| --- | --- |");
  });

  it("keeps structured tables in the frontend document contract", () => {
    const document = {
      template: {
        templateId: "evidence_schedule",
        name: "证据目录",
        scenario: "整理证据",
        requiredFields: ["evidence"],
        optionalFields: [],
        citationPolicy: "仅使用有效引用",
        version: "2.0.0",
      },
      title: "证据目录",
      fields: [],
      sections: [],
      tables: [
        {
          sectionHeading: "证据目录",
          headers: ["序号", "证据名称"],
          columnWidthsDxa: [1_000, 8_360],
          rows: [{ cells: ["1", "合同"], sourceIds: ["evidence-1"] }],
          sourceIds: ["evidence-1"],
        },
      ],
      citations: [],
      markdown: "# 证据目录",
    } satisfies GeneratedDocument;

    expect(document.tables[0].rows[0].sourceIds).toEqual(["evidence-1"]);
  });
});
