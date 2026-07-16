import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  DocumentCitationList,
  formatDocumentFieldLabel,
  parseDocumentWorkspaceError,
} from "./DocumentWorkspace";
import type { DocumentCitation, GeneratedDocument } from "./ipc/document/types";

const CITATION: DocumentCitation = {
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
      message: "案件资料不完整，补齐下列必填字段后才能生成文书。",
      missingFields: ["plaintiff", "facts"],
      invalidCitationIds: [],
    });
    expect(formatDocumentFieldLabel("plaintiff")).toBe("原告信息");
    expect(formatDocumentFieldLabel("custom_field")).toBe("custom_field");
  });

  it("preserves a non-validation IPC type and readable message", () => {
    const problem = parseDocumentWorkspaceError(
      JSON.stringify({ errorType: "io", message: "目标文件不可写" }),
    );

    expect(problem).toMatchObject({
      errorType: "io",
      message: "目标文件不可写",
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
    expect(problem.message).toContain("补齐下列必填字段");
  });
});

describe("document citation traceability", () => {
  it("renders an exact local-law navigation action for every verified citation", () => {
    const markup = renderToStaticMarkup(
      <DocumentCitationList citations={[CITATION]} onOpenCitation={vi.fn()} />,
    );

    expect(markup).toContain("打开本地条文详情");
    expect(markup).toContain('data-document-id="document"');
    expect(markup).toContain('data-article-id="article-577"');
    expect(markup).toContain("law:document:version:art:577");
    expect(markup).toContain("中华人民共和国民法典");
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
