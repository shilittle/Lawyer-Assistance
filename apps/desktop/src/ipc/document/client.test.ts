import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { exportDocumentPdf, previewDocument } from "./client";

describe("document IPC", () => {
  beforeEach(() => invoke.mockReset());

  it("keeps the reviewed seal and confirmation inside the typed export envelope", async () => {
    invoke.mockResolvedValue({
      cancelled: false,
      replayed: false,
      recordId: "r",
      fileName: "x.pdf",
      citationCount: 1,
    });
    await exportDocumentPdf({
      projectId: "p",
      templateId: "complaint",
      modelDraft: "draft",
      expectedRevision: "a".repeat(64),
      generationHash: "b".repeat(64),
      confirmed: true,
      idempotencyKey: "pdf-export-request-1",
    });
    expect(invoke).toHaveBeenCalledWith("export_document_pdf", {
      request: {
        projectId: "p",
        templateId: "complaint",
        modelDraft: "draft",
        expectedRevision: "a".repeat(64),
        generationHash: "b".repeat(64),
        confirmed: true,
        idempotencyKey: "pdf-export-request-1",
      },
    });
  });

  it("passes standalone material without requiring a project id", async () => {
    invoke.mockResolvedValue({
      document: { title: "独立律师函" },
      caseRevision: null,
      generationHash: "a".repeat(64),
    });
    const standaloneInput = {
      title: "独立律师函",
      partyA: "甲公司",
      partyB: "乙公司",
      facts: "已交货",
      requests: "支付货款",
      evidence: "合同",
      requirements: "正式简洁",
    };

    await previewDocument({
      projectId: null,
      standaloneInput,
      templateId: "lawyer_letter",
    });

    expect(invoke).toHaveBeenCalledWith("preview_document", {
      request: {
        projectId: null,
        standaloneInput,
        templateId: "lawyer_letter",
      },
    });
  });

  it("keeps the preview document and generation seal together", async () => {
    invoke.mockResolvedValue({
      document: { title: "t" },
      caseRevision: "a".repeat(64),
      generationHash: "b".repeat(64),
    });
    expect(
      (await previewDocument({ projectId: "p", templateId: "defence" }))
        .generationHash,
    ).toBe("b".repeat(64));
  });
});
