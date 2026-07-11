import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  confirmStructuredCaseExtraction,
  discardStructuredCaseExtraction,
  generateStructuredCaseExtraction,
} from "./client";
import type { StructuredCaseExtraction } from "./types";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const extraction: StructuredCaseExtraction = {
  parties: [{ name: "甲公司", role: "plaintiff" }],
  facts: [
    {
      occurredOn: "2026-01-02",
      title: "用户审阅后的事实",
      description: "审阅后的描述",
      evidenceNumbers: ["E-1"],
    },
  ],
  evidence: [
    {
      evidenceNumber: "E-1",
      title: "合同",
      source: "当事人提交",
      formedOn: null,
      summary: "合同摘要",
    },
  ],
  legalIssues: [{ title: "违约", description: "逾期", claim: "付款" }],
  uncertainties: [
    {
      description: "付款日期仍待核实",
      relatedEntityType: "fact",
      relatedReference: "用户审阅后的事实",
    },
  ],
};

describe("case extraction IPC client", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
    vi.mocked(invoke).mockResolvedValue({});
  });

  it("generates from selected IDs without sending keys or manual model output", async () => {
    await generateStructuredCaseExtraction({
      projectId: "case-1",
      providerId: "provider-1",
      fileIds: ["file-1"],
    });

    expect(invoke).toHaveBeenCalledWith("generate_structured_case_extraction", {
      request: {
        projectId: "case-1",
        providerId: "provider-1",
        fileIds: ["file-1"],
      },
    });
    const payload = JSON.stringify(vi.mocked(invoke).mock.calls[0]);
    expect(payload).not.toContain("apiKey");
    expect(payload).not.toContain("rawOutput");
    expect(payload).not.toContain("repairedOutput");
  });

  it("confirms the user-reviewed draft through the dedicated transaction command", async () => {
    await confirmStructuredCaseExtraction({
      reviewId: "review-1",
      projectId: "case-1",
      providerId: "provider-1",
      fileIds: ["file-1"],
      extraction,
      confirmed: true,
    });

    expect(invoke).toHaveBeenCalledWith("confirm_structured_case_extraction", {
      request: {
        reviewId: "review-1",
        projectId: "case-1",
        providerId: "provider-1",
        fileIds: ["file-1"],
        extraction,
        confirmed: true,
      },
    });
  });

  it("discards the server-side review token when the user cancels", async () => {
    await discardStructuredCaseExtraction({ reviewId: "review-1" });

    expect(invoke).toHaveBeenCalledWith("discard_structured_case_extraction", {
      request: { reviewId: "review-1" },
    });
  });
});
