import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  applyCaseRedactionRiskReviewAction,
  approveCaseRedactionReview,
  assignUnassignedCaseMaterial,
  deleteCaseRedactionReview,
  exportApprovedCaseRedaction,
  listCaseMaterials,
  listCaseRedactionGenerations,
  listUnassignedCaseMaterials,
  loadCaseRedactionReview,
  prepareCaseMaterial,
  redoCaseRedactionRiskReview,
  undoCaseRedactionRiskReview,
} from "./case-material-client";
import type {
  CaseRedactionReview,
  CaseRedactionRiskReviewState,
} from "./case-material-types";

describe("case material IPC", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses the fixed project-scoped command boundary for every operation", async () => {
    const projectId = "case-project-1";
    const materialId = "mat_1";
    const redactionId = "red_1";
    const editedPages = [{ pageNumber: 1, redactedText: "[姓名1]" }];

    await prepareCaseMaterial({ projectId, customTerms: ["内部代号"] });
    await listCaseMaterials({ projectId });
    await listUnassignedCaseMaterials({ projectId });
    await assignUnassignedCaseMaterial({
      projectId,
      materialId,
      expectedRowVersion: 2,
      actor: "reviewer",
    });
    await listCaseRedactionGenerations({ projectId, materialId });
    await loadCaseRedactionReview({ projectId, redactionId });
    await applyCaseRedactionRiskReviewAction({
      projectId,
      redactionId,
      expectedRevision: 3,
      actor: "reviewer",
      editedPages,
      action: { kind: "confirm_edited_output" },
    });
    await undoCaseRedactionRiskReview({
      projectId,
      redactionId,
      expectedRevision: 4,
    });
    await redoCaseRedactionRiskReview({
      projectId,
      redactionId,
      expectedRevision: 5,
    });
    await approveCaseRedactionReview({
      projectId,
      redactionId,
      expectedRiskRevision: 5,
      expectedSuggestedRedactedSha256: "a".repeat(64),
      editedPages,
      reviewer: "reviewer",
      destination: {
        kind: "verified_local_provider",
        identifier: "local-safe-pdf-export-v1",
      },
      purpose: "local_safe_pdf_export",
      ttlSeconds: 3600,
    });
    await exportApprovedCaseRedaction({
      projectId,
      redactionId,
      format: "pdf",
    });
    await deleteCaseRedactionReview({
      projectId,
      redactionId,
      expectedSourceSha256: "b".repeat(64),
      expectedExtractionSha256: "c".repeat(64),
    });

    const commands = invoke.mock.calls.map(([command]) => command);
    expect(commands).toEqual([
      "prepare_case_material",
      "list_case_materials",
      "list_unassigned_case_materials",
      "assign_unassigned_case_material",
      "list_case_redaction_generations",
      "load_case_redaction_review",
      "apply_case_redaction_risk_review_action",
      "undo_case_redaction_risk_review",
      "redo_case_redaction_risk_review",
      "approve_case_redaction_review",
      "export_approved_case_redaction",
      "delete_case_redaction_review",
    ]);
    for (const [, payload] of invoke.mock.calls) {
      expect(payload).toEqual({
        request: expect.objectContaining({ projectId }),
      });
    }
    const wire = JSON.stringify(invoke.mock.calls);
    expect(wire).not.toContain('"caseId"');
    expect(wire).not.toContain("privacyCaseId");
    expect(wire).not.toContain("vaultObjectId");
  });

  it("does not expose Privacy case identity even if a backend payload regresses", async () => {
    invoke.mockResolvedValue({
      projectId: "case-project-1",
      caseId: "forbidden-outer",
      privacyCaseId: "forbidden-explicit",
      riskReview: {
        case_id: "forbidden-snake",
        privacy_case_id: "forbidden-private-snake",
        revision: 1,
      },
    });

    const review = await loadCaseRedactionReview({
      projectId: "case-project-1",
      redactionId: "red_1",
    });
    expect(JSON.stringify(review)).not.toContain("forbidden");
    expect(review.projectId).toBe("case-project-1");

    const outerHasCaseId: "caseId" extends keyof CaseRedactionReview
      ? true
      : false = false;
    const outerHasPrivacyCaseId: "privacyCaseId" extends keyof CaseRedactionReview
      ? true
      : false = false;
    const riskHasCaseId: "caseId" extends keyof CaseRedactionRiskReviewState
      ? true
      : false = false;
    expect([
      outerHasCaseId,
      outerHasPrivacyCaseId,
      riskHasCaseId,
    ]).toEqual([false, false, false]);
  });
});
