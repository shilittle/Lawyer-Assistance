import { describe, expect, it, vi } from "vitest";

import type { UnassignedCaseMaterialSummary } from "../../../ipc/privacy/case-material-types";
import {
  buildUnassignedAssignmentRequest,
  CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION,
  caseMaterialsWorkspaceDraftIsDirty,
  executeConfirmedUnassignedAssignment,
  unassignedAssignmentConfirmation,
} from "./unassignedAssignment";

const material: UnassignedCaseMaterialSummary = {
  materialId: "mat_unassigned",
  displayName: "历史证据.pdf",
  mediaType: "application/pdf",
  sourceKind: "local_review",
  extractionStatus: "extracted_local",
  migrationStatus: "unassigned",
  state: "human_reviewed",
  generationCount: 1,
  historicalIdentity: "preserved",
  assignable: true,
  rowVersion: 7,
  updatedAt: "2026-07-30T13:00:00Z",
  deletedAt: null,
};

describe("unassigned material assignment", () => {
  it("uses the displayed current row version and explicit target project", () => {
    const request = buildUnassignedAssignmentRequest(
      "case-project-1",
      material,
      "  复核律师  ",
    );

    expect(request).toEqual({
      projectId: "case-project-1",
      materialId: "mat_unassigned",
      expectedRowVersion: 7,
      actor: "复核律师",
    });
    expect(
      unassignedAssignmentConfirmation(
        request,
        material.displayName,
      ),
    ).toContain("当前行版本 7");
    expect(JSON.stringify(request)).not.toContain("privacyCaseId");
    expect(JSON.stringify(request)).not.toContain("caseId");
  });

  it("fails before IPC when the actor is invalid or the backend marks the row unavailable", () => {
    expect(() =>
      buildUnassignedAssignmentRequest(
        "case-project-1",
        material,
        " ",
      ),
    ).toThrow("归属操作人必填");
    expect(() =>
      buildUnassignedAssignmentRequest(
        "case-project-1",
        { ...material, assignable: false },
        "复核律师",
      ),
    ).toThrow("后端已将该历史材料标记为不可归属");
  });

  it("protects actor input on route and window close without treating it as a material switch draft", () => {
    expect(caseMaterialsWorkspaceDraftIsDirty(false, "")).toBe(false);
    expect(
      caseMaterialsWorkspaceDraftIsDirty(false, "复核律师"),
    ).toBe(true);
    expect(caseMaterialsWorkspaceDraftIsDirty(true, "")).toBe(true);
  });

  it("asks for draft-discard authorization before assignment confirmation and commits only after both", async () => {
    const order: string[] = [];
    const commit = vi.fn();
    const outcome = await executeConfirmedUnassignedAssignment({
      authorizeContextChange: () => {
        order.push(CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION);
        return true;
      },
      confirmAssignment: () => {
        order.push(
          unassignedAssignmentConfirmation(
            buildUnassignedAssignmentRequest(
              "case-project-1",
              material,
              "复核律师",
            ),
            material.displayName,
          ),
        );
        return true;
      },
      execute: async () => {
        order.push("ipc");
        return "assigned";
      },
      commit,
    });

    expect(outcome).toEqual({
      kind: "assigned",
      value: "assigned",
    });
    expect(order[0]).toBe(
      CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION,
    );
    expect(order[1]).toContain("确认将“历史证据.pdf”明确归入案件");
    expect(order[2]).toBe("ipc");
    expect(commit).toHaveBeenCalledOnce();
  });

  it.each([
    ["draft switch", false, true, "context_cancelled"],
    ["assignment", true, false, "assignment_cancelled"],
  ])(
    "keeps state and performs zero IPC when %s confirmation is cancelled",
    async (
      _label,
      authorizeContext,
      confirmAssignment,
      expectedKind,
    ) => {
      const execute = vi.fn(async () => "assigned");
      const commit = vi.fn();
      const outcome =
        await executeConfirmedUnassignedAssignment({
          authorizeContextChange: () => authorizeContext,
          confirmAssignment: () => confirmAssignment,
          execute,
          commit,
        });

      expect(outcome.kind).toBe(expectedKind);
      expect(execute).not.toHaveBeenCalled();
      expect(commit).not.toHaveBeenCalled();
    },
  );

  it("does not commit a material switch when assignment or refresh fails", async () => {
    const commit = vi.fn();
    await expect(
      executeConfirmedUnassignedAssignment({
        authorizeContextChange: () => true,
        confirmAssignment: () => true,
        execute: async () => {
          throw new Error("stable_conflict");
        },
        commit,
      }),
    ).rejects.toThrow("stable_conflict");
    expect(commit).not.toHaveBeenCalled();
  });
});
