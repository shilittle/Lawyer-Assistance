import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  CaseMaterialSummary,
  CaseRedactionGenerationSummary,
  UnassignedCaseMaterialSummary,
} from "../../../ipc/privacy/case-material-types";
import { ApprovedGenerationList } from "./ApprovedGenerationList";
import { CaseMaterialHistorySummary } from "./CaseMaterialHistorySummary";
import { CaseMaterialList } from "./CaseMaterialList";
import { CaseMaterialsWorkspace } from "./CaseMaterialsWorkspace";
import caseMaterialsWorkspaceSource from "./CaseMaterialsWorkspace.tsx?raw";
import {
  caseMaterialSelectionIsHistoryOnly,
  isCaseMaterialAvailable,
} from "./caseMaterialAvailability";
import { UnassignedCaseMaterialList } from "./UnassignedCaseMaterialList";

const material: CaseMaterialSummary = {
  projectId: "case-project-1",
  materialId: "mat_1",
  displayName: "起诉状.pdf",
  mediaType: "application/pdf",
  sourceKind: "vault",
  extractionStatus: "extracted_local",
  migrationStatus: "ready",
  state: "human_reviewed",
  latestReviewState: "approved",
  latestGenerationStatus: "ready",
  latestRevocationState: "active",
  generationCount: 2,
  updatedAt: "2026-07-30T12:00:00Z",
  deletedAt: null,
};

const generation: CaseRedactionGenerationSummary = {
  projectId: material.projectId,
  materialId: material.materialId,
  redactionId: "red_2",
  generationNumber: 2,
  generationStatus: "ready",
  reviewState: "approved",
  riskRevision: 4,
  approvedPayloadSha256: "a".repeat(64),
  approvedAt: "2026-07-30T12:00:00Z",
  revocationState: "active",
  revokedAt: null,
  createdAt: "2026-07-30T11:00:00Z",
};

describe("case materials catalog", () => {
  it("renders case material and approved generation state without a Privacy case identity", () => {
    const markup = renderToStaticMarkup(
      <>
        <CaseMaterialList
          materials={[material]}
          selectedMaterialId={material.materialId}
          busy={false}
          onSelect={vi.fn()}
        />
        <ApprovedGenerationList
          generations={[generation]}
          selectedRedactionId={generation.redactionId}
          busy={false}
          onSelect={vi.fn()}
        />
      </>,
    );

    expect(markup).toContain("起诉状.pdf");
    expect(markup).toContain("2 个脱敏代次");
    expect(markup).toContain("第 2 代");
    expect(markup).toContain("已批准");
    expect(markup).toContain("风险 revision 4");
    expect(markup).not.toContain("case_");
  });

  it("separates ready materials from blocked, legacy, and deleted migration issues", () => {
    const ready = { ...material, materialId: "mat_ready" };
    const blocked = {
      ...material,
      materialId: "mat_blocked",
      migrationStatus: "blocked",
      state: "blocked",
    };
    const legacy = {
      ...material,
      materialId: "mat_legacy",
      sourceKind: "legacy_reference",
      migrationStatus: "legacy_reference",
    };
    const deleted = {
      ...material,
      materialId: "mat_deleted",
      deletedAt: "2026-07-30T13:00:00Z",
    };
    const mixed = [blocked, legacy, deleted, ready];
    const markup = renderToStaticMarkup(
      <CaseMaterialList
        materials={mixed}
        selectedMaterialId={null}
        busy={false}
        onSelect={vi.fn()}
      />,
    );

    expect(markup).toContain("可用材料");
    expect(markup).toContain("只读历史与迁移问题");
    expect(markup).toContain("可选择查看安全摘要与版本历史");
    expect(markup).toContain("迁移：blocked");
    expect(markup).toContain("迁移：legacy_reference");
    expect(markup).toContain("已删除");
    expect(markup).not.toContain("disabled=\"\"");
    expect(mixed.filter(isCaseMaterialAvailable)).toEqual([ready]);
  });

  it("keeps revoked generations selectable as read-only version history without blocking the material", () => {
    const revokedMaterial = {
      ...material,
      latestReviewState: "revoked",
      latestGenerationStatus: "ready",
      latestRevocationState: "revoked",
    };
    const revokedGeneration = {
      ...generation,
      redactionId: "red_revoked",
      reviewState: "revoked",
      revocationState: "revoked",
      revokedAt: "2026-07-30T13:00:00Z",
    };
    const markup = renderToStaticMarkup(
      <>
        <CaseMaterialList
          materials={[revokedMaterial]}
          selectedMaterialId={revokedMaterial.materialId}
          busy={false}
          onSelect={vi.fn()}
        />
        <ApprovedGenerationList
          generations={[revokedGeneration]}
          selectedRedactionId={null}
          busy={false}
          onSelect={vi.fn()}
        />
      </>,
    );

    expect(isCaseMaterialAvailable(revokedMaterial)).toBe(true);
    expect(markup).toContain("已撤销");
    expect(markup).toContain("is-history-only");
    expect(markup).not.toContain("disabled=\"\"");
  });

  it("shows only returned summary metadata for historical records and no workbench action", () => {
    const deletedMaterial = {
      ...material,
      state: "deleted",
      deletedAt: "2026-07-30T13:00:00Z",
    };
    const revokedGeneration = {
      ...generation,
      reviewState: "revoked",
      revocationState: "revoked",
      revokedAt: "2026-07-30T13:00:00Z",
    };
    const markup = renderToStaticMarkup(
      <CaseMaterialHistorySummary
        material={deletedMaterial}
        generation={revokedGeneration}
      />,
    );

    expect(markup).toContain("材料与代次安全摘要");
    expect(markup).toContain("仅展示目录接口已经返回的摘要元数据");
    expect(markup).toContain("第 2 代");
    expect(markup).toContain("revoked");
    expect(markup).not.toContain("选择材料并生成审阅");
    expect(markup).not.toContain("进入人工批准");
    expect(markup).not.toContain("<button");
    expect(markup).not.toContain("originalText");
    expect(
      caseMaterialSelectionIsHistoryOnly(
        deletedMaterial,
        revokedGeneration,
      ),
    ).toBe(true);
    expect(
      caseMaterialSelectionIsHistoryOnly(
        { ...material, migrationStatus: "blocked" },
        generation,
      ),
    ).toBe(true);
    expect(
      caseMaterialSelectionIsHistoryOnly(
        { ...material, sourceKind: "legacy_reference" },
        generation,
      ),
    ).toBe(true);
    expect(
      caseMaterialSelectionIsHistoryOnly(material, generation),
    ).toBe(false);
  });

  it("renders explicit unassigned assignment controls without exposing a Privacy case identity", () => {
    const unassigned: UnassignedCaseMaterialSummary[] = [
      {
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
      },
      {
        materialId: "mat_blocked",
        displayName: "冲突材料.pdf",
        mediaType: "application/pdf",
        sourceKind: "local_review",
        extractionStatus: "extracted_local",
        migrationStatus: "blocked",
        state: "blocked",
        generationCount: 1,
        historicalIdentity: "missing",
        assignable: false,
        rowVersion: 3,
        updatedAt: "2026-07-30T13:00:00Z",
        deletedAt: null,
      },
    ];
    const markup = renderToStaticMarkup(
      <UnassignedCaseMaterialList
        projectId="case-project-1"
        materials={unassigned}
        actor="复核律师"
        busy={false}
        onActorChange={vi.fn()}
        onAssign={vi.fn()}
      />,
    );

    expect(markup).toContain("未归属本地材料");
    expect(markup).toContain("case-project-1");
    expect(markup).toContain("历史材料身份已保留");
    expect(markup).toContain("历史材料身份为空");
    expect(markup).toContain("行版本 7");
    expect(markup).toContain("明确归入当前案件");
    expect(markup).toContain("后端判定不可归属");
    expect(markup.match(/disabled=""/gu)).toHaveLength(1);
    expect(markup).not.toContain("case_");
  });

  it("defers draft discard and material switching until both confirmations and assignment complete", () => {
    const assignmentFlow = caseMaterialsWorkspaceSource.slice(
      caseMaterialsWorkspaceSource.indexOf(
        "const assignUnassigned",
      ),
    );
    const contextConfirmation = assignmentFlow.indexOf(
      "requestWorkbenchContextChange(true)",
    );
    const assignmentConfirmation = assignmentFlow.indexOf(
      "unassignedAssignmentConfirmation(",
    );
    const assignmentIpc = assignmentFlow.indexOf(
      "assignUnassignedCaseMaterial(request)",
    );
    const committedDiscard = assignmentFlow.indexOf(
      "discardWorkbenchContext();",
    );

    expect(contextConfirmation).toBeGreaterThanOrEqual(0);
    expect(assignmentConfirmation).toBeGreaterThan(
      contextConfirmation,
    );
    expect(assignmentIpc).toBeGreaterThan(
      assignmentConfirmation,
    );
    expect(committedDiscard).toBeGreaterThan(assignmentIpc);
  });

  it("requires a persisted project before the material workflow can mount", () => {
    const markup = renderToStaticMarkup(
      <CaseMaterialsWorkspace
        projectId={null}
        resetKey={0}
        onDraftDirtyChange={vi.fn()}
        onMutationActivityChange={vi.fn()}
      />,
    );

    expect(markup).toContain("先选择一个已保存案件");
    expect(markup).toContain(
      "案件材料必须归属于现有 ProjectId",
    );
    expect(markup).not.toContain("选择材料并生成审阅");
  });
});
