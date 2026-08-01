import { describe, expect, it, vi } from "vitest";

import {
  assistantWritesBlockClose,
  canBypassDirtyDraftsForWorkspaceRecovery,
  decideCaseMaterialContextChange,
  decideCaseMaterialRouteNavigation,
  decideLocalProcessingRouteNavigation,
  decideMaintenanceRouteNavigation,
  decideMcpRouteNavigation,
  decideWorkspaceClose,
  workspaceCloseWasApproved,
  type CaseDraftKind,
  type WorkspaceCloseProtectionState,
} from "./navigationGuards";

const cleanCloseState: WorkspaceCloseProtectionState = {
  dirtyCaseDrafts: [],
  providerDraftDirty: false,
  caseMutationInFlight: false,
  providerMutationInFlight: false,
  extractionMutationInFlight: false,
};

describe("navigation guards", () => {
  it("preserves the close-decision priority for active runs, writes, drafts, and clean state", () => {
    expect(
      decideWorkspaceClose({
        ...cleanCloseState,
        dirtyCaseDrafts: ["project"],
        providerDraftDirty: true,
        caseMutationInFlight: true,
        assistantRunActive: true,
      }),
    ).toEqual({
      kind: "block",
      message:
        "助理任务仍在运行。请先等待完成或在助理工作区取消，再关闭窗口。",
    });

    expect(
      decideWorkspaceClose({
        ...cleanCloseState,
        dirtyCaseDrafts: ["project"],
        providerDraftDirty: true,
        caseMutationInFlight: true,
        providerMutationInFlight: true,
        extractionMutationInFlight: true,
        assistantMutationInFlight: true,
        mcpMutationInFlight: true,
        localProcessingMutationInFlight: true,
        maintenanceMutationInFlight: true,
      }),
    ).toEqual({
      kind: "block",
      message:
        "案件数据写入、Provider 或 API Key 写入、材料审阅保存、助理保存、导入、导出、法律库桥接或已确认建议写入、MCP 服务配置或生命周期变更、本地处理配置或组件操作、应用更新、诊断或隐私生命周期维护尚未完成；为避免结果不明，已阻止关闭窗口。请等待当前操作完成后重试。",
    });

    const allCaseDrafts: readonly CaseDraftKind[] = [
      "project",
      "file",
      "party",
      "fact",
      "evidence",
      "legal_issue",
      "evidence_link",
      "fact_issue_link",
      "legal_basis",
    ];
    expect(
      decideWorkspaceClose({
        ...cleanCloseState,
        dirtyCaseDrafts: allCaseDrafts,
        providerDraftDirty: true,
        assistantDraftDirty: true,
        mcpDraftDirty: true,
        localProcessingDraftDirty: true,
      }),
    ).toEqual({
      kind: "confirm_discard",
      message:
        "关闭窗口将永久丢弃这些未保存内容：案件基本信息、案件材料、当事人、事实、证据、争点、事实—证据关联、事实—争点关联、法律依据、Provider Profile 或 API Key 输入、助理中未发送的任务草稿、MCP 服务配置或待写入 Bearer Token、本地处理与 OCR 配置。确定继续关闭吗？",
    });

    expect(decideWorkspaceClose(cleanCloseState)).toEqual({
      kind: "proceed",
    });
  });

  it("preserves MCP navigation protection for every changed route", () => {
    expect(
      decideMcpRouteNavigation(
        { area: "settings", page: "mcp" },
        { area: "settings", page: "mcp" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideMcpRouteNavigation(
        { area: "assistant", page: "chat" },
        { area: "cases", page: "overview" },
        true,
        true,
      ),
    ).toEqual({
      kind: "block",
      message:
        "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    });
    expect(
      decideMcpRouteNavigation(
        { area: "settings", page: "mcp" },
        { area: "settings", page: "maintenance" },
        false,
        true,
      ),
    ).toEqual({
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的 MCP 服务配置或待写入 Bearer Token。确定继续吗？",
    });
    expect(
      decideMcpRouteNavigation(
        { area: "settings", page: "mcp" },
        { area: "assistant", page: "chat" },
        false,
        false,
      ),
    ).toEqual({ kind: "proceed" });
  });

  it("treats a repeated state-free location as non-navigation", () => {
    const currentMcpRoute = {
      area: "settings",
      page: "mcp",
    } as const;
    const nextMcpRoute = {
      area: "settings",
      page: "mcp",
    } as const;

    expect(
      decideMcpRouteNavigation(
        currentMcpRoute,
        nextMcpRoute,
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideLocalProcessingRouteNavigation(
        currentMcpRoute,
        nextMcpRoute,
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
  });

  it("preserves MCP protection for every different typed location", () => {
    expect(
      decideMcpRouteNavigation(
        { area: "assistant", page: "chat" },
        { area: "cases", page: "overview" },
        true,
        true,
      ),
    ).toEqual({
      kind: "block",
      message:
        "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    });

    expect(
      decideMcpRouteNavigation(
        { area: "cases", page: "overview" },
        { area: "cases", page: "work" },
        false,
        true,
      ),
    ).toEqual({
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的 MCP 服务配置或待写入 Bearer Token。确定继续吗？",
    });

    expect(
      decideMcpRouteNavigation(
        { area: "settings", page: "mcp" },
        { area: "assistant", page: "chat" },
        false,
        false,
      ),
    ).toEqual({ kind: "proceed" });
  });

  it("preserves local-processing protection only when leaving its route", () => {
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "local-processing" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "providers" },
        { area: "assistant", page: "chat" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "mcp" },
        true,
        true,
      ),
    ).toEqual({
      kind: "block",
      message:
        "本地处理配置或组件操作尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "settings", page: "maintenance" },
        false,
        true,
      ),
    ).toEqual({
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的本地处理与 OCR 配置。确定继续吗？",
    });
    expect(
      decideLocalProcessingRouteNavigation(
        { area: "settings", page: "local-processing" },
        { area: "assistant", page: "chat" },
        false,
        false,
      ),
    ).toEqual({ kind: "proceed" });
  });

  it("protects case-material edits only when leaving materials or changing its project context", () => {
    expect(
      decideCaseMaterialRouteNavigation(
        { area: "cases", page: "materials" },
        { area: "cases", page: "materials" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideCaseMaterialRouteNavigation(
        { area: "cases", page: "overview" },
        { area: "assistant", page: "chat" },
        true,
        true,
      ),
    ).toEqual({ kind: "proceed" });
    expect(
      decideCaseMaterialRouteNavigation(
        { area: "cases", page: "materials" },
        { area: "cases", page: "work" },
        true,
        false,
      ),
    ).toEqual({
      kind: "block",
      message:
        "案件材料脱敏操作尚未完成；为避免结果不明，已阻止切换。请等待当前操作完成后重试。",
    });
    expect(decideCaseMaterialContextChange(false, true)).toEqual({
      kind: "confirm_discard",
      message:
        "切换将永久丢弃当前案件材料与风险审阅草稿。确定继续吗？",
    });
  });

  it("includes case-material operations and drafts in window-close protection", () => {
    const mutation = decideWorkspaceClose({
      ...cleanCloseState,
      caseMaterialMutationInFlight: true,
    });
    expect(mutation.kind).toBe("block");
    expect("message" in mutation ? mutation.message : "").toContain(
      "案件材料脱敏操作",
    );

    const draft = decideWorkspaceClose({
      ...cleanCloseState,
      caseMaterialDraftDirty: true,
    });
    expect(draft.kind).toBe("confirm_discard");
    expect("message" in draft ? draft.message : "").toContain(
      "案件材料与风险审阅草稿",
    );
  });

  it("protects maintenance activity only when leaving maintenance", () => {
    expect(
      decideMaintenanceRouteNavigation(
        { area: "settings", page: "providers" },
        { area: "assistant", page: "chat" },
        true,
      ),
    ).toEqual({ kind: "proceed" });

    expect(
      decideMaintenanceRouteNavigation(
        { area: "settings", page: "maintenance" },
        { area: "settings", page: "maintenance" },
        true,
      ),
    ).toEqual({ kind: "proceed" });

    expect(
      decideMaintenanceRouteNavigation(
        { area: "settings", page: "maintenance" },
        { area: "settings", page: "mcp" },
        true,
      ),
    ).toEqual({
      kind: "block",
      message:
        "应用更新、诊断或隐私生命周期维护尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    });

    expect(
      decideMaintenanceRouteNavigation(
        { area: "settings", page: "maintenance" },
        { area: "assistant", page: "chat" },
        false,
      ),
    ).toEqual({ kind: "proceed" });
  });

  it("preserves assistant write aggregation", () => {
    expect(assistantWritesBlockClose(false, false)).toBe(false);
    expect(assistantWritesBlockClose(true, false)).toBe(true);
    expect(assistantWritesBlockClose(false, true)).toBe(true);
    expect(assistantWritesBlockClose(true, true)).toBe(true);
  });

  it("asks for confirmation only for discard decisions", () => {
    const confirmDiscard = vi.fn(() => true);

    expect(
      workspaceCloseWasApproved({ kind: "proceed" }, confirmDiscard),
    ).toBe(true);
    expect(
      workspaceCloseWasApproved(
        { kind: "block", message: "blocked" },
        confirmDiscard,
      ),
    ).toBe(false);
    expect(confirmDiscard).not.toHaveBeenCalled();

    expect(
      workspaceCloseWasApproved(
        { kind: "confirm_discard", message: "confirm" },
        confirmDiscard,
      ),
    ).toBe(true);
    expect(confirmDiscard).toHaveBeenCalledOnce();
    expect(confirmDiscard).toHaveBeenCalledWith("confirm");

    confirmDiscard.mockReturnValue(false);
    expect(
      workspaceCloseWasApproved(
        { kind: "confirm_discard", message: "decline" },
        confirmDiscard,
      ),
    ).toBe(false);
  });

  it("bypasses dirty drafts only for the exact blocked recovery project", () => {
    expect(
      canBypassDirtyDraftsForWorkspaceRecovery(
        "case-a",
        "case-a",
        true,
        "case-a",
      ),
    ).toBe(true);

    const rejectedRecoveryStates: ReadonlyArray<
      readonly [
        targetProjectId: string,
        selectedProjectId: string | null,
        workspaceWriteBlocked: boolean,
        persistedMutationRecoveryProjectId: string | null,
      ]
    > = [
      ["case-b", "case-a", true, "case-a"],
      ["case-a", "case-b", true, "case-a"],
      ["case-a", "case-a", false, "case-a"],
      ["case-a", "case-a", true, "case-b"],
      ["case-a", null, true, "case-a"],
      ["case-a", "case-a", true, null],
    ];
    for (const args of rejectedRecoveryStates) {
      expect(canBypassDirtyDraftsForWorkspaceRecovery(...args)).toBe(false);
    }
  });
});
