import type { ViewMode } from "./views";

export type CaseDraftKind =
  | "project"
  | "file"
  | "party"
  | "fact"
  | "evidence"
  | "legal_issue"
  | "evidence_link"
  | "fact_issue_link"
  | "legal_basis";

export const CASE_DRAFT_LABELS: Readonly<Record<CaseDraftKind, string>> = {
  project: "案件基本信息",
  file: "案件材料",
  party: "当事人",
  fact: "事实",
  evidence: "证据",
  legal_issue: "争点",
  evidence_link: "事实—证据关联",
  fact_issue_link: "事实—争点关联",
  legal_basis: "法律依据",
};

export interface WorkspaceCloseProtectionState {
  dirtyCaseDrafts: readonly CaseDraftKind[];
  providerDraftDirty: boolean;
  caseMutationInFlight: boolean;
  providerMutationInFlight: boolean;
  extractionMutationInFlight: boolean;
  assistantRunActive?: boolean;
  assistantMutationInFlight?: boolean;
  assistantDraftDirty?: boolean;
  mcpMutationInFlight?: boolean;
  mcpDraftDirty?: boolean;
  privacyMutationInFlight?: boolean;
  privacyDraftDirty?: boolean;
}

export type WorkspaceCloseDecision =
  | { kind: "proceed" }
  | { kind: "block"; message: string }
  | { kind: "confirm_discard"; message: string };

export function decideWorkspaceClose(
  state: WorkspaceCloseProtectionState,
): WorkspaceCloseDecision {
  if (state.assistantRunActive) {
    return {
      kind: "block",
      message:
        "助理任务仍在运行。请先等待完成或在助理工作区取消，再关闭窗口。",
    };
  }

  const activeWrites = [
    state.caseMutationInFlight ? "案件数据写入" : null,
    state.providerMutationInFlight ? "Provider 或 API Key 写入" : null,
    state.extractionMutationInFlight ? "材料审阅保存" : null,
    state.assistantMutationInFlight
      ? "助理保存、导入、导出、法律库桥接或已确认建议写入"
      : null,
    state.mcpMutationInFlight ? "MCP 服务配置或生命周期变更" : null,
    state.privacyMutationInFlight ? "隐私与本地处理配置写入" : null,
  ].filter((item): item is string => item !== null);
  if (activeWrites.length > 0) {
    return {
      kind: "block",
      message: `${activeWrites.join("、")}尚未完成；为避免结果不明，已阻止关闭窗口。请等待当前操作完成后重试。`,
    };
  }

  const unsaved = state.dirtyCaseDrafts.map(
    (kind) => CASE_DRAFT_LABELS[kind],
  );
  if (state.providerDraftDirty) {
    unsaved.push("Provider Profile 或 API Key 输入");
  }
  if (state.assistantDraftDirty) {
    unsaved.push("助理中未发送的任务草稿");
  }
  if (state.mcpDraftDirty) {
    unsaved.push("MCP 服务配置或待写入 Bearer Token");
  }
  if (state.privacyDraftDirty) {
    unsaved.push("隐私与本地 OCR 配置");
  }
  if (unsaved.length > 0) {
    return {
      kind: "confirm_discard",
      message: `关闭窗口将永久丢弃这些未保存内容：${unsaved.join("、")}。确定继续关闭吗？`,
    };
  }

  return { kind: "proceed" };
}

export function decideMcpWorkspaceNavigation(
  currentView: ViewMode,
  nextView: ViewMode,
  mutationInFlight: boolean,
  draftDirty: boolean,
): WorkspaceCloseDecision {
  if (currentView === nextView) {
    return { kind: "proceed" };
  }
  if (mutationInFlight) {
    return {
      kind: "block",
      message:
        "MCP 服务配置或生命周期变更尚未完成；为避免结果不明，已阻止切换工作区。请等待当前操作完成后重试。",
    };
  }
  if (draftDirty) {
    return {
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的 MCP 服务配置或待写入 Bearer Token。确定继续吗？",
    };
  }
  return { kind: "proceed" };
}

export function decidePrivacyWorkspaceNavigation(
  currentView: ViewMode,
  nextView: ViewMode,
  mutationInFlight: boolean,
  draftDirty: boolean,
): WorkspaceCloseDecision {
  if (currentView === nextView) {
    return { kind: "proceed" };
  }
  if (currentView !== "privacy") {
    return { kind: "proceed" };
  }
  if (mutationInFlight) {
    return {
      kind: "block",
      message:
        "隐私与本地处理配置正在写入；为避免结果不明，已阻止切换工作区。请等待保存完成后重试。",
    };
  }
  if (draftDirty) {
    return {
      kind: "confirm_discard",
      message:
        "切换工作区将永久丢弃未保存的隐私与本地 OCR 配置。确定继续吗？",
    };
  }
  return { kind: "proceed" };
}

export function assistantWritesBlockClose(
  workspaceMutationActive: boolean,
  legalSourceBridgeMutationActive: boolean,
): boolean {
  return workspaceMutationActive || legalSourceBridgeMutationActive;
}

export function workspaceCloseWasApproved(
  decision: WorkspaceCloseDecision,
  confirmDiscard: (message: string) => boolean,
): boolean {
  if (decision.kind === "proceed") {
    return true;
  }
  return (
    decision.kind === "confirm_discard" &&
    confirmDiscard(decision.message)
  );
}

export function canBypassDirtyDraftsForWorkspaceRecovery(
  targetProjectId: string,
  selectedProjectId: string | null,
  workspaceWriteBlocked: boolean,
  persistedMutationRecoveryProjectId: string | null,
): boolean {
  return (
    workspaceWriteBlocked &&
    targetProjectId === selectedProjectId &&
    targetProjectId === persistedMutationRecoveryProjectId
  );
}
