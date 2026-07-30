import type {
  AssignUnassignedCaseMaterialRequest,
  UnassignedCaseMaterialSummary,
} from "../../../ipc/privacy/case-material-types";

export const CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION =
  "切换材料或脱敏代次将永久丢弃尚未保存的案件材料与风险审阅草稿。确定继续吗？";

export function buildUnassignedAssignmentRequest(
  projectId: string,
  material: UnassignedCaseMaterialSummary,
  actorInput: string,
): AssignUnassignedCaseMaterialRequest {
  const actor = actorInput.trim();
  if (!actor || actor.length > 128) {
    throw new Error("归属操作人必填且不能超过 128 个字符。");
  }
  if (!material.assignable) {
    throw new Error("后端已将该历史材料标记为不可归属；操作已阻断。");
  }
  return {
    projectId,
    materialId: material.materialId,
    expectedRowVersion: material.rowVersion,
    actor,
  };
}

export function unassignedAssignmentConfirmation(
  request: AssignUnassignedCaseMaterialRequest,
  displayName: string,
): string {
  return `确认将“${displayName}”明确归入案件 ${request.projectId} 吗？系统将按当前行版本 ${request.expectedRowVersion} 提交，冲突时不会覆盖其他变更。`;
}

export function caseMaterialsWorkspaceDraftIsDirty(
  workbenchDirty: boolean,
  assignmentActor: string,
): boolean {
  return workbenchDirty || assignmentActor.length > 0;
}

export type ConfirmedUnassignedAssignmentOutcome<T> =
  | { kind: "context_cancelled" }
  | { kind: "assignment_cancelled" }
  | { kind: "assigned"; value: T };

export async function executeConfirmedUnassignedAssignment<T>({
  authorizeContextChange,
  confirmAssignment,
  execute,
  commit,
}: {
  authorizeContextChange: () => boolean;
  confirmAssignment: () => boolean;
  execute: () => Promise<T>;
  commit: (value: T) => void;
}): Promise<ConfirmedUnassignedAssignmentOutcome<T>> {
  if (!authorizeContextChange()) {
    return { kind: "context_cancelled" };
  }
  if (!confirmAssignment()) {
    return { kind: "assignment_cancelled" };
  }
  const value = await execute();
  commit(value);
  return { kind: "assigned", value };
}
