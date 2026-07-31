import type {
  CaseAssistantGeneration,
  CaseAssistantOutputKind,
  CaseAssistantPendingOutput,
  CaseAssistantRunEvent,
} from "../../../ipc/case-assistant/types";

export const CASE_ASSISTANT_OUTPUT_KIND_LABELS = {
  case_analysis: "案件分析",
  case_document: "案件文书",
  case_diagram: "案件图示",
} as const satisfies Record<CaseAssistantOutputKind, string>;

export interface CaseAssistantStreamState {
  runId: string;
  lastSequence: number;
  status: string;
  verifiedResponse: string;
  receivedVerifiedDelta: boolean;
  promptTokens: number | null;
  completionTokens: number | null;
  totalTokens: number | null;
  error: string | null;
}
export function initialCaseAssistantStreamState(
  runId: string,
): CaseAssistantStreamState {
  return {
    runId,
    lastSequence: 0,
    status: "accepted",
    verifiedResponse: "",
    receivedVerifiedDelta: false,
    promptTokens: null,
    completionTokens: null,
    totalTokens: null,
    error: null,
  };
}

export function reduceCaseAssistantRunEvent(
  current: CaseAssistantStreamState,
  event: CaseAssistantRunEvent,
): CaseAssistantStreamState {
  if (
    event.runId !== current.runId ||
    event.sequence <= current.lastSequence
  ) {
    return current;
  }
  const next = { ...current, lastSequence: event.sequence };
  switch (event.eventType) {
    case "status":
      return { ...next, status: event.status };
    case "usage":
      return {
        ...next,
        promptTokens: event.usage.promptTokens ?? null,
        completionTokens: event.usage.completionTokens ?? null,
        totalTokens: event.usage.totalTokens ?? null,
      };
    case "delta":
      return current.receivedVerifiedDelta
        ? next
        : {
            ...next,
            verifiedResponse: event.content,
            receivedVerifiedDelta: true,
          };
    case "error":
      return {
        ...next,
        error: event.message,
      };
    case "tool":
      return next;
  }
}

export function selectedGenerationIdsFromProjection(
  generations: readonly CaseAssistantGeneration[],
): string[] {
  return generations
    .filter((generation) => generation.selected)
    .map((generation) => generation.redactionGenerationId);
}

export function reconcileCaseAssistantGenerationIds(
  currentIds: readonly string[],
  generations: readonly CaseAssistantGeneration[],
): string[] {
  const availableIds = new Set(
    generations.map((generation) => generation.redactionGenerationId),
  );
  return [
    ...new Set([
      ...currentIds.filter((generationId) =>
        availableIds.has(generationId),
      ),
      ...selectedGenerationIdsFromProjection(generations),
    ]),
  ];
}

const CASE_ASSISTANT_RESELECTION_ERROR_TYPES = new Set([
  "generation_revoked",
  "case_assistant_source_conflict",
  "privacy_store_conflict",
  "case_material_unavailable",
  "redaction_not_approved",
]);

export function caseAssistantRunFailureMessage(
  publicMessage: string,
  errorType?: string,
): string {
  const reselection =
    errorType !== undefined &&
    CASE_ASSISTANT_RESELECTION_ERROR_TYPES.has(errorType);
  return `案件助理运行失败：${publicMessage}${
    reselection ? " 请重新选择材料后再试。" : ""
  }`;
}

export function failCaseAssistantStreamState(
  current: CaseAssistantStreamState,
  message: string,
): CaseAssistantStreamState {
  return {
    ...current,
    status: "failed",
    error: message,
  };
}

export function toggleCaseAssistantGeneration(
  generations: readonly CaseAssistantGeneration[],
  selectedIds: readonly string[],
  generationId: string,
  checked: boolean,
): string[] {
  const target = generations.find(
    (generation) => generation.redactionGenerationId === generationId,
  );
  if (!target) return [...selectedIds];
  if (!checked) {
    return selectedIds.filter((selectedId) => selectedId !== generationId);
  }
  const sameMaterialIds = new Set(
    generations
      .filter((generation) => generation.materialId === target.materialId)
      .map((generation) => generation.redactionGenerationId),
  );
  return [
    ...selectedIds.filter(
      (selectedId) =>
        !sameMaterialIds.has(selectedId) && selectedId !== generationId,
    ),
    generationId,
  ];
}

export function caseAssistantConfirmationMessage(
  output: CaseAssistantPendingOutput,
): string {
  const label = CASE_ASSISTANT_OUTPUT_KIND_LABELS[output.outputKind];
  return `确认应用这份${label}？系统会再次验证案件工作区与全部已批准脱敏来源；确认前不会写入案件或成果。`;
}
