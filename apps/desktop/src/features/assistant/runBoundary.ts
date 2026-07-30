import {
  cancelAssistantRun,
  startInteractiveAssistantRun,
} from "../../ipc/assistant/client";
import type {
  AssistantRunEvent,
  AssistantRunIntent,
  StartInteractiveAssistantRunRequest,
  StartInteractiveAssistantRunResponse,
} from "../../ipc/assistant/types";

export type {
  AssistantRunIntent,
  StartInteractiveAssistantRunRequest,
  StartInteractiveAssistantRunResponse,
};

export interface AssistantRunBoundary {
  start(
    request: StartInteractiveAssistantRunRequest,
    onEvent: (event: AssistantRunEvent) => void,
  ): Promise<StartInteractiveAssistantRunResponse>;
  cancel(runId: string): Promise<boolean>;
}

export interface AssistantRunEventCursor {
  runId: string;
  epoch: number;
  lastSequence: number;
}

/**
 * Advances only the currently active run. The callback epoch is captured when
 * start() is invoked, so an old Channel cannot mutate a replacement run even
 * if a buggy backend reuses or delays an event.
 */
export function advanceAssistantRunEventCursor<T extends AssistantRunEventCursor>(
  current: T | null,
  callbackEpoch: number,
  event: AssistantRunEvent,
): T | null {
  if (
    !current ||
    current.runId !== event.runId ||
    current.epoch !== callbackEpoch ||
    event.sequence <= current.lastSequence
  ) {
    return null;
  }
  return { ...current, lastSequence: event.sequence };
}

export function applyAssistantCancellationResult<
  T extends { runId: string; cancelling: boolean },
>(current: T | null, runId: string, cancelled: boolean): T | null {
  if (!current || current.runId !== runId || cancelled) return current;
  return { ...current, cancelling: false };
}

export const ASSISTANT_RUN_INTENT_LABELS: Readonly<
  Record<AssistantRunIntent, string>
> = {
  legal_research: "法律研究",
  file_analysis: "材料分析",
  document_draft: "文书草拟",
  map_build: "分析图构建",
  case_analysis: "案件分析",
};

export interface AssistantAttachmentPolicy {
  accepts: boolean;
  requires: boolean;
}

/** Mirrors the Rust fixed plan so invalid attachment combinations never leave the UI. */
export function assistantAttachmentPolicy(
  intent: AssistantRunIntent,
  hasProject: boolean,
): AssistantAttachmentPolicy {
  switch (intent) {
    case "legal_research":
    case "case_analysis":
      return { accepts: false, requires: false };
    case "file_analysis":
      return { accepts: true, requires: true };
    case "document_draft":
    case "map_build":
      return { accepts: true, requires: !hasProject };
  }
}

/** Keeps the component testable and prevents run-command details spreading. */
export const defaultAssistantRunBoundary: AssistantRunBoundary = {
  start: startInteractiveAssistantRun,

  async cancel(runId) {
    const response = await cancelAssistantRun({ runId });
    return response.cancelled;
  },
};

export function createAssistantRunId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `assistant-run-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
