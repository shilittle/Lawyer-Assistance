import type {
  LegalAnswerStreamEvent,
  LegalAnswerStreamUsage,
} from "./types";

export type LegalAnswerStreamStatus =
  | "idle"
  | "connecting"
  | "streaming"
  | "cancelling"
  | "finalizing"
  | "cancelled"
  | "error"
  | "done";

export interface LegalAnswerStreamState {
  requestId?: string | null;
  status: LegalAnswerStreamStatus;
  answer: string;
  usage?: LegalAnswerStreamUsage | null;
  errorType?: string | null;
  message?: string | null;
}

export const INITIAL_LEGAL_ANSWER_STREAM_STATE: LegalAnswerStreamState = {
  requestId: null,
  status: "idle",
  answer: "",
  usage: null,
  errorType: null,
  message: null,
};

export function startLegalAnswerStream(
  requestId: string,
): LegalAnswerStreamState {
  return {
    requestId,
    status: "connecting",
    answer: "",
    usage: null,
    errorType: null,
    message: null,
  };
}

export function markLegalAnswerCancelling(
  state: LegalAnswerStreamState,
): LegalAnswerStreamState {
  if (!isLegalAnswerStreamCancellable(state)) {
    return state;
  }

  return { ...state, status: "cancelling", message: "正在取消生成…" };
}

export function shouldCancelLegalAnswerOnPageLeave(
  state: LegalAnswerStreamState,
  requestId: string | null,
): boolean {
  return (
    requestId !== null &&
    state.requestId === requestId &&
    ["connecting", "streaming"].includes(state.status)
  );
}

export function settleLegalAnswerCancellation(
  state: LegalAnswerStreamState,
  requestId: string,
  cancelled: boolean,
  message = "生成已取消",
): LegalAnswerStreamState {
  if (
    !cancelled ||
    state.requestId !== requestId ||
    !["connecting", "streaming", "cancelling"].includes(state.status)
  ) {
    return state;
  }

  return {
    ...state,
    requestId: null,
    status: "cancelled",
    errorType: "cancelled",
    message,
  };
}

export function restoreLegalAnswerAfterRejectedCancellation(
  state: LegalAnswerStreamState,
  requestId: string,
  previousStatus: "connecting" | "streaming",
): LegalAnswerStreamState {
  if (state.requestId !== requestId || state.status !== "cancelling") {
    return state;
  }

  return {
    ...state,
    status: previousStatus,
    message: "取消未生效，等待当前请求结束",
  };
}

export function reduceLegalAnswerStreamEvent(
  state: LegalAnswerStreamState,
  event: LegalAnswerStreamEvent,
): LegalAnswerStreamState {
  if (state.requestId !== event.requestId) {
    return state;
  }
  if (["finalizing", "cancelled", "error", "done"].includes(state.status)) {
    return state;
  }
  if (
    state.status === "cancelling" &&
    (event.eventType === "delta" || event.eventType === "usage")
  ) {
    return state;
  }

  switch (event.eventType) {
    case "delta":
      return {
        ...state,
        status: "streaming",
        answer: state.answer + (event.content ?? ""),
      };
    case "usage":
      return { ...state, usage: event.usage ?? null };
    case "error": {
      const cancelled = event.errorType === "cancelled";
      return {
        ...state,
        requestId: cancelled ? null : state.requestId,
        status: cancelled ? "cancelled" : "error",
        errorType: event.errorType ?? "stream_error",
        message: event.message ?? "生成过程中发生错误",
      };
    }
    case "done":
      return {
        ...state,
        // The channel event is emitted after the answer has been saved but just
        // before the invoke Promise resolves with its supporting-law details.
        status: "finalizing",
        message: "回答已保存，正在载入法条依据",
      };
  }
}

export function isLegalAnswerStreamActive(
  state: LegalAnswerStreamState,
): boolean {
  return ["connecting", "streaming", "cancelling", "finalizing"].includes(
    state.status,
  );
}

export function isLegalAnswerStreamCancellable(
  state: LegalAnswerStreamState,
): boolean {
  return ["connecting", "streaming"].includes(state.status);
}

export function formatLegalAnswerStreamStatus(
  state: LegalAnswerStreamState,
): string {
  const labels: Record<LegalAnswerStreamStatus, string> = {
    idle: "等待生成",
    connecting: "正在准备回答",
    streaming: "正在整理回答",
    cancelling: "正在取消",
    finalizing: "回答已保存，正在载入法条依据",
    cancelled: "已取消",
    error: state.message ?? "生成失败",
    done: "回答已完成",
  };

  return labels[state.status];
}
