import type {
  LegalAnswerStreamEvent,
  LegalAnswerStreamUsage,
} from "./types";

export type LegalAnswerStreamStatus =
  | "idle"
  | "connecting"
  | "streaming"
  | "cancelling"
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
  if (!isLegalAnswerStreamActive(state)) {
    return state;
  }

  return { ...state, status: "cancelling", message: "正在取消生成…" };
}

export function reduceLegalAnswerStreamEvent(
  state: LegalAnswerStreamState,
  event: LegalAnswerStreamEvent,
): LegalAnswerStreamState {
  if (state.requestId !== event.requestId) {
    return state;
  }
  if (["cancelled", "error", "done"].includes(state.status)) {
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
    case "error":
      return {
        ...state,
        status: event.errorType === "cancelled" ? "cancelled" : "error",
        errorType: event.errorType ?? "stream_error",
        message: event.message ?? "生成过程中发生错误",
      };
    case "done":
      return {
        ...state,
        status: "done",
        message: "引用已由 Rust 校验，回答已保存",
      };
  }
}

export function isLegalAnswerStreamActive(
  state: LegalAnswerStreamState,
): boolean {
  return ["connecting", "streaming", "cancelling"].includes(state.status);
}

export function formatLegalAnswerStreamStatus(
  state: LegalAnswerStreamState,
): string {
  const labels: Record<LegalAnswerStreamStatus, string> = {
    idle: "等待生成",
    connecting: "正在连接 Provider",
    streaming: "正在生成（引用未校验）",
    cancelling: "正在取消",
    cancelled: "已取消",
    error: state.message ?? "生成失败",
    done: "已完成并校验引用",
  };

  return labels[state.status];
}
