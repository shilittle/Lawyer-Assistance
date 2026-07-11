import { describe, expect, it } from "vitest";

import {
  formatLegalAnswerStreamStatus,
  INITIAL_LEGAL_ANSWER_STREAM_STATE,
  isLegalAnswerStreamActive,
  isLegalAnswerStreamCancellable,
  markLegalAnswerCancelling,
  reduceLegalAnswerStreamEvent,
  startLegalAnswerStream,
} from "./stream";

describe("legal answer stream state", () => {
  it("builds incremental text and usage before trusted completion", () => {
    let state = startLegalAnswerStream("answer-1");
    state = reduceLegalAnswerStreamEvent(state, {
      requestId: "answer-1",
      eventType: "delta",
      content: "第一段",
    });
    state = reduceLegalAnswerStreamEvent(state, {
      requestId: "answer-1",
      eventType: "delta",
      content: "第二段",
    });
    state = reduceLegalAnswerStreamEvent(state, {
      requestId: "answer-1",
      eventType: "usage",
      usage: { promptTokens: 10, completionTokens: 2, totalTokens: 12 },
    });

    expect(state.answer).toBe("第一段第二段");
    expect(state.usage?.totalTokens).toBe(12);
    expect(formatLegalAnswerStreamStatus(state)).toContain("引用未校验");

    state = reduceLegalAnswerStreamEvent(state, {
      requestId: "answer-1",
      eventType: "done",
    });
    expect(state.status).toBe("finalizing");
    expect(formatLegalAnswerStreamStatus(state)).toContain("正在载入结果");
    expect(isLegalAnswerStreamActive(state)).toBe(true);
    expect(isLegalAnswerStreamCancellable(state)).toBe(false);
    expect(markLegalAnswerCancelling(state)).toBe(state);
  });

  it("shows cancellation and provider error states", () => {
    let cancelled = markLegalAnswerCancelling(startLegalAnswerStream("answer-2"));
    expect(cancelled.status).toBe("cancelling");
    cancelled = reduceLegalAnswerStreamEvent(cancelled, {
      requestId: "answer-2",
      eventType: "delta",
      content: "late delta",
    });
    expect(cancelled.answer).toBe("");
    cancelled = reduceLegalAnswerStreamEvent(cancelled, {
      requestId: "answer-2",
      eventType: "error",
      errorType: "cancelled",
      message: "legal answer request was cancelled",
    });
    expect(cancelled.status).toBe("cancelled");

    const failed = reduceLegalAnswerStreamEvent(
      startLegalAnswerStream("answer-3"),
      {
        requestId: "answer-3",
        eventType: "error",
        errorType: "rate_limit",
        message: "请求过于频繁",
      },
    );
    expect(failed.status).toBe("error");
    expect(formatLegalAnswerStreamStatus(failed)).toBe("请求过于频繁");
  });

  it("ignores late events from a released request", () => {
    const state = reduceLegalAnswerStreamEvent(
      startLegalAnswerStream("new-request"),
      {
        requestId: "old-request",
        eventType: "delta",
        content: "stale",
      },
    );

    expect(state).toEqual(startLegalAnswerStream("new-request"));
    expect(markLegalAnswerCancelling(INITIAL_LEGAL_ANSWER_STREAM_STATE)).toBe(
      INITIAL_LEGAL_ANSWER_STREAM_STATE,
    );
  });

  it("does not let late channel events move a finalized request backwards", () => {
    let state = reduceLegalAnswerStreamEvent(startLegalAnswerStream("answer-4"), {
      requestId: "answer-4",
      eventType: "done",
    });
    state = reduceLegalAnswerStreamEvent(state, {
      requestId: "answer-4",
      eventType: "delta",
      content: "late",
    });

    expect(state.status).toBe("finalizing");
    expect(state.answer).toBe("");
  });
});
