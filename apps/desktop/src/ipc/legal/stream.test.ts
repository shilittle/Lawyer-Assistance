import { describe, expect, it } from "vitest";

import {
  formatLegalAnswerStreamStatus,
  INITIAL_LEGAL_ANSWER_STREAM_STATE,
  isLegalAnswerStreamActive,
  isLegalAnswerStreamCancellable,
  markLegalAnswerCancelling,
  reduceLegalAnswerStreamEvent,
  restoreLegalAnswerAfterRejectedCancellation,
  settleLegalAnswerCancellation,
  shouldCancelLegalAnswerOnPageLeave,
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
    expect(cancelled.requestId).toBeNull();

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

  it("does not cancel or relabel a request that is already finalizing", () => {
    const finalizing = reduceLegalAnswerStreamEvent(
      startLegalAnswerStream("answer-finalizing"),
      {
        requestId: "answer-finalizing",
        eventType: "done",
      },
    );

    expect(
      shouldCancelLegalAnswerOnPageLeave(finalizing, "answer-finalizing"),
    ).toBe(false);
    expect(
      settleLegalAnswerCancellation(
        finalizing,
        "answer-finalizing",
        true,
        "离开问答页面，生成已取消",
      ),
    ).toBe(finalizing);
  });

  it("uses the cancel command result as the cancellation authority", () => {
    const streaming = reduceLegalAnswerStreamEvent(
      startLegalAnswerStream("answer-cancel-result"),
      {
        requestId: "answer-cancel-result",
        eventType: "delta",
        content: "partial",
      },
    );
    const cancelling = markLegalAnswerCancelling(streaming);

    expect(
      shouldCancelLegalAnswerOnPageLeave(streaming, "answer-cancel-result"),
    ).toBe(true);
    expect(
      settleLegalAnswerCancellation(
        cancelling,
        "answer-cancel-result",
        false,
      ),
    ).toBe(cancelling);

    const restored = restoreLegalAnswerAfterRejectedCancellation(
      cancelling,
      "answer-cancel-result",
      "streaming",
    );
    expect(restored.status).toBe("streaming");
    expect(restored.message).toContain("取消未生效");

    const cancelled = settleLegalAnswerCancellation(
      cancelling,
      "answer-cancel-result",
      true,
    );
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.requestId).toBeNull();
    expect(cancelled.answer).toBe("partial");
  });
});
