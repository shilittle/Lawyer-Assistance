import { beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class<T> {
    onmessage: (event: T) => void;

    constructor(onmessage: (event: T) => void) {
      this.onmessage = onmessage;
    }
  },
  invoke: invokeMock,
}));

import { answerLegalQuestion, cancelLegalAnswer } from "./client";
import type { LegalAnswerRequest, LegalAnswerStreamEvent } from "./types";

describe("legal answer streaming IPC client", () => {
  beforeEach(() => invokeMock.mockReset());

  it("passes a Tauri channel and forwards incremental events", async () => {
    invokeMock.mockResolvedValue({ providerId: "provider", answer: "done" });
    const received: LegalAnswerStreamEvent[] = [];
    const request = requestFixture();

    const promise = answerLegalQuestion(request, (event) => received.push(event));
    const args = invokeMock.mock.calls[0][1] as {
      request: LegalAnswerRequest;
      onEvent: { onmessage: (event: LegalAnswerStreamEvent) => void };
    };
    args.onEvent.onmessage({
      requestId: request.requestId,
      eventType: "delta",
      content: "增量",
    });
    await promise;

    expect(invokeMock).toHaveBeenCalledWith("answer_legal_question", {
      request,
      onEvent: args.onEvent,
    });
    expect(received[0].content).toBe("增量");
  });

  it("invokes the cancellation command with the active request id", async () => {
    invokeMock.mockResolvedValue({ requestId: "answer-2", cancelled: true });

    await expect(cancelLegalAnswer({ requestId: "answer-2" })).resolves.toEqual({
      requestId: "answer-2",
      cancelled: true,
    });
    expect(invokeMock).toHaveBeenCalledWith("cancel_legal_answer", {
      request: { requestId: "answer-2" },
    });
  });
});

function requestFixture(): LegalAnswerRequest {
  return {
    requestId: "answer-1",
    providerId: "provider",
    question: "违约责任是什么？",
    lawName: null,
    articleNumber: null,
    keywords: ["违约责任"],
    caseDate: null,
    effectivenessLevels: [],
    includeExpired: false,
    limit: 8,
    temperature: 0.1,
    maxTokens: 128,
  };
}
