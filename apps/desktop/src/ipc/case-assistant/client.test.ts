import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({
  Channel: class<T> {
    onmessage: (event: T) => void;

    constructor(onmessage: (event: T) => void) {
      this.onmessage = onmessage;
    }
  },
  invoke,
}));

import {
  cancelCaseAssistantRun,
  CaseAssistantIpcClientError,
  confirmCaseAssistantOutput,
  createCaseAssistantConversation,
  getCaseAssistantConversation,
  listCaseAssistantConversations,
  listCaseAssistantGenerations,
  listCaseAssistantPendingOutputs,
  normalizeCaseAssistantIpcError,
  startCaseAssistantRun,
} from "./client";

describe("case assistant typed IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses backend-scoped case-work conversation commands", async () => {
    await createCaseAssistantConversation({
      projectId: "case-project-1",
      title: "案件分析会话",
    });
    await listCaseAssistantConversations({
      projectId: "case-project-1",
      limit: 25,
    });
    await getCaseAssistantConversation({
      projectId: "case-project-1",
      conversationId: "case-conversation-1",
    });

    expect(invoke.mock.calls).toEqual([
      [
        "create_case_assistant_conversation",
        {
          request: {
            projectId: "case-project-1",
            title: "案件分析会话",
          },
        },
      ],
      [
        "list_case_assistant_conversations",
        {
          request: {
            projectId: "case-project-1",
            limit: 25,
          },
        },
      ],
      [
        "get_case_assistant_conversation",
        {
          request: {
            projectId: "case-project-1",
            conversationId: "case-conversation-1",
          },
        },
      ],
    ]);
  });

  it("lists only the case-facing approved generation projection", async () => {
    await listCaseAssistantGenerations({ projectId: "case-project-1" });

    expect(invoke).toHaveBeenCalledWith(
      "list_case_assistant_generations",
      {
        request: { projectId: "case-project-1" },
      },
    );
  });

  it("deep-closes every case run request before crossing IPC", async () => {
    const received: string[] = [];
    const promise = startCaseAssistantRun(
      {
        runId: "case-run-1",
        conversationId: "case-conversation-1",
        projectId: "case-project-1",
        providerId: "provider-1",
        prompt: "根据所选脱敏材料分析争点。",
        redactionGenerationIds: ["redaction-generation-1"],
        outputKind: "case_analysis",
        budget: {
          maxToolCalls: 4,
          maxProviderRoundTrips: 2,
          maxInputBodyBytes: 65_536,
          maxVisibleAttachments: 2,
          maxModelResponseBytes: 131_072,
          hiddenBudgetField: "must-not-cross",
        },
        caseId: "case_00000000000000000000000000000000",
        privacyCaseId: "case_00000000000000000000000000000000",
        generationHashes: ["must-not-cross"],
        riskRevision: 9,
        attachmentIds: ["must-not-cross"],
        path: "C:/must-not-cross",
        vaultObjectId: "must-not-cross",
        receipt: "must-not-cross",
        authority: "must-not-cross",
        classification: "must-not-cross",
        mcpProfileId: "must-not-cross",
        artifactId: "must-not-cross",
        userConfirmed: true,
      } as never,
      (event) => received.push(event.eventType),
    );

    const invocation = invoke.mock.calls[0][1] as {
      onEvent: {
        onmessage: (event: {
          runId: string;
          sequence: number;
          eventType: "delta";
          content: string;
          privacyCaseId?: string;
        }) => void;
      };
    };
    invocation.onEvent.onmessage({
      runId: "case-run-1",
      sequence: 1,
      eventType: "delta",
      content: "已完成扫描的回答",
      privacyCaseId: "must-not-surface",
    });
    await promise;

    expect(invoke).toHaveBeenCalledWith("start_case_assistant_run", {
      request: {
        runId: "case-run-1",
        conversationId: "case-conversation-1",
        projectId: "case-project-1",
        providerId: "provider-1",
        prompt: "根据所选脱敏材料分析争点。",
        redactionGenerationIds: ["redaction-generation-1"],
        outputKind: "case_analysis",
        budget: {
          maxToolCalls: 4,
          maxProviderRoundTrips: 2,
          maxInputBodyBytes: 65_536,
          maxVisibleAttachments: 2,
          maxModelResponseBytes: 131_072,
        },
      },
      onEvent: invocation.onEvent,
    });
    expect(received).toEqual(["delta"]);
    const payload = JSON.stringify(invoke.mock.calls[0]);
    for (const forbidden of [
      "caseId",
      "privacyCaseId",
      "generationHashes",
      "riskRevision",
      "attachmentIds",
      "path",
      "vaultObjectId",
      "receipt",
      "authority",
      "classification",
      "mcpProfileId",
      "artifactId",
      "userConfirmed",
      "hiddenBudgetField",
    ]) {
      expect(payload).not.toContain(forbidden);
    }
  });

  it("lists pending outputs and confirms only with backend-issued CAS fields", async () => {
    await listCaseAssistantPendingOutputs({
      projectId: "case-project-1",
      conversationId: "case-conversation-1",
    });
    await confirmCaseAssistantOutput({
      projectId: "case-project-1",
      pendingOutputId: "pending-output-1",
      expectedVersion: 3,
      expectedOutputSha256: "a".repeat(64),
      expectedWorkspaceDigest: "b".repeat(64),
      userConfirmed: true,
      expectedPrivacyCaseId: "must-not-cross",
      applyAutomatically: true,
    } as never);

    expect(invoke.mock.calls).toEqual([
      [
        "list_case_assistant_pending_outputs",
        {
          request: {
            projectId: "case-project-1",
            conversationId: "case-conversation-1",
          },
        },
      ],
      [
        "confirm_case_assistant_output",
        {
          request: {
            projectId: "case-project-1",
            pendingOutputId: "pending-output-1",
            expectedVersion: 3,
            expectedOutputSha256: "a".repeat(64),
            expectedWorkspaceDigest: "b".repeat(64),
            userConfirmed: true,
          },
        },
      ],
    ]);
    const payload = JSON.stringify(invoke.mock.calls);
    expect(payload).not.toContain("expectedPrivacyCaseId");
    expect(payload).not.toContain("applyAutomatically");
  });

  it("never upgrades a false confirmation into authorization", async () => {
    await expect(
      confirmCaseAssistantOutput({
        projectId: "case-project-1",
        pendingOutputId: "pending-output-1",
        expectedVersion: 1,
        expectedOutputSha256: "a".repeat(64),
        expectedWorkspaceDigest: "b".repeat(64),
        userConfirmed: false,
      } as never),
    ).rejects.toMatchObject({
      errorType: "confirmation_required",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("reuses cancellation by run id without importing ordinary chat state", async () => {
    await cancelCaseAssistantRun({ runId: "case-run-1" });

    expect(invoke).toHaveBeenCalledWith("cancel_assistant_run", {
      request: { runId: "case-run-1" },
    });
  });

  it("strips forbidden Privacy identities from every response depth", async () => {
    invoke.mockResolvedValue({
      generations: [
        {
          redactionGenerationId: "generation-1",
          materialId: "material-1",
          privacyCaseId: "must-not-surface",
          nested: { case_id: "must-not-surface" },
        },
      ],
      caseId: "must-not-surface",
    });

    const response = await listCaseAssistantGenerations({
      projectId: "case-project-1",
    });

    expect(response).toEqual({
      generations: [
        {
          redactionGenerationId: "generation-1",
          materialId: "material-1",
          nested: {},
        },
      ],
    });
  });

  it("normalizes structured failures without surfacing internal fields", async () => {
    invoke.mockRejectedValue({
      errorType: "generation_revoked",
      message: "所选脱敏版本已撤销，请重新选择。",
      privacyCaseId: "must-not-surface",
      path: "C:/must-not-surface",
    });

    await expect(
      listCaseAssistantGenerations({ projectId: "case-project-1" }),
    ).rejects.toMatchObject({
      name: "CaseAssistantIpcClientError",
      errorType: "generation_revoked",
      message: "所选脱敏版本已撤销，请重新选择。",
    });
    expect(
      normalizeCaseAssistantIpcError({ unexpected: true }),
    ).toBeInstanceOf(CaseAssistantIpcClientError);
  });
});
