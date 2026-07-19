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
  addAssistantLegalSource,
  applyAssistantCaseChangeProposal,
  archiveAssistantConversation,
  AssistantIpcClientError,
  bindAssistantArtifact,
  bindAssistantConversation,
  cancelAssistantRun,
  createAssistantCaseChangeProposal,
  createAssistantConversation,
  deleteAssistantAttachment,
  exportAssistantArtifact,
  getAssistantArtifact,
  getAssistantCapabilities,
  getAssistantConversation,
  importAssistantFiles,
  listAssistantArtifacts,
  listAssistantConversations,
  normalizeAssistantIpcError,
  proposeAssistantLegalBasis,
  rejectAssistantCaseChangeProposal,
  saveAssistantArtifact,
  startAssistantRun,
} from "./client";
import type {
  CaseChangeSpec,
  SaveAssistantArtifactRequest,
} from "./types";

const changes: CaseChangeSpec = {
  schemaVersion: 1,
  facts: [
    {
      id: "fact-new",
      statement: "The payment was due on 2026-01-02.",
      occurredOn: "2026-01-02",
      sourceRefs: ["attachment-1"],
    },
  ],
  evidence: [
    {
      id: "evidence-new",
      title: "Signed contract",
      summary: "The signed payment clause.",
      provesFactIds: ["fact-new"],
      sourceRefs: ["attachment-1"],
    },
  ],
  issues: [
    {
      id: "issue-new",
      title: "Late payment",
      analysis: "Whether the payment was overdue.",
      relatedFactIds: ["fact-new"],
      sourceRefs: ["attachment-1"],
    },
  ],
  legalBasis: [],
  attachmentTransfers: [
    { attachmentId: "attachment-1", title: "Signed contract" },
  ],
  artifactTransfers: [],
};

describe("assistant typed IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("gets the immutable capability registry without an untyped payload", async () => {
    const response = { capabilities: [], defaultBudget: {} };
    invoke.mockResolvedValue(response);

    await expect(getAssistantCapabilities()).resolves.toBe(response);
    expect(invoke).toHaveBeenCalledWith("get_assistant_capabilities");
  });

  it("uses the exact conversation list, create, get, bind, and archive envelopes", async () => {
    await listAssistantConversations({
      projectId: null,
      includeArchived: true,
      limit: 25,
    });
    await createAssistantConversation({ title: "Research", projectId: null });
    await getAssistantConversation({ conversationId: "conversation-1" });
    await bindAssistantConversation({
      conversationId: "conversation-1",
      projectId: "case-1",
    });
    await archiveAssistantConversation({ conversationId: "conversation-1" });

    expect(invoke.mock.calls).toEqual([
      [
        "list_assistant_conversations",
        {
          request: {
            projectId: null,
            includeArchived: true,
            limit: 25,
          },
        },
      ],
      [
        "create_assistant_conversation",
        { request: { title: "Research", projectId: null } },
      ],
      [
        "get_assistant_conversation",
        { request: { conversationId: "conversation-1" } },
      ],
      [
        "bind_assistant_conversation",
        {
          request: {
            conversationId: "conversation-1",
            projectId: "case-1",
          },
        },
      ],
      [
        "archive_assistant_conversation",
        { request: { conversationId: "conversation-1" } },
      ],
    ]);
  });

  it("omits absent optional list and conversation fields", async () => {
    await listAssistantConversations();
    await createAssistantConversation({ title: "Standalone" });

    expect(invoke.mock.calls).toEqual([
      ["list_assistant_conversations", { request: {} }],
      [
        "create_assistant_conversation",
        { request: { title: "Standalone" } },
      ],
    ]);
  });

  it("adds a verified local legal source by identifier only", async () => {
    await addAssistantLegalSource({
      conversationId: "conversation-1",
      sourceId: "source-1",
    });

    expect(invoke).toHaveBeenCalledWith("add_assistant_legal_source", {
      request: {
        conversationId: "conversation-1",
        sourceId: "source-1",
      },
    });
  });

  it("creates a pending case legal-basis proposal from one local source", async () => {
    await proposeAssistantLegalBasis({
      conversationId: "conversation-1",
      projectId: "case-1",
      sourceId: "source-1",
    });

    expect(invoke).toHaveBeenCalledWith("propose_assistant_legal_basis", {
      request: {
        conversationId: "conversation-1",
        projectId: "case-1",
        sourceId: "source-1",
      },
    });
  });

  it("uses exact artifact list, detail, and case-binding requests", async () => {
    await listAssistantArtifacts({ conversationId: "conversation-1", limit: 8 });
    await getAssistantArtifact({ artifactId: "artifact-1" });
    await bindAssistantArtifact({
      artifactId: "artifact-1",
      projectId: "case-1",
      userConfirmed: true,
    });

    expect(invoke.mock.calls).toEqual([
      [
        "list_assistant_artifacts",
        { request: { conversationId: "conversation-1", limit: 8 } },
      ],
      [
        "get_assistant_artifact",
        { request: { artifactId: "artifact-1" } },
      ],
      [
        "bind_assistant_artifact",
        {
          request: {
            artifactId: "artifact-1",
            projectId: "case-1",
            userConfirmed: true,
          },
        },
      ],
    ]);
  });

  it("deep-closes a research artifact request before invoking Rust", async () => {
    const unsafeRequest = {
      conversationId: "conversation-1",
      artifactId: "artifact-1",
      expectedCurrentVersion: 2,
      title: "Research memo",
      providerSnapshot: { modelId: "must-not-cross" },
      apiKey: "dummy-do-not-cross",
      draft: {
        kind: "research",
        spec: {
          schemaVersion: 1,
          title: "Research memo",
          answer: "Answer [SRC:source-1]",
          sourceRefs: ["source-1"],
          assumptions: [],
          missingInformation: [],
          riskWarnings: [],
          providerSnapshot: { modelId: "must-not-cross" },
        },
      },
    } as unknown as SaveAssistantArtifactRequest;

    await saveAssistantArtifact(unsafeRequest);

    expect(invoke).toHaveBeenCalledWith("save_assistant_artifact", {
      request: {
        conversationId: "conversation-1",
        artifactId: "artifact-1",
        expectedCurrentVersion: 2,
        title: "Research memo",
        draft: {
          kind: "research",
          spec: {
            schemaVersion: 1,
            title: "Research memo",
            answer: "Answer [SRC:source-1]",
            sourceRefs: ["source-1"],
            assumptions: [],
            missingInformation: [],
            riskWarnings: [],
          },
        },
      },
    });
    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).not.toContain("apiKey");
    expect(payload).not.toContain("providerSnapshot");
  });

  it("deep-closes map nodes and edges instead of forwarding renderer controls", async () => {
    await saveAssistantArtifact({
      conversationId: "conversation-1",
      title: "Case map",
      draft: {
        kind: "map",
        spec: {
          schemaVersion: 1,
          title: "Case map",
          layoutHint: "layered",
          nodes: [
            {
              id: "node-1",
              label: "Claim",
              summary: "Payment claim",
              parentId: null,
              sourceRefs: ["fact-1"],
              script: "must-not-cross",
            } as never,
          ],
          edges: [],
        },
      },
    });

    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).not.toContain("script");
    expect(invoke).toHaveBeenCalledWith("save_assistant_artifact", {
      request: {
        conversationId: "conversation-1",
        title: "Case map",
        draft: {
          kind: "map",
          spec: {
            schemaVersion: 1,
            title: "Case map",
            layoutHint: "layered",
            nodes: [
              {
                id: "node-1",
                label: "Claim",
                summary: "Payment claim",
                parentId: null,
                sourceRefs: ["fact-1"],
              },
            ],
            edges: [],
          },
        },
      },
    });
  });

  it("exports through the Rust save dialog and imports through the Rust open dialog", async () => {
    await exportAssistantArtifact({
      artifactId: "artifact-1",
      versionNumber: 3,
      format: "document_docx",
      exportPath: "C:/must-not-cross.docx",
    } as never);
    await importAssistantFiles({
      conversationId: "conversation-1",
      filePaths: ["C:/must-not-cross.pdf"],
    } as never);

    expect(invoke.mock.calls).toEqual([
      [
        "export_assistant_artifact",
        {
          request: {
            artifactId: "artifact-1",
            versionNumber: 3,
            format: "document_docx",
          },
        },
      ],
      [
        "import_assistant_files",
        { request: { conversationId: "conversation-1" } },
      ],
    ]);
    const payload = JSON.stringify(invoke.mock.calls);
    expect(payload).not.toContain("exportPath");
    expect(payload).not.toContain("filePaths");
    expect(payload).not.toContain("C:/");
  });

  it("permanently deletes an attachment only through explicit confirmation", async () => {
    await deleteAssistantAttachment({
      conversationId: "conversation-1",
      attachmentId: "attachment-1",
      userConfirmed: true,
    });

    expect(invoke).toHaveBeenCalledWith("delete_assistant_attachment", {
      request: {
        conversationId: "conversation-1",
        attachmentId: "attachment-1",
        userConfirmed: true,
      },
    });
  });

  it("cancels only by the assistant run identifier", async () => {
    await cancelAssistantRun({ runId: "assistant-run-1" });

    expect(invoke).toHaveBeenCalledWith("cancel_assistant_run", {
      request: { runId: "assistant-run-1" },
    });
  });

  it("starts a cancellable run with one closed provider-agnostic plan", async () => {
    const received: string[] = [];
    const promise = startAssistantRun({
      runId: "assistant-run-2",
      conversationId: "conversation-1",
      providerId: "provider-1",
      intent: "document_draft",
      prompt: "Draft a contract from the selected material.",
      attachmentIds: ["attachment-1"],
      saveResearchArtifact: null,
      regenerationTarget: {
        artifactId: "artifact-1",
        sourceVersionNumber: 2,
        expectedCurrentVersion: 3,
        hiddenTargetField: "must-not-cross",
      },
      budget: {
        maxToolCalls: 5,
        maxProviderRoundTrips: 2,
        maxInputBodyBytes: 1024,
        maxVisibleAttachments: 1,
        maxModelResponseBytes: 4096,
        hiddenBudgetField: "must-not-cross",
      } as never,
      apiKey: "dummy-do-not-cross",
      command: "arbitrary-command",
    } as never, (event) => received.push(event.eventType));

    const invocation = invoke.mock.calls[0][1] as {
      onEvent: { onmessage: (event: {
        runId: string;
        sequence: number;
        eventType: "delta";
        content: string;
      }) => void };
    };
    invocation.onEvent.onmessage({
      runId: "assistant-run-2",
      sequence: 1,
      eventType: "delta",
      content: "partial",
    });
    await promise;

    expect(invoke).toHaveBeenCalledWith("start_assistant_run", {
      request: {
        runId: "assistant-run-2",
        conversationId: "conversation-1",
        providerId: "provider-1",
        intent: "document_draft",
        prompt: "Draft a contract from the selected material.",
        attachmentIds: ["attachment-1"],
        saveResearchArtifact: null,
        regenerationTarget: {
          artifactId: "artifact-1",
          sourceVersionNumber: 2,
          expectedCurrentVersion: 3,
        },
        budget: {
          maxToolCalls: 5,
          maxProviderRoundTrips: 2,
          maxInputBodyBytes: 1024,
          maxVisibleAttachments: 1,
          maxModelResponseBytes: 4096,
        },
      },
      onEvent: invocation.onEvent,
    });
    expect(received).toEqual(["delta"]);
    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).not.toContain("apiKey");
    expect(payload).not.toContain("arbitrary-command");
    expect(payload).not.toContain("hiddenBudgetField");
    expect(payload).not.toContain("hiddenTargetField");
  });

  it("creates a closed pending case-change proposal without an apply flag", async () => {
    const unsafeChanges = {
      ...changes,
      sql: "must-not-cross",
      facts: [{ ...changes.facts[0], replacementId: "must-not-cross" }],
    } as unknown as CaseChangeSpec;

    await createAssistantCaseChangeProposal({
      conversationId: "conversation-1",
      projectId: "case-1",
      changes: unsafeChanges,
      runId: "must-not-cross",
      userConfirmed: true,
    } as never);

    expect(invoke).toHaveBeenCalledWith(
      "create_assistant_case_change_proposal",
      {
        request: {
          conversationId: "conversation-1",
          projectId: "case-1",
          changes,
        },
      },
    );
    const payload = JSON.stringify(invoke.mock.calls[0]);
    expect(payload).not.toContain("userConfirmed");
    expect(payload).not.toContain("must-not-cross");
    expect(payload).not.toContain("replacementId");
    expect(payload).not.toContain("sql");
  });

  it("rejects and explicitly confirms apply through separate commands", async () => {
    await rejectAssistantCaseChangeProposal({
      proposalId: "proposal-1",
      projectId: "case-1",
    });
    await applyAssistantCaseChangeProposal({
      proposalId: "proposal-2",
      projectId: "case-1",
      userConfirmed: true,
    });

    expect(invoke.mock.calls).toEqual([
      [
        "reject_assistant_case_change_proposal",
        { request: { proposalId: "proposal-1", projectId: "case-1" } },
      ],
      [
        "apply_assistant_case_change_proposal",
        {
          request: {
            proposalId: "proposal-2",
            projectId: "case-1",
            userConfirmed: true,
          },
        },
      ],
    ]);
  });

  it("normalizes structured object and JSON-string invoke failures", async () => {
    invoke.mockRejectedValueOnce({
      errorType: "confirmation_required",
      message: "Explicit confirmation is required.",
      internalPath: "C:/must-not-surface",
    });

    await expect(
      applyAssistantCaseChangeProposal({
        proposalId: "proposal-1",
        projectId: "case-1",
        userConfirmed: false,
      }),
    ).rejects.toEqual(
      expect.objectContaining({
        name: "AssistantIpcClientError",
        errorType: "confirmation_required",
        message: "Explicit confirmation is required.",
      }),
    );

    invoke.mockRejectedValueOnce(
      JSON.stringify({ errorType: "conflict", message: "Version conflict." }),
    );
    await expect(
      getAssistantArtifact({ artifactId: "artifact-1" }),
    ).rejects.toMatchObject({
      errorType: "conflict",
      message: "Version conflict.",
    });
  });

  it("uses a bounded stable fallback for malformed errors", () => {
    const normalized = normalizeAssistantIpcError({ unexpected: true });
    expect(normalized).toBeInstanceOf(AssistantIpcClientError);
    expect(normalized).toMatchObject({
      errorType: "assistant_ipc",
      message: "Assistant operation failed. Please try again.",
    });

    const sanitized = normalizeAssistantIpcError({
      errorType: "bad type!<script>",
      message: "  failed  ",
    });
    expect(sanitized.errorType).toBe("badtypescript");
    expect(sanitized.message).toBe("failed");
  });
});
