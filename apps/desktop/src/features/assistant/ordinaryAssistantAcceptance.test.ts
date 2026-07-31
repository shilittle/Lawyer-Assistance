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

import assistantWorkspaceSource from "./AssistantWorkspace.tsx?raw";
import {
  buildInteractiveProviderDisclosure,
  INTERACTIVE_PROVIDER_EGRESS_WARNING,
} from "./providerEgressDisclosure";
import { defaultAssistantRunBoundary } from "./runBoundary";
import { toggleAttachmentSelection } from "./workspaceState";

const SYNTHETIC_PROVIDER = {
  id: "provider-phase7-ordinary-synthetic",
  displayName: "Phase 7 合成模型服务",
} as const;
const SYNTHETIC_CONVERSATION_ID = "conversation-phase7-ordinary-independent";
const SYNTHETIC_ATTACHMENT = {
  attachmentId: "attachment-phase7-synthetic-contract",
  originalName: "phase7-synthetic-contract.txt",
  extension: "txt",
  detectedMime: "text/plain",
  sizeBytes: 384,
} as const;
const EXACT_QUESTION = "合同解除的一般条件是什么？";

interface InteractiveInvokeEnvelope {
  readonly request: Record<string, unknown>;
  readonly onEvent: {
    onmessage: (event: {
      runId: string;
      sequence: number;
      eventType: "delta";
      content: string;
    }) => void;
  };
}

describe("Phase 7 ordinary Assistant and explicit-attachment acceptance", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation(
      async (command: string, value: unknown) => {
        if (command !== "start_interactive_assistant_run") {
          throw new Error(`unexpected synthetic command: ${command}`);
        }
        const envelope = value as InteractiveInvokeEnvelope;
        envelope.onEvent.onmessage({
          runId: "run-phase7-ordinary-synthetic",
          sequence: 1,
          eventType: "delta",
          content: "合同解除通常需要",
        });
        envelope.onEvent.onmessage({
          runId: "run-phase7-ordinary-synthetic",
          sequence: 2,
          eventType: "delta",
          content: "法定或约定事由。",
        });
        return {
          run: {
            runId: "run-phase7-ordinary-synthetic",
            status: "succeeded",
          },
        };
      },
    );
  });

  it("selects, cancels, reselects and streams only the closed interactive request without redirecting", async () => {
    let selectedAttachmentIds = toggleAttachmentSelection(
      [],
      SYNTHETIC_ATTACHMENT.attachmentId,
    );
    expect(selectedAttachmentIds).toEqual([
      SYNTHETIC_ATTACHMENT.attachmentId,
    ]);

    const selectedDisclosure = buildInteractiveProviderDisclosure({
      provider: SYNTHETIC_PROVIDER,
      selectedAttachments: [SYNTHETIC_ATTACHMENT],
    });
    expect(selectedDisclosure.providerLabel).toBe(
      SYNTHETIC_PROVIDER.displayName,
    );
    expect(selectedDisclosure.attachmentSummary).toContain(
      "phase7-synthetic-contract.txt（text/plain，384 B）",
    );
    expect(selectedDisclosure.attachmentSummary).toContain(
      "本地提取正文发送给模型服务",
    );

    selectedAttachmentIds = toggleAttachmentSelection(
      selectedAttachmentIds,
      SYNTHETIC_ATTACHMENT.attachmentId,
    );
    expect(selectedAttachmentIds).toEqual([]);
    expect(
      buildInteractiveProviderDisclosure({
        provider: SYNTHETIC_PROVIDER,
        selectedAttachments: [],
      }).attachmentSummary,
    ).toBe("本次不发送附件正文或本地路径。");

    selectedAttachmentIds = toggleAttachmentSelection(
      selectedAttachmentIds,
      SYNTHETIC_ATTACHMENT.attachmentId,
    );
    const streamed: Array<{ sequence: number; content: string }> = [];
    await defaultAssistantRunBoundary.start(
      {
        runId: "run-phase7-ordinary-synthetic",
        conversationId: SYNTHETIC_CONVERSATION_ID,
        providerId: SYNTHETIC_PROVIDER.id,
        prompt: EXACT_QUESTION,
        attachmentIds: selectedAttachmentIds,
        projectId: "case-must-not-cross",
        privacyCaseId: "case_00000000000000000000000000000000",
        generationIds: ["generation-must-not-cross"],
        receipt: "receipt-must-not-cross",
        mcpProfileId: "mcp-must-not-cross",
        authority: "approved_case",
        classification: "case_raw",
        caseMaterialId: "material-must-not-cross",
        approvedProviderTaskRequest: "handoff-must-not-cross",
      } as never,
      (event) => {
        if (event.eventType === "delta") {
          streamed.push({
            sequence: event.sequence,
            content: event.content,
          });
        }
      },
    );

    expect(streamed).toEqual([
      { sequence: 1, content: "合同解除通常需要" },
      { sequence: 2, content: "法定或约定事由。" },
    ]);
    expect(invoke).toHaveBeenCalledTimes(1);
    const [command, rawEnvelope] = invoke.mock.calls[0] as [
      string,
      InteractiveInvokeEnvelope,
    ];
    expect(command).toBe("start_interactive_assistant_run");
    expect(rawEnvelope.request).toEqual({
      runId: "run-phase7-ordinary-synthetic",
      conversationId: SYNTHETIC_CONVERSATION_ID,
      providerId: SYNTHETIC_PROVIDER.id,
      prompt: EXACT_QUESTION,
      attachmentIds: [SYNTHETIC_ATTACHMENT.attachmentId],
    });

    const requestWire = JSON.stringify(rawEnvelope.request);
    for (const forbidden of [
      "projectId",
      "privacyCaseId",
      "generationIds",
      "receipt",
      "mcpProfileId",
      "authority",
      "classification",
      "caseMaterialId",
      "approvedProviderTaskRequest",
      "must-not-cross",
    ]) {
      expect(requestWire).not.toContain(forbidden);
    }

    const ordinaryRunSource = assistantWorkspaceSource.slice(
      assistantWorkspaceSource.indexOf("async function performRun("),
      assistantWorkspaceSource.indexOf(
        "async function openProtectedArtifactRegeneration(",
      ),
    );
    expect(ordinaryRunSource).toContain("runBoundary.start({");
    expect(ordinaryRunSource).not.toMatch(
      /navigateFromShell|redirectLegacyEgressToApprovedProvider|onOpenApprovedProvider|onOpenCaseMaterials|CaseMaterial/u,
    );
  });

  it("keeps the Provider warning mounted with and without a loaded conversation", () => {
    expect(INTERACTIVE_PROVIDER_EGRESS_WARNING).toBe(
      "内容将通过 API 发送至所选模型供应商服务器。请勿输入或上传未脱敏的案件材料。案件文件请先到“案件工作台 → 材料与脱敏”处理。",
    );
    expect(
      assistantWorkspaceSource.match(/<ProviderEgressNotice/gu),
    ).toHaveLength(2);
    const composerSource = assistantWorkspaceSource.slice(
      assistantWorkspaceSource.indexOf(
        '<form className="assistant-composer"',
      ),
      assistantWorkspaceSource.indexOf(
        "</form>",
        assistantWorkspaceSource.indexOf(
          '<form className="assistant-composer"',
        ),
      ),
    );
    expect(composerSource).toContain("<ProviderEgressNotice");
    expect(composerSource).toContain("普通聊天消息");
    expect(composerSource).toContain("本次显式发送的普通附件");
  });
});
