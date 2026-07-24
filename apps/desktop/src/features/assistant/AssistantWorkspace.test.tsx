import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ProviderProfile } from "../../ipc/provider/types";
import {
  ASSISTANT_HISTORY_DISCLOSURE,
  AssistantWorkspace,
  UNVALIDATED_LIVE_DRAFT_NOTICE,
  archiveConversationWithDraftConfirmation,
  approvedProviderTaskForAssistantIntent,
  assistantRunIsIndependentPublicLegal,
  assistantWorkspaceHasUnsavedDrafts,
  attachmentDeletionFailureText,
  buildArtifactRegenerationConfirmation,
  buildAssistantProviderDisclosure,
  confirmArtifactDraftDiscard,
  confirmArtifactRegeneration,
  deleteAttachmentWithConfirmation,
} from "./AssistantWorkspace";

describe("AssistantWorkspace approved Provider routing", () => {
  it("maps every legacy assistant intent and regeneration to a fixed task", () => {
    expect(approvedProviderTaskForAssistantIntent("legal_research")).toBe(
      "case_legal_qa",
    );
    expect(approvedProviderTaskForAssistantIntent("file_analysis")).toBe(
      "case_organization",
    );
    expect(approvedProviderTaskForAssistantIntent("document_draft")).toBe(
      "document_generation",
    );
    expect(approvedProviderTaskForAssistantIntent("map_build")).toBe(
      "relationship_graph",
    );
    expect(approvedProviderTaskForAssistantIntent("case_analysis")).toBe(
      "legal_analysis",
    );
    expect(
      approvedProviderTaskForAssistantIntent("document_draft", true),
    ).toBe("regenerate");
  });

  it("routes even a completely empty independent legal-research shell to approval", () => {
    const clean = {
      intent: "legal_research" as const,
      projectId: null,
      messageCount: 0,
      artifactCount: 0,
      runCount: 0,
      selectedAttachmentCount: 0,
    };
    expect(assistantRunIsIndependentPublicLegal(clean)).toBe(false);
    expect(
      assistantRunIsIndependentPublicLegal({ ...clean, messageCount: 1 }),
    ).toBe(false);
    expect(
      assistantRunIsIndependentPublicLegal({ ...clean, artifactCount: 1 }),
    ).toBe(false);
    expect(
      assistantRunIsIndependentPublicLegal({ ...clean, projectId: "case-1" }),
    ).toBe(false);
    expect(
      assistantRunIsIndependentPublicLegal({
        ...clean,
        intent: "file_analysis",
      }),
    ).toBe(false);
  });
});

const PROVIDER: ProviderProfile = {
  id: "provider-1",
  displayName: "本地配置",
  kind: "deep_seek",
  modelId: "model-1",
  baseUrl: "https://api.example.test",
  credentialAccountId: "account-1",
  capabilities: {
    chat: true,
    streaming: false,
    customModelId: false,
    customBaseUrl: false,
    reasoning: false,
  },
  options: {},
};

describe("AssistantWorkspace static accessibility", () => {
  it("keeps independent conversations available without an active case", () => {
    const markup = renderToStaticMarkup(
      <AssistantWorkspace activeProject={null} providerProfiles={[PROVIDER]} />,
    );
    expect(markup).toContain('aria-label="办案助理工作区"');
    expect(markup).toContain('aria-label="助理会话"');
    expect(markup).toContain('aria-label="来源、成果与案件建议"');
    expect(markup).toContain("未打开案件；仍可创建独立会话");
    expect(markup).toContain("从一个独立会话开始");
    expect(markup).not.toContain("Codex");
  });

  it("labels the opt-in case binding when a case is active", () => {
    const markup = renderToStaticMarkup(
      <AssistantWorkspace
        activeProject={{ projectId: "case-1", title: "示例案件" }}
        providerProfiles={[PROVIDER]}
      />,
    );
    expect(markup).toContain("新会话绑定当前案件");
    expect(markup).toContain('type="checkbox"');
    expect(markup).toContain("正在读取会话…");
    expect(markup).toContain('disabled=""');
  });
});

describe("AssistantWorkspace destructive action guards", () => {
  it("does not archive or clear past the guard when a non-empty prompt draft is kept", async () => {
    const confirmAction = vi.fn(() => false);
    const archiveAction = vi.fn(async () => undefined);
    const onConfirmed = vi.fn();

    await expect(
      archiveConversationWithDraftConfirmation({
        conversationId: "conversation-1",
        promptDraft: "unsent legal question",
        confirmAction,
        archiveAction,
        onConfirmed,
      }),
    ).resolves.toBe(false);

    expect(confirmAction).toHaveBeenCalledWith(
      expect.stringContaining("尚未发送的任务草稿"),
    );
    expect(archiveAction).not.toHaveBeenCalled();
    expect(onConfirmed).not.toHaveBeenCalled();
  });

  it("archives after explicit confirmation and does not prompt for a blank draft", async () => {
    const confirmAction = vi.fn(() => true);
    const archiveAction = vi.fn(async () => undefined);

    await expect(
      archiveConversationWithDraftConfirmation({
        conversationId: "conversation-1",
        promptDraft: "  ",
        confirmAction,
        archiveAction,
      }),
    ).resolves.toBe(true);

    expect(confirmAction).not.toHaveBeenCalled();
    expect(archiveAction).toHaveBeenCalledWith({
      conversationId: "conversation-1",
    });
  });

  it("requires permanent-delete confirmation and sends userConfirmed only after acceptance", async () => {
    const attachment = {
      attachmentId: "attachment-1",
      originalName: "signed-agreement.pdf",
    };
    const deleteAction = vi.fn(async () => undefined);

    await expect(
      deleteAttachmentWithConfirmation({
        conversationId: "conversation-1",
        attachment,
        confirmAction: () => false,
        deleteAction,
      }),
    ).resolves.toBe(false);
    expect(deleteAction).not.toHaveBeenCalled();

    await expect(
      deleteAttachmentWithConfirmation({
        conversationId: "conversation-1",
        attachment,
        confirmAction: () => true,
        deleteAction,
      }),
    ).resolves.toBe(true);
    expect(deleteAction).toHaveBeenCalledTimes(1);
    expect(deleteAction).toHaveBeenCalledWith({
      conversationId: "conversation-1",
      attachmentId: "attachment-1",
      userConfirmed: true,
    });
  });

  it("keeps an in-use attachment deletion failure visible and actionable", () => {
    expect(
      attachmentDeletionFailureText(
        new Error("attachment is still referenced by an artifact"),
      ),
    ).toBe("附件删除失败：操作未完成，请重试；如仍失败，请导出诊断报告。");
  });

  it("merges prompt and artifact editor dirty state for the parent guard", () => {
    expect(assistantWorkspaceHasUnsavedDrafts({}, false)).toBe(false);
    expect(
      assistantWorkspaceHasUnsavedDrafts({ "conversation-1": " draft " }, false),
    ).toBe(true);
    expect(assistantWorkspaceHasUnsavedDrafts({}, true)).toBe(true);
  });

  it("does not switch conversations or artifacts when an artifact edit is kept", async () => {
    const confirmAction = vi.fn(() => false);
    expect(
      confirmArtifactDraftDiscard({
        artifactDraftDirty: true,
        action: "切换会话",
        confirmAction,
      }),
    ).toBe(false);
    expect(confirmAction).toHaveBeenCalledWith(
      expect.stringContaining("切换会话会永久丢弃"),
    );

    const archiveAction = vi.fn(async () => undefined);
    await expect(
      archiveConversationWithDraftConfirmation({
        conversationId: "conversation-1",
        promptDraft: "",
        artifactDraftDirty: true,
        confirmAction: () => false,
        archiveAction,
      }),
    ).resolves.toBe(false);
    expect(archiveAction).not.toHaveBeenCalled();
  });
});

describe("AssistantWorkspace provider and regeneration disclosure", () => {
  it("states the exact provider, history, attachment, case, and off-device scope", () => {
    const disclosure = buildAssistantProviderDisclosure({
      provider: PROVIDER,
      intent: "document_draft",
      attachmentPolicyAccepts: true,
      selectedAttachments: [
        {
          originalName: "evidence.pdf",
          extension: "pdf",
          sizeBytes: 1536,
        },
      ],
      intentUsesCase: true,
      boundCaseLabel: "示例案件",
    });
    const text = [disclosure.target, ...disclosure.items].join("\n");

    expect(disclosure.target).toBe("本地配置");
    expect(text).toContain(ASSISTANT_HISTORY_DISCLOSURE);
    expect(text).toContain(
      "发送所选附件的提取正文：evidence.pdf（PDF，1.5 KB）；不发送本地路径。",
    );
    expect(text).toContain("生成版本化成果");
    expect(text).toContain("示例案件");
    expect(text).toContain("已确认案件数据");
    expect(text).toContain("会离开本机");
    expect(text).toContain("留存及是否用于训练");
    expect(text).not.toContain("model-1");
    expect(text).not.toContain("https://api.example.test");
  });

  it("makes regeneration confirmation cancellation explicit and append-only", () => {
    const options = {
      artifactTitle: "付款风险分析",
      sourceVersionNumber: 3,
      provider: PROVIDER,
    };
    const message = buildArtifactRegenerationConfirmation(options);
    expect(message).toContain("模型服务“本地配置”");
    expect(message).toContain("当前会话的必要摘要");
    expect(message).not.toContain("model-1");
    expect(message).not.toContain("https://api.example.test");
    expect(message).toContain("留存及是否用于训练");
    expect(message).toContain("只追加新版本，不覆盖或删除旧版");

    const cancel = vi.fn(() => false);
    const accept = vi.fn(() => true);
    expect(confirmArtifactRegeneration(options, cancel)).toBe(false);
    expect(confirmArtifactRegeneration(options, accept)).toBe(true);
    expect(cancel).toHaveBeenCalledWith(message);
    expect(accept).toHaveBeenCalledWith(message);
  });

  it("labels streaming text as an unvalidated and unsaved draft", () => {
    expect(UNVALIDATED_LIVE_DRAFT_NOTICE).toBe(
      "正在生成并校验内容；完成前不会显示未经确认的草稿。",
    );
  });
});
