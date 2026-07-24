/* eslint-disable react-refresh/only-export-components -- keep the tested disclosure and destructive-action guards next to the component paths that consume them */
import {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  ArtifactPanel,
  type ArtifactRegenerationRequest,
} from "../artifacts/ArtifactPanel";
import { SafeArtifactMarkdown } from "../artifacts/SafeArtifactMarkdown";
import {
  AssistantIpcClientError,
  archiveAssistantConversation,
  bindAssistantConversation,
  createAssistantConversation,
  deleteAssistantAttachment,
  getAssistantConversation,
  importAssistantFiles,
  listAssistantConversations,
} from "../../ipc/assistant/client";
import type {
  AssistantArtifact,
  AssistantAttachment,
  AssistantCapabilityName,
  AssistantConversation,
  AssistantConversationDetail,
  AssistantMessage,
  AssistantRun,
  AssistantRunEvent,
  AssistantRegenerationTarget,
  AssistantRunStreamStatus,
  AssistantRunStreamUsage,
  AssistantRunStatus,
  AssistantRunToolEventStatus,
} from "../../ipc/assistant/types";
import {
  getProviderApiKeyStatus,
  listProviderProfiles,
} from "../../ipc/provider/client";
import type { ProviderProfile } from "../../ipc/provider/types";
import type { ApprovedProviderTask } from "../../ipc/privacy/types";
import { publicErrorMessage, publicTitle } from "../../publicOutput";
import {
  ASSISTANT_RUN_INTENT_LABELS,
  advanceAssistantRunEventCursor,
  applyAssistantCancellationResult,
  assistantAttachmentPolicy,
  createAssistantRunId,
  defaultAssistantRunBoundary,
  type AssistantRunBoundary,
  type AssistantRunIntent,
} from "./runBoundary";
import {
  INITIAL_ASSISTANT_WORKSPACE_STATE,
  assistantWorkspaceReducer,
  clearPromptDraftIfUnchanged,
  replaceRunIfCurrent,
  toggleAttachmentSelection,
} from "./workspaceState";
import "./assistant.css";

export interface AssistantProjectContext {
  projectId: string;
  title: string;
}

export interface AssistantWorkspaceProps {
  activeProject: AssistantProjectContext | null;
  caseHandoff?: (AssistantProjectContext & { requestId: number }) | null;
  externalRefreshKey?: number;
  providerProfiles?: readonly ProviderProfile[];
  onConversationChange?: (conversation: AssistantConversation | null) => void;
  onDraftDirtyChange?: (dirty: boolean) => void;
  onCaseProposalApplied?: (projectId: string) => void;
  onMutationActivityChange?: (active: boolean) => void;
  onOpenApprovedProvider?: (
    task: ApprovedProviderTask,
    notice: string,
  ) => void;
  onOpenProviderSettings?: () => void;
  onRunActivityChange?: (active: boolean) => void;
  proposalApplyBlockedReason?: string | null;
  runBoundary?: AssistantRunBoundary;
}

export function approvedProviderTaskForAssistantIntent(
  intent: AssistantRunIntent,
  regenerating = false,
): ApprovedProviderTask {
  if (regenerating) return "regenerate";
  switch (intent) {
    case "legal_research":
      return "case_legal_qa";
    case "file_analysis":
      return "case_organization";
    case "document_draft":
      return "document_generation";
    case "map_build":
      return "relationship_graph";
    case "case_analysis":
      return "legal_analysis";
  }
}

export function assistantRunIsIndependentPublicLegal(input: {
  intent: AssistantRunIntent;
  projectId: string | null;
  messageCount: number;
  artifactCount: number;
  runCount: number;
  selectedAttachmentCount: number;
}): boolean {
  void input;
  // User-authored free text has no trustworthy public provenance. The legacy Assistant never
  // sends it directly, even when the surrounding conversation shell appears empty.
  return false;
}

const RUN_INTENTS = Object.keys(
  ASSISTANT_RUN_INTENT_LABELS,
) as AssistantRunIntent[];

interface ActiveAssistantRun {
  runId: string;
  conversationId: string;
  epoch: number;
  lastSequence: number;
  cancelling: boolean;
  status: AssistantRunStreamStatus;
  liveText: string;
  usage: AssistantRunStreamUsage | null;
  tools: Array<{
    toolCallId: string;
    capabilityName: AssistantCapabilityName;
    status: AssistantRunToolEventStatus;
  }>;
  streamError: string | null;
}

type ConfirmationAction = (message: string) => boolean;

export const UNVALIDATED_LIVE_DRAFT_NOTICE =
  "正在生成并校验内容；完成前不会显示未经确认的草稿。";

export const ASSISTANT_HISTORY_DISCLOSURE =
  "最多发送同一会话最近 24 条、合计 32 KiB 的持久化消息摘要上下文；成果只发送引用元数据，不读取隐藏原始响应，也不读取其他会话。";

export function assistantWorkspaceHasUnsavedDrafts(
  promptDrafts: Readonly<Record<string, string>>,
  artifactDraftDirty: boolean,
): boolean {
  return (
    artifactDraftDirty ||
    Object.values(promptDrafts).some((draft) => draft.trim().length > 0)
  );
}

export function confirmArtifactDraftDiscard(options: {
  artifactDraftDirty: boolean;
  action: string;
  confirmAction?: ConfirmationAction;
}): boolean {
  const {
    artifactDraftDirty,
    action,
    confirmAction = (message) => window.confirm(message),
  } = options;
  return (
    !artifactDraftDirty ||
    confirmAction(
      `当前成果有尚未保存的编辑。${action}会永久丢弃这些修改，确定继续吗？`,
    )
  );
}

export async function archiveConversationWithDraftConfirmation(options: {
  conversationId: string;
  promptDraft: string;
  artifactDraftDirty?: boolean;
  confirmAction?: ConfirmationAction;
  archiveAction?: (request: { conversationId: string }) => Promise<unknown>;
  onConfirmed?: () => void;
}): Promise<boolean> {
  const {
    conversationId,
    promptDraft,
    artifactDraftDirty = false,
    confirmAction = (message) => window.confirm(message),
    archiveAction = archiveAssistantConversation,
    onConfirmed,
  } = options;
  const hasPromptDraft = promptDraft.trim().length > 0;
  if (hasPromptDraft || artifactDraftDirty) {
    const unsavedDescription =
      hasPromptDraft && artifactDraftDirty
        ? "尚未发送的任务草稿和未保存的成果编辑"
        : hasPromptDraft
          ? "尚未发送的任务草稿"
          : "未保存的成果编辑";
    if (
      !confirmAction(
        `当前会话有${unsavedDescription}。归档会话会永久丢弃这些内容；仍要归档吗？`,
      )
    ) {
      return false;
    }
  }
  onConfirmed?.();
  await archiveAction({ conversationId });
  return true;
}

export async function deleteAttachmentWithConfirmation(options: {
  conversationId: string;
  attachment: Pick<AssistantAttachment, "attachmentId" | "originalName">;
  confirmAction?: ConfirmationAction;
  deleteAction?: (request: {
    conversationId: string;
    attachmentId: string;
    userConfirmed: true;
  }) => Promise<unknown>;
  onConfirmed?: () => void;
}): Promise<boolean> {
  const {
    conversationId,
    attachment,
    confirmAction = (message) => window.confirm(message),
    deleteAction = deleteAssistantAttachment,
    onConfirmed,
  } = options;
  const confirmed = confirmAction(
    `永久删除“${attachment.originalName}”及其本地导入正文？此操作不可撤销。若该附件仍被其他消息、成果、案件材料或案件建议引用，系统会拒绝删除并保留现状。`,
  );
  if (!confirmed) return false;
  onConfirmed?.();
  await deleteAction({
    conversationId,
    attachmentId: attachment.attachmentId,
    userConfirmed: true,
  });
  return true;
}

export function attachmentDeletionFailureText(error: unknown): string {
  return `附件删除失败：${displayError(error)}`;
}

export function buildArtifactRegenerationConfirmation(options: {
  artifactTitle: string;
  sourceVersionNumber: number;
  provider: Pick<ProviderProfile, "displayName">;
}): string {
  const { artifactTitle, sourceVersionNumber, provider } = options;
  return `将把“${artifactTitle}”第 ${sourceVersionNumber} 版的正文、当前会话的必要摘要以及该任务依法需要的材料发送到模型服务“${provider.displayName}”。这些内容会离开本机；留存及是否用于训练由该服务条款决定。成功后只追加新版本，不覆盖或删除旧版。继续吗？`;
}

export function confirmArtifactRegeneration(
  options: Parameters<typeof buildArtifactRegenerationConfirmation>[0],
  confirmAction: ConfirmationAction = (message) => window.confirm(message),
): boolean {
  return confirmAction(buildArtifactRegenerationConfirmation(options));
}

export function buildAssistantProviderDisclosure(options: {
  provider: ProviderProfile | undefined;
  intent: AssistantRunIntent;
  attachmentPolicyAccepts: boolean;
  selectedAttachments: readonly Pick<
    AssistantAttachment,
    "originalName" | "extension" | "sizeBytes"
  >[];
  intentUsesCase: boolean;
  boundCaseLabel: string | null;
}): { target: string; items: string[] } {
  const {
    provider,
    intent,
    attachmentPolicyAccepts,
    selectedAttachments,
    intentUsesCase,
    boundCaseLabel,
  } = options;
  const intentDisclosure =
    intent === "case_analysis"
      ? "本次只读取已确认案件数据，并最多生成一份待审阅的案件建议；不会直接写入案件。"
      : intent === "document_draft" || intent === "map_build"
        ? "本次生成版本化成果；不会直接修改案件数据。"
        : intent === "legal_research"
          ? "本次只读检索本地法律库，并保存附有完整法条依据的研究成果。"
          : "本次只读分析所选材料并保存回答；不会直接修改案件数据。";
  const selectedAttachmentLabels = selectedAttachments.map(
    (attachment) =>
      `${attachment.originalName}（${attachment.extension.toUpperCase()}，${byteSize(attachment.sizeBytes)}）`,
  );
  const items = [
    intentDisclosure,
    "发送你在上方填写的任务文本。",
    ASSISTANT_HISTORY_DISCLOSURE,
    attachmentPolicyAccepts && selectedAttachmentLabels.length > 0
      ? `发送所选附件的提取正文：${selectedAttachmentLabels.join("、")}；不发送本地路径。`
      : "不发送附件正文或本地路径。",
    intentUsesCase
      ? `发送“${boundCaseLabel}”范围内的已确认案件数据；不发送待确认草稿。`
      : "不发送案件数据。",
    intent === "legal_research"
      ? "本地检索完成后，会发送命中的法律条文片段用于生成受引用约束的回答。"
      : "本任务不会自动附加法律检索结果。",
    "所选任务文本、附件提取正文、案件确认数据或法律片段会离开本机；服务地域、留存及是否用于训练由目标模型服务的条款与配置决定。",
  ];
  if (provider?.kind === "custom") {
    items.push(
      `自定义模型服务的私网访问：${
        provider.options.allowPrivateNetwork
          ? "已显式允许 localhost/私网/链路本地地址（高风险）。"
          : "未允许私网地址。"
      }`,
    );
  }
  return {
    target: provider
      ? provider.displayName
      : "尚未选择模型服务",
    items,
  };
}

function displayError(error: unknown): string {
  return publicErrorMessage(error);
}

function dateTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN");
}

function byteSize(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function truncateUtf8(value: string, maxBytes: number): string {
  let result = "";
  for (const character of value) {
    if (utf8ByteLength(result + character) > maxBytes) break;
    result += character;
  }
  return result;
}

function runStatusLabel(status: AssistantRunStatus): string {
  switch (status) {
    case "queued":
      return "排队中";
    case "running":
      return "运行中";
    case "succeeded":
      return "已完成";
    case "failed":
      return "失败";
    case "cancelled":
      return "已取消";
  }
}

function liveStatusLabel(status: AssistantRunStreamStatus): string {
  switch (status) {
    case "accepted":
      return "任务已接收";
    case "preparing":
      return "正在准备受限上下文";
    case "running":
      return "正在执行";
    case "finalizing":
      return "正在校验并保存";
    case "completed":
      return "已完成";
    case "cancelled":
      return "已取消";
  }
}

function roleLabel(role: AssistantMessage["role"]): string {
  switch (role) {
    case "user":
      return "你";
    case "assistant":
      return "助理";
    case "system":
      return "系统";
    case "tool":
      return "本地工具";
  }
}

function uniqueAttachments(detail: AssistantConversationDetail): AssistantAttachment[] {
  const unique = new Map<string, AssistantAttachment>();
  for (const message of detail.messages) {
    for (const attachment of message.attachments) {
      unique.set(attachment.attachmentId, attachment);
    }
  }
  return [...unique.values()].sort((left, right) =>
    right.createdAt.localeCompare(left.createdAt),
  );
}

function MessageCard({
  message,
  onSelectArtifact,
}: {
  message: AssistantMessage;
  onSelectArtifact: (artifactId: string) => void;
}) {
  if (message.role === "system" || message.role === "tool") return null;
  return (
    <article className={`assistant-message assistant-message--${message.role}`}>
      <header>
        <strong>{roleLabel(message.role)}</strong>
        <time dateTime={message.createdAt}>{dateTime(message.createdAt)}</time>
      </header>
      {message.role === "assistant" ? (
        <SafeArtifactMarkdown markdown={message.textSummary} label="助理消息" />
      ) : (
        <p>{message.textSummary}</p>
      )}
      {message.attachments.length > 0 ? (
        <ul className="assistant-message-attachments" aria-label="此消息的附件">
          {message.attachments.map((attachment) => (
            <li key={attachment.attachmentId}>
              {attachment.originalName} · {byteSize(attachment.sizeBytes)} ·{" "}
              {attachment.extractionStatus === "succeeded" ? "已提取" : "不可用于分析"}
            </li>
          ))}
        </ul>
      ) : null}
      {message.kind === "artifact_ref" && message.artifactId ? (
        <button type="button" onClick={() => onSelectArtifact(message.artifactId!)}>
          打开关联成果
        </button>
      ) : null}
    </article>
  );
}

function RunTimeline({
  runs,
}: {
  runs: AssistantRun[];
}) {
  if (runs.length === 0) return null;
  return (
    <details className="assistant-run-timeline">
      <summary>任务记录（{runs.length}）</summary>
      <ol>
        {[...runs]
          .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
          .map((run) => {
            const intent = RUN_INTENTS.includes(run.intent as AssistantRunIntent)
              ? ASSISTANT_RUN_INTENT_LABELS[run.intent as AssistantRunIntent]
              : "助理任务";
            return (
              <li key={run.runId}>
                <header>
                  <strong>{intent}</strong>
                  <span data-run-status={run.status}>{runStatusLabel(run.status)}</span>
                </header>
                <p>开始于 {dateTime(run.createdAt)}</p>
              </li>
            );
          })}
      </ol>
    </details>
  );
}

function LiveRunProgress({ run }: { run: ActiveAssistantRun }) {
  return (
    <section className="assistant-run-timeline" aria-live="polite" aria-label="助理实时进度">
      <strong>{liveStatusLabel(run.status)}</strong>
      <p className="assistant-muted" role="note">
        {UNVALIDATED_LIVE_DRAFT_NOTICE}
      </p>
      {run.tools.length > 0 ? (
        <p className="assistant-muted">正在读取并校验本地资料。</p>
      ) : null}
      {run.liveText ? (
        <p className="assistant-muted">内容正在生成并校验，完成后将在会话和成果区显示。</p>
      ) : null}
      {run.streamError ? (
        <p className="assistant-problem">
          {publicErrorMessage(run.streamError, "助理处理未完成，请重试。")}
        </p>
      ) : null}
    </section>
  );
}

export function AssistantWorkspace({
  activeProject,
  caseHandoff = null,
  externalRefreshKey = 0,
  providerProfiles,
  onConversationChange,
  onDraftDirtyChange,
  onCaseProposalApplied,
  onMutationActivityChange,
  onOpenApprovedProvider,
  onOpenProviderSettings,
  onRunActivityChange,
  proposalApplyBlockedReason,
  runBoundary = defaultAssistantRunBoundary,
}: AssistantWorkspaceProps) {
  const [state, dispatch] = useReducer(
    assistantWorkspaceReducer,
    INITIAL_ASSISTANT_WORKSPACE_STATE,
  );
  const [providersLoaded, setProvidersLoaded] = useState<ProviderProfile[]>([]);
  const [conversationListLoaded, setConversationListLoaded] = useState(false);
  const providers = providerProfiles ?? providersLoaded;
  const [providerStatuses, setProviderStatuses] = useState<
    Record<string, boolean | null>
  >({});
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [artifactDraftDirty, setArtifactDraftDirty] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [bindNewConversation, setBindNewConversation] = useState(
    activeProject !== null,
  );
  const [intent, setIntent] = useState<AssistantRunIntent>("legal_research");
  const [promptDrafts, setPromptDrafts] = useState<Record<string, string>>({});
  const [selectedAttachmentIds, setSelectedAttachmentIds] = useState<string[]>([]);
  const [activeRun, setActiveRun] = useState<ActiveAssistantRun | null>(null);
  const [notice, setNotice] = useState<{
    conversationId: string | null;
    kind: "status" | "error";
    text: string;
  } | null>(null);
  const [operation, setOperation] = useState<
    "create" | "archive" | "bind" | "import" | "delete" | null
  >(null);
  const [artifactMutationActive, setArtifactMutationActive] = useState(false);
  const detailEpoch = useRef(0);
  const runEpoch = useRef(0);
  const handledCaseHandoff = useRef<number | null>(null);
  const latestCaseHandoffRequest = useRef<number | null>(null);
  const lastExternalRefreshKey = useRef(externalRefreshKey);
  const selectedConversationRef = useRef<string | null>(null);
  const selectedArtifactIdRef = useRef<string | null>(selectedArtifactId);
  const artifactDraftDirtyRef = useRef(false);
  const mounted = useRef(true);
  latestCaseHandoffRequest.current = caseHandoff?.requestId ?? null;
  selectedArtifactIdRef.current = selectedArtifactId;

  const updateArtifactDraftDirty = useCallback((dirty: boolean) => {
    artifactDraftDirtyRef.current = dirty;
    setArtifactDraftDirty(dirty);
  }, []);

  useEffect(() => {
    selectedConversationRef.current = state.selectedConversationId;
  }, [state.selectedConversationId]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const loadConversation = useCallback(
    (
      conversationId: string | null,
      options: { discardAlreadyConfirmed?: boolean } = {},
    ): boolean => {
      const sameConversation =
        selectedConversationRef.current === conversationId;
      if (
        !sameConversation &&
        !options.discardAlreadyConfirmed &&
        !confirmArtifactDraftDiscard({
          artifactDraftDirty: artifactDraftDirtyRef.current,
          action: "切换会话",
        })
      ) {
        return false;
      }
      const epoch = detailEpoch.current + 1;
      detailEpoch.current = epoch;
      selectedConversationRef.current = conversationId;
      dispatch({ type: "select_conversation", conversationId, epoch });
      setSelectedAttachmentIds([]);
      if (!sameConversation) {
        updateArtifactDraftDirty(false);
        selectedArtifactIdRef.current = null;
        setSelectedArtifactId(null);
      }
      if (!conversationId) return true;
      void getAssistantConversation({ conversationId })
        .then((response) => {
          if (!mounted.current) return;
          dispatch({
            type: "detail_loaded",
            conversationId,
            epoch,
            detail: response.detail,
          });
        })
        .catch((error: unknown) => {
          if (!mounted.current) return;
          dispatch({
            type: "detail_failed",
            conversationId,
            epoch,
            message: displayError(error),
          });
        });
      return true;
    },
    [updateArtifactDraftDirty],
  );

  const selectArtifact = useCallback(
    (artifactId: string | null): boolean => {
      if (selectedArtifactIdRef.current === artifactId) return true;
      if (
        !confirmArtifactDraftDiscard({
          artifactDraftDirty: artifactDraftDirtyRef.current,
          action: "切换成果",
        })
      ) {
        return false;
      }
      updateArtifactDraftDirty(false);
      selectedArtifactIdRef.current = artifactId;
      setSelectedArtifactId(artifactId);
      return true;
    },
    [updateArtifactDraftDirty],
  );

  const refreshConversation = useCallback(() => {
    loadConversation(selectedConversationRef.current);
  }, [loadConversation]);

  useEffect(() => {
    let cancelled = false;
    void listAssistantConversations({ includeArchived: false, limit: 100 })
      .then((response) => {
        if (cancelled) return;
        setConversationListLoaded(true);
        dispatch({ type: "replace_conversations", conversations: response.conversations });
        if (!selectedConversationRef.current && response.conversations[0]) {
          loadConversation(response.conversations[0].conversationId);
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setConversationListLoaded(true);
        setNotice({ conversationId: null, kind: "error", text: `会话列表读取失败：${displayError(error)}` });
      });
    return () => {
      cancelled = true;
    };
  }, [loadConversation]);

  useEffect(() => {
    if (providerProfiles !== undefined) return;
    let cancelled = false;
    void listProviderProfiles()
      .then((response) => {
        if (!cancelled) setProvidersLoaded(response.profiles);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setNotice({ conversationId: null, kind: "error", text: `模型服务列表读取失败：${displayError(error)}` });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [providerProfiles]);

  useEffect(() => {
    let cancelled = false;
    setProviderStatuses(
      Object.fromEntries(providers.map((provider) => [provider.id, null])),
    );
    void Promise.allSettled(
      providers.map(async (provider) => {
        const response = await getProviderApiKeyStatus({
          providerId: provider.id,
          accountId: provider.credentialAccountId,
        });
        return [provider.id, response.status.configured] as const;
      }),
    )
      .then((results) => {
        if (cancelled) return;
        const entries = results.map((result, index) =>
          result.status === "fulfilled"
            ? result.value
            : ([providers[index].id, false] as const),
        );
        setProviderStatuses(Object.fromEntries(entries));
      });
    return () => {
      cancelled = true;
    };
  }, [providers]);

  useEffect(() => {
    if (providers.some((provider) => provider.id === selectedProviderId)) return;
    setSelectedProviderId(providers[0]?.id ?? "");
  }, [providers, selectedProviderId]);

  const detail =
    state.detail?.conversation.conversationId === state.selectedConversationId
      ? state.detail
      : null;
  const prompt = state.selectedConversationId
    ? promptDrafts[state.selectedConversationId] ?? ""
    : "";
  const selectedConversation =
    state.conversations.find(
      (conversation) => conversation.conversationId === state.selectedConversationId,
    ) ?? null;

  useEffect(() => {
    onConversationChange?.(selectedConversation);
  }, [onConversationChange, selectedConversation]);

  useEffect(() => {
    onRunActivityChange?.(activeRun !== null);
  }, [activeRun, onRunActivityChange]);

  useEffect(() => {
    onMutationActivityChange?.(operation !== null || artifactMutationActive);
  }, [artifactMutationActive, onMutationActivityChange, operation]);

  useEffect(() => {
    onDraftDirtyChange?.(
      assistantWorkspaceHasUnsavedDrafts(promptDrafts, artifactDraftDirty),
    );
  }, [artifactDraftDirty, onDraftDirtyChange, promptDrafts]);

  useEffect(
    () => () => {
      onConversationChange?.(null);
      onDraftDirtyChange?.(false);
      onMutationActivityChange?.(false);
      onRunActivityChange?.(false);
    },
    [
      onConversationChange,
      onDraftDirtyChange,
      onMutationActivityChange,
      onRunActivityChange,
    ],
  );

  useEffect(() => {
    if (lastExternalRefreshKey.current === externalRefreshKey) return;
    lastExternalRefreshKey.current = externalRefreshKey;
    refreshConversation();
  }, [externalRefreshKey, refreshConversation]);

  useEffect(() => {
    if (
      !caseHandoff ||
      !conversationListLoaded ||
      operation !== null ||
      handledCaseHandoff.current === caseHandoff.requestId
    ) {
      return;
    }
    handledCaseHandoff.current = caseHandoff.requestId;
    const existing = state.conversations.find(
      (conversation) => conversation.projectId === caseHandoff.projectId,
    );
    if (existing) {
      if (!loadConversation(existing.conversationId)) {
        setNotice({
          conversationId: selectedConversationRef.current,
          kind: "status",
          text: `已取消打开案件“${publicTitle(caseHandoff.title, "当前案件")}”的助理会话；未保存的成果编辑仍保留。`,
        });
        return;
      }
      setNotice({
        conversationId: existing.conversationId,
        kind: "status",
        text: `已打开案件“${publicTitle(caseHandoff.title, "当前案件")}”的助理会话。`,
      });
      return;
    }

    setOperation("create");
    setNotice(null);
    void createAssistantConversation({
      title: truncateUtf8(`${publicTitle(caseHandoff.title, "当前案件")} · 助理`, 256),
      projectId: caseHandoff.projectId,
    })
      .then((response) => {
        if (!mounted.current) return;
        dispatch({ type: "upsert_conversation", conversation: response.conversation });
        if (latestCaseHandoffRequest.current !== caseHandoff.requestId) return;
        if (!loadConversation(response.conversation.conversationId)) {
          setNotice({
            conversationId: selectedConversationRef.current,
            kind: "status",
            text: `已为案件“${publicTitle(caseHandoff.title, "当前案件")}”创建助理会话；因保留未保存的成果编辑，仍停留在当前会话。`,
          });
          return;
        }
        setNotice({
          conversationId: response.conversation.conversationId,
          kind: "status",
          text: `已创建并绑定案件“${publicTitle(caseHandoff.title, "当前案件")}”的助理会话。`,
        });
      })
      .catch((error: unknown) => {
        if (!mounted.current) return;
        setNotice({
          conversationId: null,
          kind: "error",
          text: `打开案件助理会话失败：${displayError(error)}`,
        });
      })
      .finally(() => {
        if (mounted.current) {
          setOperation((current) => (current === "create" ? null : current));
        }
      });
  }, [
    caseHandoff,
    conversationListLoaded,
    loadConversation,
    operation,
    state.conversations,
  ]);
  const attachments = useMemo(
    () => (detail ? uniqueAttachments(detail) : []),
    [detail],
  );
  const selectableAttachmentIds = useMemo(
    () =>
      new Set(
        attachments
          .filter((attachment) => attachment.extractionStatus === "succeeded")
          .map((attachment) => attachment.attachmentId),
      ),
    [attachments],
  );

  useEffect(() => {
    setSelectedAttachmentIds((current) =>
      current.filter((attachmentId) => selectableAttachmentIds.has(attachmentId)),
    );
  }, [selectableAttachmentIds]);

  useEffect(() => {
    if (!detail) return;
    if (
      selectedArtifactId &&
      detail.artifacts.some((artifact) => artifact.artifactId === selectedArtifactId)
    ) {
      return;
    }
    selectArtifact(detail.artifacts[0]?.artifactId ?? null);
  }, [detail, selectArtifact, selectedArtifactId]);

  const selectedProvider = providers.find(
    (provider) => provider.id === selectedProviderId,
  );
  const selectedProviderConfigured = selectedProvider
    ? providerStatuses[selectedProvider.id]
    : false;
  const conversationProjectId = detail?.conversation.projectId ?? null;
  const attachmentPolicy = assistantAttachmentPolicy(
    intent,
    conversationProjectId !== null,
  );
  const requiredAttachmentsMissing =
    attachmentPolicy.requires && selectedAttachmentIds.length === 0;
  const intentUsesCase = Boolean(
    conversationProjectId &&
      (intent === "case_analysis" ||
        intent === "document_draft" ||
        intent === "map_build"),
  );
  const boundCaseLabel = conversationProjectId
    ? activeProject?.projectId === conversationProjectId
      ? publicTitle(activeProject.title, "当前案件")
      : "已绑定的其他案件"
    : null;
  const selectedAttachments = attachments.filter((attachment) =>
    selectedAttachmentIds.includes(attachment.attachmentId),
  );
  const providerDisclosure = buildAssistantProviderDisclosure({
    provider: selectedProvider,
    intent,
    attachmentPolicyAccepts: attachmentPolicy.accepts,
    selectedAttachments,
    intentUsesCase,
    boundCaseLabel,
  });
  useEffect(() => {
    if (!attachmentPolicy.accepts) setSelectedAttachmentIds([]);
  }, [attachmentPolicy.accepts]);
  const activeRunForConversation =
    activeRun?.conversationId === state.selectedConversationId ? activeRun : null;
  const currentNotice =
    notice &&
    (notice.conversationId === null ||
      notice.conversationId === state.selectedConversationId)
      ? notice
      : null;
  const caseIntentWithoutCase = intent === "case_analysis" && !conversationProjectId;
  const independentPublicLegalShell = Boolean(
    detail &&
      assistantRunIsIndependentPublicLegal({
        intent,
        projectId: detail.conversation.projectId,
        messageCount: detail.messages.length,
        artifactCount: detail.artifacts.length,
        runCount: detail.runs.length,
        selectedAttachmentCount: selectedAttachmentIds.length,
      }),
  );
  const routesToApprovedProvider = Boolean(
    detail &&
      prompt.trim() &&
      !activeRun &&
      !independentPublicLegalShell &&
      onOpenApprovedProvider,
  );
  const canSend = Boolean(
    detail &&
      prompt.trim() &&
      !activeRun &&
      (routesToApprovedProvider ||
        (selectedProvider &&
          selectedProviderConfigured === true &&
          !caseIntentWithoutCase &&
          !requiredAttachmentsMissing)),
  );

  async function createConversation(event: FormEvent) {
    event.preventDefault();
    if (operation !== null || !conversationListLoaded) return;
    const title = newTitle.trim() || "新助理会话";
    const selectionAtStart = selectedConversationRef.current;
    const detailEpochAtStart = detailEpoch.current;
    setOperation("create");
    setNotice(null);
    try {
      const response = await createAssistantConversation({
        title,
        ...(bindNewConversation && activeProject
          ? { projectId: activeProject.projectId }
          : {}),
      });
      dispatch({ type: "upsert_conversation", conversation: response.conversation });
      setNewTitle("");
      if (
        selectedConversationRef.current === selectionAtStart &&
        detailEpoch.current === detailEpochAtStart
      ) {
        const switched = loadConversation(response.conversation.conversationId);
        if (!switched) {
          setNotice({
            conversationId: null,
            kind: "status",
            text: `会话“${response.conversation.title}”已创建；保留未保存的成果编辑和当前会话。`,
          });
        }
      } else {
        setNotice({
          conversationId: null,
          kind: "status",
          text: `会话“${response.conversation.title}”已创建；保留你后来选择的会话。`,
        });
      }
    } catch (error: unknown) {
      setNotice({ conversationId: null, kind: "error", text: `新建会话失败：${displayError(error)}` });
    } finally {
      setOperation((current) => (current === "create" ? null : current));
    }
  }

  async function archiveConversation() {
    const conversationId = state.selectedConversationId;
    if (!conversationId || operation !== null) return;
    let archiveStarted = false;
    try {
      const archived = await archiveConversationWithDraftConfirmation({
        conversationId,
        promptDraft: promptDrafts[conversationId] ?? "",
        artifactDraftDirty: artifactDraftDirtyRef.current,
        onConfirmed: () => {
          archiveStarted = true;
          setOperation("archive");
          setNotice(null);
        },
      });
      if (!archived) return;
      const next = state.conversations.find(
        (conversation) => conversation.conversationId !== conversationId,
      );
      dispatch({ type: "remove_conversation", conversationId });
      setPromptDrafts((current) => {
        if (!(conversationId in current)) return current;
        const updated = { ...current };
        delete updated[conversationId];
        return updated;
      });
      if (selectedConversationRef.current === conversationId) {
        updateArtifactDraftDirty(false);
        loadConversation(next?.conversationId ?? null, {
          discardAlreadyConfirmed: true,
        });
      }
    } catch (error: unknown) {
      setNotice({ conversationId, kind: "error", text: `归档失败：${displayError(error)}` });
    } finally {
      if (archiveStarted) {
        setOperation((current) => (current === "archive" ? null : current));
      }
    }
  }

  async function bindConversation() {
    if (!detail || !activeProject || operation !== null) return;
    const conversationId = detail.conversation.conversationId;
    setOperation("bind");
    setNotice(null);
    try {
      await bindAssistantConversation({
        conversationId,
        projectId: activeProject.projectId,
      });
      setNotice({
        conversationId,
        kind: "status",
        text: `会话已绑定到案件“${publicTitle(activeProject.title, "当前案件")}”。`,
      });
      if (selectedConversationRef.current === conversationId) {
        loadConversation(conversationId);
      }
    } catch (error: unknown) {
      setNotice({ conversationId, kind: "error", text: `绑定失败：${displayError(error)}` });
    } finally {
      setOperation((current) => (current === "bind" ? null : current));
    }
  }

  async function importFiles() {
    const conversationId = state.selectedConversationId;
    if (!conversationId || operation !== null) return;
    setOperation("import");
    setNotice(null);
    try {
      const response = await importAssistantFiles({ conversationId });
      if (response.cancelled) {
        setNotice({ conversationId, kind: "status", text: "已取消导入。" });
      } else {
        const duplicate = response.duplicateCount
          ? `，其中 ${response.duplicateCount} 个已存在`
          : "";
        setNotice({ conversationId, kind: "status", text: `已导入 ${response.attachments.length} 个附件${duplicate}。` });
        if (selectedConversationRef.current === conversationId) {
          loadConversation(conversationId);
        }
      }
    } catch (error: unknown) {
      setNotice({ conversationId, kind: "error", text: `材料导入失败：${displayError(error)}` });
    } finally {
      setOperation((current) => (current === "import" ? null : current));
    }
  }

  async function deleteAttachment(attachment: AssistantAttachment) {
    const conversationId = state.selectedConversationId;
    if (!conversationId || operation !== null || activeRun !== null) return;
    let deleteStarted = false;
    try {
      const deleted = await deleteAttachmentWithConfirmation({
        conversationId,
        attachment,
        onConfirmed: () => {
          deleteStarted = true;
          setOperation("delete");
          setNotice(null);
        },
      });
      if (!deleted) return;
      setSelectedAttachmentIds((current) =>
        current.filter((attachmentId) => attachmentId !== attachment.attachmentId),
      );
      setNotice({
        conversationId,
        kind: "status",
        text: `已永久删除附件“${attachment.originalName}”。`,
      });
      if (selectedConversationRef.current === conversationId) {
        loadConversation(conversationId);
      }
    } catch (error: unknown) {
      setNotice({
        conversationId,
        kind: "error",
        text: attachmentDeletionFailureText(error),
      });
    } finally {
      if (deleteStarted) {
        setOperation((current) => (current === "delete" ? null : current));
      }
    }
  }

  async function performRun(options: {
    conversationId: string;
    intent: AssistantRunIntent;
    requestPrompt: string;
    attachmentIds: string[];
    saveResearchArtifact: boolean;
    regenerationTarget?: AssistantRegenerationTarget;
    promptDraftAtStart?: string;
    rethrowError?: boolean;
  }) {
    if (!selectedProvider) {
      throw new Error("尚未选择模型服务配置。");
    }
    const {
      conversationId,
      intent: runIntent,
      requestPrompt,
      attachmentIds,
      saveResearchArtifact,
      regenerationTarget,
      promptDraftAtStart,
      rethrowError = false,
    } = options;
    const runId = createAssistantRunId();
    const epoch = runEpoch.current + 1;
    runEpoch.current = epoch;
    setActiveRun({
      runId,
      conversationId,
      epoch,
      lastSequence: 0,
      cancelling: false,
      status: "accepted",
      liveText: "",
      usage: null,
      tools: [],
      streamError: null,
    });
    setNotice({ conversationId, kind: "status", text: "助理正在处理；可随时取消。" });
    try {
      const response = await runBoundary.start({
        runId,
        conversationId,
        providerId: selectedProvider.id,
        intent: runIntent,
        prompt: requestPrompt,
        attachmentIds,
        saveResearchArtifact,
        ...(regenerationTarget ? { regenerationTarget } : {}),
      }, (streamEvent: AssistantRunEvent) => {
        if (!mounted.current) return;
        setActiveRun((current) => {
          const advanced = advanceAssistantRunEventCursor(
            current,
            epoch,
            streamEvent,
          );
          if (!advanced) return current;
          switch (streamEvent.eventType) {
            case "status":
              return { ...advanced, status: streamEvent.status };
            case "delta":
              return {
                ...advanced,
                liveText: advanced.liveText + streamEvent.content,
              };
            case "usage":
              return { ...advanced, usage: streamEvent.usage };
            case "error":
              return {
                ...advanced,
                streamError: streamEvent.message,
                status:
                  streamEvent.errorType === "cancelled"
                    ? "cancelled"
                    : advanced.status,
              };
            case "tool": {
              const existing = advanced.tools.findIndex(
                (tool) => tool.toolCallId === streamEvent.toolCallId,
              );
              const tool = {
                toolCallId: streamEvent.toolCallId,
                capabilityName: streamEvent.capabilityName,
                status: streamEvent.status,
              };
              return {
                ...advanced,
                tools:
                  existing < 0
                    ? [...advanced.tools, tool]
                    : advanced.tools.map((currentTool, index) =>
                        index === existing ? tool : currentTool,
                      ),
              };
            }
          }
        });
      });
      if (!mounted.current) return;
      setNotice({
        conversationId,
        kind: response.run.status === "succeeded" ? "status" : "error",
        text:
          response.run.status === "succeeded"
            ? "处理完成，结果和审计记录已保存。"
            : `运行${runStatusLabel(response.run.status)}。`,
      });
      if (promptDraftAtStart !== undefined) {
        setPromptDrafts((current) =>
          clearPromptDraftIfUnchanged(
            current,
            conversationId,
            promptDraftAtStart,
          ),
        );
      }
      if (selectedConversationRef.current === conversationId) {
        setSelectedAttachmentIds([]);
        loadConversation(conversationId);
        if (response.artifact) selectArtifact(response.artifact.artifactId);
      }
    } catch (error: unknown) {
      if (!mounted.current) return;
      if (
        error instanceof AssistantIpcClientError &&
        error.errorType === "approved_provider_required" &&
        onOpenApprovedProvider
      ) {
        onOpenApprovedProvider(
          approvedProviderTaskForAssistantIntent(
            runIntent,
            regenerationTarget !== undefined,
          ),
          "用户自由文本不得从旧助理入口直接发送；已切换到脱敏工作区，并预选对应的 Approved Provider 固定任务。",
        );
        return;
      }
      const cancelled =
        error instanceof AssistantIpcClientError &&
        error.errorType === "cancelled";
      setNotice({
        conversationId,
        kind: cancelled ? "status" : "error",
        text: cancelled ? "运行已取消。" : `助理运行失败：${displayError(error)}`,
      });
      if (selectedConversationRef.current === conversationId) {
        loadConversation(conversationId);
      }
      if (rethrowError) throw error;
    } finally {
      if (mounted.current) {
        setActiveRun((current) => replaceRunIfCurrent(current, runId, null));
      }
    }
  }

  async function startRun(event: FormEvent) {
    event.preventDefault();
    if (!detail || !prompt.trim() || activeRun) return;
    if (!independentPublicLegalShell && onOpenApprovedProvider) {
      onOpenApprovedProvider(
        approvedProviderTaskForAssistantIntent(intent),
        "旧助理入口不再直接发送任何用户自由文本；已切换到脱敏工作区并预选对应的 Approved Provider 固定任务。",
      );
      return;
    }
    if (!canSend || !selectedProvider) return;
    await performRun({
      conversationId: detail.conversation.conversationId,
      intent,
      requestPrompt: prompt.trim(),
      attachmentIds: attachmentPolicy.accepts
        ? [...selectedAttachmentIds]
        : [],
      saveResearchArtifact: intent === "legal_research",
      promptDraftAtStart: prompt,
    });
  }

  async function regenerateArtifact(
    request: ArtifactRegenerationRequest,
  ): Promise<boolean> {
    if (
      !detail ||
      detail.conversation.conversationId !== request.conversationId ||
      activeRun !== null ||
      operation !== null
    ) {
      throw new Error("当前会话尚未准备好，不能重新生成。");
    }
    const artifact = detail.artifacts.find(
      (candidate) => candidate.artifactId === request.artifactId,
    );
    if (
      !artifact ||
      artifact.kind !== request.kind ||
      artifact.projectId !== request.projectId
    ) {
      throw new Error("成果已变化，请重新加载后再试。");
    }
    const originRun = [...detail.messages]
      .reverse()
      .filter(
        (message) =>
          message.artifactId === request.artifactId && message.runId !== null,
      )
      .map((message) =>
        detail.runs.find(
          (run) =>
            run.runId === message.runId &&
            run.status === "succeeded" &&
            run.assistantMessageId === message.messageId,
        ),
      )
      .find((run): run is AssistantRun => run !== undefined);
    if (
      !originRun ||
      !RUN_INTENTS.includes(originRun.intent as AssistantRunIntent)
    ) {
      throw new Error("该成果没有可信的成功生成记录，不能自动重新生成。");
    }
    const regenerationIntent = originRun.intent as AssistantRunIntent;
    const kindMatches =
      (request.kind === "research" &&
        (regenerationIntent === "legal_research" ||
          regenerationIntent === "file_analysis")) ||
      (request.kind === "document" && regenerationIntent === "document_draft") ||
      (request.kind === "map" && regenerationIntent === "map_build");
    if (!kindMatches) {
      throw new Error("成果类型与原生成任务不一致，已停止重新生成。");
    }
    if (onOpenApprovedProvider) {
      onOpenApprovedProvider(
        approvedProviderTaskForAssistantIntent(regenerationIntent, true),
        "重新生成必须使用当前脱敏 generation 和受保护历史输出；已切换到 Approved Provider 固定任务“重新生成”。",
      );
      return false;
    }
    if (!selectedProvider || selectedProviderConfigured !== true) {
      throw new Error("模型服务尚未准备好，不能重新生成。");
    }
    const confirmed = confirmArtifactRegeneration({
      artifactTitle: artifact.title,
      sourceVersionNumber: request.sourceVersionNumber,
      provider: selectedProvider,
    });
    if (!confirmed) return false;
    await performRun({
      conversationId: request.conversationId,
      intent: regenerationIntent,
      requestPrompt: `请基于所选成果第 ${request.sourceVersionNumber} 版重新生成并改进；保持原成果类型、标题与来源约束。`,
      attachmentIds: [],
      saveResearchArtifact: request.kind === "research",
      regenerationTarget: {
        artifactId: request.artifactId,
        sourceVersionNumber: request.sourceVersionNumber,
        expectedCurrentVersion: artifact.currentVersion,
      },
      rethrowError: true,
    });
    return true;
  }

  async function cancelRun() {
    if (!activeRun) return;
    const run = activeRun;
    setActiveRun((current) =>
      current?.runId === run.runId ? { ...current, cancelling: true } : current,
    );
    try {
      const cancelled = await runBoundary.cancel(run.runId);
      setNotice({
        conversationId: run.conversationId,
        kind: "status",
        text: cancelled
          ? "已发送取消请求。"
          : "当前未能取消；任务可能尚未登记或已进入收尾，请等待状态刷新。",
      });
      if (!cancelled) {
        setActiveRun((current) =>
          applyAssistantCancellationResult(current, run.runId, cancelled),
        );
      }
    } catch (error: unknown) {
      setNotice({ conversationId: run.conversationId, kind: "error", text: `取消失败：${displayError(error)}` });
      setActiveRun((current) => replaceRunIfCurrent(current, run.runId, run));
    }
  }

  return (
    <section className="assistant-workspace" aria-label="办案助理工作区">
      <aside className="assistant-conversation-rail" aria-label="助理会话">
        <form className="assistant-new-conversation" onSubmit={(event) => void createConversation(event)}>
          <label>
            新会话标题
            <input
              placeholder="例如：买卖合同争议初步分析"
              value={newTitle}
              onChange={(event) =>
                setNewTitle(truncateUtf8(event.currentTarget.value, 256))
              }
            />
            <small>{utf8ByteLength(newTitle)} / 256 UTF-8 字节</small>
          </label>
          {activeProject ? (
            <label className="assistant-check-label">
              <input
                checked={bindNewConversation}
                type="checkbox"
                onChange={(event) => setBindNewConversation(event.currentTarget.checked)}
              />
              新会话绑定当前案件
            </label>
          ) : (
            <p className="assistant-muted">未打开案件；仍可创建独立会话。</p>
          )}
          <button
            disabled={operation !== null || !conversationListLoaded}
            type="submit"
          >
            {!conversationListLoaded
              ? "正在读取会话…"
              : operation === "create"
                ? "正在创建…"
                : "新建会话"}
          </button>
        </form>

        <nav className="assistant-conversation-list" aria-label="会话列表">
          <h2>会话</h2>
          {state.conversations.length === 0 ? (
            <p className="assistant-empty">还没有会话。</p>
          ) : (
            state.conversations.map((conversation) => (
              <button
                aria-current={
                  state.selectedConversationId === conversation.conversationId
                    ? "page"
                    : undefined
                }
                key={conversation.conversationId}
                type="button"
                onClick={() => loadConversation(conversation.conversationId)}
              >
                <strong>{publicTitle(conversation.title, "助理会话")}</strong>
                <span>{conversation.projectId ? "已绑定案件" : "独立会话"}</span>
                <time dateTime={conversation.updatedAt}>{dateTime(conversation.updatedAt)}</time>
              </button>
            ))
          )}
        </nav>

        <section className="assistant-recent-work" aria-labelledby="assistant-recent-heading">
          <h2 id="assistant-recent-heading">最近工作</h2>
          {detail?.artifacts.length ? (
            detail.artifacts.slice(0, 5).map((artifact: AssistantArtifact) => (
              <button
                key={artifact.artifactId}
                type="button"
                onClick={() => selectArtifact(artifact.artifactId)}
              >
                {publicTitle(artifact.title, "助理成果")}
                <span>第 {artifact.currentVersion} 版</span>
              </button>
            ))
          ) : (
            <p className="assistant-empty">当前会话暂无成果。</p>
          )}
        </section>
      </aside>

      <section
        className="assistant-conversation-main"
        aria-label="助理会话详情"
      >
        {state.detailPhase === "loading" ? (
          <p className="assistant-loading" role="status">正在读取会话…</p>
        ) : null}
        {state.detailPhase === "error" ? (
          <div className="assistant-problem" role="alert">
            <p>会话读取失败：{state.detailError}</p>
            <button type="button" onClick={refreshConversation}>重试</button>
          </div>
        ) : null}
        {!state.selectedConversationId ? (
          <div className="assistant-welcome">
            <p className="eyebrow">本地留痕的案件助理</p>
            <h2>从一个独立会话开始</h2>
            <p>你可以先研究法律、分析材料或起草内容，稍后再绑定案件。</p>
          </div>
        ) : null}
        {detail ? (
          <>
            <header className="assistant-conversation-header">
              <div>
                <p className="eyebrow">当前会话</p>
                <h2>{publicTitle(detail.conversation.title, "助理会话")}</h2>
                <p>
                  {conversationProjectId
                    ? activeProject?.projectId === conversationProjectId
                      ? `已绑定当前案件：${publicTitle(activeProject.title, "当前案件")}`
                      : "已绑定案件，但当前案件工作台未打开该案件"
                    : "独立会话：不会读取或写入案件数据"}
                </p>
              </div>
              <div className="assistant-button-row">
                {!conversationProjectId && activeProject ? (
                  <button
                    disabled={operation !== null}
                    type="button"
                    onClick={() => void bindConversation()}
                  >
                    {operation === "bind" ? "正在绑定…" : "绑定当前案件"}
                  </button>
                ) : null}
                <button
                  disabled={operation !== null || activeRunForConversation !== null}
                  type="button"
                  onClick={() => void archiveConversation()}
                >
                  {operation === "archive" ? "正在归档…" : "归档会话"}
                </button>
              </div>
            </header>

            <div className="assistant-message-list" aria-label="会话消息" aria-live="polite">
              {detail.messages.length === 0 ? (
                <p className="assistant-empty">输入任务开始这次会话。</p>
              ) : (
                detail.messages.map((message) => (
                  <MessageCard
                    key={message.messageId}
                    message={message}
                    onSelectArtifact={selectArtifact}
                  />
                ))
              )}
            </div>

            <RunTimeline runs={detail.runs} />

            {activeRunForConversation ? (
              <LiveRunProgress run={activeRunForConversation} />
            ) : null}

            <form className="assistant-composer" onSubmit={(event) => void startRun(event)}>
              <div className="assistant-composer-context" role="status">
                <span>
                  模型服务：{selectedProvider
                    ? selectedProviderConfigured === null
                      ? `${selectedProvider.displayName}（正在检查凭据）`
                      : selectedProviderConfigured
                        ? `${selectedProvider.displayName}（凭据已配置）`
                        : `${selectedProvider.displayName}（未配置凭据）`
                    : "尚未创建配置"}
                </span>
                <span>
                  案件范围：
                  {intentUsesCase
                    ? `将读取“${boundCaseLabel}”的已确认数据`
                    : "本任务不读取案件数据"}
                </span>
              </div>
              <div className="assistant-composer-options">
                <label>
                  任务类型
                  <select
                    value={intent}
                    onChange={(event) => setIntent(event.currentTarget.value as AssistantRunIntent)}
                  >
                    {RUN_INTENTS.map((value) => (
                      <option key={value} value={value}>{ASSISTANT_RUN_INTENT_LABELS[value]}</option>
                    ))}
                  </select>
                </label>
                <label>
                  模型服务配置
                  <select
                    value={selectedProviderId}
                    onChange={(event) => setSelectedProviderId(event.currentTarget.value)}
                  >
                    {providers.length === 0 ? <option value="">没有可用配置</option> : null}
                    {providers.map((provider) => (
                      <option key={provider.id} value={provider.id}>{provider.displayName}</option>
                    ))}
                  </select>
                </label>
                {onOpenProviderSettings ? (
                  <button type="button" onClick={onOpenProviderSettings}>管理模型服务</button>
                ) : null}
              </div>
              {caseIntentWithoutCase ? (
                <p className="assistant-problem" role="note">案件分析需要先把本会话绑定到案件。</p>
              ) : null}
              {requiredAttachmentsMissing ? (
                <p className="assistant-problem" role="note">
                  {intent === "file_analysis"
                    ? "材料分析至少需要选择 1 个已提取附件。"
                    : "当前任务在没有案件上下文时至少需要选择 1 个已提取附件。"}
                </p>
              ) : null}
              <label className="assistant-prompt-label">
                给助理的任务
                <textarea
                  maxLength={12000}
                  placeholder="写清楚目标、已知条件与希望的输出形式。模型生成内容仍需人工核对。"
                  rows={5}
                  value={prompt}
                  onChange={(event) => {
                    const conversationId = state.selectedConversationId;
                    if (!conversationId) return;
                    const value = event.currentTarget.value;
                    setPromptDrafts((current) => ({
                      ...current,
                      [conversationId]: value,
                    }));
                  }}
                />
              </label>
              <fieldset className="assistant-attachment-picker">
                <legend>
                  {attachmentPolicy.accepts
                    ? `本次可见附件（最多 2 个，已选 ${selectedAttachmentIds.length}/2）`
                    : "当前任务不向模型发送附件"}
                </legend>
                <button
                  disabled={operation !== null || activeRun !== null}
                  type="button"
                  onClick={() => void importFiles()}
                >
                  {operation === "import" ? "正在导入…" : "从系统对话框导入材料"}
                </button>
                <p className="assistant-muted">文件路径和附件正文不会交给前端；这里只显示名称与提取状态。</p>
                {attachments.length === 0 ? (
                  <p className="assistant-empty">尚未导入材料。</p>
                ) : (
                  <div className="assistant-attachment-options">
                    {attachments.map((attachment) => {
                      const selected = selectedAttachmentIds.includes(attachment.attachmentId);
                      const selectable = attachment.extractionStatus === "succeeded";
                      return (
                        <div
                          className="assistant-attachment-option"
                          key={attachment.attachmentId}
                        >
                          <label>
                            <input
                              checked={selected}
                              disabled={
                                !selectable ||
                                !attachmentPolicy.accepts ||
                                (!selected && selectedAttachmentIds.length >= 2) ||
                                activeRun !== null
                              }
                              type="checkbox"
                              onChange={() =>
                                setSelectedAttachmentIds((current) =>
                                  toggleAttachmentSelection(current, attachment.attachmentId),
                                )
                              }
                            />
                            <span>{attachment.originalName}</span>
                            <small>
                              {selectable
                                ? `${attachment.extension.toUpperCase()} · ${byteSize(attachment.sizeBytes)} · ${attachment.segmentCount} 个文本片段`
                                : `${attachment.extension.toUpperCase()} · ${byteSize(attachment.sizeBytes)} · 不可分析`}
                            </small>
                          </label>
                          <button
                            className="assistant-delete-attachment"
                            disabled={operation !== null || activeRun !== null}
                            type="button"
                            onClick={() => void deleteAttachment(attachment)}
                          >
                            永久删除
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </fieldset>
              <section
                className="assistant-provider-disclosure"
                aria-label="发送到模型服务的数据范围"
              >
                <strong>发送前确认范围</strong>
                <p>目标：{providerDisclosure.target}</p>
                <ul>
                  {providerDisclosure.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </section>
              <div className="assistant-composer-submit">
                <button disabled={!canSend} type="submit">
                  {activeRun
                    ? "另一个任务正在运行"
                    : routesToApprovedProvider
                      ? "前往脱敏批准"
                      : "发送任务"}
                </button>
                {activeRun ? (
                  <button
                    className="assistant-cancel-run"
                    disabled={activeRun.cancelling}
                    type="button"
                    onClick={() => void cancelRun()}
                  >
                    {activeRun.cancelling ? "正在取消…" : "取消运行"}
                  </button>
                ) : null}
              </div>
              {currentNotice ? (
                <p
                  className={currentNotice.kind === "error" ? "assistant-problem" : "assistant-inline-status"}
                  role={currentNotice.kind === "error" ? "alert" : "status"}
                >
                  {currentNotice.text}
                </p>
              ) : null}
            </form>
          </>
        ) : null}
      </section>

      <ArtifactPanel
        activeProject={activeProject}
        artifacts={detail?.artifacts ?? []}
        messages={detail?.messages ?? []}
        proposals={detail?.proposals ?? []}
        runs={detail?.runs ?? []}
        selectedArtifactId={selectedArtifactId}
        sources={detail?.sources ?? []}
        onConversationRefresh={refreshConversation}
        onDraftDirtyChange={updateArtifactDraftDirty}
        onMutationActivityChange={setArtifactMutationActive}
        onProposalApplied={onCaseProposalApplied}
        onRegenerateArtifact={regenerateArtifact}
        onSelectArtifact={selectArtifact}
        proposalApplyBlockedReason={proposalApplyBlockedReason}
      />
    </section>
  );
}
