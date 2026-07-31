import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  CaseAssistantIpcClientError,
  cancelCaseAssistantRun,
  confirmCaseAssistantOutput,
  createCaseAssistantConversation,
  getCaseAssistantConversation,
  listCaseAssistantConversations,
  listCaseAssistantGenerations,
  startCaseAssistantRun,
} from "../../../ipc/case-assistant/client";
import type {
  CaseAssistantConversation,
  CaseAssistantConversationDetail,
  CaseAssistantGeneration,
  CaseAssistantOutputKind,
  CaseAssistantPendingOutput,
} from "../../../ipc/case-assistant/types";
import { getProviderApiKeyStatus } from "../../../ipc/provider/client";
import type { ProviderProfile } from "../../../ipc/provider/types";
import { publicErrorMessage } from "../../../publicOutput";
import { createId } from "../model";
import { CaseAssistantGenerationPicker } from "./CaseAssistantGenerationPicker";
import { CaseAssistantPendingOutputs } from "./CaseAssistantPendingOutputs";
import { CaseAssistantProviderNotice } from "./CaseAssistantProviderNotice";
import {
  caseAssistantConfirmationMessage,
  caseAssistantRunFailureMessage,
  initialCaseAssistantStreamState,
  reconcileCaseAssistantGenerationIds,
  reduceCaseAssistantRunEvent,
  selectedGenerationIdsFromProjection,
  toggleCaseAssistantGeneration,
  type CaseAssistantStreamState,
} from "./caseAssistantState";
import "./case-assistant.css";

type CaseAssistantOperation =
  | "loading"
  | "create_conversation"
  | "refresh_generations"
  | null;

export interface CaseAssistantWorkspaceProps {
  projectId: string | null;
  providerProfiles: readonly ProviderProfile[];
  onDraftDirtyChange?: (dirty: boolean) => void;
  onMutationActivityChange?: (active: boolean) => void;
  onRunActivityChange?: (active: boolean) => void;
  onOutputApplied?: () => void;
  confirmAction?: (message: string) => boolean;
}
function replacePendingOutput(
  outputs: readonly CaseAssistantPendingOutput[],
  next: CaseAssistantPendingOutput,
): CaseAssistantPendingOutput[] {
  const retained = outputs.filter(
    (output) => output.pendingOutputId !== next.pendingOutputId,
  );
  return [next, ...retained];
}

export function CaseAssistantWorkspace({
  projectId,
  providerProfiles,
  onDraftDirtyChange,
  onMutationActivityChange,
  onRunActivityChange,
  onOutputApplied,
  confirmAction = (message) => window.confirm(message),
}: CaseAssistantWorkspaceProps) {
  const [conversations, setConversations] = useState<
    CaseAssistantConversation[]
  >([]);
  const [selectedConversationId, setSelectedConversationId] = useState<
    string | null
  >(null);
  const [detail, setDetail] =
    useState<CaseAssistantConversationDetail | null>(null);
  const [generations, setGenerations] = useState<CaseAssistantGeneration[]>([]);
  const [selectedGenerationIds, setSelectedGenerationIds] = useState<string[]>(
    [],
  );
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [providerStatuses, setProviderStatuses] = useState<
    Record<string, boolean | null>
  >({});
  const [newConversationTitle, setNewConversationTitle] = useState("");
  const [prompt, setPrompt] = useState("");
  const [outputKind, setOutputKind] =
    useState<CaseAssistantOutputKind>("case_analysis");
  const [operation, setOperation] = useState<CaseAssistantOperation>(null);
  const [confirmingOutputId, setConfirmingOutputId] = useState<string | null>(
    null,
  );
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [streamState, setStreamState] =
    useState<CaseAssistantStreamState | null>(null);
  const [notice, setNotice] = useState<{
    kind: "status" | "error";
    text: string;
  } | null>(null);
  const projectEpoch = useRef(0);
  const activeRunIdRef = useRef<string | null>(null);
  const mounted = useRef(true);

  const selectedProvider = providerProfiles.find(
    (provider) => provider.id === selectedProviderId,
  );
  const selectedGenerations = useMemo(
    () =>
      generations.filter((generation) =>
        selectedGenerationIds.includes(generation.redactionGenerationId),
      ),
    [generations, selectedGenerationIds],
  );

  const loadConversation = useCallback(
    async (
      targetProjectId: string,
      conversationId: string,
      expectedEpoch = projectEpoch.current,
    ) => {
      try {
        const response = await getCaseAssistantConversation({
          projectId: targetProjectId,
          conversationId,
        });
        if (
          !mounted.current ||
          projectEpoch.current !== expectedEpoch ||
          response.detail.conversation.projectId !== targetProjectId
        ) {
          return;
        }
        setSelectedConversationId(conversationId);
        setDetail(response.detail);
      } catch (error: unknown) {
        if (
          mounted.current &&
          projectEpoch.current === expectedEpoch
        ) {
          setNotice({
            kind: "error",
            text: `案件助理会话读取失败：${publicErrorMessage(error)}`,
          });
        }
      }
    },
    [],
  );

  const refreshGenerations = useCallback(async (
    options: { announceSuccess?: boolean } = {},
  ) => {
    if (!projectId) return;
    const expectedEpoch = projectEpoch.current;
    setOperation("refresh_generations");
    try {
      const response = await listCaseAssistantGenerations({ projectId });
      if (
        !mounted.current ||
        projectEpoch.current !== expectedEpoch
      ) {
        return;
      }
      setGenerations(response.generations);
      setSelectedGenerationIds((current) =>
        reconcileCaseAssistantGenerationIds(
          current,
          response.generations,
        ),
      );
      if (options.announceSuccess !== false) {
        setNotice({
          kind: "status",
          text: "已重新读取当前案件可用的 approved/current 脱敏版本。",
        });
      }
    } catch (error: unknown) {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setNotice({
          kind: "error",
          text: `可用脱敏版本读取失败：${publicErrorMessage(error)}`,
        });
      }
    } finally {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setOperation(null);
      }
    }
  }, [projectId]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const runId = activeRunIdRef.current;
      if (runId) {
        void cancelCaseAssistantRun({ runId });
      }
    };
  }, []);

  useEffect(() => {
    const expectedEpoch = projectEpoch.current + 1;
    projectEpoch.current = expectedEpoch;
    const runId = activeRunIdRef.current;
    if (runId) {
      void cancelCaseAssistantRun({ runId });
    }
    activeRunIdRef.current = null;
    setActiveRunId(null);
    setStreamState(null);
    setConversations([]);
    setSelectedConversationId(null);
    setDetail(null);
    setGenerations([]);
    setSelectedGenerationIds([]);
    setNewConversationTitle("");
    setPrompt("");
    setOutputKind("case_analysis");
    setConfirmingOutputId(null);
    setNotice(null);
    if (!projectId) {
      setOperation(null);
      return;
    }

    setOperation("loading");
    void Promise.all([
      listCaseAssistantConversations({ projectId, limit: 100 }),
      listCaseAssistantGenerations({ projectId }),
    ])
      .then(([conversationResponse, generationResponse]) => {
        if (
          !mounted.current ||
          projectEpoch.current !== expectedEpoch
        ) {
          return;
        }
        setConversations(conversationResponse.conversations);
        setGenerations(generationResponse.generations);
        setSelectedGenerationIds(
          selectedGenerationIdsFromProjection(
            generationResponse.generations,
          ),
        );
        const firstConversation = conversationResponse.conversations[0];
        if (firstConversation) {
          void loadConversation(
            projectId,
            firstConversation.conversationId,
            expectedEpoch,
          );
        }
      })
      .catch((error: unknown) => {
        if (
          mounted.current &&
          projectEpoch.current === expectedEpoch
        ) {
          setNotice({
            kind: "error",
            text: `案件助理初始化失败：${publicErrorMessage(error)}`,
          });
        }
      })
      .finally(() => {
        if (
          mounted.current &&
          projectEpoch.current === expectedEpoch
        ) {
          setOperation(null);
        }
      });
  }, [loadConversation, projectId]);

  useEffect(() => {
    let cancelled = false;
    setProviderStatuses(
      Object.fromEntries(
        providerProfiles.map((provider) => [provider.id, null]),
      ),
    );
    void Promise.allSettled(
      providerProfiles.map(async (provider) => {
        const response = await getProviderApiKeyStatus({
          providerId: provider.id,
          accountId: provider.credentialAccountId,
        });
        return [provider.id, response.status.configured] as const;
      }),
    ).then((results) => {
      if (cancelled) return;
      setProviderStatuses(
        Object.fromEntries(
          results.map((result, index) =>
            result.status === "fulfilled"
              ? result.value
              : ([providerProfiles[index].id, false] as const),
          ),
        ),
      );
    });
    return () => {
      cancelled = true;
    };
  }, [providerProfiles]);

  useEffect(() => {
    if (
      providerProfiles.some(
        (provider) => provider.id === selectedProviderId,
      )
    ) {
      return;
    }
    setSelectedProviderId(providerProfiles[0]?.id ?? "");
  }, [providerProfiles, selectedProviderId]);

  useEffect(() => {
    onDraftDirtyChange?.(
      prompt.trim().length > 0 || newConversationTitle.trim().length > 0,
    );
  }, [newConversationTitle, onDraftDirtyChange, prompt]);

  useEffect(() => {
    onRunActivityChange?.(activeRunId !== null);
  }, [activeRunId, onRunActivityChange]);

  useEffect(() => {
    onMutationActivityChange?.(
      operation !== null ||
        confirmingOutputId !== null ||
        activeRunId !== null,
    );
  }, [
    activeRunId,
    confirmingOutputId,
    onMutationActivityChange,
    operation,
  ]);

  useEffect(
    () => () => {
      onDraftDirtyChange?.(false);
      onMutationActivityChange?.(false);
      onRunActivityChange?.(false);
    },
    [
      onDraftDirtyChange,
      onMutationActivityChange,
      onRunActivityChange,
    ],
  );

  async function createConversation() {
    if (!projectId || operation !== null || activeRunId !== null) return;
    const expectedEpoch = projectEpoch.current;
    setOperation("create_conversation");
    try {
      const response = await createCaseAssistantConversation({
        projectId,
        title: newConversationTitle.trim() || "新案件工作会话",
      });
      if (
        !mounted.current ||
        projectEpoch.current !== expectedEpoch
      ) {
        return;
      }
      setConversations((current) => [
        response.conversation,
        ...current.filter(
          (conversation) =>
            conversation.conversationId !==
            response.conversation.conversationId,
        ),
      ]);
      setNewConversationTitle("");
      setPrompt("");
      await loadConversation(
        projectId,
        response.conversation.conversationId,
        expectedEpoch,
      );
    } catch (error: unknown) {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setNotice({
          kind: "error",
          text: `案件助理会话创建失败：${publicErrorMessage(error)}`,
        });
      }
    } finally {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setOperation(null);
      }
    }
  }

  function selectConversation(conversationId: string) {
    if (
      !projectId ||
      activeRunId !== null ||
      confirmingOutputId !== null ||
      conversationId === selectedConversationId
    ) {
      return;
    }
    setPrompt("");
    setStreamState(null);
    setDetail(null);
    void loadConversation(projectId, conversationId);
  }

  async function runCaseAssistant() {
    if (
      !projectId ||
      !selectedConversationId ||
      !selectedProviderId ||
      providerStatuses[selectedProviderId] !== true ||
      !prompt.trim() ||
      selectedGenerationIds.length === 0 ||
      activeRunId !== null ||
      operation !== null ||
      confirmingOutputId !== null
    ) {
      return;
    }
    const expectedEpoch = projectEpoch.current;
    const runId = createId("case-assistant-run");
    const requestPrompt = prompt.trim();
    const explicitGenerationIds = [...selectedGenerationIds];
    activeRunIdRef.current = runId;
    setActiveRunId(runId);
    setStreamState(initialCaseAssistantStreamState(runId));
    setNotice({
      kind: "status",
      text: "正在由后端重新验证案件、脱敏来源和一次性 Provider 授权。",
    });
    try {
      const response = await startCaseAssistantRun(
        {
          runId,
          conversationId: selectedConversationId,
          projectId,
          providerId: selectedProviderId,
          prompt: requestPrompt,
          redactionGenerationIds: explicitGenerationIds,
          outputKind,
        },
        (event) => {
          if (
            !mounted.current ||
            projectEpoch.current !== expectedEpoch ||
            activeRunIdRef.current !== runId
          ) {
            return;
          }
          setStreamState((current) =>
            current
              ? reduceCaseAssistantRunEvent(current, event)
              : current,
          );
        },
      );
      if (
        !mounted.current ||
        projectEpoch.current !== expectedEpoch ||
        activeRunIdRef.current !== runId
      ) {
        return;
      }
      setPrompt("");
      setDetail((current) =>
        current
          ? {
              ...current,
              runs: [
                response.run,
                ...current.runs.filter(
                  (run) => run.runId !== response.run.runId,
                ),
              ],
              pendingOutputs: replacePendingOutput(
                current.pendingOutputs,
                response.pendingOutput,
              ),
            }
          : current,
      );
      setNotice({
        kind: "status",
        text: "案件助理输出已通过后端扫描并保存为待确认状态；尚未写入案件或成果。",
      });
      await Promise.all([
        loadConversation(
          projectId,
          selectedConversationId,
          expectedEpoch,
        ),
        refreshGenerations(),
      ]);
    } catch (error: unknown) {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        const errorType =
          error instanceof CaseAssistantIpcClientError
            ? error.errorType
            : undefined;
        const failureMessage = caseAssistantRunFailureMessage(
          publicErrorMessage(error),
          errorType,
        );
        await refreshGenerations({ announceSuccess: false });
        if (
          mounted.current &&
          projectEpoch.current === expectedEpoch
        ) {
          setNotice({ kind: "error", text: failureMessage });
        }
      }
    } finally {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch &&
        activeRunIdRef.current === runId
      ) {
        activeRunIdRef.current = null;
        setActiveRunId(null);
      }
    }
  }

  async function cancelActiveRun() {
    const runId = activeRunIdRef.current;
    if (!runId) return;
    try {
      const response = await cancelCaseAssistantRun({ runId });
      setNotice({
        kind: "status",
        text: response.cancelled
          ? "已请求取消案件助理运行。"
          : "案件助理运行已进入不可取消的终结阶段。",
      });
    } catch (error: unknown) {
      setNotice({
        kind: "error",
        text: `取消案件助理失败：${publicErrorMessage(error)}`,
      });
    }
  }

  async function confirmPendingOutput(output: CaseAssistantPendingOutput) {
    if (
      !projectId ||
      output.projectId !== projectId ||
      output.conversationId !== selectedConversationId ||
      output.status !== "pending" ||
      activeRunId !== null ||
      confirmingOutputId !== null ||
      !confirmAction(caseAssistantConfirmationMessage(output))
    ) {
      return;
    }
    const expectedEpoch = projectEpoch.current;
    setConfirmingOutputId(output.pendingOutputId);
    try {
      const response = await confirmCaseAssistantOutput({
        projectId,
        pendingOutputId: output.pendingOutputId,
        expectedVersion: output.version,
        expectedOutputSha256: output.outputSha256,
        expectedWorkspaceDigest: output.workspaceDigest,
        userConfirmed: true,
      });
      if (
        !mounted.current ||
        projectEpoch.current !== expectedEpoch
      ) {
        return;
      }
      setDetail((current) =>
        current
          ? {
              ...current,
              pendingOutputs: replacePendingOutput(
                current.pendingOutputs,
                response.pendingOutput,
              ),
            }
          : current,
      );
      setNotice({
        kind: "status",
        text: "待确认输出已通过来源与工作区 CAS 复核并应用。",
      });
      onOutputApplied?.();
      if (selectedConversationId) {
        await loadConversation(
          projectId,
          selectedConversationId,
          expectedEpoch,
        );
      }
    } catch (error: unknown) {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setNotice({
          kind: "error",
          text: `输出确认失败：${publicErrorMessage(error)}`,
        });
        await Promise.all([
          selectedConversationId
            ? loadConversation(
                projectId,
                selectedConversationId,
                expectedEpoch,
              )
            : Promise.resolve(),
          refreshGenerations(),
        ]);
      }
    } finally {
      if (
        mounted.current &&
        projectEpoch.current === expectedEpoch
      ) {
        setConfirmingOutputId(null);
      }
    }
  }

  const busy =
    operation !== null ||
    confirmingOutputId !== null ||
    activeRunId !== null;
  const canSend =
    projectId !== null &&
    selectedConversationId !== null &&
    prompt.trim().length > 0 &&
    selectedGenerationIds.length > 0 &&
    selectedProviderId.length > 0 &&
    providerStatuses[selectedProviderId] === true &&
    !busy;

  if (!projectId) {
    return (
      <section className="panel case-assistant-workspace">
        <div className="panel-heading">
          <h2>案件助理</h2>
          <span>独立案件边界</span>
        </div>
        <p className="empty-state">
          请先从左侧选择一个已保存案件，再创建独立的案件工作会话。
        </p>
      </section>
    );
  }

  return (
    <section
      className="panel case-assistant-workspace"
      aria-busy={busy}
      aria-labelledby="case-assistant-title"
    >
      <div className="panel-heading">
        <div>
          <h2 id="case-assistant-title">案件助理</h2>
          <p>
            独立 case_work 会话；不会加载普通助理会话、附件、成果或自动化历史。
          </p>
        </div>
        <span>{activeRunId ? "运行中" : "受保护案件模式"}</span>
      </div>

      {notice ? (
        <p
          className={notice.kind === "error" ? "error-text" : "privacy-note"}
          role={notice.kind === "error" ? "alert" : "status"}
        >
          {notice.text}
        </p>
      ) : null}

      <div className="case-assistant-layout">
        <aside
          className="case-assistant-conversations"
          aria-label="案件助理会话"
        >
          <label>
            <span>新会话标题</span>
            <input
              disabled={busy}
              value={newConversationTitle}
              onChange={(event) =>
                setNewConversationTitle(event.target.value)
              }
            />
          </label>
          <button
            disabled={busy}
            type="button"
            onClick={() => void createConversation()}
          >
            {operation === "create_conversation"
              ? "正在创建…"
              : "创建案件工作会话"}
          </button>
          <div className="provider-list">
            {conversations.map((conversation) => (
              <button
                className={
                  conversation.conversationId === selectedConversationId
                    ? "provider-item is-selected"
                    : "provider-item"
                }
                disabled={busy}
                key={conversation.conversationId}
                type="button"
                onClick={() =>
                  selectConversation(conversation.conversationId)
                }
              >
                <span className="item-title">{conversation.title}</span>
                <span className="item-meta">
                  {conversation.status === "open" ? "进行中" : "已归档"} ·{" "}
                  {conversation.updatedAt}
                </span>
              </button>
            ))}
            {conversations.length === 0 && operation !== "loading" ? (
              <p className="empty-state">当前案件还没有案件工作会话。</p>
            ) : null}
          </div>
        </aside>

        <div className="case-assistant-main">
          <div className="form-grid">
            <label>
              <span>模型服务</span>
              <select
                disabled={busy}
                value={selectedProviderId}
                onChange={(event) =>
                  setSelectedProviderId(event.target.value)
                }
              >
                <option value="">请选择模型服务</option>
                {providerProfiles.map((provider) => (
                  <option key={provider.id} value={provider.id}>
                    {provider.displayName}
                    {providerStatuses[provider.id] === false
                      ? "（未配置凭据）"
                      : providerStatuses[provider.id] === null
                        ? "（正在检查凭据）"
                        : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>输出类型</span>
              <select
                disabled={busy}
                value={outputKind}
                onChange={(event) =>
                  setOutputKind(
                    event.target.value as CaseAssistantOutputKind,
                  )
                }
              >
                <option value="case_analysis">案件分析</option>
                <option value="case_document">案件文书</option>
                <option value="case_diagram">案件图示</option>
              </select>
            </label>
          </div>

          <section
            className="case-assistant-history"
            aria-label="案件工作会话历史"
          >
            {detail?.messages.map((message) => (
              <article
                className={`case-assistant-message is-${message.role}`}
                key={message.messageId}
              >
                <strong>{message.role === "user" ? "你" : "案件助理"}</strong>
                <p>{message.textSummary}</p>
              </article>
            ))}
            {selectedConversationId && detail?.messages.length === 0 ? (
              <p className="empty-state">该案件工作会话暂无消息。</p>
            ) : null}
            {!selectedConversationId ? (
              <p className="empty-state">
                创建或选择案件工作会话后才能发送。
              </p>
            ) : null}
          </section>

          <CaseAssistantGenerationPicker
            disabled={busy}
            generations={generations}
            loading={operation === "refresh_generations"}
            selectedIds={selectedGenerationIds}
            onReload={() => void refreshGenerations()}
            onToggle={(generationId, checked) =>
              setSelectedGenerationIds((current) =>
                toggleCaseAssistantGeneration(
                  generations,
                  current,
                  generationId,
                  checked,
                ),
              )
            }
          />

          <label className="case-assistant-prompt">
            <span>当前案件任务</span>
            <textarea
              disabled={busy || !selectedConversationId}
              placeholder="只描述本次希望基于所选脱敏版本与已确认案件数据完成的任务。"
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
            />
          </label>

          <CaseAssistantProviderNotice
            outputKind={outputKind}
            provider={selectedProvider}
            selectedGenerations={selectedGenerations}
          />

          <div className="command-row">
            <button
              disabled={!canSend}
              type="button"
              onClick={() => void runCaseAssistant()}
            >
              选择并发送
            </button>
            <button
              disabled={activeRunId === null}
              type="button"
              onClick={() => void cancelActiveRun()}
            >
              取消当前运行
            </button>
          </div>

          {streamState ? (
            <section
              className="case-assistant-stream-result"
              aria-label="案件助理本次响应"
            >
              <div className="section-heading">
                <strong>本次响应</strong>
                <span>{streamState.status}</span>
              </div>
              {streamState.verifiedResponse ? (
                <pre>{streamState.verifiedResponse}</pre>
              ) : (
                <p className="privacy-note">
                  响应尚未完成后端缓冲与扫描，因此不会显示未验证片段。
                </p>
              )}
              {streamState.totalTokens !== null ? (
                <small>模型报告总 token：{streamState.totalTokens}</small>
              ) : null}
              {streamState.error ? (
                <p className="error-text">{streamState.error}</p>
              ) : null}
            </section>
          ) : null}

          <CaseAssistantPendingOutputs
            busyOutputId={confirmingOutputId}
            outputs={detail?.pendingOutputs ?? []}
            onConfirm={(output) => void confirmPendingOutput(output)}
          />
        </div>
      </div>
    </section>
  );
}
