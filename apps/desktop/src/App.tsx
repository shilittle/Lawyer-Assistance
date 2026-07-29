import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import {
  formatConfirmationStatus,
  formatGapKind,
  formatGapSeverity,
  formatLegalBasisInvalidReason,
  formatLegalBasisStatus,
  formatLegalIssueStatus,
  formatPartyRole,
} from "./ipc/case/format";
import {
  extractionLocksSources,
} from "./ipc/case/extractionReview";
import type {
  ConfirmationStatus,
  LegalIssueStatus,
  PartyRole,
} from "./ipc/case/types";
import { formatLegalSourceLabel, formatStatus } from "./ipc/legal/format";
import type { GraphMode, GraphNode } from "./ipc/graph/types";
import {
  addAssistantLegalSource,
  proposeAssistantLegalBasis,
} from "./ipc/assistant/client";
import type { AssistantConversation } from "./ipc/assistant/types";
import type { ApprovedProviderTask } from "./ipc/privacy/types";
import {
  providerApiKeyDeletionConfirmation,
  providerApiKeyOverwriteConfirmation,
  providerDeletionConfirmation,
  providerNavigationHasUnsavedChanges,
  runConfirmedDestructiveAction,
} from "./features/settings/providers/policies";
import { AppShell } from "./app/AppShell";
import {
  assistantWritesBlockClose,
  decideMcpWorkspaceNavigation,
  decidePrivacyWorkspaceNavigation,
  decideWorkspaceClose,
  workspaceCloseWasApproved,
} from "./app/navigationGuards";
import { VIEW_METADATA, type ViewMode } from "./app/views";
import { useHealthStatus } from "./app/useHealthStatus";
import { AssistantWorkspace } from "./features/assistant/AssistantWorkspace";
import { CasesWorkspace } from "./features/cases/CasesWorkspace";
import {
  caseEntityEditorAllows,
  caseEntityEditorMatches,
  caseGraphNodeDomId,
  clampCaseProjectPage,
  formatLegalBasisTitle,
  formatLegalBasisWindow,
  graphNodeDestination,
  publicCaseBusinessText,
  publicEvidenceNumber,
} from "./features/cases/model";
import { useCaseWorkspaceController } from "./features/cases/useCaseWorkspaceController";
import { LegacyQaWorkspace } from "./features/legal-library/LegacyQaWorkspace";
import { LegalLibrarySearchWorkspace } from "./features/legal-library/LegalLibrarySearchWorkspace";
import { useLegalLibraryController } from "./features/legal-library/useLegalLibraryController";
import { ProviderSettingsWorkspace } from "./features/settings/providers/ProviderSettingsWorkspace";
import { useProviderSettingsController } from "./features/settings/providers/useProviderSettingsController";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import {
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "./publicOutput";

const DocumentWorkspace = lazy(() => import("./DocumentWorkspace").then((module) => ({ default: module.DocumentWorkspace })));
const GraphWorkspace = lazy(() => import("./GraphWorkspace").then((module) => ({ default: module.GraphWorkspace })));
const McpWorkspace = lazy(() => import("./features/mcp/McpWorkspace").then((module) => ({ default: module.McpWorkspace })));
const PrivacyWorkspace = lazy(() => import("./features/privacy/PrivacyWorkspace").then((module) => ({ default: module.PrivacyWorkspace })));
const ReleaseWorkspace = lazy(() => import("./ReleaseWorkspace").then((module) => ({ default: module.ReleaseWorkspace })));

function errorMessage(error: unknown): string {
  return publicErrorMessage(error);
}

export function App() {
  const [viewMode, setViewMode] = useState<ViewMode>("assistant");
  const health = useHealthStatus();
  const [closeProtectionMessage, setCloseProtectionMessage] = useState<
    string | null
  >(null);
  const [assistantConversation, setAssistantConversation] =
    useState<AssistantConversation | null>(null);
  const [assistantRefreshKey, setAssistantRefreshKey] = useState(0);
  const [assistantCaseHandoff, setAssistantCaseHandoff] = useState<
    { projectId: string; title: string; requestId: number } | null
  >(null);
  const [approvedProviderTaskRequest, setApprovedProviderTaskRequest] = useState<{
    task: ApprovedProviderTask;
    notice: string;
    requestId: number;
  } | null>(null);
  const approvedProviderTaskRequestSequence = useRef(0);
  const assistantCaseHandoffSequence = useRef(0);
  const assistantDraftDirty = useRef(false);
  const assistantMutationActive = useRef(false);
  const assistantRunActive = useRef(false);
  const mcpDraftDirty = useRef(false);
  const mcpMutationActive = useRef(false);
  const privacyDraftDirty = useRef(false);
  const privacyMutationActive = useRef(false);
  const handleAssistantConversationChange = useCallback(
    (conversation: AssistantConversation | null) => {
      setAssistantConversation(conversation);
    },
    [],
  );
  const handleAssistantRunActivityChange = useCallback((active: boolean) => {
    assistantRunActive.current = active;
  }, []);
  const handleAssistantDraftDirtyChange = useCallback((dirty: boolean) => {
    assistantDraftDirty.current = dirty;
  }, []);
  const handleAssistantMutationActivityChange = useCallback((active: boolean) => {
    assistantMutationActive.current = active;
  }, []);
  const handleMcpDraftDirtyChange = useCallback((dirty: boolean) => {
    mcpDraftDirty.current = dirty;
  }, []);
  const handleMcpMutationActivityChange = useCallback((active: boolean) => {
    mcpMutationActive.current = active;
  }, []);
  const handlePrivacyDraftDirtyChange = useCallback((dirty: boolean) => {
    privacyDraftDirty.current = dirty;
  }, []);
  const handlePrivacyMutationActivityChange = useCallback((active: boolean) => {
    privacyMutationActive.current = active;
  }, []);
  const [graphMode, setGraphMode] = useState<GraphMode>("case");
  const [graphCaseTarget, setGraphCaseTarget] = useState<{
    sourceKind: string;
    sourceId: string;
  } | null>(null);

  const controlledCloseApproved = useRef(false);
  const caseController = useCaseWorkspaceController({
    onLegacyApprovedProviderRequest: redirectLegacyEgressToApprovedProvider,
  });
  const {
    caseState,
    caseProjects,
    setCaseProjectPage,
    selectedCaseProjectId,
    caseWorkspace,
    caseValidationTargetId,
    caseMutationInFlight,
    activeCaseEntityEditor,
    caseProjectDraft,
    setCaseProjectDraft,
    fileDraft,
    setFileDraft,
    partyDraft,
    setPartyDraft,
    factDraft,
    setFactDraft,
    evidenceDraft,
    setEvidenceDraft,
    issueDraft,
    setIssueDraft,
    basisSourceId,
    setBasisSourceId,
    basisIssueId,
    setBasisIssueId,
    basisCaseDate,
    setBasisCaseDate,
    basisIncludeExpired,
    setBasisIncludeExpired,
    basisNote,
    setBasisNote,
    linkFactId,
    setLinkFactId,
    linkEvidenceId,
    setLinkEvidenceId,
    factIssueFactId,
    setFactIssueFactId,
    factIssueIssueId,
    setFactIssueIssueId,
    caseNavigationLocked,
    caseProjectMutationLocked,
    caseChildrenReady,
    editingFile,
    editingParty,
    editingFact,
    editingEvidence,
    editingIssue,
    paginatedCaseProjects,
    assistantActiveProject,
    assistantProposalApplyBlockedReason,
    startCaseEntityEdit,
    cancelCaseEntityEdit,
    startNewCaseProject,
    selectCaseProject,
    saveCaseProject,
    removeCaseProject,
    saveParty,
    saveFile,
    saveFact,
    saveEvidence,
    saveIssue,
    saveLegalBasis,
    linkEvidenceToFact,
    linkFactToIssue,
    removeCaseEntity,
    refreshCaseAfterAssistantProposal,
    reportCaseError,
    setUnsupportedGraphNodeStatus,
  } = caseController;
  const {
    providerId: extractionProviderId,
    setProviderId: setExtractionProviderId,
    fileIds: extractionFileIds,
    setFileIds: setExtractionFileIds,
    state: extractionState,
    confirmPreparing: extractionConfirmPreparing,
    discarding: extractionDiscarding,
    discardError: extractionDiscardError,
    draftSaveState: extractionDraftSaveState,
    reviewReloadRequired: extractionReviewReloadRequired,
    closePreparing: extractionClosePreparing,
    pendingReviewRecoveryBlock,
    reviewRef: extractionReviewRef,
    sourcesLocked: extractionSourcesLocked,
    deletionBlockedProviderId: providerDeletionBlockedProviderId,
    closeGuard: caseCloseGuard,
    runStructuredExtraction,
    updateDraft: updateExtractionDraft,
    cancelReview: cancelExtractionReview,
    discardUnrestorablePendingReview,
    reloadServerDraft: reloadServerExtractionDraft,
    resetResult: resetExtractionResult,
    confirmReview: confirmExtractionReview,
    selectInitialProvider: selectInitialExtractionProvider,
    handleProviderSaved: handleExtractionProviderSaved,
    handleProviderDeleted: handleExtractionProviderDeleted,
  } = caseController.extraction;
  const legalLibrary = useLegalLibraryController({
    qaActive: viewMode === "qa",
    selectedCaseProjectId,
    assistantConversation,
    assistantActiveProject,
    onNavigateToSearch: () => setViewMode("search"),
    onOpenLawGraph: () => {
      setGraphMode("law");
      setViewMode("graph");
    },
    onContinueInAssistant: continueSelectedCaseInAssistant,
    onOpenAssistant: () => setViewMode("assistant"),
    onLegacyApprovedProviderRequest: redirectLegacyEgressToApprovedProvider,
    onAddAssistantLegalSource: addLegalSourceToAssistant,
    onProposeAssistantLegalBasis: proposeAssistantLegalBasisForCase,
  });
  const handleInitialProviderSelected = useCallback(
    (providerId: string) => {
      legalLibrary.providerBridge.selectInitialProvider(providerId);
      selectInitialExtractionProvider(providerId);
    },
    [legalLibrary.providerBridge, selectInitialExtractionProvider],
  );
  const handleProviderSaved = useCallback((providerId: string) => {
    handleExtractionProviderSaved(providerId);
  }, [handleExtractionProviderSaved]);
  const handleProviderDeleted = useCallback(
    (deletedProviderId: string, fallbackProviderId: string | null) => {
      legalLibrary.providerBridge.handleProviderDeleted(
        deletedProviderId,
        fallbackProviderId,
      );
      handleExtractionProviderDeleted(deletedProviderId, fallbackProviderId);
    },
    [handleExtractionProviderDeleted, legalLibrary.providerBridge],
  );
  const confirmProviderAction = useCallback(
    (message: string) => window.confirm(message),
    [],
  );
  const providerSettings = useProviderSettingsController({
    policies: {
      hasUnsavedChanges: providerNavigationHasUnsavedChanges,
      providerDeletionConfirmation,
      apiKeyDeletionConfirmation: providerApiKeyDeletionConfirmation,
      apiKeyOverwriteConfirmation: providerApiKeyOverwriteConfirmation,
      runConfirmedDestructiveAction,
      confirmAction: confirmProviderAction,
    },
    deletionBlockedProviderId: providerDeletionBlockedProviderId,
    onInitialProviderSelected: handleInitialProviderSelected,
    onProviderSaved: handleProviderSaved,
    onProviderDeleted: handleProviderDeleted,
  });
  const providerProfiles = providerSettings.profiles;

  useEffect(() => {
    let disposed = false;
    let unlistenCloseRequested: (() => void) | undefined;

    const currentCloseDecision = () => {
      const caseCloseSnapshot = caseCloseGuard.read();
      return decideWorkspaceClose({
        dirtyCaseDrafts: caseCloseSnapshot.dirtyDrafts,
        providerDraftDirty:
          providerSettings.hasUnsavedChangesRef.current,
        caseMutationInFlight: caseCloseSnapshot.caseMutationInFlight,
        providerMutationInFlight:
          providerSettings.mutationInFlightRef.current,
        extractionMutationInFlight:
          caseCloseSnapshot.extractionMutationInFlight,
        assistantRunActive: assistantRunActive.current,
        assistantMutationInFlight: assistantWritesBlockClose(
          assistantMutationActive.current,
          legalLibrary.bridgeMutationInFlightRef.current,
        ),
        assistantDraftDirty: assistantDraftDirty.current,
        mcpMutationInFlight: mcpMutationActive.current,
        mcpDraftDirty: mcpDraftDirty.current,
        privacyMutationInFlight: privacyMutationActive.current,
        privacyDraftDirty: privacyDraftDirty.current,
      });
    };
    const blockBrowserUnload = (event: BeforeUnloadEvent) => {
      if (controlledCloseApproved.current) {
        return;
      }
      const caseCloseSnapshot = caseCloseGuard.read();
      if (
        !caseCloseSnapshot.extractionNeedsFlush &&
        currentCloseDecision().kind === "proceed"
      ) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    };

    window.addEventListener("beforeunload", blockBrowserUnload);
    if ("__TAURI_INTERNALS__" in window) {
      const appWindow = getCurrentWindow();
      void appWindow
        .onCloseRequested(async (event) => {
          if (caseCloseGuard.read().extractionCloseInProgress) {
            event.preventDefault();
            return;
          }
          const closeDecision = currentCloseDecision();
          if (closeDecision.kind === "block") {
            event.preventDefault();
            setCloseProtectionMessage(closeDecision.message);
            return;
          }
          let forceControlledClose = false;
          if (closeDecision.kind === "confirm_discard") {
            event.preventDefault();
            if (
              !workspaceCloseWasApproved(closeDecision, (message) =>
                window.confirm(message),
              )
            ) {
              setCloseProtectionMessage(
                "已取消关闭；未保存内容仍保留在当前窗口。",
              );
              return;
            }
            forceControlledClose = true;
            controlledCloseApproved.current = true;
          }

          if (
            caseCloseGuard.read().extractionNeedsFlush ||
            forceControlledClose
          ) {
            setCloseProtectionMessage(null);
          }
          const result = await caseCloseGuard.requestControlledClose({
            forceControlledClose,
            preventDefault: () => event.preventDefault(),
            destroyWindow: () => appWindow.destroy(),
            onBlocked: (message) => {
              reportCaseError(message);
              setCloseProtectionMessage(message);
            },
          });
          if (result === "blocked") {
            controlledCloseApproved.current = false;
          }
        })
        .then((unlisten) => {
          if (disposed) {
            unlisten();
          } else {
            unlistenCloseRequested = unlisten;
          }
        })
        .catch((error: unknown) => {
          if (!disposed) {
            setCloseProtectionMessage(
              `无法注册关闭前草稿保护：${errorMessage(error)}`,
            );
          }
        });
    }

    return () => {
      disposed = true;
      window.removeEventListener("beforeunload", blockBrowserUnload);
      unlistenCloseRequested?.();
    };
    // The handler intentionally reads mutable refs so it always protects the
    // latest workspace and review without re-registering the native listener.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function openCaseGraph() {
    if (!selectedCaseProjectId) return;
    setGraphMode("case");
    setViewMode("graph");
  }

  function openGraphNode(node: GraphNode) {
    const destination = graphNodeDestination(node);
    if (destination === "law") {
      void legalLibrary.openLawDocumentFromGraph(node);
      return;
    }
    if (destination === "case") {
      setGraphCaseTarget({ sourceKind: node.sourceKind, sourceId: node.sourceId });
      setViewMode("cases");
      return;
    }
    setStatusForUnsupportedGraphNode(node);
  }

  function setStatusForUnsupportedGraphNode(node: GraphNode) {
    void node;
    setUnsupportedGraphNodeStatus();
  }

  useEffect(() => {
    if (viewMode !== "cases" || !graphCaseTarget) return;
    const targetId = caseGraphNodeDomId(
      graphCaseTarget.sourceKind,
      graphCaseTarget.sourceId,
    );
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(targetId);
      target?.scrollIntoView({ behavior: "smooth", block: "center" });
      target?.focus({ preventScroll: true });
    });
    const clearHighlight = window.setTimeout(() => setGraphCaseTarget(null), 4000);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(clearHighlight);
    };
  }, [graphCaseTarget, viewMode]);

  const activeProductArea = VIEW_METADATA[viewMode].futureArea;

  function continueSelectedCaseInAssistant() {
    if (!assistantActiveProject) return;
    assistantCaseHandoffSequence.current += 1;
    setAssistantCaseHandoff({
      projectId: assistantActiveProject.projectId,
      title: assistantActiveProject.title,
      requestId: assistantCaseHandoffSequence.current,
    });
    setViewMode("assistant");
  }

  async function addLegalSourceToAssistant(sourceId: string) {
    if (!assistantConversation) {
      throw new Error("当前没有可接收法律来源的助理会话");
    }
    await addAssistantLegalSource({
      conversationId: assistantConversation.conversationId,
      sourceId,
    });
    setAssistantRefreshKey((current) => current + 1);
  }

  async function proposeAssistantLegalBasisForCase(sourceId: string) {
    if (
      !assistantConversation ||
      !selectedCaseProjectId ||
      assistantConversation.projectId !== selectedCaseProjectId
    ) {
      throw new Error("当前助理会话未绑定所选案件");
    }
    await proposeAssistantLegalBasis({
      conversationId: assistantConversation.conversationId,
      projectId: selectedCaseProjectId,
      sourceId,
    });
    setAssistantRefreshKey((current) => current + 1);
  }

  function redirectLegacyEgressToApprovedProvider(
    task: ApprovedProviderTask,
    notice: string,
  ): void {
    approvedProviderTaskRequestSequence.current += 1;
    setApprovedProviderTaskRequest({
      task,
      notice,
      requestId: approvedProviderTaskRequestSequence.current,
    });
    navigateFromShell("privacy");
  }

  function navigateFromShell(nextView: ViewMode) {
    const mcpNavigation = decideMcpWorkspaceNavigation(
      viewMode,
      nextView,
      mcpMutationActive.current,
      mcpDraftDirty.current,
    );
    if (mcpNavigation.kind === "block") {
      setCloseProtectionMessage(mcpNavigation.message);
      return;
    }
    if (mcpNavigation.kind === "confirm_discard") {
      if (!window.confirm(mcpNavigation.message)) {
        setCloseProtectionMessage(
          "已取消切换；未保存的 MCP 设置仍保留在当前工作区。",
        );
        return;
      }
      // The MCP workspace is conditionally mounted. Once the user explicitly
      // approves discarding it there is no remaining draft for the global
      // close guard to protect after navigation unmounts the workspace.
      mcpDraftDirty.current = false;
    }
    const privacyNavigation = decidePrivacyWorkspaceNavigation(
      viewMode,
      nextView,
      privacyMutationActive.current,
      privacyDraftDirty.current,
    );
    if (privacyNavigation.kind === "block") {
      setCloseProtectionMessage(privacyNavigation.message);
      return;
    }
    if (privacyNavigation.kind === "confirm_discard") {
      if (!window.confirm(privacyNavigation.message)) {
        setCloseProtectionMessage(
          "已取消切换；未保存的隐私与本地 OCR 配置仍保留在当前工作区。",
        );
        return;
      }
      // PrivacyWorkspace is conditionally mounted. Once the user approves
      // discarding it, no stale dirty flag should remain in the close guard.
      privacyDraftDirty.current = false;
    }
    setCloseProtectionMessage(null);
    if (nextView === "graph") {
      if (selectedCaseProjectId) setGraphMode("case");
      else if (legalLibrary.search.selectedDocument) {
        setGraphMode("law");
      }
    }
    if (nextView !== "privacy") {
      setApprovedProviderTaskRequest(null);
    }
    setViewMode(nextView);
  }

  return (
    <AppShell
      activeView={viewMode}
      status={{ kind: health.state.kind, text: health.text }}
      onNavigate={navigateFromShell}
    >

      {closeProtectionMessage ? (
        <p className="error-text" role="alert" aria-live="assertive">
          {closeProtectionMessage}
        </p>
      ) : null}

      {activeProductArea !== "legal-library" ? (
        <nav className="workspace-subnav" aria-label="当前产品区功能">
          {activeProductArea === "assistant" ? (
            <>
              <button
                aria-current={viewMode === "assistant" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("assistant")}
              >
                助理工作区
              </button>
              <button
                aria-current={viewMode === "qa" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("qa")}
              >
                兼容引用问答
              </button>
            </>
          ) : activeProductArea === "cases" ? (
            <>
              <button
                aria-current={viewMode === "cases" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("cases")}
              >
                案件工作台 β
              </button>
              <button
                aria-current={viewMode === "documents" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("documents")}
              >
                既有文书模板
              </button>
              <button
                aria-current={viewMode === "graph" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("graph")}
              >
                确定性图谱
              </button>
            </>
          ) : (
            <>
              <button
                aria-current={viewMode === "providers" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("providers")}
              >
                Provider 与凭据
              </button>
              <button
                aria-current={viewMode === "privacy" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("privacy")}
              >
                隐私与本地处理
              </button>
              <button
                aria-current={viewMode === "mcp" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("mcp")}
              >
                MCP 服务
              </button>
              <button
                aria-current={viewMode === "release" ? "page" : undefined}
                type="button"
                onClick={() => navigateFromShell("release")}
              >
                版本、备份与诊断
              </button>
            </>
          )}
        </nav>
      ) : null}

      <div className="assistant-workspace-host" hidden={viewMode !== "assistant"}>
        <AssistantWorkspace
          activeProject={assistantActiveProject}
          caseHandoff={assistantCaseHandoff}
          externalRefreshKey={assistantRefreshKey}
          providerProfiles={providerProfiles}
          proposalApplyBlockedReason={assistantProposalApplyBlockedReason}
          onCaseProposalApplied={refreshCaseAfterAssistantProposal}
          onConversationChange={handleAssistantConversationChange}
          onDraftDirtyChange={handleAssistantDraftDirtyChange}
          onMutationActivityChange={handleAssistantMutationActivityChange}
          onOpenProviderSettings={() => navigateFromShell("providers")}
          onOpenApprovedProvider={(task, notice) =>
            redirectLegacyEgressToApprovedProvider(task, notice)
          }
          onRunActivityChange={handleAssistantRunActivityChange}
        />
      </div>

      {viewMode === "assistant" ? null : viewMode === "search" ? (
        <LegalLibrarySearchWorkspace controller={legalLibrary} />
      ) : viewMode === "qa" ? (
        <LegacyQaWorkspace
          caseWorkspace={caseWorkspace}
          controller={legalLibrary}
          providerProfiles={providerProfiles}
        />
      ) : viewMode === "documents" ? (
        <Suspense fallback={<p className="empty-state">正在加载文书工作台…</p>}>
          <DocumentWorkspace
            projectId={selectedCaseProjectId}
            onOpenCitation={(citation) =>
              void legalLibrary.openDocumentCitation(citation)
            }
          />
        </Suspense>
      ) : viewMode === "graph" ? (
        <Suspense fallback={<p className="empty-state">正在加载关系图…</p>}>
          <GraphWorkspace
            documentId={
              legalLibrary.graphDocumentId ??
              legalLibrary.search.selectedDocument?.documentId ??
              null
            }
            mode={graphMode}
            projectId={selectedCaseProjectId}
            onModeChange={setGraphMode}
            onOpenNode={openGraphNode}
          />
        </Suspense>
      ) : viewMode === "privacy" ? (
        <SettingsWorkspace mode="privacy">
          <Suspense fallback={<p className="empty-state">正在加载隐私设置…</p>}>
            <PrivacyWorkspace
              providerTaskRequest={approvedProviderTaskRequest}
              onDraftDirtyChange={handlePrivacyDraftDirtyChange}
              onMutationActivityChange={handlePrivacyMutationActivityChange}
            />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "release" ? (
        <SettingsWorkspace mode="maintenance">
          <Suspense fallback={<p className="empty-state">正在加载版本信息…</p>}>
            <ReleaseWorkspace />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "mcp" ? (
        <SettingsWorkspace mode="mcp">
          <Suspense fallback={<p className="empty-state">正在加载 MCP 服务设置…</p>}>
            <McpWorkspace
              onDraftDirtyChange={handleMcpDraftDirtyChange}
              onMutationActivityChange={handleMcpMutationActivityChange}
            />
          </Suspense>
        </SettingsWorkspace>
      ) : viewMode === "cases" ? (
        <CasesWorkspace busy={caseState.kind === "loading"}>
          <aside className="panel case-list-panel" aria-labelledby="case-list-title">
            <div className="panel-heading">
              <h2 id="case-list-title">案件项目</h2>
              <span>{caseProjects.length}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={caseNavigationLocked}
                type="button"
                onClick={startNewCaseProject}
              >
                新建案件
              </button>
            </div>
            <div className="provider-list">
              {paginatedCaseProjects.projects.map((project) => (
                <button
                  className={`provider-item ${
                    selectedCaseProjectId === project.projectId
                      ? "is-selected"
                      : ""
                  }`}
                  disabled={caseNavigationLocked}
                  key={project.projectId}
                  type="button"
                  onClick={() => selectCaseProject(project)}
                >
                  <span className="item-title">
                    {publicTitle(project.title, "未命名案件")}
                  </span>
                  <span className="item-meta">
                    {project.caseType || "未分类"} ·{" "}
                    {project.openedOn ?? "未登记日期"}
                  </span>
                  <span className="item-summary">
                    {publicCaseBusinessText(project.summary, "暂无案件摘要")}
                  </span>
                </button>
              ))}
              {caseProjects.length === 0 ? (
                <p className="empty-state">暂无案件项目</p>
              ) : null}
            </div>
            {caseProjects.length > 0 ? (
              <nav className="case-pagination" aria-label="案件列表分页">
                <button
                  disabled={
                    caseNavigationLocked || paginatedCaseProjects.page <= 1
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current - 1, caseProjects.length),
                    )
                  }
                >
                  上一页
                </button>
                <span aria-live="polite">
                  第 {paginatedCaseProjects.page} / {paginatedCaseProjects.totalPages} 页
                </span>
                <button
                  disabled={
                    caseNavigationLocked ||
                    paginatedCaseProjects.page >= paginatedCaseProjects.totalPages
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current + 1, caseProjects.length),
                    )
                  }
                >
                  下一页
                </button>
              </nav>
            ) : null}
          </aside>

          <section className="panel case-workbench-panel" aria-labelledby="case-workbench-title">
            <div className="panel-heading">
              <h2 id="case-workbench-title">案件工作台 β</h2>
              <span>{caseState.kind === "loading" ? "处理中" : "本地"}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={!assistantActiveProject || caseNavigationLocked}
                type="button"
                onClick={continueSelectedCaseInAssistant}
              >
                在助理中继续
              </button>
            </div>
            <div className="case-scroll">
              {caseState.kind === "error" ? (
                <p
                  className="error-text"
                  id="case-workbench-error"
                  role="alert"
                  aria-live="assertive"
                >
                  {caseState.message}
                </p>
              ) : null}
              <form className="case-form" onSubmit={saveCaseProject}>
                <fieldset
                  className="case-entity-fields"
                  disabled={caseProjectMutationLocked}
                >
                <div className="form-grid">
                  <label>
                    <span>案件名称</span>
                    <input
                      id="case-project-title"
                      value={caseProjectDraft.title}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          title: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>案件类型</span>
                    <input
                      value={caseProjectDraft.caseType}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          caseType: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>立案/接案日期</span>
                    <input
                      type="date"
                      value={caseProjectDraft.openedOn ?? ""}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          openedOn: event.target.value || null,
                        }))
                      }
                    />
                  </label>
                  <label>
                    <span>状态</span>
                    <select
                      value={caseProjectDraft.status}
                      onChange={(event) =>
                        setCaseProjectDraft((current) => ({
                          ...current,
                          status: event.target.value as "active" | "archived",
                        }))
                      }
                    >
                      <option value="active">进行中</option>
                      <option value="archived">已归档</option>
                    </select>
                  </label>
                </div>
                <label>
                  <span>摘要</span>
                  <textarea
                    value={caseProjectDraft.summary}
                    onChange={(event) =>
                      setCaseProjectDraft((current) => ({
                        ...current,
                        summary: event.target.value,
                      }))
                    }
                  />
                </label>
                <div className="command-row">
                  <button disabled={caseProjectMutationLocked} type="submit">
                    保存案件
                  </button>
                  <button
                    disabled={
                      !selectedCaseProjectId || caseProjectMutationLocked
                    }
                    type="button"
                    onClick={() => void removeCaseProject()}
                  >
                    删除案件
                  </button>
                  <button
                    disabled={!selectedCaseProjectId || caseProjectMutationLocked}
                    type="button"
                    onClick={openCaseGraph}
                  >
                    查看案件关系图
                  </button>
                </div>
                </fieldset>
              </form>
              {!caseChildrenReady ? (
                <p className="privacy-note">
                  请先保存案件；保存成功后才能录入、关联或删除案件子项。
                </p>
              ) : null}

              <section className="case-section">
                <div className="section-heading">
                  <h3>案件材料</h3>
                  <span>{caseWorkspace?.files.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFile}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                    }
                  >
                  {editingFile ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的案件材料；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>标题</span>
                      <input
                        id="case-file-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-file-title"}
                        value={fileDraft.title}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>类型</span>
                      <input
                        value={fileDraft.fileType}
                        onChange={(event) =>
                          setFileDraft((current) => ({
                            ...current,
                            fileType: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>材料摘要</span>
                    <textarea
                      value={fileDraft.summary}
                      onChange={(event) =>
                        setFileDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "file")
                      }
                      type="submit"
                    >
                      {editingFile ? "更新材料" : "添加材料"}
                    </button>
                    {editingFile ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.files.map((file) => (
                    <div className="compact-row" key={file.fileId}>
                      <label className="material-select">
                        <input
                          checked={extractionFileIds.includes(file.fileId)}
                          disabled={caseProjectMutationLocked}
                          type="checkbox"
                          onChange={(event) =>
                            setExtractionFileIds((current) =>
                              event.target.checked
                                ? [...current, file.fileId]
                                : current.filter(
                                    (fileId) => fileId !== file.fileId,
                                  ),
                            )
                          }
                        />
                        <strong>{publicTitle(file.title, "案件材料")}</strong>
                      </label>
                      <span>{publicTitle(file.fileType, "未分类")}</span>
                      <span>
                        {publicContentSummary(file.summary, "未填写材料摘要")}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "file", entity: file })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "file",
                            file.fileId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            extractionSourcesLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "file",
                              file.fileId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("file", file.fileId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>当事人</h3>
                  <span>{caseWorkspace?.parties.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveParty}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                    }
                  >
                  {editingParty ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的当事人；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>名称</span>
                      <input
                        id="case-party-name"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-party-name"}
                        value={partyDraft.name}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            name: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标准化名称</span>
                      <input
                        value={partyDraft.normalizedName}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            normalizedName: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>角色</span>
                      <select
                        value={partyDraft.role}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            role: event.target.value as PartyRole,
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </label>
                    <label>
                      <span>联系方式</span>
                      <input
                        value={partyDraft.contact}
                        onChange={(event) =>
                          setPartyDraft((current) => ({
                            ...current,
                            contact: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "party")
                      }
                      type="submit"
                    >
                      {editingParty ? "更新当事人" : "添加当事人"}
                    </button>
                    {editingParty ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.parties.map((party) => (
                    <div className="compact-row" key={party.partyId}>
                      <strong>{publicTitle(party.name, "案件当事人")}</strong>
                      <span>{formatPartyRole(party.role)}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "party",
                              entity: party,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "party",
                            party.partyId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "party",
                              party.partyId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("party", party.partyId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实时间线</h3>
                  <span>{caseWorkspace?.facts.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveFact}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                    }
                  >
                  {editingFact ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的事实；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>日期</span>
                      <input
                        type="date"
                        value={factDraft.occurredOn ?? ""}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            occurredOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>事实标题</span>
                      <input
                        id="case-fact-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-fact-title"}
                        value={factDraft.title}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>状态</span>
                      <select
                        value={factDraft.confirmationStatus}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            confirmationStatus:
                              event.target.value as ConfirmationStatus,
                          }))
                        }
                      >
                        <option value="confirmed">已确认事实</option>
                        <option value="model_suggested">待审阅建议</option>
                      </select>
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={factDraft.source}
                        onChange={(event) =>
                          setFactDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>事实描述</span>
                    <textarea
                      value={factDraft.description}
                      onChange={(event) =>
                        setFactDraft((current) => ({
                          ...current,
                          description: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "fact")
                      }
                      type="submit"
                    >
                      {editingFact ? "更新事实" : "添加事实"}
                    </button>
                    {editingFact ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.facts.map((fact) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "case_fact" &&
                        graphCaseTarget.sourceId === fact.factId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("case_fact", fact.factId)}
                      key={fact.factId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(fact.title, "案件事实")}</strong>
                      <span>
                        {fact.occurredOn ?? "未登记日期"} ·{" "}
                        {formatConfirmationStatus(fact.confirmationStatus)}
                      </span>
                      <span>
                        {publicCaseBusinessText(
                          fact.description,
                          "未填写事实描述",
                        )}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({ entityType: "fact", entity: fact })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "fact",
                            fact.factId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "fact",
                              fact.factId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("fact", fact.factId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>证据目录</h3>
                  <span>{caseWorkspace?.evidence.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveEvidence}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                    }
                  >
                  {editingEvidence ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的证据；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>编号</span>
                      <input
                        id="case-evidence-number"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-number"
                        }
                        value={evidenceDraft.evidenceNumber}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            evidenceNumber: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>标题</span>
                      <input
                        id="case-evidence-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-evidence-title"
                        }
                        value={evidenceDraft.title}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>来源</span>
                      <input
                        value={evidenceDraft.source}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            source: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>形成日期</span>
                      <input
                        type="date"
                        value={evidenceDraft.formedOn ?? ""}
                        onChange={(event) =>
                          setEvidenceDraft((current) => ({
                            ...current,
                            formedOn: event.target.value || null,
                          }))
                        }
                      />
                    </label>
                  </div>
                  <label>
                    <span>摘要</span>
                    <textarea
                      value={evidenceDraft.summary}
                      onChange={(event) =>
                        setEvidenceDraft((current) => ({
                          ...current,
                          summary: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(activeCaseEntityEditor, "evidence")
                      }
                      type="submit"
                    >
                      {editingEvidence ? "更新证据" : "添加证据"}
                    </button>
                    {editingEvidence ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.evidence.map((item) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "evidence_item" &&
                        graphCaseTarget.sourceId === item.evidenceId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("evidence_item", item.evidenceId)}
                      key={item.evidenceId}
                      tabIndex={-1}
                    >
                      <strong>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </strong>
                      <span>
                        {publicCaseBusinessText(item.source, "缺少来源")} ·{" "}
                        {item.formedOn ?? "缺少形成时间"}
                      </span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "evidence",
                              entity: item,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "evidence",
                            item.evidenceId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "evidence",
                              item.evidenceId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence", item.evidenceId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>事实-证据关联</h3>
                  <span>{caseWorkspace?.evidenceLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    id="case-link-fact"
                    aria-label="要关联的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={caseValidationTargetId === "case-link-fact"}
                    disabled={caseProjectMutationLocked}
                    value={linkFactId}
                    onChange={(event) => setLinkFactId(event.target.value)}
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-link-evidence"
                    aria-label="要关联的证据"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-link-evidence"
                    }
                    disabled={caseProjectMutationLocked}
                    value={linkEvidenceId}
                    onChange={(event) => setLinkEvidenceId(event.target.value)}
                  >
                    <option value="">选择证据</option>
                    {caseWorkspace?.evidence.map((item) => (
                      <option key={item.evidenceId} value={item.evidenceId}>
                        {publicEvidenceNumber(item.evidenceNumber)} ·{" "}
                        {publicTitle(item.title, "案件证据")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkEvidenceToFact()}
                  >
                    关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.evidenceLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const evidence = caseWorkspace.evidence.find(
                      (item) => item.evidenceId === link.evidenceId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          {publicEvidenceNumber(
                            evidence?.evidenceNumber,
                            "相关证据",
                          )}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("evidence_link", link.linkId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>争点与主张</h3>
                  <span>{caseWorkspace?.legalIssues.length ?? 0}</span>
                </div>
                <form className="case-form compact-case-form" onSubmit={saveIssue}>
                  <fieldset
                    className="case-entity-fields"
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      !caseEntityEditorAllows(
                        activeCaseEntityEditor,
                        "legal_issue",
                      )
                    }
                  >
                  {editingIssue ? (
                    <p className="case-edit-note" role="status">
                      正在更新已保存的争点；保存后将覆盖原记录。
                    </p>
                  ) : null}
                  <div className="form-grid">
                    <label>
                      <span>争点</span>
                      <input
                        id="case-issue-title"
                        aria-describedby="case-workbench-error"
                        aria-invalid={caseValidationTargetId === "case-issue-title"}
                        value={issueDraft.title}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            title: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <label>
                      <span>处理状态</span>
                      <select
                        value={issueDraft.status}
                        onChange={(event) =>
                          setIssueDraft((current) => ({
                            ...current,
                            status: event.target.value as LegalIssueStatus,
                          }))
                        }
                      >
                        <option value="open">待处理</option>
                        <option value="resolved">已解决</option>
                      </select>
                    </label>
                  </div>
                  <label>
                    <span>主张</span>
                    <textarea
                      value={issueDraft.claim}
                      onChange={(event) =>
                        setIssueDraft((current) => ({
                          ...current,
                          claim: event.target.value,
                        }))
                      }
                    />
                  </label>
                  <div className="command-row">
                    <button
                      disabled={
                        !caseChildrenReady ||
                        caseNavigationLocked ||
                        !caseEntityEditorAllows(
                          activeCaseEntityEditor,
                          "legal_issue",
                        )
                      }
                      type="submit"
                    >
                      {editingIssue ? "更新争点" : "添加争点"}
                    </button>
                    {editingIssue ? (
                      <button type="button" onClick={cancelCaseEntityEdit}>
                        取消编辑
                      </button>
                    ) : null}
                  </div>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalIssues.map((issue) => (
                    <div
                      className={`compact-row ${
                        graphCaseTarget?.sourceKind === "legal_issue" &&
                        graphCaseTarget.sourceId === issue.issueId
                          ? "graph-jump-target"
                          : ""
                      }`}
                      id={caseGraphNodeDomId("legal_issue", issue.issueId)}
                      key={issue.issueId}
                      tabIndex={-1}
                    >
                      <strong>{publicTitle(issue.title, "相关法律争点")}</strong>
                      <span>{formatLegalIssueStatus(issue.status)}</span>
                      <span>{publicCaseBusinessText(issue.claim, "尚未填写主张")}</span>
                      <div className="compact-row-actions">
                        <button
                          className="edit-action"
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            startCaseEntityEdit({
                              entityType: "legal_issue",
                              entity: issue,
                            })
                          }
                        >
                          {caseEntityEditorMatches(
                            activeCaseEntityEditor,
                            "legal_issue",
                            issue.issueId,
                          )
                            ? "编辑中"
                            : "编辑"}
                        </button>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            !caseEntityEditorAllows(
                              activeCaseEntityEditor,
                              "legal_issue",
                              issue.issueId,
                            )
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_issue", issue.issueId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <div>
                    <h3>事实—争点关联</h3>
                    <p className="muted">
                      仅保存你手动建立的关联，不会自动推断。
                    </p>
                  </div>
                  <span>{caseWorkspace?.factIssueLinks.length ?? 0}</span>
                </div>
                <div className="case-link-row">
                  <select
                    id="case-fact-issue-fact"
                    aria-label="要关联到争点的事实"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-fact"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueFactId}
                    onChange={(event) =>
                      setFactIssueFactId(event.target.value)
                    }
                  >
                    <option value="">选择事实</option>
                    {caseWorkspace?.facts.map((fact) => (
                      <option key={fact.factId} value={fact.factId}>
                        {publicTitle(fact.title, "相关事实")}
                      </option>
                    ))}
                  </select>
                  <select
                    id="case-fact-issue-issue"
                    aria-label="要关联到事实的争点"
                    aria-describedby="case-workbench-error"
                    aria-invalid={
                      caseValidationTargetId === "case-fact-issue-issue"
                    }
                    disabled={caseProjectMutationLocked}
                    value={factIssueIssueId}
                    onChange={(event) =>
                      setFactIssueIssueId(event.target.value)
                    }
                  >
                    <option value="">选择争点</option>
                    {caseWorkspace?.legalIssues.map((issue) => (
                      <option key={issue.issueId} value={issue.issueId}>
                        {publicTitle(issue.title, "相关法律争点")}
                      </option>
                    ))}
                  </select>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="button"
                    onClick={() => void linkFactToIssue()}
                  >
                    建立显式关联
                  </button>
                </div>
                <div className="compact-list">
                  {caseWorkspace?.factIssueLinks.map((link) => {
                    const fact = caseWorkspace.facts.find(
                      (item) => item.factId === link.factId,
                    );
                    const issue = caseWorkspace.legalIssues.find(
                      (item) => item.issueId === link.issueId,
                    );

                    return (
                      <div className="compact-row" key={link.linkId}>
                        <strong>{publicTitle(fact?.title, "相关事实")}</strong>
                        <span>
                          争点：{publicTitle(issue?.title, "相关法律争点")}
                        </span>
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity(
                              "fact_issue_link",
                              link.linkId,
                            )
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.factIssueLinks.length === 0 ? (
                    <p className="muted">尚未手动建立事实—争点关联。</p>
                  ) : null}
                </div>
              </section>

              <section className="case-section">
                <div className="section-heading">
                  <h3>法律依据</h3>
                  <span>{caseWorkspace?.legalBasis.length ?? 0}</span>
                </div>
                <form
                  className="case-form compact-case-form"
                  onSubmit={saveLegalBasis}
                >
                  <fieldset
                    className="case-entity-fields"
                    disabled={caseProjectMutationLocked}
                  >
                  <div className="form-grid">
                    <label>
                      <span>本地法律来源</span>
                      <select
                        id="case-basis-source-id"
                        aria-describedby="case-workbench-error"
                        aria-invalid={
                          caseValidationTargetId === "case-basis-source-id"
                        }
                        value={basisSourceId}
                        onChange={(event) => setBasisSourceId(event.target.value)}
                      >
                        <option value="">请选择已检索的法律来源</option>
                        {legalLibrary.activeSources.map((source) => (
                          <option key={source.sourceId} value={source.sourceId}>
                            {formatLegalSourceLabel(source)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>关联争点</span>
                      <select
                        value={basisIssueId}
                        onChange={(event) => setBasisIssueId(event.target.value)}
                      >
                        <option value="">不关联争点</option>
                        {caseWorkspace?.legalIssues.map((issue) => (
                          <option key={issue.issueId} value={issue.issueId}>
                            {publicTitle(issue.title, "相关法律争点")}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>案件日期</span>
                      <input
                        type="date"
                        value={basisCaseDate}
                        onChange={(event) => setBasisCaseDate(event.target.value)}
                      />
                      <small>
                        留空将按当前有效性校验，不会使用立案/接案日期代替。
                      </small>
                    </label>
                  </div>
                  <label>
                    <span>备注</span>
                    <textarea
                      value={basisNote}
                      onChange={(event) => setBasisNote(event.target.value)}
                    />
                  </label>
                  <div className="toggle-row">
                    <label>
                      <input
                        checked={basisIncludeExpired}
                        type="checkbox"
                        onChange={(event) =>
                          setBasisIncludeExpired(event.target.checked)
                        }
                      />
                      <span>允许已失效版本</span>
                    </label>
                  </div>
                  <button
                    disabled={
                      !caseChildrenReady ||
                      caseNavigationLocked ||
                      activeCaseEntityEditor !== null
                    }
                    type="submit"
                  >
                    添加依据
                  </button>
                  </fieldset>
                </form>
                <div className="compact-list">
                  {caseWorkspace?.legalBasis.map((basis, basisIndex) => {
                    const linkedIssue = caseWorkspace.legalIssues.find(
                      (issue) => issue.issueId === basis.issueId,
                    );
                    const isFirstBasisForSource =
                      caseWorkspace.legalBasis.findIndex(
                        (item) => item.sourceId === basis.sourceId,
                      ) === basisIndex;

                    return (
                      <div
                        className={`compact-row legal-basis-row legal-basis-row--${basis.status} ${
                          graphCaseTarget?.sourceKind === "verified_citation" &&
                          graphCaseTarget.sourceId === basis.sourceId
                            ? "graph-jump-target"
                            : ""
                        }`}
                        id={
                          isFirstBasisForSource
                            ? caseGraphNodeDomId("verified_citation", basis.sourceId)
                            : undefined
                        }
                        key={basis.basisId}
                        tabIndex={-1}
                      >
                        <strong>{formatLegalBasisTitle(basis)}</strong>
                        <span>
                          {formatLegalBasisStatus(basis.status)}
                          {basis.status === "invalid"
                            ? ` · ${formatLegalBasisInvalidReason(
                                basis.invalidReason,
                              )}`
                            : ""}{" "}
                          ·{" "}
                          {basis.versionStatus
                            ? formatStatus(basis.versionStatus)
                            : "未校验版本"}{" "}
                          · {formatLegalBasisWindow(basis)}
                        </span>
                        <span>
                          {linkedIssue
                            ? `争点：${publicTitle(linkedIssue.title, "相关法律争点")}`
                            : "未关联争点"}{" "}
                          · {basis.caseDate ?? "未指定案件日期"}
                        </span>
                        {basis.excerpt ? (
                          <span>内容摘要：{publicContentSummary(basis.excerpt)}</span>
                        ) : null}
                        {basis.note ? (
                          <span>
                            {sanitizePublicGeneratedText(
                              basis.note,
                              "补充说明暂不可用。",
                            )}
                          </span>
                        ) : null}
                        <button
                          disabled={
                            caseNavigationLocked ||
                            activeCaseEntityEditor !== null
                          }
                          type="button"
                          onClick={() =>
                            void removeCaseEntity("legal_basis", basis.basisId)
                          }
                        >
                          删除
                        </button>
                      </div>
                    );
                  })}
                  {caseWorkspace && caseWorkspace.legalBasis.length === 0 ? (
                    <p className="empty-state">暂无法律依据</p>
                  ) : null}
                </div>
              </section>
            </div>
          </section>

          <aside className="panel case-gap-panel" aria-labelledby="case-gap-title">
            <div className="panel-heading">
              <h2 id="case-gap-title">缺口分析</h2>
              <span>{caseWorkspace?.gaps.length ?? 0}</span>
            </div>
            <div className="compact-list">
              {caseWorkspace?.gaps.map((gap) => (
                <div className="compact-row" key={gap.gapId}>
                  <strong>
                    {formatGapSeverity(gap.severity)} · {formatGapKind(gap.kind)}
                  </strong>
                  <span>{gap.message}</span>
                </div>
              ))}
              {caseWorkspace && caseWorkspace.gaps.length === 0 ? (
                <p className="empty-state">当前没有证据缺口</p>
              ) : null}
            </div>

            <section className="provider-subsection">
              <h3>待核实事项</h3>
              <div className="compact-list extraction-uncertainty-list">
                {caseWorkspace?.uncertainties.map((uncertainty) => (
                  <div className="compact-row" key={uncertainty.uncertaintyId}>
                    <strong>
                      {publicCaseBusinessText(
                        uncertainty.description,
                        "相关事项需要核实",
                      )}
                    </strong>
                    <span>
                      {uncertainty.status === "open" ? "待核实" : "已解决"} ·{" "}
                      {formatConfirmationStatus(uncertainty.confirmationStatus)}
                    </span>
                    <button
                      disabled={
                        caseNavigationLocked ||
                        activeCaseEntityEditor !== null
                      }
                      type="button"
                      onClick={() =>
                        void removeCaseEntity(
                          "uncertainty",
                          uncertainty.uncertaintyId,
                        )
                      }
                    >
                      删除
                    </button>
                  </div>
                ))}
                {caseWorkspace && caseWorkspace.uncertainties.length === 0 ? (
                  <p className="empty-state">暂无独立待核实事项</p>
                ) : null}
              </div>
            </section>

            <section className="provider-subsection extraction-panel">
              <h3>材料信息整理</h3>
              <p className="privacy-note">
                仅处理已勾选材料的摘要，不会读取原始文件。整理结果须经你逐项审阅，确认前不会改动案件内容。
              </p>
              {pendingReviewRecoveryBlock?.projectId ===
              selectedCaseProjectId ? (
                <div className="risk-banner" role="alert">
                  <p>{pendingReviewRecoveryBlock.message}</p>
                  <button
                    disabled={extractionDiscarding || caseMutationInFlight}
                    type="button"
                    onClick={() =>
                      pendingReviewRecoveryBlock.reloadRequired
                        ? void reloadServerExtractionDraft(
                            pendingReviewRecoveryBlock.projectId,
                          )
                        : void discardUnrestorablePendingReview()
                    }
                  >
                    {pendingReviewRecoveryBlock.reloadRequired
                      ? caseMutationInFlight
                        ? "正在重新加载…"
                        : "重新加载最新草稿"
                      : extractionDiscarding
                        ? "正在放弃…"
                        : "放弃该待审阅草稿并解锁案件"}
                  </button>
                </div>
              ) : null}
              <label>
                <span>Provider</span>
                <select
                  id="extraction-provider"
                  aria-describedby="case-workbench-error"
                  aria-invalid={
                    caseValidationTargetId === "extraction-provider"
                  }
                  disabled={caseProjectMutationLocked}
                  value={extractionProviderId}
                  onChange={(event) =>
                    setExtractionProviderId(event.target.value)
                  }
                >
                  <option value="">选择已保存 Provider</option>
                  {providerProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.displayName} · {profile.modelId}
                    </option>
                  ))}
                </select>
              </label>
              <button
                disabled={
                  !caseChildrenReady ||
                  caseProjectMutationLocked ||
                  activeCaseEntityEditor !== null ||
                  extractionLocksSources(extractionState)
                }
                type="button"
                onClick={() => void runStructuredExtraction()}
              >
                {extractionState.kind === "generating"
                  ? "正在请求并严格校验…"
                  : `生成待审阅内容（已选 ${extractionFileIds.length} 份材料）`}
              </button>

              {extractionState.kind === "reviewing" ||
              extractionState.kind === "committing" ? (
                <div
                  className="extraction-review"
                  role="region"
                  aria-labelledby="extraction-review-title"
                  aria-describedby="extraction-review-description"
                  onKeyDown={(event) => {
                    if (
                      event.key === "Escape" &&
                      extractionState.kind === "reviewing" &&
                      !extractionConfirmPreparing &&
                      !extractionDiscarding &&
                      !extractionReviewReloadRequired.current
                    ) {
                      event.preventDefault();
                      void cancelExtractionReview();
                    }
                  }}
                  ref={extractionReviewRef}
                  tabIndex={-1}
                >
                  <div className="review-banner" aria-live="polite">
                    <strong id="extraction-review-title">
                      待审阅整理结果，尚未保存
                    </strong>
                    <span>
                      <span id="extraction-review-description" className="sr-only">
                        请逐项审阅整理结果。按 Escape 可取消且不会保存。
                      </span>
                      {extractionState.restored
                        ? `已从本地恢复待审阅草稿（创建于 ${extractionState.restoredCreatedAt ?? "未知时间"}，到期于 ${extractionState.restoredExpiresAt ?? "未知时间"}）。`
                        : extractionState.repaired
                          ? "初次结果未通过校验，系统已修正并重新校验。"
                          : "整理结果已通过系统校验。"}
                    </span>
                  </div>
                  <p
                    className={
                      extractionDraftSaveState.kind === "conflict"
                        ? "error-text"
                        : "privacy-note"
                    }
                    role={
                      extractionDraftSaveState.kind === "conflict"
                        ? "alert"
                        : "status"
                    }
                  >
                    {extractionDraftSaveState.kind === "pending"
                      ? "审阅修改等待自动保存…"
                      : extractionDraftSaveState.kind === "saving"
                        ? "正在保存审阅修改…"
                        : extractionDraftSaveState.kind === "saved"
                          ? `审阅修改已保存${
                              extractionDraftSaveState.expiresAt
                                ? `；草稿到期于 ${extractionDraftSaveState.expiresAt}`
                                : ""
                            }。`
                          : extractionDraftSaveState.kind === "conflict"
                            ? extractionDraftSaveState.message
                            : "模型原始建议已保存在本地；编辑后会自动保存。"}
                  </p>
                  {extractionDraftSaveState.kind === "conflict" ? (
                    <div className="risk-banner" role="alert">
                      <p>
                        为避免覆盖其他窗口或重复提交，必须放弃本窗口尚未确认的内容并重新读取最新草稿。
                      </p>
                      <button
                        disabled={caseMutationInFlight || extractionDiscarding}
                        type="button"
                        onClick={() =>
                          void reloadServerExtractionDraft(
                            extractionState.context.projectId,
                          )
                        }
                      >
                        {caseMutationInFlight
                          ? "正在重新加载…"
                          : "重新加载最新草稿"}
                      </button>
                    </div>
                  ) : null}

                  <fieldset
                    className="review-fields"
                    disabled={
                      extractionState.kind === "committing" ||
                      extractionConfirmPreparing ||
                      extractionDiscarding ||
                      extractionClosePreparing ||
                      extractionDraftSaveState.kind === "conflict"
                    }
                  >
                  <legend className="sr-only">材料信息审阅字段</legend>
                  <h4 id="extraction-parties-title">当事人</h4>
                  {extractionState.draft.parties.map((party, index) => (
                    <div
                      className="review-card"
                      key={`party-${index}`}
                      role="group"
                      aria-label={`建议当事人 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议当事人：{party.name || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议当事人 ${index + 1}`}
                        value={party.name}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, name: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <select
                        aria-label={`建议当事人 ${index + 1} 的角色`}
                        value={party.role}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            parties: draft.parties.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    role: event.target.value as PartyRole,
                                  }
                                : item,
                            ),
                          }))
                        }
                      >
                        <option value="plaintiff">原告</option>
                        <option value="defendant">被告</option>
                        <option value="claimant">申请人</option>
                        <option value="respondent">被申请人</option>
                        <option value="third_party">第三人</option>
                        <option value="other">其他</option>
                      </select>
                    </div>
                  ))}

                  <h4 id="extraction-facts-title">事实</h4>
                  {extractionState.draft.facts.map((fact, index) => (
                    <div
                      className="review-card"
                      key={`fact-${index}`}
                      role="group"
                      aria-label={`建议事实 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议事实：{fact.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议事实 ${index + 1} 的发生日期`}
                        type="date"
                        value={fact.occurredOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    occurredOn: event.target.value || null,
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议事实 ${index + 1} 的标题`}
                        value={fact.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, title: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议事实 ${index + 1} 的描述`}
                        value={fact.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, description: event.target.value }
                                : item,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议事实 ${index + 1} 关联的证据编号，逗号分隔`}
                        value={fact.evidenceNumbers.join(", ")}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            facts: draft.facts.map((item, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...item,
                                    evidenceNumbers: event.target.value
                                      .split(/[,，]/u)
                                      .map((value) => value.trim())
                                      .filter(Boolean),
                                  }
                                : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-evidence-title">证据</h4>
                  {extractionState.draft.evidence.map((item, index) => (
                    <div
                      className="review-card"
                      key={`evidence-${index}`}
                      role="group"
                      aria-label={`建议证据 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议证据：{item.evidenceNumber || item.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议证据 ${index + 1} 的编号`}
                        value={item.evidenceNumber}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    evidenceNumber: event.target.value,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的标题`}
                        value={item.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, title: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的来源`}
                        value={item.source}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, source: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <input
                        aria-label={`建议证据 ${index + 1} 的形成日期`}
                        type="date"
                        value={item.formedOn ?? ""}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? {
                                    ...evidence,
                                    formedOn: event.target.value || null,
                                  }
                                : evidence,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议证据 ${index + 1} 的摘要`}
                        value={item.summary}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            evidence: draft.evidence.map((evidence, itemIndex) =>
                              itemIndex === index
                                ? { ...evidence, summary: event.target.value }
                                : evidence,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-issues-title">争点与主张</h4>
                  {extractionState.draft.legalIssues.map((issue, index) => (
                    <div
                      className="review-card"
                      key={`issue-${index}`}
                      role="group"
                      aria-label={`建议争点 ${index + 1}`}
                    >
                      <button
                        className="review-remove"
                        type="button"
                        onClick={() =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.filter(
                              (_, itemIndex) => itemIndex !== index,
                            ),
                          }))
                        }
                      >
                        移除建议争点：{issue.title || `第 ${index + 1} 项`}
                      </button>
                      <input
                        aria-label={`建议争点 ${index + 1} 的标题`}
                        value={issue.title}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, title: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议争点 ${index + 1} 的描述`}
                        value={issue.description}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? {
                                      ...item,
                                      description: event.target.value,
                                    }
                                  : item,
                            ),
                          }))
                        }
                      />
                      <textarea
                        aria-label={`建议争点 ${index + 1} 的主张`}
                        value={issue.claim}
                        onChange={(event) =>
                          updateExtractionDraft((draft) => ({
                            ...draft,
                            legalIssues: draft.legalIssues.map(
                              (item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, claim: event.target.value }
                                  : item,
                            ),
                          }))
                        }
                      />
                    </div>
                  ))}

                  <h4 id="extraction-uncertainties-title">待核实事项</h4>
                  {extractionState.draft.uncertainties.map(
                    (uncertainty, index) => (
                      <div
                        className="review-card"
                        key={`uncertainty-${index}`}
                        role="group"
                        aria-label={`建议待核实事项 ${index + 1}`}
                      >
                        <button
                          className="review-remove"
                          type="button"
                          onClick={() =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.filter(
                                (_, itemIndex) => itemIndex !== index,
                              ),
                            }))
                          }
                        >
                          移除建议待核实事项：{uncertainty.description || `第 ${index + 1} 项`}
                        </button>
                        <textarea
                          aria-label={`建议待核实事项 ${index + 1} 的描述`}
                          value={uncertainty.description}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        description: event.target.value,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                        <select
                          aria-label={`建议待核实事项 ${index + 1} 的关联实体类型`}
                          value={uncertainty.relatedEntityType}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedEntityType: event.target.value as typeof item.relatedEntityType,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        >
                          <option value="general">一般</option>
                          <option value="party">当事人</option>
                          <option value="fact">事实</option>
                          <option value="evidence">证据</option>
                          <option value="legal_issue">争点</option>
                        </select>
                        <input
                          aria-label={`建议待核实事项 ${index + 1} 的关联名称或编号`}
                          placeholder="关联名称/标题/证据编号（可空）"
                          value={uncertainty.relatedReference ?? ""}
                          onChange={(event) =>
                            updateExtractionDraft((draft) => ({
                              ...draft,
                              uncertainties: draft.uncertainties.map(
                                (item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        relatedReference:
                                          event.target.value || null,
                                      }
                                    : item,
                              ),
                            }))
                          }
                        />
                      </div>
                    ),
                  )}
                  </fieldset>

                  {extractionState.kind === "reviewing" &&
                  extractionState.commitError ? (
                    <p className="error-text" role="alert">
                      {extractionState.commitError}
                    </p>
                  ) : null}
                  {extractionDiscardError ? (
                    <p className="error-text" role="alert">
                      {extractionDiscardError}
                    </p>
                  ) : null}

                  <div className="review-actions">
                    <button
                      className="secondary-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void cancelExtractionReview()}
                    >
                      {extractionDiscarding
                        ? "正在取消…"
                        : extractionClosePreparing
                          ? "正在保存并关闭…"
                          : "取消，不写入"}
                    </button>
                    <button
                      className="confirm-action"
                      disabled={
                        extractionState.kind === "committing" ||
                        extractionConfirmPreparing ||
                        extractionDiscarding ||
                        extractionClosePreparing ||
                        extractionDraftSaveState.kind === "conflict"
                      }
                      type="button"
                      onClick={() => void confirmExtractionReview()}
                    >
                      {extractionClosePreparing
                        ? "正在保存并关闭窗口…"
                        : extractionState.kind === "committing"
                        ? "正在保存审阅结果…"
                        : extractionConfirmPreparing
                          ? "正在保存并准备确认…"
                        : "确认并保存审阅结果"}
                    </button>
                  </div>
                </div>
              ) : null}

              {extractionState.kind === "failed" ? (
                <div className="extraction-failure">
                  <strong>
                    材料信息整理未完成：
                    {publicErrorMessage(
                      extractionState.message,
                      "请检查模型服务和网络后重试。",
                    )}
                  </strong>
                  <span>
                    {extractionState.repairAttempted
                      ? "系统已尝试修正，但结果仍未通过校验。"
                      : "模型服务或网络异常，未生成可审阅内容。"}
                  </span>
                  <button type="button" onClick={resetExtractionResult}>
                    关闭
                  </button>
                </div>
              ) : null}

              {extractionState.kind === "committed" ? (
                <div className="connection-summary">
                  <span className="status-dot status-dot--succeeded" />
                  <strong>审阅结果已写入案件。</strong>
                </div>
              ) : null}
            </section>
          </aside>
        </CasesWorkspace>
      ) : (
        <ProviderSettingsWorkspace controller={providerSettings} />
      )}
    </AppShell>
  );
}
