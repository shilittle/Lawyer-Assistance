import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

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
import { CaseWorkspaceCompatibilityOutlet } from "./features/cases/CaseWorkspaceCompatibilityOutlet";
import {
  caseGraphNodeDomId,
  graphNodeDestination,
} from "./features/cases/model";
import { useCaseWorkspaceController } from "./features/cases/useCaseWorkspaceController";
import { LegacyQaWorkspace } from "./features/legal-library/LegacyQaWorkspace";
import { LegalLibrarySearchWorkspace } from "./features/legal-library/LegalLibrarySearchWorkspace";
import { useLegalLibraryController } from "./features/legal-library/useLegalLibraryController";
import { ProviderSettingsWorkspace } from "./features/settings/providers/ProviderSettingsWorkspace";
import { useProviderSettingsController } from "./features/settings/providers/useProviderSettingsController";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import { publicErrorMessage } from "./publicOutput";

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
    selectedCaseProjectId,
    caseWorkspace,
    assistantActiveProject,
    assistantProposalApplyBlockedReason,
    refreshCaseAfterAssistantProposal,
    reportCaseError,
    setUnsupportedGraphNodeStatus,
  } = caseController;
  const {
    deletionBlockedProviderId: providerDeletionBlockedProviderId,
    closeGuard: caseCloseGuard,
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
        <CaseWorkspaceCompatibilityOutlet
          controller={caseController}
          graphTarget={graphCaseTarget}
          legalSources={legalLibrary.activeSources}
          onContinueInAssistant={continueSelectedCaseInAssistant}
          onOpenCaseGraph={openCaseGraph}
          providerProfiles={providerProfiles}
        />
      ) : (
        <ProviderSettingsWorkspace controller={providerSettings} />
      )}
    </AppShell>
  );
}
