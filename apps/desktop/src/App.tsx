import {
  lazy,
  Suspense,
  useCallback,
  useMemo,
} from "react";

import { AppErrorBoundary } from "./app/AppErrorBoundary";
import { AppRouter, type AppRouterSlots } from "./app/AppRouter";
import { AppShell } from "./app/AppShell";
import type {
  AppRoute,
  ApprovedProviderTaskRequest,
  GraphTargetRequest,
  LegalCitationRequest,
} from "./app/routes";
import { useAppNavigationController } from "./app/useAppNavigationController";
import { useHealthStatus } from "./app/useHealthStatus";
import { useWindowCloseProtection } from "./app/useWindowCloseProtection";
import { useWorkspaceActivityChannel } from "./app/useWorkspaceActivityChannel";
import { AssistantWorkspace } from "./features/assistant/AssistantWorkspace";
import { useAssistantController } from "./features/assistant/useAssistantController";
import { CaseWorkspaceCompatibilityOutlet } from "./features/cases/CaseWorkspaceCompatibilityOutlet";
import { useCaseMaterialActivityChannel } from "./features/cases/materials/useCaseMaterialActivityChannel";
import { graphNodeDestination } from "./features/cases/model";
import { useGraphOutputController } from "./features/cases/outputs/useGraphOutputController";
import { useCaseWorkspaceController } from "./features/cases/useCaseWorkspaceController";
import { LegacyQaWorkspace } from "./features/legal-library/LegacyQaWorkspace";
import { LegalLibrarySearchWorkspace } from "./features/legal-library/LegalLibrarySearchWorkspace";
import { useLegalLibraryController } from "./features/legal-library/useLegalLibraryController";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import { ProviderSettingsWorkspace } from "./features/settings/providers/ProviderSettingsWorkspace";
import {
  providerApiKeyDeletionConfirmation,
  providerApiKeyOverwriteConfirmation,
  providerDeletionConfirmation,
  providerNavigationHasUnsavedChanges,
  runConfirmedDestructiveAction,
} from "./features/settings/providers/policies";
import { useProviderSettingsController } from "./features/settings/providers/useProviderSettingsController";
import type { GraphNode } from "./ipc/graph/types";

const DocumentWorkspace = lazy(() =>
  import("./DocumentWorkspace").then((module) => ({
    default: module.DocumentWorkspace,
  })),
);
const GraphWorkspace = lazy(() =>
  import("./GraphWorkspace").then((module) => ({
    default: module.GraphWorkspace,
  })),
);
const McpAndAutomationWorkspace = lazy(() =>
  import("./features/settings/automation/McpAndAutomationWorkspace").then(
    (module) => ({
      default: module.McpAndAutomationWorkspace,
    }),
  ),
);
const PrivacyWorkspace = lazy(() =>
  import("./features/privacy/PrivacyWorkspace").then((module) => ({
    default: module.PrivacyWorkspace,
  })),
);
const ReleaseWorkspace = lazy(() =>
  import("./ReleaseWorkspace").then((module) => ({
    default: module.ReleaseWorkspace,
  })),
);

const ASSISTANT_ROUTE = {
  area: "assistant",
  page: "chat",
} as const satisfies AppRoute;
const LEGAL_LIBRARY_ROUTE = {
  area: "legal-library",
  page: "library",
} as const satisfies AppRoute;
const PROVIDER_SETTINGS_ROUTE = {
  area: "settings",
  page: "providers",
} as const satisfies AppRoute;
const CASE_ASSISTANT_ROUTE = {
  area: "cases",
  page: "work",
} as const satisfies AppRoute;
const CASE_GRAPH_ROUTE = {
  area: "cases",
  page: "outputs",
  output: "graph",
} as const satisfies AppRoute;

export function App() {
  const health = useHealthStatus();
  const graphOutput = useGraphOutputController();
  const mcpActivity = useWorkspaceActivityChannel();
  const privacyActivity = useWorkspaceActivityChannel();
  const caseMaterialsActivity = useCaseMaterialActivityChannel();
  const confirmDiscard = useCallback(
    (message: string) => window.confirm(message),
    [],
  );
  const navigation = useAppNavigationController({
    mcp: mcpActivity,
    privacy: privacyActivity,
    caseMaterials: caseMaterialsActivity,
    confirmDiscard,
  });
  const consumeRouteState = navigation.consumeRouteState;
  const assistantController = useAssistantController();
  const caseController = useCaseWorkspaceController({
    onLegacyApprovedProviderRequest:
      redirectLegacyEgressToApprovedProvider,
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
  const legalLibrary = useLegalLibraryController({
    qaActive:
      navigation.route.area === "assistant" &&
      navigation.route.page === "legacy-qa",
    selectedCaseProjectId,
    assistantConversation: assistantController.conversation,
    assistantActiveProject,
    onNavigateToSearch: () => navigateFromShell(LEGAL_LIBRARY_ROUTE),
    onOpenLawGraph: openLawGraph,
    onOpenCaseAssistant: openSelectedCaseAssistant,
    onOpenAssistant: () => navigateFromShell(ASSISTANT_ROUTE),
    onLegacyApprovedProviderRequest:
      redirectLegacyEgressToApprovedProvider,
    onAddAssistantLegalSource: assistantController.addLegalSource,
    onProposeAssistantLegalBasis: (sourceId) =>
      assistantController.proposeLegalBasisForCase(
        sourceId,
        selectedCaseProjectId,
      ),
  });
  const {
    deletionBlockedProviderId: providerDeletionBlockedProviderId,
    closeGuard: caseCloseGuard,
    selectInitialProvider: selectInitialExtractionProvider,
    handleProviderSaved: handleExtractionProviderSaved,
    handleProviderDeleted: handleExtractionProviderDeleted,
  } = caseController.extraction;

  const handleInitialProviderSelected = useCallback(
    (providerId: string) => {
      legalLibrary.providerBridge.selectInitialProvider(providerId);
      selectInitialExtractionProvider(providerId);
    },
    [legalLibrary.providerBridge, selectInitialExtractionProvider],
  );
  const handleProviderSaved = useCallback(
    (providerId: string) => {
      handleExtractionProviderSaved(providerId);
    },
    [handleExtractionProviderSaved],
  );
  const handleProviderDeleted = useCallback(
    (deletedProviderId: string, fallbackProviderId: string | null) => {
      legalLibrary.providerBridge.handleProviderDeleted(
        deletedProviderId,
        fallbackProviderId,
      );
      handleExtractionProviderDeleted(
        deletedProviderId,
        fallbackProviderId,
      );
    },
    [handleExtractionProviderDeleted, legalLibrary.providerBridge],
  );
  const providerSettings = useProviderSettingsController({
    policies: {
      hasUnsavedChanges: providerNavigationHasUnsavedChanges,
      providerDeletionConfirmation,
      apiKeyDeletionConfirmation: providerApiKeyDeletionConfirmation,
      apiKeyOverwriteConfirmation:
        providerApiKeyOverwriteConfirmation,
      runConfirmedDestructiveAction,
      confirmAction: confirmDiscard,
    },
    deletionBlockedProviderId: providerDeletionBlockedProviderId,
    onInitialProviderSelected: handleInitialProviderSelected,
    onProviderSaved: handleProviderSaved,
    onProviderDeleted: handleProviderDeleted,
  });
  const providerActivity = useMemo(
    () => ({
      readDraftDirty: () =>
        providerSettings.hasUnsavedChangesRef.current,
      readMutationInFlight: () =>
        providerSettings.mutationInFlightRef.current,
    }),
    [
      providerSettings.hasUnsavedChangesRef,
      providerSettings.mutationInFlightRef,
    ],
  );
  const readLegalBridgeMutationInFlight = useCallback(
    () => legalLibrary.bridgeMutationInFlightRef.current,
    [legalLibrary.bridgeMutationInFlightRef],
  );
  const windowClose = useWindowCloseProtection({
    assistantActivity: assistantController.activity,
    caseCloseGuard,
    provider: providerActivity,
    mcp: mcpActivity,
    privacy: privacyActivity,
    caseMaterials: caseMaterialsActivity,
    readLegalBridgeMutationInFlight,
    onCaseCloseBlocked: reportCaseError,
  });

  function completeNavigation(didNavigate: boolean): boolean {
    if (didNavigate) {
      windowClose.clearProtectionMessage();
    }
    return didNavigate;
  }

  function navigateFromShell(nextRoute: AppRoute): boolean {
    if (!completeNavigation(navigation.navigate(nextRoute))) {
      return false;
    }
    if (
      nextRoute.area === "cases" &&
      nextRoute.page === "outputs" &&
      nextRoute.output === "graph"
    ) {
      graphOutput.prepareForNavigation(
        selectedCaseProjectId != null,
        legalLibrary.search.selectedDocument != null,
      );
    }
    return true;
  }

  function redirectLegacyEgressToApprovedProvider(
    task: ApprovedProviderTaskRequest["task"],
    notice: string,
  ): void {
    completeNavigation(
      navigation.handoffApprovedProvider({ task, notice }),
    );
  }

  function openSelectedCaseAssistant(): void {
    if (!assistantActiveProject) return;
    navigateFromShell(CASE_ASSISTANT_ROUTE);
  }

  function openCaseGraph(): void {
    if (!selectedCaseProjectId) return;
    if (navigateFromShell(CASE_GRAPH_ROUTE)) {
      graphOutput.showCaseGraph();
    }
  }

  function openLawGraph(documentId: string): void {
    void documentId;
    if (navigateFromShell(CASE_GRAPH_ROUTE)) {
      graphOutput.showLawGraph();
    }
  }

  function openGraphNode(node: GraphNode): void {
    const destination = graphNodeDestination(node);
    if (destination === "law") {
      void legalLibrary.openLawDocumentFromGraph(node);
      return;
    }
    if (destination === "case") {
      completeNavigation(
        navigation.handoffGraphTarget({
          sourceKind: node.sourceKind,
          sourceId: node.sourceId,
        }),
      );
      return;
    }
    setUnsupportedGraphNodeStatus();
  }

  const consumeGraphTarget = useCallback(
    (request: GraphTargetRequest) => {
      consumeRouteState({
        area: "cases",
        page: "work",
        state: { kind: "graph-target", request },
      });
    },
    [consumeRouteState],
  );
  const consumeLegalCitation = useCallback(
    (request: LegalCitationRequest) => {
      consumeRouteState({
        area: "legal-library",
        page: "library",
        state: { kind: "legal-citation", request },
      });
    },
    [consumeRouteState],
  );
  const consumeApprovedProviderTask = useCallback(
    (request: ApprovedProviderTaskRequest) => {
      consumeRouteState({
        area: "settings",
        page: "mcp",
        state: { kind: "approved-provider-task", request },
      });
    },
    [consumeRouteState],
  );

  const slots: AppRouterSlots = {
    assistant: () => (
      <AssistantWorkspace
        activeProject={assistantActiveProject}
        externalRefreshKey={assistantController.refreshKey}
        providerProfiles={providerSettings.profiles}
        proposalApplyBlockedReason={assistantProposalApplyBlockedReason}
        onCaseProposalApplied={refreshCaseAfterAssistantProposal}
        onConversationChange={
          assistantController.workspaceCallbacks.onConversationChange
        }
        onDraftDirtyChange={
          assistantController.workspaceCallbacks.onDraftDirtyChange
        }
        onMutationActivityChange={
          assistantController.workspaceCallbacks
            .onMutationActivityChange
        }
        onOpenProtectedArtifactRegeneration={(notice) =>
          redirectLegacyEgressToApprovedProvider("regenerate", notice)
        }
        onOpenProviderSettings={() =>
          navigateFromShell(PROVIDER_SETTINGS_ROUTE)
        }
        onRunActivityChange={
          assistantController.workspaceCallbacks.onRunActivityChange
        }
      />
    ),
    qa: () => (
      <LegacyQaWorkspace
        caseWorkspace={caseWorkspace}
        controller={legalLibrary}
        providerProfiles={providerSettings.profiles}
      />
    ),
    cases: ({ route }) => (
      <CaseWorkspaceCompatibilityOutlet
        section={route.page}
        controller={caseController}
        graphTarget={route.state?.request ?? null}
        legalSources={legalLibrary.activeSources}
        onGraphTargetConsumed={consumeGraphTarget}
        onOpenCaseGraph={openCaseGraph}
        providerProfiles={providerSettings.profiles}
        caseMaterialResetKey={caseMaterialsActivity.resetKey}
        onCaseMaterialDraftDirtyChange={caseMaterialsActivity.onDraftDirtyChange}
        onCaseMaterialMutationActivityChange={caseMaterialsActivity.onMutationActivityChange}
        onBeforeCaseMaterialProjectChange={navigation.guardCaseMaterialContextChange}
      />
    ),
    documents: () => (
      <Suspense
        fallback={
          <p className="empty-state">正在加载文书工作台…</p>
        }
      >
        <DocumentWorkspace
          projectId={selectedCaseProjectId}
          onOpenCitation={(citation) =>
            completeNavigation(
              navigation.handoffLegalCitation(citation),
            )
          }
        />
      </Suspense>
    ),
    graph: () => (
      <Suspense
        fallback={<p className="empty-state">正在加载关系图…</p>}
      >
        <GraphWorkspace
          documentId={
            legalLibrary.graphDocumentId ??
            legalLibrary.search.selectedDocument?.documentId ??
            null
          }
          mode={graphOutput.mode}
          projectId={selectedCaseProjectId}
          onModeChange={graphOutput.setMode}
          onOpenNode={openGraphNode}
        />
      </Suspense>
    ),
    search: ({ route }) => (
      <LegalLibrarySearchWorkspace
        citationRequest={route.state?.request ?? null}
        controller={legalLibrary}
        onCitationRequestConsumed={consumeLegalCitation}
      />
    ),
    providers: () => (
      <ProviderSettingsWorkspace controller={providerSettings} />
    ),
    privacy: () => (
      <SettingsWorkspace mode="privacy">
        <Suspense
          fallback={
            <p className="empty-state">正在加载隐私设置…</p>
          }
        >
          <PrivacyWorkspace
            onDraftDirtyChange={
              privacyActivity.onDraftDirtyChange
            }
            onMutationActivityChange={
              privacyActivity.onMutationActivityChange
            }
          />
        </Suspense>
      </SettingsWorkspace>
    ),
    mcp: ({ route }) => (
      <SettingsWorkspace mode="mcp">
        <Suspense
          fallback={
            <p className="empty-state">
              正在加载 MCP 与自动化设置…
            </p>
          }
        >
          <McpAndAutomationWorkspace
            providerTaskRequest={route.state?.request ?? null}
            onProviderTaskRequestConsumed={
              consumeApprovedProviderTask
            }
            onDraftDirtyChange={mcpActivity.onDraftDirtyChange}
            onMutationActivityChange={
              mcpActivity.onMutationActivityChange
            }
          />
        </Suspense>
      </SettingsWorkspace>
    ),
    release: () => (
      <SettingsWorkspace mode="maintenance">
        <Suspense
          fallback={
            <p className="empty-state">正在加载版本信息…</p>
          }
        >
          <ReleaseWorkspace />
        </Suspense>
      </SettingsWorkspace>
    ),
  };
  const protectionMessage =
    navigation.protectionMessage ?? windowClose.protectionMessage;

  return (
    <AppErrorBoundary resetKey="app-root">
      <AppShell
        route={navigation.route}
        status={{ kind: health.state.kind, text: health.text }}
        onNavigate={navigateFromShell}
      >
        {protectionMessage ? (
          <p className="error-text" role="alert" aria-live="assertive">
            {protectionMessage}
          </p>
        ) : null}
        <AppRouter
          route={navigation.route}
          assistantHostRoute={navigation.assistantHostRoute}
          slots={slots}
          onNavigate={navigateFromShell}
        />
      </AppShell>
    </AppErrorBoundary>
  );
}
