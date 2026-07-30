import { useCallback, useRef, useState } from "react";

import {
  decideCaseMaterialContextChange,
  decideCaseMaterialRouteNavigation,
  decideMcpRouteNavigation,
  decidePrivacyRouteNavigation,
} from "./navigationGuards";
import {
  DEFAULT_ROUTE,
  sameRouteLocation,
  sameRouteStateRequest,
  type AppRoute,
  type ApprovedProviderTaskRequest,
  type AssistantCaseHandoffRequest,
  type AssistantRoute,
  type GraphTargetRequest,
  type LegalCitationRequest,
} from "./routes";

export interface NavigationProtectionChannel {
  readonly readMutationInFlight: () => boolean;
  readonly readDraftDirty: () => boolean;
  readonly discardDraft: () => void;
}

export interface UseAppNavigationControllerOptions {
  readonly initialRoute?: AppRoute;
  readonly mcp: NavigationProtectionChannel;
  readonly privacy: NavigationProtectionChannel;
  readonly caseMaterials: NavigationProtectionChannel;
  readonly confirmDiscard: (message: string) => boolean;
}

export type AssistantHostRoute = Extract<
  AssistantRoute,
  { readonly page: "chat" }
>;

export type AssistantCaseHandoffInput = Omit<
  AssistantCaseHandoffRequest,
  "requestId"
>;

export type ApprovedProviderTaskInput = Omit<
  ApprovedProviderTaskRequest,
  "requestId"
>;

export interface AppNavigationController {
  readonly route: AppRoute;
  readonly assistantHostRoute: AssistantHostRoute;
  readonly protectionMessage: string | null;
  readonly navigate: (nextRoute: AppRoute) => boolean;
  readonly clearProtectionMessage: () => void;
  readonly handoffAssistantCase: (
    request: AssistantCaseHandoffInput,
  ) => boolean;
  readonly handoffApprovedProvider: (
    request: ApprovedProviderTaskInput,
  ) => boolean;
  readonly handoffGraphTarget: (request: GraphTargetRequest) => boolean;
  readonly handoffLegalCitation: (
    request: LegalCitationRequest,
  ) => boolean;
  readonly consumeRouteState: (expectedRoute: AppRoute) => boolean;
  readonly guardCaseMaterialContextChange: () => boolean;
}

const MCP_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的 MCP 设置仍保留在当前工作区。";

const PRIVACY_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的隐私与本地 OCR 配置仍保留在当前工作区。";

const CASE_MATERIAL_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的案件材料脱敏文本仍保留在当前工作区。";

function initialAssistantHostRoute(route: AppRoute): AssistantHostRoute {
  return route.area === "assistant" && route.page === "chat"
    ? route
    : { area: "assistant", page: "chat" };
}

function routeWithoutNonAssistantState(route: AppRoute): AppRoute | null {
  switch (route.area) {
    case "assistant":
      return null;
    case "cases":
      return route.page === "work" && route.state
        ? { area: "cases", page: "work" }
        : null;
    case "legal-library":
      return route.state
        ? { area: "legal-library", page: "library" }
        : null;
    case "settings":
      return route.page === "privacy" && route.state
        ? { area: "settings", page: "privacy" }
        : null;
  }
}

export function useAppNavigationController(
  options: UseAppNavigationControllerOptions,
): AppNavigationController {
  const initialRoute = options.initialRoute ?? DEFAULT_ROUTE;
  const [route, setRoute] = useState<AppRoute>(initialRoute);
  const routeRef = useRef<AppRoute>(initialRoute);
  const [assistantHostRoute, setAssistantHostRoute] =
    useState<AssistantHostRoute>(() =>
      initialAssistantHostRoute(initialRoute),
    );
  const [protectionMessage, setProtectionMessage] = useState<string | null>(
    null,
  );
  const readMcpMutationInFlight = options.mcp.readMutationInFlight;
  const readMcpDraftDirty = options.mcp.readDraftDirty;
  const discardMcpDraft = options.mcp.discardDraft;
  const readPrivacyMutationInFlight =
    options.privacy.readMutationInFlight;
  const readPrivacyDraftDirty = options.privacy.readDraftDirty;
  const discardPrivacyDraft = options.privacy.discardDraft;
  const readCaseMaterialMutationInFlight =
    options.caseMaterials.readMutationInFlight;
  const readCaseMaterialDraftDirty =
    options.caseMaterials.readDraftDirty;
  const discardCaseMaterialDraft =
    options.caseMaterials.discardDraft;
  const confirmDiscard = options.confirmDiscard;
  const assistantRequestSequence = useRef(
    assistantHostRoute.state?.request.requestId ?? 0,
  );
  const approvedProviderRequestSequence = useRef(
    initialRoute.area === "settings" &&
      initialRoute.page === "privacy" &&
      initialRoute.state?.kind === "approved-provider-task"
      ? initialRoute.state.request.requestId
      : 0,
  );

  const navigate = useCallback((nextRoute: AppRoute): boolean => {
    const currentRoute = routeRef.current;
    const mcpDecision = decideMcpRouteNavigation(
      currentRoute,
      nextRoute,
      readMcpMutationInFlight(),
      readMcpDraftDirty(),
    );
    if (mcpDecision.kind === "block") {
      setProtectionMessage(mcpDecision.message);
      return false;
    }
    if (mcpDecision.kind === "confirm_discard") {
      if (!confirmDiscard(mcpDecision.message)) {
        setProtectionMessage(MCP_NAVIGATION_CANCELLED_MESSAGE);
        return false;
      }
      discardMcpDraft();
    }

    const privacyDecision = decidePrivacyRouteNavigation(
      currentRoute,
      nextRoute,
      readPrivacyMutationInFlight(),
      readPrivacyDraftDirty(),
    );
    if (privacyDecision.kind === "block") {
      setProtectionMessage(privacyDecision.message);
      return false;
    }
    if (privacyDecision.kind === "confirm_discard") {
      if (!confirmDiscard(privacyDecision.message)) {
        setProtectionMessage(PRIVACY_NAVIGATION_CANCELLED_MESSAGE);
        return false;
      }
      discardPrivacyDraft();
    }

    const caseMaterialDecision = decideCaseMaterialRouteNavigation(
      currentRoute,
      nextRoute,
      readCaseMaterialMutationInFlight(),
      readCaseMaterialDraftDirty(),
    );
    if (caseMaterialDecision.kind === "block") {
      setProtectionMessage(caseMaterialDecision.message);
      return false;
    }
    if (caseMaterialDecision.kind === "confirm_discard") {
      if (!confirmDiscard(caseMaterialDecision.message)) {
        setProtectionMessage(
          CASE_MATERIAL_NAVIGATION_CANCELLED_MESSAGE,
        );
        return false;
      }
      discardCaseMaterialDraft();
    }

    if (
      nextRoute.area === "assistant" &&
      nextRoute.page === "chat" &&
      nextRoute.state?.kind === "assistant-case-handoff"
    ) {
      assistantRequestSequence.current = Math.max(
        assistantRequestSequence.current,
        nextRoute.state.request.requestId,
      );
      setAssistantHostRoute(nextRoute);
    }
    if (
      nextRoute.area === "settings" &&
      nextRoute.page === "privacy" &&
      nextRoute.state?.kind === "approved-provider-task"
    ) {
      approvedProviderRequestSequence.current = Math.max(
        approvedProviderRequestSequence.current,
        nextRoute.state.request.requestId,
      );
    }

    routeRef.current = nextRoute;
    setRoute(nextRoute);
    setProtectionMessage(null);
    return true;
  }, [
    confirmDiscard,
    discardMcpDraft,
    discardPrivacyDraft,
    discardCaseMaterialDraft,
    readMcpDraftDirty,
    readMcpMutationInFlight,
    readPrivacyDraftDirty,
    readPrivacyMutationInFlight,
    readCaseMaterialDraftDirty,
    readCaseMaterialMutationInFlight,
  ]);

  const guardCaseMaterialContextChange = useCallback((): boolean => {
    const decision = decideCaseMaterialContextChange(
      readCaseMaterialMutationInFlight(),
      readCaseMaterialDraftDirty(),
    );
    if (decision.kind === "block") {
      setProtectionMessage(decision.message);
      return false;
    }
    if (decision.kind === "confirm_discard") {
      if (!confirmDiscard(decision.message)) {
        setProtectionMessage(
          CASE_MATERIAL_NAVIGATION_CANCELLED_MESSAGE,
        );
        return false;
      }
      discardCaseMaterialDraft();
    }
    setProtectionMessage(null);
    return true;
  }, [
    confirmDiscard,
    discardCaseMaterialDraft,
    readCaseMaterialDraftDirty,
    readCaseMaterialMutationInFlight,
  ]);

  const clearProtectionMessage = useCallback(() => {
    setProtectionMessage(null);
  }, []);

  const handoffAssistantCase = useCallback(
    (request: AssistantCaseHandoffInput): boolean => {
      assistantRequestSequence.current += 1;
      return navigate({
        area: "assistant",
        page: "chat",
        state: {
          kind: "assistant-case-handoff",
          request: {
            ...request,
            requestId: assistantRequestSequence.current,
          },
        },
      });
    },
    [navigate],
  );

  const handoffApprovedProvider = useCallback(
    (request: ApprovedProviderTaskInput): boolean => {
      approvedProviderRequestSequence.current += 1;
      return navigate({
        area: "settings",
        page: "privacy",
        state: {
          kind: "approved-provider-task",
          request: {
            ...request,
            requestId: approvedProviderRequestSequence.current,
          },
        },
      });
    },
    [navigate],
  );

  const handoffGraphTarget = useCallback(
    (request: GraphTargetRequest): boolean =>
      navigate({
        area: "cases",
        page: "work",
        state: { kind: "graph-target", request },
      }),
    [navigate],
  );

  const handoffLegalCitation = useCallback(
    (request: LegalCitationRequest): boolean =>
      navigate({
        area: "legal-library",
        page: "library",
        state: { kind: "legal-citation", request },
      }),
    [navigate],
  );

  const consumeRouteState = useCallback(
    (expectedRoute: AppRoute): boolean => {
      const expectedState = expectedRoute.state;
      if (
        !expectedState ||
        expectedState.kind === "assistant-case-handoff"
      ) {
        return false;
      }

      const currentRoute = routeRef.current;
      if (
        !sameRouteLocation(currentRoute, expectedRoute) ||
        !sameRouteStateRequest(currentRoute.state, expectedState)
      ) {
        return false;
      }

      const nextRoute = routeWithoutNonAssistantState(currentRoute);
      if (!nextRoute) {
        return false;
      }
      routeRef.current = nextRoute;
      setRoute(nextRoute);
      return true;
    },
    [],
  );

  return {
    route,
    assistantHostRoute,
    protectionMessage,
    navigate,
    clearProtectionMessage,
    handoffAssistantCase,
    handoffApprovedProvider,
    handoffGraphTarget,
    handoffLegalCitation,
    consumeRouteState,
    guardCaseMaterialContextChange,
  };
}
