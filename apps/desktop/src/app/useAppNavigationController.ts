import { useCallback, useRef, useState } from "react";

import {
  decideCaseMaterialContextChange,
  decideCaseMaterialRouteNavigation,
  decideLocalProcessingRouteNavigation,
  decideMaintenanceRouteNavigation,
  decideMcpRouteNavigation,
} from "./navigationGuards";
import {
  DEFAULT_ROUTE,
  sameRouteLocation,
  sameRouteStateRequest,
  type AppRoute,
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
  readonly localProcessing: NavigationProtectionChannel;
  readonly maintenance: NavigationProtectionChannel;
  readonly caseMaterials: NavigationProtectionChannel;
  readonly confirmDiscard: (message: string) => boolean;
}

export interface AppNavigationController {
  readonly route: AppRoute;
  readonly protectionMessage: string | null;
  readonly navigate: (nextRoute: AppRoute) => boolean;
  readonly clearProtectionMessage: () => void;
  readonly handoffGraphTarget: (request: GraphTargetRequest) => boolean;
  readonly handoffLegalCitation: (
    request: LegalCitationRequest,
  ) => boolean;
  readonly consumeRouteState: (expectedRoute: AppRoute) => boolean;
  readonly guardCaseMaterialContextChange: () => boolean;
}

const MCP_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的 MCP 设置仍保留在当前工作区。";

const LOCAL_PROCESSING_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的本地处理与 OCR 配置仍保留在当前工作区。";

const CASE_MATERIAL_NAVIGATION_CANCELLED_MESSAGE =
  "已取消切换；未保存的案件材料脱敏文本仍保留在当前工作区。";

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
      return null;
  }
}

export function useAppNavigationController(
  options: UseAppNavigationControllerOptions,
): AppNavigationController {
  const initialRoute = options.initialRoute ?? DEFAULT_ROUTE;
  const [route, setRoute] = useState<AppRoute>(initialRoute);
  const routeRef = useRef<AppRoute>(initialRoute);
  const [protectionMessage, setProtectionMessage] = useState<string | null>(
    null,
  );
  const readMcpMutationInFlight = options.mcp.readMutationInFlight;
  const readMcpDraftDirty = options.mcp.readDraftDirty;
  const discardMcpDraft = options.mcp.discardDraft;
  const readLocalProcessingMutationInFlight =
    options.localProcessing.readMutationInFlight;
  const readLocalProcessingDraftDirty =
    options.localProcessing.readDraftDirty;
  const discardLocalProcessingDraft = options.localProcessing.discardDraft;
  const readMaintenanceMutationInFlight =
    options.maintenance.readMutationInFlight;
  const readCaseMaterialMutationInFlight =
    options.caseMaterials.readMutationInFlight;
  const readCaseMaterialDraftDirty =
    options.caseMaterials.readDraftDirty;
  const discardCaseMaterialDraft =
    options.caseMaterials.discardDraft;
  const confirmDiscard = options.confirmDiscard;
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

    const localProcessingDecision = decideLocalProcessingRouteNavigation(
      currentRoute,
      nextRoute,
      readLocalProcessingMutationInFlight(),
      readLocalProcessingDraftDirty(),
    );
    if (localProcessingDecision.kind === "block") {
      setProtectionMessage(localProcessingDecision.message);
      return false;
    }
    if (localProcessingDecision.kind === "confirm_discard") {
      if (!confirmDiscard(localProcessingDecision.message)) {
        setProtectionMessage(LOCAL_PROCESSING_NAVIGATION_CANCELLED_MESSAGE);
        return false;
      }
      discardLocalProcessingDraft();
    }

    const maintenanceDecision = decideMaintenanceRouteNavigation(
      currentRoute,
      nextRoute,
      readMaintenanceMutationInFlight(),
    );
    if (maintenanceDecision.kind === "block") {
      setProtectionMessage(maintenanceDecision.message);
      return false;
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

    routeRef.current = nextRoute;
    setRoute(nextRoute);
    setProtectionMessage(null);
    return true;
  }, [
    confirmDiscard,
    discardMcpDraft,
    discardLocalProcessingDraft,
    discardCaseMaterialDraft,
    readMcpDraftDirty,
    readMcpMutationInFlight,
    readLocalProcessingDraftDirty,
    readLocalProcessingMutationInFlight,
    readMaintenanceMutationInFlight,
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
      if (!expectedState) {
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
    protectionMessage,
    navigate,
    clearProtectionMessage,
    handoffGraphTarget,
    handoffLegalCitation,
    consumeRouteState,
    guardCaseMaterialContextChange,
  };
}
