import type { DocumentCitation } from "../ipc/document/types";
import type { GraphNode } from "../ipc/graph/types";
import type { ApprovedProviderTask } from "../ipc/privacy/types";
import type { ProductArea, ViewMode } from "./views";

export const ASSISTANT_ROUTE_PAGES = ["chat", "legacy-qa"] as const;
export type AssistantRoutePage = (typeof ASSISTANT_ROUTE_PAGES)[number];

export const CASE_ROUTE_PAGES = [
  "overview",
  "materials",
  "work",
  "outputs",
] as const;
export type CaseRoutePage = (typeof CASE_ROUTE_PAGES)[number];

export const CASE_OUTPUT_ROUTES = ["documents", "graph"] as const;
export type CaseOutputRoute = (typeof CASE_OUTPUT_ROUTES)[number];

export const LEGAL_LIBRARY_ROUTE_PAGES = ["library"] as const;
export type LegalLibraryRoutePage =
  (typeof LEGAL_LIBRARY_ROUTE_PAGES)[number];

// Phase 2 keeps the existing settings destinations. Responsibility and label
// changes for local processing and automation belong to the later phases.
export const SETTINGS_ROUTE_PAGES = [
  "providers",
  "privacy",
  "mcp",
  "maintenance",
] as const;
export type SettingsRoutePage = (typeof SETTINGS_ROUTE_PAGES)[number];

export interface AssistantCaseHandoffRequest {
  readonly projectId: string;
  readonly title: string;
  readonly requestId: number;
}

export type LegalCitationRequest = Readonly<
  Pick<
    DocumentCitation,
    "sourceId" | "documentId" | "versionId" | "articleId"
  >
>;

export type GraphTargetRequest = Readonly<
  Pick<GraphNode, "sourceKind" | "sourceId">
>;

export interface ApprovedProviderTaskRequest {
  readonly task: ApprovedProviderTask;
  readonly notice: string;
  readonly requestId: number;
}

export interface AssistantCaseHandoffRouteState {
  readonly kind: "assistant-case-handoff";
  readonly request: AssistantCaseHandoffRequest;
}

export interface LegalCitationRouteState {
  readonly kind: "legal-citation";
  readonly request: LegalCitationRequest;
}

export interface GraphTargetRouteState {
  readonly kind: "graph-target";
  readonly request: GraphTargetRequest;
}

export interface ApprovedProviderTaskRouteState {
  readonly kind: "approved-provider-task";
  readonly request: ApprovedProviderTaskRequest;
}

export type RouteState =
  | AssistantCaseHandoffRouteState
  | LegalCitationRouteState
  | GraphTargetRouteState
  | ApprovedProviderTaskRouteState;

export type AssistantRoute =
  | {
      readonly area: "assistant";
      readonly page: "chat";
      readonly state?: AssistantCaseHandoffRouteState;
    }
  | {
      readonly area: "assistant";
      readonly page: "legacy-qa";
      readonly state?: never;
    };

export type CaseRoute =
  | {
      readonly [Page in "overview" | "materials"]: {
        readonly area: "cases";
        readonly page: Page;
        readonly state?: never;
      };
    }["overview" | "materials"]
  | {
      readonly area: "cases";
      readonly page: "work";
      readonly state?: GraphTargetRouteState;
    }
  | {
      readonly [Output in CaseOutputRoute]: {
        readonly area: "cases";
        readonly page: "outputs";
        readonly output: Output;
        readonly state?: never;
      };
    }[CaseOutputRoute];

export interface LegalLibraryRoute {
  readonly area: "legal-library";
  readonly page: LegalLibraryRoutePage;
  readonly state?: LegalCitationRouteState;
}

export type SettingsRoute =
  | {
      readonly area: "settings";
      readonly page: "mcp";
      readonly state?: ApprovedProviderTaskRouteState;
    }
  | {
      readonly [Page in "providers" | "privacy" | "maintenance"]: {
        readonly area: "settings";
        readonly page: Page;
        readonly state?: never;
      };
    }["providers" | "privacy" | "maintenance"];

export type AppRoute =
  | AssistantRoute
  | CaseRoute
  | LegalLibraryRoute
  | SettingsRoute;

export type RouteForArea<Area extends ProductArea> = Extract<
  AppRoute,
  { readonly area: Area }
>;

export const DEFAULT_ROUTE_BY_AREA: {
  readonly [Area in ProductArea]: RouteForArea<Area>;
} = {
  assistant: { area: "assistant", page: "chat" },
  cases: { area: "cases", page: "overview" },
  "legal-library": { area: "legal-library", page: "library" },
  settings: { area: "settings", page: "providers" },
};

export const DEFAULT_ROUTE: AppRoute = DEFAULT_ROUTE_BY_AREA.assistant;

export function defaultRouteForArea<Area extends ProductArea>(
  area: Area,
): RouteForArea<Area> {
  return DEFAULT_ROUTE_BY_AREA[area];
}

export function routeLocationKey(route: AppRoute): string {
  if (route.area === "cases" && route.page === "outputs") {
    return `${route.area}:${route.page}:${route.output}`;
  }
  return `${route.area}:${route.page}`;
}

/**
 * Compares rendered locations only. One-shot route state is deliberately
 * ignored so a repeated request can target an already mounted workspace.
 */
export function sameRouteLocation(left: AppRoute, right: AppRoute): boolean {
  return routeLocationKey(left) === routeLocationKey(right);
}

/**
 * Compares the identity of one-shot cross-feature route requests without
 * comparing mutable display data such as a case title or a Provider notice.
 */
export function sameRouteStateRequest(
  left: RouteState | null | undefined,
  right: RouteState | null | undefined,
): boolean {
  if (left == null || right == null) {
    return left == null && right == null;
  }
  if (left.kind !== right.kind) return false;

  switch (left.kind) {
    case "assistant-case-handoff":
      return (
        right.kind === "assistant-case-handoff" &&
        left.request.requestId === right.request.requestId
      );
    case "approved-provider-task":
      return (
        right.kind === "approved-provider-task" &&
        left.request.requestId === right.request.requestId
      );
    case "legal-citation":
      return (
        right.kind === "legal-citation" &&
        left.request.sourceId === right.request.sourceId &&
        left.request.documentId === right.request.documentId &&
        left.request.versionId === right.request.versionId &&
        left.request.articleId === right.request.articleId
      );
    case "graph-target":
      return (
        right.kind === "graph-target" &&
        left.request.sourceKind === right.request.sourceKind &&
        left.request.sourceId === right.request.sourceId
      );
  }
}

export function routeFromLegacyView(view: ViewMode): AppRoute {
  switch (view) {
    case "assistant":
      return DEFAULT_ROUTE_BY_AREA.assistant;
    case "qa":
      return { area: "assistant", page: "legacy-qa" };
    case "cases":
      return DEFAULT_ROUTE_BY_AREA.cases;
    case "documents":
      return { area: "cases", page: "outputs", output: "documents" };
    case "graph":
      return { area: "cases", page: "outputs", output: "graph" };
    case "search":
      return DEFAULT_ROUTE_BY_AREA["legal-library"];
    case "providers":
      return DEFAULT_ROUTE_BY_AREA.settings;
    case "privacy":
      return { area: "settings", page: "privacy" };
    case "mcp":
      return { area: "settings", page: "mcp" };
    case "release":
      return { area: "settings", page: "maintenance" };
  }
}

export function legacyViewFromRoute(route: AppRoute): ViewMode {
  switch (route.area) {
    case "assistant":
      return route.page === "legacy-qa" ? "qa" : "assistant";
    case "cases":
      if (route.page !== "outputs") return "cases";
      return route.output;
    case "legal-library":
      return "search";
    case "settings":
      switch (route.page) {
        case "providers":
          return "providers";
        case "privacy":
          return "privacy";
        case "mcp":
          return "mcp";
        case "maintenance":
          return "release";
      }
  }
}
