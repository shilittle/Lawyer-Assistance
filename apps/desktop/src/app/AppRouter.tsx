import type { ReactNode } from "react";

import {
  CaseNavigation,
  type CaseSection,
} from "../features/cases/CaseNavigation";
import { AppErrorBoundary } from "./AppErrorBoundary";
import { routeLocationKey } from "./routes";
import type {
  AppRoute,
  AssistantRoute,
  CaseRoute,
  SettingsRoute,
} from "./routes";

export type AssistantChatRoute = Extract<
  AssistantRoute,
  { readonly page: "chat" }
>;

export type AssistantLegacyQaRoute = Extract<
  AssistantRoute,
  { readonly page: "legacy-qa" }
>;

export type CasePrimaryRoute = Extract<
  CaseRoute,
  { readonly page: "overview" | "materials" | "work" }
>;

export type CaseDocumentsRoute = Extract<
  CaseRoute,
  { readonly page: "outputs"; readonly output: "documents" }
>;

export type CaseGraphRoute = Extract<
  CaseRoute,
  { readonly page: "outputs"; readonly output: "graph" }
>;

export type LegalLibraryRoute = Extract<
  AppRoute,
  { readonly area: "legal-library" }
>;

export type ProviderSettingsRoute = Extract<
  SettingsRoute,
  { readonly page: "providers" }
>;

export type LocalProcessingSettingsRoute = Extract<
  SettingsRoute,
  { readonly page: "local-processing" }
>;

export type McpSettingsRoute = Extract<
  SettingsRoute,
  { readonly page: "mcp" }
>;

export type MaintenanceSettingsRoute = Extract<
  SettingsRoute,
  { readonly page: "maintenance" }
>;

export interface WorkspaceRenderContext<Route extends AppRoute> {
  readonly route: Route;
  readonly active: boolean;
}

export type WorkspaceRenderer<Route extends AppRoute> = (
  context: WorkspaceRenderContext<Route>,
) => ReactNode;

/**
 * Phase 2 compatibility slots. Their names deliberately match the ten
 * pre-rebuild destinations so the router changes ownership without changing
 * workspace behavior.
 */
export interface AppRouterSlots {
  readonly assistant: WorkspaceRenderer<AssistantChatRoute>;
  readonly qa: WorkspaceRenderer<AssistantLegacyQaRoute>;
  readonly cases: WorkspaceRenderer<CasePrimaryRoute>;
  readonly documents: WorkspaceRenderer<CaseDocumentsRoute>;
  readonly graph: WorkspaceRenderer<CaseGraphRoute>;
  readonly search: WorkspaceRenderer<LegalLibraryRoute>;
  readonly providers: WorkspaceRenderer<ProviderSettingsRoute>;
  readonly localProcessing: WorkspaceRenderer<LocalProcessingSettingsRoute>;
  readonly mcp: WorkspaceRenderer<McpSettingsRoute>;
  readonly maintenance: WorkspaceRenderer<MaintenanceSettingsRoute>;
}

export interface AppRouterProps {
  readonly route: AppRoute;
  readonly slots: AppRouterSlots;
  readonly onNavigate: (route: AppRoute) => void;
}

const ASSISTANT_CHAT_ROUTE: AssistantChatRoute = {
  area: "assistant",
  page: "chat",
};

const ASSISTANT_NAVIGATION = [
  { page: "chat", label: "助理工作区" },
  { page: "legacy-qa", label: "兼容引用问答" },
] as const;

const CASE_OUTPUT_NAVIGATION = [
  { output: "documents", label: "既有文书模板" },
  { output: "graph", label: "确定性图谱" },
] as const;

const SETTINGS_NAVIGATION = [
  { page: "providers", label: "Provider 与凭据" },
  { page: "local-processing", label: "本地处理环境与 OCR 组件" },
  { page: "mcp", label: "MCP 与自动化" },
  { page: "maintenance", label: "版本、备份与诊断" },
] as const;

function isAssistantChatRoute(
  route: AppRoute,
): route is AssistantChatRoute {
  return route.area === "assistant" && route.page === "chat";
}

function caseRouteForSection(
  currentRoute: CaseRoute,
  section: CaseSection,
): CaseRoute {
  if (section === "outputs") {
    return currentRoute.page === "outputs"
      ? currentRoute
      : { area: "cases", page: "outputs", output: "documents" };
  }
  return { area: "cases", page: section };
}

function renderSubnavigation(
  route: AppRoute,
  onNavigate: (route: AppRoute) => void,
): ReactNode {
  switch (route.area) {
    case "assistant":
      return (
        <nav className="workspace-subnav" aria-label="助理功能">
          {ASSISTANT_NAVIGATION.map((item) => (
            <button
              aria-current={route.page === item.page ? "page" : undefined}
              key={item.page}
              type="button"
              onClick={() => onNavigate({ area: "assistant", page: item.page })}
            >
              {item.label}
            </button>
          ))}
        </nav>
      );
    case "cases":
      return (
        <>
          <CaseNavigation
            section={route.page}
            onSectionChange={(section) =>
              onNavigate(caseRouteForSection(route, section))
            }
          />
          {route.page === "outputs" ? (
            <nav className="workspace-subnav" aria-label="案件成果类型">
              {CASE_OUTPUT_NAVIGATION.map((item) => (
                <button
                  aria-current={
                    route.output === item.output ? "page" : undefined
                  }
                  key={item.output}
                  type="button"
                  onClick={() =>
                    onNavigate({
                      area: "cases",
                      page: "outputs",
                      output: item.output,
                    })
                  }
                >
                  {item.label}
                </button>
              ))}
            </nav>
          ) : null}
        </>
      );
    case "legal-library":
      return null;
    case "settings":
      return (
        <nav className="workspace-subnav" aria-label="设置功能">
          {SETTINGS_NAVIGATION.map((item) => (
            <button
              aria-current={route.page === item.page ? "page" : undefined}
              key={item.page}
              type="button"
              onClick={() => onNavigate({ area: "settings", page: item.page })}
            >
              {item.label}
            </button>
          ))}
        </nav>
      );
  }
}

interface AssistantWorkspaceSlotProps {
  readonly active: boolean;
  readonly render: WorkspaceRenderer<AssistantChatRoute>;
  readonly route: AssistantChatRoute;
}

function AssistantWorkspaceSlot({
  active,
  render,
  route,
}: AssistantWorkspaceSlotProps) {
  return render({ route, active });
}

interface ActiveWorkspaceSlotProps {
  readonly route: Exclude<AppRoute, AssistantChatRoute>;
  readonly slots: AppRouterSlots;
}

function ActiveWorkspaceSlot({
  route,
  slots,
}: ActiveWorkspaceSlotProps) {
  switch (route.area) {
    case "assistant":
      return slots.qa({
        route: route as AssistantLegacyQaRoute,
        active: true,
      });
    case "cases":
      if (route.page !== "outputs") {
        return slots.cases({
          route: route as CasePrimaryRoute,
          active: true,
        });
      }
      if (route.output === "documents") {
        return slots.documents({
          route: route as CaseDocumentsRoute,
          active: true,
        });
      }
      return slots.graph({
        route: route as CaseGraphRoute,
        active: true,
      });
    case "legal-library":
      return slots.search({
        route: route as LegalLibraryRoute,
        active: true,
      });
    case "settings":
      switch (route.page) {
        case "providers":
          return slots.providers({
            route: route as ProviderSettingsRoute,
            active: true,
          });
        case "local-processing":
          return slots.localProcessing({
            route: route as LocalProcessingSettingsRoute,
            active: true,
          });
        case "mcp":
          return slots.mcp({
            route: route as McpSettingsRoute,
            active: true,
          });
        case "maintenance":
          return slots.maintenance({
            route: route as MaintenanceSettingsRoute,
            active: true,
          });
      }
  }
}

export function AppRouter({
  route,
  slots,
  onNavigate,
}: AppRouterProps) {
  const assistantActive = isAssistantChatRoute(route);

  return (
    <section className="app-router" data-route-location={routeLocationKey(route)}>
      {renderSubnavigation(route, onNavigate)}

      <div
        className="assistant-workspace-host"
        data-workspace-slot="assistant"
        hidden={!assistantActive}
      >
        <AppErrorBoundary resetKey="assistant:chat">
          <AssistantWorkspaceSlot
            active={assistantActive}
            render={slots.assistant}
            route={ASSISTANT_CHAT_ROUTE}
          />
        </AppErrorBoundary>
      </div>

      {!assistantActive ? (
        <div
          className="app-router__active-workspace"
          data-workspace-slot="active"
        >
          <AppErrorBoundary resetKey={routeLocationKey(route)}>
            <ActiveWorkspaceSlot route={route} slots={slots} />
          </AppErrorBoundary>
        </div>
      ) : null}
    </section>
  );
}
