import { describe, expect, it } from "vitest";

import type { ViewMode } from "./views";
import {
  ASSISTANT_ROUTE_PAGES,
  CASE_OUTPUT_ROUTES,
  CASE_ROUTE_PAGES,
  DEFAULT_ROUTE,
  DEFAULT_ROUTE_BY_AREA,
  LEGAL_LIBRARY_ROUTE_PAGES,
  SETTINGS_ROUTE_PAGES,
  defaultRouteForArea,
  legacyViewFromRoute,
  routeFromLegacyView,
  sameRouteLocation,
  sameRouteStateRequest,
  type AppRoute,
  type RouteState,
} from "./routes";

describe("typed application routes", () => {
  it("defines the four planned product areas and their stable default entries", () => {
    expect(DEFAULT_ROUTE).toEqual({ area: "assistant", page: "chat" });
    expect(DEFAULT_ROUTE_BY_AREA).toEqual({
      assistant: { area: "assistant", page: "chat" },
      cases: { area: "cases", page: "overview" },
      "legal-library": { area: "legal-library", page: "library" },
      settings: { area: "settings", page: "providers" },
    });
    expect(defaultRouteForArea("cases")).toEqual({
      area: "cases",
      page: "overview",
    });
  });

  it("covers the fixed case navigation and all Phase 2 compatibility pages", () => {
    expect(ASSISTANT_ROUTE_PAGES).toEqual(["chat", "legacy-qa"]);
    expect(CASE_ROUTE_PAGES).toEqual([
      "overview",
      "materials",
      "work",
      "outputs",
    ]);
    expect(CASE_OUTPUT_ROUTES).toEqual(["documents", "graph"]);
    expect(LEGAL_LIBRARY_ROUTE_PAGES).toEqual(["library"]);
    expect(SETTINGS_ROUTE_PAGES).toEqual([
      "providers",
      "privacy",
      "mcp",
      "maintenance",
    ]);
  });

  it("maps all ten legacy views into typed locations without changing behavior", () => {
    const expected: Record<ViewMode, AppRoute> = {
      assistant: { area: "assistant", page: "chat" },
      qa: { area: "assistant", page: "legacy-qa" },
      cases: { area: "cases", page: "overview" },
      documents: {
        area: "cases",
        page: "outputs",
        output: "documents",
      },
      graph: { area: "cases", page: "outputs", output: "graph" },
      search: { area: "legal-library", page: "library" },
      providers: { area: "settings", page: "providers" },
      privacy: { area: "settings", page: "privacy" },
      mcp: { area: "settings", page: "mcp" },
      release: { area: "settings", page: "maintenance" },
    };

    for (const [view, route] of Object.entries(expected) as [
      ViewMode,
      AppRoute,
    ][]) {
      expect(routeFromLegacyView(view)).toEqual(route);
      expect(legacyViewFromRoute(route)).toBe(view);
    }
  });

  it("maps new case sub-navigation back to the existing cases view", () => {
    expect(
      legacyViewFromRoute({ area: "cases", page: "materials" }),
    ).toBe("cases");
    expect(legacyViewFromRoute({ area: "cases", page: "work" })).toBe(
      "cases",
    );
  });

  it("compares rendered locations independently from route state", () => {
    expect(
      sameRouteLocation(
        {
          area: "assistant",
          page: "chat",
          state: {
            kind: "assistant-case-handoff",
            request: { projectId: "case-1", title: "案件一", requestId: 1 },
          },
        },
        {
          area: "assistant",
          page: "chat",
          state: {
            kind: "assistant-case-handoff",
            request: { projectId: "case-2", title: "案件二", requestId: 2 },
          },
        },
      ),
    ).toBe(true);
    expect(
      sameRouteLocation(
        { area: "cases", page: "outputs", output: "documents" },
        { area: "cases", page: "outputs", output: "graph" },
      ),
    ).toBe(false);
    expect(
      sameRouteLocation(
        { area: "cases", page: "overview" },
        { area: "cases", page: "work" },
      ),
    ).toBe(false);
  });

  it("owns the compatibility approved Provider request on MCP and automation", () => {
    const route = {
      area: "settings",
      page: "mcp",
      state: {
        kind: "approved-provider-task",
        request: {
          task: "summary",
          notice: "显式兼容请求",
          requestId: 4,
        },
      },
    } as const satisfies AppRoute;

    expect(route.state.request.requestId).toBe(4);
    expect(
      sameRouteLocation(route, { area: "settings", page: "mcp" }),
    ).toBe(true);
  });
});

describe("route-state request identity", () => {
  const assistantRequest: RouteState = {
    kind: "assistant-case-handoff",
    request: { projectId: "case-1", title: "案件一", requestId: 7 },
  };
  const citationRequest: RouteState = {
    kind: "legal-citation",
    request: {
      sourceId: "citation-1",
      documentId: "document-1",
      versionId: "version-1",
      articleId: "article-1",
    },
  };
  const graphRequest: RouteState = {
    kind: "graph-target",
    request: { sourceKind: "case_fact", sourceId: "fact-1" },
  };
  const providerRequest: RouteState = {
    kind: "approved-provider-task",
    request: {
      task: "case_legal_qa",
      notice: "当前提示",
      requestId: 11,
    },
  };

  it("uses the existing sequence id for assistant and approved Provider requests", () => {
    expect(
      sameRouteStateRequest(assistantRequest, {
        kind: "assistant-case-handoff",
        request: {
          projectId: "case-changed",
          title: "标题变化不改变请求身份",
          requestId: 7,
        },
      }),
    ).toBe(true);
    expect(
      sameRouteStateRequest(providerRequest, {
        kind: "approved-provider-task",
        request: {
          task: "summary",
          notice: "提示变化不改变请求身份",
          requestId: 11,
        },
      }),
    ).toBe(true);
    expect(
      sameRouteStateRequest(assistantRequest, {
        kind: "assistant-case-handoff",
        request: { projectId: "case-1", title: "案件一", requestId: 8 },
      }),
    ).toBe(false);
  });

  it("uses exact source identities for citations and graph targets", () => {
    expect(
      sameRouteStateRequest(citationRequest, {
        kind: "legal-citation",
        request: {
          sourceId: "citation-1",
          documentId: "document-1",
          versionId: "version-1",
          articleId: "article-1",
        },
      }),
    ).toBe(true);
    expect(
      sameRouteStateRequest(citationRequest, {
        kind: "legal-citation",
        request: {
          sourceId: "citation-1",
          documentId: "document-1",
          versionId: "version-2",
          articleId: "article-1",
        },
      }),
    ).toBe(false);
    expect(
      sameRouteStateRequest(graphRequest, {
        kind: "graph-target",
        request: { sourceKind: "case_fact", sourceId: "fact-1" },
      }),
    ).toBe(true);
    expect(
      sameRouteStateRequest(graphRequest, {
        kind: "graph-target",
        request: { sourceKind: "evidence_item", sourceId: "fact-1" },
      }),
    ).toBe(false);
  });

  it("does not confuse request kinds or missing requests", () => {
    expect(sameRouteStateRequest(assistantRequest, providerRequest)).toBe(
      false,
    );
    expect(sameRouteStateRequest(undefined, null)).toBe(true);
    expect(sameRouteStateRequest(undefined, assistantRequest)).toBe(false);
  });
});
