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
      "local-processing",
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
      "local-processing": {
        area: "settings",
        page: "local-processing",
      },
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
          area: "legal-library",
          page: "library",
          state: {
            kind: "legal-citation",
            request: {
              sourceId: "citation-1",
              documentId: "document-1",
              versionId: "version-1",
              articleId: "article-1",
            },
          },
        },
        {
          area: "legal-library",
          page: "library",
          state: {
            kind: "legal-citation",
            request: {
              sourceId: "citation-2",
              documentId: "document-2",
              versionId: "version-2",
              articleId: "article-2",
            },
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

  it("keeps Assistant chat and MCP as state-free destinations", () => {
    expect({ area: "assistant", page: "chat" } satisfies AppRoute).toEqual({
      area: "assistant",
      page: "chat",
    });
    expect({ area: "settings", page: "mcp" } satisfies AppRoute).toEqual({
      area: "settings",
      page: "mcp",
    });
  });
});

describe("route-state request identity", () => {
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
    expect(sameRouteStateRequest(citationRequest, graphRequest)).toBe(false);
    expect(sameRouteStateRequest(undefined, null)).toBe(true);
    expect(sameRouteStateRequest(undefined, citationRequest)).toBe(false);
  });
});
