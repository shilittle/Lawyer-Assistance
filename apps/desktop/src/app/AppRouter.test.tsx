import {
  Children,
  Fragment,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  CaseNavigation,
  type CaseSection,
} from "../features/cases/CaseNavigation";
import { AppErrorBoundary } from "./AppErrorBoundary";
import {
  AppRouter,
  type AppRouterSlots,
  type WorkspaceRenderContext,
} from "./AppRouter";
import type { AppRoute } from "./routes";
import type { ViewMode } from "./views";

const DEFAULT_ASSISTANT_HOST_ROUTE = {
  area: "assistant",
  page: "chat",
} as const;

const LEGACY_ROUTES: Readonly<Record<ViewMode, AppRoute>> = {
  assistant: { area: "assistant", page: "chat" },
  qa: { area: "assistant", page: "legacy-qa" },
  cases: { area: "cases", page: "overview" },
  documents: { area: "cases", page: "outputs", output: "documents" },
  graph: { area: "cases", page: "outputs", output: "graph" },
  search: { area: "legal-library", page: "library" },
  providers: { area: "settings", page: "providers" },
  privacy: { area: "settings", page: "privacy" },
  mcp: { area: "settings", page: "mcp" },
  release: { area: "settings", page: "maintenance" },
};

function slotSpies() {
  return {
    assistant: vi.fn(
      ({ active }: WorkspaceRenderContext<AppRoute & { area: "assistant" }>) => (
        <p data-rendered-slot="assistant">
          assistant:{active ? "active" : "hidden"}
        </p>
      ),
    ),
    qa: vi.fn(() => <p data-rendered-slot="qa">qa</p>),
    cases: vi.fn(() => <p data-rendered-slot="cases">cases</p>),
    documents: vi.fn(() => <p data-rendered-slot="documents">documents</p>),
    graph: vi.fn(() => <p data-rendered-slot="graph">graph</p>),
    search: vi.fn(() => <p data-rendered-slot="search">search</p>),
    providers: vi.fn(() => <p data-rendered-slot="providers">providers</p>),
    privacy: vi.fn(() => <p data-rendered-slot="privacy">privacy</p>),
    mcp: vi.fn(() => <p data-rendered-slot="mcp">mcp</p>),
    release: vi.fn(() => <p data-rendered-slot="release">release</p>),
  } satisfies AppRouterSlots;
}

function visitElements(
  node: ReactNode,
  visitor: (element: ReactElement) => void,
) {
  Children.forEach(node, (child) => {
    if (!isValidElement(child)) return;
    visitor(child);
    if (child.type === Fragment) {
      const fragment = child as ReactElement<{ children?: ReactNode }>;
      visitElements(fragment.props.children, visitor);
      return;
    }
    const props = child.props as { children?: ReactNode };
    if (props.children !== undefined) {
      visitElements(props.children, visitor);
    }
  });
}

function routerTree(
  route: AppRoute,
  onNavigate = vi.fn<(route: AppRoute) => void>(),
) {
  return {
    onNavigate,
    tree: AppRouter({
      route,
      assistantHostRoute: DEFAULT_ASSISTANT_HOST_ROUTE,
      slots: slotSpies(),
      onNavigate,
    }),
  };
}

describe("AppRouter workspace ownership", () => {
  it.each(Object.entries(LEGACY_ROUTES) as [ViewMode, AppRoute][])(
    "keeps Assistant mounted and renders only the active conditional slot for %s",
    (destination, route) => {
      const slots = slotSpies();
      const markup = renderToStaticMarkup(
        <AppRouter
          route={route}
          assistantHostRoute={
            route.area === "assistant" && route.page === "chat"
              ? route
              : DEFAULT_ASSISTANT_HOST_ROUTE
          }
          slots={slots}
          onNavigate={vi.fn()}
        />,
      );

      expect(slots.assistant).toHaveBeenCalledTimes(1);
      expect(markup).toContain('data-rendered-slot="assistant"');

      const conditionalSlots = Object.entries(slots).filter(
        ([name]) => name !== "assistant",
      );
      const expectedConditional =
        destination === "assistant" ? null : destination;
      for (const [name, renderer] of conditionalSlots) {
        expect(renderer).toHaveBeenCalledTimes(
          name === expectedConditional ? 1 : 0,
        );
      }

      if (destination === "assistant") {
        expect(markup).toContain('data-workspace-slot="assistant"');
        expect(markup).not.toContain(
          'data-workspace-slot="assistant" hidden=""',
        );
        expect(markup).not.toContain('data-workspace-slot="active"');
      } else {
        expect(markup).toContain(
          'data-workspace-slot="assistant" hidden=""',
        );
        expect(markup).toContain('data-workspace-slot="active"');
      }
    },
  );

  it("passes exact typed route state to the active Assistant renderer", () => {
    const slots = slotSpies();
    const route = {
      area: "assistant",
      page: "chat",
      state: {
        kind: "assistant-case-handoff",
        request: {
          projectId: "case-1",
          title: "案件一",
          requestId: 3,
        },
      },
    } as const satisfies AppRoute;

    renderToStaticMarkup(
      <AppRouter
        route={route}
        assistantHostRoute={route}
        slots={slots}
        onNavigate={vi.fn()}
      />,
    );

    expect(slots.assistant).toHaveBeenCalledWith({
      route,
      active: true,
    });
  });

  it("keeps the retained Assistant handoff route while its host is hidden", () => {
    const slots = slotSpies();
    const assistantHostRoute = {
      area: "assistant",
      page: "chat",
      state: {
        kind: "assistant-case-handoff",
        request: {
          projectId: "case-hidden",
          title: "隐藏期间仍处理",
          requestId: 9,
        },
      },
    } as const;

    renderToStaticMarkup(
      <AppRouter
        route={{ area: "cases", page: "overview" }}
        assistantHostRoute={assistantHostRoute}
        slots={slots}
        onNavigate={vi.fn()}
      />,
    );

    expect(slots.assistant).toHaveBeenCalledWith({
      route: assistantHostRoute,
      active: false,
    });
    expect(slots.cases).toHaveBeenCalledTimes(1);
  });

  it("keeps automation unrendered for Assistant and privacy, then passes exact state on the MCP route", () => {
    for (const route of [
      { area: "assistant", page: "chat" },
      { area: "settings", page: "privacy" },
    ] as const satisfies readonly AppRoute[]) {
      const slots = slotSpies();
      renderToStaticMarkup(
        <AppRouter
          route={route}
          assistantHostRoute={DEFAULT_ASSISTANT_HOST_ROUTE}
          slots={slots}
          onNavigate={vi.fn()}
        />,
      );
      expect(slots.mcp).not.toHaveBeenCalled();
    }

    const slots = slotSpies();
    const route = {
      area: "settings",
      page: "mcp",
      state: {
        kind: "approved-provider-task",
        request: {
          task: "regenerate",
          notice: "仅处理显式兼容请求",
          requestId: 7,
        },
      },
    } as const satisfies AppRoute;

    renderToStaticMarkup(
      <AppRouter
        route={route}
        assistantHostRoute={DEFAULT_ASSISTANT_HOST_ROUTE}
        slots={slots}
        onNavigate={vi.fn()}
      />,
    );

    expect(slots.mcp).toHaveBeenCalledWith({ route, active: true });
    expect(slots.privacy).not.toHaveBeenCalled();
  });

  it("isolates the always-mounted Assistant and active workspace by location", () => {
    const { tree } = routerTree({
      area: "cases",
      page: "outputs",
      output: "graph",
    });
    const resetKeys: string[] = [];

    visitElements(tree, (element) => {
      if (element.type === AppErrorBoundary) {
        resetKeys.push(
          (element.props as { resetKey: string }).resetKey,
        );
      }
    });

    expect(resetKeys).toEqual(["assistant:chat", "cases:outputs:graph"]);
  });
});

describe("AppRouter typed subnavigation", () => {
  it.each(["overview", "materials", "work", "outputs"] as const)(
    "renders the fixed four-case navigation with %s selected",
    (page) => {
      const route: AppRoute =
        page === "outputs"
          ? { area: "cases", page, output: "documents" }
          : { area: "cases", page };
      const markup = renderToStaticMarkup(
        <AppRouter
          route={route}
          assistantHostRoute={DEFAULT_ASSISTANT_HOST_ROUTE}
          slots={slotSpies()}
          onNavigate={vi.fn()}
        />,
      );

      for (const label of ["概览", "材料与脱敏", "案件工作", "成果"]) {
        expect(markup).toContain(`>${label}</button>`);
      }
      expect(markup).toMatch(
        new RegExp(`aria-current="page"[^>]*>${{
          overview: "概览",
          materials: "材料与脱敏",
          work: "案件工作",
          outputs: "成果",
        }[page]}</button>`),
      );
    },
  );

  it.each([
    ["overview", { area: "cases", page: "overview" }],
    ["materials", { area: "cases", page: "materials" }],
    ["work", { area: "cases", page: "work" }],
    [
      "outputs",
      { area: "cases", page: "outputs", output: "documents" },
    ],
  ] as const)("navigates the case section %s with a typed route", (section, expected) => {
    const { tree, onNavigate } = routerTree({
      area: "cases",
      page: "overview",
    });
    let caseNavigation: ReactElement<{
      onSectionChange: (nextSection: CaseSection) => void;
    }> | null = null;

    visitElements(tree, (element) => {
      if (element.type === CaseNavigation) {
        caseNavigation = element as typeof caseNavigation;
      }
    });
    expect(caseNavigation).not.toBeNull();

    caseNavigation!.props.onSectionChange(section);

    expect(onNavigate).toHaveBeenCalledWith(expected);
  });

  it("switches outputs between the typed documents and graph routes", () => {
    const { tree, onNavigate } = routerTree({
      area: "cases",
      page: "outputs",
      output: "documents",
    });
    const buttons: ReactElement<{
      children: ReactNode;
      onClick: () => void;
    }>[] = [];

    visitElements(tree, (element) => {
      const props = element.props as {
        children?: ReactNode;
        onClick?: () => void;
      };
      if (
        element.type === "button" &&
        props.children === "确定性图谱" &&
        props.onClick
      ) {
        buttons.push(element as (typeof buttons)[number]);
      }
    });
    buttons[0].props.onClick();

    expect(onNavigate).toHaveBeenCalledWith({
      area: "cases",
      page: "outputs",
      output: "graph",
    });
  });

  it("keeps the Phase 2 Assistant and settings destinations typed", () => {
    const assistant = routerTree({
      area: "assistant",
      page: "legacy-qa",
    });
    const settings = routerTree({
      area: "settings",
      page: "providers",
    });

    for (const [tree, label, expected, navigate] of [
      [
        assistant.tree,
        "助理工作区",
        { area: "assistant", page: "chat" },
        assistant.onNavigate,
      ],
      [
        settings.tree,
        "隐私与本地处理",
        { area: "settings", page: "privacy" },
        settings.onNavigate,
      ],
      [
        settings.tree,
        "MCP 与自动化",
        { area: "settings", page: "mcp" },
        settings.onNavigate,
      ],
      [
        settings.tree,
        "版本、备份与诊断",
        { area: "settings", page: "maintenance" },
        settings.onNavigate,
      ],
    ] as const) {
      visitElements(tree, (element) => {
        const props = element.props as {
          children?: ReactNode;
          onClick?: () => void;
        };
        if (
          element.type === "button" &&
          props.children === label &&
          props.onClick
        ) {
          props.onClick();
        }
      });
      expect(navigate).toHaveBeenCalledWith(expected);
    }
  });

  it("does not add an internal subnavigation to the legal library", () => {
    const markup = renderToStaticMarkup(
      <AppRouter
        route={{ area: "legal-library", page: "library" }}
        assistantHostRoute={DEFAULT_ASSISTANT_HOST_ROUTE}
        slots={slotSpies()}
        onNavigate={vi.fn()}
      />,
    );

    expect(markup).not.toContain("workspace-subnav");
  });
});
