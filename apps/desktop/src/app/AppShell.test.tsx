import {
  Children,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { AppShell } from "./AppShell";
import {
  defaultRouteForArea,
  routeFromLegacyView,
  type AppRoute,
} from "./routes";
import {
  PRODUCT_AREAS,
  VIEW_METADATA,
  VIEW_MODES,
  VIEW_NAVIGATION,
} from "./views";

function visitElements(
  node: ReactNode,
  visitor: (element: ReactElement) => void,
) {
  Children.forEach(node, (child) => {
    if (!isValidElement(child)) return;
    visitor(child);
    visitElements(
      (child.props as { children?: ReactNode }).children,
      visitor,
    );
  });
}

describe("AppShell", () => {
  it.each(PRODUCT_AREAS)(
    "marks the typed %s route as the only active product area",
    (area) => {
      const markup = renderToStaticMarkup(
        <AppShell
          route={defaultRouteForArea(area)}
          status={{ kind: "ready", text: "ready" }}
          onNavigate={vi.fn()}
        >
          <p>workspace</p>
        </AppShell>,
      );
      const activeNavigationLabel = VIEW_NAVIGATION.find(
        (view) => view.futureArea === area,
      )!.navigationLabel;

      expect(markup.match(/aria-current="page"/g)).toHaveLength(1);
      expect(markup).toMatch(
        new RegExp(
          `<button[^>]*aria-current="page"[^>]*>${activeNavigationLabel}</button>`,
        ),
      );
    },
  );

  it.each(VIEW_MODES)(
    "keeps the legacy %s heading when addressed through a typed route",
    (legacyView) => {
      const markup = renderToStaticMarkup(
        <AppShell
          route={routeFromLegacyView(legacyView)}
          status={{ kind: "ready", text: "ready" }}
          onNavigate={vi.fn()}
        >
          <p>workspace</p>
        </AppShell>,
      );

      expect(markup).toContain(
        `<p class="eyebrow">${VIEW_METADATA[legacyView].eyebrow}</p>`,
      );
      expect(markup).toContain(`<h1>${VIEW_METADATA[legacyView].title}</h1>`);
    },
  );

  it("maps typed main-navigation clicks to each area's default route", () => {
    const onNavigate = vi.fn<(route: AppRoute) => void>();
    const tree = AppShell({
      route: { area: "cases", page: "work" },
      status: { kind: "ready", text: "ready" },
      onNavigate,
      children: <p>workspace</p>,
    });
    const navigationButtons: ReactElement<{
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
        VIEW_NAVIGATION.some(
          (view) => view.navigationLabel === props.children,
        ) &&
        props.onClick
      ) {
        navigationButtons.push(
          element as (typeof navigationButtons)[number],
        );
      }
    });

    expect(navigationButtons).toHaveLength(PRODUCT_AREAS.length);
    navigationButtons.forEach((button) => button.props.onClick());
    expect(onNavigate.mock.calls.map(([route]) => route)).toEqual(
      VIEW_NAVIGATION.map((view) => defaultRouteForArea(view.futureArea)),
    );
  });

  it("exposes exactly the four product areas in the main navigation", () => {
    expect(VIEW_NAVIGATION.map((view) => view.id)).toEqual([
      "assistant",
      "cases",
      "search",
      "providers",
    ]);
    expect(VIEW_NAVIGATION.map((view) => view.navigationLabel)).toEqual([
      "助理",
      "案件工作台",
      "法律库",
      "设置",
    ]);
  });

  it("provides a typed migration point for all four future product areas", () => {
    expect(
      new Set(VIEW_MODES.map((view) => VIEW_METADATA[view].futureArea)),
    ).toEqual(new Set(PRODUCT_AREAS));
    expect(VIEW_METADATA.documents.futureArea).toBe("cases");
    expect(VIEW_METADATA.graph.futureArea).toBe("cases");
    expect(VIEW_METADATA.mcp.futureArea).toBe("settings");
  });

  it.each(VIEW_MODES)(
    "renders %s as the only current view with its stable heading",
    (activeView) => {
      const markup = renderToStaticMarkup(
        <AppShell
          activeView={activeView}
          status={{ kind: "ready", text: "Rust command 正常" }}
          onNavigate={vi.fn()}
        >
          <p>工作区内容</p>
        </AppShell>,
      );

      expect(markup.match(/aria-current="page"/g)).toHaveLength(1);
      expect(markup).toContain(
        `<p class="eyebrow">${VIEW_METADATA[activeView].eyebrow}</p>`,
      );
      expect(markup).toContain(`<h1>${VIEW_METADATA[activeView].title}</h1>`);
      expect(markup).toContain("工作区内容");
      expect(markup).toContain("Rust command 正常");
    },
  );
});
