import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { AppShell } from "./AppShell";
import {
  PRODUCT_AREAS,
  VIEW_METADATA,
  VIEW_MODES,
  VIEW_NAVIGATION,
} from "./views";

describe("AppShell", () => {
  it("exposes exactly the four product areas in the main navigation", () => {
    expect(VIEW_NAVIGATION.map((view) => view.id)).toEqual([
      "assistant",
      "cases",
      "search",
      "providers",
    ]);
    expect(VIEW_NAVIGATION.map((view) => view.navigationLabel)).toEqual([
      "助理",
      "案件工作台 β",
      "法律库",
      "设置与维护",
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
