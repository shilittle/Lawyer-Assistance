import { Children, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import {
  CASE_NAVIGATION_ITEMS,
  CaseNavigation,
  type CaseSection,
} from "./CaseNavigation";

describe("CaseNavigation", () => {
  it("exposes exactly the four planned case sections", () => {
    expect(CASE_NAVIGATION_ITEMS.map((item) => item.label)).toEqual([
      "概览",
      "材料与脱敏",
      "案件工作",
      "成果",
    ]);
  });

  it.each(CASE_NAVIGATION_ITEMS)(
    "marks $label as the only current section",
    ({ section, label }) => {
      const markup = renderToStaticMarkup(
        <CaseNavigation section={section} onSectionChange={vi.fn()} />,
      );

      expect(markup.match(/aria-current="page"/g)).toHaveLength(1);
      expect(markup).toContain(`aria-current="page" class="is-active"`);
      expect(markup).toMatch(
        new RegExp(
          `<button[^>]*aria-current="page"[^>]*>${label}</button>`,
        ),
      );
    },
  );

  it("reports the selected typed section through its callback", () => {
    const onSectionChange = vi.fn<(section: CaseSection) => void>();
    const navigation = CaseNavigation({
      section: "overview",
      onSectionChange,
    });
    const buttons = Children.toArray(navigation.props.children) as ReactElement<
      { onClick: () => void }
    >[];

    buttons[1].props.onClick();

    expect(onSectionChange).toHaveBeenCalledTimes(1);
    expect(onSectionChange).toHaveBeenCalledWith("materials");
  });
});
