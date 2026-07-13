import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { ProviderCreateMenu } from "./ProviderCreateMenu";

describe("ProviderCreateMenu", () => {
  it("shows only DeepSeek before the closed secondary-provider disclosure", () => {
    const markup = renderToStaticMarkup(
      <ProviderCreateMenu disabled={false} onCreate={vi.fn()} />,
    );
    const disclosureIndex = markup.indexOf("<details");

    expect(markup).toContain('data-provider-quick-create="deep_seek"');
    expect(disclosureIndex).toBeGreaterThan(0);
    expect(markup).not.toContain("<details open");
    expect(markup.indexOf('data-provider-quick-create="deep_seek"')).toBeLessThan(
      disclosureIndex,
    );
    for (const kind of ["qwen", "silicon_flow", "volcengine_ark", "custom"]) {
      expect(markup.indexOf(`data-provider-secondary-create="${kind}"`)).toBeGreaterThan(
        disclosureIndex,
      );
    }
    expect(markup).toContain("其他提供商与自定义");
    expect(markup).toContain("添加自定义 OpenAI 兼容提供商");
  });

  it("disables every create action while provider state is busy", () => {
    const markup = renderToStaticMarkup(
      <ProviderCreateMenu disabled onCreate={vi.fn()} />,
    );

    expect(markup.match(/<button/g)).toHaveLength(5);
    expect(markup.match(/ disabled=""/g)).toHaveLength(5);
  });
});
