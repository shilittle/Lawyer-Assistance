import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { CasesWorkspace } from "./cases/CasesWorkspace";
import { LegalLibraryWorkspace } from "./legal-library/LegalLibraryWorkspace";
import { SettingsWorkspace } from "./settings/SettingsWorkspace";

describe("top-level product workspace boundaries", () => {
  it("exposes stable semantic regions for cases, legal library, and settings", () => {
    const cases = renderToStaticMarkup(
      <CasesWorkspace busy={true}>案件内容</CasesWorkspace>,
    );
    const legal = renderToStaticMarkup(
      <LegalLibraryWorkspace>法律内容</LegalLibraryWorkspace>,
    );
    const settings = renderToStaticMarkup(
      <SettingsWorkspace mode="providers">设置内容</SettingsWorkspace>,
    );
    const mcp = renderToStaticMarkup(
      <SettingsWorkspace mode="mcp">MCP 内容</SettingsWorkspace>,
    );

    expect(cases).toContain('class="case-layout"');
    expect(cases).toContain('aria-label="案件工作台 β"');
    expect(cases).toContain('aria-busy="true"');
    expect(legal).toContain('aria-label="法律库工作区"');
    expect(settings).toContain('class="provider-layout"');
    expect(settings).toContain('aria-label="Provider 与凭据设置"');
    expect(mcp).toContain('class="settings-maintenance-workspace"');
    expect(mcp).toContain('aria-label="MCP 与自动化设置"');
  });
});
