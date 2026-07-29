import { describe, expect, it } from "vitest";

import appSource from "../App.tsx?raw";

describe("Phase 2 App composition boundary", () => {
  it("keeps the root component limited to typed feature assembly", () => {
    expect(appSource).toContain('<AppErrorBoundary resetKey="app-root">');
    expect(appSource).toMatch(/<AppShell[\s\S]*?\broute=/u);
    expect(appSource).toContain("<AppRouter");

    for (const controller of [
      "useAppNavigationController",
      "useAssistantController",
      "useCaseWorkspaceController",
      "useLegalLibraryController",
      "useProviderSettingsController",
      "useGraphOutputController",
      "useWindowCloseProtection",
    ]) {
      expect(appSource).toContain(`${controller}(`);
    }

    expect(appSource).not.toMatch(
      /\bViewMode\b|\bviewMode\b|activeView=/u,
    );
    expect(appSource).not.toContain("<form");
    expect(appSource).not.toMatch(/\buseState\b|\buseReducer\b/u);
    expect(appSource).not.toMatch(
      /from "\.\/ipc\/(?:assistant|case|legal|privacy|provider)\//u,
    );
    expect(appSource).not.toMatch(
      /\b(caseProjectDraft|fileDraft|partyDraft|factDraft|evidenceDraft|issueDraft|extractionState)\b/u,
    );
    expect(appSource.split(/\r?\n/u).length).toBeLessThan(500);
  });
});
