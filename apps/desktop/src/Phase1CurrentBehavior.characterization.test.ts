import { describe, expect, it } from "vitest";

import appSource from "./App.tsx?raw";
import assistantWorkspaceSource from "./features/assistant/AssistantWorkspace.tsx?raw";
import redactionWorkbenchSource from "./features/cases/materials/RedactionWorkbench.tsx?raw";
import privacyWorkspaceSource from "./features/privacy/PrivacyWorkspace.tsx?raw";

describe("Phase 1 current application workflow characterization", () => {
  it("routes every ordinary Assistant submission into the Privacy approved-Provider flow", () => {
    expect(assistantWorkspaceSource).toMatch(
      /export function assistantRunIsIndependentPublicLegal[\s\S]*?return false;\s*\}/u,
    );
    expect(assistantWorkspaceSource).toMatch(
      /if \(!independentPublicLegalShell && onOpenApprovedProvider\) \{[\s\S]*?onOpenApprovedProvider\([\s\S]*?approvedProviderTaskForAssistantIntent\(intent\)[\s\S]*?return;/u,
    );
    expect(appSource).toMatch(
      /function redirectLegacyEgressToApprovedProvider\([\s\S]*?navigation\.handoffApprovedProvider\(\{ task, notice \}\)[\s\S]*?\}/u,
    );
    expect(appSource).toMatch(
      /<AssistantWorkspace[\s\S]*?onOpenApprovedProvider=\{[\s\S]*?redirectLegacyEgressToApprovedProvider[\s\S]*?\}/u,
    );
  });

  it("routes case material preparation through the required ProjectId boundary", () => {
    expect(redactionWorkbenchSource).toMatch(
      /prepareCaseMaterial\(\{\s*projectId,\s*customTerms: terms,\s*\}\)/u,
    );
    expect(redactionWorkbenchSource).not.toContain(
      "preparePrivacyMaterial(",
    );
    expect(redactionWorkbenchSource).not.toMatch(
      /\bprivacyCaseId\b|\bcaseId\b/u,
    );
  });

  it("keeps local processing and automation controls in settings but removes case review content", () => {
    const workspaceImplementation = privacyWorkspaceSource.slice(
      privacyWorkspaceSource.indexOf("export function PrivacyWorkspace("),
    );

    for (const panel of [
      "PrivacyWorkspaceView",
      "MineruComponentManagerPanel",
      "PrivacyQualificationControls",
      "PrivacyLifecyclePanel",
      "ProviderApprovalPanel",
      "ApprovedMcpPanel",
    ]) {
      expect(workspaceImplementation).toContain(`<${panel}`);
    }
    expect(workspaceImplementation).not.toContain(
      "<PrivacyReviewWorkbench",
    );
  });
});
