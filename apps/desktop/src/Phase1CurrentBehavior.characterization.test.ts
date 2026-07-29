import { describe, expect, it } from "vitest";

import appSource from "./App.tsx?raw";
import assistantWorkspaceSource from "./features/assistant/AssistantWorkspace.tsx?raw";
import privacyReviewWorkbenchSource from "./features/privacy/PrivacyReviewWorkbench.tsx?raw";
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
      /function redirectLegacyEgressToApprovedProvider\([\s\S]*?navigateFromShell\("privacy"\);[\s\S]*?\}/u,
    );
    expect(appSource).toMatch(
      /<AssistantWorkspace[\s\S]*?onOpenApprovedProvider=\{\(task, notice\) =>[\s\S]*?redirectLegacyEgressToApprovedProvider\(task, notice\)/u,
    );
  });

  it("calls preparePrivacyMaterial from the Workbench without a case id", () => {
    expect(privacyReviewWorkbenchSource).toContain(
      "preparePrivacyMaterial({ customTerms: terms })",
    );
    expect(privacyReviewWorkbenchSource).not.toMatch(
      /preparePrivacyMaterial\(\{[\s\S]{0,200}\bcaseId\b/u,
    );
  });

  it("mounts review, lifecycle, provider approval, MCP approval, qualification, and OCR management together", () => {
    const workspaceImplementation = privacyWorkspaceSource.slice(
      privacyWorkspaceSource.indexOf("export function PrivacyWorkspace("),
    );

    for (const panel of [
      "PrivacyWorkspaceView",
      "MineruComponentManagerPanel",
      "PrivacyQualificationControls",
      "PrivacyLifecyclePanel",
      "PrivacyReviewWorkbench",
      "ProviderApprovalPanel",
      "ApprovedMcpPanel",
    ]) {
      expect(workspaceImplementation).toContain(`<${panel}`);
    }
  });
});
