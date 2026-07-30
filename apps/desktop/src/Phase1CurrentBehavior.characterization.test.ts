import { describe, expect, it } from "vitest";

import appSource from "./App.tsx?raw";
import assistantClientSource from "./ipc/assistant/client.ts?raw";
import assistantWorkspaceSource from "./features/assistant/AssistantWorkspace.tsx?raw";
import providerEgressNoticeSource from "./features/assistant/ProviderEgressNotice.tsx?raw";
import redactionWorkbenchSource from "./features/cases/materials/RedactionWorkbench.tsx?raw";
import privacyWorkspaceSource from "./features/privacy/PrivacyWorkspace.tsx?raw";

describe("Phase 1 current application workflow characterization", () => {
  it("sends ordinary Assistant messages through the independent interactive boundary", () => {
    expect(assistantClientSource).toContain(
      'invokeAssistant("start_interactive_assistant_run"',
    );
    expect(assistantWorkspaceSource).toContain("<ProviderEgressNotice");
    expect(providerEgressNoticeSource).toContain(
      "INTERACTIVE_PROVIDER_EGRESS_WARNING",
    );
    expect(assistantWorkspaceSource).not.toContain(
      "assistantRunIsIndependentPublicLegal",
    );
    expect(assistantWorkspaceSource).not.toContain("onOpenApprovedProvider");
    expect(assistantWorkspaceSource).not.toContain("前往脱敏批准");
    expect(assistantWorkspaceSource).toMatch(
      /<form className="assistant-composer"[\s\S]*?<ProviderEgressNotice/u,
    );
    expect(assistantWorkspaceSource).toContain(
      "onOpenProtectedArtifactRegeneration",
    );
    expect(appSource).not.toMatch(
      /<AssistantWorkspace[\s\S]*?onOpenApprovedProvider=/u,
    );
    expect(appSource).toContain("onOpenProtectedArtifactRegeneration=");
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
