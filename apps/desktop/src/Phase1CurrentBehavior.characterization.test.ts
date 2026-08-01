import { describe, expect, it } from "vitest";

import appSource from "./App.tsx?raw";
import assistantClientSource from "./ipc/assistant/client.ts?raw";
import assistantWorkspaceSource from "./features/assistant/AssistantWorkspace.tsx?raw";
import caseAssistantWorkspaceSource from "./features/cases/assistant/CaseAssistantWorkspace.tsx?raw";
import providerEgressNoticeSource from "./features/assistant/ProviderEgressNotice.tsx?raw";
import redactionWorkbenchSource from "./features/cases/materials/RedactionWorkbench.tsx?raw";
import localProcessingWorkspaceSource from "./features/settings/local-processing/LocalProcessingWorkspace.tsx?raw";
import maintenanceWorkspaceSource from "./features/settings/maintenance/MaintenanceWorkspace.tsx?raw";
import automationWorkspaceSource from "./features/settings/automation/McpAndAutomationWorkspace.tsx?raw";

describe("Phase 1 current application workflow characterization", () => {
  it("sends ordinary Assistant messages through the independent interactive boundary", () => {
    expect(assistantClientSource).toContain(
      'invokeAssistant("start_interactive_assistant_run"',
    );
    expect(assistantClientSource).not.toContain(
      'invokeAssistant("start_assistant_run"',
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
    expect(assistantWorkspaceSource).not.toContain("caseHandoff");
    expect(assistantWorkspaceSource).not.toContain("handledCaseHandoff");
    expect(assistantWorkspaceSource).not.toContain(
      "latestCaseHandoffRequest",
    );
    expect(assistantWorkspaceSource).toMatch(
      /<form className="assistant-composer"[\s\S]*?<ProviderEgressNotice/u,
    );
    expect(assistantWorkspaceSource).not.toContain(
      "onOpenProtectedArtifactRegeneration",
    );
    expect(appSource).not.toMatch(
      /<AssistantWorkspace[\s\S]*?onOpenApprovedProvider=/u,
    );
    expect(appSource).not.toContain("onOpenProtectedArtifactRegeneration=");
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

  it("keeps local processing separate from the MCP and automation settings owner", () => {
    const workspaceImplementation = localProcessingWorkspaceSource.slice(
      localProcessingWorkspaceSource.indexOf(
        "export function LocalProcessingWorkspace(",
      ),
    );

    for (const panel of [
      "LocalProcessingWorkspaceView",
      "MineruComponentManagerPanel",
      "PrivacyQualificationControls",
    ]) {
      expect(workspaceImplementation).toContain(`<${panel}`);
    }
    expect(workspaceImplementation).not.toContain(
      "<AutomationOutboundApprovalPanel",
    );
    expect(workspaceImplementation).not.toContain("<ProviderApprovalPanel");
    expect(workspaceImplementation).not.toContain("<ApprovedMcpPanel");
    expect(workspaceImplementation).not.toContain(
      "<PrivacyReviewWorkbench",
    );
    expect(workspaceImplementation).not.toContain("<PrivacyLifecyclePanel");
    expect(maintenanceWorkspaceSource).toContain("<PrivacyLifecyclePanel");

    for (const panel of [
      "McpWorkspace",
      "AutomationOutboundApprovalPanel",
      "ApprovedMcpPanel",
    ]) {
      expect(automationWorkspaceSource).toContain(`<${panel}`);
    }
  });

  it("does not import automation panels into ordinary or case Assistant", () => {
    for (const source of [
      assistantWorkspaceSource,
      caseAssistantWorkspaceSource,
    ]) {
      expect(source).not.toContain("AutomationOutboundApprovalPanel");
      expect(source).not.toContain("ProviderApprovalPanel");
      expect(source).not.toContain("ApprovedMcpPanel");
      expect(source).not.toContain("McpAndAutomationWorkspace");
    }
  });
});
