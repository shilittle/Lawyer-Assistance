import { useEffect, useState } from "react";

import type { GraphTargetRequest } from "../../app/routes";
import type { LegalSource } from "../../ipc/legal/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import { CaseGapExtractionPanel } from "./CaseGapExtractionPanel";
import { CaseAssistantWorkspace } from "./assistant/CaseAssistantWorkspace";
import { CaseProjectListPanel } from "./CaseProjectListPanel";
import { CasesWorkspace } from "./CasesWorkspace";
import { CaseWorkbenchPanel } from "./CaseWorkbenchPanel";
import { caseGraphNodeDomId } from "./model";
import { CaseMaterialsWorkspace } from "./materials/CaseMaterialsWorkspace";
import type { CaseSection } from "./CaseNavigation";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseWorkspaceCompatibilityOutletProps {
  section: Exclude<CaseSection, "outputs">;
  controller: CaseWorkspaceController;
  providerProfiles: readonly ProviderProfile[];
  legalSources: readonly LegalSource[];
  graphTarget: GraphTargetRequest | null;
  onGraphTargetConsumed: (target: GraphTargetRequest) => void;
  onOpenCaseGraph: () => void;
  caseMaterialResetKey: number;
  onCaseMaterialDraftDirtyChange: (dirty: boolean) => void;
  onCaseMaterialMutationActivityChange: (active: boolean) => void;
  onBeforeCaseMaterialProjectChange: (
    projectId: string | null,
  ) => boolean;
}

export function CaseWorkspaceCompatibilityOutlet({
  section,
  controller,
  providerProfiles,
  legalSources,
  graphTarget,
  onGraphTargetConsumed,
  onOpenCaseGraph,
  caseMaterialResetKey,
  onCaseMaterialDraftDirtyChange,
  onCaseMaterialMutationActivityChange,
  onBeforeCaseMaterialProjectChange,
}: CaseWorkspaceCompatibilityOutletProps) {
  const [activeGraphTarget, setActiveGraphTarget] =
    useState<GraphTargetRequest | null>(null);
  const [caseAssistantDraftDirty, setCaseAssistantDraftDirty] =
    useState(false);
  const [caseAssistantMutationActive, setCaseAssistantMutationActive] =
    useState(false);
  const [caseAssistantRunActive, setCaseAssistantRunActive] =
    useState(false);

  useEffect(() => {
    if (!graphTarget) return;
    const frame = window.requestAnimationFrame(() => {
      setActiveGraphTarget(graphTarget);
      onGraphTargetConsumed(graphTarget);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [graphTarget, onGraphTargetConsumed]);

  useEffect(() => {
    if (!activeGraphTarget) return;
    const targetId = caseGraphNodeDomId(
      activeGraphTarget.sourceKind,
      activeGraphTarget.sourceId,
    );
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(targetId);
      target?.scrollIntoView({ behavior: "smooth", block: "center" });
      target?.focus({ preventScroll: true });
    });
    const clearHighlight = window.setTimeout(() => {
      setActiveGraphTarget((current) =>
        current?.sourceKind === activeGraphTarget.sourceKind &&
        current.sourceId === activeGraphTarget.sourceId
          ? null
          : current,
      );
    }, 4000);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(clearHighlight);
    };
  }, [activeGraphTarget]);

  if (section === "materials") {
    return (
      <CasesWorkspace busy={controller.caseState.kind === "loading"}>
        <CaseProjectListPanel
          controller={controller}
          onBeforeProjectChange={
            onBeforeCaseMaterialProjectChange
          }
        />
        <CaseMaterialsWorkspace
          key={`${controller.selectedCaseProjectId ?? "none"}:${caseMaterialResetKey}`}
          projectId={controller.selectedCaseProjectId}
          resetKey={caseMaterialResetKey}
          onDraftDirtyChange={
            onCaseMaterialDraftDirtyChange
          }
          onMutationActivityChange={
            onCaseMaterialMutationActivityChange
          }
        />
      </CasesWorkspace>
    );
  }

  const caseAssistantLocked =
    caseAssistantMutationActive || caseAssistantRunActive;
  const beforeCaseAssistantProjectChange = () => {
    if (caseAssistantLocked) return false;
    if (
      caseAssistantDraftDirty &&
      !window.confirm(
        "切换案件将清空当前案件助理尚未发送的会话标题和任务草稿。是否放弃这些草稿？",
      )
    ) {
      return false;
    }
    setCaseAssistantDraftDirty(false);
    return true;
  };

  return (
    <CasesWorkspace busy={controller.caseState.kind === "loading"}>
      <CaseProjectListPanel
        controller={controller}
        externallyLocked={section === "work" && caseAssistantLocked}
        onBeforeProjectChange={
          section === "work"
            ? beforeCaseAssistantProjectChange
            : undefined
        }
      />
      <CaseWorkbenchPanel
        controller={controller}
        graphTarget={activeGraphTarget}
        legalSources={legalSources}
        onOpenCaseGraph={onOpenCaseGraph}
      />
      <CaseGapExtractionPanel
        controller={controller}
      />
      {section === "work" ? (
        <CaseAssistantWorkspace
          key={controller.selectedCaseProjectId ?? "no-case"}
          projectId={controller.selectedCaseProjectId}
          providerProfiles={providerProfiles}
          onDraftDirtyChange={setCaseAssistantDraftDirty}
          onMutationActivityChange={setCaseAssistantMutationActive}
          onRunActivityChange={setCaseAssistantRunActive}
          onOutputApplied={() => {
            if (controller.selectedCaseProjectId) {
              controller.refreshCaseAfterAssistantProposal(
                controller.selectedCaseProjectId,
              );
            }
          }}
        />
      ) : null}
    </CasesWorkspace>
  );
}
