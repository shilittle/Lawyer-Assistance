import { useEffect, useState } from "react";

import type { GraphTargetRequest } from "../../app/routes";
import type { LegalSource } from "../../ipc/legal/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import { CaseGapExtractionPanel } from "./CaseGapExtractionPanel";
import { CaseProjectListPanel } from "./CaseProjectListPanel";
import { CasesWorkspace } from "./CasesWorkspace";
import { CaseWorkbenchPanel } from "./CaseWorkbenchPanel";
import { caseGraphNodeDomId } from "./model";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseWorkspaceCompatibilityOutletProps {
  controller: CaseWorkspaceController;
  providerProfiles: readonly ProviderProfile[];
  legalSources: readonly LegalSource[];
  graphTarget: GraphTargetRequest | null;
  onGraphTargetConsumed: (target: GraphTargetRequest) => void;
  onContinueInAssistant: () => void;
  onOpenCaseGraph: () => void;
}

export function CaseWorkspaceCompatibilityOutlet({
  controller,
  providerProfiles,
  legalSources,
  graphTarget,
  onGraphTargetConsumed,
  onContinueInAssistant,
  onOpenCaseGraph,
}: CaseWorkspaceCompatibilityOutletProps) {
  const [activeGraphTarget, setActiveGraphTarget] =
    useState<GraphTargetRequest | null>(null);

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

  return (
    <CasesWorkspace busy={controller.caseState.kind === "loading"}>
      <CaseProjectListPanel controller={controller} />
      <CaseWorkbenchPanel
        controller={controller}
        graphTarget={activeGraphTarget}
        legalSources={legalSources}
        onContinueInAssistant={onContinueInAssistant}
        onOpenCaseGraph={onOpenCaseGraph}
      />
      <CaseGapExtractionPanel
        controller={controller}
        providerProfiles={providerProfiles}
      />
    </CasesWorkspace>
  );
}
