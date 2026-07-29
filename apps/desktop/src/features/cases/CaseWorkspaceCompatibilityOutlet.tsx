import type { GraphTargetRequest } from "../../app/routes";
import type { LegalSource } from "../../ipc/legal/types";
import type { ProviderProfile } from "../../ipc/provider/types";
import { CaseGapExtractionPanel } from "./CaseGapExtractionPanel";
import { CaseProjectListPanel } from "./CaseProjectListPanel";
import { CasesWorkspace } from "./CasesWorkspace";
import { CaseWorkbenchPanel } from "./CaseWorkbenchPanel";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseWorkspaceCompatibilityOutletProps {
  controller: CaseWorkspaceController;
  providerProfiles: readonly ProviderProfile[];
  legalSources: readonly LegalSource[];
  graphTarget: GraphTargetRequest | null;
  onContinueInAssistant: () => void;
  onOpenCaseGraph: () => void;
}

export function CaseWorkspaceCompatibilityOutlet({
  controller,
  providerProfiles,
  legalSources,
  graphTarget,
  onContinueInAssistant,
  onOpenCaseGraph,
}: CaseWorkspaceCompatibilityOutletProps) {
  return (
    <CasesWorkspace busy={controller.caseState.kind === "loading"}>
      <CaseProjectListPanel controller={controller} />
      <CaseWorkbenchPanel
        controller={controller}
        graphTarget={graphTarget}
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
