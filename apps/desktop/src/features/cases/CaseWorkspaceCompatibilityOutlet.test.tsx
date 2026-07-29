import { describe, expect, it } from "vitest";

import appSource from "../../App.tsx?raw";
import gapPanelSource from "./CaseGapExtractionPanel.tsx?raw";
import listPanelSource from "./CaseProjectListPanel.tsx?raw";
import outletSource from "./CaseWorkspaceCompatibilityOutlet.tsx?raw";
import workbenchPanelSource from "./CaseWorkbenchPanel.tsx?raw";

const caseFeatureSource = [
  outletSource,
  listPanelSource,
  workbenchPanelSource,
  gapPanelSource,
].join("\n");

describe("CaseWorkspaceCompatibilityOutlet source boundary", () => {
  it("keeps the characterized case forms and extraction review in the case feature", () => {
    expect(caseFeatureSource).toContain('<form className="case-form"');
    expect(caseFeatureSource).toContain("case-file-title");
    expect(caseFeatureSource).toContain("case-party-name");
    expect(caseFeatureSource).toContain("case-fact-title");
    expect(caseFeatureSource).toContain("case-evidence-number");
    expect(caseFeatureSource).toContain("case-issue-title");
    expect(caseFeatureSource).toContain('className="extraction-review"');
    expect(caseFeatureSource).toContain("extraction-review-title");
    expect(caseFeatureSource).toContain("confirmExtractionReview");
  });

  it("leaves App as assembly without case forms or draft setters", () => {
    expect(appSource).not.toContain("<form");
    expect(appSource).not.toContain("setCaseProjectDraft");
    expect(appSource).not.toContain("setExtractionFileIds");
    expect(appSource).toContain("<CaseWorkspaceCompatibilityOutlet");
  });
});
