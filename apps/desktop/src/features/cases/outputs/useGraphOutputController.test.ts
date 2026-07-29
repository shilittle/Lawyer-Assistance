import { describe, expect, it } from "vitest";

import { graphModeForNavigation } from "./useGraphOutputController";

describe("graphModeForNavigation", () => {
  it("preserves the characterized case-first navigation choice", () => {
    expect(graphModeForNavigation("law", true, true)).toBe("case");
    expect(graphModeForNavigation("law", true, false)).toBe("case");
  });

  it("uses law mode only when no case and a legal document is selected", () => {
    expect(graphModeForNavigation("case", false, true)).toBe("law");
  });

  it("keeps the current mode when neither source scope is selected", () => {
    expect(graphModeForNavigation("case", false, false)).toBe("case");
    expect(graphModeForNavigation("law", false, false)).toBe("law");
  });
});
