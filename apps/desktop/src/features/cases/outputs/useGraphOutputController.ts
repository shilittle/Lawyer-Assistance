import { useCallback, useState } from "react";

import type { GraphMode } from "../../../ipc/graph/types";

export function graphModeForNavigation(
  current: GraphMode,
  hasSelectedCase: boolean,
  hasSelectedLegalDocument: boolean,
): GraphMode {
  if (hasSelectedCase) return "case";
  if (hasSelectedLegalDocument) return "law";
  return current;
}

export interface GraphOutputController {
  readonly mode: GraphMode;
  readonly setMode: (mode: GraphMode) => void;
  readonly showCaseGraph: () => void;
  readonly showLawGraph: () => void;
  readonly prepareForNavigation: (
    hasSelectedCase: boolean,
    hasSelectedLegalDocument: boolean,
  ) => void;
}

export function useGraphOutputController(): GraphOutputController {
  const [mode, setMode] = useState<GraphMode>("case");
  const showCaseGraph = useCallback(() => setMode("case"), []);
  const showLawGraph = useCallback(() => setMode("law"), []);
  const prepareForNavigation = useCallback(
    (
      hasSelectedCase: boolean,
      hasSelectedLegalDocument: boolean,
    ) => {
      setMode((current) =>
        graphModeForNavigation(
          current,
          hasSelectedCase,
          hasSelectedLegalDocument,
        ),
      );
    },
    [],
  );

  return {
    mode,
    setMode,
    showCaseGraph,
    showLawGraph,
    prepareForNavigation,
  };
}
