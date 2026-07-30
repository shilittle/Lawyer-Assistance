import { useCallback, useMemo, useState } from "react";

import {
  useWorkspaceActivityChannel,
  type WorkspaceActivityChannel,
} from "../../../app/useWorkspaceActivityChannel";

export interface CaseMaterialActivityChannel
  extends WorkspaceActivityChannel {
  readonly resetKey: number;
}

/**
 * Discarding a ref alone would leave sensitive edited text mounted. This
 * channel advances a render key as part of the same discard operation so the
 * case material workspace is remounted with a clean UI state.
 */
export function useCaseMaterialActivityChannel(): CaseMaterialActivityChannel {
  const base = useWorkspaceActivityChannel();
  const [resetKey, setResetKey] = useState(0);
  const discardDraft = useCallback(() => {
    base.discardDraft();
    setResetKey((current) => current + 1);
  }, [base]);

  return useMemo(
    () => ({
      ...base,
      discardDraft,
      resetKey,
    }),
    [base, discardDraft, resetKey],
  );
}
