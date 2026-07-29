import { useCallback, useMemo, useRef } from "react";

import type { NavigationProtectionChannel } from "./useAppNavigationController";

export interface WorkspaceActivityChannel
  extends NavigationProtectionChannel {
  readonly onDraftDirtyChange: (dirty: boolean) => void;
  readonly onMutationActivityChange: (active: boolean) => void;
}

export function useWorkspaceActivityChannel(): WorkspaceActivityChannel {
  const draftDirty = useRef(false);
  const mutationInFlight = useRef(false);

  const readDraftDirty = useCallback(() => draftDirty.current, []);
  const readMutationInFlight = useCallback(
    () => mutationInFlight.current,
    [],
  );
  const discardDraft = useCallback(() => {
    draftDirty.current = false;
  }, []);
  const onDraftDirtyChange = useCallback((dirty: boolean) => {
    draftDirty.current = dirty;
  }, []);
  const onMutationActivityChange = useCallback((active: boolean) => {
    mutationInFlight.current = active;
  }, []);

  return useMemo(
    () => ({
      readDraftDirty,
      readMutationInFlight,
      discardDraft,
      onDraftDirtyChange,
      onMutationActivityChange,
    }),
    [
      discardDraft,
      onDraftDirtyChange,
      onMutationActivityChange,
      readDraftDirty,
      readMutationInFlight,
    ],
  );
}
