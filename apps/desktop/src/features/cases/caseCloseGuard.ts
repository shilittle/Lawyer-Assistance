import type { CaseDraftKind } from "../../app/navigationGuards";
import {
  guardExtractionClose,
  type ExtractionCloseGuardResult,
} from "../../ipc/case/extractionReview";

export interface CaseCloseSnapshot {
  dirtyDrafts: readonly CaseDraftKind[];
  caseMutationInFlight: boolean;
  extractionMutationInFlight: boolean;
  extractionNeedsFlush: boolean;
  extractionCloseInProgress: boolean;
}

export interface CaseControlledCloseRequest {
  forceControlledClose: boolean;
  preventDefault: () => void;
  destroyWindow: () => Promise<void>;
  onBlocked: (message: string) => void;
}

export interface CaseCloseGuardPort {
  read(): CaseCloseSnapshot;
  requestControlledClose(
    request: CaseControlledCloseRequest,
  ): Promise<ExtractionCloseGuardResult>;
}

export interface CaseCloseGuardDependencies {
  readSnapshot: () => CaseCloseSnapshot;
  flushPendingDraft: () => Promise<boolean>;
  beginControlledClose: (needsFlush: boolean) => void;
  finishBlockedClose: () => void;
}

/**
 * Creates the case feature's narrow close-guard port. The port deliberately
 * knows nothing about Tauri, browser events, or the other feature workspaces;
 * App owns those global concerns and supplies only the controlled-close
 * capabilities for the current request.
 */
export function createCaseCloseGuard(
  dependencies: CaseCloseGuardDependencies,
): CaseCloseGuardPort {
  return {
    read: dependencies.readSnapshot,
    async requestControlledClose(request) {
      const snapshot = dependencies.readSnapshot();
      const needsFlush = snapshot.extractionNeedsFlush;
      if (needsFlush || request.forceControlledClose) {
        dependencies.beginControlledClose(needsFlush);
      }

      const result = await guardExtractionClose({
        needsFlush,
        forceControlledClose: request.forceControlledClose,
        preventDefault: request.preventDefault,
        flush: dependencies.flushPendingDraft,
        destroyWindow: request.destroyWindow,
        onBlocked: request.onBlocked,
      });
      if (result === "blocked") {
        dependencies.finishBlockedClose();
      }
      return result;
    },
  };
}
