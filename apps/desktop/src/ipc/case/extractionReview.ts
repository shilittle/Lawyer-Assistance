import type {
  ConfirmStructuredCaseExtractionRequest,
  StructuredCaseExtraction,
  UpdatePendingStructuredCaseExtractionRequest,
} from "./types";
import type { ProviderAuditSnapshot } from "../provider/types";

export type PendingExtractionDraftSaveRequest = Omit<
  UpdatePendingStructuredCaseExtractionRequest,
  "expectedRevision"
>;

export interface ExtractionContext {
  requestId: string;
  projectId: string;
  providerId: string;
  providerSnapshot: ProviderAuditSnapshot | null;
  sourceFileIds: string[];
}

export type ExtractionState =
  | { kind: "idle" }
  | { kind: "generating"; context: ExtractionContext }
  | {
      kind: "reviewing";
      context: ExtractionContext;
      reviewId: string;
      draft: StructuredCaseExtraction;
      revision: number;
      repaired: boolean;
      restored?: boolean;
      restoredCreatedAt?: string;
      restoredExpiresAt?: string;
      commitError?: string;
    }
  | {
      kind: "committing";
      context: ExtractionContext;
      reviewId: string;
      draft: StructuredCaseExtraction;
      revision: number;
      repaired: boolean;
      restored?: boolean;
      restoredCreatedAt?: string;
      restoredExpiresAt?: string;
    }
  | {
      kind: "failed";
      message: string;
      repairAttempted: boolean;
      rawOutput?: string | null;
      repairOutput?: string | null;
    }
  | { kind: "committed"; message: string };

export type ExtractionAction =
  | { type: "start"; context: ExtractionContext }
  | {
      type: "generated";
      requestId: string;
      reviewId: string;
      draft: StructuredCaseExtraction;
      revision: number;
      repaired: boolean;
      providerSnapshot?: ProviderAuditSnapshot | null;
    }
  | {
      type: "restore";
      context: ExtractionContext;
      reviewId: string;
      draft: StructuredCaseExtraction;
      revision: number;
      createdAt: string;
      expiresAt: string;
    }
  | {
      type: "failed";
      requestId: string;
      message: string;
      repairAttempted: boolean;
      rawOutput?: string | null;
      repairOutput?: string | null;
    }
  | { type: "edit"; draft: StructuredCaseExtraction }
  | { type: "saved"; reviewId: string; revision: number; expiresAt: string }
  | { type: "begin_commit" }
  | { type: "commit_failed"; message: string }
  | { type: "committed"; message: string }
  | { type: "cancel" }
  | { type: "reset" };

export function createExtractionContext(
  requestId: string,
  projectId: string,
  providerId: string,
  sourceFileIds: string[],
  providerSnapshot: ProviderAuditSnapshot | null = null,
): ExtractionContext {
  return {
    requestId,
    projectId,
    providerId,
    providerSnapshot,
    sourceFileIds: [...sourceFileIds],
  };
}

export function extractionReducer(
  state: ExtractionState,
  action: ExtractionAction,
): ExtractionState {
  switch (action.type) {
    case "start":
      return state.kind === "generating" ||
        state.kind === "reviewing" ||
        state.kind === "committing"
        ? state
        : { kind: "generating", context: action.context };
    case "generated":
      if (
        state.kind !== "generating" ||
        state.context.requestId !== action.requestId
      ) {
        return state;
      }
      return {
        kind: "reviewing",
        context: {
          ...state.context,
          providerSnapshot:
            action.providerSnapshot ?? state.context.providerSnapshot,
        },
        reviewId: action.reviewId,
        draft: action.draft,
        revision: action.revision,
        repaired: action.repaired,
      };
    case "restore":
      if (
        state.kind === "generating" ||
        state.kind === "reviewing" ||
        state.kind === "committing"
      ) {
        return state;
      }
      return {
        kind: "reviewing",
        context: action.context,
        reviewId: action.reviewId,
        draft: action.draft,
        revision: action.revision,
        repaired: false,
        restored: true,
        restoredCreatedAt: action.createdAt,
        restoredExpiresAt: action.expiresAt,
      };
    case "failed":
      if (
        state.kind !== "generating" ||
        state.context.requestId !== action.requestId
      ) {
        return state;
      }
      return {
        kind: "failed",
        message: action.message,
        repairAttempted: action.repairAttempted,
        rawOutput: action.rawOutput,
        repairOutput: action.repairOutput,
      };
    case "edit":
      return state.kind === "reviewing"
        ? { ...state, draft: action.draft, commitError: undefined }
        : state;
    case "saved":
      return state.kind === "reviewing" && state.reviewId === action.reviewId
        ? {
            ...state,
            revision: action.revision,
            restoredExpiresAt: action.expiresAt,
          }
        : state;
    case "begin_commit":
      return state.kind === "reviewing"
        ? {
            kind: "committing",
            context: state.context,
            reviewId: state.reviewId,
            draft: state.draft,
            revision: state.revision,
            repaired: state.repaired,
            restored: state.restored,
            restoredCreatedAt: state.restoredCreatedAt,
            restoredExpiresAt: state.restoredExpiresAt,
          }
        : state;
    case "commit_failed":
      return state.kind === "committing"
        ? {
            kind: "reviewing",
            context: state.context,
            reviewId: state.reviewId,
            draft: state.draft,
            revision: state.revision,
            repaired: state.repaired,
            restored: state.restored,
            restoredCreatedAt: state.restoredCreatedAt,
            restoredExpiresAt: state.restoredExpiresAt,
            commitError: action.message,
          }
        : state;
    case "committed":
      return state.kind === "committing"
        ? { kind: "committed", message: action.message }
        : state;
    case "cancel":
    case "reset":
      return { kind: "idle" };
  }
}

export function buildConfirmationRequest(
  state: ExtractionState,
): ConfirmStructuredCaseExtractionRequest | null {
  if (state.kind !== "reviewing") {
    return null;
  }
  return {
    reviewId: state.reviewId,
    projectId: state.context.projectId,
    providerId: state.context.providerId,
    fileIds: [...state.context.sourceFileIds],
    extraction: state.draft,
    expectedRevision: state.revision,
    confirmed: true,
  };
}

export function pendingExtractionUpdateAtRevision(
  request: PendingExtractionDraftSaveRequest,
  expectedRevision: number,
): UpdatePendingStructuredCaseExtractionRequest {
  return { ...request, expectedRevision };
}

export interface PendingExtractionSaveDrain<T> {
  targetSequence: () => number;
  isBlocked: () => boolean;
  savedSequence: () => number;
  hasPending: () => boolean;
  takePending: () => T | null;
  waitForCurrent: () => Promise<boolean>;
  enqueue: (pending: T) => Promise<boolean>;
}

/**
 * Waits until every edit that existed when confirmation/cancellation began is
 * durably saved. A timer may already have taken a draft, or a second edit may
 * appear while an earlier save is in flight, so neither `pending === null` nor
 * awaiting one captured promise is by itself a safe completion condition.
 */
export async function drainPendingExtractionSaves<T>(
  drain: PendingExtractionSaveDrain<T>,
): Promise<boolean> {
  while (drain.savedSequence() < drain.targetSequence()) {
    if (drain.isBlocked()) {
      return false;
    }
    const savedBefore = drain.savedSequence();
    const pending = drain.takePending();
    const saved = pending
      ? await drain.enqueue(pending)
      : await drain.waitForCurrent();
    if (!saved) {
      return false;
    }
    if (drain.savedSequence() <= savedBefore && !drain.hasPending()) {
      // A resolved "success" promise that cannot advance the durable sequence
      // must fail closed. Looping it would starve the renderer forever.
      return false;
    }
  }
  return (
    !drain.isBlocked() &&
    !drain.hasPending() &&
    drain.savedSequence() >= drain.targetSequence()
  );
}

export interface ExtractionCloseGuard {
  needsFlush: boolean;
  forceControlledClose?: boolean;
  preventDefault: () => void;
  flush: () => Promise<boolean>;
  destroyWindow: () => Promise<void>;
  onBlocked: (message: string) => void;
}

export type ExtractionCloseGuardResult =
  | "allow"
  | "saved_and_closed"
  | "blocked";

/**
 * Prevents a controlled native close synchronously, flushes queued review
 * edits when required, then destroys the window. A failed flush or destroy
 * keeps the window open so the user can recover safely.
 */
export async function guardExtractionClose(
  guard: ExtractionCloseGuard,
): Promise<ExtractionCloseGuardResult> {
  if (!guard.needsFlush && !guard.forceControlledClose) {
    return "allow";
  }

  guard.preventDefault();
  try {
    if (guard.needsFlush && !(await guard.flush())) {
      guard.onBlocked("审阅修改尚未安全保存，已阻止关闭窗口。请检查提示并重试。");
      return "blocked";
    }
    await guard.destroyWindow();
    return "saved_and_closed";
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error);
    guard.onBlocked(`关闭前保存审阅修改失败，窗口已保持打开：${detail}`);
    return "blocked";
  }
}

export function extractionReviewNeedsCloseFlush(
  state: ExtractionState,
  savedSequence: number,
  targetSequence: number,
  hasPendingDraft: boolean,
): boolean {
  return (
    state.kind === "reviewing" &&
    (hasPendingDraft || savedSequence < targetSequence)
  );
}

/** A close must wait while a destructive review transaction is unresolved. */
export function extractionMutationBlocksClose(
  confirmInFlight: boolean,
  discardInFlight: boolean,
): boolean {
  return confirmInFlight || discardInFlight;
}

export function extractionLocksSources(state: ExtractionState): boolean {
  return (
    state.kind === "generating" ||
    state.kind === "reviewing" ||
    state.kind === "committing"
  );
}
