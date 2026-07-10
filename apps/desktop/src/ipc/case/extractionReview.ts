import type {
  ConfirmStructuredCaseExtractionRequest,
  StructuredCaseExtraction,
} from "./types";

export interface ExtractionContext {
  requestId: string;
  projectId: string;
  providerId: string;
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
      repaired: boolean;
      commitError?: string;
    }
  | {
      kind: "committing";
      context: ExtractionContext;
      reviewId: string;
      draft: StructuredCaseExtraction;
      repaired: boolean;
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
      repaired: boolean;
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
): ExtractionContext {
  return {
    requestId,
    projectId,
    providerId,
    sourceFileIds: [...sourceFileIds],
  };
}

export function extractionReducer(
  state: ExtractionState,
  action: ExtractionAction,
): ExtractionState {
  switch (action.type) {
    case "start":
      return { kind: "generating", context: action.context };
    case "generated":
      if (
        state.kind !== "generating" ||
        state.context.requestId !== action.requestId
      ) {
        return state;
      }
      return {
        kind: "reviewing",
        context: state.context,
        reviewId: action.reviewId,
        draft: action.draft,
        repaired: action.repaired,
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
    case "begin_commit":
      return state.kind === "reviewing"
        ? {
            kind: "committing",
            context: state.context,
            reviewId: state.reviewId,
            draft: state.draft,
            repaired: state.repaired,
          }
        : state;
    case "commit_failed":
      return state.kind === "committing"
        ? {
            kind: "reviewing",
            context: state.context,
            reviewId: state.reviewId,
            draft: state.draft,
            repaired: state.repaired,
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
    confirmed: true,
  };
}

export function extractionLocksSources(state: ExtractionState): boolean {
  return (
    state.kind === "generating" ||
    state.kind === "reviewing" ||
    state.kind === "committing"
  );
}
