import type {
  PrivacyDictionaryCategory,
  PrivacyEntityType,
} from "../../ipc/privacy/risk-types";

export interface RiskReviewDraftSnapshot {
  entityType: PrivacyEntityType;
  replacement: string;
  dictionaryCategory: PrivacyDictionaryCategory;
  dictionaryRequired: boolean;
  mergeTarget: string;
  visualReasons: Readonly<Record<string, string>>;
}

export function cloneRiskReviewDraftSnapshot(
  snapshot: RiskReviewDraftSnapshot,
): RiskReviewDraftSnapshot {
  return {
    ...snapshot,
    visualReasons: { ...snapshot.visualReasons },
  };
}

function visualReasonsMatch(
  left: Readonly<Record<string, string>>,
  right: Readonly<Record<string, string>>,
): boolean {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  return [...keys].every(
    (key) => (left[key] ?? "") === (right[key] ?? ""),
  );
}

export function riskReviewDraftIsDirty(
  baseline: RiskReviewDraftSnapshot,
  current: RiskReviewDraftSnapshot,
): boolean {
  return (
    baseline.entityType !== current.entityType ||
    baseline.replacement !== current.replacement ||
    baseline.dictionaryCategory !== current.dictionaryCategory ||
    baseline.dictionaryRequired !== current.dictionaryRequired ||
    baseline.mergeTarget !== current.mergeTarget ||
    !visualReasonsMatch(
      baseline.visualReasons,
      current.visualReasons,
    )
  );
}

export function allowRiskFindingSwitch(
  draftDirty: boolean,
  confirmDiscard: () => boolean,
): boolean {
  return !draftDirty || confirmDiscard();
}

export function riskReviewActionSucceeded(
  result: boolean | void,
): result is true {
  return result === true;
}
