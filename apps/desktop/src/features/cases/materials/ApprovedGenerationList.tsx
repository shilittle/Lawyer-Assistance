import type { CaseRedactionGenerationSummary } from "../../../ipc/privacy/case-material-types";
import { isCaseRedactionGenerationAvailable } from "./caseMaterialAvailability";

export interface ApprovedGenerationListProps {
  generations: readonly CaseRedactionGenerationSummary[];
  selectedRedactionId: string | null;
  busy: boolean;
  onSelect: (redactionId: string) => void;
}

function generationStatus(
  generation: CaseRedactionGenerationSummary,
): string {
  if (generation.generationStatus !== "ready") {
    return `不可用：${generation.generationStatus}`;
  }
  if (
    generation.revocationState !== "active" ||
    generation.revokedAt !== null
  ) {
    return "已撤销";
  }
  if (
    generation.reviewState === "approved" &&
    generation.approvedPayloadSha256
  ) {
    return "已批准";
  }
  return generation.reviewState === "review_required"
    ? "待人工复核"
    : generation.reviewState;
}

export function ApprovedGenerationList({
  generations,
  selectedRedactionId,
  busy,
  onSelect,
}: ApprovedGenerationListProps) {
  return (
    <section
      className="case-generation-list"
      aria-labelledby="case-generation-list-title"
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">版本历史</p>
          <h2 id="case-generation-list-title">脱敏代次</h2>
        </div>
        <span>{generations.length}</span>
      </div>
      <div className="case-generation-list__items">
        {generations.map((generation) => {
          const available =
            isCaseRedactionGenerationAvailable(generation);
          const approved =
            available &&
            generation.reviewState === "approved" &&
            generation.approvedPayloadSha256 !== null &&
            generation.revocationState === "active" &&
            generation.revokedAt === null;
          return (
            <button
              aria-current={
                selectedRedactionId === generation.redactionId
                  ? "true"
                  : undefined
              }
              className={[
                "case-generation-card",
                selectedRedactionId === generation.redactionId
                  ? "is-selected"
                  : "",
                approved ? "is-approved" : "",
                !available ? "is-history-only" : "",
              ]
                .filter(Boolean)
                .join(" ")}
              disabled={busy}
              key={generation.redactionId}
              type="button"
              onClick={() => onSelect(generation.redactionId)}
            >
              <strong>第 {generation.generationNumber} 代</strong>
              <span>{generationStatus(generation)}</span>
              <small>风险 revision {generation.riskRevision}</small>
            </button>
          );
        })}
        {generations.length === 0 ? (
          <p className="empty-state">该材料尚无脱敏代次。</p>
        ) : null}
      </div>
    </section>
  );
}
