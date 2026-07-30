import type {
  CaseMaterialSummary,
  CaseRedactionGenerationSummary,
} from "../../../ipc/privacy/case-material-types";

export const UNAVAILABLE_CASE_MATERIAL_STATES = new Set([
  "blocked",
  "stale",
  "revoked",
  "deleted",
]);

export function isCaseMaterialAvailable(
  material: CaseMaterialSummary,
): boolean {
  return (
    material.migrationStatus === "ready" &&
    material.deletedAt === null &&
    material.sourceKind !== "legacy_reference" &&
    !UNAVAILABLE_CASE_MATERIAL_STATES.has(material.state)
  );
}

export function isCaseRedactionGenerationAvailable(
  generation: CaseRedactionGenerationSummary,
): boolean {
  return (
    generation.generationStatus === "ready" &&
    generation.revocationState === "active" &&
    generation.revokedAt === null &&
    !["revoked", "stale"].includes(generation.reviewState)
  );
}

export function caseMaterialSelectionIsHistoryOnly(
  material: CaseMaterialSummary | null,
  generation: CaseRedactionGenerationSummary | null,
): boolean {
  return Boolean(
    material &&
      (!isCaseMaterialAvailable(material) ||
        (generation &&
          !isCaseRedactionGenerationAvailable(generation))),
  );
}
