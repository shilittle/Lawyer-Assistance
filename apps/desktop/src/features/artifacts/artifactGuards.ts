import type { AssistantArtifactVersion } from "../../ipc/assistant/types";
import type { MapArtifactEditFields } from "./artifactEditing";
import { mapSpecFromArtifactVersion } from "./mapModel";

export function mapArtifactEditHasUnsavedChanges(
  fields: MapArtifactEditFields | null,
  version: AssistantArtifactVersion | null,
): boolean {
  if (!fields || !version) return false;
  const spec = mapSpecFromArtifactVersion(version);
  if (!spec) return true;
  return (
    fields.title !== spec.title ||
    fields.layoutHint !== spec.layoutHint ||
    fields.nodesJson !== JSON.stringify(spec.nodes, null, 2) ||
    fields.edgesJson !== JSON.stringify(spec.edges, null, 2)
  );
}
