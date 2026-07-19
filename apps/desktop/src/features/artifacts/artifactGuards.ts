import type {
  AssistantArtifact,
  AssistantArtifactVersion,
  AssistantMessage,
  AssistantRun,
} from "../../ipc/assistant/types";
import type { MapArtifactEditFields } from "./artifactEditing";
import { mapSpecFromArtifactVersion } from "./mapModel";

export function artifactHasTrustedRegenerationOrigin(
  artifact: AssistantArtifact,
  messages: readonly AssistantMessage[],
  runs: readonly AssistantRun[],
): boolean {
  const allowedIntents =
    artifact.kind === "research"
      ? new Set(["legal_research", "file_analysis"])
      : artifact.kind === "document"
        ? new Set(["document_draft"])
        : new Set(["map_build"]);
  return messages.some((message) => {
    if (
      message.conversationId !== artifact.conversationId ||
      message.role !== "assistant" ||
      message.kind !== "artifact_ref" ||
      message.artifactId !== artifact.artifactId ||
      message.runId === null
    ) {
      return false;
    }
    return runs.some(
      (run) =>
        run.runId === message.runId &&
        run.conversationId === artifact.conversationId &&
        run.assistantMessageId === message.messageId &&
        run.status === "succeeded" &&
        allowedIntents.has(run.intent),
    );
  });
}

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
