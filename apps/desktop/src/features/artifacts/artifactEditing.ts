import { saveAssistantArtifact } from "../../ipc/assistant/client";
import type {
  AssistantArtifact,
  GetAssistantArtifactResponse,
  JsonValue,
  MapLayoutHint,
  MapSpec,
  SaveAssistantArtifactRequest,
  SaveAssistantArtifactResponse,
} from "../../ipc/assistant/types";
import { mapSpecFromJsonValue } from "./mapModel";

const MAX_MAP_TITLE_BYTES = 256;
const MAX_JSON_EDITOR_CHARS = 2 * 1024 * 1024;

export interface MapArtifactEditFields {
  title: string;
  layoutHint: MapLayoutHint;
  nodesJson: string;
  edgesJson: string;
}

export type MapArtifactEditParseResult =
  | { ok: true; spec: MapSpec }
  | { ok: false; message: string };

export interface PersistMapArtifactEditRequest {
  artifact: AssistantArtifact;
  expectedCurrentVersion: number;
  fields: MapArtifactEditFields;
}

export interface PersistMapArtifactEditResult {
  detail: GetAssistantArtifactResponse;
  mode: "new_version" | "renamed_copy";
}

export type SaveAssistantArtifact = (
  request: SaveAssistantArtifactRequest,
) => Promise<SaveAssistantArtifactResponse>;

function parseArray(text: string, label: string): JsonValue[] | string {
  if (!text.trim()) return `${label} 不能为空。`;
  if (text.length > MAX_JSON_EDITOR_CHARS) return `${label} 过大。`;
  try {
    const parsed = JSON.parse(text) as unknown;
    return Array.isArray(parsed)
      ? (parsed as JsonValue[])
      : `${label} 必须是 JSON 数组。`;
  } catch {
    return `${label} 不是有效 JSON。`;
  }
}

export function parseMapArtifactEdit(
  fields: MapArtifactEditFields,
): MapArtifactEditParseResult {
  const title = fields.title.trim();
  if (!title) return { ok: false, message: "标题不能为空。" };
  if (new TextEncoder().encode(title).byteLength > MAX_MAP_TITLE_BYTES) {
    return { ok: false, message: "标题不能超过 256 个 UTF-8 字节。" };
  }

  const nodes = parseArray(fields.nodesJson, "节点 JSON");
  if (typeof nodes === "string") return { ok: false, message: nodes };
  const edges = parseArray(fields.edgesJson, "关系 JSON");
  if (typeof edges === "string") return { ok: false, message: edges };

  const spec = mapSpecFromJsonValue(
    {
      schemaVersion: 1,
      title,
      layoutHint: fields.layoutHint,
      nodes,
      edges,
    },
    true,
  );
  return spec
    ? { ok: true, spec }
    : {
        ok: false,
        message:
          "MapSpec 结构无效：仅允许闭合的节点/关系字段，且 ID、父子关系与关系端点必须一致。",
      };
}

/**
 * Saves an immutable-titled artifact with CAS. A title change is deliberately
 * stored as a new artifact because the backend does not allow renaming an
 * existing artifact record.
 */
export async function persistMapArtifactEdit(
  request: PersistMapArtifactEditRequest,
  save: SaveAssistantArtifact = saveAssistantArtifact,
): Promise<PersistMapArtifactEditResult> {
  const conversationId = request.artifact.conversationId;
  if (!conversationId) throw new Error("该成果不属于可编辑的助理会话。");
  const parsed = parseMapArtifactEdit(request.fields);
  if (!parsed.ok) throw new Error(parsed.message);

  const renamed = parsed.spec.title !== request.artifact.title;
  const response = await save({
    conversationId,
    ...(renamed
      ? {}
      : {
          artifactId: request.artifact.artifactId,
          expectedCurrentVersion: request.expectedCurrentVersion,
        }),
    title: parsed.spec.title,
    draft: { kind: "map", spec: parsed.spec },
  });
  return {
    detail: response.detail,
    mode: renamed ? "renamed_copy" : "new_version",
  };
}
