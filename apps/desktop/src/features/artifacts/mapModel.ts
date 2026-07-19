import type { ElementDefinition } from "cytoscape";

import type {
  AssistantArtifactVersion,
  JsonValue,
  MapEdge,
  MapLayoutHint,
  MapNode,
  MapSpec,
} from "../../ipc/assistant/types";
import { publicTitle } from "../../publicOutput";

export interface AssistantMapElements {
  nodes: ElementDefinition[];
  edges: ElementDefinition[];
  layoutName: "breadthfirst" | "concentric";
}

function record(value: JsonValue): Record<string, JsonValue> | null {
  return value !== null && !Array.isArray(value) && typeof value === "object"
    ? value
    : null;
}

function hasExactKeys(
  value: Record<string, JsonValue>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function stringArray(value: JsonValue | undefined): string[] | null {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return null;
  }
  return [...value] as string[];
}

function mapNode(value: JsonValue, strictKeys = false): MapNode | null {
  const item = record(value);
  if (
    !item ||
    (strictKeys &&
      !hasExactKeys(item, ["id", "label", "summary", "parentId", "sourceRefs"])) ||
    typeof item.id !== "string" ||
    typeof item.label !== "string" ||
    typeof item.summary !== "string" ||
    !(
      item.parentId === null ||
      item.parentId === undefined ||
      typeof item.parentId === "string"
    )
  ) {
    return null;
  }
  const sourceRefs = stringArray(item.sourceRefs);
  if (!sourceRefs) return null;
  return {
    id: item.id,
    label: item.label,
    summary: item.summary,
    parentId: typeof item.parentId === "string" ? item.parentId : null,
    sourceRefs,
  };
}

function mapEdge(value: JsonValue, strictKeys = false): MapEdge | null {
  const item = record(value);
  if (
    !item ||
    (strictKeys &&
      !hasExactKeys(item, [
        "id",
        "source",
        "target",
        "label",
        "relation",
        "sourceRefs",
      ])) ||
    typeof item.id !== "string" ||
    typeof item.source !== "string" ||
    typeof item.target !== "string" ||
    typeof item.label !== "string" ||
    typeof item.relation !== "string"
  ) {
    return null;
  }
  const sourceRefs = stringArray(item.sourceRefs);
  if (!sourceRefs) return null;
  return {
    id: item.id,
    source: item.source,
    target: item.target,
    label: item.label,
    relation: item.relation,
    sourceRefs,
  };
}

function layoutHint(value: JsonValue | undefined): MapLayoutHint | null {
  return value === "mindmap" || value === "layered" || value === "radial"
    ? value
    : null;
}

export function mapSpecFromArtifactVersion(
  version: AssistantArtifactVersion,
): MapSpec | null {
  const draft = record(version.content);
  if (!draft || draft.kind !== "map") return null;
  return mapSpecFromJsonValue(draft.spec);
}

/** Parses only the closed, non-executable MapSpec fields used by the editor and preview. */
export function mapSpecFromJsonValue(
  value: JsonValue,
  strictKeys = false,
): MapSpec | null {
  const spec = record(value);
  if (
    !spec ||
    (strictKeys &&
      !hasExactKeys(spec, [
        "schemaVersion",
        "title",
        "layoutHint",
        "nodes",
        "edges",
      ])) ||
    typeof spec.schemaVersion !== "number" ||
    typeof spec.title !== "string" ||
    !Array.isArray(spec.nodes) ||
    !Array.isArray(spec.edges)
  ) {
    return null;
  }
  const hint = layoutHint(spec.layoutHint);
  const nodes = spec.nodes.map((node) => mapNode(node, strictKeys));
  const edges = spec.edges.map((edge) => mapEdge(edge, strictKeys));
  if (
    spec.schemaVersion !== 1 ||
    !spec.title.trim() ||
    spec.nodes.length === 0 ||
    spec.nodes.length > 200 ||
    spec.edges.length > 400 ||
    !hint ||
    nodes.some((node) => node === null) ||
    edges.some((edge) => edge === null)
  ) {
    return null;
  }
  const parsedNodes = nodes as MapNode[];
  const parsedEdges = edges as MapEdge[];
  const allIds = new Set<string>();
  const nodeIds = new Set<string>();
  for (const node of parsedNodes) {
    if (!node.id || allIds.has(node.id)) return null;
    allIds.add(node.id);
    nodeIds.add(node.id);
  }
  for (const edge of parsedEdges) {
    if (
      !edge.id ||
      allIds.has(edge.id) ||
      !nodeIds.has(edge.source) ||
      !nodeIds.has(edge.target)
    ) {
      return null;
    }
    allIds.add(edge.id);
  }
  const parents = new Map(
    parsedNodes.map((node) => [node.id, node.parentId] as const),
  );
  for (const node of parsedNodes) {
    const path = new Set<string>([node.id]);
    let parentId = node.parentId;
    while (parentId) {
      if (!nodeIds.has(parentId) || path.has(parentId)) return null;
      path.add(parentId);
      parentId = parents.get(parentId) ?? null;
    }
  }
  return {
    schemaVersion: spec.schemaVersion,
    title: spec.title,
    layoutHint: hint,
    nodes: parsedNodes,
    edges: parsedEdges,
  };
}

/** Maps only the closed MapSpec data fields; style and executable data are ignored. */
export function mapSpecToCytoscapeElements(spec: MapSpec): AssistantMapElements {
  const nodeIds = new Set(spec.nodes.map((node) => node.id));
  const nodes: ElementDefinition[] = spec.nodes.map((node) => ({
    group: "nodes",
    data: {
      id: `assistant-map-node:${node.id}`,
      rawId: node.id,
      label: publicTitle(node.label, "相关内容"),
      ...(node.parentId && nodeIds.has(node.parentId) && node.parentId !== node.id
        ? { parent: `assistant-map-node:${node.parentId}` }
        : {}),
    },
  }));
  const edges: ElementDefinition[] = spec.edges
    .filter(
      (edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target),
    )
    .map((edge) => ({
      group: "edges",
      data: {
        id: `assistant-map-edge:${edge.id}`,
        rawId: edge.id,
        source: `assistant-map-node:${edge.source}`,
        target: `assistant-map-node:${edge.target}`,
        label: publicTitle(edge.label, "关联"),
      },
    }));
  return {
    nodes,
    edges,
    layoutName: spec.layoutHint === "radial" ? "concentric" : "breadthfirst",
  };
}
