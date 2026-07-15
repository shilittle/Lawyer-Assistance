export interface GraphNode {
  id: string;
  label: string;
  category: string;
  sourceKind: string;
  sourceId: string;
}

export interface GraphProvenance {
  sourceKind: string;
  sourceId: string;
  description: string;
  sourceReference?: string | null;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  category: string;
  label: string;
  provenance: GraphProvenance;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type GraphMode = "case" | "law";

export type GraphSelection =
  | { kind: "node"; node: GraphNode }
  | { kind: "edge"; edge: GraphEdge };

export function graphEdgeHasProvenance(edge: GraphEdge): boolean {
  return (
    edge.provenance.sourceKind.trim().length > 0 &&
    edge.provenance.sourceId.trim().length > 0 &&
    edge.provenance.description.trim().length > 0
  );
}

export function visibleGraph(
  graph: GraphData,
  nodeCategories: ReadonlySet<string>,
  edgeCategories: ReadonlySet<string> = new Set(),
  searchQuery = "",
): GraphData {
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const nodes = graph.nodes.filter(
    (node) =>
      (nodeCategories.size === 0 || nodeCategories.has(node.category)) &&
      graphNodeMatchesSearch(node, normalizedSearch),
  );
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter(
    (edge) =>
      nodeIds.has(edge.from) &&
      nodeIds.has(edge.to) &&
      (edgeCategories.size === 0 || edgeCategories.has(edge.category)) &&
      graphEdgeHasProvenance(edge),
  );
  return { nodes, edges };
}

export function graphNodeMatchesSearch(node: GraphNode, searchQuery: string): boolean {
  const normalizedSearch = searchQuery.trim().toLowerCase();
  if (!normalizedSearch) return true;

  return [node.label, node.sourceId, node.category].some((value) =>
    value.toLowerCase().includes(normalizedSearch),
  );
}

export function graphContainsSelection(
  graph: GraphData,
  selection: GraphSelection | null,
): boolean {
  if (!selection) return false;
  return selection.kind === "node"
    ? graph.nodes.some((node) => node.id === selection.node.id)
    : graph.edges.some((edge) => edge.id === selection.edge.id);
}

export function resolveGraphSelection(
  graph: GraphData,
  kind: GraphSelection["kind"],
  id: string,
): GraphSelection | null {
  if (kind === "node") {
    const node = graph.nodes.find((item) => item.id === id);
    return node ? { kind: "node", node } : null;
  }

  const edge = graph.edges.find((item) => item.id === id);
  return edge ? { kind: "edge", edge } : null;
}

export function graphModeWithAvailableSource(
  requested: GraphMode,
  projectId: string | null,
  documentId: string | null,
): GraphMode {
  if (requested === "case" && projectId) return "case";
  if (requested === "law" && documentId) return "law";
  if (projectId) return "case";
  return "law";
}
