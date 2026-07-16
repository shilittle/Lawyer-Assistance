import { describe, expect, it } from "vitest";

import {
  graphContainsSelection,
  graphEdgeHasProvenance,
  graphNodeMatchesSearch,
  graphModeWithAvailableSource,
  resolveGraphSelection,
  visibleGraph,
  type GraphData,
} from "./types";

function graphFixture(): GraphData {
  return {
    nodes: [
      { id: "fact-1", label: "交付", category: "fact", sourceKind: "case_fact", sourceId: "fact-1" },
      { id: "fact-2", label: "催告", category: "fact", sourceKind: "case_fact", sourceId: "fact-2" },
      { id: "evidence-1", label: "合同", category: "evidence", sourceKind: "evidence_item", sourceId: "evidence-1" },
    ],
    edges: [
      {
        id: "link-1",
        from: "fact-1",
        to: "evidence-1",
        category: "fact_evidence",
        label: "证据支持",
        provenance: { sourceKind: "case_evidence_link", sourceId: "link-1", description: "证据支持" },
      },
      {
        id: "link-2",
        from: "fact-2",
        to: "fact-1",
        category: "fact_sequence",
        label: "发生在前",
        provenance: { sourceKind: "case_project", sourceId: "project-1", description: "发生在前" },
      },
      {
        id: "untrusted",
        from: "fact-1",
        to: "fact-2",
        category: "invented",
        label: "无来源",
        provenance: { sourceKind: "", sourceId: "", description: "" },
      },
    ],
  };
}

describe("graph filtering and selection", () => {
  it("handles a large graph without mutating the source", () => {
    const graph: GraphData = {
      nodes: Array.from({ length: 500 }, (_, index) => ({
        id: `n${index}`,
        label: `N${index}`,
        category: index % 2 ? "fact" : "evidence",
        sourceKind: "case",
        sourceId: `n${index}`,
      })),
      edges: [
        {
          id: "edge",
          from: "n1",
          to: "n3",
          category: "link",
          label: "支持",
          provenance: { sourceKind: "link", sourceId: "edge", description: "支持" },
        },
      ],
    };

    const result = visibleGraph(graph, new Set(["fact"]));
    expect(result.nodes).toHaveLength(250);
    expect(result.edges.map((edge) => edge.id)).toEqual(["edge"]);
    expect(graph.nodes).toHaveLength(500);
  });

  it("searches a large graph by label, source id, or category without mutating it", () => {
    const graph: GraphData = {
      nodes: Array.from({ length: 2_000 }, (_, index) => ({
        id: `node-${index}`,
        label: index === 1_337 ? "Special Contract" : `Node ${index}`,
        category: index % 2 ? "FACT" : "evidence",
        sourceKind: "case",
        sourceId: `SOURCE-${index}`,
      })),
      edges: [
        {
          id: "visible-edge",
          from: "node-1337",
          to: "node-1339",
          category: "link",
          label: "related",
          provenance: { sourceKind: "case", sourceId: "edge", description: "stored" },
        },
      ],
    };

    expect(visibleGraph(graph, new Set(), new Set(), "  special CONTRACT ").nodes).toHaveLength(1);
    expect(visibleGraph(graph, new Set(), new Set(), "source-1337").nodes[0]?.id).toBe(
      "node-1337",
    );
    expect(visibleGraph(graph, new Set(), new Set(), "fact").nodes).toHaveLength(1_000);
    expect(graph.nodes).toHaveLength(2_000);
  });

  it("keeps only edges whose two endpoints survive the search", () => {
    const graph = graphFixture();
    const oneEndpoint = visibleGraph(graph, new Set(), new Set(), "交付");
    expect(oneEndpoint.nodes.map((node) => node.id)).toEqual(["fact-1"]);
    expect(oneEndpoint.edges).toEqual([]);
  });

  it("matches node search case-insensitively after trimming", () => {
    const node = graphFixture().nodes[0];
    expect(graphNodeMatchesSearch(node, "  FACT-1 ")).toBe(true);
    expect(graphNodeMatchesSearch(node, " FaCt ")).toBe(true);
    expect(graphNodeMatchesSearch(node, "missing")).toBe(false);
    expect(graphNodeMatchesSearch(node, "   ")).toBe(true);
  });

  it("filters node and edge categories independently", () => {
    const graph = graphFixture();
    const result = visibleGraph(
      graph,
      new Set(["fact", "evidence"]),
      new Set(["fact_evidence"]),
    );
    expect(result.nodes).toHaveLength(3);
    expect(result.edges.map((edge) => edge.id)).toEqual(["link-1"]);
  });

  it("never exposes an edge whose provenance is incomplete", () => {
    const graph = graphFixture();
    expect(graphEdgeHasProvenance(graph.edges[0])).toBe(true);
    expect(graphEdgeHasProvenance(graph.edges[2])).toBe(false);
    expect(visibleGraph(graph, new Set()).edges.map((edge) => edge.id)).toEqual([
      "link-1",
      "link-2",
    ]);
  });

  it("resolves node and edge detail from typed graph data", () => {
    const graph = graphFixture();
    expect(resolveGraphSelection(graph, "node", "fact-1")).toMatchObject({
      kind: "node",
      node: { sourceKind: "case_fact", sourceId: "fact-1" },
    });
    expect(resolveGraphSelection(graph, "edge", "link-1")).toMatchObject({
      kind: "edge",
      edge: { provenance: { sourceKind: "case_evidence_link", sourceId: "link-1" } },
    });
    expect(resolveGraphSelection(graph, "edge", "missing")).toBeNull();

    const nodeSelection = resolveGraphSelection(graph, "node", "fact-1");
    expect(graphContainsSelection(graph, nodeSelection)).toBe(true);
    expect(
      graphContainsSelection(visibleGraph(graph, new Set(), new Set(), "合同"), nodeSelection),
    ).toBe(false);
  });

  it("falls back only to a source that is actually available", () => {
    expect(graphModeWithAvailableSource("law", "case-1", null)).toBe("case");
    expect(graphModeWithAvailableSource("case", null, "law-1")).toBe("law");
    expect(graphModeWithAvailableSource("law", "case-1", "law-1")).toBe("law");
  });

  it("supports an empty graph", () => {
    expect(visibleGraph({ nodes: [], edges: [] }, new Set(), new Set(), "anything")).toEqual({
      nodes: [],
      edges: [],
    });
    expect(graphContainsSelection({ nodes: [], edges: [] }, null)).toBe(false);
  });
});
