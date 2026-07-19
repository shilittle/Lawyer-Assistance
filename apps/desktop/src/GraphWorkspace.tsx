import cytoscape, { type Core } from "cytoscape";
import { useEffect, useId, useMemo, useRef, useState } from "react";

import { syncGraphVisualSelection } from "./graphVisualSelection";
import { getCaseGraph, getLawGraph } from "./ipc/graph/client";
import {
  graphContainsSelection,
  graphModeWithAvailableSource,
  resolveGraphSelection,
  visibleGraph,
  type GraphData,
  type GraphMode,
  type GraphNode,
  type GraphSelection,
} from "./ipc/graph/types";
import {
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "./publicOutput";

const EMPTY_GRAPH: GraphData = { nodes: [], edges: [] };
type GraphLayout = "cose" | "breadthfirst" | "circle" | "grid";

interface GraphWorkspaceProps {
  projectId: string | null;
  documentId: string | null;
  mode: GraphMode;
  onModeChange: (mode: GraphMode) => void;
  onOpenNode: (node: GraphNode) => void;
}

function errorMessage(error: unknown): string {
  return publicErrorMessage(error, "关系图读取失败，请重试。 ");
}

function graphTypeLabel(value: string): string {
  const labels: Readonly<Record<string, string>> = {
    case: "案件",
    project: "案件",
    party: "当事人",
    case_file: "案件材料",
    file: "案件材料",
    fact: "案件事实",
    evidence: "证据",
    legal_issue: "法律争点",
    legal_basis: "法律依据",
    legal_citation: "法律条文",
    uncertainty: "待核事项",
    document: "法律文件",
    article: "法律条文",
    proves: "证明",
    relates_to: "关联",
    supports: "支持",
    cites: "引用",
  };
  return labels[value] ?? "相关内容";
}

function graphNodeLabel(value: string | null | undefined): string {
  const publicValue = sanitizePublicGeneratedText(value ?? "", "").trim();
  return publicTitle(publicValue, "相关记录");
}

interface GraphTextAlternativeProps {
  graph: GraphData;
  selection: GraphSelection | null;
  onSelect: (selection: GraphSelection) => void;
}

export function GraphTextAlternative({
  graph,
  selection,
  onSelect,
}: GraphTextAlternativeProps) {
  const nodeLabels = new Map(
    graph.nodes.map((node) => [node.id, graphNodeLabel(node.label)]),
  );
  const nodeTitleId = useId();
  const edgeTitleId = useId();

  return (
    <details className="graph-text-alternative">
      <summary>
        关系图文字列表（{graph.nodes.length} 个节点，{graph.edges.length} 条关系）
      </summary>
      <div className="graph-text-grid">
        <section aria-labelledby={nodeTitleId}>
          <h3 id={nodeTitleId}>节点</h3>
          {graph.nodes.length > 0 ? (
            <ul>
              {graph.nodes.map((node) => (
                <li key={node.id}>
                  <button
                    aria-pressed={
                      selection?.kind === "node" && selection.node.id === node.id
                    }
                    type="button"
                    onClick={() => onSelect({ kind: "node", node })}
                  >
                    {graphNodeLabel(node.label)}（{graphTypeLabel(node.category)}）
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">当前没有可显示的节点。</p>
          )}
        </section>
        <section aria-labelledby={edgeTitleId}>
          <h3 id={edgeTitleId}>关系</h3>
          {graph.edges.length > 0 ? (
            <ul>
              {graph.edges.map((edge) => (
                <li key={edge.id}>
                  <button
                    aria-pressed={
                      selection?.kind === "edge" && selection.edge.id === edge.id
                    }
                    type="button"
                    onClick={() => onSelect({ kind: "edge", edge })}
                  >
                    {nodeLabels.get(edge.from) ?? "相关记录"} →{" "}
                    {publicTitle(edge.label, "关联")} →{" "}
                    {nodeLabels.get(edge.to) ?? "相关记录"}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">当前没有可显示的关系。</p>
          )}
        </section>
      </div>
    </details>
  );
}

export function GraphWorkspace({
  projectId,
  documentId,
  mode,
  onModeChange,
  onOpenNode,
}: GraphWorkspaceProps) {
  const host = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [result, setResult] = useState<{
    sourceKey: string;
    graph: GraphData;
    status: string;
  }>({ sourceKey: "", graph: EMPTY_GRAPH, status: "" });
  const [selection, setSelection] = useState<{
    sourceKey: string;
    value: GraphSelection | null;
  }>({ sourceKey: "", value: null });
  const [nodeCategories, setNodeCategories] = useState<Set<string>>(new Set());
  const [edgeCategories, setEdgeCategories] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [layout, setLayout] = useState<GraphLayout>("cose");

  const activeMode = graphModeWithAvailableSource(mode, projectId, documentId);
  const sourceId = activeMode === "case" ? projectId : documentId;
  const sourceKey = sourceId ? `${activeMode}:${sourceId}` : "";
  const graph = result.sourceKey === sourceKey ? result.graph : EMPTY_GRAPH;
  const selected = selection.sourceKey === sourceKey ? selection.value : null;
  const status = !sourceId
    ? activeMode === "case"
      ? "请先选择案件。"
      : "请先选择法律或有效引用。"
    : result.sourceKey === sourceKey
      ? result.status
      : activeMode === "case"
        ? "正在读取案件关系…"
        : "正在读取法律关系…";

  useEffect(() => {
    if (!sourceId) return;

    let cancelled = false;
    const request = activeMode === "case" ? getCaseGraph(sourceId) : getLawGraph(sourceId);
    void request
      .then((response) => {
        if (cancelled) return;
        setResult({
          sourceKey,
          graph: response,
          status:
            response.nodes.length === 0
              ? "当前数据源没有可显示的已存关系。"
              : `已载入 ${response.nodes.length} 个节点、${response.edges.length} 条可追溯关系。`,
        });
        setSelection({ sourceKey, value: null });
        setNodeCategories(new Set());
        setEdgeCategories(new Set());
        setSearchQuery("");
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setResult({
          sourceKey,
          graph: EMPTY_GRAPH,
          status: errorMessage(error),
        });
        setSelection({ sourceKey, value: null });
      });
    return () => {
      cancelled = true;
    };
  }, [activeMode, sourceId, sourceKey]);

  const allNodeCategories = useMemo(
    () => [...new Set(graph.nodes.map((node) => node.category))].sort(),
    [graph],
  );
  const allEdgeCategories = useMemo(
    () => [...new Set(graph.edges.map((edge) => edge.category))].sort(),
    [graph],
  );
  const shown = useMemo(
    () => visibleGraph(graph, nodeCategories, edgeCategories, searchQuery),
    [edgeCategories, graph, nodeCategories, searchQuery],
  );
  const visibleSelection = graphContainsSelection(shown, selected)
    ? selected
    : null;

  useEffect(() => {
    if (!host.current) return;
    const cy = cytoscape({
      container: host.current,
      elements: [
        ...shown.nodes.map((node) => ({
          data: {
            id: `node:${node.id}`,
            rawId: node.id,
            label: graphNodeLabel(node.label),
            category: node.category,
          },
        })),
        ...shown.edges.map((edge) => ({
          data: {
            id: `edge:${edge.id}`,
            rawId: edge.id,
            source: `node:${edge.from}`,
            target: `node:${edge.to}`,
            label: publicTitle(edge.label, "关联"),
            category: edge.category,
          },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": "#275d55",
            color: "#153d37",
            "font-size": "11px",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.88,
            "text-background-padding": "3px",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-wrap": "wrap",
            "text-max-width": "120px",
          },
        },
        { selector: 'node[category = "evidence"]', style: { "background-color": "#966b26" } },
        { selector: 'node[category = "legal_issue"]', style: { "background-color": "#7b4b78" } },
        { selector: 'node[category = "legal_citation"]', style: { "background-color": "#315f91" } },
        {
          selector: "edge",
          style: {
            label: "data(label)",
            width: 1.5,
            "line-color": "#9aa9a4",
            "target-arrow-color": "#9aa9a4",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "font-size": "9px",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.8,
          },
        },
        { selector: ":selected", style: { "border-width": 4, "border-color": "#cf7d2c", "line-color": "#cf7d2c", "target-arrow-color": "#cf7d2c" } },
      ],
      layout: { name: layout, animate: false, fit: true, padding: 35 },
    });
    cyRef.current = cy;
    cy.on("tap", "node", (event) => {
      setSelection({
        sourceKey,
        value: resolveGraphSelection(shown, "node", String(event.target.data("rawId"))),
      });
    });
    cy.on("tap", "edge", (event) => {
      setSelection({
        sourceKey,
        value: resolveGraphSelection(shown, "edge", String(event.target.data("rawId"))),
      });
    });
    cy.on("tap", (event) => {
      if (event.target === cy) setSelection({ sourceKey, value: null });
    });
    return () => {
      cyRef.current = null;
      cy.destroy();
    };
  }, [layout, shown, sourceKey]);

  useEffect(() => {
    // Keep keyboard/text-list selection and the visual graph highlight in
    // sync, including immediately after a layout or filter recreates Cytoscape.
    syncGraphVisualSelection(cyRef.current, visibleSelection);
  });

  function toggleCategory(
    category: string,
    update: React.Dispatch<React.SetStateAction<Set<string>>>,
  ) {
    update((current) => {
      const next = new Set(current);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  }

  function zoom(factor: number) {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom(Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor)));
    cy.center();
  }

  const selectedEdgeLabels =
    visibleSelection?.kind === "edge"
      ? {
          from:
            graph.nodes.find((node) => node.id === visibleSelection.edge.from)
              ?.label ?? "相关记录",
          to:
            graph.nodes.find((node) => node.id === visibleSelection.edge.to)
              ?.label ?? "相关记录",
        }
      : null;

  return (
    <section className="workspace-card graph-workspace">
      <div className="section-heading">
        <div>
          <h2>{activeMode === "case" ? "案件关系图" : "法律关系图"}</h2>
          <p className="muted">只展示数据库和案件中已存在且带来源记录的关系。</p>
        </div>
        <div className="graph-source-tabs" role="group" aria-label="关系图数据源">
          <button
            aria-pressed={activeMode === "case"}
            className={activeMode === "case" ? "is-active" : ""}
            disabled={!projectId}
            type="button"
            onClick={() => onModeChange("case")}
          >
            当前案件
          </button>
          <button
            aria-pressed={activeMode === "law"}
            className={activeMode === "law" ? "is-active" : ""}
            disabled={!documentId}
            type="button"
            onClick={() => onModeChange("law")}
          >
            当前法律
          </button>
        </div>
      </div>

      <div className="graph-toolbar" aria-label="关系图视图控制">
        <label>
          <span>搜索节点</span>
          <input
            type="search"
            value={searchQuery}
            placeholder="名称或类型"
            onChange={(event) => setSearchQuery(event.target.value)}
          />
        </label>
        <button
          type="button"
          disabled={!searchQuery}
          onClick={() => setSearchQuery("")}
        >
          清除搜索
        </button>
        <label>
          <span>布局</span>
          <select value={layout} onChange={(event) => setLayout(event.target.value as GraphLayout)}>
            <option value="cose">自动关系布局</option>
            <option value="breadthfirst">层级布局</option>
            <option value="circle">环形布局</option>
            <option value="grid">网格布局</option>
          </select>
        </label>
        <button type="button" onClick={() => zoom(1.2)} aria-label="放大关系图">放大</button>
        <button type="button" onClick={() => zoom(1 / 1.2)} aria-label="缩小关系图">缩小</button>
        <button type="button" onClick={() => cyRef.current?.fit(undefined, 35)}>适应画布</button>
      </div>

      <details className="graph-filter-panel">
        <summary>类型过滤（未勾选时显示全部）</summary>
        <div className="graph-filters">
          <fieldset>
            <legend>节点类型</legend>
            {allNodeCategories.map((category) => (
              <label key={category}>
                <input
                  type="checkbox"
                  checked={nodeCategories.has(category)}
                  onChange={() => toggleCategory(category, setNodeCategories)}
                />
                {category}
              </label>
            ))}
          </fieldset>
          <fieldset>
            <legend>关系类型</legend>
            {allEdgeCategories.map((category) => (
              <label key={category}>
                <input
                  type="checkbox"
                  checked={edgeCategories.has(category)}
                  onChange={() => toggleCategory(category, setEdgeCategories)}
                />
                {category}
              </label>
            ))}
          </fieldset>
          <button type="button" onClick={() => { setNodeCategories(new Set()); setEdgeCategories(new Set()); }}>
            清除过滤
          </button>
        </div>
      </details>

      <GraphTextAlternative
        graph={shown}
        selection={visibleSelection}
        onSelect={(value) => setSelection({ sourceKey, value })}
      />

      <div className="graph-layout">
        <div>
          <div ref={host} className="graph-canvas" aria-hidden="true" />
          {graph.nodes.length > 0 && shown.nodes.length === 0 && (
            <p className="muted" role="status">
              没有匹配当前搜索和类型过滤条件的节点。
            </p>
          )}
        </div>
        <aside className="graph-detail" aria-live="polite">
          <h3>{visibleSelection?.kind === "edge" ? "关系来源" : "节点详情"}</h3>
          {visibleSelection?.kind === "node" ? (
            <>
              <strong>{graphNodeLabel(visibleSelection.node.label)}</strong>
              <dl>
                <dt>内容类型</dt><dd>{graphTypeLabel(visibleSelection.node.category)}</dd>
                <dt>资料范围</dt><dd>{graphTypeLabel(visibleSelection.node.sourceKind)}</dd>
              </dl>
              <button type="button" onClick={() => onOpenNode(visibleSelection.node)}>
                打开原始本地记录
              </button>
            </>
          ) : visibleSelection?.kind === "edge" && selectedEdgeLabels ? (
            <>
              <strong>{publicTitle(visibleSelection.edge.label, "关联关系")}</strong>
              <p>{selectedEdgeLabels.from} → {selectedEdgeLabels.to}</p>
              <dl>
                <dt>关系类型</dt><dd>{graphTypeLabel(visibleSelection.edge.category)}</dd>
                <dt>资料范围</dt><dd>{graphTypeLabel(visibleSelection.edge.provenance.sourceKind)}</dd>
                <dt>来源说明</dt>
                <dd>
                  {sanitizePublicGeneratedText(
                    visibleSelection.edge.provenance.description,
                    "来源说明暂不可用。",
                  )}
                </dd>
                {visibleSelection.edge.provenance.sourceReference ? (
                  <><dt>来源核验</dt><dd>官方来源记录已保留</dd></>
                ) : null}
              </dl>
            </>
          ) : (
            <p>点击节点可查看并返回原始记录；点击连线可核验关系来源。</p>
          )}
        </aside>
      </div>
      <p role="status">{status}</p>
    </section>
  );
}
