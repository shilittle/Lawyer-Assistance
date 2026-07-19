import cytoscape, { type Core } from "cytoscape";
import { useEffect, useId, useMemo, useRef, useState } from "react";

import type { MapEdge, MapNode, MapSpec } from "../../ipc/assistant/types";
import {
  publicTitle,
  sanitizePublicGeneratedText,
} from "../../publicOutput";
import { mapSpecToCytoscapeElements } from "./mapModel";

type MapSelection =
  | { kind: "node"; value: MapNode }
  | { kind: "edge"; value: MapEdge }
  | null;

export function AssistantMapTextAlternative({ spec }: { spec: MapSpec }) {
  const nodeHeadingId = useId();
  const edgeHeadingId = useId();
  const nodeLabels = new Map(
    spec.nodes.map((node) => [node.id, publicTitle(node.label, "相关内容")]),
  );

  return (
    <details className="assistant-map-text">
      <summary>
        分析图文字版（{spec.nodes.length} 个节点，{spec.edges.length} 条关系）
      </summary>
      <div className="assistant-map-text-grid">
        <section aria-labelledby={nodeHeadingId}>
          <h4 id={nodeHeadingId}>节点</h4>
          {spec.nodes.length === 0 ? (
            <p className="assistant-muted">没有节点。</p>
          ) : (
            <ul>
              {spec.nodes.map((node) => (
                <li key={node.id}>
                  <strong>{publicTitle(node.label, "相关内容")}</strong>
                  {node.summary
                    ? `：${sanitizePublicGeneratedText(node.summary, "内容摘要暂不可用。")}`
                    : ""}
                  {node.sourceRefs.length > 0
                    ? `（已关联 ${node.sourceRefs.length} 项来源）`
                    : "（无来源）"}
                </li>
              ))}
            </ul>
          )}
        </section>
        <section aria-labelledby={edgeHeadingId}>
          <h4 id={edgeHeadingId}>关系</h4>
          {spec.edges.length === 0 ? (
            <p className="assistant-muted">没有关系。</p>
          ) : (
            <ul>
              {spec.edges.map((edge) => (
                <li key={edge.id}>
                  {nodeLabels.get(edge.source) ?? "相关内容"} →{" "}
                  {publicTitle(edge.label, "关联")} →{" "}
                  {nodeLabels.get(edge.target) ?? "相关内容"}
                  {edge.sourceRefs.length > 0
                    ? `（已关联 ${edge.sourceRefs.length} 项来源）`
                    : "（无来源）"}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </details>
  );
}

export function AssistantMapPreview({ spec }: { spec: MapSpec }) {
  const host = useRef<HTMLDivElement>(null);
  const graph = useRef<Core | null>(null);
  const [selection, setSelection] = useState<MapSelection>(null);
  const mapped = useMemo(() => mapSpecToCytoscapeElements(spec), [spec]);
  const nodesById = useMemo(
    () => new Map(spec.nodes.map((node) => [node.id, node])),
    [spec.nodes],
  );
  const edgesById = useMemo(
    () => new Map(spec.edges.map((edge) => [edge.id, edge])),
    [spec.edges],
  );

  useEffect(() => {
    if (!host.current) return;
    const cy = cytoscape({
      container: host.current,
      elements: [...mapped.nodes, ...mapped.edges],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#2b6f62",
            color: "#17251f",
            label: "data(label)",
            "font-size": "11px",
            "text-wrap": "wrap",
            "text-max-width": "120px",
            "text-valign": "bottom",
            "text-margin-y": 7,
            width: 28,
            height: 28,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#96aaa3",
            "target-arrow-color": "#96aaa3",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "9px",
            color: "#52635b",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.92,
            "text-background-padding": "2px",
          },
        },
        {
          selector: ":selected",
          style: {
            "border-color": "#d97706",
            "border-width": 4,
            "line-color": "#d97706",
            "target-arrow-color": "#d97706",
          },
        },
      ],
      layout:
        mapped.layoutName === "concentric"
          ? { name: "concentric", animate: false, fit: true, padding: 24 }
          : {
              name: "breadthfirst",
              animate: false,
              directed: true,
              fit: true,
              padding: 24,
            },
    });
    graph.current = cy;
    cy.on("select", "node", (event) => {
      const rawId = String(event.target.data("rawId"));
      const node = nodesById.get(rawId);
      if (node) setSelection({ kind: "node", value: node });
    });
    cy.on("select", "edge", (event) => {
      const rawId = String(event.target.data("rawId"));
      const edge = edgesById.get(rawId);
      if (edge) setSelection({ kind: "edge", value: edge });
    });
    cy.on("unselect", () => {
      if (cy.$(":selected").length === 0) setSelection(null);
    });
    const observer =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver((entries) => {
            const bounds = entries[0]?.contentRect;
            if (!bounds || bounds.width <= 0 || bounds.height <= 0) return;
            cy.resize();
            cy.fit(cy.elements(), 24);
          });
    observer?.observe(host.current);
    return () => {
      observer?.disconnect();
      graph.current = null;
      cy.destroy();
    };
  }, [edgesById, mapped, nodesById]);

  return (
    <section className="assistant-map-preview" aria-label="助理分析图预览">
      <p className="assistant-map-disclaimer" role="note">
        这是助理生成的分析成果，不是案件工作台中的已确认关系图；写入案件仍需单独确认。
      </p>
      <div
        className="assistant-map-canvas"
        ref={host}
        role="img"
        aria-label={`${publicTitle(spec.title, "分析图")}，${spec.nodes.length} 个节点、${spec.edges.length} 条关系`}
      />
      {selection ? (
        <div className="assistant-map-selection" aria-live="polite">
          <strong>
            {publicTitle(selection.value.label, "相关内容")}
          </strong>
          <span>
            {selection.kind === "node"
              ? sanitizePublicGeneratedText(
                  selection.value.summary,
                  "内容摘要暂不可用。",
                )
              : sanitizePublicGeneratedText(
                  selection.value.label,
                  "关联说明暂不可用。",
                )}
          </span>
          <small>
            来源：
            {selection.value.sourceRefs.length > 0
              ? `已关联 ${selection.value.sourceRefs.length} 项`
              : "无"}
          </small>
        </div>
      ) : null}
      <AssistantMapTextAlternative spec={spec} />
    </section>
  );
}
