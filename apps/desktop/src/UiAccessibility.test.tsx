import cytoscape from "cytoscape";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { DocumentWorkspace } from "./DocumentWorkspace";
import {
  GraphTextAlternative,
  GraphWorkspace,
} from "./GraphWorkspace";
import { syncGraphVisualSelection } from "./graphVisualSelection";
import { ReleaseWorkspace } from "./ReleaseWorkspace";
import type { GraphData } from "./ipc/graph/types";

const GRAPH: GraphData = {
  nodes: [
    {
      id: "fact-1",
      label: "合同已经签订",
      category: "fact",
      sourceKind: "case_fact",
      sourceId: "fact-1",
    },
    {
      id: "evidence-1",
      label: "书面合同",
      category: "evidence",
      sourceKind: "evidence_item",
      sourceId: "evidence-1",
    },
  ],
  edges: [
    {
      id: "link-1",
      from: "fact-1",
      to: "evidence-1",
      category: "fact_evidence",
      label: "由证据支持",
      provenance: {
        sourceKind: "case_evidence_link",
        sourceId: "link-1",
        description: "用户建立的事实—证据关联",
      },
    },
  ],
};

describe("workspace accessibility and Chinese rendering", () => {
  it("marks exactly one main navigation destination as the current page", () => {
    const markup = renderToStaticMarkup(<App />);
    const mainNavigation = markup.match(
      /<nav class="view-tabs"[\s\S]*?<\/nav>/,
    )?.[0];

    expect(mainNavigation).toBeDefined();
    expect(mainNavigation?.match(/aria-current="page"/g)).toHaveLength(1);
    expect(mainNavigation).toMatch(
      /<button aria-current="page"[^>]*>助理<\/button>/,
    );
    for (const label of [
      "助理",
      "案件工作台",
      "法律库",
      "设置",
    ]) {
      expect(mainNavigation).toContain(label);
    }
    expect(mainNavigation).not.toContain("引用问答");
    expect(mainNavigation).not.toContain("文书生成");
  });

  it("provides a keyboard-operable text alternative for graph nodes and edges", () => {
    const markup = renderToStaticMarkup(
      <GraphTextAlternative
        graph={GRAPH}
        selection={{ kind: "node", node: GRAPH.nodes[0] }}
        onSelect={vi.fn()}
      />,
    );

    expect(markup).toContain("关系图文字列表（2 个节点，1 条关系）");
    expect(markup).toContain("合同已经签订（案件事实）");
    expect(markup).toContain("合同已经签订 → 由证据支持 → 书面合同");
    expect(markup).toContain('aria-pressed="true"');
  });

  it("removes legacy service identifiers from graph labels", () => {
    const graph: GraphData = {
      nodes: [
        {
          ...GRAPH.nodes[1],
          label: "service-aabbccddeeff0011-3 书面合同",
        },
      ],
      edges: [],
    };
    const markup = renderToStaticMarkup(
      <GraphTextAlternative graph={graph} selection={null} onSelect={vi.fn()} />,
    );

    expect(markup).toContain("书面合同（证据）");
    expect(markup).not.toContain("service-aabbccddeeff0011-3");
  });

  it("uses normal pressed buttons for graph source switching and hides the canvas duplicate", () => {
    const markup = renderToStaticMarkup(
      <GraphWorkspace
        projectId="case-1"
        documentId="law-1"
        mode="case"
        onModeChange={vi.fn()}
        onOpenNode={vi.fn()}
      />,
    );

    expect(markup).toContain('role="group"');
    expect(markup).toContain('aria-label="关系图数据源"');
    expect(markup).toContain('aria-pressed="true"');
    expect(markup).toContain('class="graph-canvas" aria-hidden="true"');
    expect(markup).not.toContain('role="tab"');
  });

  it("keeps keyboard selection synchronized with the visual graph highlight", () => {
    const cy = cytoscape({
      headless: true,
      elements: [
        { data: { id: "node:fact-1" } },
        { data: { id: "node:evidence-1" } },
        {
          data: {
            id: "edge:link-1",
            source: "node:fact-1",
            target: "node:evidence-1",
          },
        },
      ],
    });

    syncGraphVisualSelection(cy, { kind: "node", node: GRAPH.nodes[0] });
    expect(cy.getElementById("node:fact-1").selected()).toBe(true);
    expect(cy.getElementById("edge:link-1").selected()).toBe(false);

    syncGraphVisualSelection(cy, { kind: "edge", edge: GRAPH.edges[0] });
    expect(cy.getElementById("node:fact-1").selected()).toBe(false);
    expect(cy.getElementById("edge:link-1").selected()).toBe(true);

    syncGraphVisualSelection(cy, null);
    expect(cy.$(":selected")).toHaveLength(0);
    cy.destroy();
  });

  it("keeps Chinese workspace copy valid UTF-8 without replacement or question runs", () => {
    const markup = [
      renderToStaticMarkup(
        <DocumentWorkspace projectId={null} onOpenCitation={vi.fn()} />,
      ),
      renderToStaticMarkup(<ReleaseWorkspace />),
      renderToStaticMarkup(
        <GraphTextAlternative graph={GRAPH} selection={null} onSelect={vi.fn()} />,
      ),
    ].join("\n");

    expect(markup).toContain("文书生成");
    expect(markup).toContain("版本与数据维护");
    expect(markup).toContain("关系图文字列表");
    expect(markup).toContain('class="workspace-card document-workspace"');
    expect(markup).toContain('class="workspace-card release-workspace"');
    expect(markup).not.toContain("\uFFFD");
    expect(markup).not.toMatch(/\?{3,}/);
  });

  it("keeps document settings and preview in separate compact workspace panels", () => {
    const markup = renderToStaticMarkup(
      <DocumentWorkspace projectId={null} onOpenCitation={vi.fn()} />,
    );

    expect(markup).toContain('class="document-layout"');
    expect(markup).toContain('aria-labelledby="document-controls-title"');
    expect(markup).toContain('aria-labelledby="document-output-title"');
    expect(markup).toContain("生成设置");
    expect(markup).toContain("校验与预览");
    expect(markup).toContain("尚未生成预览");
    expect(markup).toContain("直接填写要求，无需创建案件");
    expect(markup).toContain("系统“另存为”对话框");
    expect(markup).toContain("导出 PDF");
    expect(markup).not.toContain("DOCX");
    expect(markup).toContain('aria-pressed="true"');
    expect(markup).not.toContain("请先到案件工作台选择需要生成文书的案件");
  });
});
