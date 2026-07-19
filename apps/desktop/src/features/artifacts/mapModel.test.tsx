import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type {
  AssistantArtifactVersion,
  MapSpec,
} from "../../ipc/assistant/types";
import { AssistantMapTextAlternative } from "./AssistantMapPreview";
import {
  mapSpecFromArtifactVersion,
  mapSpecToCytoscapeElements,
} from "./mapModel";

const MAP_SPEC: MapSpec = {
  schemaVersion: 1,
  title: "合同履行分析",
  layoutHint: "layered",
  nodes: [
    {
      id: "fact-1",
      label: "交付",
      summary: "卖方完成交付",
      parentId: null,
      sourceRefs: ["attachment-1"],
    },
    {
      id: "issue-1",
      label: "付款义务",
      summary: "买方是否逾期",
      parentId: null,
      sourceRefs: ["source-1"],
    },
  ],
  edges: [
    {
      id: "edge-1",
      source: "fact-1",
      target: "issue-1",
      label: "支持判断",
      relation: "analysis_support",
      sourceRefs: ["attachment-1"],
    },
  ],
};

function version(content: AssistantArtifactVersion["content"]): AssistantArtifactVersion {
  return {
    versionId: "version-1",
    artifactId: "artifact-1",
    versionNumber: 1,
    content,
    renderedText: "",
    sourceRefs: [],
    citationReport: null,
    providerSnapshot: null,
    createdAt: "2026-07-17T00:00:00Z",
  };
}

describe("assistant MapSpec mapping", () => {
  it("maps only fixed node, edge and layout fields", () => {
    const parsed = mapSpecFromArtifactVersion(
      version({
        kind: "map",
        spec: {
          ...MAP_SPEC,
          style: "background-image: url(secret)",
          html: "<script>run()</script>",
          javascript: "run()",
          nodes: [
            {
              ...MAP_SPEC.nodes[0],
              style: { backgroundImage: "url(secret)" },
              html: "<img src=x onerror=run()>",
            },
            MAP_SPEC.nodes[1],
          ],
        },
      } as unknown as AssistantArtifactVersion["content"]),
    );
    expect(parsed).not.toBeNull();

    const mapped = mapSpecToCytoscapeElements(parsed!);
    expect(mapped.layoutName).toBe("breadthfirst");
    expect(mapped.nodes).toHaveLength(2);
    expect(mapped.edges).toHaveLength(1);
    expect(mapped.nodes[0].data).toEqual({
      id: "assistant-map-node:fact-1",
      rawId: "fact-1",
      label: "交付",
    });
    expect(JSON.stringify(mapped)).not.toContain("background-image");
    expect(JSON.stringify(mapped)).not.toContain("<script>");
    expect(JSON.stringify(mapped)).not.toContain("javascript");
  });

  it("drops edges whose endpoints are outside the closed node set", () => {
    const mapped = mapSpecToCytoscapeElements({
      ...MAP_SPEC,
      layoutHint: "radial",
      edges: [
        ...MAP_SPEC.edges,
        { ...MAP_SPEC.edges[0], id: "outside", target: "missing" },
      ],
    });
    expect(mapped.layoutName).toBe("concentric");
    expect(mapped.edges).toHaveLength(1);
  });

  it.each([
    { ...MAP_SPEC, schemaVersion: 2 },
    { ...MAP_SPEC, nodes: [...MAP_SPEC.nodes, MAP_SPEC.nodes[0]] },
    {
      ...MAP_SPEC,
      edges: [{ ...MAP_SPEC.edges[0], target: "missing" }],
    },
    {
      ...MAP_SPEC,
      nodes: [
        { ...MAP_SPEC.nodes[0], parentId: "issue-1" },
        { ...MAP_SPEC.nodes[1], parentId: "fact-1" },
      ],
    },
  ])("fails closed for an invalid persisted MapSpec", (invalidSpec) => {
    expect(
      mapSpecFromArtifactVersion(
        version(
          { kind: "map", spec: invalidSpec } as unknown as AssistantArtifactVersion["content"],
        ),
      ),
    ).toBeNull();
  });

  it("always supplies a keyboard-readable text alternative", () => {
    const markup = renderToStaticMarkup(
      <AssistantMapTextAlternative spec={MAP_SPEC} />,
    );
    expect(markup).toContain("分析图文字版");
    expect(markup).toContain("交付");
    expect(markup).toContain("付款义务");
    expect(markup).toContain("支持判断");
    expect(markup).toContain("已关联 1 项来源");
    expect(markup).not.toContain("attachment-1");
    expect(markup).not.toContain("analysis_support");
  });
});
