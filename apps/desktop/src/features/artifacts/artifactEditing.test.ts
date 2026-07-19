import { describe, expect, it, vi } from "vitest";

import type {
  AssistantArtifact,
  GetAssistantArtifactResponse,
} from "../../ipc/assistant/types";
import {
  parseMapArtifactEdit,
  persistMapArtifactEdit,
  type MapArtifactEditFields,
} from "./artifactEditing";

const ARTIFACT: AssistantArtifact = {
  artifactId: "artifact-1",
  conversationId: "conversation-1",
  projectId: null,
  kind: "map",
  title: "案件关系图",
  status: "draft",
  currentVersion: 2,
  createdAt: "2026-07-17T00:00:00Z",
  updatedAt: "2026-07-17T00:00:00Z",
};

const FIELDS: MapArtifactEditFields = {
  title: ARTIFACT.title,
  layoutHint: "layered",
  nodesJson: JSON.stringify([
    {
      id: "node-1",
      label: "交付",
      summary: "交付事实",
      parentId: null,
      sourceRefs: ["attachment-1"],
    },
    {
      id: "node-2",
      label: "付款",
      summary: "付款义务",
      parentId: "node-1",
      sourceRefs: [],
    },
  ]),
  edgesJson: JSON.stringify([
    {
      id: "edge-1",
      source: "node-1",
      target: "node-2",
      label: "对应",
      relation: "supports",
      sourceRefs: ["attachment-1"],
    },
  ]),
};

function detail(artifact: AssistantArtifact): GetAssistantArtifactResponse {
  return { artifact, versions: [] };
}

describe("map artifact structured editing", () => {
  it("parses the closed MapSpec fields and rejects executable extension fields", () => {
    const parsed = parseMapArtifactEdit(FIELDS);
    expect(parsed).toEqual({
      ok: true,
      spec: {
        schemaVersion: 1,
        title: "案件关系图",
        layoutHint: "layered",
        nodes: JSON.parse(FIELDS.nodesJson),
        edges: JSON.parse(FIELDS.edgesJson),
      },
    });

    const withExecutableField = {
      ...FIELDS,
      nodesJson: JSON.stringify([
        {
          ...JSON.parse(FIELDS.nodesJson)[0],
          rawHtml: "<script>window.evil()</script>",
        },
      ]),
    };
    expect(parseMapArtifactEdit(withExecutableField)).toMatchObject({
      ok: false,
    });
  });

  it("rejects invalid JSON and graph references before invoking IPC", () => {
    expect(
      parseMapArtifactEdit({ ...FIELDS, nodesJson: "not-json" }),
    ).toEqual({ ok: false, message: "节点 JSON 不是有效 JSON。" });
    expect(
      parseMapArtifactEdit({
        ...FIELDS,
        edgesJson: JSON.stringify([
          {
            id: "edge-1",
            source: "missing-node",
            target: "node-2",
            label: "对应",
            relation: "supports",
            sourceRefs: [],
          },
        ]),
      }),
    ).toMatchObject({ ok: false });
  });

  it("saves an unchanged title as a CAS-protected new version", async () => {
    const nextArtifact = { ...ARTIFACT, currentVersion: 3 };
    const save = vi.fn().mockResolvedValue({ detail: detail(nextArtifact) });

    await expect(
      persistMapArtifactEdit(
        { artifact: ARTIFACT, expectedCurrentVersion: 2, fields: FIELDS },
        save,
      ),
    ).resolves.toEqual({
      detail: detail(nextArtifact),
      mode: "new_version",
    });
    expect(save).toHaveBeenCalledWith({
      conversationId: "conversation-1",
      artifactId: "artifact-1",
      expectedCurrentVersion: 2,
      title: "案件关系图",
      draft: {
        kind: "map",
        spec: expect.objectContaining({
          schemaVersion: 1,
          title: "案件关系图",
          layoutHint: "layered",
        }),
      },
    });
  });

  it("stores a title change as a clearly separated artifact copy", async () => {
    const copy = {
      ...ARTIFACT,
      artifactId: "artifact-copy",
      title: "新版案件关系图",
      currentVersion: 1,
    };
    const save = vi.fn().mockResolvedValue({ detail: detail(copy) });

    await expect(
      persistMapArtifactEdit(
        {
          artifact: ARTIFACT,
          expectedCurrentVersion: 2,
          fields: { ...FIELDS, title: copy.title },
        },
        save,
      ),
    ).resolves.toMatchObject({ mode: "renamed_copy" });
    expect(save).toHaveBeenCalledWith(
      expect.not.objectContaining({
        artifactId: expect.anything(),
        expectedCurrentVersion: expect.anything(),
      }),
    );
  });
});
