import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { getCaseGraph, getLawGraph } from "./client";

describe("graph IPC client", () => {
  beforeEach(() => invoke.mockReset());

  it("keeps the case identifier in the typed request envelope", async () => {
    invoke.mockResolvedValue({ nodes: [], edges: [] });
    await getCaseGraph("case-1");
    expect(invoke).toHaveBeenCalledWith("get_case_graph", {
      request: { projectId: "case-1" },
    });
  });

  it("keeps the law identifier in the typed request envelope", async () => {
    invoke.mockResolvedValue({ nodes: [], edges: [] });
    await getLawGraph("law-1");
    expect(invoke).toHaveBeenCalledWith("get_law_graph", {
      request: { documentId: "law-1" },
    });
  });
});
