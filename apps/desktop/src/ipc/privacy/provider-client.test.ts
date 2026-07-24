import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import {
  approveApprovedProviderTask,
  dispatchApprovedProvider,
  getProviderQualificationStatus,
  listApprovedProviderOutputs,
  loadApprovedProviderOutput,
  revokeApprovedProviderOutput,
  revokeProviderQualification,
  runProviderQualification,
} from "./client";

describe("approved Provider privacy IPC client", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("uses exact qualification commands with only profile ID and bounded TTL", async () => {
    await getProviderQualificationStatus({ providerId: "provider-main" });
    await runProviderQualification({
      providerId: "provider-main",
      ttlSeconds: 3600,
    });
    await revokeProviderQualification({ providerId: "provider-main" });

    expect(invoke).toHaveBeenNthCalledWith(1, "get_provider_qualification_status", {
      request: { providerId: "provider-main" },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "run_provider_qualification", {
      request: { providerId: "provider-main", ttlSeconds: 3600 },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "revoke_provider_qualification", {
      request: { providerId: "provider-main" },
    });
  });
  it("dispatches only an exact redaction/profile/task/instruction/prior/token binding", async () => {
    await dispatchApprovedProvider({
      redactionId: "red_approved_1",
      providerId: "provider-main",
      task: "case_legal_qa",
      instruction: "仅回答该法律问题并保留脱敏占位符。",
      priorOutput: null,
      maxTokens: 1024,
    });

    expect(invoke).toHaveBeenCalledWith("dispatch_approved_provider", {
      request: {
        redactionId: "red_approved_1",
        providerId: "provider-main",
        task: "case_legal_qa",
        instruction: "仅回答该法律问题并保留脱敏占位符。",
        priorOutput: null,
        maxTokens: 1024,
      },
    });
    const wire = JSON.stringify(invoke.mock.calls[0]);
    expect(wire).not.toContain("purpose");
    expect(wire).not.toContain("receiptToken");
    expect(wire).not.toContain("approvedPayloadJson");
    expect(wire).not.toContain("apiKey");
    expect(wire).not.toContain("secret");
    expect(wire).not.toContain("bearer");
    expect(wire).not.toContain("originalText");
    expect(wire).not.toContain("path");
  });

  it("approves the complete task binding without exposing a signed token", async () => {
    await approveApprovedProviderTask({
      redactionId: "red_approved_1",
      expectedRiskRevision: 7,
      expectedSuggestedRedactedSha256: "a".repeat(64),
      editedPages: [{ pageNumber: 1, redactedText: "原告：[PERSON_001]" }],
      reviewer: "reviewer-1",
      providerId: "provider-main",
      task: "repair",
      instruction: "修复格式，不改变事实。",
      priorOutput: { outputId: "out_1", task: "summary" },
      maxTokens: 2048,
      ttlSeconds: 3600,
      confirmed: true,
    });

    expect(invoke).toHaveBeenCalledWith("approve_approved_provider_task", {
      request: {
        redactionId: "red_approved_1",
        expectedRiskRevision: 7,
        expectedSuggestedRedactedSha256: "a".repeat(64),
        editedPages: [{ pageNumber: 1, redactedText: "原告：[PERSON_001]" }],
        reviewer: "reviewer-1",
        providerId: "provider-main",
        task: "repair",
        instruction: "修复格式，不改变事实。",
        priorOutput: { outputId: "out_1", task: "summary" },
        maxTokens: 2048,
        ttlSeconds: 3600,
        confirmed: true,
      },
    });
    const wire = JSON.stringify(invoke.mock.calls[0]);
    expect(wire).not.toContain("receiptToken");
    expect(wire).not.toContain("approvedPayloadJson");
  });

  it("lists, loads and revokes outputs with exact provider/model/output task context", async () => {
    await listApprovedProviderOutputs({
      redactionId: "red_approved_1",
      providerId: "provider-main",
    });
    await loadApprovedProviderOutput({
      outputId: "out_1",
      redactionId: "red_approved_1",
      providerId: "provider-main",
      modelId: "model-main",
      task: "summary",
    });
    await revokeApprovedProviderOutput({
      outputId: "out_1",
      redactionId: "red_approved_1",
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "list_approved_provider_outputs", {
      request: {
        redactionId: "red_approved_1",
        providerId: "provider-main",
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "load_approved_provider_output", {
      request: {
        outputId: "out_1",
        redactionId: "red_approved_1",
        providerId: "provider-main",
        modelId: "model-main",
        task: "summary",
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "revoke_approved_provider_output", {
      request: { outputId: "out_1", redactionId: "red_approved_1" },
    });
    const wire = JSON.stringify(invoke.mock.calls);
    expect(wire).not.toContain("receiptToken");
    expect(wire).not.toContain("approvedPayloadJson");
    expect(wire).not.toContain("content\"");
  });
});
