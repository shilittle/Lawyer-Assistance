import { describe, expect, it, vi } from "vitest";

import type { ApplyAssistantCaseChangeProposalResponse } from "../../ipc/assistant/types";
import { applyProposalAfterExplicitConfirmation } from "./proposalActions";

describe("applyProposalAfterExplicitConfirmation", () => {
  it("never calls IPC before the explicit confirmation boundary", async () => {
    const apply = vi.fn();
    const result = await applyProposalAfterExplicitConfirmation(
      {
        proposalId: "proposal-1",
        projectId: "case-1",
        explicitlyConfirmed: false,
      },
      apply,
    );
    expect(result).toEqual({ kind: "confirmation_required" });
    expect(apply).not.toHaveBeenCalled();
  });

  it("closes the IPC request with userConfirmed=true after confirmation", async () => {
    const response = {
      proposal: {
        proposalId: "proposal-1",
      },
      applied: true,
      stale: false,
    } as ApplyAssistantCaseChangeProposalResponse;
    const apply = vi.fn().mockResolvedValue(response);
    const result = await applyProposalAfterExplicitConfirmation(
      {
        proposalId: "proposal-1",
        projectId: "case-1",
        explicitlyConfirmed: true,
      },
      apply,
    );
    expect(apply).toHaveBeenCalledWith({
      proposalId: "proposal-1",
      projectId: "case-1",
      userConfirmed: true,
    });
    expect(result).toEqual({ kind: "submitted", response });
  });
});
