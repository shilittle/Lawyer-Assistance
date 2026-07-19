import { applyAssistantCaseChangeProposal } from "../../ipc/assistant/client";
import type {
  ApplyAssistantCaseChangeProposalResponse,
  ApplyAssistantCaseChangeProposalRequest,
} from "../../ipc/assistant/types";

export type ProposalApplyFunction = (
  request: ApplyAssistantCaseChangeProposalRequest,
) => Promise<ApplyAssistantCaseChangeProposalResponse>;

export type ExplicitProposalApplyResult =
  | { kind: "confirmation_required" }
  | { kind: "submitted"; response: ApplyAssistantCaseChangeProposalResponse };

/** The UI cannot send userConfirmed=true without a separate explicit state. */
export async function applyProposalAfterExplicitConfirmation(
  request: {
    proposalId: string;
    projectId: string;
    explicitlyConfirmed: boolean;
  },
  apply: ProposalApplyFunction = applyAssistantCaseChangeProposal,
): Promise<ExplicitProposalApplyResult> {
  if (!request.explicitlyConfirmed) {
    return { kind: "confirmation_required" };
  }
  const response = await apply({
    proposalId: request.proposalId,
    projectId: request.projectId,
    userConfirmed: true,
  });
  return { kind: "submitted", response };
}
