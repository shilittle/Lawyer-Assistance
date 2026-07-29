import { describe, expect, it, vi } from "vitest";

import {
  createCaseCloseGuard,
  type CaseCloseSnapshot,
} from "./caseCloseGuard";

function snapshot(
  patch: Partial<CaseCloseSnapshot> = {},
): CaseCloseSnapshot {
  return {
    dirtyDrafts: [],
    caseMutationInFlight: false,
    extractionMutationInFlight: false,
    extractionNeedsFlush: false,
    extractionCloseInProgress: false,
    ...patch,
  };
}

describe("case close guard port", () => {
  it("exposes the current case snapshot without owning global close policy", () => {
    const current = snapshot({
      dirtyDrafts: ["project"],
      caseMutationInFlight: true,
    });
    const guard = createCaseCloseGuard({
      readSnapshot: () => current,
      flushPendingDraft: vi.fn(async () => true),
      beginControlledClose: vi.fn(),
      finishBlockedClose: vi.fn(),
    });

    expect(guard.read()).toBe(current);
  });

  it("flushes an active review through the controlled native-close path", async () => {
    const calls: string[] = [];
    const guard = createCaseCloseGuard({
      readSnapshot: () => snapshot({ extractionNeedsFlush: true }),
      flushPendingDraft: async () => {
        calls.push("flush");
        return true;
      },
      beginControlledClose: (needsFlush) =>
        calls.push(`begin:${String(needsFlush)}`),
      finishBlockedClose: () => calls.push("finish-blocked"),
    });

    await expect(
      guard.requestControlledClose({
        forceControlledClose: false,
        preventDefault: () => calls.push("prevent"),
        destroyWindow: async () => {
          calls.push("destroy");
        },
        onBlocked: (message) => calls.push(`blocked:${message}`),
      }),
    ).resolves.toBe("saved_and_closed");
    expect(calls).toEqual(["begin:true", "prevent", "flush", "destroy"]);
  });

  it("restores the feature close state when a fail-closed flush blocks closing", async () => {
    const calls: string[] = [];
    const guard = createCaseCloseGuard({
      readSnapshot: () => snapshot({ extractionNeedsFlush: true }),
      flushPendingDraft: async () => false,
      beginControlledClose: () => calls.push("begin"),
      finishBlockedClose: () => calls.push("finish-blocked"),
    });

    await expect(
      guard.requestControlledClose({
        forceControlledClose: false,
        preventDefault: () => calls.push("prevent"),
        destroyWindow: async () => {
          calls.push("destroy");
        },
        onBlocked: () => calls.push("blocked"),
      }),
    ).resolves.toBe("blocked");
    expect(calls).toEqual(["begin", "prevent", "blocked", "finish-blocked"]);
  });
});
