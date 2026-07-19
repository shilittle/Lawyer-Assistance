import { describe, expect, it, vi } from "vitest";

import {
  PRIVACY_REVIEW_DELETION_CONFIRMATION,
  deletePrivacyReviewAfterConfirmation,
} from "./privacyReviewDeletion";

const request = {
  redactionId: "red_1",
  expectedSourceSha256: "a".repeat(64),
  expectedExtractionSha256: "b".repeat(64),
};

describe("privacy review deletion confirmation", () => {
  it("makes cancellation side-effect free and never invokes deletion", async () => {
    const confirm = vi.fn(() => false);
    const deleteReview = vi.fn();
    const onConfirmed = vi.fn();

    await expect(
      deletePrivacyReviewAfterConfirmation(request, {
        confirm,
        deleteReview,
        onConfirmed,
      }),
    ).resolves.toEqual({ cancelled: true, deleted: false });
    expect(confirm).toHaveBeenCalledWith(PRIVACY_REVIEW_DELETION_CONFIRMATION);
    expect(onConfirmed).not.toHaveBeenCalled();
    expect(deleteReview).not.toHaveBeenCalled();
  });

  it("starts the operation and forwards only the exact bound request after confirmation", async () => {
    const order: string[] = [];
    const deleteReview = vi.fn(async () => {
      order.push("delete");
      return { deleted: true };
    });

    await expect(
      deletePrivacyReviewAfterConfirmation(request, {
        confirm: () => true,
        onConfirmed: () => order.push("confirmed"),
        deleteReview,
      }),
    ).resolves.toEqual({ cancelled: false, deleted: true });
    expect(order).toEqual(["confirmed", "delete"]);
    expect(deleteReview).toHaveBeenCalledWith(request);
  });
});
