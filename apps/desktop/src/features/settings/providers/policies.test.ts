import { describe, expect, it, vi } from "vitest";

import { createProviderProfileDraft } from "../../../ipc/provider/catalog";
import {
  providerApiKeyDeletionConfirmation,
  providerApiKeyOverwriteConfirmation,
  providerDeletionConfirmation,
  providerNavigationHasUnsavedChanges,
  runConfirmedDestructiveAction,
} from "./policies";

describe("Provider settings policies", () => {
  it("treats normalized profile formatting and blank credentials as unchanged", () => {
    const baseline = createProviderProfileDraft("deep_seek", "provider-1");
    const draft = {
      ...baseline,
      id: ` ${baseline.id} `,
      displayName: ` ${baseline.displayName} `,
      modelId: ` ${baseline.modelId} `,
      baseUrl: ` ${baseline.baseUrl} `,
      credentialAccountId: "  ",
    };

    expect(
      providerNavigationHasUnsavedChanges(baseline, draft, " \n\t "),
    ).toBe(false);
  });

  it("detects either a profile change or a non-blank credential input", () => {
    const baseline = createProviderProfileDraft("deep_seek", "provider-1");

    expect(
      providerNavigationHasUnsavedChanges(
        baseline,
        { ...baseline, modelId: "different-model" },
        "",
      ),
    ).toBe(true);
    expect(
      providerNavigationHasUnsavedChanges(baseline, baseline, "secret"),
    ).toBe(true);
  });

  it("preserves the exact Provider deletion confirmation", () => {
    const expected =
      "确定永久删除 Provider“示例服务”吗？对应配置和已保存的访问凭据会一并删除；既有结果不受影响。";

    expect(providerDeletionConfirmation("示例服务", "account-a")).toBe(
      expected,
    );
    expect(providerDeletionConfirmation("示例服务", "account-b")).toBe(
      expected,
    );
  });

  it("preserves the exact API key deletion confirmation", () => {
    const expected =
      "确定删除 Provider“示例服务”的访问凭据吗？删除后需重新录入才能调用该服务。";

    expect(providerApiKeyDeletionConfirmation("示例服务", "account-a")).toBe(
      expected,
    );
    expect(providerApiKeyDeletionConfirmation("示例服务", "account-b")).toBe(
      expected,
    );
  });

  it("preserves the exact API key overwrite confirmation", () => {
    const expected =
      "Provider“示例服务”已经保存访问凭据。确定用当前输入覆盖旧凭据吗？旧凭据无法恢复。";

    expect(providerApiKeyOverwriteConfirmation("示例服务", "account-a")).toBe(
      expected,
    );
    expect(providerApiKeyOverwriteConfirmation("示例服务", "account-b")).toBe(
      expected,
    );
  });

  it("does not execute a destructive action when confirmation is declined", async () => {
    const confirmAction = vi.fn(() => false);
    const action = vi.fn(async () => "deleted");

    await expect(
      runConfirmedDestructiveAction(
        "确认删除？",
        confirmAction,
        action,
      ),
    ).resolves.toEqual({ executed: false });
    expect(confirmAction).toHaveBeenCalledOnce();
    expect(confirmAction).toHaveBeenCalledWith("确认删除？");
    expect(action).not.toHaveBeenCalled();
  });

  it("executes once and returns the action value after confirmation", async () => {
    const confirmAction = vi.fn(() => true);
    const action = vi.fn(async () => ({ deleted: true }));

    await expect(
      runConfirmedDestructiveAction(
        "确认删除？",
        confirmAction,
        action,
      ),
    ).resolves.toEqual({
      executed: true,
      value: { deleted: true },
    });
    expect(confirmAction).toHaveBeenCalledOnce();
    expect(action).toHaveBeenCalledOnce();
  });

  it("preserves action failures after confirmation", async () => {
    const failure = new Error("write failed");
    const action = vi.fn(async () => {
      throw failure;
    });

    await expect(
      runConfirmedDestructiveAction("确认删除？", () => true, action),
    ).rejects.toBe(failure);
    expect(action).toHaveBeenCalledOnce();
  });
});
