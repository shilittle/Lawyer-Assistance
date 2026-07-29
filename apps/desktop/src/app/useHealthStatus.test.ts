import { beforeEach, describe, expect, it, vi } from "vitest";

const hookHarness = vi.hoisted(() => {
  let state: unknown;
  let initialized = false;
  let effectRegistered = false;
  let cleanup: (() => void) | undefined;
  let stateUpdateCount = 0;

  return {
    reset() {
      state = undefined;
      initialized = false;
      effectRegistered = false;
      cleanup = undefined;
      stateUpdateCount = 0;
    },
    useState<T>(
      initial: T | (() => T),
    ): [T, (next: T | ((current: T) => T)) => void] {
      if (!initialized) {
        state =
          typeof initial === "function"
            ? (initial as () => T)()
            : initial;
        initialized = true;
      }
      return [
        state as T,
        (next: T | ((current: T) => T)) => {
          state =
            typeof next === "function"
              ? (next as (current: T) => T)(state as T)
              : next;
          stateUpdateCount += 1;
        },
      ];
    },
    useEffect(effect: () => void | (() => void)) {
      if (effectRegistered) return;
      effectRegistered = true;
      cleanup = effect() ?? undefined;
    },
    unmount() {
      cleanup?.();
      cleanup = undefined;
    },
    stateUpdateCount() {
      return stateUpdateCount;
    },
  };
});

vi.mock("react", () => ({
  useEffect: hookHarness.useEffect,
  useState: hookHarness.useState,
}));

import type { HealthCheckResponse } from "../ipc/health/types";
import { useHealthStatus } from "./useHealthStatus";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function flushPromises(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("useHealthStatus", () => {
  beforeEach(() => {
    hookHarness.reset();
  });

  it("starts the health check eagerly and exposes the original loading text", () => {
    const pending = deferred<HealthCheckResponse>();
    const checkHealth = vi.fn(() => pending.promise);

    expect(useHealthStatus(checkHealth)).toEqual({
      state: { kind: "loading" },
      text: "正在检查本地服务…",
    });
    expect(checkHealth).toHaveBeenCalledOnce();
  });

  it("formats a successful response with the existing health formatter", async () => {
    const pending = deferred<HealthCheckResponse>();
    const checkHealth = vi.fn(() => pending.promise);
    const response: HealthCheckResponse = {
      status: "ok",
      appName: "Lawyer Assistance",
      architecture: "x86_64",
    };

    useHealthStatus(checkHealth);
    pending.resolve(response);
    await flushPromises();

    expect(useHealthStatus(checkHealth)).toEqual({
      state: { kind: "ready", response },
      text: "本地服务正常",
    });
    expect(checkHealth).toHaveBeenCalledOnce();
  });

  it("publishes a closed-vocabulary error instead of the raw failure", async () => {
    const pending = deferred<HealthCheckResponse>();
    const checkHealth = vi.fn(() => pending.promise);

    useHealthStatus(checkHealth);
    pending.reject({
      errorType: "provider_failure",
      message: "raw internal health failure",
    });
    await flushPromises();

    expect(useHealthStatus(checkHealth)).toEqual({
      state: {
        kind: "error",
        message: "模型服务暂时不可用，请稍后重试。",
      },
      text: "模型服务暂时不可用，请稍后重试。",
    });
  });

  it("ignores a late response after unmount", async () => {
    const pending = deferred<HealthCheckResponse>();
    const checkHealth = vi.fn(() => pending.promise);

    useHealthStatus(checkHealth);
    hookHarness.unmount();
    pending.resolve({
      status: "ok",
      appName: "Lawyer Assistance",
      architecture: "x86_64",
    });
    await flushPromises();

    expect(hookHarness.stateUpdateCount()).toBe(0);
    expect(useHealthStatus(checkHealth)).toEqual({
      state: { kind: "loading" },
      text: "正在检查本地服务…",
    });
  });
});
