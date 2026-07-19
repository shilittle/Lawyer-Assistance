import { describe, expect, it } from "vitest";

import {
  formatConnectionResult,
  formatHttpStatus,
  formatKeyStatus,
  formatLatency,
  formatProviderKind,
} from "./format";

describe("provider IPC format helpers", () => {
  it("formats all supported provider kinds", () => {
    expect(formatProviderKind("deep_seek")).toBe("DeepSeek");
    expect(formatProviderKind("qwen")).toContain("Alibaba");
    expect(formatProviderKind("silicon_flow")).toBe("SiliconFlow");
    expect(formatProviderKind("volcengine_ark")).toBe("Volcengine Ark");
    expect(formatProviderKind("custom")).toBe("自定义 OpenAI 兼容提供商");
  });

  it("formats masked key status without exposing a full key", () => {
    const formatted = formatKeyStatus({
      providerId: "deepseek-main",
      accountId: "default",
      configured: true,
      maskedKey: "****1234",
    });

    expect(formatted).toBe("已配置 ****1234");
    expect(formatted).not.toContain("secret");
  });

  it("formats missing latency and HTTP status", () => {
    expect(formatLatency(null)).toBe("未返回");
    expect(formatLatency(12)).toBe("12 ms");
    expect(formatHttpStatus(null)).toBe("未返回状态码");
    expect(formatHttpStatus(200)).toBe("状态码 200");
  });

  it("formats connection success and failure", () => {
    expect(
      formatConnectionResult({
        status: "succeeded",
        providerId: "qwen-main",
        httpStatus: 200,
        model: "qwen-plus",
        firstTokenLatencyMs: 10,
        totalLatencyMs: 18,
        usage: null,
        errorType: null,
        message: "connection_ok",
      }),
    ).toBe("连接成功");

    expect(
      formatConnectionResult({
        status: "failed",
        providerId: "qwen-main",
        httpStatus: 401,
        model: null,
        firstTokenLatencyMs: null,
        totalLatencyMs: 18,
        usage: null,
        errorType: "http",
        message: "auth_error",
      }),
    ).toBe("连接失败，请检查配置和网络后重试。");
  });
});
