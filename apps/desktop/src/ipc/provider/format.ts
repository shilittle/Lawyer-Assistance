import type {
  ConnectionTest,
  ProviderApiKeyStatus,
  ProviderKind,
} from "./types";

export function formatProviderKind(kind: ProviderKind): string {
  const labels: Record<ProviderKind, string> = {
    deep_seek: "DeepSeek",
    qwen: "Qwen / Alibaba Cloud Model Studio",
    silicon_flow: "SiliconFlow",
    volcengine_ark: "Volcengine Ark",
  };

  return labels[kind];
}

export function formatKeyStatus(status?: ProviderApiKeyStatus): string {
  if (!status || !status.configured) {
    return "未配置";
  }

  return status.maskedKey ? `已配置 ${status.maskedKey}` : "已配置";
}

export function formatLatency(value?: number | null): string {
  return typeof value === "number" ? `${value} ms` : "未返回";
}

export function formatHttpStatus(value?: number | null): string {
  return typeof value === "number" ? `HTTP ${value}` : "无 HTTP 状态";
}

export function formatConnectionResult(result?: ConnectionTest): string {
  if (!result) {
    return "未测试";
  }

  if (result.status === "succeeded") {
    return `成功 · ${formatHttpStatus(result.httpStatus)} · ${
      result.model ?? "未返回模型名"
    }`;
  }

  return `失败 · ${result.errorType ?? "unknown"} · ${result.message}`;
}
