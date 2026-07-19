import type { HealthCheckResponse } from "./types";

export function formatHealthCheck(response: HealthCheckResponse): string {
  return response.status === "ok" ? "本地服务正常" : "本地服务状态异常";
}
