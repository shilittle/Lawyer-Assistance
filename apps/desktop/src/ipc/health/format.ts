import type { HealthCheckResponse } from "./types";

export function formatHealthCheck(response: HealthCheckResponse): string {
  return `${response.status} · ${response.appName} · ${response.architecture}`;
}
