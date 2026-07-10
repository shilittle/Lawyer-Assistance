import { invoke } from "@tauri-apps/api/core";

import type { HealthCheckResponse } from "./types";

export function healthCheck(): Promise<HealthCheckResponse> {
  return invoke<HealthCheckResponse>("health_check");
}
