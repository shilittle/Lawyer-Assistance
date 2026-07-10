export type HealthStatus = "ok";

export interface HealthCheckResponse {
  status: HealthStatus;
  appName: string;
  architecture: "x86_64";
}
