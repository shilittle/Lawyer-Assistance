import { useEffect, useState } from "react";

import { healthCheck } from "../ipc/health/client";
import { formatHealthCheck } from "../ipc/health/format";
import type { HealthCheckResponse } from "../ipc/health/types";
import { publicErrorMessage } from "../publicOutput";

export type HealthState =
  | { kind: "loading" }
  | { kind: "ready"; response: HealthCheckResponse }
  | { kind: "error"; message: string };

export interface UseHealthStatusResult {
  readonly state: HealthState;
  readonly text: string;
}

export type HealthCheckOperation = () => Promise<HealthCheckResponse>;

function healthStatusText(state: HealthState): string {
  return state.kind === "ready"
    ? formatHealthCheck(state.response)
    : state.kind === "error"
      ? state.message
      : "正在检查本地服务…";
}

export function useHealthStatus(
  checkHealth: HealthCheckOperation = healthCheck,
): UseHealthStatusResult {
  const [state, setState] = useState<HealthState>({ kind: "loading" });

  useEffect(() => {
    let isMounted = true;

    checkHealth()
      .then((response) => {
        if (isMounted) {
          setState({ kind: "ready", response });
        }
      })
      .catch((error: unknown) => {
        if (isMounted) {
          setState({
            kind: "error",
            message: publicErrorMessage(error),
          });
        }
      });

    return () => {
      isMounted = false;
    };
  }, [checkHealth]);

  return {
    state,
    text: healthStatusText(state),
  };
}
