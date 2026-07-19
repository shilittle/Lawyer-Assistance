import { describe, expect, it } from "vitest";

import { formatHealthCheck } from "./format";

describe("formatHealthCheck", () => {
  it("formats the typed health_check response", () => {
    expect(
      formatHealthCheck({
        status: "ok",
        appName: "Lawyer Assistance",
        architecture: "x86_64",
      }),
    ).toBe("本地服务正常");
  });
});
