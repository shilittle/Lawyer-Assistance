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
    ).toBe("ok · Lawyer Assistance · x86_64");
  });
});
