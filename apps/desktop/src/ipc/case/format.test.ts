import { describe, expect, it } from "vitest";

import {
  formatConfirmationStatus,
  formatGapKind,
  formatGapSeverity,
  formatLegalBasisInvalidReason,
  formatLegalBasisStatus,
  formatLegalIssueStatus,
  formatPartyRole,
} from "./format";

describe("case IPC format helpers", () => {
  it("formats party roles and confirmation states", () => {
    expect(formatPartyRole("plaintiff")).toBe("原告");
    expect(formatPartyRole("third_party")).toBe("第三人");
    expect(formatConfirmationStatus("confirmed")).toBe("已确认事实");
    expect(formatConfirmationStatus("model_suggested")).toBe("模型建议");
  });

  it("formats issue status and gap labels", () => {
    expect(formatLegalIssueStatus("open")).toBe("待处理");
    expect(formatLegalIssueStatus("resolved")).toBe("已解决");
    expect(formatGapKind("fact_missing_evidence")).toBe("事实缺少证据支撑");
    expect(formatGapKind("legal_issue_missing_basis")).toBe("争点缺少法律依据");
    expect(formatGapSeverity("blocking")).toBe("需处理");
  });

  it("formats legal basis validation states", () => {
    expect(formatLegalBasisStatus("valid")).toBe("已校验");
    expect(formatLegalBasisStatus("invalid")).toBe("未通过");
    expect(formatLegalBasisInvalidReason("date_out_of_range")).toBe(
      "不适用于案件日期",
    );
  });
});
