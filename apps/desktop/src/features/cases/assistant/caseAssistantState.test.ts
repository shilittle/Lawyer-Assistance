import { describe, expect, it } from "vitest";

import type {
  CaseAssistantGeneration,
  CaseAssistantPendingOutput,
} from "../../../ipc/case-assistant/types";
import {
  caseAssistantConfirmationMessage,
  initialCaseAssistantStreamState,
  reduceCaseAssistantRunEvent,
  selectedGenerationIdsFromProjection,
  toggleCaseAssistantGeneration,
} from "./caseAssistantState";

const generations: CaseAssistantGeneration[] = [
  {
    redactionGenerationId: "generation-a1",
    materialId: "material-a",
    generationNumber: 1,
    mediaType: "application/pdf",
    pageCount: 2,
    approvedAt: "2026-07-31T00:00:00Z",
    selected: false,
    displayName: "材料 A / 第 1 代",
  },
  {
    redactionGenerationId: "generation-a2",
    materialId: "material-a",
    generationNumber: 2,
    mediaType: "application/pdf",
    pageCount: 2,
    approvedAt: "2026-07-31T01:00:00Z",
    selected: true,
    displayName: "材料 A / 第 2 代",
  },
  {
    redactionGenerationId: "generation-b1",
    materialId: "material-b",
    generationNumber: 1,
    mediaType: "text/plain",
    pageCount: 1,
    approvedAt: "2026-07-31T02:00:00Z",
    selected: true,
    displayName: "材料 B / 第 1 代",
  },
];

describe("case assistant frontend state", () => {
  it("restores only backend-declared active selections", () => {
    expect(selectedGenerationIdsFromProjection(generations)).toEqual([
      "generation-a2",
      "generation-b1",
    ]);
  });

  it("keeps at most one explicitly selected generation per material", () => {
    expect(
      toggleCaseAssistantGeneration(
        generations,
        ["generation-a2", "generation-b1"],
        "generation-a1",
        true,
      ),
    ).toEqual(["generation-b1", "generation-a1"]);
    expect(
      toggleCaseAssistantGeneration(
        generations,
        ["generation-a2", "generation-b1"],
        "generation-b1",
        false,
      ),
    ).toEqual(["generation-a2"]);
  });

  it("accepts only one post-scan delta from the active ordered channel", () => {
    const initial = initialCaseAssistantStreamState("run-1");
    const first = reduceCaseAssistantRunEvent(initial, {
      runId: "run-1",
      sequence: 2,
      eventType: "delta",
      content: "扫描通过后的完整回答",
    });
    const duplicate = reduceCaseAssistantRunEvent(first, {
      runId: "run-1",
      sequence: 3,
      eventType: "delta",
      content: "不得追加的第二段",
    });
    const stale = reduceCaseAssistantRunEvent(duplicate, {
      runId: "run-1",
      sequence: 1,
      eventType: "status",
      status: "running",
    });
    const wrongRun = reduceCaseAssistantRunEvent(stale, {
      runId: "run-2",
      sequence: 4,
      eventType: "delta",
      content: "其他运行",
    });

    expect(first.verifiedResponse).toBe("扫描通过后的完整回答");
    expect(duplicate.verifiedResponse).toBe("扫描通过后的完整回答");
    expect(stale).toBe(duplicate);
    expect(wrongRun).toBe(stale);
  });

  it("makes confirmation a separate explicit write boundary", () => {
    const output = {
      outputKind: "case_document",
    } as CaseAssistantPendingOutput;
    expect(caseAssistantConfirmationMessage(output)).toContain("确认应用");
    expect(caseAssistantConfirmationMessage(output)).toContain(
      "确认前不会写入案件或成果",
    );
  });
});
