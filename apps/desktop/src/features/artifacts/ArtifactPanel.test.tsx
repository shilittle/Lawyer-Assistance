import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  AssistantArtifact,
  AssistantArtifactVersion,
  AssistantCaseChangeProposal,
  AssistantConversationSource,
  AssistantMessage,
  AssistantRun,
} from "../../ipc/assistant/types";
import { ArtifactPanel } from "./ArtifactPanel";
import {
  artifactHasTrustedRegenerationOrigin,
  mapArtifactEditHasUnsavedChanges,
} from "./artifactGuards";

const PROPOSAL: AssistantCaseChangeProposal = {
  proposalId: "proposal-1",
  conversationId: "conversation-1",
  projectId: "case-1",
  runId: "run-1",
  baseCaseDigest: "sha256:1234567890abcdefghijklmnopqrstuvwxyz",
  status: "pending",
  changes: {
    schemaVersion: 1,
    facts: [
      {
        id: "fact-1",
        statement: "2026 年 7 月 1 日完成交付。",
        occurredOn: "2026-07-01",
        sourceRefs: ["attachment-1"],
      },
    ],
    evidence: [
      {
        id: "evidence-1",
        title: "交付凭证",
        summary: "证明交付已经完成。",
        provesFactIds: ["fact-1"],
        sourceRefs: ["attachment-1"],
      },
    ],
    issues: [
      {
        id: "issue-1",
        title: "是否履行",
        analysis: "需要结合交付凭证判断。",
        relatedFactIds: ["fact-1"],
        sourceRefs: ["attachment-1"],
      },
    ],
    legalBasis: [
      {
        id: "basis-1",
        issueIds: ["issue-1"],
        sourceRef: "source-1",
        marker: "[SRC:source-1]",
        citation: "《示例法》第一条第一款（2026年起施行）",
        proposition: "应依约履行。",
      },
    ],
    attachmentTransfers: [],
    artifactTransfers: [],
  },
  sourceRefs: ["attachment-1"],
  createdAt: "2026-07-17T00:00:00Z",
  decidedAt: null,
  appliedAt: null,
};

const RUN: AssistantRun = {
  runId: "run-1",
  conversationId: "conversation-1",
  userMessageId: "message-1",
  assistantMessageId: "message-2",
  providerId: "provider-1",
  providerSnapshot: {
    kind: "openai-compatible",
    modelId: "model-1",
    baseUrl: "https://provider.example/v1",
  },
  intent: "case_analysis",
  status: "succeeded",
  budget: {
    maxToolCalls: 8,
    maxProviderRoundTrips: 2,
    maxInputBodyBytes: 100_000,
    maxVisibleAttachments: 2,
    maxModelResponseBytes: 100_000,
  },
  errorType: null,
  createdAt: "2026-07-17T00:00:00Z",
  finishedAt: "2026-07-17T00:01:00Z",
  toolCalls: [],
};

const SOURCE: AssistantConversationSource = {
  sourceId: "source-1",
  createdAt: "2026-07-17T00:00:00Z",
  source: {
    sourceId: "source-1",
    articleId: "article-1",
    documentId: "document-1",
    versionId: "version-1",
    documentTitle: "示例法",
    versionLabel: "现行",
    articleNumber: "第一条",
    articleTitle: null,
    canonicalLabel: "《示例法》第一条",
    content: "不会由该面板完整显示的条文正文",
    snippet: "只显示可核对的条文摘要。",
    effectiveFrom: "2026-01-01",
    effectiveTo: null,
    versionStatus: "effective",
  },
};

const ARTIFACT: AssistantArtifact = {
  artifactId: "artifact-1",
  conversationId: "conversation-1",
  projectId: "case-1",
  kind: "map",
  title: "案件关系图",
  status: "draft",
  currentVersion: 1,
  createdAt: "2026-07-16T00:00:00Z",
  updatedAt: "2026-07-16T00:01:00Z",
};

const ARTIFACT_MESSAGE: AssistantMessage = {
  messageId: "message-2",
  conversationId: "conversation-1",
  role: "assistant",
  kind: "artifact_ref",
  textSummary: "已生成关系图",
  artifactId: "artifact-1",
  runId: "run-1",
  createdAt: "2026-07-16T00:01:00Z",
  attachments: [],
};

const MAP_VERSION: AssistantArtifactVersion = {
  versionId: "version-1",
  artifactId: "artifact-1",
  versionNumber: 1,
  content: {
    kind: "map",
    spec: {
      schemaVersion: 1,
      title: "案件关系图",
      layoutHint: "layered",
      nodes: [
        {
          id: "node-1",
          label: "当事人",
          summary: "原告",
          parentId: null,
          sourceRefs: [],
        },
      ],
      edges: [],
    },
  },
  renderedText: "案件关系图",
  sourceRefs: [],
  citationReport: null,
  providerSnapshot: null,
  createdAt: "2026-07-16T00:01:00Z",
};

describe("ArtifactPanel proposal review", () => {
  it("enables regeneration only for a matching trusted artifact-producing run", () => {
    const mapRun = { ...RUN, intent: "map_build" };
    expect(
      artifactHasTrustedRegenerationOrigin(
        ARTIFACT,
        [ARTIFACT_MESSAGE],
        [mapRun],
      ),
    ).toBe(true);
    expect(
      artifactHasTrustedRegenerationOrigin(
        { ...ARTIFACT, artifactId: "renamed-copy" },
        [ARTIFACT_MESSAGE],
        [mapRun],
      ),
    ).toBe(false);
    expect(
      artifactHasTrustedRegenerationOrigin(
        ARTIFACT,
        [ARTIFACT_MESSAGE],
        [{ ...mapRun, intent: "document_draft" }],
      ),
    ).toBe(false);
    expect(
      artifactHasTrustedRegenerationOrigin(
        ARTIFACT,
        [ARTIFACT_MESSAGE],
        [{ ...mapRun, status: "failed" }],
      ),
    ).toBe(false);
  });

  it("reports only actual Map editor changes as an unsaved draft", () => {
    const baseline = {
      title: "案件关系图",
      layoutHint: "layered" as const,
      nodesJson: JSON.stringify(
        [
          {
            id: "node-1",
            label: "当事人",
            summary: "原告",
            parentId: null,
            sourceRefs: [],
          },
        ],
        null,
        2,
      ),
      edgesJson: "[]",
    };
    expect(mapArtifactEditHasUnsavedChanges(null, MAP_VERSION)).toBe(false);
    expect(mapArtifactEditHasUnsavedChanges(baseline, MAP_VERSION)).toBe(false);
    expect(
      mapArtifactEditHasUnsavedChanges(
        { ...baseline, title: "尚未保存的新标题" },
        MAP_VERSION,
      ),
    ).toBe(true);
  });

  it("shows source snippets and keeps case application disabled until checked", () => {
    const markup = renderToStaticMarkup(
      <ArtifactPanel
        activeProject={{ projectId: "case-1", title: "示例案件" }}
        artifacts={[]}
        proposals={[PROPOSAL]}
        runs={[RUN]}
        selectedArtifactId={null}
        sources={[SOURCE]}
        onConversationRefresh={vi.fn()}
        onSelectArtifact={vi.fn()}
      />,
    );

    expect(markup).toContain("只显示可核对的条文摘要");
    expect(markup).not.toContain("不会由该面板完整显示的条文正文");
    expect(markup).toContain("待审阅内容不会自动改动案件");
    expect(markup).toContain("发生日期：2026-07-01");
    expect(markup).toContain("证明事实：");
    expect(markup).toContain("关联事实：");
    expect(markup).toContain("写入争点：");
    expect(markup).toContain("《示例法》第一条第一款（2026年起施行）");
    expect(markup).toContain("效力状态：现行有效");
    expect(markup).toContain("我已逐项审阅");
    expect(markup).toContain("建议来源");
    expect(markup).toContain("案件助理整理");
    expect(markup).not.toContain("projectId");
    expect(markup).not.toContain("baseCaseDigest");
    expect(markup).not.toContain("runId");
    expect(markup).not.toContain("case-1");
    expect(markup).not.toContain("sha256:12345");
    expect(markup).not.toContain("run-1");
    expect(markup).not.toContain("provider.example");
    expect(markup).toMatch(/<button[^>]*disabled=""[^>]*>确认写入案件<\/button>/);
    expect(markup).toContain("拒绝建议");
  });

  it("labels a proposal without runId as a manual suggestion", () => {
    const markup = renderToStaticMarkup(
      <ArtifactPanel
        activeProject={{ projectId: "case-1", title: "示例案件" }}
        artifacts={[]}
        proposals={[{ ...PROPOSAL, proposalId: "manual", runId: null }]}
        runs={[RUN]}
        selectedArtifactId={null}
        sources={[SOURCE]}
        onConversationRefresh={vi.fn()}
        onSelectArtifact={vi.fn()}
      />,
    );

    expect(markup).toContain("建议来源");
    expect(markup).toContain("人工整理");
    expect(markup).not.toContain("运行记录");
  });

  it("never exposes a legacy machine case title in the approval copy", () => {
    const markup = renderToStaticMarkup(
      <ArtifactPanel
        activeProject={{ projectId: "case-1", title: "service-deadbeef-1" }}
        artifacts={[]}
        proposals={[PROPOSAL]}
        runs={[RUN]}
        selectedArtifactId={null}
        sources={[SOURCE]}
        onConversationRefresh={vi.fn()}
        onSelectArtifact={vi.fn()}
      />,
    );

    expect(markup).toContain("当前案件");
    expect(markup).not.toContain("service-deadbeef-1");
  });
});
