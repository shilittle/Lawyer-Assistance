export const PRODUCT_AREAS = [
  "assistant",
  "cases",
  "legal-library",
  "settings",
] as const;

export type ProductArea = (typeof PRODUCT_AREAS)[number];

export const VIEW_MODES = [
  "assistant",
  "search",
  "qa",
  "cases",
  "providers",
  "local-processing",
  "documents",
  "graph",
  "mcp",
  "release",
] as const;

export type ViewMode = (typeof VIEW_MODES)[number];

export interface ViewMetadata {
  id: ViewMode;
  eyebrow: string;
  title: string;
  navigationLabel: string;
  futureArea: ProductArea;
}

export const VIEW_METADATA: Readonly<Record<ViewMode, ViewMetadata>> = {
  assistant: {
    id: "assistant",
    eyebrow: "本地留痕的有界编排",
    title: "助理",
    navigationLabel: "助理",
    futureArea: "assistant",
  },
  search: {
    id: "search",
    eyebrow: "离线法律库",
    title: "法律库",
    navigationLabel: "法律库",
    futureArea: "legal-library",
  },
  qa: {
    id: "qa",
    eyebrow: "来源受限回答",
    title: "引用问答",
    navigationLabel: "引用问答",
    futureArea: "assistant",
  },
  cases: {
    id: "cases",
    eyebrow: "案件与证据",
    title: "案件工作台 β",
    navigationLabel: "案件工作台",
    futureArea: "cases",
  },
  providers: {
    id: "providers",
    eyebrow: "BYOK Provider",
    title: "设置与维护",
    navigationLabel: "设置",
    futureArea: "settings",
  },
  "local-processing": {
    id: "local-processing",
    eyebrow: "本地脱敏与 OCR",
    title: "本地处理环境与 OCR 组件",
    navigationLabel: "本地处理环境与 OCR 组件",
    futureArea: "settings",
  },
  documents: {
    id: "documents",
    eyebrow: "结构化文书",
    title: "文书生成",
    navigationLabel: "文书生成",
    futureArea: "cases",
  },
  graph: {
    id: "graph",
    eyebrow: "可追溯关系",
    title: "关系图",
    navigationLabel: "关系图",
    futureArea: "cases",
  },
  mcp: {
    id: "mcp",
    eyebrow: "MCP 与自动化",
    title: "MCP 与自动化",
    navigationLabel: "MCP 与自动化",
    futureArea: "settings",
  },
  release: {
    id: "release",
    eyebrow: "Windows 发布与维护",
    title: "版本与数据维护",
    navigationLabel: "版本与备份",
    futureArea: "settings",
  },
};

export const VIEW_NAVIGATION = [
  VIEW_METADATA.assistant,
  VIEW_METADATA.cases,
  VIEW_METADATA.search,
  VIEW_METADATA.providers,
] as const;
