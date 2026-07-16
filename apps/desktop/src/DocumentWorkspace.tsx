import { useEffect, useState } from "react";

import {
  exportDocument,
  listDocumentTemplates,
  previewDocument,
} from "./ipc/document/client";
import type {
  DocumentCitation,
  DocumentIpcError,
  DocumentTemplateId,
  DocumentTemplateMetadata,
  DocumentValidationErrorPayload,
  GeneratedDocument,
} from "./ipc/document/types";

const DOCUMENT_FIELD_LABELS: Readonly<Record<string, string>> = {
  plaintiff: "原告信息",
  defendant: "被告信息",
  sender: "发函方信息",
  recipient: "收函方信息",
  claims: "诉讼请求、答辩主张或办理要求",
  facts: "案件事实",
  dated_facts: "包含日期的案件事实",
  evidence: "证据",
  issues: "法律争点",
  valid_citations: "已通过本地校验的法律引用",
  case_date: "案件日期",
  model_draft: "模型草稿",
};

export interface DocumentWorkspaceProblem {
  errorType: string;
  message: string;
  missingFields: string[];
  invalidCitationIds: string[];
}

interface DocumentWorkspaceProps {
  projectId: string | null;
  onOpenCitation: (citation: DocumentCitation) => void;
}

interface DocumentCitationListProps {
  citations: DocumentCitation[];
  onOpenCitation: (citation: DocumentCitation) => void;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function parseJsonObject(value: string): Record<string, unknown> | null {
  try {
    return objectValue(JSON.parse(value));
  } catch {
    return null;
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function validationPayload(message: string): DocumentValidationErrorPayload | null {
  const parsed = parseJsonObject(message);
  if (!parsed || typeof parsed.code !== "string") return null;
  return {
    code: parsed.code,
    missingFields: stringArray(parsed.missingFields),
    invalidCitationIds: stringArray(parsed.invalidCitationIds),
  };
}

function ipcError(error: unknown): DocumentIpcError | null {
  const direct = objectValue(error);
  const parsed =
    typeof error === "string"
      ? parseJsonObject(error)
      : error instanceof Error
        ? parseJsonObject(error.message)
        : null;
  for (const candidate of [direct, parsed]) {
    if (
      candidate &&
      typeof candidate.errorType === "string" &&
      typeof candidate.message === "string"
    ) {
      return { errorType: candidate.errorType, message: candidate.message };
    }
  }
  return null;
}

// eslint-disable-next-line react-refresh/only-export-components
export function formatDocumentFieldLabel(field: string): string {
  return DOCUMENT_FIELD_LABELS[field] ?? field;
}

// eslint-disable-next-line react-refresh/only-export-components
export function parseDocumentWorkspaceError(error: unknown): DocumentWorkspaceProblem {
  const ipc = ipcError(error);
  const rawMessage =
    ipc?.message ??
    (error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "文书操作失败，请重试。");
  const validation = validationPayload(rawMessage);

  if (validation?.code === "missing_required_fields") {
    return {
      errorType: ipc?.errorType ?? "document_validation",
      message: "案件资料不完整，补齐下列必填字段后才能生成文书。",
      missingFields: validation.missingFields,
      invalidCitationIds: validation.invalidCitationIds,
    };
  }
  if (validation && validation.invalidCitationIds.length > 0) {
    return {
      errorType: ipc?.errorType ?? "document_validation",
      message: "文书引用未通过本地校验，已阻止生成。",
      missingFields: validation.missingFields,
      invalidCitationIds: validation.invalidCitationIds,
    };
  }
  return {
    errorType: ipc?.errorType ?? "document",
    message: rawMessage.trim() || "文书操作失败，请重试。",
    missingFields: [],
    invalidCitationIds: [],
  };
}

export function DocumentCitationList({
  citations,
  onOpenCitation,
}: DocumentCitationListProps) {
  if (citations.length === 0) {
    return <p className="empty-state">本模板未使用法律引用。</p>;
  }
  return (
    <div className="compact-list" aria-label="文书引用来源">
      {citations.map((citation) => (
        <div className="compact-row" key={citation.sourceId}>
          <strong>{citation.canonicalLabel}</strong>
          <span>{citation.excerpt}</span>
          <code>{citation.sourceId}</code>
          <button
            data-article-id={citation.articleId}
            data-document-id={citation.documentId}
            type="button"
            onClick={() => onOpenCitation(citation)}
          >
            打开本地条文详情
          </button>
        </div>
      ))}
    </div>
  );
}

export function DocumentWorkspace({
  projectId,
  onOpenCitation,
}: DocumentWorkspaceProps) {
  const [templates, setTemplates] = useState<DocumentTemplateMetadata[]>([]);
  const [templateId, setTemplateId] =
    useState<DocumentTemplateId>("complaint");
  const [preview, setPreview] = useState<{
    key: string;
    document: GeneratedDocument;
  } | null>(null);
  const [draft, setDraft] = useState("");
  const [path, setPath] = useState("");
  const [status, setStatus] = useState("");
  const [problem, setProblem] = useState<DocumentWorkspaceProblem | null>(null);
  const [operation, setOperation] = useState<"preview" | "export" | null>(null);

  const previewKey = JSON.stringify([projectId, templateId, draft]);
  const document = preview?.key === previewKey ? preview.document : null;

  useEffect(() => {
    void listDocumentTemplates()
      .then(setTemplates)
      .catch((error: unknown) => {
        const next = parseDocumentWorkspaceError(error);
        setProblem(next);
        setStatus(next.message);
      });
  }, []);

  async function generatePreview() {
    if (operation) return;
    if (!projectId) {
      setProblem(null);
      setStatus("请先在案件工作台选择案件");
      return;
    }
    setOperation("preview");
    try {
      setProblem(null);
      setStatus("正在校验并生成预览…");
      const generated = await previewDocument({
        projectId,
        templateId,
        modelDraft: draft || null,
      });
      setPreview({ key: previewKey, document: generated });
      setStatus("预览已生成；模型草稿会单独标注。");
    } catch (error: unknown) {
      const next = parseDocumentWorkspaceError(error);
      setPreview(null);
      setProblem(next);
      setStatus(next.message);
    } finally {
      setOperation(null);
    }
  }

  async function save() {
    if (operation) return;
    if (!projectId || !path) {
      setProblem(null);
      setStatus("请选择案件并填写 .docx 导出路径");
      return;
    }
    if (!document) {
      setProblem(null);
      setStatus("案件、模板或草稿已变化，请重新校验并生成预览后再导出。");
      return;
    }
    setOperation("export");
    try {
      setProblem(null);
      const result = await exportDocument({
        projectId,
        templateId,
        modelDraft: draft || null,
        exportPath: path,
      });
      setStatus(
        `已导出 ${result.exportPath}，写入 ${result.citationCount} 条已校验引用`,
      );
    } catch (error: unknown) {
      const next = parseDocumentWorkspaceError(error);
      setProblem(next);
      setStatus(next.message);
    } finally {
      setOperation(null);
    }
  }

  return (
    <section className="workspace-card">
      <h2>文书生成</h2>
      <p className="muted">
        以案件事实和已校验本地引用组装文书；缺少必填字段时不会导出半成品。
      </p>
      {!projectId ? (
        <p className="notice warning">当前未选择案件，请先到案件工作台选择。</p>
      ) : null}
      <div className="form-grid">
        <label>
          模板
          <select
            disabled={operation !== null}
            value={templateId}
            onChange={(event) => {
              setTemplateId(event.target.value as DocumentTemplateId);
              setProblem(null);
            }}
          >
            {templates.map((template) => (
              <option key={template.templateId} value={template.templateId}>
                {template.name}
              </option>
            ))}
          </select>
        </label>
        <label className="full-width">
          模型草稿（可选，始终标记待复核）
          <textarea
            disabled={operation !== null}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setProblem(null);
            }}
            rows={4}
          />
        </label>
        <label className="full-width">
          DOCX 导出路径
          <input
            disabled={operation !== null}
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="C:\\Users\\...\\起诉状.docx"
          />
        </label>
      </div>
      <div className="button-row">
        <button
          type="button"
          onClick={() => void generatePreview()}
          disabled={operation !== null}
        >
          {operation === "preview" ? "正在生成…" : "校验并预览"}
        </button>
        <button
          type="button"
          onClick={() => void save()}
          disabled={!document || operation !== null}
        >
          {operation === "export" ? "正在导出…" : "导出 DOCX"}
        </button>
      </div>
      {status && !problem ? (
        <p className="notice" role="status">
          {status}
        </p>
      ) : null}
      {problem ? (
        <div className="notice warning" role="alert" data-error-type={problem.errorType}>
          <strong>错误类型：{problem.errorType}</strong>
          <p>{problem.message}</p>
          {problem.missingFields.length > 0 ? (
            <>
              <p>缺少以下必填内容：</p>
              <ul>
                {problem.missingFields.map((field) => (
                  <li key={field}>
                    {formatDocumentFieldLabel(field)} <code>{field}</code>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          {problem.invalidCitationIds.length > 0 ? (
            <>
              <p>未通过校验的引用：</p>
              <ul>
                {problem.invalidCitationIds.map((sourceId) => (
                  <li key={sourceId}>
                    <code>{sourceId}</code>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      ) : null}
      {document ? (
        <article className="document-preview">
          <h3>{document.title}</h3>
          <pre>{document.markdown}</pre>
          <p>
            来源：
            {document.sections.flatMap((section) => section.sourceIds).length} 项案件数据；
            {document.citations.length} 条已校验法律引用。
          </p>
          <h4>已校验法律引用</h4>
          <DocumentCitationList
            citations={document.citations}
            onOpenCitation={onOpenCitation}
          />
        </article>
      ) : null}
    </section>
  );
}
