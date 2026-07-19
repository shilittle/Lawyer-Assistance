import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import {
  exportDocumentPdf,
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
  PreviewDocumentRequest,
  StandaloneDocumentInput,
} from "./ipc/document/types";
import {
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "./publicOutput";

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
  standalone_content: "写作要求或已知材料",
};

const EMPTY_STANDALONE_INPUT: StandaloneDocumentInput = {
  title: "",
  partyA: "",
  partyB: "",
  facts: "",
  requests: "",
  evidence: "",
  requirements: "",
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
  return DOCUMENT_FIELD_LABELS[field] ?? "其他必填内容";
}

// eslint-disable-next-line react-refresh/only-export-components
export function formatDocumentCitationLabel(citation: DocumentCitation): string {
  const generic =
    citation.kind === "judicialCase"
      ? "相关案例（案号或裁判年份待核对）"
      : "相关法律条文（条款层级或施行年份待核对）";
  const title = publicTitle(citation.title, "");
  const locator = publicTitle(citation.locator, "");
  const year = /^(\d{4})/u.exec(citation.effectiveOrDecidedOn)?.[1];
  if (!title || !locator || !year) return generic;
  if (citation.kind === "judicialCase") {
    const caseNumber = locator.replace(/^案号[：:]\s*/u, "");
    return `${title}（案号：${caseNumber}；${year}年裁判）`;
  }
  if (!locator.includes("款")) return generic;
  const lawName = title.replace(/^《|》$/gu, "");
  return `《${lawName}》${locator}（${year}年起施行）`;
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
      message: "生成材料不完整，补齐下列内容后才能生成文书。",
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
    message: publicErrorMessage(error, "文书操作失败，请重试。"),
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
    <table aria-label="文书引用表">
      <thead>
        <tr>
          <th scope="col">引用条文</th>
          <th scope="col">内容摘要</th>
          <th scope="col">核对原文</th>
        </tr>
      </thead>
      <tbody>
        {citations.map((citation) => (
          <tr key={citation.sourceId}>
            <td>{formatDocumentCitationLabel(citation)}</td>
            <td>{publicContentSummary(citation.excerpt)}</td>
            <td>
              <button type="button" onClick={() => onOpenCitation(citation)}>
                打开条文
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function LegalMarkdownPreview({ markdown }: { markdown: string }) {
  const publicMarkdown = sanitizePublicGeneratedText(
    markdown,
    "预览内容暂不可显示，请重新生成。",
  );
  return (
    <div className="legal-document-markdown" data-preview-format="markdown">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{publicMarkdown}</ReactMarkdown>
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
    caseRevision: string | null;
    generationHash: string;
    idempotencyKey: string;
  } | null>(null);
  const [sourceMode, setSourceMode] = useState<"standalone" | "case">(
    "standalone",
  );
  const [standaloneInput, setStandaloneInput] =
    useState<StandaloneDocumentInput>(EMPTY_STANDALONE_INPUT);
  const [draft, setDraft] = useState("");
  const [status, setStatus] = useState("");
  const [problem, setProblem] = useState<DocumentWorkspaceProblem | null>(null);
  const [operation, setOperation] = useState<"preview" | "export" | null>(null);

  const previewKey = JSON.stringify([
    sourceMode,
    projectId,
    standaloneInput,
    templateId,
    draft,
  ]);
  const activePreview = preview?.key === previewKey ? preview : null;
  const document = activePreview?.document ?? null;

  function documentRequest(): PreviewDocumentRequest {
    return {
      projectId: sourceMode === "case" ? projectId : null,
      standaloneInput: sourceMode === "standalone" ? standaloneInput : null,
      templateId,
      modelDraft: draft || null,
    };
  }

  function updateStandaloneInput(
    field: keyof StandaloneDocumentInput,
    value: string,
  ) {
    setStandaloneInput((current) => ({ ...current, [field]: value }));
    setProblem(null);
  }

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
    if (sourceMode === "case" && !projectId) {
      setProblem(null);
      setStatus("请先在案件工作台选择案件");
      return;
    }
    setOperation("preview");
    try {
      setProblem(null);
      setStatus("正在校验并生成预览…");
      const generated = await previewDocument(documentRequest());
      setPreview({
        key: previewKey,
        document: generated.document,
        caseRevision: generated.caseRevision,
        generationHash: generated.generationHash,
        idempotencyKey: globalThis.crypto.randomUUID(),
      });
      setStatus("预览已生成；直接输入及已有草稿均会标记为待复核材料。");
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
    if (!document || !activePreview) {
      setProblem(null);
      setStatus("案件、模板或草稿已变化，请重新校验并生成预览后再导出。");
      return;
    }
    setOperation("export");
    try {
      setProblem(null);
      const result = await exportDocumentPdf({
        ...documentRequest(),
        expectedRevision: activePreview.caseRevision,
        generationHash: activePreview.generationHash,
        confirmed: true,
        idempotencyKey: activePreview.idempotencyKey,
      });
      if (result.cancelled) {
        setStatus("已取消 PDF 导出，预览仍可继续复核。");
        return;
      }
      setStatus(`PDF 已导出；已核验 ${result.citationCount} 条法律引用。`);
    } catch (error: unknown) {
      const next = parseDocumentWorkspaceError(error);
      setProblem(next);
      setStatus(next.message);
    } finally {
      setOperation(null);
    }
  }

  return (
    <section className="workspace-card document-workspace">
      <header className="document-workspace__header">
        <div>
          <h2>文书生成</h2>
          <p className="muted">
            可直接填写要求独立生成，也可复用案件工作台中已核验的资料。
          </p>
        </div>
        <span
          className={`document-case-badge ${
            sourceMode === "standalone" || projectId ? "is-ready" : "is-missing"
          }`}
        >
          {sourceMode === "standalone"
            ? "独立生成"
            : projectId
              ? "使用已选案件"
              : "尚未选择案件"}
        </span>
      </header>

      <div className="document-layout">
        <section className="document-controls" aria-labelledby="document-controls-title">
          <div className="document-panel-heading">
            <div>
              <span className="document-step">01</span>
              <h3 id="document-controls-title">生成设置</h3>
            </div>
            <span>模板与导出</span>
          </div>

          <div className="document-controls__body">
            <div
              className="document-source-switch"
              role="group"
              aria-label="文书材料来源"
            >
              <button
                aria-pressed={sourceMode === "standalone"}
                className={sourceMode === "standalone" ? "is-active" : ""}
                disabled={operation !== null}
                type="button"
                onClick={() => {
                  setSourceMode("standalone");
                  setProblem(null);
                  setStatus("");
                }}
              >
                独立生成
                <small>直接填写要求，无需创建案件</small>
              </button>
              <button
                aria-pressed={sourceMode === "case"}
                className={sourceMode === "case" ? "is-active" : ""}
                disabled={operation !== null}
                type="button"
                onClick={() => {
                  setSourceMode("case");
                  setProblem(null);
                  setStatus("");
                }}
              >
                使用案件资料
                <small>复用已核验的案件事实和引用</small>
              </button>
            </div>
            {sourceMode === "case" && !projectId ? (
              <p className="notice warning">请先到案件工作台选择需要生成文书的案件。</p>
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
              {sourceMode === "standalone" ? (
                <>
                  <label>
                    文书标题
                    <span className="field-hint">可选；留空时使用模板名称</span>
                    <input
                      disabled={operation !== null}
                      value={standaloneInput.title}
                      onChange={(event) =>
                        updateStandaloneInput("title", event.target.value)
                      }
                      placeholder="例如：关于催付货款的律师函"
                    />
                  </label>
                  <div className="standalone-party-grid">
                    <label>
                      我方或主要主体
                      <input
                        disabled={operation !== null}
                        value={standaloneInput.partyA}
                        onChange={(event) =>
                          updateStandaloneInput("partyA", event.target.value)
                        }
                        placeholder="名称、身份及必要联系方式"
                      />
                    </label>
                    <label>
                      对方或其他主体
                      <input
                        disabled={operation !== null}
                        value={standaloneInput.partyB}
                        onChange={(event) =>
                          updateStandaloneInput("partyB", event.target.value)
                        }
                        placeholder="名称、身份及必要联系方式"
                      />
                    </label>
                  </div>
                  <label>
                    已知事实
                    <textarea
                      disabled={operation !== null}
                      value={standaloneInput.facts}
                      onChange={(event) =>
                        updateStandaloneInput("facts", event.target.value)
                      }
                      placeholder="按时间顺序填写已知事实；每行可填写一个事实"
                      rows={4}
                    />
                  </label>
                  <label>
                    请求、主张或办理目标
                    <textarea
                      disabled={operation !== null}
                      value={standaloneInput.requests}
                      onChange={(event) =>
                        updateStandaloneInput("requests", event.target.value)
                      }
                      placeholder="例如：七日内支付货款及逾期利息"
                      rows={3}
                    />
                  </label>
                  <label>
                    写作要求与其他材料
                    <span className="field-hint">
                      只填写这一项也可以生成；请尽量写明用途、语气和必须包含的内容
                    </span>
                    <textarea
                      disabled={operation !== null}
                      value={standaloneInput.requirements}
                      onChange={(event) =>
                        updateStandaloneInput("requirements", event.target.value)
                      }
                      placeholder="例如：用于庭前沟通，语气正式克制，突出履约经过和付款期限"
                      rows={4}
                    />
                  </label>
                  <details className="document-more-materials">
                    <summary>补充证据或附件说明（可选）</summary>
                    <label>
                      证据及证明目的
                      <textarea
                        disabled={operation !== null}
                        value={standaloneInput.evidence}
                        onChange={(event) =>
                          updateStandaloneInput("evidence", event.target.value)
                        }
                        placeholder="每行填写一项，例如：采购合同——证明合同关系"
                        rows={3}
                      />
                    </label>
                  </details>
                </>
              ) : null}
              <label>
                已有草稿
                <span className="field-hint">可选；将作为待复核内容附在文书中</span>
                <textarea
                  disabled={operation !== null}
                  value={draft}
                  onChange={(event) => {
                    setDraft(event.target.value);
                    setProblem(null);
                  }}
                  placeholder="可粘贴已有草稿或希望保留的原文内容"
                  rows={sourceMode === "standalone" ? 3 : 5}
                />
              </label>
              <p className="field-hint">
                导出时将打开系统“另存为”对话框；系统只保存本次选择的新 PDF 文件，并在导出前再次核对文书内容。
              </p>
            </div>
            <div className="button-row document-actions">
              <button
                type="button"
                onClick={() => void generatePreview()}
                disabled={operation !== null}
              >
                {operation === "preview" ? "正在生成…" : "校验并预览"}
              </button>
              <button
                className="secondary-action"
                type="button"
                onClick={() => void save()}
                disabled={!document || operation !== null}
              >
                {operation === "export" ? "正在导出…" : "导出 PDF"}
              </button>
            </div>
            {status && !problem ? (
              <p className="notice" role="status">
                {status}
              </p>
            ) : null}
          </div>
        </section>

        <section className="document-output" aria-labelledby="document-output-title">
          <div className="document-panel-heading">
            <div>
              <span className="document-step">02</span>
              <h3 id="document-output-title">校验与预览</h3>
            </div>
            <span>{document ? "可以导出" : problem ? "需要补充资料" : "等待生成"}</span>
          </div>
          <div className="document-output__body">
            {problem ? (
              <div className="notice warning document-problem" role="alert">
                <strong>暂时无法生成</strong>
                <p>{problem.message}</p>
                {problem.missingFields.length > 0 ? (
                  <>
                    <p>缺少以下必填内容：</p>
                    <ul>
                      {problem.missingFields.map((field) => (
                        <li key={field}>
                          <span>{formatDocumentFieldLabel(field)}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                ) : null}
                {problem.invalidCitationIds.length > 0 ? (
                  <p>有 {problem.invalidCitationIds.length} 条法律引用未通过本地校验。</p>
                ) : null}
              </div>
            ) : document ? (
              <article className="document-preview">
                <div className="document-preview__toolbar">
                  <div>
                    <h3>{publicTitle(document.title, "法律文书")}</h3>
                    <p>参照人民法院文书常用排版，PDF 将按此内容导出</p>
                  </div>
                </div>
                <div className="document-source-summary">
                  <span>
                    {sourceMode === "standalone"
                      ? `${document.fields.length} 项直接输入`
                      : `${document.sections.flatMap((section) => section.sourceIds).length} 项案件数据`}
                  </span>
                  <span>{document.citations.length} 条已校验法律引用</span>
                </div>
                <LegalMarkdownPreview markdown={document.markdown} />
                {document.citations.length > 0 ? (
                  <>
                    <h4>已校验法律引用</h4>
                    <DocumentCitationList
                      citations={document.citations}
                      onOpenCitation={onOpenCitation}
                    />
                  </>
                ) : null}
              </article>
            ) : (
              <div className="document-empty-state">
                <span aria-hidden="true">文</span>
                <strong>尚未生成预览</strong>
                <p>
                  {sourceMode === "standalone"
                    ? "填写写作要求或已知材料后即可生成，无需先创建案件。"
                    : "选择案件和模板后点击“校验并预览”，生成结果会显示在这里。"}
                </p>
              </div>
            )}
          </div>
        </section>
      </div>
    </section>
  );
}
