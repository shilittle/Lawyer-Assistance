import { ApiClient, ApiError, apiErrorMessage, pathId, queryString, splitIds } from "./api.js";

export const VIEWS = Object.freeze({
  privacy: "材料脱敏",
  legal: "法律检索",
  templates: "文书写作",
  chat: "AI 对话",
  settings: "设置"
});

export const ENTITY_KINDS = Object.freeze([
  "person_name", "organization_name", "address", "phone_number", "email_address",
  "identity_number", "passport_number", "case_number", "bank_account", "landline_number",
  "organization_code", "business_license_number", "vehicle_plate", "ip_address", "social_account",
  "payment_account", "account_name", "contract_number", "tracking_number", "property_certificate_number", "custom"
]);

export function optionalAlias(value) {
  const alias = String(value || "").trim();
  return alias || null;
}

export function materialReviewDecision(finding, alias = finding.alias, dismissed = Boolean(finding.dismissed)) {
  const canDismiss = (finding.source === "local_ner" && ["person_name", "organization_name", "address"].includes(finding.kind)) || (finding.source === "ai" && finding.kind === "custom");
  const ignored = Boolean(dismissed && canDismiss);
  const changed = optionalAlias(alias) !== optionalAlias(finding.alias);
  return {
    canDismiss, ignored,
    dismissedId: ignored ? finding.id : null,
    entry: !ignored && (!finding.resolved || changed || finding.dismissed)
      ? { text: finding.text, kind: finding.kind, alias: optionalAlias(alias) } : null
  };
}

export const STATUS_LABELS = Object.freeze({
  queued: "排队中",
  extracting: "提取中",
  analyzing: "识别中",
  processing: "处理中",
  awaiting_consent: "等待云辅助授权",
  needs_review: "待复核",
  ready: "可用",
  partial: "部分完成",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
  revoked: "已撤销",
  expired: "已过期",
  running: "运行中",
  pending: "等待处理"
});

const AI_STATUS_LABELS = Object.freeze({
  queued: "排队中",
  running: "生成中",
  searching: "检索中",
  writing: "写作中",
  checking: "检查中",
  completed: "已完成",
  ready: "已完成",
  failed: "失败",
  cancelled: "已取消",
  paused: "等待继续",
  interrupted: "已中断，可继续",
  needs_review: "待复核",
  waiting: "等待继续",
  pending: "等待处理"
});

const LEGAL_STATUS_LABELS = Object.freeze({
  in_force: "现行有效",
  amended: "已修订",
  repealed: "已废止",
  expired: "已失效",
  not_yet_effective: "尚未生效",
  draft: "草案",
  unknown: "状态未知"
});

export const AI_RUN_KINDS = Object.freeze({ search: "search", writing: "writing", chat: "chat" });

export const AI_RUN_STATUS_LABELS = AI_STATUS_LABELS;

export const AI_PROVIDER_PRESETS = Object.freeze([
  Object.freeze({ id: "glm", name: "智谱 GLM", preset: "glm", base_url: "https://open.bigmodel.cn/api/paas/v4", domestic: true }),
  Object.freeze({ id: "deepseek", name: "DeepSeek", preset: "deepseek", base_url: "https://api.deepseek.com", domestic: true }),
  Object.freeze({ id: "qwen", name: "通义千问", preset: "qwen", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", domestic: true }),
  Object.freeze({ id: "siliconflow", name: "硅基流动", preset: "siliconflow", base_url: "https://api.siliconflow.cn/v1", domestic: true }),
  Object.freeze({ id: "volcengine", name: "火山方舟", preset: "volcengine", base_url: "https://ark.cn-beijing.volces.com/api/v3", domestic: true }),
  Object.freeze({ id: "kimi", name: "Kimi", preset: "kimi", base_url: "https://api.moonshot.cn/v1", domestic: true }),
  Object.freeze({ id: "custom", name: "自定义兼容服务", preset: "custom", base_url: "", domestic: false })
]);

export function aiRunStatusLabel(status) {
  const key = String(status || "").toLowerCase();
  return AI_STATUS_LABELS[key] || (key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "待核验" : "等待处理");
}

export function legalStatusLabel(status) {
  const key = String(status || "").toLowerCase();
  return LEGAL_STATUS_LABELS[key] || (key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "待核验" : "状态未知");
}

export function aiRunId(run) {
  return textValue(field(run, ["id", "run_id", "runId", "new_run_id", "newRunId"]));
}

export function aiRunKindLabel(kind) {
  const labels = { search: "AI 法律搜索", writing: "文书写作", chat: "AI 对话" };
  return labels[String(kind || "").toLowerCase()] || "AI 任务";
}

export function aiToolLabel(tool) {
  const key = String(tool || "").toLowerCase();
  const labels = { legal_search: "检索法条", legal_get_article: "读取法条正文", legal_get_versions: "读取历史版本", legal_version_articles: "读取历史版本正文", legal_get_relations: "读取关联法规", legal_search_cases: "检索最高法案例", legal_get_case: "读取案例正文" };
  return labels[key] || (key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "读取法律资料" : "完成一步检索");
}

export function aiRunContent(run) {
  return textValue(field(run, ["content", "markdown", "text", "answer", "output"]));
}

export function aiRunTitle(run, fallback = "未命名任务") {
  const value = textValue(field(run, ["title", "name"]));
  return value || fallback;
}

const CITATION_VERIFICATION_STATE_LABELS = Object.freeze({
  passed: "机械校验通过",
  pending: "等待机械复核",
  stale: "正文或日期已变化，待机械复核",
  legacy_pending: "历史记录待机械复核"
});

const CITATION_VERIFICATION_REASON_LABELS = Object.freeze({
  quote_mismatch: "引文与正文未匹配",
  quote_ambiguous: "引文匹配不唯一",
  case_date_unknown: "缺少文书适用日期",
  source_changed: "引用来源已变化",
  source_missing: "引用来源不存在",
  source_full_text_unavailable: "未读取引用来源全文"
});

const CITATION_SOURCE_CHECK_STATES = Object.freeze({
  sourceExists: Object.freeze(["passed", "not_found", "unknown"]),
  fullTextRead: Object.freeze(["passed", "not_read", "unavailable", "not_found", "unknown"]),
  citationMatch: Object.freeze(["matched", "mismatch", "ambiguous", "not_provided", "not_requested", "not_checked", "unknown"]),
  timeCheck: Object.freeze(["passed", "outside_case_date", "outside", "not_applicable", "unknown"])
});

const CITATION_SOURCE_CHECK_LABELS = Object.freeze({
  sourceExists: Object.freeze({ passed: "已找到", not_found: "未找到", unknown: "未核实" }),
  fullTextRead: Object.freeze({ passed: "已读取", not_read: "未读取", unavailable: "全文不可用", not_found: "来源未找到", unknown: "未核实" }),
  citationMatch: Object.freeze({ matched: "已匹配", mismatch: "不匹配", ambiguous: "匹配不唯一", not_provided: "未提供引文", not_requested: "未提供引文", not_checked: "未检查", unknown: "未核实" }),
  timeCheck: Object.freeze({ passed: "通过", outside_case_date: "不在文书日期范围", outside: "不在文书日期范围", not_applicable: "不适用", unknown: "未核实" })
});

const CITATION_SOURCE_ERROR_LABELS = Object.freeze({
  citation_not_found: "未找到引用来源",
  citation_source_unavailable: "引用来源当前不可用"
});

function normalizeCitationCheckState(kind, value) {
  const allowed = CITATION_SOURCE_CHECK_STATES[kind] || [];
  if (allowed.includes(value)) return value;
  // Pre-LA13 records used booleans. Preserve their conservative meaning while
  // the public endpoint uses the stricter string-state contract.
  if (value === true) return kind === "citationMatch" ? "matched" : "passed";
  if (value === false) {
    if (kind === "sourceExists") return "not_found";
    if (kind === "fullTextRead") return "not_read";
    if (kind === "citationMatch") return "mismatch";
  }
  return "unknown";
}

function citationCheckTone(kind, value) {
  const state = normalizeCitationCheckState(kind, value);
  if (["passed", "matched", "not_applicable"].includes(state)) return "passed";
  if (["not_found", "mismatch", "outside_case_date", "outside"].includes(state)) return "failed";
  return state === "unavailable" || state === "ambiguous" ? "warning" : "unknown";
}

function normalizeCitationErrorCategory(value) {
  const category = textValue(value);
  return Object.hasOwn(CITATION_SOURCE_ERROR_LABELS, category) ? category : "";
}

function normalizeSourceContentState(value) {
  return textValue(value) === "changed" ? "changed" : "";
}

function safeVerificationHash(value) {
  const hash = textValue(value).toLowerCase();
  return /^[a-f0-9]{12,128}$/u.test(hash) ? hash : "";
}

function safeCitationLocator(value) {
  const locator = textValue(value);
  if (safeContextLocator(locator)) return locator;
  if (/^law-article:[A-Za-z0-9._~-]+:[A-Za-z0-9._~-]+:[\p{L}\p{N}._~-]{1,80}$/u.test(locator)) return locator;
  return /^judicial-case:[A-Za-z0-9._~-]+$/u.test(locator) ? locator : "";
}

function safeCitationRanges(value) {
  const rows = Array.isArray(value) ? value : [];
  return rows.map((row) => {
    const start = Number(field(row, ["start_byte", "startByte"]));
    const end = Number(field(row, ["end_byte", "endByte"]));
    return Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && end >= start ? { start, end } : null;
  }).filter(Boolean);
}

export function citationVerificationStateLabel(state) {
  return CITATION_VERIFICATION_STATE_LABELS[textValue(state)] || "引用校验状态未核实";
}

export function citationVerificationReasonLabel(reason) {
  return CITATION_VERIFICATION_REASON_LABELS[textValue(reason)] || "需要重新机械核验";
}

export function citationCheckLabel(kind, value) {
  if (value === undefined) return kind === true ? "通过" : kind === false ? "未通过" : "未核实";
  const state = normalizeCitationCheckState(kind, value);
  return CITATION_SOURCE_CHECK_LABELS[kind]?.[state] || "未核实";
}

export function citationErrorCategoryLabel(category) {
  return CITATION_SOURCE_ERROR_LABELS[normalizeCitationErrorCategory(category)] || "";
}

export function normalizeCitationVerification(value) {
  const source = value && typeof value === "object" ? value : {};
  const state = textValue(source.state, "legacy_pending");
  const rawSources = Array.isArray(source.sources) ? source.sources : [];
  return {
    state: Object.hasOwn(CITATION_VERIFICATION_STATE_LABELS, state) ? state : "legacy_pending",
    reasons: (Array.isArray(source.reasons) ? source.reasons : []).map((reason) => textValue(reason)).filter(Boolean),
    bodySha256: safeVerificationHash(source.body_sha256 ?? source.bodySha256),
    runRevision: aiRunRevision(source),
    caseDate: legalDateValue(source.case_date ?? source.caseDate),
    verifiedAt: textValue(source.verified_at ?? source.verifiedAt),
    sources: rawSources.map((item) => ({
      sourceKind: textValue(field(item, ["source_kind", "sourceKind"])),
      sourceId: textValue(field(item, ["source_id", "sourceId"])),
      documentId: textValue(field(item, ["document_id", "documentId"])),
      versionId: textValue(field(item, ["version_id", "versionId"])),
      sourceFullTextSha256: safeVerificationHash(field(item, ["source_full_text_sha256", "sourceFullTextSha256"])),
      citationLocator: safeCitationLocator(field(item, ["citation_locator", "citationLocator"])),
      quoteSha256: safeVerificationHash(field(item, ["quote_sha256", "quoteSha256"])),
      matchedRanges: safeCitationRanges(field(item, ["matched_ranges", "matchedRanges"])),
      sourceExists: normalizeCitationCheckState("sourceExists", field(item, ["source_exists", "sourceExists"])),
      fullTextRead: normalizeCitationCheckState("fullTextRead", field(item, ["full_text_read", "fullTextRead"])),
      citationMatch: normalizeCitationCheckState("citationMatch", field(item, ["citation_match", "citationMatch"])),
      timeCheck: normalizeCitationCheckState("timeCheck", field(item, ["time_check", "timeCheck"])),
      errorCategory: normalizeCitationErrorCategory(field(item, ["error_category", "errorCategory"])),
      sourceContentState: normalizeSourceContentState(field(item, ["source_content", "sourceContent"])),
      relevance: "manual_review_required"
    })).filter((item) => item.sourceKind || item.sourceId || item.documentId)
  };
}

export function normalizeAiRun(run) {
  if (!run || typeof run !== "object") return { id: "", kind: "", status: "failed", stage: "", prompt: "", title: "", content: "", html: "", citations: [], tool_steps: [], error_code: "", usage: null };
  const citations = Array.isArray(run.citations) ? run.citations : Array.isArray(run.references) ? run.references : [];
  const toolSteps = Array.isArray(run.tool_steps) ? run.tool_steps : Array.isArray(run.toolSteps) ? run.toolSteps : [];
  return {
    ...run,
    id: aiRunId(run),
    kind: textValue(field(run, ["kind", "type"])),
    status: textValue(field(run, ["status"]), "pending"),
    stage: textValue(field(run, ["stage", "phase"])),
    prompt: textValue(field(run, ["prompt", "query", "message"])),
    title: aiRunTitle(run, "未命名任务"),
    content: aiRunContent(run),
    html: textValue(field(run, ["html", "rendered_html"])),
    citations,
    citationVerification: normalizeCitationVerification(field(run, ["citation_verification", "citationVerification"])),
    tool_steps: toolSteps,
    error_code: textValue(field(run, ["error_code", "errorCode"])),
    usage: run.usage && typeof run.usage === "object" ? run.usage : null
  };
}

export function normalizeAiRunList(response) {
  const items = Array.isArray(response) ? response : response?.runs || response?.items || response?.tasks || [];
  return Array.isArray(items) ? items.map(normalizeAiRun) : [];
}

export function normalizeCursorPage(response, keys = [], defaults = {}) {
  const source = response && typeof response === "object" ? response : {};
  const names = Array.isArray(keys) ? keys : [keys];
  const rawItems = Array.isArray(response)
    ? response
    : names.map((key) => source[key]).find(Array.isArray) || source.items || [];
  const items = Array.isArray(rawItems) ? rawItems : [];
  const parsedTotal = Number(source.total ?? source.total_items ?? source.totalItems);
  const parsedCorrupt = Number(source.corrupt_count ?? source.corruptCount);
  return {
    items,
    nextCursor: textValue(source.next_cursor ?? source.nextCursor),
    total: Number.isSafeInteger(parsedTotal) && parsedTotal >= 0 ? parsedTotal : (Number(defaults.total) || items.length),
    corruptCount: Number.isSafeInteger(parsedCorrupt) && parsedCorrupt >= 0 ? parsedCorrupt : 0
  };
}

function appendUniqueById(current, next) {
  const result = [];
  const seen = new Set();
  for (const item of [...(Array.isArray(current) ? current : []), ...(Array.isArray(next) ? next : [])]) {
    const id = textValue(field(item, ["id", "run_id", "runId", "material_id", "materialId", "conversation_id", "conversationId"]));
    const key = id || `index:${result.length}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

export function aiRunRevision(run, fallback = 0) {
  const revision = Number(field(run, ["revision", "run_revision", "runRevision"]));
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : fallback;
}

// A document keeps this stable identity as immutable writing versions receive
// new run ids. Older records did not have it, so their own run id remains the
// compatible logical-document identity.
export function writingDocumentId(run) {
  return textValue(field(run, ["document_id", "documentId"])) || aiRunId(run);
}

export function writingDraftIdForRun(run) {
  const documentId = writingDocumentId(run);
  return documentId ? `writing-${documentId}` : "writing-current";
}

export function writingDraftCandidateId(baseId, randomHex = "") {
  const base = textValue(baseId);
  const supplied = String(randomHex || "").toLowerCase();
  let nonce = supplied;
  if (!/^[a-f0-9]{32}$/u.test(nonce)) {
    if (typeof globalThis.crypto?.getRandomValues !== "function") return "";
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    nonce = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
  }
  // ai_draft names are bounded at 80 characters. The canonical writing bases
  // are 44 characters, leaving room for "-c-" and a 128-bit hex nonce.
  return /^[A-Za-z0-9_-]{1,45}$/u.test(base) && /^[a-f0-9]{32}$/u.test(nonce)
    ? `${base}-c-${nonce}`
    : "";
}

function newWritingDraftState(id = "writing-current") {
  return {
    id,
    revision: 0,
    loaded: false,
    timer: null,
    saving: false,
    savingPromise: null,
    clearing: false,
    pending: null,
    sequence: 0,
    retryAttempts: 0,
    retryStopped: false,
    conflicts: [],
    conflictLoadPromise: null,
    conflictNextCursor: "",
    conflictTotal: 0,
    conflictCorruptCount: 0
  };
}

const WRITING_LAST_RUN_STORAGE_KEY = "lawyer-assistance.writing.last-run.v1";

function safeWritingRunPointer(value) {
  const id = textValue(value);
  return /^[A-Za-z0-9_-]{1,64}$/u.test(id) ? id : "";
}

function staleAsyncError() {
  const error = new Error("stale_async_response");
  error.name = "AbortError";
  return error;
}

export function conversationContextRevision(conversation, fallback = 0) {
  const revision = Number(field(conversation, ["context_revision", "contextRevision", "revision"]));
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : fallback;
}

function normalizedDraftContextRanges(value) {
  const rows = Array.isArray(value?.context_ranges ?? value?.contextRanges)
    ? (value.context_ranges ?? value.contextRanges) : [];
  return rows.map((item) => {
    const sourceKind = textValue(field(item, ["source_kind", "sourceKind"]));
    const sourceId = textValue(field(item, ["source_id", "sourceId"]));
    const source = textValue(field(item, ["source"]));
    const mode = textValue(field(item, ["mode"]));
    const ranges = (Array.isArray(item?.ranges) ? item.ranges : []).map((range) => {
      const start = Number(field(range, ["start"]));
      const end = Number(field(range, ["end"]));
      return Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 1 && end >= start ? { start, end } : null;
    }).filter(Boolean);
    const inspectionHash = textValue(field(item, ["inspection_hash", "inspectionHash"]));
    if (!sourceId || !["material", "attachment"].includes(sourceKind)) return null;
    if (sourceKind === "material" && !["original", "redacted"].includes(source)) return null;
    if (!["all", "pages", "paragraphs"].includes(mode)) return null;
    if (mode === "all") return { source_kind: sourceKind, source_id: sourceId, ...(sourceKind === "material" ? { source } : {}), mode };
    if (!ranges.length || !inspectionHash) return null;
    return {
      source_kind: sourceKind,
      source_id: sourceId,
      ...(sourceKind === "material" ? { source } : {}),
      mode,
      ranges,
      inspection_hash: inspectionHash
    };
  }).filter(Boolean);
}

export function writingDraftContent(value = {}) {
  const materials = Array.isArray(value.materials) ? value.materials
    .map((reference) => ({
      id: textValue(field(reference, ["id", "material_id", "materialId"])),
      source: textValue(field(reference, ["source"]))
    }))
    .filter((reference) => reference.id && ["original", "redacted"].includes(reference.source)) : [];
  const attachmentIds = Array.isArray(value.attachment_ids || value.attachmentIds)
    ? (value.attachment_ids || value.attachmentIds).map((id) => textValue(id)).filter(Boolean) : [];
  const runId = textValue(value.run_id ?? value.runId);
  const runRevision = Number(field(value, ["run_revision", "runRevision", "revision"]));
  return {
    document_type: textValue(value.document_type ?? value.documentType),
    prompt: textValue(value.prompt),
    requirements: textValue(value.requirements),
    case_date: textValue(value.case_date ?? value.caseDate),
    provider_id: textValue(value.provider_id ?? value.providerId),
    model: textValue(value.model),
    materials,
    attachment_ids: attachmentIds,
    context_ranges: normalizedDraftContextRanges(value),
    // These are optional as a pair.  JSON null maps to the service's
    // Option fields; an empty string would be an invalid run identifier.
    run_id: runId || null,
    run_revision: runId && Number.isSafeInteger(runRevision) && runRevision >= 0 ? runRevision : null,
    content: textValue(value.content),
    dirty: value.dirty === true
  };
}

export function writingDraftRestorePlan(draft, summaryRun = null, { hasLocalInput = false } = {}) {
  const snapshot = writingDraftContent(draft);
  if (hasLocalInput || !snapshot.dirty || !snapshot.run_id || !snapshot.content) return null;
  const fallbackRevision = aiRunRevision(summaryRun, null);
  const expectedRevision = Number.isSafeInteger(snapshot.run_revision) && snapshot.run_revision >= 0
    ? snapshot.run_revision
    : Number.isSafeInteger(fallbackRevision) && fallbackRevision >= 0 ? fallbackRevision : null;
  return { runId: snapshot.run_id, expectedRevision, content: snapshot.content };
}

export const AI_RUN_POLL_MAX_CONSECUTIVE_FAILURES = 5;
export const AI_RUN_POLL_RETRY_BASE_DELAY_MS = 1500;
export const AI_RUN_POLL_RETRY_MAX_DELAY_MS = 30000;

export function isRetryableAiPollError(error) {
  return Boolean(error instanceof ApiError && error.retryable && ![401, 403, 404].includes(error.status));
}

export function aiRunPollBackoffDelay(consecutiveFailures, { baseDelayMs = AI_RUN_POLL_RETRY_BASE_DELAY_MS, maxDelayMs = AI_RUN_POLL_RETRY_MAX_DELAY_MS } = {}) {
  const failures = Math.max(1, Number.isSafeInteger(Number(consecutiveFailures)) ? Number(consecutiveFailures) : 1);
  const base = Math.max(1, Number(baseDelayMs) || AI_RUN_POLL_RETRY_BASE_DELAY_MS);
  const max = Math.max(base, Number(maxDelayMs) || AI_RUN_POLL_RETRY_MAX_DELAY_MS);
  return Math.min(max, base * (2 ** (failures - 1)));
}

// One poller owns at most one in-flight request per run. Views subscribe with a
// scope and dispose that scope when their DOM is replaced, so detached panels
// cannot keep mutating application state or retrying a terminal HTTP error.
export class AiRunPoller {
  constructor({ getRun, onRun = () => {}, setTimer = globalThis.setTimeout.bind(globalThis), clearTimer = globalThis.clearTimeout.bind(globalThis), maxConsecutiveFailures = AI_RUN_POLL_MAX_CONSECUTIVE_FAILURES, retryBaseDelayMs = AI_RUN_POLL_RETRY_BASE_DELAY_MS, retryMaxDelayMs = AI_RUN_POLL_RETRY_MAX_DELAY_MS } = {}) {
    this.getRun = getRun;
    this.onRun = onRun;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.maxConsecutiveFailures = Math.max(1, Number(maxConsecutiveFailures) || AI_RUN_POLL_MAX_CONSECUTIVE_FAILURES);
    this.retryBaseDelayMs = Math.max(1, Number(retryBaseDelayMs) || AI_RUN_POLL_RETRY_BASE_DELAY_MS);
    this.retryMaxDelayMs = Math.max(this.retryBaseDelayMs, Number(retryMaxDelayMs) || AI_RUN_POLL_RETRY_MAX_DELAY_MS);
    this.entries = new Map();
  }

  subscribe(id, { scope = "default", onUpdate, onDone, onError } = {}) {
    const key = String(id || "");
    if (!key) return () => {};
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { id: key, listeners: new Map(), timer: null, controller: null, inFlight: false, generation: 0, consecutiveFailures: 0 };
      this.entries.set(key, entry);
    }
    entry.listeners.set(scope, { onUpdate, onDone, onError });
    if (!entry.inFlight && !entry.timer) this.#poll(entry);
    return () => this.unsubscribe(key, scope);
  }

  unsubscribe(id, scope) {
    const entry = this.entries.get(String(id || ""));
    if (!entry) return;
    entry.listeners.delete(scope);
    if (!entry.listeners.size) this.stop(entry.id);
  }

  disposeScope(scope) {
    for (const [id, entry] of this.entries) {
      entry.listeners.delete(scope);
      if (!entry.listeners.size) this.stop(id);
    }
  }

  stop(id) {
    const entry = this.entries.get(String(id || ""));
    if (!entry) return;
    entry.generation += 1;
    if (entry.timer) this.clearTimer(entry.timer);
    entry.timer = null;
    entry.controller?.abort();
    entry.controller = null;
    this.entries.delete(entry.id);
  }

  #emit(entry, kind, ...values) {
    for (const listener of [...entry.listeners.values()]) listener[kind]?.(...values);
  }

  #schedule(entry, delay) {
    if (this.entries.get(entry.id) !== entry || !entry.listeners.size) return;
    entry.timer = this.setTimer(() => {
      entry.timer = null;
      this.#poll(entry);
    }, delay);
  }

  #poll(entry) {
    if (this.entries.get(entry.id) !== entry || entry.inFlight || !entry.listeners.size) return;
    const generation = ++entry.generation;
    const controller = new AbortController();
    entry.controller = controller;
    entry.inFlight = true;
    // Capture a synchronous getRun throw in the same bounded failure path,
    // while still starting an ordinary request immediately for subscribers.
    let request;
    try {
      request = this.getRun(entry.id, { signal: controller.signal });
    } catch (error) {
      request = Promise.reject(error);
    }
    Promise.resolve(request)
      .then((run) => {
        if (this.entries.get(entry.id) !== entry || entry.generation !== generation) return;
        entry.consecutiveFailures = 0;
        this.onRun(run);
        this.#emit(entry, "onUpdate", run);
        if (aiRunIsTerminal(run)) {
          this.#emit(entry, "onDone", run);
          this.stop(entry.id);
        } else this.#schedule(entry, 1500);
      })
      .catch((error) => {
        if (this.entries.get(entry.id) !== entry || entry.generation !== generation || error?.name === "AbortError") return;
        const retryable = isRetryableAiPollError(error);
        entry.consecutiveFailures += 1;
        const exhausted = !retryable || entry.consecutiveFailures >= this.maxConsecutiveFailures;
        const retryDelayMs = retryable && !exhausted
          ? aiRunPollBackoffDelay(entry.consecutiveFailures, { baseDelayMs: this.retryBaseDelayMs, maxDelayMs: this.retryMaxDelayMs })
          : null;
        this.#emit(entry, "onError", error, { retryable, consecutiveFailures: entry.consecutiveFailures, maxConsecutiveFailures: this.maxConsecutiveFailures, retryDelayMs, exhausted });
        if (retryDelayMs !== null) this.#schedule(entry, retryDelayMs);
        else this.stop(entry.id);
      })
      .finally(() => {
        if (this.entries.get(entry.id) === entry && entry.generation === generation) {
          entry.inFlight = false;
          entry.controller = null;
        }
      });
  }
}

export function aiRunElapsedSeconds(run, now = Date.now()) {
  const created = Number(field(run, ["created_at", "createdAt"]));
  if (!Number.isFinite(created) || created <= 0) return null;
  const createdMs = created > 1e12 ? created : created * 1000;
  const elapsed = Math.floor((Number(now) - createdMs) / 1000);
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : 0;
}

export function aiRunProgress(run) {
  const status = String(field(run, ["status"], "pending")).toLowerCase();
  const stage = String(field(run, ["stage", "phase"]));
  if (["completed", "ready"].includes(status)) return 100;
  if (["failed", "cancelled"].includes(status)) return 0;
  if (status === "queued" || status === "pending") return 5;
  if (/读取材料|提取/u.test(stage)) return 20;
  if (/写作|成文/u.test(stage)) return 70;
  if (/检查|核验/u.test(stage)) return 85;
  if (/分析|检索|法律/u.test(stage)) return 50;
  return 30;
}

export function aiRunProgressText(run) {
  const elapsed = aiRunElapsedSeconds(run);
  const parts = [`进度 ${aiRunProgress(run)}%`];
  if (elapsed !== null) parts.push(`已用 ${elapsed} 秒`);
  return parts.join(" · ");
}

export function aiRunIsTerminal(run) {
  return ["completed", "ready", "failed", "cancelled", "needs_review", "paused", "interrupted"].includes(String(field(run, ["status"], "")).toLowerCase());
}

export function normalizeAiMaterials(response) {
  const items = Array.isArray(response) ? response : response?.materials || response?.items || [];
  return Array.isArray(items) ? items.map((material) => ({
    ...material,
    id: textValue(field(material, ["id", "material_id", "materialId"])),
    name: materialName(material),
    group_id: textValue(field(material, ["group_id", "groupId"])),
    group_name: textValue(field(material, ["group_name", "groupName"])),
    status: textValue(field(material, ["status"]), "unknown"),
    result_id: resultId(material),
    has_original: material.has_original === true || material.hasOriginal === true
  })).filter((material) => material.id) : [];
}

export const LEGAL_FILTER_OPTIONS = Object.freeze({
  type: Object.freeze([
    ["", "全部类型"],
    ["law", "法律"],
    ["regulation", "行政法规"],
    ["local", "地方性法规"],
    ["department", "部门规章"],
    ["judicial_interpretation", "司法解释"],
    ["other", "其他规范性文件"]
  ]),
  level: Object.freeze([
    ["", "全部效力层级"],
    ["constitution", "宪法"],
    ["law", "法律"],
    ["administrative", "行政法规"],
    ["local", "地方性法规"],
    ["department", "部门规章"]
  ]),
  status: Object.freeze([
    ["", "全部状态"],
    ["in_force", "现行有效"],
    ["amended", "已修订"],
    ["repealed", "已废止"],
    ["expired", "已失效"]
  ]),
  sort: Object.freeze([
    ["relevance", "相关性（默认）"],
    ["effectiveness", "效力层级"],
    ["published_date", "公布日期（新→旧）"],
    ["effective_date", "施行日期（新→旧）"]
  ]),
  view: Object.freeze([
    ["grouped", "按法律归组"],
    ["flat", "逐条浏览"]
  ])
});

const LEGAL_FACET_LABELS = Object.freeze({
  type: Object.freeze({ law: "法律", regulation: "行政法规", administrative_regulation: "行政法规", local: "地方性法规", local_regulation: "地方性法规", local_government_rule: "地方政府规章", department: "部门规章", department_rule: "部门规章", judicial_interpretation: "司法解释", legal_interpretation: "司法解释", autonomous_regulation: "自治条例和单行条例", special_zone_regulation: "经济特区法规", supervision_regulation: "监察法规", decision: "决定", constitution: "宪法", legal_document: "法律文件", other: "其他规范性文件" }),
  level: Object.freeze({ constitution: "宪法", law: "法律", national_law: "法律", administrative: "行政法规", administrative_regulation: "行政法规", local: "地方性法规", local_regulation: "地方性法规", local_government_rule: "地方政府规章", department: "部门规章", department_rule: "部门规章", judicial_interpretation: "司法解释", legal_interpretation: "司法解释", legal_document: "法律文件" }),
  status: Object.freeze({ in_force: "现行有效", amended: "已修订", repealed: "已废止", expired: "已失效", not_yet_effective: "尚未生效", unspecified: "未标注" })
});

export function legalFacetLabel(kind, value) {
  const text = textValue(value);
  return LEGAL_FACET_LABELS[kind]?.[text] || (text && /[\u3400-\u9fff]/u.test(text) ? text : text || "未知");
}

const LEGAL_MATCH_MODES = Object.freeze(["all", "any", "phrase"]);
const LEGAL_VERSION_SCOPES = Object.freeze(["current", "as_of", "all"]);

export function legalDateValue(value) {
  const date = String(value || "").trim();
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(date);
  if (!match) return "";
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || year < 1 || month < 1 || month > 12 || day < 1) return "";
  const monthDays = [31, (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= monthDays[month - 1] ? date : "";
}

export function legalMatchMode(value) {
  const mode = String(value || "").trim();
  return LEGAL_MATCH_MODES.includes(mode) ? mode : "all";
}

export function legalVersionScope(value) {
  const scope = String(value || "").trim();
  return LEGAL_VERSION_SCOPES.includes(scope) ? scope : "current";
}

export function legalScopedReadParams(appliedQuery = {}) {
  const scope = legalVersionScope(appliedQuery?.versionScope ?? appliedQuery?.version_scope);
  const asOf = scope === "as_of" ? legalDateValue(appliedQuery?.asOf ?? appliedQuery?.as_of ?? appliedQuery?.caseDate ?? appliedQuery?.case_date) : "";
  return {
    versionScope: scope,
    ...(asOf ? { caseDate: asOf } : {})
  };
}

export function legalQueryScopeSummary(query = {}, { unknown = "该历史任务未记录检索范围。" } = {}) {
  const source = query && typeof query === "object" ? query : {};
  const recorded = ["match_mode", "matchMode", "version_scope", "versionScope", "version_status", "versionStatus", "case_date", "caseDate", "as_of", "asOf"].some((key) => Object.hasOwn(source, key));
  if (!recorded) return unknown;
  const matchMode = legalMatchMode(field(source, ["match_mode", "matchMode"]));
  const versionScope = legalVersionScope(field(source, ["version_scope", "versionScope"]));
  const caseDate = versionScope === "as_of" ? legalDateValue(field(source, ["case_date", "caseDate", "as_of", "asOf"])) : "";
  const versionStatus = textValue(field(source, ["version_status", "versionStatus"]));
  const matchText = matchMode === "any" ? "任一词匹配" : matchMode === "phrase" ? "完整短语匹配" : "全部词均匹配";
  const scopeText = versionScope === "as_of" ? `适用日期 ${caseDate || "未知"}` : versionScope === "all" ? "全部版本" : "当前有效版本";
  return `检索条件：${matchText} · ${scopeText}${versionStatus ? ` · 状态 ${legalStatusLabel(versionStatus)}` : ""}`;
}

const CONTEXT_BUDGET_STAGE_LABELS = Object.freeze({
  ready: "预检通过",
  conservative: "保守预检",
  scope_required: "需要缩小范围",
  budget_exceeded: "超出上下文预算"
});

const CONTEXT_OMISSION_REASON_LABELS = Object.freeze({
  budget_cut: "受预算限制未采用",
  metadata_unknown: "元数据不足，未读取正文",
  ocr_page_scope_required: "材料超出预算，请拆分文件或减少材料",
  no_relevant_segment: "未找到相关片段",
  history_budget_cut: "受历史范围预算限制未采用"
});

function boundedTokenCount(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}

function safeContextLocator(value) {
  const locator = textValue(value);
  return /^(?:page|paragraph|docx-image):[1-9]\d*$|^line:[1-9]\d*-[1-9]\d*$/u.test(locator) ? locator : "";
}

function normalizeContextScopeItems(value, kind) {
  const rows = Array.isArray(value) ? value : [];
  return rows.map((item) => ({
    // Context plans use source_id/source_kind, while older estimate payloads
    // used their type-specific ids. Accept both without inventing a source.
    id: textValue(field(item, ["id", "source_id", "sourceId", "material_id", "materialId", "attachment_id", "attachmentId", "run_id", "runId"])),
    source: textValue(field(item, ["source"])),
    format: textValue(field(item, ["format", "content_type", "contentType"])),
    locators: (Array.isArray(item?.locators) ? item.locators : []).map(safeContextLocator).filter(Boolean),
    kind
  })).filter((item) => item.id || item.locators.length);
}

export function contextBudgetStageLabel(stage) {
  return CONTEXT_BUDGET_STAGE_LABELS[textValue(stage)] || "预检状态未核实";
}

export function contextOmissionReasonLabel(reason) {
  return CONTEXT_OMISSION_REASON_LABELS[textValue(reason)] || "未采用原因未核实";
}

export function normalizeAiContextEstimate(value) {
  const source = value && typeof value === "object" ? value : {};
  const rawCapabilities = source.capabilities && typeof source.capabilities === "object" ? source.capabilities : {};
  const rawEstimate = source.estimate && typeof source.estimate === "object" ? source.estimate : {};
  const selected = source.selected_scope && typeof source.selected_scope === "object" ? source.selected_scope : source.selectedScope && typeof source.selectedScope === "object" ? source.selectedScope : {};
  const omitted = Array.isArray(source.omitted_scope) ? source.omitted_scope : Array.isArray(source.omittedScope) ? source.omittedScope : [];
  const stage = textValue(source.stage, "conservative");
  return {
    providerId: textValue(source.provider_id ?? source.providerId),
    model: textValue(source.model),
    planHash: textValue(source.plan_hash ?? source.planHash),
    stage: Object.hasOwn(CONTEXT_BUDGET_STAGE_LABELS, stage) ? stage : "conservative",
    capabilities: {
      verified: rawCapabilities.verified === true,
      maxInputTokens: boundedTokenCount(rawCapabilities.max_input_tokens ?? rawCapabilities.maxInputTokens),
      maxOutputTokens: boundedTokenCount(rawCapabilities.max_output_tokens ?? rawCapabilities.maxOutputTokens),
      supportsTools: rawCapabilities.supports_tools === true || rawCapabilities.supportsTools === true,
      supportsStructuredOutput: rawCapabilities.supports_structured_output === true || rawCapabilities.supportsStructuredOutput === true,
      supportsVision: rawCapabilities.supports_vision === true || rawCapabilities.supportsVision === true
    },
    estimate: {
      inputTokens: boundedTokenCount(rawEstimate.input_tokens ?? rawEstimate.inputTokens),
      reservedOutputTokens: boundedTokenCount(rawEstimate.reserved_output_tokens ?? rawEstimate.reservedOutputTokens),
      historyTokens: boundedTokenCount(rawEstimate.history_tokens ?? rawEstimate.historyTokens),
      materialTokens: boundedTokenCount(rawEstimate.material_tokens ?? rawEstimate.materialTokens),
      attachmentTokens: boundedTokenCount(rawEstimate.attachment_tokens ?? rawEstimate.attachmentTokens),
      toolReserveTokens: boundedTokenCount(rawEstimate.tool_reserve_tokens ?? rawEstimate.toolReserveTokens)
    },
    selectedScope: {
      materials: normalizeContextScopeItems(selected.materials, "material"),
      attachments: normalizeContextScopeItems(selected.attachments, "attachment"),
      historyRunIds: Array.isArray(selected.history_run_ids ?? selected.historyRunIds) ? (selected.history_run_ids ?? selected.historyRunIds).map((id) => textValue(id)).filter(Boolean) : []
    },
    omittedScope: omitted.map((item) => ({
      sourceKind: textValue(field(item, ["source_kind", "sourceKind"])),
      sourceId: textValue(field(item, ["source_id", "sourceId"])),
      reason: textValue(field(item, ["reason"])),
      estimatedTokens: boundedTokenCount(field(item, ["estimated_tokens", "estimatedTokens"]))
    })).filter((item) => item.sourceKind || item.sourceId || item.reason)
  };
}

export function contextEstimateCanProceed(estimate) {
  return ["ready", "conservative"].includes(normalizeAiContextEstimate(estimate).stage);
}

export function modelCapabilitiesPayload(value = {}) {
  const source = value && typeof value === "object" ? value : {};
  const contextWindow = boundedTokenCount(source.context_window_tokens ?? source.contextWindowTokens);
  const maxOutput = boundedTokenCount(source.max_output_tokens ?? source.maxOutputTokens);
  const triState = (names, presenceName) => {
    const selected = field(source, names);
    // Editing state carries an explicit touched bit.  Existing declarations
    // are shown in the picker but must not be re-submitted just because a
    // user changed capacity; that would falsely mark a legacy field reviewed.
    const present = Object.hasOwn(source, presenceName)
      ? source[presenceName] === true
      : names.some((name) => Object.hasOwn(source, name));
    return { present, value: selected === true ? true : selected === false ? false : null };
  };
  const supportsTools = triState(["supports_tools", "supportsTools"], "supportsToolsPresent");
  const supportsStructuredOutput = triState(["supports_structured_output", "supportsStructuredOutput"], "supportsStructuredOutputPresent");
  const supportsVision = triState(["supports_vision", "supportsVision"], "supportsVisionPresent");
  const hasCapacity = Boolean(contextWindow || maxOutput);
  const hasFeatureDeclaration = [supportsTools, supportsStructuredOutput, supportsVision].some((item) => item.present);
  if (!hasCapacity && !hasFeatureDeclaration) return null;
  // Capacity is declared as one bound pair. Feature declarations are
  // independent tri-state facts: unknown must not be serialized as false.
  if (hasCapacity && (!contextWindow || !maxOutput || maxOutput >= contextWindow)) return null;
  return {
    ...(hasCapacity ? { context_window_tokens: contextWindow, max_output_tokens: maxOutput } : {}),
    ...(supportsTools.present ? { supports_tools: supportsTools.value } : {}),
    ...(supportsStructuredOutput.present ? { supports_structured_output: supportsStructuredOutput.value } : {}),
    ...(supportsVision.present ? { supports_vision: supportsVision.value } : {})
  };
}

function contextRangeSourceKey(source) {
  const kind = textValue(source?.source_kind ?? source?.sourceKind);
  const id = textValue(source?.source_id ?? source?.sourceId);
  const variant = kind === "material" ? textValue(source?.source) : "";
  return kind && id ? `${kind}:${id}:${variant}` : "";
}

function contextRangeSources(materials, attachmentIds) {
  const sourceRows = [];
  const seen = new Set();
  for (const material of Array.isArray(materials) ? materials : []) {
    const source = {
      source_kind: "material",
      source_id: textValue(field(material, ["id", "material_id", "materialId"])),
      source: textValue(field(material, ["source"]))
    };
    const key = contextRangeSourceKey(source);
    if (key && !seen.has(key)) {
      seen.add(key);
      sourceRows.push(source);
    }
  }
  for (const attachment of Array.isArray(attachmentIds) ? attachmentIds : []) {
    const source = { source_kind: "attachment", source_id: textValue(attachment) };
    const key = contextRangeSourceKey(source);
    if (key && !seen.has(key)) {
      seen.add(key);
      sourceRows.push(source);
    }
  }
  return sourceRows;
}

export function parseContextUnitRanges(value, { max = 0 } = {}) {
  const raw = textValue(value).trim();
  if (!raw) return [];
  const ranges = [];
  for (const part of raw.split(/[,，\s]+/u).filter(Boolean)) {
    const match = /^(\d+)(?:\s*[-–]\s*(\d+))?$/u.exec(part);
    if (!match) return null;
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 1 || end < start || (max && end > max)) return null;
    ranges.push({ start, end });
  }
  return ranges;
}

export function legalSearchPageParams({ query = "", documentId = "", caseDate = "", matchMode = "all", versionScope = "current", versionStatus = "", type = "", level = "", region = "", status = "", sort = "relevance", view = "grouped", pageSize = 20, offset = 0, includeHistory = true, includeRelations = true } = {}) {
  const safePageSize = Math.max(1, Math.min(100, Number.isFinite(Number(pageSize)) ? Math.floor(Number(pageSize)) : 20));
  const safeOffset = Math.max(0, Number.isFinite(Number(offset)) ? Math.floor(Number(offset)) : 0);
  const scope = legalVersionScope(versionScope);
  const asOf = scope === "as_of" ? legalDateValue(caseDate) : "";
  return {
    query: String(query || "").trim(),
    ...(String(documentId || "").trim() ? { document_id: String(documentId).trim() } : {}),
    ...(asOf ? { case_date: asOf } : {}),
    matchMode: legalMatchMode(matchMode),
    versionScope: scope,
    ...(scope !== "current" && String(versionStatus || "").trim() ? { versionStatus: String(versionStatus).trim() } : {}),
    ...(String(type || "").trim() ? { document_type: String(type).trim() } : {}),
    ...(String(level || "").trim() ? { effectiveness_level: String(level).trim() } : {}),
    ...(String(region || "").trim() ? { jurisdiction: String(region).trim() } : {}),
    ...(String(status || "").trim() ? { status: String(status).trim() } : {}),
    sort: String(sort || "relevance"),
    view: String(view || "grouped"),
    limit: safePageSize,
    offset: safeOffset
  };
}

function cssPixelValue(value) {
  const parsed = Number.parseFloat(String(value || ""));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function visiblePageRows(target) {
  if (!target) return [];
  return [...(target.children || [])].filter((child) => {
    if (!child || child.hidden || child.classList?.contains("empty-state") || child.classList?.contains("status-message") || typeof child.getBoundingClientRect !== "function") return false;
    const rect = child.getBoundingClientRect();
    return Number.isFinite(rect.height) && rect.height > 1;
  });
}

export function adaptiveLegalPageSize(target, fallback = 12) {
  const safeFallback = Math.max(1, Math.min(100, Number.isFinite(Number(fallback)) ? Math.floor(Number(fallback)) : 12));
  if (!target) return safeFallback;
  const style = typeof globalThis.getComputedStyle === "function" ? globalThis.getComputedStyle(target) : null;
  const rect = typeof target.getBoundingClientRect === "function" ? target.getBoundingClientRect() : null;
  const computedHeight = cssPixelValue(style?.height);
  const clientHeight = Number(target.clientHeight);
  const rectHeight = Number(rect?.height);
  const viewportHeight = Number(globalThis.window?.innerHeight);
  const viewportRemaining = Number.isFinite(viewportHeight) && Number.isFinite(Number(rect?.top))
    ? Math.max(0, viewportHeight - Number(rect.top) - 24)
    : 0;
  const height = computedHeight || (Number.isFinite(clientHeight) && clientHeight > 0 ? clientHeight : 0)
    || (Number.isFinite(rectHeight) && rectHeight > 0 ? rectHeight : 0)
    || viewportRemaining;
  if (!Number.isFinite(height) || height <= 0) return safeFallback;

  const rows = visiblePageRows(target);
  const measuredRowHeight = rows.reduce((largest, row) => {
    const rowRect = row.getBoundingClientRect();
    const rowHeight = Number(rowRect.height) || Number(row.offsetHeight) || 0;
    return Math.max(largest, rowHeight);
  }, 0);
  const fallbackRowHeight = cssPixelValue(target.dataset?.rowHeight) || 84;
  const rowHeight = measuredRowHeight || fallbackRowHeight;
  const rowGap = cssPixelValue(style?.rowGap || style?.gap);
  const count = Math.floor((height + rowGap) / (rowHeight + rowGap));
  return Math.max(1, Math.min(100, count || 1));
}

export function normalizeLegalPageResponse(response, defaults = {}) {
  const root = response?.page && typeof response.page === "object" ? response.page : response?.data && typeof response.data === "object" ? response.data : response && typeof response === "object" ? response : {};
  const rawItems = root.items || root.articles || root.results || [];
  const groups = Array.isArray(root.groups) ? root.groups : Array.isArray(root.laws) ? root.laws : Array.isArray(response?.groups) ? response.groups : Array.isArray(response?.laws) ? response.laws : [];
  const items = Array.isArray(rawItems) ? rawItems : [];
  const parsedLimit = Number(root.page_size ?? root.pageSize ?? root.limit ?? defaults.pageSize);
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(100, Math.floor(parsedLimit)) : 20;
  const parsedOffset = Number(root.offset);
  const parsedPage = Number(root.page);
  const offset = Number.isFinite(parsedOffset) && parsedOffset >= 0
    ? Math.floor(parsedOffset)
    : Number.isFinite(parsedPage) && parsedPage > 0 ? (Math.floor(parsedPage) - 1) * limit : Math.max(0, Number(defaults.offset) || 0);
  const parsedTotal = Number(root.total ?? root.total_items ?? root.totalItems ?? root.count);
  const total = Number.isFinite(parsedTotal) && parsedTotal >= 0 ? Math.floor(parsedTotal) : items.length;
  const parsedTotalLaws = Number(root.total_laws ?? root.totalLaws);
  const parsedTotalArticles = Number(root.total_articles ?? root.totalArticles);
  const rawAppliedQuery = root.appliedQuery && typeof root.appliedQuery === "object"
    ? root.appliedQuery
    : response?.appliedQuery && typeof response.appliedQuery === "object" ? response.appliedQuery : {};
  const rawAmbiguities = Array.isArray(root.ambiguities) ? root.ambiguities : Array.isArray(response?.ambiguities) ? response.ambiguities : [];
  const ambiguities = rawAmbiguities.map((ambiguity) => {
    const candidates = Array.isArray(ambiguity?.candidates) ? ambiguity.candidates.map((candidate) => ({
      documentId: textValue(field(candidate, ["documentId", "document_id", "id"])),
      title: textValue(field(candidate, ["title", "documentTitle", "document_title", "name"]))
    })).filter((candidate) => candidate.documentId) : [];
    return { query: textValue(field(ambiguity, ["query"])), candidates };
  }).filter((ambiguity) => ambiguity.candidates.length);
  return {
    schemaVersion: textValue(root.schemaVersion ?? root.schema_version),
    items,
    groups,
    total,
    totalLaws: Number.isFinite(parsedTotalLaws) && parsedTotalLaws >= 0 ? Math.floor(parsedTotalLaws) : (textValue(root.view, defaults.view || "grouped") === "grouped" ? total : groups.length),
    totalArticles: Number.isFinite(parsedTotalArticles) && parsedTotalArticles >= 0 ? Math.floor(parsedTotalArticles) : (textValue(root.view, defaults.view || "grouped") === "flat" ? total : 0),
    totalGroups: Number(root.total_groups ?? root.totalGroups ?? groups.length) || groups.length,
    limit,
    offset,
    view: textValue(root.view, defaults.view || "grouped"),
    databaseVersion: textValue(root.databaseVersion ?? root.database_version),
    warnings: caseTextList(root.warnings),
    hasMore: root.has_more === true || root.hasMore === true || offset + limit < total,
    appliedQuery: {
      matchMode: legalMatchMode(field(rawAppliedQuery, ["matchMode", "match_mode"], defaults.matchMode || "all")),
      versionScope: legalVersionScope(field(rawAppliedQuery, ["versionScope", "version_scope"], defaults.versionScope || "current")),
      asOf: legalDateValue(field(rawAppliedQuery, ["asOf", "as_of", "caseDate", "case_date"], defaults.caseDate || "")),
      resolvedDocumentId: textValue(field(rawAppliedQuery, ["resolvedDocumentId", "resolved_document_id", "documentId", "document_id"])),
      exactArticleNumber: textValue(field(rawAppliedQuery, ["exactArticleNumber", "exact_article_number"]))
    },
    ambiguities
  };
}

export function aiMaterialSource(material, preferRedacted = true) {
  if (preferRedacted && (material?.result_id || material?.resultId)) return "redacted";
  return "original";
}

export function providerTrustLabel(provider) {
  if (provider?.trust_raw === true || provider?.trustRaw === true) return "国内供应商：允许发送原文";
  if (provider?.trust_raw === false || provider?.trustRaw === false) return "默认使用脱敏材料";
  return "需确认原文发送策略";
}

function normalizedProviderBaseUrl(value) {
  const raw = textValue(value).trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return "";
    let pathname = parsed.pathname.replace(/\/+$/u, "");
    pathname = pathname.replace(/\/(?:chat\/completions|responses|models)$/iu, "").replace(/\/+$/u, "");
    return `${parsed.protocol}//${parsed.host}${pathname}`.toLowerCase();
  } catch {
    return raw.replace(/\/+$/u, "").toLowerCase();
  }
}

export function providerPresetForBaseUrl(value) {
  const normalized = normalizedProviderBaseUrl(value);
  if (!normalized) return null;
  return AI_PROVIDER_PRESETS.find((item) => item.base_url && normalizedProviderBaseUrl(item.base_url) === normalized) || null;
}

export function providerModelIds(provider) {
  const configured = field(provider, ["enabled_models", "enabledModels"], []);
  const values = Array.isArray(configured) ? configured : [];
  const fallback = textValue(field(provider, ["model"]));
  return [...new Set([...values, fallback].map((value) => textValue(value).trim()).filter(Boolean))];
}

export function aiDefaultSelection(defaults, purpose) {
  const selection = defaults && typeof defaults === "object" ? defaults[purpose] : null;
  return {
    providerId: textValue(field(selection, ["provider_id", "providerId"])),
    model: textValue(field(selection, ["model"]))
  };
}

export function markdownPlainText(markdown) {
  return String(markdown || "")
    .replace(/```[\s\S]*?```/gu, (block) => block.replace(/^```[^\n]*\n?/u, "").replace(/```$/u, ""))
    .replace(/^#{1,6}\s*/gmu, "")
    .replace(/^[ \t]*[-*+][ \t]+/gmu, "")
    .replace(/^[ \t]*\d+[.)][ \t]+/gmu, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/gu, "$1")
    .replace(/[*_`~]/gu, "")
    .replace(/\n{3,}/gu, "\n\n")
    .trim();
}

export function statusLabel(status) {
  const key = String(status || "").toLowerCase();
  return STATUS_LABELS[key] || (key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "待核验" : "未知状态");
}

const REASON_LABELS = Object.freeze({
  ai_dispatch_interrupted: "AI 任务中断",
  cloud_dispatch_interrupted: "云辅助任务中断",
  cloud_consent_required: "需要授权云辅助",
  cloud_authorization_revoked: "云辅助授权已撤销",
  cloud_authorization_changed: "云辅助授权已变化，需要重新处理",
  cloud_response_invalid: "云端模型结果无法核验",
  manual_review_required: "需要人工复核",
  dictionary_changed: "分组词典已变化，需要重新处理",
  cancelled: "任务已取消",
  material_changed: "材料在处理期间发生变化",
  provider_changed: "模型服务配置已变化，需要重新处理",
  result_expired: "脱敏结果已过期",
  result_revoked: "脱敏结果已撤销",
  result_not_ready: "脱敏结果尚未准备好",
  result_integrity_failed: "脱敏结果校验失败",
  source_integrity_failed: "原始文件校验失败",
  extraction_failed: "文件提取失败",
  redaction_failed: "脱敏识别失败",
  redaction_requires_trusted_provider: "需要可信模型服务",
  sensitive_content_blocked: "残留敏感信息检查未通过",
  provider_network_failed: "模型服务网络连接失败",
  provider_timeout: "模型服务响应超时",
  ocr_model_not_configured: "未配置 OCR 模型",
  ocr_requires_trusted_provider: "OCR 模型服务未确认可发送原文",
  ocr_asset_limit_exceeded: "OCR 文件页数或大小超过限制",
  ocr_response_invalid: "OCR 返回无效",
  ocr_incomplete: "OCR 返回不完整",
  ai_response_invalid: "模型结果无法核验",
  ai_review_evidence_missing: "请重新处理材料后复核",
  review_evidence_invalid: "复核记录与原文不一致",
  ai_run_reauthorization_required: "继续任务前需要重新确认材料发送策略"
});

export function reasonLabel(reason) {
  const key = String(reason || "").trim();
  return REASON_LABELS[key] || (key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "需要核验" : "");
}

export function pipelineStageLabel(stage) {
  const key = String(stage || "").trim().toLowerCase();
  const labels = { ocr_running: "视觉 OCR 识别中", text_ready: "文本提取完成", redaction_running: "模型脱敏识别中", needs_review: "待复核", completed: "处理完成", failed: "处理失败", interrupted: "已中断，可继续" };
  return labels[key] || (stage && /[\u3400-\u9fff]/u.test(String(stage)) ? String(stage) : key ? "处理中" : "");
}

export function materialStatusTone(status) {
  const key = String(status || "").toLowerCase();
  if (["ready", "completed"].includes(key)) return "success";
  if (["failed", "revoked", "expired"].includes(key)) return "danger";
  if (["needs_review", "awaiting_consent", "partial"].includes(key)) return "warning";
  return "info";
}

export function field(object, keys, fallback = "") {
  if (!object || typeof object !== "object") return fallback;
  for (const key of keys) {
    const value = object[key];
    if (value !== undefined && value !== null && String(value) !== "") return value;
  }
  return fallback;
}

export function textValue(value, fallback = "") {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function node(tag, options = {}, children = []) {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.id) element.id = options.id;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.type) element.type = options.type;
  if (options.value !== undefined) element.value = options.value;
  if (options.name) element.name = options.name;
  if (options.placeholder) element.placeholder = options.placeholder;
  if (options.checked !== undefined) element.checked = Boolean(options.checked);
  if (options.disabled !== undefined) element.disabled = Boolean(options.disabled);
  if (options.required !== undefined) element.required = Boolean(options.required);
  if (options.multiple !== undefined) element.multiple = Boolean(options.multiple);
  if (options.rows !== undefined) element.rows = options.rows;
  if (options.cols !== undefined) element.cols = options.cols;
  if (options.min !== undefined) element.min = options.min;
  if (options.max !== undefined) element.max = options.max;
  if (options.step !== undefined) element.step = options.step;
  if (options.accept) element.accept = options.accept;
  if (options.autocomplete) element.autocomplete = options.autocomplete;
  if (options.href) element.href = options.href;
  if (options.download) element.download = options.download;
  if (options.hidden !== undefined) element.hidden = Boolean(options.hidden);
  if (options.open !== undefined) element.open = Boolean(options.open);
  if (options.readOnly !== undefined) element.readOnly = Boolean(options.readOnly);
  if (options.role) element.setAttribute("role", options.role);
  if (options.ariaLabel) element.setAttribute("aria-label", options.ariaLabel);
  if (options.ariaLive) element.setAttribute("aria-live", options.ariaLive);
  if (options.title) element.title = options.title;
  if (options.events) {
    for (const [eventName, listener] of Object.entries(options.events)) element.addEventListener(eventName, listener);
  }
  for (const child of children) {
    if (child !== null && child !== undefined) element.append(child);
  }
  return element;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

function safeInlineMarkdown(value) {
  let text = escapeHtml(value);
  text = text.replace(/`([^`\n]+)`/gu, "<code>$1</code>");
  text = text.replace(/\*\*([^*\n]+)\*\*/gu, "<strong>$1</strong>");
  text = text.replace(/__([^_\n]+)__/gu, "<strong>$1</strong>");
  text = text.replace(/\*([^*\n]+)\*/gu, "<em>$1</em>");
  text = text.replace(/_([^_\n]+)_/gu, "<em>$1</em>");
  // Only retain links with an absolute HTTP(S) target.  The label and URL are
  // escaped before insertion, so model output cannot create executable markup.
  text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/giu, (_match, label, url) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${label}</a>`);
  return text;
}

export function markdownToHtml(markdown) {
  const source = String(markdown || "").replace(/\r\n?/gu, "\n");
  if (!source.trim()) return "<p class=\"empty-state\">暂无内容。</p>";
  const lines = source.split("\n");
  const output = [];
  let inList = false;
  let listType = "ul";
  let inCode = false;
  let codeLines = [];
  let tableHeader = null;
  const closeList = () => {
    if (inList) {
      output.push(`</${listType}>`);
      inList = false;
    }
  };
  const closeTable = () => {
    if (!tableHeader) return;
    tableHeader = null;
    output.push("</tbody></table>");
  };
  for (const line of lines) {
    if (/^\s*```/u.test(line)) {
      closeList();
      closeTable();
      if (inCode) {
        output.push(`<pre class="document-code"><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
        codeLines = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }
    const headingMatch = line.match(/^\s*(#{1,6})\s+(.+?)\s*#*\s*$/u);
    if (headingMatch) {
      closeList();
      closeTable();
      const level = Math.min(6, headingMatch[1].length);
      output.push(`<h${level}>${safeInlineMarkdown(headingMatch[2])}</h${level}>`);
      continue;
    }
    const listMatch = line.match(/^\s*([-*+] |\d+[.)] )(.+)$/u);
    if (listMatch) {
      closeTable();
      const ordered = /^\d/u.test(listMatch[1]);
      const nextType = ordered ? "ol" : "ul";
      if (!inList || listType !== nextType) {
        closeList();
        listType = nextType;
        output.push(`<${listType}>`);
        inList = true;
      }
      output.push(`<li>${safeInlineMarkdown(listMatch[2])}</li>`);
      continue;
    }
    const tableCells = /^\s*\|(.+)\|\s*$/u.exec(line);
    if (tableCells) {
      closeList();
      const cells = tableCells[1].split("|").map((cell) => cell.trim());
      if (!tableHeader) {
        tableHeader = cells;
        output.push(`<table><thead><tr>${cells.map((cell) => `<th>${safeInlineMarkdown(cell)}</th>`).join("")}</tr></thead><tbody>`);
      } else if (!cells.every((cell) => /^:?-{3,}:?$/u.test(cell))) {
        output.push(`<tr>${cells.map((cell) => `<td>${safeInlineMarkdown(cell)}</td>`).join("")}</tr>`);
      }
      continue;
    }
    if (!line.trim()) {
      closeList();
      closeTable();
      continue;
    }
    closeList();
    closeTable();
    output.push(`<p>${safeInlineMarkdown(line)}</p>`);
  }
  if (inCode) output.push(`<pre class="document-code"><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
  closeList();
  closeTable();
  return output.join("");
}

export function renderMarkdown(target, markdown) {
  if (!target) return;
  target.innerHTML = markdownToHtml(markdown);
}

// The service renders the canonical Markdown once and stores the resulting
// HTML alongside the source.  Prefer that representation so the preview and
// exported document share the same block structure.  Keep a small allowlist
// here as a browser-side boundary in case a stale or compromised response
// contains unexpected markup; Markdown remains the fallback for older runs.
const RENDERED_HTML_TAGS = new Set([
  "a", "br", "code", "em", "h1", "h2", "h3", "h4", "h5", "h6", "li",
  "ol", "p", "pre", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul"
]);
const DANGEROUS_RENDERED_HTML_TAGS = new Set(["base", "embed", "iframe", "link", "meta", "object", "script", "style", "svg"]);

function sanitizeRenderedHtml(html) {
  const template = document.createElement("template");
  template.innerHTML = String(html || "");
  const visit = (parent) => {
    for (const child of [...parent.childNodes]) {
      if (child.nodeType !== 1) {
        if (child.nodeType !== 3) child.remove();
        continue;
      }
      const tag = child.tagName.toLowerCase();
      if (!RENDERED_HTML_TAGS.has(tag)) {
        if (DANGEROUS_RENDERED_HTML_TAGS.has(tag)) {
          child.remove();
          continue;
        }
        // Flatten unknown wrappers so a harmless text response still remains
        // readable while scripts, style blocks and embeds are discarded.
        while (child.firstChild) child.parentNode.insertBefore(child.firstChild, child);
        child.remove();
        continue;
      }
      for (const attribute of [...child.attributes]) {
        const name = attribute.name.toLowerCase();
        const allowed = (tag === "a" && name === "href")
          || (tag === "ol" && name === "start")
          || ((tag === "td" || tag === "th") && ["colspan", "rowspan"].includes(name));
        if (!allowed) child.removeAttribute(attribute.name);
      }
      if (tag === "a") {
        const href = safeExternalUrl(child.getAttribute("href"));
        if (href) {
          child.setAttribute("href", href);
          child.setAttribute("target", "_blank");
          child.setAttribute("rel", "noopener noreferrer");
        } else {
          child.removeAttribute("href");
        }
      }
      if (tag === "ol") {
        const start = Number(child.getAttribute("start"));
        if (!Number.isInteger(start) || start < 1 || start > 1000000) child.removeAttribute("start");
      }
      for (const attribute of ["colspan", "rowspan"]) {
        if (child.hasAttribute(attribute)) {
          const value = Number(child.getAttribute(attribute));
          if (!Number.isInteger(value) || value < 1 || value > 1000) child.removeAttribute(attribute);
        }
      }
      visit(child);
    }
  };
  visit(template.content);
  return [...template.content.childNodes];
}

function renderRenderedContent(target, html, markdown, emptyText = "暂无内容。") {
  if (!target) return;
  const sourceHtml = textValue(html).trim();
  if (sourceHtml && typeof document !== "undefined") {
    replaceChildren(target, sanitizeRenderedHtml(sourceHtml));
    return;
  }
  renderMarkdown(target, textValue(markdown) || emptyText);
}

function button(label, onClick, className = "button") {
  return node("button", { className, type: "button", text: label, events: { click: onClick } });
}

function formButton(label, className = "button primary") {
  return node("button", { className, type: "submit", text: label });
}

function heading(level, text) {
  return node(`h${level}`, { text });
}

function labelFor(text, control) {
  const label = node("label", { className: "field-label", text });
  label.append(control);
  return label;
}

function fieldInput(label, options = {}) {
  // Callers that need to keep a reference to the control (for example the
  // provider editor) pass an already-created input. Reusing it keeps event
  // handlers and programmatic value updates attached to the control shown in
  // the form; plain option objects retain the original convenience API.
  const input = options?.nodeType === 1 ? options : node("input", options);
  return labelFor(label, input);
}

function fieldSelect(label, options = {}) {
  const select = node("select", options);
  return labelFor(label, select);
}

function fieldTextArea(label, options = {}) {
  const textarea = node("textarea", options);
  return labelFor(label, textarea);
}

function panel(title, children = [], className = "panel") {
  const section = node("section", { className }, [heading(2, title)]);
  section.append(...children);
  return section;
}

function statusBox(text = "", tone = "") {
  return node("p", { className: `status-message${tone ? ` ${tone}` : ""}`, text, ariaLive: "polite" });
}

function setStatus(target, message, tone = "") {
  if (!target) return;
  target.className = `status-message${tone ? ` ${tone}` : ""}`;
  target.textContent = message;
}

function replaceChildren(target, children = []) {
  target.replaceChildren(...children.filter((child) => child !== null && child !== undefined));
}

function emptyState(message) {
  return node("p", { className: "empty-state", text: message });
}

function appendOption(select, value, label, selected = false) {
  const option = node("option", { value, text: label });
  option.selected = selected;
  select.append(option);
}

function safeFilename(name, extension) {
  const cleaned = String(name || "律师助手导出").replace(/[\\/:*?"<>|\u0000-\u001f]/gu, "_").slice(0, 100) || "律师助手导出";
  return extension && !cleaned.toLowerCase().endsWith(`.${extension}`) ? `${cleaned}.${extension}` : cleaned;
}

async function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = node("a", { href: url, download: filename });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function copyText(text) {
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") throw new Error("clipboard_unavailable");
  await navigator.clipboard.writeText(String(text || ""));
}

function getFragmentToken() {
  const hash = String(globalThis.location?.hash || "");
  if (!hash.startsWith("#")) return "";
  const params = new URLSearchParams(hash.slice(1));
  return params.get("token") || "";
}

function clearFragment() {
  if (!globalThis.history || !globalThis.location) return;
  globalThis.history.replaceState(null, "", `${globalThis.location.pathname}${globalThis.location.search}`);
}

function parseJsonList(value) {
  return Array.isArray(value) ? value : [];
}

function responseList(response, keys) {
  if (Array.isArray(response)) return response;
  for (const key of keys) {
    if (Array.isArray(response?.[key])) return response[key];
  }
  return [];
}

function formatDate(value) {
  const text = textValue(value);
  if (!text) return "";
  const date = new Date(text);
  return Number.isNaN(date.valueOf()) ? text : date.toLocaleString("zh-CN", { hour12: false });
}

function materialName(material) {
  return textValue(field(material, ["name", "filename", "file_name"]), "未命名材料");
}

function articleId(article) {
  return textValue(field(article, ["id", "articleId", "article_id"]));
}

export function legalArticleDocumentId(article) {
  return textValue(field(article, ["documentId", "document_id"]));
}

export function legalArticleDisplayTitle(article) {
  const documentTitle = textValue(field(article, ["documentTitle", "document_title"]));
  const number = textValue(field(article, ["articleNumber", "article_number"]));
  const articleTitle = textValue(field(article, ["articleTitle", "article_title", "title", "name"]));
  return [documentTitle, number, articleTitle].filter(Boolean).join(" · ") || "未命名条文";
}

export function legalRelationTarget(relation, currentDocumentId) {
  const fromId = textValue(field(relation, ["fromDocumentId", "from_document_id"]));
  const toId = textValue(field(relation, ["toDocumentId", "to_document_id"]));
  if (fromId && fromId === currentDocumentId) {
    const title = textValue(field(relation, ["toTitle", "to_title"]));
    return { documentId: toId, title: title || "关联法规" };
  }
  if (toId && toId === currentDocumentId) {
    const title = textValue(field(relation, ["fromTitle", "from_title"]));
    return { documentId: fromId, title: title || "关联法规" };
  }
  const title = textValue(field(relation, ["toTitle", "to_title", "fromTitle", "from_title"]));
  return { documentId: toId || fromId, title: title || "关联法规" };
}

export const LEGAL_SEARCH_MODES = Object.freeze({
  statute: "statute",
  ai: "ai",
  case: "case"
});

export const CASE_TYPES = Object.freeze({
  all: "all",
  guiding: "guiding",
  reference: "reference",
  typical: "typical"
});

export const OFFICIAL_CASE_LINKS = Object.freeze([
  Object.freeze({
    label: "人民法院案例库",
    description: "最高人民法院统一审核的指导案例、参考案例和典型案例合集",
    url: "https://rmfyalk.court.gov.cn/"
  }),
  Object.freeze({
    label: "最高人民法院指导案例栏目",
    description: "查看最高人民法院官网发布的指导性案例及相关案例资源",
    url: "https://www.court.gov.cn/shenpan/gengduo/77.html"
  })
]);

export function safeExternalUrl(value) {
  const text = String(value ?? "").trim();
  if (!text || text.length > 2048 || /[\u0000-\u001f\u007f]/u.test(text)) return "";
  if (!/^https?:\/\//iu.test(text)) return "";
  try {
    const parsed = new URL(text);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return "";
    return parsed.href;
  } catch {
    return "";
  }
}

export function caseTypeLabel(caseType) {
  const key = String(caseType || "").toLowerCase();
  if (key === CASE_TYPES.guiding) return "指导案例";
  if (key === CASE_TYPES.reference) return "参考案例";
  if (key === CASE_TYPES.typical) return "典型案例合集";
  return key && /[\u3400-\u9fff]/u.test(key) ? key : key ? "待核验" : "案例";
}

export function caseId(item) {
  return textValue(field(item, ["caseId", "id", "case_id"]));
}

export function caseTitle(item) {
  return textValue(field(item, ["title", "caseTitle", "case_title", "name"]), "未命名案例");
}

const CASE_STATUS_LABELS = Object.freeze({
  published: "已发布",
  active: "有效",
  ready: "可用",
  withdrawn: "不再参照",
  deprecated: "不再参照",
  draft: "草稿",
  review: "待核验",
  needs_review: "待核验"
});

export function caseStatusLabel(status) {
  const key = String(status || "").toLowerCase();
  return CASE_STATUS_LABELS[key] || (key ? "待核验" : "");
}

function structuredText(value) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (!value || typeof value !== "object") return "";
  return textValue(field(value, ["text", "label", "value", "issue", "description", "name", "title", "code"]));
}

export function caseTextList(value) {
  if (!Array.isArray(value)) {
    const text = structuredText(value);
    return text ? [text] : [];
  }
  return value.map(structuredText).filter(Boolean);
}

const CASE_WARNING_LABELS = Object.freeze({
  ai_interpretation_requires_review: "AI 理解结果需要人工核验。",
  legal_database_missing: "本地法律库尚未配置。",
  legal_database_unavailable: "本地法律库暂不可用。",
  case_database_missing: "本地案例库尚未配置。",
  case_database_unavailable: "本地案例库暂不可用。"
});

export function caseWarningLabel(value) {
  const text = structuredText(value);
  if (!text) return "";
  const key = text.toLowerCase();
  if (CASE_WARNING_LABELS[key]) return CASE_WARNING_LABELS[key];
  return /^[a-z][a-z0-9_.-]*$/iu.test(text) ? "结果包含需要核验的提示。" : text;
}

export function caseWarningList(value) {
  return caseTextList(value).map(caseWarningLabel).filter(Boolean);
}

export function caseSourceLabel(item) {
  const explicit = textValue(field(item, ["source", "sourceName", "source_name"]));
  if (explicit) return explicit;
  const sourceUrl = safeExternalUrl(field(item, ["sourceUrl", "source_url"]));
  try {
    const hostname = sourceUrl ? new URL(sourceUrl).hostname.toLowerCase() : "";
    if (hostname === "rmfyalk.court.gov.cn" || hostname.endsWith(".rmfyalk.court.gov.cn")) return "人民法院案例库";
  } catch {
    // The URL is already validated; keep the conservative default if parsing is unavailable.
  }
  return "最高人民法院官网";
}

export function normalizeCaseSearchResponse(response, defaults = {}) {
  const source = response?.results && typeof response.results === "object" && !Array.isArray(response.results)
    ? response.results
    : response && typeof response === "object" ? response : {};
  const cases = Array.isArray(source.cases) ? source.cases : [];
  const parsedTotal = Number(source.total);
  const total = Number.isFinite(parsedTotal) && parsedTotal >= 0 ? Math.floor(parsedTotal) : cases.length;
  const parsedLimit = Number(source.limit);
  const defaultLimit = Number(defaults.limit);
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0
    ? Math.min(Math.floor(parsedLimit), 100)
    : Number.isFinite(defaultLimit) && defaultLimit > 0 ? Math.min(Math.floor(defaultLimit), 100) : 20;
  const parsedOffset = Number(source.offset);
  const defaultOffset = Number(defaults.offset);
  const offset = Number.isFinite(parsedOffset) && parsedOffset >= 0
    ? Math.floor(parsedOffset)
    : Number.isFinite(defaultOffset) && defaultOffset >= 0 ? Math.floor(defaultOffset) : 0;
  return {
    schemaVersion: textValue(source.schemaVersion),
    cases,
    total,
    limit,
    offset,
    databaseVersion: textValue(source.databaseVersion),
    warnings: caseTextList(source.warnings)
  };
}

export function legalCaseSearchParams(query, caseType = CASE_TYPES.all, offset = 0, includeWithdrawn = false) {
  const normalizedType = [CASE_TYPES.guiding, CASE_TYPES.reference, CASE_TYPES.typical].includes(caseType) ? caseType : CASE_TYPES.all;
  const parsedOffset = Number.isFinite(Number(offset)) && Number(offset) >= 0 ? Math.floor(Number(offset)) : 0;
  return {
    query: String(query || "").trim(),
    ...(normalizedType === CASE_TYPES.all ? {} : { case_type: normalizedType }),
    limit: 20,
    offset: parsedOffset,
    include_withdrawn: Boolean(includeWithdrawn)
  };
}

export function caseUnderstandPayload(query, providerId, model, caseType = CASE_TYPES.all, includeWithdrawn = false) {
  const payload = {
    query: String(query || "").trim(),
    provider_id: String(providerId || ""),
    model: String(model || ""),
    include_withdrawn: Boolean(includeWithdrawn)
  };
  const normalizedType = [CASE_TYPES.guiding, CASE_TYPES.reference, CASE_TYPES.typical].includes(caseType) ? caseType : CASE_TYPES.all;
  if (normalizedType !== CASE_TYPES.all) payload.case_type = normalizedType;
  return payload;
}

function resultId(material) {
  return textValue(field(material, ["result_id", "resultId"]));
}

function groupId(group) {
  return textValue(field(group, ["id", "groupId", "group_id"]));
}

export function mcpClientDetails(client, groups = []) {
  const clientGroupId = textValue(field(client, ["group_id", "groupId"]));
  const group = Array.isArray(groups) ? groups.find((item) => groupId(item) === clientGroupId) : null;
  const resolvedGroupName = textValue(field(group, ["name"]));
  return Object.freeze({
    groupId: clientGroupId,
    groupName: resolvedGroupName || (clientGroupId ? "未找到分组" : "未绑定分组"),
    inbox: textValue(field(client, ["inbox"]))
  });
}

export class WebApp {
  constructor(root, api = new ApiClient()) {
    this.root = root;
    this.api = api;
    this.state = {
      authenticated: false,
      csrfToken: "",
      sessionEpoch: 0,
      view: "privacy",
      health: null,
      groups: [],
      groupsPage: { items: [], nextCursor: "", total: 0, corruptCount: 0 },
      selectedGroupId: "",
      materials: [],
      privacyMaterialPages: new Map(),
      privacySelectedMaterialIds: new Map(),
      selectedMaterial: null,
      legalResults: [],
      legalCases: [],
      legalMode: LEGAL_SEARCH_MODES.statute,
      legalCaseType: CASE_TYPES.all,
      legalCaseQuery: "",
      legalCaseOffset: 0,
      legalIncludeWithdrawn: false,
      legalCaseResponse: null,
      legalCaseStatus: null,
      legalBookmarks: [],
      selectedArticle: null,
      selectedCase: null,
      legalSearchGeneration: 0,
      legalSearchAbort: null,
      legalArticleOffset: 0,
      legalArticleQuery: "",
      legalQueryFilters: { caseDate: "", matchMode: "all", versionScope: "current", versionStatus: "", documentId: "", documentTitle: "", type: "", level: "", region: "", status: "", sort: "relevance", view: "grouped", includeHistory: true, includeRelations: true },
      aiSearchFilters: { caseDate: "", matchMode: "all", versionScope: "current", versionStatus: "" },
      legalArticlePage: null,
      legalViewportCleanup: null,
      legalDetailOptions: { includeHistory: true, includeRelations: true },
      legalDetailGeneration: 0,
      legalDetailAbort: null,
      providers: [],
      aiDefaults: {},
       aiMaterials: [],
       aiMaterialsPage: { nextCursor: "", total: 0, corruptCount: 0, error: "", loaded: false },
       aiAttachments: [],
       aiRuns: [],
       aiRunPages: new Map(),
       runsById: new Map(),
       pageRunIds: { writing: "", search: "", chat: "" },
       conversations: [],
       conversationPage: { nextCursor: "", total: 0, corruptCount: 0, loaded: false },
       selectedConversation: null,
       mcpClients: [],
       taskTimer: null,
       chatAbort: null,
       activeRenderScope: "",
       renderGeneration: 0,
       providerLoadPromise: null,
       writingDrafts: new Map(),
       writingDraft: newWritingDraftState(),
       pendingMcpToken: null,
       pendingCitation: null
     };
     this.state.writingDrafts.set(this.state.writingDraft.id, this.state.writingDraft);
     this.api.setSessionEpoch?.(this.state.sessionEpoch);
     this.api.onUnauthenticated = () => this.requireLogin();
     this.aiRunPoller = new AiRunPoller({
       getRun: async (id, options) => {
         const sessionEpoch = this.state.sessionEpoch;
         const response = await this.api.getAiRun(id, options);
         if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
         return normalizeAiRun(response?.run || response);
       },
       onRun: (run) => {
         if (this.state.authenticated) this.rememberAiRun(run);
       }
     });
     globalThis.addEventListener?.("pagehide", () => {
       void this.flushAllWritingDrafts();
     });
  }

  async start() {
    this.render();
    const token = getFragmentToken();
    if (token) {
      try {
        const session = await this.api.request("/session", { method: "POST", body: { token } });
        clearFragment();
        this.setSession(session);
      } catch (error) {
        clearFragment();
        this.state.authenticated = false;
        this.renderLogin(apiErrorMessage(error));
        return;
      }
    } else {
      try {
        const session = await this.api.request("/session");
        this.setSession(session);
      } catch {
        this.state.authenticated = false;
        this.renderLogin();
        return;
      }
    }
    await this.loadHealth();
    this.render();
  }

  setSession(session) {
    this.state.authenticated = Boolean(session && session.authenticated);
    this.state.csrfToken = textValue(session && session.csrf_token);
    this.api.setCsrfToken(this.state.csrfToken);
    if (this.state.authenticated) {
      this.state.sessionEpoch += 1;
      this.api.setSessionEpoch?.(this.state.sessionEpoch);
    }
  }

  requireLogin() {
    this.state.sessionEpoch += 1;
    this.state.authenticated = false;
    this.state.csrfToken = "";
    this.api.setCsrfToken("");
    this.api.setSessionEpoch?.(this.state.sessionEpoch);
    for (const id of [...this.aiRunPoller.entries.keys()]) this.aiRunPoller.stop(id);
    this.cancelLegalRequests();
    this.teardownLegalViewport();
    this.state.chatAbort?.abort();
    this.state.chatAbort = null;
    if (this.state.taskTimer) clearTimeout(this.state.taskTimer);
    this.state.taskTimer = null;
    for (const draft of this.state.writingDrafts.values()) {
      if (draft.timer) clearTimeout(draft.timer);
      draft.timer = null;
      draft.pending = null;
      draft.savingPromise = null;
      draft.saving = false;
      draft.lastContent = undefined;
      draft.conflicts = [];
      draft.onConflictsChanged = null;
      draft.conflictLoadPromise = null;
    }
    this.state.writingDrafts.clear();
    this.state.writingDraft = newWritingDraftState();
    this.state.writingDrafts.set(this.state.writingDraft.id, this.state.writingDraft);
    this.state.health = null;
    this.state.groups = [];
    this.state.groupsPage = { items: [], nextCursor: "", total: 0, corruptCount: 0 };
    this.state.selectedGroupId = "";
    this.state.materials = [];
    this.state.privacyMaterialPages.clear();
    this.state.privacySelectedMaterialIds.clear();
    this.state.selectedMaterial = null;
    this.state.legalResults = [];
    this.state.legalCases = [];
    this.state.legalMode = LEGAL_SEARCH_MODES.statute;
    this.state.legalCaseType = CASE_TYPES.all;
    this.state.legalCaseQuery = "";
    this.state.legalCaseOffset = 0;
    this.state.legalIncludeWithdrawn = false;
    this.state.legalCaseResponse = null;
    this.state.legalCaseStatus = null;
    this.state.legalBookmarks = [];
    this.state.selectedArticle = null;
    this.state.selectedCase = null;
    this.state.legalArticleOffset = 0;
    this.state.legalArticleQuery = "";
    this.state.legalQueryFilters = { caseDate: "", matchMode: "all", versionScope: "current", versionStatus: "", documentId: "", documentTitle: "", type: "", level: "", region: "", status: "", sort: "relevance", view: "grouped", includeHistory: true, includeRelations: true };
    this.state.aiSearchFilters = { caseDate: "", matchMode: "all", versionScope: "current", versionStatus: "" };
    this.state.legalArticlePage = null;
    this.state.legalDetailOptions = { includeHistory: true, includeRelations: true };
    this.state.providers = [];
    this.state.aiDefaults = {};
    this.state.aiMaterials = [];
    this.state.aiMaterialsPage = { nextCursor: "", total: 0, corruptCount: 0, error: "", loaded: false };
    this.state.aiAttachments = [];
    this.state.aiRuns = [];
    this.state.aiRunPages.clear();
    this.state.runsById.clear();
    this.state.pageRunIds = { writing: "", search: "", chat: "" };
    this.state.conversations = [];
    this.state.conversationPage = { nextCursor: "", total: 0, corruptCount: 0, loaded: false };
    this.state.selectedConversation = null;
    this.state.mcpClients = [];
    this.state.providerLoadPromise = null;
    this.state.pendingMcpToken = null;
    this.state.pendingCitation = null;
    this.state.activeRenderScope = `session-cleared-${++this.state.renderGeneration}`;
    this.renderLogin("会话已失效，请使用新的本地访问链接。", true);
  }

  isSessionCurrent(epoch) {
    return this.state.authenticated && this.state.sessionEpoch === epoch;
  }

  writingDraftState(id = "writing-current") {
    const key = textValue(id, "writing-current") || "writing-current";
    let draft = this.state.writingDrafts.get(key);
    if (!draft) {
      draft = newWritingDraftState(key);
      this.state.writingDrafts.set(key, draft);
    }
    return draft;
  }

  activateWritingDraft(id) {
    const draft = this.writingDraftState(id);
    this.state.writingDraft = draft;
    return draft;
  }

  async flushAllWritingDrafts() {
    await Promise.allSettled([...this.state.writingDrafts.values()].map((draft) => this.flushWritingDraft(draft)));
  }

  rememberWritingRunPointer(run) {
    const id = safeWritingRunPointer(aiRunId(run));
    if (!id) return;
    try { globalThis.localStorage?.setItem(WRITING_LAST_RUN_STORAGE_KEY, id); } catch {}
  }

  restoredWritingRunPointer() {
    try { return safeWritingRunPointer(globalThis.localStorage?.getItem(WRITING_LAST_RUN_STORAGE_KEY)); } catch { return ""; }
  }

  async loadHealth() {
    const sessionEpoch = this.state.sessionEpoch;
    try {
      const health = await this.api.request("/health");
      if (!this.isSessionCurrent(sessionEpoch)) return;
      this.state.health = health;
    } catch {
      if (this.isSessionCurrent(sessionEpoch)) this.state.health = null;
    }
  }

  navigate(view) {
    if (!Object.prototype.hasOwnProperty.call(VIEWS, view)) return;
    if (this.state.view === "templates") void this.flushWritingDraft();
    this.state.view = view;
    this.render();
  }

  rememberAiRun(run) {
    const normalized = normalizeAiRun(run);
    if (normalized.id) this.state.runsById.set(normalized.id, normalized);
    return normalized;
  }

  selectPageRun(page, run) {
    const normalized = this.rememberAiRun(run);
    if (normalized.id && Object.prototype.hasOwnProperty.call(this.state.pageRunIds, page)) {
      this.state.pageRunIds[page] = normalized.id;
    }
    return normalized;
  }

  pageRun(page) {
    const id = this.state.pageRunIds?.[page];
    return id ? this.state.runsById.get(id) || null : null;
  }

  beginRenderScope() {
    if (this.state.activeRenderScope) this.aiRunPoller.disposeScope(this.state.activeRenderScope);
    const scope = `view-${++this.state.renderGeneration}`;
    this.state.activeRenderScope = scope;
    return scope;
  }

  render() {
    this.teardownLegalViewport();
    this.beginRenderScope();
    if (!this.state.authenticated) {
      this.renderLogin();
      return;
    }
    const shell = node("div", { className: "app-shell" });
    const header = node("header", { className: "app-header" });
    const brand = node("div", { className: "brand" }, [
      node("span", { className: "brand-mark", text: "律" }),
      node("div", {}, [node("strong", { text: "律师助手" }), node("span", { text: "本机脱敏与法律检索" })])
    ]);
    const nav = node("nav", { className: "main-nav", role: "navigation", ariaLabel: "主导航" });
    for (const [key, label] of Object.entries(VIEWS)) {
      const navButton = button(label, () => this.navigate(key), `nav-button${this.state.view === key ? " active" : ""}`);
      navButton.setAttribute("aria-current", this.state.view === key ? "page" : "false");
      nav.append(navButton);
    }
    const healthReady = ["ok", "ready"].includes(textValue(this.state.health?.status).toLowerCase());
    const health = node("span", { className: `health-dot${healthReady ? " online" : ""}`, text: healthReady ? "服务正常" : "服务检查中" });
    const healthButton = button("检查服务", async () => {
      health.textContent = "检查中";
      await this.loadHealth();
      const refreshedHealthReady = ["ok", "ready"].includes(textValue(this.state.health?.status).toLowerCase());
      health.className = `health-dot${refreshedHealthReady ? " online" : ""}`;
      health.textContent = refreshedHealthReady ? "服务正常" : "服务不可用";
    }, "button subtle");
    const headerActions = node("div", { className: "header-actions" }, [health, healthButton]);
    header.append(brand, nav, headerActions);
    const main = node("main", { className: "app-main" });
    shell.append(header, main);
    this.root.replaceChildren(shell);
    if (this.state.view === "privacy") this.renderPrivacy(main);
    else if (this.state.view === "legal") this.renderLegal(main);
    else if (this.state.view === "templates") this.renderWriting(main);
    else if (this.state.view === "chat") this.renderAiChat(main);
    else this.renderSettings(main);
  }

  renderLogin(message = "", sessionExpired = false) {
    const wrapper = node("div", { className: "login-page" });
    const card = node("section", { className: "login-card" }, [
      node("span", { className: "brand-mark large", text: "律" }),
      heading(1, "律师助手"),
      node("p", { className: "muted", text: "本机 Web 工作台 · 材料先脱敏，再进入 AI" })
    ]);
    const form = node("form", { className: "stack-form" });
    const tokenInput = node("input", { type: "password", placeholder: "粘贴本地访问令牌", autocomplete: "off", required: true });
    form.append(labelFor("本地访问令牌", tokenInput));
    const status = statusBox(message, message ? "warning" : "");
    const submit = formButton("进入工作台", "button primary full");
    form.append(submit, status);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      setStatus(status, "正在建立本机会话…");
      try {
        const session = await this.api.request("/session", { method: "POST", body: { token: tokenInput.value } });
        clearFragment();
        this.setSession(session);
        await this.loadHealth();
        this.render();
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
        submit.disabled = false;
      }
    });
    card.append(form);
    if (sessionExpired) card.append(node("p", { className: "muted small", text: "浏览器会话只保留在本机 HttpOnly Cookie 中。" }));
    wrapper.append(card);
    this.root.replaceChildren(wrapper);
  }

  async renderPrivacy(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "材料脱敏"), node("p", { text: "导入文本、DOCX、PDF 或图片；本地预扫描结合云端模型识别与检查，成品统一保存为纯 TXT。" })]);
    const layout = node("div", { className: "workspace-grid privacy-grid" });
    const left = node("div", { className: "workspace-column" });
    const right = node("div", { className: "workspace-column" });
    layout.append(left, right);
    main.append(title, layout);
    const groupPanel = panel("材料分组");
    const groupRow = node("div", { className: "inline-form" });
    const groupSelect = node("select", { ariaLabel: "选择材料分组" });
    groupRow.append(groupSelect);
    const refreshGroups = button("刷新", () => this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus), "button subtle");
    groupRow.append(refreshGroups);
    const loadMoreGroups = button("加载更多分组", () => this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus, { appendGroups: true }), "button subtle");
    loadMoreGroups.hidden = true;
    const groupPageStatus = statusBox();
    groupSelect.loadMoreControl = loadMoreGroups;
    groupSelect.pageStatus = groupPageStatus;
    groupPanel.append(groupRow, loadMoreGroups, groupPageStatus);
    const newGroupForm = node("form", { className: "inline-form" });
    const newGroupName = node("input", { type: "text", placeholder: "新分组名称", required: true });
    const addGroupButton = formButton("新建分组", "button secondary");
    const groupStatus = statusBox();
    newGroupForm.append(newGroupName, addGroupButton);
    newGroupForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      addGroupButton.disabled = true;
      try {
        await this.api.request("/groups", { method: "POST", body: { name: newGroupName.value.trim() } });
        newGroupName.value = "";
        setStatus(groupStatus, "分组已创建", "success");
        await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
      } catch (error) {
        setStatus(groupStatus, apiErrorMessage(error), "danger");
      } finally {
        addGroupButton.disabled = false;
      }
    });
    groupPanel.append(newGroupForm, groupStatus);
    const dictionaryPanel = panel("分组词典");
    const dictionaryList = node("div", { className: "dictionary-list" }, [emptyState("选择分组后加载词典。")]);
    const dictionaryAddForm = node("form", { className: "inline-form" });
    const dictionaryText = node("input", { type: "text", placeholder: "敏感词" });
    const dictionaryKind = node("input", { type: "text", value: "custom", placeholder: "person_name / person / custom" });
    const dictionaryAlias = node("input", { type: "text", placeholder: "统一别名" });
    const dictionaryAdd = formButton("添加", "button secondary");
    dictionaryAddForm.append(dictionaryText, dictionaryKind, dictionaryAlias, dictionaryAdd);
    const dictionaryStatus = statusBox();
    const dictionarySave = button("保存分组词典", async () => {
      const group = groupSelect.value || this.state.selectedGroupId;
      if (!group) return;
      dictionarySave.disabled = true;
      try {
        const entries = [...dictionaryList.querySelectorAll(".dictionary-row")].map((row) => ({
          text: row.querySelector("input[data-dictionary-text]")?.value.trim() || "",
          kind: row.querySelector("input[data-dictionary-kind]")?.value.trim() || "custom",
          alias: optionalAlias(row.querySelector("input[data-dictionary-alias]")?.value)
        })).filter((entry) => entry.text);
        await this.api.request(`/groups/${pathId(group)}/dictionary`, { method: "PUT", body: { entries } });
        setStatus(dictionaryStatus, "分组词典已保存。", "success");
        await this.loadDictionary(group, dictionaryList, dictionaryStatus);
      } catch (error) {
        setStatus(dictionaryStatus, apiErrorMessage(error), "danger");
      } finally {
        dictionarySave.disabled = false;
      }
    }, "button secondary");
    dictionaryAddForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const text = dictionaryText.value.trim();
      if (!text) return;
      dictionaryList.append(this.dictionaryRow({ text, kind: dictionaryKind.value.trim() || "custom", alias: dictionaryAlias.value.trim() }));
      dictionaryText.value = "";
      dictionaryAlias.value = "";
      setStatus(dictionaryStatus, "词典条目已加入待保存列表。", "success");
    });
    dictionaryPanel.append(dictionaryList, dictionaryAddForm, dictionarySave, dictionaryStatus);
    const importPanel = panel("导入材料");
    const importForm = node("form", { className: "stack-form" });
    const fileInput = node("input", { type: "file", accept: ".txt,.docx,.pdf,.png,.jpg,.jpeg,.webp", multiple: true, required: true });
    const encodingSelect = node("select");
    appendOption(encodingSelect, "", "自动判断 TXT 编码");
    appendOption(encodingSelect, "utf-8", "UTF-8");
    appendOption(encodingSelect, "gb18030", "GB18030");
    const importButton = formButton("开始脱敏", "button primary");
    const importStatus = statusBox("支持 TXT、DOCX、PDF、PNG、JPEG、WebP；PDF/图片将调用已配置的 OCR 模型。", "muted");
    const aiModeStatus = statusBox("AI 脱敏模式：正在读取默认模型配置…", "muted");
    importForm.append(labelFor("选择文件", fileInput), fieldSelect("TXT 编码（可选）", { children: [] }));
    const encodingLabel = importForm.lastChild;
    encodingLabel.replaceChildren(node("span", { text: "TXT 编码（可选）" }), encodingSelect);
    importForm.append(aiModeStatus, importButton, importStatus);
    importForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const group = groupSelect.value || this.state.selectedGroupId;
      if (!group || !fileInput.files?.length) {
        setStatus(importStatus, "请选择材料分组和至少一个文件。", "warning");
        return;
      }
      importButton.disabled = true;
      setStatus(importStatus, "正在上传并创建任务…");
      const formData = new FormData();
      formData.set("group_id", group);
      formData.set("request_id", globalThis.crypto?.randomUUID?.() || `web-${Date.now()}-${Math.random().toString(16).slice(2)}`);
      if (encodingSelect.value) formData.set("encoding", encodingSelect.value);
      for (const file of fileInput.files) formData.append("files", file, file.name);
      try {
        const result = await this.api.request("/imports", { method: "POST", body: formData });
        const taskId = textValue(field(result, ["task_id", "taskId", "id"]));
        setStatus(importStatus, taskId ? `任务已创建：${taskId}` : "任务已创建，正在刷新材料列表。", "success");
        await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
        if (taskId) this.pollTask(taskId, importStatus, groupSelect, materialsList, detail);
      } catch (error) {
        setStatus(importStatus, apiErrorMessage(error), "danger");
      } finally {
        importButton.disabled = false;
      }
    });
    importPanel.append(importForm);
    const materialsPanel = panel("材料列表", [], "panel materials-panel");
    const materialsList = node("div", { className: "materials-list" }, [emptyState("正在加载分组…")]);
    materialsPanel.append(materialsList);
    left.append(groupPanel, dictionaryPanel, importPanel, materialsPanel);

    const detail = node("div", { className: "detail-area" });
    right.append(detail);
    try {
      await this.loadAiProviders();
      const redaction = this.state.aiDefaults?.redaction;
      const ocr = this.state.aiDefaults?.ocr;
      const redactionModel = textValue(field(redaction, ["model"]));
      const ocrModel = textValue(field(ocr, ["model"]));
      if (redactionModel && ocrModel) setStatus(aiModeStatus, `AI 脱敏模式已启用：识别模型 ${redactionModel} · OCR 模型 ${ocrModel}。国内预设默认允许原文发送，其他服务默认使用脱敏材料。`, "success");
      else if (redactionModel) setStatus(aiModeStatus, `AI 脱敏模式已启用：识别模型 ${redactionModel}；PDF/图片仍需配置 OCR 模型。`, "warning");
      else setStatus(aiModeStatus, "尚未配置 AI 脱敏模型，将使用本地规则；请在设置中配置识别和 OCR 模型。", "warning");
    } catch (error) {
      setStatus(aiModeStatus, `AI 模型配置暂不可用：${apiErrorMessage(error)}`, "warning");
    }
    await this.loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus);
  }

  dictionaryRow(entry) {
    const text = node("input", { type: "text", value: textValue(entry?.text), ariaLabel: "词典敏感词" });
    text.dataset.dictionaryText = "true";
    const kind = node("input", { type: "text", value: textValue(entry?.kind, "custom"), ariaLabel: "词典类别" });
    kind.dataset.dictionaryKind = "true";
    const alias = node("input", { type: "text", value: textValue(entry?.alias), placeholder: "可留空自动生成", ariaLabel: "词典别名" });
    alias.dataset.dictionaryAlias = "true";
    let row;
    const remove = button("删除", () => row.remove(), "button subtle");
    row = node("div", { className: "dictionary-row" }, [text, kind, alias, remove]);
    return row;
  }

  async loadDictionary(groupIdValue, target, status) {
    if (!target) return;
    if (!groupIdValue) {
      replaceChildren(target, [emptyState("请选择分组后加载词典。")]);
      return;
    }
    try {
      const response = await this.api.request(`/groups/${pathId(groupIdValue)}/dictionary`);
      const entries = parseJsonList(response?.entries);
      replaceChildren(target, entries.length ? entries.map((entry) => this.dictionaryRow(entry)) : [emptyState("当前分组没有自定义词典。")]);
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
      setStatus(status, apiErrorMessage(error), "danger");
    }
  }

  async loadGroupsPage({ append = false, limit = 50 } = {}) {
    const previous = this.state.groupsPage;
    const cursor = append ? textValue(previous.nextCursor) : "";
    if (append && !cursor) return previous;
    const response = await this.api.listGroups({ limit, cursor });
    const page = normalizeCursorPage(response, ["groups"]);
    const items = append ? appendUniqueById(previous.items, page.items) : page.items;
    const next = { items, nextCursor: page.nextCursor, total: page.total, corruptCount: page.corruptCount };
    this.state.groupsPage = next;
    this.state.groups = items;
    return next;
  }

  async loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus, { appendGroups = false } = {}) {
    try {
      const groupsPage = await this.loadGroupsPage({ append: appendGroups });
      const loadMoreGroups = groupSelect.loadMoreControl;
      if (loadMoreGroups) loadMoreGroups.hidden = !groupsPage.nextCursor;
      if (groupSelect.pageStatus) {
        const summary = `已加载 ${groupsPage.items.length}${groupsPage.total ? ` / ${groupsPage.total}` : ""} 个分组。`;
        setStatus(groupSelect.pageStatus, groupsPage.corruptCount > 0 ? `${summary} 检测到 ${groupsPage.corruptCount} 个损坏分组记录，未显示。` : summary, groupsPage.corruptCount > 0 ? "warning" : "muted");
      }
      replaceChildren(groupSelect);
      if (!this.state.groups.length) {
        appendOption(groupSelect, "", "暂无分组，请先新建");
        this.state.selectedGroupId = "";
        this.state.materials = [];
        replaceChildren(materialsList, [emptyState("请先创建材料分组。")]);
        replaceChildren(detail, [emptyState("选择材料后在这里复核。")]);
        if (dictionaryList) replaceChildren(dictionaryList, [emptyState("请先创建材料分组。")]);
        return;
      }
      const preferred = this.state.selectedGroupId && this.state.groups.some((group) => groupId(group) === this.state.selectedGroupId)
        ? this.state.selectedGroupId
        : groupId(this.state.groups[0]);
      this.state.selectedGroupId = preferred;
      for (const group of this.state.groups) appendOption(groupSelect, groupId(group), textValue(field(group, ["name", "title"]), "未命名分组"), groupId(group) === preferred);
      groupSelect.onchange = () => {
        this.state.selectedGroupId = groupSelect.value;
        this.state.selectedMaterial = null;
        this.loadPrivacyMaterials(groupSelect, materialsList, detail);
        this.loadDictionary(groupSelect.value, dictionaryList, dictionaryStatus);
      };
      await this.loadPrivacyMaterials(groupSelect, materialsList, detail);
      await this.loadDictionary(preferred, dictionaryList, dictionaryStatus);
    } catch (error) {
      replaceChildren(materialsList, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async loadPrivacyMaterials(groupSelect, materialsList, detail, { append = false } = {}) {
    if (!groupSelect.value) return;
    const groupIdValue = groupSelect.value;
    const previous = this.state.privacyMaterialPages.get(groupIdValue) || { items: [], nextCursor: "", total: 0, corruptCount: 0 };
    const cursor = append ? textValue(previous.nextCursor) : "";
    if (append && !cursor) return;
    if (!append) replaceChildren(materialsList, [emptyState("正在加载材料…")]);
    try {
      const response = await this.api.listMaterials(groupIdValue, { limit: 50, cursor });
      const page = normalizeCursorPage(response, ["materials"]);
      const items = append ? appendUniqueById(previous.items, page.items) : page.items;
      const pageState = { items, nextCursor: page.nextCursor, total: page.total, corruptCount: page.corruptCount };
      this.state.privacyMaterialPages.set(groupIdValue, pageState);
      this.state.materials = items;
      const selectedIds = this.state.privacySelectedMaterialIds.get(groupIdValue) || new Set();
      this.state.privacySelectedMaterialIds.set(groupIdValue, selectedIds);
      const rows = [];
      for (const material of this.state.materials) {
        const id = textValue(field(material, ["id", "materialId", "material_id"]));
        const checkbox = node("input", { type: "checkbox", ariaLabel: `选择${materialName(material)}`, checked: selectedIds.has(id) });
        checkbox.dataset.materialId = id;
        checkbox.addEventListener("change", () => {
          if (!id) return;
          if (checkbox.checked) selectedIds.add(id);
          else selectedIds.delete(id);
        });
        const label = node("label", { className: "material-row" }, [
          checkbox,
          node("span", { className: "material-name", text: materialName(material) }),
          node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) })
        ]);
        label.append(node("span", { className: "material-meta", text: reasonLabel(field(material, ["reason_code", "reasonCode"])) }));
        const openButton = button("查看", () => this.loadMaterialDetail(id, detail), "button subtle");
        const row = node("div", { className: "material-item" }, [label, openButton]);
        rows.push(row);
      }
      if (!rows.length) rows.push(emptyState("当前分组还没有材料。"));
      const exportBar = node("div", { className: "list-actions" });
      const format = node("select", { ariaLabel: "批量导出格式" });
      appendOption(format, "zip", "批量导出 ZIP");
      const exportButton = button("导出已选", async () => {
        const materialIds = [...selectedIds];
        if (!materialIds.length) return;
        exportButton.disabled = true;
        try {
          const blob = await this.api.download("/exports", { method: "POST", body: { material_ids: materialIds, format: format.value } });
          await downloadBlob(blob, "律师助手脱敏材料.zip");
        } catch (error) {
          const message = statusBox(apiErrorMessage(error), "danger");
          materialsList.prepend(message);
        } finally {
          exportButton.disabled = false;
        }
      }, "button secondary");
      exportBar.append(format, exportButton);
      const pageSummary = node("p", { className: "muted small", text: `已加载 ${items.length}${pageState.total ? ` / ${pageState.total}` : ""} 个材料。` });
      const corrupt = pageState.corruptCount > 0 ? statusBox(`检测到 ${pageState.corruptCount} 个损坏材料记录，未显示。`, "warning") : null;
      const loadMore = pageState.nextCursor ? button("加载更多材料", () => this.loadPrivacyMaterials(groupSelect, materialsList, detail, { append: true }), "button subtle") : null;
      replaceChildren(materialsList, [pageSummary, corrupt, exportBar, ...rows, loadMore]);
      if (this.state.selectedMaterial) await this.loadMaterialDetail(textValue(field(this.state.selectedMaterial, ["id", "materialId"])), detail);
      else replaceChildren(detail, [emptyState("选择材料后在这里复核。")]);
    } catch (error) {
      replaceChildren(materialsList, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async loadMaterialDetail(id, detail) {
    if (!id) return;
    replaceChildren(detail, [emptyState("正在加载材料详情…")]);
    try {
      const material = await this.api.request(`/materials/${pathId(id)}`);
      this.state.selectedMaterial = material;
      this.renderMaterialDetail(material, detail);
    } catch (error) {
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderMaterialDetail(material, detail) {
    const id = textValue(field(material, ["id", "materialId"]));
    const revision = field(material, ["revision"], "");
    const title = node("div", { className: "detail-heading" }, [
      heading(2, materialName(material)),
      node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) })
    ]);
    const actions = node("div", { className: "button-row" });
    const result = resultId(material);
    for (const format of ["txt"]) {
      const exportButton = button(`下载 ${format.toUpperCase()}`, async () => {
        exportButton.disabled = true;
        try {
          const blob = await this.api.download(`/results/${pathId(result)}/export${queryString({ format })}`);
          await downloadBlob(blob, safeFilename(materialName(material), format));
        } catch (error) {
          setStatus(detailStatus, apiErrorMessage(error), "danger");
        } finally {
          exportButton.disabled = false;
        }
      }, "button secondary");
      exportButton.disabled = !result || !["ready", "completed"].includes(String(material.status).toLowerCase());
      actions.append(exportButton);
    }
    const revokeButton = button("撤销结果", async () => {
      if (!window.confirm("撤销后该结果将不能通过 MCP 读取，是否继续？")) return;
      revokeButton.disabled = true;
      try {
        await this.api.request(`/materials/${pathId(id)}/revoke`, { method: "POST", body: {} });
        await this.loadMaterialDetail(id, detail);
      } catch (error) {
        setStatus(detailStatus, apiErrorMessage(error), "danger");
        revokeButton.disabled = false;
      }
    }, "button danger");
    revokeButton.disabled = !result;
    actions.append(revokeButton);
    const replacePanel = panel("替换源文件并重新处理", [], "panel replace-panel");
    const replaceForm = node("form", { className: "stack-form" });
    const replacementFile = node("input", { type: "file", accept: ".txt,.docx,.pdf,.png,.jpg,.jpeg,.webp", required: true });
    const replacementEncoding = node("select");
    appendOption(replacementEncoding, "", "自动判断 TXT 编码");
    appendOption(replacementEncoding, "utf-8", "UTF-8");
    appendOption(replacementEncoding, "gb18030", "GB18030");
    appendOption(replacementEncoding, "utf-16", "UTF-16");
    appendOption(replacementEncoding, "utf-16le", "UTF-16LE");
    appendOption(replacementEncoding, "utf-16be", "UTF-16BE");
    const replaceButton = formButton("上传并重新处理", "button secondary");
    const replaceStatus = statusBox("适用于处理失败或需要重新指定 TXT 编码的材料。", "muted");
    replaceForm.append(labelFor("新的材料源文件", replacementFile), labelFor("TXT 编码（可选）", replacementEncoding), replaceButton, replaceStatus);
    replaceForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const file = replacementFile.files?.[0];
      if (!file) {
        setStatus(replaceStatus, "请选择一个 TXT、DOCX、PDF 或图片文件。", "warning");
        return;
      }
      replaceButton.disabled = true;
      setStatus(replaceStatus, "正在替换源文件并创建新版本…");
      const formData = new FormData();
      formData.set("revision", String(revision));
      if (replacementEncoding.value) formData.set("encoding", replacementEncoding.value);
      formData.set("file", file, file.name);
      try {
        const response = await this.api.request(`/materials/${pathId(id)}/replace`, { method: "POST", body: formData });
        const responseId = textValue(field(response, ["id", "materialId", "material_id"]), id);
        const responseTaskId = textValue(field(response, ["task_id", "taskId"]));
        setStatus(replaceStatus, responseTaskId ? "源文件已替换，正在重新处理。" : "源文件已替换。", "success");
        await this.loadMaterialDetail(responseId, detail);
        if (responseTaskId && !textValue(field(this.state.selectedMaterial, ["task_id", "taskId"]))) {
          this.pollTask(responseTaskId, replaceStatus, null, null, detail);
        }
      } catch (error) {
        setStatus(replaceStatus, apiErrorMessage(error), "danger");
        replaceButton.disabled = false;
      }
    });
    const analysis = field(material, ["analysis"], {});
    const findings = parseJsonList(analysis?.findings);
    const hasAnalysis = Boolean(analysis && typeof analysis === "object" && ("text" in analysis || "findings" in analysis || "needsReview" in analysis));
    const analysisNeedsReview = analysis?.needsReview === true;
    const pipelineStage = textValue(field(material, ["stage", "processing_stage", "processingStage"]));
    const pipelineNotice = pipelineStage ? `处理阶段：${pipelineStageLabel(pipelineStage)}` : "本地预扫描 → 模型识别 → 本地替换 → 模型漏项检查 → 残留检查";
    const analysisNotice = !hasAnalysis
      ? statusBox(`${pipelineNotice}。等待分析结果。`, "muted")
      : analysisNeedsReview
      ? statusBox(`${pipelineNotice}。自动检查标记为待复核；保存复核后才会重新发布结果。`, "warning")
      : statusBox(`${pipelineNotice}。当前识别结果已通过检查。`, "success");
    const original = node("pre", { className: "source-text", text: textValue(material.original_text, "原文尚未提取或不可用。") });
    const sourceDetails = node("details", { className: "source-disclosure" }, [node("summary", { text: "查看已导入原文（仅本机）" }), original]);
    const redactedText = node("pre", { className: "redacted-text", text: textValue(analysis?.text, "脱敏文本尚未生成。") });
    const reviewForm = node("form", { className: "review-form" });
    const findingRows = [];
    const dictionary = [];
    for (const finding of findings) {
      const text = textValue(field(finding, ["text", "value"]));
      const kind = textValue(field(finding, ["kind", "type"]), "other");
      const alias = node("input", { type: "text", value: textValue(field(finding, ["alias"])) });
      const decision = materialReviewDecision(finding);
      const dismissed = node("input", { type: "checkbox", checked: decision.ignored, disabled: !decision.canDismiss });
      const row = node("div", { className: "finding-row" }, [
        node("span", { className: "finding-text", text }),
        node("span", { className: "finding-kind", text: kind }),
        labelFor("替换为", alias),
        labelFor("确认非敏感，保留原文", dismissed)
      ]);
      findingRows.push({ finding, text, kind, alias, dismissed });
      reviewForm.append(row);
      if (text) dictionary.push({ text, kind, alias: alias.value });
    }
    if (!findingRows.length) reviewForm.append(emptyState("没有检测到待处理项目。"));
    const extraText = node("input", { type: "text", placeholder: "补充需要脱敏的词语" });
    const extraKind = node("input", { type: "text", value: "custom", placeholder: "custom / person / person_name" });
    const extraAlias = node("input", { type: "text", placeholder: "留空自动生成，如 [PERSON_x]" });
    const addRow = node("div", { className: "finding-row add-finding" }, [labelFor("补充词语", extraText), labelFor("类别（支持 person 等别名）", extraKind), labelFor("替换别名（可留空）", extraAlias)]);
    reviewForm.append(addRow);
    const reviewButton = formButton("保存复核并重新检查", "button primary");
    const detailStatus = statusBox();
    reviewForm.append(reviewButton, detailStatus);
    reviewForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      reviewButton.disabled = true;
      const decisions = findingRows.map(row => materialReviewDecision(row.finding, row.alias.value, row.dismissed.checked));
      const entries = decisions.map(row => row.entry).filter(row => row?.text);
      if (extraText.value.trim()) entries.push({ text: extraText.value.trim(), kind: extraKind.value.trim() || "custom", alias: optionalAlias(extraAlias.value) });
      const dismissed = decisions.map(row => row.dismissedId).filter(Boolean);
      try {
        await this.api.request(`/materials/${pathId(id)}/review`, { method: "POST", body: { revision, dictionary: entries, dismissed } });
        setStatus(detailStatus, "已保存，材料将重新检查。", "success");
        await this.loadMaterialDetail(id, detail);
      } catch (error) {
        setStatus(detailStatus, apiErrorMessage(error), "danger");
        reviewButton.disabled = false;
      }
    });
    const taskId = textValue(field(material, ["task_id", "taskId"]));
    const taskPanel = node("div", { className: "task-panel" });
    if (taskId) this.renderTaskControls(taskId, taskPanel, detail);
    const detailStatusAndReview = node("div", { className: "review-panel" }, [heading(3, "检测结果与复核"), analysisNotice, reviewForm]);
    replaceChildren(detail, [title, actions, replacePanel, sourceDetails, heading(3, "脱敏预览"), redactedText, taskPanel, detailStatusAndReview]);
    replacePanel.append(replaceForm);
  }

  renderTaskControls(taskId, container, detail) {
    const text = statusBox("正在读取任务状态…");
    const controls = node("div", { className: "button-row" });
    const cancel = button("取消任务", async () => {
      cancel.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/cancel`, { method: "POST", body: {} });
        setStatus(text, "任务已取消。", "warning");
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        cancel.disabled = false;
      }
    }, "button subtle");
    const retry = button("重试任务", async () => {
      retry.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/retry`, { method: "POST", body: {} });
        setStatus(text, "已提交重试。", "success");
        this.pollTask(taskId, text, null, null, detail);
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        retry.disabled = false;
      }
    }, "button secondary");
    const consentForm = node("form", { className: "consent-form" });
    const provider = node("select");
    appendOption(provider, "", "选择已配置的模型服务");
    this.loadProvidersInto(provider);
    const model = node("input", { type: "text", placeholder: "模型名称", required: true });
    const consent = formButton("授权本批次云辅助", "button secondary");
    const revokeConsent = button("撤销云辅助授权", async () => {
      revokeConsent.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/consent`, { method: "DELETE" });
        setStatus(text, "云辅助授权已撤销，未发送新的材料。", "warning");
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
        revokeConsent.disabled = false;
      }
    }, "button subtle");
    consentForm.append(provider, model, consent);
    consentForm.append(revokeConsent);
    consentForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      consent.disabled = true;
      try {
        await this.api.request(`/tasks/${pathId(taskId)}/consent`, { method: "POST", body: { provider_id: provider.value, model: model.value.trim(), purpose: "redaction_assistance" } });
        setStatus(text, "本批次云辅助已授权。", "success");
        this.pollTask(taskId, text, null, null, detail);
      } catch (error) {
        setStatus(text, apiErrorMessage(error), "danger");
      } finally {
        consent.disabled = false;
      }
    });
    controls.append(cancel, retry);
    container.append(heading(3, "任务状态"), text, controls, consentForm);
    this.pollTask(taskId, text, null, null, detail);
  }

  async loadProvidersInto(select, purpose = "") {
    try {
      await this.loadAiProviders();
      for (const provider of this.state.providers) appendOption(select, textValue(field(provider, ["id"])), textValue(field(provider, ["name"]), "未命名服务"));
      if (purpose && this.state.providers.length) {
        const configured = aiDefaultSelection(this.state.aiDefaults, purpose);
        const hasConfiguredProvider = configured.providerId && this.state.providers.some((provider) => textValue(field(provider, ["id"])) === configured.providerId);
        select.value = hasConfiguredProvider ? configured.providerId : textValue(field(this.state.providers[0], ["id"]));
      }
    } catch {
      if (this.state.providers.length) {
        for (const provider of this.state.providers) appendOption(select, textValue(field(provider, ["id"])), textValue(field(provider, ["name"]), "未命名服务"));
      } else appendOption(select, "", "暂无可用模型服务");
    }
  }

  pollTask(taskId, status, groupSelect, materialsList, detail) {
    if (this.state.taskTimer) clearTimeout(this.state.taskTimer);
    const sessionEpoch = this.state.sessionEpoch;
    const poll = async () => {
      if (!this.isSessionCurrent(sessionEpoch)) return;
      try {
        const task = await this.api.request(`/tasks/${pathId(taskId)}`);
        if (!this.isSessionCurrent(sessionEpoch)) return;
        const taskStatus = textValue(field(task, ["status"]));
        setStatus(status, `任务：${statusLabel(taskStatus)}`, materialStatusTone(taskStatus));
        const done = ["completed", "failed", "cancelled", "ready", "partial", "needs_review", "awaiting_consent"].includes(taskStatus.toLowerCase());
        if (!done) {
          if (this.isSessionCurrent(sessionEpoch)) this.state.taskTimer = setTimeout(poll, 1500);
        } else if (groupSelect && materialsList && detail) {
          await this.loadPrivacyData(groupSelect, materialsList, detail);
        } else if (this.isSessionCurrent(sessionEpoch) && detail && this.state.selectedMaterial) {
          const selectedId = textValue(field(this.state.selectedMaterial, ["id", "materialId"]));
          if (selectedId) await this.loadMaterialDetail(selectedId, detail);
        }
      } catch (error) {
        if (error?.name !== "AbortError" && this.isSessionCurrent(sessionEpoch)) setStatus(status, apiErrorMessage(error), "danger");
      }
    };
    poll();
  }

  async loadAiProviders() {
    if (this.state.providerLoadPromise) return this.state.providerLoadPromise;
    const load = (async () => {
      try {
        const response = await this.api.listAiProviders();
        const providers = response?.providers || response?.items || [];
        this.state.providers = Array.isArray(providers) ? providers : [];
        this.state.aiDefaults = response?.defaults && typeof response.defaults === "object" ? response.defaults : {};
        this.state.providerPresets = Array.isArray(response?.presets) ? response.presets : AI_PROVIDER_PRESETS;
      } catch (error) {
        // The redaction consent panel still uses the v1 provider endpoint. Keep
        // that legacy path available while an upgraded server is restarting.
        try {
          const response = await this.api.request("/providers");
          this.state.providers = parseJsonList(response?.providers);
        } catch {
          this.state.providers = [];
        }
        throw error;
      }
      return this.state.providers;
    })();
    this.state.providerLoadPromise = load;
    try {
      return await load;
    } finally {
      if (this.state.providerLoadPromise === load) this.state.providerLoadPromise = null;
    }
  }

  async loadAiMaterials({ append = false, limit = 50 } = {}) {
    const current = this.state.aiMaterialsPage;
    const cursor = append ? textValue(current.nextCursor) : "";
    if (append && !cursor) return this.state.aiMaterials;
    try {
      const response = await this.api.listAiMaterials({ limit, cursor });
      const page = normalizeCursorPage(response, ["materials"]);
      const next = normalizeAiMaterials({ materials: page.items });
      this.state.aiMaterials = append ? appendUniqueById(this.state.aiMaterials, next) : next;
      this.state.aiMaterialsPage = {
        nextCursor: page.nextCursor,
        total: page.total,
        corruptCount: page.corruptCount,
        error: "",
        loaded: true
      };
    } catch (error) {
      // Keep earlier pages selectable, including references retained from a
      // draft or conversation, while making the local storage error visible.
      const message = apiErrorMessage(error);
      this.state.aiMaterialsPage = {
        ...this.state.aiMaterialsPage,
        ...(append ? {} : { nextCursor: "", total: 0, corruptCount: 0 }),
        error: message,
        loaded: true
      };
      if (!append) this.state.aiMaterials = [];
    }
    return this.state.aiMaterials;
  }

  async loadAiRunPage(kind, { append = false, limit = 20 } = {}) {
    const key = textValue(kind);
    const previous = this.state.aiRunPages.get(key) || { items: [], nextCursor: "", total: 0, corruptCount: 0 };
    const cursor = append ? textValue(previous.nextCursor) : "";
    if (append && !cursor) return previous;
    const response = await this.api.listAiRuns(key, { limit, cursor });
    const page = normalizeCursorPage(response, ["runs", "tasks"]);
    const received = page.items.map(normalizeAiRun);
    const items = append ? appendUniqueById(previous.items, received) : received;
    const next = { items, nextCursor: page.nextCursor, total: page.total, corruptCount: page.corruptCount };
    this.state.aiRunPages.set(key, next);
    this.state.aiRuns = [...this.state.aiRuns.filter((run) => run.kind !== key), ...items];
    for (const run of items) this.rememberAiRun(run);
    return next;
  }

  renderAiMaterialPicker(materials = this.state.aiMaterials, { multiple = true, title = "选择材料", preferRedacted = true, selectedValues = [], hasMore = false, total = 0, corruptCount = 0, errorMessage = "", onLoadMore = null, onChange = () => {} } = {}) {
    const picker = node("div", { className: "ai-material-picker" });
    const initialSources = new Map((Array.isArray(selectedValues) ? selectedValues : [])
      .map((reference) => [textValue(field(reference, ["id", "material_id", "materialId"])), textValue(field(reference, ["source"]))])
      .filter(([id]) => id));
    const rows = Array.isArray(materials) ? materials.filter((material) => material.id) : [];
    const rowIds = new Set(rows.map((material) => material.id));
    const retained = [...initialSources.entries()].filter(([id]) => !rowIds.has(id)).map(([id, source]) => ({ id, source: source || "redacted" }));
    const options = { multiple, title, preferRedacted, selectedValues, hasMore, total, corruptCount, errorMessage, onLoadMore, onChange };
    const selectedValuesForPicker = () => {
      const selected = [...picker.querySelectorAll("input[data-material-id]:checked")].map((input) => {
        const row = input.closest(".material-picker-row");
        const material = rows.find((item) => item.id === input.dataset.materialId);
        const source = row?.querySelector(".material-source")?.value || aiMaterialSource(material, preferRedacted);
        return { id: input.dataset.materialId, source };
      });
      return multiple ? [...selected, ...retained] : selected.slice(0, 1);
    };
    if (!rows.length) {
      picker.append(retained.length
        ? node("p", { className: "muted small", text: `已保留 ${retained.length} 个尚未加载的已选材料；加载更多后可取消。` })
        : emptyState("暂无可用材料；请先在“材料脱敏”中完成处理。"));
      picker.values = selectedValuesForPicker;
      picker.notifySelection = () => onChange(picker.values());
      picker.refresh = (next) => this.renderAiMaterialPicker(next, options);
      if (errorMessage) picker.append(statusBox(errorMessage, "danger"));
      if (hasMore && typeof onLoadMore === "function") {
        const loadMore = button("加载更多材料", async () => {
          loadMore.disabled = true;
          try { await onLoadMore(picker.values()); } finally { loadMore.disabled = false; }
        }, "button subtle");
        picker.append(loadMore);
      }
      return picker;
    }
    const count = Number.isSafeInteger(Number(total)) && Number(total) >= rows.length ? `${rows.length} / ${total} 个材料` : `${rows.length} 个材料`;
    const header = node("div", { className: "picker-heading" }, [node("strong", { text: title }), node("span", { className: "muted small", text: count })]);
    picker.append(header);
    if (retained.length) picker.append(node("p", { className: "muted small", text: `已保留 ${retained.length} 个尚未加载的已选材料；加载更多后可取消。` }));
    if (Number(corruptCount) > 0) picker.append(statusBox(`检测到 ${Math.floor(Number(corruptCount))} 个损坏材料记录，未显示。`, "warning"));
    if (errorMessage) picker.append(statusBox(errorMessage, "danger"));
    for (const material of rows) {
      const initialSource = initialSources.get(material.id);
      const check = node("input", { type: multiple ? "checkbox" : "radio", name: multiple ? undefined : `ai-material-${title}`, ariaLabel: `选择${material.name}`, checked: initialSources.has(material.id) });
      check.dataset.materialId = material.id;
      const source = node("select", { className: "material-source", ariaLabel: `${material.name}发送版本` });
      const hasRedacted = Boolean(material.result_id) && ["ready", "completed"].includes(String(material.status).toLowerCase());
      if (hasRedacted) appendOption(source, "redacted", "发送脱敏版", preferRedacted);
      if (material.has_original || !hasRedacted) appendOption(source, "original", "发送原文", !hasRedacted && !preferRedacted);
      if (initialSource && [...source.options].some((option) => option.value === initialSource)) source.value = initialSource;
      if (!source.options.length) source.disabled = true;
      const label = node("label", { className: "material-picker-row" }, [check, node("span", { className: "material-picker-name", text: material.name }), node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) }), source]);
      picker.append(label);
      check.addEventListener("change", () => {
        if (!multiple) {
          for (const other of picker.querySelectorAll("input[data-material-id]")) if (other !== check) other.checked = false;
        }
        picker.notifySelection();
      });
      source.addEventListener("change", () => picker.notifySelection());
    }
    picker.values = selectedValuesForPicker;
    picker.notifySelection = () => onChange(picker.values());
    picker.refresh = (next) => this.renderAiMaterialPicker(next, options);
    if (hasMore && typeof onLoadMore === "function") {
      const loadMore = button("加载更多材料", async () => {
        loadMore.disabled = true;
        try { await onLoadMore(picker.values()); } finally { loadMore.disabled = false; }
      }, "button subtle");
      picker.append(loadMore);
    }
    return picker;
  }

  applyMaterialTrust(picker, provider, { notify = true } = {}) {
    if (!picker) return;
    const allowRaw = provider?.trust_raw === true || provider?.trustRaw === true;
    for (const source of picker.querySelectorAll(".material-source")) {
      const hasOriginal = [...source.options].some((option) => option.value === "original");
      if (allowRaw && hasOriginal) source.value = "original";
      else if ([...source.options].some((option) => option.value === "redacted")) source.value = "redacted";
    }
    if (notify) picker.notifySelection?.();
  }

  async uploadAiFiles(fileList, statusTarget) {
    const files = [...(fileList || [])];
    if (!files.length) return [];
    const uploaded = [];
    for (const file of files) {
      const formData = new FormData();
      formData.set("file", file, file.name);
      try {
        const response = await this.api.uploadAiAttachment(formData);
        const attachment = { ...response, id: textValue(field(response, ["id", "attachment_id", "attachmentId"])), name: textValue(field(response, ["name", "filename"]), file.name), status: textValue(response?.status, "uploaded") };
        if (attachment.id) {
          uploaded.push(attachment);
          this.state.aiAttachments = [...this.state.aiAttachments.filter((item) => item.id !== attachment.id), attachment];
        }
        setStatus(statusTarget, `已上传 ${uploaded.length} 个附件。`, "success");
      } catch (error) {
        setStatus(statusTarget, `${file.name}：${apiErrorMessage(error)}`, "danger");
      }
    }
    return uploaded;
  }

  renderAiAttachmentPicker({ accept = ".txt,.docx,.pdf,.png,.jpg,.jpeg,.webp", multiple = true, initialAttachments = [], onChange = () => {} } = {}) {
    const wrapper = node("div", { className: "ai-attachment-picker" });
    const input = node("input", { type: "file", accept, multiple });
    const status = statusBox("附件仅在点击生成/发送后随任务提交。", "muted");
    const list = node("div", { className: "attachment-list" });
    const selected = new Map((Array.isArray(initialAttachments) ? initialAttachments : []).map((attachment) => {
      const id = textValue(field(attachment, ["id", "attachment_id", "attachmentId"]));
      return [id, { ...attachment, id, name: textValue(field(attachment, ["name", "filename"]), "已保存附件") }];
    }).filter(([id]) => id));
    const renderSelected = () => {
      replaceChildren(list, [...selected.values()].map((item) => {
        const remove = button("移除", () => {
          selected.delete(item.id);
          renderSelected();
          wrapper.notifySelection();
        }, "button subtle attachment-remove");
        return node("span", { className: "attachment-chip" }, [node("span", { text: item.name }), remove]);
      }));
    };
    input.addEventListener("change", async () => {
      const uploaded = await this.uploadAiFiles(input.files, status);
      for (const item of uploaded) selected.set(item.id, item);
      renderSelected();
      wrapper.notifySelection();
      input.value = "";
    });
    wrapper.append(labelFor("上传附件", input), list, status);
    wrapper.attachmentIds = () => [...selected.keys()];
    wrapper.attachments = () => [...selected.values()];
    wrapper.setAttachments = (attachments) => {
      selected.clear();
      for (const attachment of Array.isArray(attachments) ? attachments : []) {
        const id = textValue(field(attachment, ["id", "attachment_id", "attachmentId"]));
        if (id) selected.set(id, { ...attachment, id, name: textValue(field(attachment, ["name", "filename"]), "已保存附件") });
      }
      renderSelected();
    };
    wrapper.notifySelection = () => onChange(wrapper.attachmentIds());
    renderSelected();
    return wrapper;
  }

  renderContextRangePicker({ title = "材料范围", getMaterials = () => [], getAttachmentIds = () => [], onChanged = () => {} } = {}) {
    const picker = node("div", { className: "context-range-picker" });
    const selections = new Map();
    const sources = () => contextRangeSources(getMaterials(), getAttachmentIds());
    const selectionFor = (source) => {
      const key = contextRangeSourceKey(source);
      let selection = selections.get(key);
      if (!selection) {
        selection = { mode: "all", rangesText: "", ranges: [], inspection: null };
        selections.set(key, selection);
      }
      return selection;
    };
    const clearRemoved = () => {
      const live = new Set(sources().map(contextRangeSourceKey));
      for (const key of selections.keys()) if (!live.has(key)) selections.delete(key);
    };
    const sourceLabelFor = (source) => {
      if (source.source_kind === "material") {
        const material = this.state.aiMaterials.find((item) => textValue(field(item, ["id"])) === source.source_id);
        const name = textValue(field(material, ["name", "title"]), source.source_id);
        return `材料 ${name}${source.source === "original" ? " · 原文" : " · 脱敏版"}`;
      }
      const attachment = this.state.aiAttachments.find((item) => textValue(field(item, ["id"])) === source.source_id);
      return `附件 ${textValue(field(attachment, ["name", "filename"]), source.source_id)}`;
    };
    const currentRanges = () => {
      const entries = sources();
      if (!entries.length) return { ranges: [], error: "" };
      const ranges = [];
      for (const source of entries) {
        const selection = selectionFor(source);
        if (selection.mode === "all") {
          ranges.push({ ...source, mode: "all" });
          continue;
        }
        const inspection = selection.inspection;
        const restored = selection.restoredRange;
        if (!inspection && restored?.inspection_hash && Array.isArray(restored.ranges) && restored.ranges.length) {
          ranges.push(restored);
          continue;
        }
        const parsed = parseContextUnitRanges(selection.rangesText, { max: inspection?.unitCount || 0 });
        if (!inspection || !inspection.inspectionHash || !["pages", "paragraphs"].includes(selection.mode) || !parsed?.length) {
          return { ranges: [], error: `${source.source_kind === "material" ? "材料" : "附件"} ${source.source_id} 的页/段落范围尚未检查或格式无效。` };
        }
        ranges.push({ ...source, mode: selection.mode, ranges: parsed, inspection_hash: inspection.inspectionHash });
      }
      return { ranges, error: "" };
    };
    const render = () => {
      clearRemoved();
      const entries = sources();
      if (!entries.length) {
        replaceChildren(picker, [heading(3, title), node("p", { className: "muted small", text: "未选择材料或附件；提交时将显式发送空范围。" })]);
        return;
      }
      const rows = entries.map((source) => {
        const selection = selectionFor(source);
        const inspection = selection.inspection;
        const sourceLabel = sourceLabelFor(source);
        const inspect = button("检查页/段落", async () => {
          inspect.disabled = true;
          try {
            const response = await this.api.inspectAiContextSource(source);
            const result = response?.inspection || response;
            const sameSource = textValue(field(result, ["source_kind", "sourceKind"])) === source.source_kind
              && textValue(field(result, ["source_id", "sourceId"])) === source.source_id
              && (source.source_kind !== "material" || textValue(field(result, ["source"])) === source.source);
            const unitKind = textValue(field(result, ["unit_kind", "unitKind"]));
            const scopeMode = unitKind === "page" ? "pages" : unitKind === "paragraph" ? "paragraphs" : "";
            const unitCount = Number(field(result, ["unit_count", "unitCount"]));
            const inspectionHash = textValue(field(result, ["inspection_hash", "inspectionHash"]));
            if (!sameSource || !scopeMode || !Number.isSafeInteger(unitCount) || unitCount < 1 || !inspectionHash) throw new ApiError("invalid_response", false, 200);
            selection.inspection = {
              unitKind,
              scopeMode,
              unitCount,
              inspectionHash,
              unitVersion: textValue(field(result, ["unit_version", "unitVersion"])),
              estimateBasis: textValue(field(result, ["estimate_basis", "estimateBasis"])),
              estimatedInputTokens: boundedTokenCount(field(result, ["estimated_input_tokens", "estimatedInputTokens"]))
            };
            if (selection.mode !== scopeMode) {
              selection.mode = "all";
              selection.rangesText = "";
              selection.ranges = [];
            }
            selection.restoredRange = null;
            render();
          } catch (error) {
            rowStatus.textContent = `无法检查范围：${apiErrorMessage(error)}`;
            rowStatus.className = "status-message danger";
          } finally {
            inspect.disabled = false;
          }
        }, "button subtle");
        const mode = node("select", { ariaLabel: `${sourceLabel}范围模式` });
        appendOption(mode, "all", "全部");
        const scopedMode = inspection?.scopeMode || (["pages", "paragraphs"].includes(selection.mode) ? selection.mode : "");
        if (scopedMode) appendOption(mode, scopedMode, scopedMode === "pages" ? "指定页" : "指定段落");
        mode.value = scopedMode && selection.mode === scopedMode ? selection.mode : "all";
        const rangeInput = node("input", { type: "text", placeholder: inspection?.scopeMode === "pages" ? "例如 1-3, 5" : "例如 1-4, 8", value: selection.rangesText, ariaLabel: `${sourceLabel}范围` });
        rangeInput.hidden = mode.value === "all";
        const apply = button("应用范围", () => {
          if (!inspection) {
            rowStatus.textContent = "请先检查页/段落范围，再修改指定范围。";
            rowStatus.className = "status-message danger";
            return;
          }
          const parsed = parseContextUnitRanges(rangeInput.value, { max: inspection?.unitCount || 0 });
          if (!parsed?.length) {
            rowStatus.textContent = `范围须为 1–${inspection?.unitCount || "?"} 的页/段落编号，例如 1-3, 5。`;
            rowStatus.className = "status-message danger";
            return;
          }
          selection.mode = mode.value;
          selection.rangesText = rangeInput.value;
          selection.ranges = parsed;
          selection.restoredRange = null;
          rowStatus.textContent = "范围已应用；需重新预检或准备后才能发送。";
          rowStatus.className = "status-message warning";
          onChanged();
        }, "button subtle");
        apply.hidden = rangeInput.hidden;
        const rowStatus = statusBox(inspection
          ? `已检查 ${inspection.scopeMode === "pages" ? "页" : "段落"}：共 ${inspection.unitCount} 个单位${inspection.estimatedInputTokens ? ` · 约 ${inspection.estimatedInputTokens} tokens` : ""}${inspection.estimateBasis ? ` · ${inspection.estimateBasis}` : ""}`
          : selection.restoredRange ? "已恢复指定范围；重新检查后才能修改范围。"
            : "未检查时将发送全部范围。", inspection ? "success" : selection.restoredRange ? "warning" : "muted");
        mode.addEventListener("change", () => {
          selection.mode = mode.value;
          if (selection.mode === "all") {
            selection.rangesText = "";
            selection.ranges = [];
            selection.restoredRange = null;
            onChanged();
          }
          render();
        });
        return node("div", { className: "context-range-row" }, [
          node("strong", { text: sourceLabel }),
          node("div", { className: "button-row" }, [mode, inspect]),
          rangeInput,
          apply,
          rowStatus
        ]);
      });
      replaceChildren(picker, [heading(3, title), node("p", { className: "muted small", text: "选择全部时按预算处理整份材料；指定页码或段落前，先在本机检查范围。检查不会调用模型。范围、来源或版本变化后，先重新预检或准备。" }), ...rows]);
    };
    picker.contextRanges = currentRanges;
    picker.setContextRanges = (value) => {
      selections.clear();
      const supplied = normalizedDraftContextRanges({ context_ranges: value });
      const byKey = new Map(supplied.map((item) => [contextRangeSourceKey(item), item]));
      for (const source of sources()) {
        const restored = byKey.get(contextRangeSourceKey(source));
        if (!restored) continue;
        const selection = selectionFor(source);
        selection.mode = restored.mode;
        selection.ranges = restored.ranges || [];
        selection.rangesText = selection.ranges.map((range) => range.start === range.end ? String(range.start) : `${range.start}-${range.end}`).join(", ");
        selection.restoredRange = restored.mode === "all" ? null : restored;
      }
      render();
    };
    picker.syncSources = ({ notify = false } = {}) => {
      clearRemoved();
      render();
      if (notify) onChanged();
    };
    render();
    return picker;
  }

  async createAiRun(payload, { page, status, onUpdate, onDone } = {}) {
    const response = await this.api.createAiRun(payload);
    const run = this.rememberAiRun(response?.run || response);
    if (!run.id) throw new ApiError("run_id_missing", false, 200);
    if (page) this.selectPageRun(page, run);
    if (run.kind === AI_RUN_KINDS.chat) this.state.currentChatRunId = run.id;
    setStatus(status, `任务已创建：${aiRunStatusLabel(run.status)}`, "info");
    this.pollAiRun(run.id, { status, onUpdate, onDone });
    return run;
  }

  pollAiRun(id, { status, onUpdate, onDone } = {}) {
    const key = String(id || "");
    if (!key) return () => {};
    const scope = this.state.activeRenderScope || "detached";
    let unsubscribe = () => {};
    let retryControl = status?.aiRunPollRetryControl || null;
    const ensureRetryControl = () => {
      if (retryControl || !status?.parentElement) return retryControl;
      retryControl = button("重新连接并更新状态", () => {
        retryControl.disabled = true;
        start();
      }, "button subtle");
      retryControl.hidden = true;
      status.aiRunPollRetryControl = retryControl;
      status.parentElement.insertBefore(retryControl, status.nextSibling);
      return retryControl;
    };
    const start = () => {
      retryControl && (retryControl.hidden = true);
      unsubscribe = this.aiRunPoller.subscribe(key, {
        scope,
        onUpdate: (run) => {
          retryControl && (retryControl.hidden = true);
          onUpdate?.(run);
          const terminal = aiRunIsTerminal(run);
          setStatus(status, `${aiRunKindLabel(run.kind)}：${aiRunStatusLabel(run.status)}${run.stage ? ` · ${pipelineStageLabel(run.stage)}` : ""} · ${aiRunProgressText(run)}`, terminal && run.status === "completed" ? "success" : terminal ? "warning" : "info");
        },
        onDone,
        onError: (error, detail = {}) => {
          if (detail.retryable && !detail.exhausted) {
            const seconds = Math.max(1, Math.ceil(Number(detail.retryDelayMs || 0) / 1000));
            setStatus(status, `连接暂时失败（第 ${detail.consecutiveFailures}/${detail.maxConsecutiveFailures} 次），将在约 ${seconds} 秒后重试。`, "warning");
            return;
          }
          if (detail.retryable && detail.exhausted) {
            const control = ensureRetryControl();
            if (control) {
              control.disabled = false;
              control.hidden = false;
            }
            setStatus(status, "与本机服务连接异常，已停止自动更新。请检查服务后重新连接。", "danger");
            return;
          }
          setStatus(status, apiErrorMessage(error), "danger");
        }
      });
      return unsubscribe;
    };
    start();
    return () => {
      unsubscribe();
      retryControl?.remove();
      if (status?.aiRunPollRetryControl === retryControl) delete status.aiRunPollRetryControl;
    };
  }

  async loadWritingDraft(draft = this.state.writingDraft, { sessionEpoch = this.state.sessionEpoch } = {}) {
    const id = draft.id;
    try {
      const response = await this.api.getAiDraft(id);
      if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
      const record = response?.draft || response || {};
      draft.revision = aiRunRevision(record, 0);
      draft.loaded = true;
      draft.exists = true;
      draft.lastContent = writingDraftContent(record.content || record);
      return draft.lastContent;
    } catch (error) {
      if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
      if (error?.name === "AbortError") throw error;
      if (error instanceof ApiError && (error.status === 404 || error.code === "not_found")) {
        draft.revision = 0;
        draft.loaded = true;
        draft.exists = false;
        draft.lastContent = writingDraftContent();
        return draft.lastContent;
      }
      throw error;
    }
  }

  queueWritingDraft(content, status, draft = this.state.writingDraft) {
    if (draft.clearing) return;
    draft.pending = { content: writingDraftContent(content), status, sequence: ++draft.sequence };
    draft.lastContent = draft.pending.content;
    draft.retryAttempts = 0;
    draft.retryStopped = false;
    status?.retryControl && (status.retryControl.hidden = true);
    if (draft.timer) clearTimeout(draft.timer);
    setStatus(status, "草稿待保存…", "info");
    draft.timer = setTimeout(() => {
      draft.timer = null;
      void this.flushWritingDraft(draft);
    }, 500);
  }

  async saveWritingConflictCandidate(draft, pending, sessionEpoch) {
    const candidateId = writingDraftCandidateId(draft.id);
    if (!candidateId) throw new ApiError("draft_conflict_candidate_invalid", false, 409);
    const response = await this.api.saveAiDraft(candidateId, {
      expected_revision: 0,
      content: pending.content
    });
    if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
    const record = response?.draft || response || {};
    const candidate = {
      id: candidateId,
      revision: aiRunRevision(record, 1),
      updated_at: textValue(field(record, ["updated_at", "updatedAt"]))
    };
    draft.conflicts = [candidate, ...draft.conflicts.filter((item) => item.id !== candidate.id)];
    draft.onConflictsChanged?.(draft.conflicts);
    return candidate;
  }

  async loadWritingDraftConflicts(draft = this.state.writingDraft, { sessionEpoch = this.state.sessionEpoch, append = false } = {}) {
    if (typeof this.api.listAiDraftConflicts !== "function") return [];
    const cursor = append ? textValue(draft.conflictNextCursor) : "";
    // The service returns metadata only. Keep each page until the user asks
    // for more; candidates after the first page must remain discoverable.
    const load = this.api.listAiDraftConflicts(draft.id, { limit: 20, ...(cursor ? { cursor } : {}) });
    draft.conflictLoadPromise = load;
    try {
      const response = await load;
      if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
      const source = response?.drafts || response?.items || [];
      const next = Array.isArray(source) ? source
        .map((item) => ({
          id: textValue(field(item, ["id"])),
          revision: aiRunRevision(item, 0),
          updated_at: textValue(field(item, ["updated_at", "updatedAt"]))
        }))
        .filter((item) => /^[-A-Za-z0-9_]+-c-[a-f0-9]{32}$/u.test(item.id)) : [];
      draft.conflicts = append
        ? appendUniqueById(draft.conflicts, next)
        : next;
      draft.conflictNextCursor = textValue(response?.next_cursor ?? response?.nextCursor);
      const total = Number(response?.total);
      const corruptCount = Number(response?.corrupt_count ?? response?.corruptCount);
      draft.conflictTotal = Number.isSafeInteger(total) && total >= 0 ? total : draft.conflicts.length;
      draft.conflictCorruptCount = Number.isSafeInteger(corruptCount) && corruptCount >= 0 ? corruptCount : 0;
      draft.onConflictsChanged?.(draft.conflicts);
      return draft.conflicts;
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      // Candidate discovery is additive: an unavailable list must never
      // prevent loading the canonical encrypted draft.
      return draft.conflicts;
    } finally {
      if (draft.conflictLoadPromise === load) draft.conflictLoadPromise = null;
    }
  }

  async flushWritingDraft(draft = this.state.writingDraft) {
    if (draft.clearing || draft.saving || !draft.pending) return draft.savingPromise;
    const pending = draft.pending;
    const sessionEpoch = this.state.sessionEpoch;
    draft.pending = null;
    draft.saving = true;
    setStatus(pending.status, "草稿保存中…", "info");
    const save = this.api.saveAiDraft(draft.id, {
      expected_revision: draft.revision,
      content: pending.content
    });
    draft.savingPromise = save;
    try {
      const response = await save;
      if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
      const record = response?.draft || response || {};
      draft.revision = aiRunRevision(record, draft.revision + 1);
      draft.loaded = true;
      draft.exists = true;
      draft.lastContent = pending.content;
      draft.retryAttempts = 0;
      pending.status?.retryControl && (pending.status.retryControl.hidden = true);
      setStatus(pending.status, "草稿已加密保存到本机。", "success");
    } catch (error) {
      if (error?.name === "AbortError") return;
      if (error instanceof ApiError && (error.status === 409 || error.code === "revision_conflict")) {
        try {
          const candidate = await this.saveWritingConflictCandidate(draft, pending, sessionEpoch);
          draft.retryStopped = true;
          pending.status?.retryControl && (pending.status.retryControl.hidden = true);
          setStatus(pending.status, `草稿发生冲突，已加密保留独立副本（${candidate.id.slice(-8)}）。请选择恢复、采用远端或合并。`, "warning");
        } catch (candidateError) {
          if (candidateError?.name === "AbortError") return;
          draft.pending = pending;
          draft.retryStopped = true;
          if (pending.status?.retryControl) pending.status.retryControl.hidden = false;
          setStatus(pending.status, `草稿未保存：冲突副本也未保存（${apiErrorMessage(candidateError)}）。`, "danger");
        }
        return;
      }
      // A newer edit wins over the failed write; never revive an older body.
      if (!draft.clearing && (!draft.pending || draft.pending.sequence <= pending.sequence)) draft.pending = pending;
      const retryable = isRetryableAiPollError(error);
      draft.retryAttempts = retryable ? draft.retryAttempts + 1 : 0;
      draft.retryStopped = !retryable || draft.retryAttempts >= 3;
      if (draft.retryStopped && pending.status?.retryControl) pending.status.retryControl.hidden = false;
      setStatus(pending.status, `草稿未保存：${apiErrorMessage(error)}`, "danger");
    } finally {
      draft.saving = false;
      draft.savingPromise = null;
      if (draft.pending && !draft.timer && !draft.clearing && !draft.retryStopped) {
        const delay = 1000 * (3 ** Math.max(0, draft.retryAttempts - 1));
        draft.timer = setTimeout(() => {
          draft.timer = null;
          void this.flushWritingDraft(draft);
        }, delay);
      }
    }
  }

  async clearWritingDraft(status, draft = this.state.writingDraft) {
    const sessionEpoch = this.state.sessionEpoch;
    draft.clearing = true;
    if (draft.timer) clearTimeout(draft.timer);
    draft.timer = null;
    draft.pending = null;
    try {
      // Wait for the write continuation too: it advances revision after the
      // HTTP promise settles.  Deleting with the advanced revision prevents a
      // late in-flight PUT from recreating a cleared draft.
      if (draft.savingPromise) {
        await draft.savingPromise.catch(() => {});
        await Promise.resolve();
      }
      await this.api.deleteAiDraft(draft.id, draft.revision);
      if (!this.isSessionCurrent(sessionEpoch)) throw staleAsyncError();
      draft.revision = 0;
      draft.loaded = true;
      draft.exists = false;
      setStatus(status, "本机草稿已清除。", "success");
    } catch (error) {
      if (error?.name === "AbortError") return;
      if (error instanceof ApiError && (error.status === 404 || error.code === "not_found")) {
        draft.revision = 0;
        return;
      }
      setStatus(status, apiErrorMessage(error), "danger");
    } finally {
      draft.clearing = false;
    }
  }

  renderRunCitations(target, citations = []) {
    const rows = Array.isArray(citations) ? citations : [];
    if (!rows.length) {
      replaceChildren(target);
      return;
    }
    replaceChildren(target, [heading(3, "法律依据"), ...rows.map((citation) => {
      const title = textValue(field(citation, ["title", "label", "document_title"]), "未命名法条");
      const article = textValue(field(citation, ["article", "article_number", "articleNumber"]));
      const reason = textValue(field(citation, ["reason", "description", "relevance"]));
      const id = textValue(field(citation, ["article_id", "articleId", "case_id", "caseId", "id"]));
      const open = id ? button(`${title}${article ? ` · ${article}` : ""}`, () => this.openCitation(citation), "link-button") : node("strong", { text: `${title}${article ? ` · ${article}` : ""}` });
      return node("div", { className: "citation-item" }, [open, reason ? node("p", { className: "result-meta", text: reason }) : null]);
    })]);
  }

  renderCitationVerification(target, run, { locallyPending = false, onUpdated = null } = {}) {
    if (!target) return null;
    const normalizedRun = normalizeAiRun(run);
    const verification = normalizeCitationVerification(normalizedRun.citationVerification);
    const hasVerification = Boolean(field(normalizedRun, ["citation_verification", "citationVerification"])) || normalizedRun.citations.length > 0;
    if (!hasVerification) {
      replaceChildren(target);
      return verification;
    }
    const state = locallyPending ? "stale" : verification.state;
    const binding = [
      verification.bodySha256 ? `正文校验 ${verification.bodySha256.slice(0, 12)}` : "正文校验未返回",
      `文书版本 ${verification.runRevision || aiRunRevision(normalizedRun) || "未返回"}`,
      verification.caseDate ? `文书适用日期 ${verification.caseDate}` : "文书适用日期未设置"
    ];
    const reasons = verification.reasons.map(citationVerificationReasonLabel);
    const sourceRows = verification.sources.map((source) => {
      const sourceName = [source.sourceKind || "来源", source.sourceId || source.documentId || "未命名"].filter(Boolean).join(" · ");
      const checks = [
        ["来源存在", "sourceExists", source.sourceExists],
        ["全文读取", "fullTextRead", source.fullTextRead],
        ["引文匹配", "citationMatch", source.citationMatch],
        ["时间核验", "timeCheck", source.timeCheck]
      ];
      const details = [
        source.citationLocator ? `定位 ${source.citationLocator}` : "定位信息未返回",
        source.matchedRanges.length ? `匹配区间 ${source.matchedRanges.map((range) => `${range.start}–${range.end} bytes`).join("、")}` : "未返回匹配区间",
        source.sourceFullTextSha256 ? `来源全文校验 ${source.sourceFullTextSha256.slice(0, 12)}` : "来源全文校验未返回",
        source.quoteSha256 ? `引文校验 ${source.quoteSha256.slice(0, 12)}` : "引文校验未返回",
        source.sourceContentState === "changed" ? "引用来源内容已变动，待重新核验" : "",
        citationErrorCategoryLabel(source.errorCategory)
      ].filter(Boolean);
      return node("li", { className: "citation-verification-source" }, [
        node("strong", { text: sourceName }),
        node("ul", { className: "citation-check-list" }, checks.map(([label, kind, value]) => node("li", { className: citationCheckTone(kind, value), text: `${label}：${citationCheckLabel(kind, value)}` }))),
        node("p", { className: "muted small", text: details.join(" · ") })
      ]);
    });
    const recheck = button("重新机械核验", async () => {
      recheck.disabled = true;
      try {
        const response = await this.api.recheckAiRunCitations(normalizedRun.id, aiRunRevision(normalizedRun));
        const next = normalizeAiRun(response?.run || response);
        if (!next.id) throw new ApiError("run_id_missing", false, 200);
        await onUpdated?.(next);
      } catch (error) {
        target.prepend(statusBox(apiErrorMessage(error), "danger"));
      } finally {
        recheck.disabled = false;
      }
    }, "button subtle");
    recheck.disabled = !normalizedRun.id || locallyPending;
    replaceChildren(target, [
      heading(3, "引用机械核验"),
      statusBox(`${citationVerificationStateLabel(state)}${locallyPending ? "。本地正文或日期已变更，旧校验不能继续使用。" : "。"}`, state === "passed" ? "success" : state === "pending" ? "info" : "warning"),
      node("p", { className: "muted small", text: binding.join(" · ") }),
      reasons.length ? node("p", { className: "muted small", text: `待处理原因：${reasons.join("；")}` }) : null,
      sourceRows.length ? node("ul", { className: "citation-verification-list" }, sourceRows) : node("p", { className: "muted small", text: "本结果没有可机械核验的来源记录。" }),
      node("p", { className: "muted small", text: `机械校验不判断论证相关性；引用与论证的相关性始终需要人工复核。${verification.verifiedAt ? ` 最近核验：${verification.verifiedAt}` : ""}` }),
      recheck
    ]);
    return verification;
  }

  renderContextEstimate(target, value) {
    if (!target) return null;
    const estimate = normalizeAiContextEstimate(value);
    const tone = estimate.stage === "ready" ? "success" : estimate.stage === "conservative" ? "warning" : "danger";
    const capabilityText = estimate.capabilities.verified
      ? `模型上下文能力已配置：输入上限 ${estimate.capabilities.maxInputTokens || "未返回"} tokens，预留输出 ${estimate.capabilities.maxOutputTokens || "未返回"} tokens。`
      : "模型上下文能力未核实；本机按输入 16k、输出 4k 的保守上限预检。";
    const totals = [
      `预计输入 ${estimate.estimate.inputTokens} tokens`,
      `预留输出 ${estimate.estimate.reservedOutputTokens} tokens`,
      `历史 ${estimate.estimate.historyTokens}`,
      `材料 ${estimate.estimate.materialTokens}`,
      `附件 ${estimate.estimate.attachmentTokens}`,
      `工具预留 ${estimate.estimate.toolReserveTokens}`
    ];
    const selectedRows = [];
    for (const item of estimate.selectedScope.materials) selectedRows.push(node("li", { text: `材料 ${item.id || "未命名"}${item.source ? ` · ${item.source === "original" ? "原文" : "脱敏版"}` : ""}${item.locators.length ? ` · ${item.locators.join("、")}` : ""}` }));
    for (const item of estimate.selectedScope.attachments) selectedRows.push(node("li", { text: `附件 ${item.id || "未命名"}${item.format ? ` · ${item.format}` : ""}${item.locators.length ? ` · ${item.locators.join("、")}` : ""}` }));
    if (estimate.selectedScope.historyRunIds.length) selectedRows.push(node("li", { text: `保留历史轮次：${estimate.selectedScope.historyRunIds.join("、")}` }));
    const omittedRows = estimate.omittedScope.map((item) => node("li", { text: `${item.sourceKind || "上下文"}${item.sourceId ? ` ${item.sourceId}` : ""} · ${contextOmissionReasonLabel(item.reason)}${item.estimatedTokens ? ` · 约 ${item.estimatedTokens} tokens` : ""}` }));
    replaceChildren(target, [
      heading(3, "上下文预算预检"),
      statusBox(`${contextBudgetStageLabel(estimate.stage)}。${capabilityText}`, tone),
      node("p", { className: "muted small", text: totals.join(" · ") }),
      heading(4, "本次实际采用范围"),
      selectedRows.length ? node("ul", { className: "context-scope-list" }, selectedRows) : node("p", { className: "muted small", text: "本次未采用材料、附件或历史轮次。" }),
      heading(4, "未采用范围及原因"),
      omittedRows.length ? node("ul", { className: "context-scope-list" }, omittedRows) : node("p", { className: "muted small", text: "没有因预算或元数据限制省略的范围。" }),
      node("p", { className: "muted small", text: "相关性判断始终由人工负责；本预检只说明本次可读取的上下文范围。" })
    ]);
    return estimate;
  }

  async preflightAiContext(payload, target, status) {
    setStatus(status, "正在预检本次上下文范围…", "info");
    try {
      const response = await this.api.estimateAiContext(payload);
      const estimate = this.renderContextEstimate(target, response);
      if (!contextEstimateCanProceed(estimate)) {
        setStatus(status, `${contextBudgetStageLabel(estimate.stage)}，请调整材料、页码范围或历史范围后重试。`, "warning");
        return null;
      }
      if (!estimate.planHash) {
        setStatus(status, "上下文预算预检未返回可绑定的计划标识，未提交生成请求。", "danger");
        return null;
      }
      setStatus(status, estimate.capabilities.verified ? "上下文预算已按已配置模型能力预检。" : "上下文预算按保守上限预检，模型能力尚未核实。", estimate.capabilities.verified ? "success" : "warning");
      return estimate;
    } catch (error) {
      replaceChildren(target, [heading(3, "上下文预算预检"), statusBox(apiErrorMessage(error), "danger")]);
      setStatus(status, `无法完成上下文预算预检：${apiErrorMessage(error)}`, "danger");
      return null;
    }
  }

  async openCitation(citation) {
    const article = textValue(field(citation, ["article_id", "articleId"]));
    const legalCase = textValue(field(citation, ["case_id", "caseId"]));
    if (!article && !legalCase) return;
    // renderLegal is asynchronous and navigation starts it synchronously, so
    // place the target in state before rendering the new page.
    this.state.pendingCitation = { article, legalCase };
    // Citations are actionable links to the local source detail.  Leave the
    // AI-only layout before navigation so the selected article/case is visible
    // immediately after the new legal page is rendered.
    this.state.legalMode = article ? LEGAL_SEARCH_MODES.statute : LEGAL_SEARCH_MODES.case;
    this.navigate("legal");
  }

  async renderLegal(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "法律检索"), node("p", { text: "在本地法律库中查询法条和最高人民法院案例，按需查看原文与官方来源。" })]);
    const layout = node("div", { className: "workspace-grid legal-grid" });
    const searchColumn = node("div", { className: "workspace-column legal-search-column" });
    const detailColumn = node("div", { className: "workspace-column legal-detail-column" });
    layout.append(searchColumn, detailColumn);
    main.append(title, layout);

    const searchPanel = panel("搜索法律库");
    const modeSwitcher = node("div", { className: "legal-mode-switch", role: "tablist", ariaLabel: "法律资源类型" });
    const statuteMode = button("法条", () => setMode("statute"), "button subtle legal-mode-button");
    const aiMode = button("AI搜索", () => setMode("ai"), "button subtle legal-mode-button");
    const caseMode = button("案例", () => setMode("case"), "button subtle legal-mode-button");
    statuteMode.setAttribute("role", "tab");
    aiMode.setAttribute("role", "tab");
    caseMode.setAttribute("role", "tab");
    modeSwitcher.append(statuteMode, aiMode, caseMode);

    const searchForm = node("form", { className: "search-form" });
    const filters = this.state.legalQueryFilters;
    const query = node("input", { type: "search", placeholder: "输入法条、关键词或文号", required: true, autocomplete: "off", value: this.state.legalMode === LEGAL_SEARCH_MODES.case ? this.state.legalCaseQuery : this.state.legalArticleQuery });
    query.addEventListener("input", () => {
      if (this.state.legalMode === LEGAL_SEARCH_MODES.case) this.state.legalCaseQuery = query.value;
      else if (this.state.legalMode === LEGAL_SEARCH_MODES.statute) {
        this.state.legalArticleQuery = query.value;
        this.state.legalQueryFilters.documentId = "";
        this.state.legalQueryFilters.documentTitle = "";
      }
    });
    const caseDate = node("input", { type: "date", value: filters.caseDate });
    const caseType = node("select", { required: true });
    appendOption(caseType, CASE_TYPES.all, "全部（指导、参考及典型案例）", this.state.legalCaseType === CASE_TYPES.all);
    appendOption(caseType, CASE_TYPES.guiding, "仅指导案例", this.state.legalCaseType === CASE_TYPES.guiding);
    appendOption(caseType, CASE_TYPES.reference, "仅参考案例", this.state.legalCaseType === CASE_TYPES.reference);
    appendOption(caseType, CASE_TYPES.typical, "仅典型案例合集", this.state.legalCaseType === CASE_TYPES.typical);
    const includeWithdrawn = node("input", { type: "checkbox", checked: this.state.legalIncludeWithdrawn === true, ariaLabel: "包含不再参照的历史案例" });
    const includeWithdrawnLabel = node("label", { className: "checkbox-label" }, [includeWithdrawn, node("span", { text: "包含不再参照的历史案例" })]);
    const lawOptions = node("div", { className: "legal-law-options" }, [labelFor("适用日期（选择“按日期范围”后使用）", caseDate)]);
    const caseOptions = node("div", { className: "legal-case-options" }, [labelFor("案例分类", caseType), includeWithdrawnLabel]);
    const statuteFilters = node("div", { className: "legal-statute-filters" });
    const matchModeFilter = node("select", { ariaLabel: "关键词匹配方式", value: legalMatchMode(filters.matchMode) });
    appendOption(matchModeFilter, "all", "全部词均匹配（默认）", legalMatchMode(filters.matchMode) === "all");
    appendOption(matchModeFilter, "any", "任一词匹配", legalMatchMode(filters.matchMode) === "any");
    appendOption(matchModeFilter, "phrase", "按完整短语匹配", legalMatchMode(filters.matchMode) === "phrase");
    const versionScopeFilter = node("select", { ariaLabel: "版本范围", value: legalVersionScope(filters.versionScope) });
    appendOption(versionScopeFilter, "current", "当前有效版本（默认）", legalVersionScope(filters.versionScope) === "current");
    appendOption(versionScopeFilter, "as_of", "按日期范围", legalVersionScope(filters.versionScope) === "as_of");
    appendOption(versionScopeFilter, "all", "全部版本", legalVersionScope(filters.versionScope) === "all");
    const versionStatusFilter = node("select", { ariaLabel: "版本状态", value: filters.versionStatus });
    const addVersionStatusOptions = (entries = []) => {
      const selected = versionStatusFilter.value || filters.versionStatus;
      replaceChildren(versionStatusFilter);
      appendOption(versionStatusFilter, "", "全部版本状态");
      const values = entries.length ? entries : ["in_force", "amended", "not_yet_effective", "repealed", "unspecified"];
      for (const entry of values) {
        const id = typeof entry === "string" ? entry : textValue(field(entry, ["id", "value", "code", "key"]));
        const label = typeof entry === "string" ? legalStatusLabel(entry) : textValue(field(entry, ["label", "name", "title"]), legalStatusLabel(id));
        if (id) appendOption(versionStatusFilter, id, label, id === selected);
      }
      versionStatusFilter.value = selected;
    };
    addVersionStatusOptions();
    const versionStatusRow = labelFor("版本状态", versionStatusFilter);
    const documentScope = node("div", { className: "legal-document-scope" });
    const typeFilter = node("select", { ariaLabel: "法律类型", value: filters.type });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.type) appendOption(typeFilter, value, label);
    const levelFilter = node("select", { ariaLabel: "效力层级", value: filters.level });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.level) appendOption(levelFilter, value, label);
    const regionFilter = node("input", { type: "search", placeholder: "地域（可选）", ariaLabel: "地域", value: filters.region });
    const statusFilter = node("select", { ariaLabel: "有效状态", value: filters.status });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.status) appendOption(statusFilter, value, label);
    const sortFilter = node("select", { ariaLabel: "排序方式", value: filters.sort });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.sort) appendOption(sortFilter, value, label);
    const viewFilter = node("select", { ariaLabel: "结果视图", value: filters.view });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.view) appendOption(viewFilter, value, label, value === filters.view);
    const includeHistory = node("input", { type: "checkbox", checked: filters.includeHistory, ariaLabel: "显示历史版本" });
    const includeRelations = node("input", { type: "checkbox", checked: filters.includeRelations, ariaLabel: "显示关联法规" });
    const filterToggles = node("div", { className: "legal-filter-toggles" }, [
      node("label", { className: "checkbox-label" }, [includeHistory, node("span", { text: "查看历史版本" })]),
      node("label", { className: "checkbox-label" }, [includeRelations, node("span", { text: "查看关联法规" })])
    ]);
    const jurisdictionList = node("datalist", { id: "legal-jurisdictions" });
    regionFilter.setAttribute("list", "legal-jurisdictions");
    statuteFilters.append(labelFor("关键词匹配", matchModeFilter), labelFor("版本范围", versionScopeFilter), versionStatusRow, documentScope, labelFor("法律类型", typeFilter), labelFor("效力层级", levelFilter), labelFor("地域", regionFilter), jurisdictionList, labelFor("有效状态", statusFilter), labelFor("排序", sortFilter), labelFor("显示方式", viewFilter), filterToggles);
    typeFilter.value = filters.type;
    levelFilter.value = filters.level;
    statusFilter.value = filters.status;
    sortFilter.value = filters.sort;
    viewFilter.value = filters.view;
    const persistLegalFilters = () => {
      this.state.legalQueryFilters = {
        caseDate: caseDate.value,
        matchMode: legalMatchMode(matchModeFilter.value),
        versionScope: legalVersionScope(versionScopeFilter.value),
        versionStatus: versionStatusFilter.value,
        documentId: this.state.legalQueryFilters.documentId,
        documentTitle: this.state.legalQueryFilters.documentTitle,
        type: typeFilter.value,
        level: levelFilter.value,
        region: regionFilter.value,
        status: statusFilter.value,
        sort: sortFilter.value,
        view: viewFilter.value,
        includeHistory: includeHistory.checked,
        includeRelations: includeRelations.checked
      };
    };
    const renderDocumentScope = () => {
      const documentId = textValue(this.state.legalQueryFilters.documentId);
      const title = textValue(this.state.legalQueryFilters.documentTitle, documentId);
      if (!documentId) {
        replaceChildren(documentScope);
        return;
      }
      const clear = button("取消限定", () => {
        this.state.legalQueryFilters.documentId = "";
        this.state.legalQueryFilters.documentTitle = "";
        persistLegalFilters();
        renderDocumentScope();
      }, "button subtle");
      replaceChildren(documentScope, [node("p", { className: "muted small", text: `已限定法律：${title}` }), clear]);
    };
    const syncVersionControls = () => {
      const scope = legalVersionScope(versionScopeFilter.value);
      versionScopeFilter.value = scope;
      versionStatusRow.hidden = scope === "current";
      caseDate.title = scope === "as_of" ? "该日期会作为版本适用日期发送。" : "当前范围不使用日期；填写日期会自动切换到“按日期范围”。";
    };
    for (const control of [matchModeFilter, versionStatusFilter, typeFilter, levelFilter, regionFilter, statusFilter, sortFilter, viewFilter, includeHistory, includeRelations]) {
      control.addEventListener(control === regionFilter ? "input" : "change", persistLegalFilters);
    }
    versionScopeFilter.addEventListener("change", () => { syncVersionControls(); persistLegalFilters(); });
    caseDate.addEventListener("change", () => {
      if (legalDateValue(caseDate.value)) versionScopeFilter.value = "as_of";
      syncVersionControls();
      persistLegalFilters();
    });
    renderDocumentScope();
    syncVersionControls();
    const loadLegalFilters = async () => {
      try {
        const response = await this.api.request("/legal/filters");
        const values = (value) => Array.isArray(value) ? value.map((item) => {
          if (typeof item === "string") return [item, item];
          return [textValue(field(item, ["id", "value", "code", "key"])), textValue(field(item, ["label", "name", "title", "value", "code"]))];
        }).filter(([id]) => id) : [];
        const apply = (select, entries, fallback, kind) => {
          if (!entries.length) return;
          replaceChildren(select);
          appendOption(select, "", fallback);
          for (const [id, label] of entries) appendOption(select, id, /[\u3400-\u9fff]/u.test(String(label || "")) ? label : legalFacetLabel(kind, id));
        };
        apply(typeFilter, values(response?.documentTypes || response?.document_types), "全部类型", "type");
        apply(levelFilter, values(response?.effectivenessLevels || response?.effectiveness_levels), "全部效力层级", "level");
        apply(statusFilter, values(response?.statuses), "全部状态", "status");
        const versionStatuses = response?.versionStatuses || response?.version_statuses || [];
        addVersionStatusOptions(versionStatuses);
        addAiVersionStatusOptions(versionStatuses);
        typeFilter.value = this.state.legalQueryFilters.type;
        levelFilter.value = this.state.legalQueryFilters.level;
        statusFilter.value = this.state.legalQueryFilters.status;
        const jurisdictions = values(response?.jurisdictions || response?.regions);
        replaceChildren(jurisdictionList, jurisdictions.map(([id, label]) => node("option", { value: id, text: label || id })));
      } catch {
        // The built-in options remain usable for older servers.
      }
    };
    const searchButton = formButton("搜索法条", "button primary");
    const searchStatus = statusBox();
    searchForm.append(labelFor("关键词", query), lawOptions, statuteFilters, caseOptions, searchButton, searchStatus);

    const aiPanel = node("div", { className: "case-ai-panel" });
    aiPanel.append(heading(3, "AI 理解案例搜索"));
    aiPanel.append(node("p", { className: "case-ai-notice", role: "note", text: "仅点击“AI理解并搜索”时，当前输入才会发送给所选模型；普通案例检索始终在本机法律库执行。请先使用公开或脱敏案情。" }));
    const aiForm = node("form", { className: "case-ai-form" });
    const providerSelect = node("select", { required: true });
    appendOption(providerSelect, "", "选择已配置的 Provider");
    const modelInput = node("select", { required: true, ariaLabel: "案例 AI 模型" });
    appendOption(modelInput, "", "选择 Provider 后载入模型");
    const aiButton = formButton("AI理解并搜索", "button secondary");
    const aiStatus = statusBox();
    aiForm.append(labelFor("Provider", providerSelect), labelFor("模型（使用当前 Provider 配置）", modelInput), aiButton, aiStatus);
    aiPanel.append(aiForm);

    const aiSearchPanel = panel("AI 法律搜索", [], "panel ai-search-panel");
    aiSearchPanel.append(node("p", { className: "case-ai-notice", role: "note", text: "AI 会先理解案情、检索法条并根据结果调整关键词。仅发送你选择的材料；国内预设默认可发送原文，其他服务默认使用脱敏版。" }));
    const aiSearchForm = node("form", { className: "stack-form" });
    const aiSearchProvider = node("select", { required: true });
    appendOption(aiSearchProvider, "", "选择已配置的模型服务");
    const aiSearchModel = node("select", { required: true, ariaLabel: "AI 法律搜索模型" });
    appendOption(aiSearchModel, "", "选择 Provider 后载入模型");
    const aiSearchPrompt = node("textarea", { rows: 5, placeholder: "描述事件、争议焦点或想确认的法律问题", required: true });
    const aiSearchFilters = this.state.aiSearchFilters;
    const aiSearchMatchMode = node("select", { ariaLabel: "AI 搜索关键词匹配方式", value: legalMatchMode(aiSearchFilters.matchMode) });
    appendOption(aiSearchMatchMode, "all", "全部词均匹配（默认）", legalMatchMode(aiSearchFilters.matchMode) === "all");
    appendOption(aiSearchMatchMode, "any", "任一词匹配", legalMatchMode(aiSearchFilters.matchMode) === "any");
    appendOption(aiSearchMatchMode, "phrase", "按完整短语匹配", legalMatchMode(aiSearchFilters.matchMode) === "phrase");
    const aiSearchVersionScope = node("select", { ariaLabel: "AI 搜索版本范围", value: legalVersionScope(aiSearchFilters.versionScope) });
    appendOption(aiSearchVersionScope, "current", "当前有效版本（默认）", legalVersionScope(aiSearchFilters.versionScope) === "current");
    appendOption(aiSearchVersionScope, "as_of", "按日期范围", legalVersionScope(aiSearchFilters.versionScope) === "as_of");
    appendOption(aiSearchVersionScope, "all", "全部版本", legalVersionScope(aiSearchFilters.versionScope) === "all");
    const aiSearchVersionStatus = node("select", { ariaLabel: "AI 搜索版本状态", value: aiSearchFilters.versionStatus });
    const addAiVersionStatusOptions = (entries = []) => {
      const selected = aiSearchVersionStatus.value || aiSearchFilters.versionStatus;
      replaceChildren(aiSearchVersionStatus);
      appendOption(aiSearchVersionStatus, "", "全部版本状态");
      const values = entries.length ? entries : ["in_force", "amended", "not_yet_effective", "repealed", "unspecified"];
      for (const entry of values) {
        const id = typeof entry === "string" ? entry : textValue(field(entry, ["id", "value", "code", "key"]));
        const label = typeof entry === "string" ? legalStatusLabel(entry) : textValue(field(entry, ["label", "name", "title"]), legalStatusLabel(id));
        if (id) appendOption(aiSearchVersionStatus, id, label, id === selected);
      }
      aiSearchVersionStatus.value = selected;
    };
    addAiVersionStatusOptions();
    const aiSearchVersionStatusRow = labelFor("版本状态", aiSearchVersionStatus);
    const aiSearchCaseDate = node("input", { type: "date", ariaLabel: "AI 搜索案件日期", value: aiSearchFilters.caseDate });
    const syncAiSearchVersionControls = () => {
      const scope = legalVersionScope(aiSearchVersionScope.value);
      aiSearchVersionScope.value = scope;
      aiSearchVersionStatusRow.hidden = scope === "current";
      aiSearchCaseDate.title = scope === "as_of" ? "该日期会作为 AI 法律检索的版本适用日期发送。" : "当前范围不使用日期；填写日期会自动切换到“按日期范围”。";
    };
    const persistAiSearchFilters = () => {
      this.state.aiSearchFilters = {
        caseDate: aiSearchCaseDate.value,
        matchMode: legalMatchMode(aiSearchMatchMode.value),
        versionScope: legalVersionScope(aiSearchVersionScope.value),
        versionStatus: aiSearchVersionStatus.value
      };
    };
    for (const control of [aiSearchMatchMode, aiSearchVersionStatus]) control.addEventListener("change", persistAiSearchFilters);
    aiSearchVersionScope.addEventListener("change", () => { syncAiSearchVersionControls(); persistAiSearchFilters(); });
    aiSearchCaseDate.addEventListener("change", () => {
      if (legalDateValue(aiSearchCaseDate.value)) aiSearchVersionScope.value = "as_of";
      syncAiSearchVersionControls();
      persistAiSearchFilters();
    });
    syncAiSearchVersionControls();
    const aiSearchMaterialHost = node("div", { className: "ai-material-host" }, [emptyState("正在加载可用材料…")]);
    let aiSearchPicker = null;
    let aiSearchRangePicker = null;
    let aiSearchScopeGeneration = 0;
    const aiSearchAttachment = this.renderAiAttachmentPicker({ onChange: () => {
      aiSearchRangePicker?.syncSources();
      aiSearchScopeGeneration += 1;
    } });
    aiSearchRangePicker = this.renderContextRangePicker({
      title: "材料与附件范围",
      getMaterials: () => aiSearchPicker?.values?.() || [],
      getAttachmentIds: () => aiSearchAttachment.attachmentIds?.() || [],
      onChanged: () => {
        aiSearchScopeGeneration += 1;
        setStatus(aiSearchStatus, "范围已修改；此前预检结果已失效，提交前将重新预检。", "warning");
      }
    });
    const aiSearchContextEstimate = node("div", { className: "context-estimate" }, [emptyState("提交前会显示本次采用的材料、页码或段落范围及上下文预算。")]);
    const aiSearchButton = formButton("开始 AI 法律搜索", "button primary");
    const aiSearchStatus = statusBox();
    const aiSearchOutput = node("article", { className: "ai-run-output" }, [emptyState("提交案情后显示检索结果。")]);
    const aiSearchRunScope = node("p", { className: "muted small", text: "" });
    const aiSearchCitations = node("div", { className: "citation-list" });
    const aiSearchVerification = node("div", { className: "citation-verification" });
    const aiSearchHistory = node("div", { className: "ai-history-list" });
    aiSearchForm.append(labelFor("Provider", aiSearchProvider), labelFor("模型", aiSearchModel), labelFor("案情或事件", aiSearchPrompt), labelFor("关键词匹配", aiSearchMatchMode), labelFor("版本范围", aiSearchVersionScope), labelFor("适用日期（选择“按日期范围”后使用）", aiSearchCaseDate), aiSearchVersionStatusRow, aiSearchMaterialHost, aiSearchAttachment, aiSearchRangePicker, aiSearchContextEstimate, aiSearchButton, aiSearchStatus, aiSearchRunScope, aiSearchOutput, aiSearchCitations, aiSearchVerification, heading(3, "AI 搜索历史"), aiSearchHistory);
    aiSearchPanel.append(aiSearchForm);

    const resultsPanel = panel("搜索结果", [], "panel results-panel");
    const responseMeta = node("div", { className: "case-response-meta" });
    const interpretation = node("div", { className: "case-interpretation", hidden: true });
    const results = node("div", { className: "legal-results" }, [emptyState("输入关键词开始搜索。")]);
    // Before the first response there is no real card to measure. This
    // compact-row estimate avoids sizing a request from the placeholder's
    // vertical padding; once cards exist, adaptiveLegalPageSize measures them.
    results.dataset.rowHeight = "120";
    const pagination = node("div", { className: "case-pagination" });
    resultsPanel.append(responseMeta, interpretation, results, pagination);

    const quickPanel = panel("权威案例入口", [], "panel case-quick-links");
    quickPanel.append(node("p", { className: "muted small", text: "本地库用于快速检索；需要查看完整公开库时，可直接打开以下官方入口。" }));
    const quickLinks = node("div", { className: "quick-links" });
    for (const item of OFFICIAL_CASE_LINKS) {
      const url = safeExternalUrl(item.url);
      if (!url) continue;
      const link = node("a", { className: "quick-link", href: url });
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.append(node("strong", { text: item.label }), node("span", { className: "muted small", text: item.description }));
      quickLinks.append(link);
    }
    quickPanel.append(quickLinks);
    const caseStatus = statusBox("正在读取案例库状态…");
    quickPanel.append(node("h3", { text: "本地案例库状态" }), caseStatus);

    const bookmarksPanel = panel("我的收藏", [], "panel bookmarks-panel");
    const bookmarks = node("div", { className: "bookmark-list" }, [emptyState("正在加载收藏…")]);
    bookmarksPanel.append(bookmarks);
    searchPanel.append(modeSwitcher, searchForm);
    searchColumn.append(searchPanel, aiPanel, aiSearchPanel, resultsPanel, quickPanel, bookmarksPanel);
    const detail = node("div", { className: "detail-area" }, [emptyState("选择一条法规查看详情。")]);
    detailColumn.append(detail);

    const setMode = (mode) => {
      const nextMode = [LEGAL_SEARCH_MODES.statute, LEGAL_SEARCH_MODES.ai, LEGAL_SEARCH_MODES.case].includes(mode) ? mode : LEGAL_SEARCH_MODES.statute;
      const previousMode = this.state.legalMode;
      if (previousMode === LEGAL_SEARCH_MODES.case) this.state.legalCaseQuery = query.value.trim();
      else if (previousMode === LEGAL_SEARCH_MODES.statute) this.state.legalArticleQuery = query.value.trim();
      this.cancelLegalRequests();
      this.state.legalMode = nextMode;
      this.state.legalCaseOffset = 0;
      this.state.legalArticleOffset = 0;
      this.state.legalCaseResponse = null;
      this.state.selectedArticle = null;
      this.state.selectedCase = null;
      this.state.legalArticlePage = null;
      if (nextMode === LEGAL_SEARCH_MODES.case) query.value = this.state.legalCaseQuery;
      else if (nextMode === LEGAL_SEARCH_MODES.statute) query.value = this.state.legalArticleQuery;
      aiButton.disabled = false;
      searchButton.disabled = false;
      setModeButton(statuteMode, nextMode === LEGAL_SEARCH_MODES.statute);
      setModeButton(aiMode, nextMode === LEGAL_SEARCH_MODES.ai);
      setModeButton(caseMode, nextMode === LEGAL_SEARCH_MODES.case);
      searchForm.hidden = nextMode === LEGAL_SEARCH_MODES.ai;
      lawOptions.hidden = nextMode !== LEGAL_SEARCH_MODES.statute;
      statuteFilters.hidden = nextMode !== LEGAL_SEARCH_MODES.statute;
      caseOptions.hidden = nextMode !== LEGAL_SEARCH_MODES.case;
      aiPanel.hidden = nextMode !== LEGAL_SEARCH_MODES.case;
      aiSearchPanel.hidden = nextMode !== LEGAL_SEARCH_MODES.ai;
      quickPanel.hidden = nextMode !== LEGAL_SEARCH_MODES.case;
      resultsPanel.hidden = nextMode === LEGAL_SEARCH_MODES.ai;
      bookmarksPanel.hidden = nextMode === LEGAL_SEARCH_MODES.ai;
      detailColumn.hidden = nextMode === LEGAL_SEARCH_MODES.ai;
      layout.classList.toggle("legal-ai-layout", nextMode === LEGAL_SEARCH_MODES.ai);
      query.placeholder = nextMode === LEGAL_SEARCH_MODES.case ? "输入案由、争议焦点、法条或脱敏案情" : "输入法条、关键词或文号";
      searchButton.textContent = nextMode === LEGAL_SEARCH_MODES.case ? "检索案例" : "搜索法条";
      setStatus(searchStatus, nextMode === LEGAL_SEARCH_MODES.case ? "可使用关键词检索本地案例库。" : nextMode === LEGAL_SEARCH_MODES.ai ? "请在 AI 搜索面板中描述案情。" : "可查询本地法律条文。", "");
      replaceChildren(results, [emptyState(nextMode === LEGAL_SEARCH_MODES.case ? "输入关键词开始搜索案例。" : "输入关键词开始搜索。")]);
      replaceChildren(responseMeta);
      replaceChildren(interpretation);
      interpretation.hidden = true;
      replaceChildren(pagination);
      replaceChildren(detail, [emptyState(nextMode === LEGAL_SEARCH_MODES.case ? "选择一条案例查看原文详情。" : nextMode === LEGAL_SEARCH_MODES.ai ? "AI 搜索结果显示在左侧面板。" : "选择一条法规查看详情。")]);
      if (nextMode === LEGAL_SEARCH_MODES.ai || nextMode === LEGAL_SEARCH_MODES.case) void loadAiSurface();
      if (nextMode === LEGAL_SEARCH_MODES.case) void loadCaseSurface();
      if (nextMode !== LEGAL_SEARCH_MODES.ai) void this.loadBookmarks(bookmarks);
    };

    const setModeButton = (control, active) => {
      control.className = `button subtle legal-mode-button${active ? " active" : ""}`;
      control.setAttribute("aria-selected", active ? "true" : "false");
      control.setAttribute("aria-pressed", active ? "true" : "false");
    };

    const currentProvider = () => this.state.providers.find((provider) => textValue(field(provider, ["id"])) === providerSelect.value);
    const syncProviderModel = ({ preserveModel = false } = {}) => {
      const provider = currentProvider();
      const previous = preserveModel ? modelInput.value : "";
      replaceChildren(modelInput);
      const models = providerModelIds(provider);
      const configured = aiDefaultSelection(this.state.aiDefaults, "chat");
      const preferred = preserveModel && models.includes(previous)
        ? previous
        : provider && textValue(field(provider, ["id"])) === configured.providerId && models.includes(configured.model)
          ? configured.model
          : models[0] || "";
      appendOption(modelInput, "", provider ? "选择模型" : "选择 Provider 后载入模型");
      for (const model of models) appendOption(modelInput, model, model, model === preferred);
      modelInput.value = preferred;
      modelInput.disabled = !provider || !models.length;
      modelInput.title = models.length ? "可选择该 Provider 已启用的模型" : "该 Provider 尚未启用模型";
    };
    providerSelect.addEventListener("change", () => syncProviderModel());

    const runCasePage = async (offset = 0, queryOverride = "") => {
      const queryText = String(queryOverride || query.value).trim();
      if (!queryText) {
        setStatus(searchStatus, "请输入案例关键词或案情。", "warning");
        return;
      }
      this.state.legalCaseQuery = queryText;
      this.state.legalCaseType = caseType.value;
      this.state.legalIncludeWithdrawn = includeWithdrawn.checked;
      searchButton.disabled = true;
      setStatus(searchStatus, offset > 0 ? "正在加载下一页案例…" : "正在查询案例…");
      const generation = await this.searchCaseResults({
        queryText,
        caseType: caseType.value,
        includeWithdrawn: includeWithdrawn.checked,
        offset,
        results,
        detail,
        pagination,
        responseMeta,
        interpretation,
        onPage: runCasePage,
        status: searchStatus
      });
      if (generation === this.state.legalSearchGeneration) searchButton.disabled = false;
    };

    const articleSearchParams = ({ queryText, documentId = "", view = viewFilter.value, pageSize, offset }) => legalSearchPageParams({
      query: queryText,
      documentId: documentId || textValue(this.state.legalQueryFilters.documentId),
      caseDate: caseDate.value,
      matchMode: matchModeFilter.value,
      versionScope: versionScopeFilter.value,
      versionStatus: versionStatusFilter.value,
      type: typeFilter.value,
      level: levelFilter.value,
      region: regionFilter.value,
      status: statusFilter.value,
      sort: sortFilter.value,
      view,
      pageSize,
      offset,
      includeHistory: includeHistory.checked,
      includeRelations: includeRelations.checked
    });
    const validateArticleVersionScope = () => {
      if (legalVersionScope(versionScopeFilter.value) !== "as_of") return true;
      if (legalDateValue(caseDate.value)) return true;
      setStatus(searchStatus, "请选择有效的适用日期；“未知”不能作为按日期范围的查询条件。", "warning");
      caseDate.focus();
      return false;
    };
    const appliedQueryText = (appliedQuery) => {
      const matchLabels = {
        all: "全部词均匹配",
        any: "任一词匹配",
        phrase: "完整短语匹配"
      };
      const scopeLabels = {
        current: "当前有效版本",
        as_of: "按日期范围",
        all: "全部版本"
      };
      const match = legalMatchMode(appliedQuery?.matchMode);
      const scope = legalVersionScope(appliedQuery?.versionScope);
      const parts = [`匹配：${matchLabels[match] || match}`, `版本：${scopeLabels[scope] || scope}`];
      const asOf = legalDateValue(appliedQuery?.asOf);
      if (asOf) parts.push(`适用日期：${asOf}`);
      const documentId = textValue(appliedQuery?.resolvedDocumentId);
      if (documentId) parts.push(`限定法律：${documentId}`);
      const articleNumber = textValue(appliedQuery?.exactArticleNumber);
      if (articleNumber) parts.push(`精确条号：${articleNumber}`);
      return parts.join(" · ");
    };
    const renderArticleSearchMeta = (normalized) => {
      const resultCount = normalized.view === "grouped" ? normalized.totalLaws : normalized.totalArticles;
      const children = [node("span", { className: "muted small", text: normalized.view === "grouped" ? `命中 ${resultCount} 部法律 · ${normalized.totalArticles} 条文` : `命中 ${resultCount} 条文` }), node("p", { className: "muted small", text: appliedQueryText(normalized.appliedQuery) })];
      for (const ambiguity of normalized.ambiguities || []) {
        const options = ambiguity.candidates.map((candidate) => button(candidate.title || candidate.documentId, () => {
          this.state.legalQueryFilters.documentId = candidate.documentId;
          this.state.legalQueryFilters.documentTitle = candidate.title || candidate.documentId;
          persistLegalFilters();
          renderDocumentScope();
          void runArticlePage(0);
        }, "button subtle"));
        children.push(node("div", { className: "legal-ambiguity" }, [node("p", { className: "status-message warning", text: `“${ambiguity.query || query.value.trim()}”对应多个法律，请选择后继续检索。` }), node("div", { className: "button-row" }, options)]));
      }
      replaceChildren(responseMeta, children);
    };

    searchForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (this.state.legalMode === LEGAL_SEARCH_MODES.case) {
        await runCasePage(0);
        return;
      }
      await runArticlePage(0);
    });

    const runArticlePage = async (offset = 0, { pageSizeOverride = 0, reason = "" } = {}) => {
      const queryText = query.value.trim();
      if (!queryText) {
        setStatus(searchStatus, "请输入法条关键词。", "warning");
        return;
      }
      if (!validateArticleVersionScope()) return;
      this.state.legalArticleQuery = queryText;
      this.state.legalArticleOffset = Math.max(0, Number(offset) || 0);
      searchButton.disabled = true;
      setStatus(searchStatus, reason === "resize" ? "窗口已调整，正在保持当前位置重新加载…" : this.state.legalArticleOffset ? "正在加载下一页法条…" : "正在查询法条…");
      const pageSize = Number(pageSizeOverride) > 0
        ? Math.max(1, Math.min(100, Math.floor(Number(pageSizeOverride))))
        : adaptiveLegalPageSize(results, 12);
      const generation = this.beginLegalSearch();
      try {
        const params = articleSearchParams({ queryText, pageSize, offset: this.state.legalArticleOffset });
        const response = await this.api.request(`/legal/search/page${queryString(params)}`, { signal: this.state.legalSearchAbort.signal });
        if (generation !== this.state.legalSearchGeneration) return;
        const normalized = normalizeLegalPageResponse(response, { pageSize, offset: params.offset, view: viewFilter.value, matchMode: params.matchMode, versionScope: params.versionScope, caseDate: params.case_date });
        this.state.legalResults = normalized.items;
        this.state.legalArticlePage = normalized;
        this.state.legalArticleOffset = normalized.offset;
        this.renderLegalPage(normalized, results, detail, { includeHistory: includeHistory.checked, includeRelations: includeRelations.checked, queryContext: normalized.appliedQuery, onPage: runArticlePage, onGroupPage: runGroupPage });
        this.renderLegalPagination(normalized, pagination, runArticlePage);
        renderArticleSearchMeta(normalized);
        setStatus(searchStatus, normalized.view === "grouped" ? `找到 ${normalized.totalLaws} 部法律，本页显示 ${normalized.groups.length} 部。` : `找到 ${normalized.totalArticles} 条法条，本页显示 ${normalized.items.length} 条。`, "success");
      } catch (error) {
        if (generation !== this.state.legalSearchGeneration || error?.name === "AbortError") return;
        setStatus(searchStatus, apiErrorMessage(error), "danger");
      } finally {
        if (generation === this.state.legalSearchGeneration) { this.state.legalSearchAbort = null; searchButton.disabled = false; }
      }
    };

    const runGroupPage = async (documentId, offset, groupTarget, groupPagination) => {
      const queryText = query.value.trim();
      if (!queryText || !documentId || !groupTarget) return;
      if (!validateArticleVersionScope()) return;
      const safeOffset = Math.max(0, Number(offset) || 0);
      groupTarget.hidden = false;
      if (groupPagination) groupPagination.hidden = false;
      // The collapsed placeholder has no useful row measurement. Start the
      // first group request with a bounded page, then measure real article
      // cards for subsequent pages after the group has been opened.
      const hasRenderedArticles = Boolean(groupTarget.querySelector?.(".legal-article-card"));
      const pageSize = hasRenderedArticles ? adaptiveLegalPageSize(groupTarget, 8) : 8;
      try {
        replaceChildren(groupTarget, [emptyState("正在加载该法律的命中条文…")]);
        const params = articleSearchParams({ documentId, queryText, view: "flat", pageSize, offset: safeOffset });
        const response = await this.api.request(`/legal/search/page${queryString(params)}`);
        const normalized = normalizeLegalPageResponse(response, { pageSize, offset: safeOffset, view: "flat", matchMode: params.matchMode, versionScope: params.versionScope, caseDate: params.case_date });
        this.renderLegalResults(normalized.items, groupTarget, detail, normalized.appliedQuery);
        this.renderLegalPagination(normalized, groupPagination, (nextOffset) => runGroupPage(documentId, nextOffset, groupTarget, groupPagination));
      } catch (error) {
        replaceChildren(groupTarget, [statusBox(apiErrorMessage(error), "danger")]);
        replaceChildren(groupPagination);
      }
    };

    const installLegalViewportListeners = () => {
      this.teardownLegalViewport();
      const browserWindow = globalThis.window;
      let timer = 0;
      let disposed = false;
      let lastViewportWidth = Number(browserWindow?.innerWidth) || 0;
      let lastViewportHeight = Number(browserWindow?.innerHeight) || 0;
      const reloadForViewport = () => {
        if (disposed || this.state.view !== "legal" || this.state.legalMode !== LEGAL_SEARCH_MODES.statute) return;
        const current = this.state.legalArticlePage;
        const queryText = query.value.trim();
        if (!current || !queryText || queryText !== textValue(this.state.legalArticleQuery) || this.state.legalSearchAbort) return;
        const pageSize = adaptiveLegalPageSize(results, current.limit || 12);
        if (pageSize === current.limit) return;
        // Keep the logical first item offset when the viewport changes.  The
        // server may return a different page size, but it must start at the
        // same offset instead of silently jumping back to the first page.
        void runArticlePage(this.state.legalArticleOffset, { pageSizeOverride: pageSize, reason: "resize" });
      };
      const schedule = (force = false) => {
        if (disposed) return;
        const viewportWidth = Number(browserWindow?.innerWidth) || 0;
        const viewportHeight = Number(browserWindow?.innerHeight) || 0;
        if (!force && viewportWidth === lastViewportWidth && viewportHeight === lastViewportHeight) return;
        lastViewportWidth = viewportWidth;
        lastViewportHeight = viewportHeight;
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          timer = 0;
          reloadForViewport();
        }, 180);
      };
      const onWindowResize = () => schedule(true);
      browserWindow?.addEventListener("resize", onWindowResize, { passive: true });
      const ResizeObserverClass = globalThis.ResizeObserver;
      // Result replacement can add a vertical scrollbar and change the
      // observed width without a viewport change. Only a real viewport change
      // should reload the query; otherwise the observer races with paging.
      const observer = typeof ResizeObserverClass === "function" ? new ResizeObserverClass(() => schedule(false)) : null;
      observer?.observe(results);
      const cleanup = () => {
        disposed = true;
        if (timer) clearTimeout(timer);
        timer = 0;
        browserWindow?.removeEventListener("resize", onWindowResize);
        observer?.disconnect();
      };
      this.state.legalViewportCleanup = cleanup;
    };
    installLegalViewportListeners();

    aiForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const queryText = query.value.trim();
      if (!queryText) {
        setStatus(aiStatus, "请输入公开或脱敏案情。", "warning");
        return;
      }
      const provider = currentProvider();
      if (!providerSelect.value || !provider) {
        setStatus(aiStatus, "尚未配置模型服务，请前往“设置”添加并配置 Provider。", "warning");
        return;
      }
      const selectedModel = modelInput.value.trim();
      if (!providerModelIds(provider).includes(selectedModel)) {
        setStatus(aiStatus, "所选模型未启用，请前往设置勾选后重试。", "warning");
        return;
      }
      this.state.legalCaseQuery = queryText;
      this.state.legalCaseType = caseType.value;
      this.state.legalIncludeWithdrawn = includeWithdrawn.checked;
      aiButton.disabled = true;
      searchButton.disabled = true;
      setStatus(aiStatus, "正在由所选模型理解案情并检索…");
      const generation = await this.understandCase({
        queryText,
        providerId: providerSelect.value,
        model: selectedModel,
        caseType: caseType.value,
        includeWithdrawn: includeWithdrawn.checked,
        results,
        detail,
        pagination,
        responseMeta,
        interpretation,
        onPage: runCasePage,
        status: aiStatus
      });
      if (generation === this.state.legalSearchGeneration) {
        aiButton.disabled = false;
        searchButton.disabled = false;
      }
    });

    const syncAiSearchModel = ({ preserveModel = false } = {}) => {
      const provider = this.state.providers.find((item) => textValue(field(item, ["id"])) === aiSearchProvider.value);
      const previous = preserveModel ? aiSearchModel.value : "";
      const models = providerModelIds(provider);
      const configured = aiDefaultSelection(this.state.aiDefaults, "chat");
      const preferred = preserveModel && models.includes(previous)
        ? previous
        : provider && textValue(field(provider, ["id"])) === configured.providerId && models.includes(configured.model)
          ? configured.model
          : models[0] || "";
      replaceChildren(aiSearchModel);
      appendOption(aiSearchModel, "", provider ? "选择模型" : "选择 Provider 后载入模型");
      for (const model of models) appendOption(aiSearchModel, model, model, model === preferred);
      aiSearchModel.value = preferred;
      aiSearchModel.disabled = !provider || !models.length;
      this.applyMaterialTrust(aiSearchPicker, provider);
    };
    const showAiSearchRun = (run, { resume = true } = {}) => {
      const normalized = this.selectPageRun("search", run);
      aiSearchRunScope.textContent = legalQueryScopeSummary(normalized);
      renderRenderedContent(aiSearchOutput, normalized.html, normalized.content, "该任务尚无正文结果。");
      this.renderRunCitations(aiSearchCitations, normalized.citations);
      this.renderCitationVerification(aiSearchVerification, normalized, { onUpdated: (next) => showAiSearchRun(next, { resume: false }) });
      setStatus(aiSearchStatus, `${aiRunKindLabel(normalized.kind)}：${aiRunStatusLabel(normalized.status)}${normalized.stage ? ` · ${pipelineStageLabel(normalized.stage)}` : ""} · ${aiRunProgressText(normalized)}`, normalized.status === "completed" ? "success" : aiRunIsTerminal(normalized) ? "warning" : "info");
      if (resume && !aiRunIsTerminal(normalized)) this.pollAiRun(normalized.id, {
        status: aiSearchStatus,
        onUpdate: (next) => {
          if (this.state.pageRunIds.search === next.id) showAiSearchRun(next, { resume: false });
        }
      });
      return normalized;
    };
    const continueAiSearchRun = async (run) => {
      try {
        const response = await this.api.continueAiRun(run.id);
        const next = normalizeAiRun(response?.run || response?.new_run || response);
        if (!next.id) throw new ApiError("run_id_missing", false, 200);
        showAiSearchRun(next);
        await refreshAiSearchHistory();
        setStatus(aiSearchStatus, "已继续 AI 法律搜索。", "info");
      } catch (error) {
        setStatus(aiSearchStatus, apiErrorMessage(error), "danger");
      }
    };
    const refreshAiSearchHistory = async ({ append = false } = {}) => {
      try {
        const page = await this.loadAiRunPage("search", { append, limit: 10 });
        const runs = page.items;
        const rows = runs.length ? runs.map((run) => {
          const open = button(`${run.title || "未命名搜索"} · ${aiRunStatusLabel(run.status)}`, async () => {
            const loaded = await this.api.getAiRun(run.id).catch(() => run);
            showAiSearchRun(loaded?.run || loaded);
          }, "conversation-item");
          const row = node("div", { className: "ai-history-row" }, [open]);
          if (["paused", "interrupted", "failed"].includes(String(run.status).toLowerCase())) row.append(button("继续", () => continueAiSearchRun(run), "button subtle"));
          row.append(button("删除", async () => {
            try { await this.api.deleteAiRun(run.id); await refreshAiSearchHistory(); }
            catch (error) { setStatus(aiSearchStatus, apiErrorMessage(error), "danger"); }
          }, "button danger"));
          return row;
        }) : [emptyState("还没有 AI 法律搜索记录。")];
        if (page.corruptCount > 0) rows.unshift(statusBox(`检测到 ${page.corruptCount} 个损坏搜索记录，未显示。`, "warning"));
        if (page.nextCursor) rows.push(button("加载更多搜索历史", () => refreshAiSearchHistory({ append: true }), "button subtle"));
        replaceChildren(aiSearchHistory, rows);
      } catch (error) {
        replaceChildren(aiSearchHistory, [statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    aiSearchProvider.addEventListener("change", () => syncAiSearchModel());
    const aiSearchRetrievalPayload = () => {
      const versionScope = legalVersionScope(aiSearchVersionScope.value);
      const caseDate = versionScope === "as_of" ? legalDateValue(aiSearchCaseDate.value) : "";
      if (versionScope === "as_of" && !caseDate) {
        setStatus(aiSearchStatus, "请选择有效的适用日期；“未知”不能作为按日期范围的查询条件。", "warning");
        aiSearchCaseDate.focus();
        return null;
      }
      return {
        match_mode: legalMatchMode(aiSearchMatchMode.value),
        version_scope: versionScope,
        ...(versionScope !== "current" && aiSearchVersionStatus.value ? { version_status: aiSearchVersionStatus.value } : {}),
        ...(caseDate ? { case_date: caseDate } : {})
      };
    };
    aiSearchForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const provider = this.state.providers.find((item) => textValue(field(item, ["id"])) === aiSearchProvider.value);
      if (!provider || !aiSearchProvider.value) {
        setStatus(aiSearchStatus, "请先在设置中选择已配置的模型服务。", "warning");
        return;
      }
      const prompt = aiSearchPrompt.value.trim();
      if (!prompt) {
        setStatus(aiSearchStatus, "请描述事件或法律问题。", "warning");
        return;
      }
      const model = aiSearchModel.value.trim();
      if (!model || !providerModelIds(provider).includes(model)) {
        setStatus(aiSearchStatus, model ? "所选模型未启用，请前往设置勾选后重试。" : "所选模型服务尚未选择模型。", "warning");
        return;
      }
      const retrievalPayload = aiSearchRetrievalPayload();
      if (!retrievalPayload) return;
      const scope = aiSearchRangePicker.contextRanges();
      if (scope.error) {
        setStatus(aiSearchStatus, scope.error, "warning");
        return;
      }
      aiSearchButton.disabled = true;
      try {
        const scopeGeneration = aiSearchScopeGeneration;
        const payload = { kind: AI_RUN_KINDS.search, prompt, provider_id: aiSearchProvider.value, model, materials: aiSearchPicker?.values?.() || [], attachment_ids: aiSearchAttachment.attachmentIds?.() || [], context_ranges: scope.ranges, ...retrievalPayload };
        const contextEstimate = await this.preflightAiContext(payload, aiSearchContextEstimate, aiSearchStatus);
        if (!contextEstimate) return;
        if (scopeGeneration !== aiSearchScopeGeneration) {
          setStatus(aiSearchStatus, "材料、附件或范围在预检期间已修改；旧预检结果未被提交。", "warning");
          return;
        }
        payload.context_plan_hash = contextEstimate.planHash;
        await this.createAiRun(payload, {
          page: "search",
          status: aiSearchStatus,
          onUpdate: (run) => {
            if (this.state.pageRunIds.search !== run.id) return;
            aiSearchRunScope.textContent = legalQueryScopeSummary(run);
            if (run.content || run.html) renderRenderedContent(aiSearchOutput, run.html, run.content, "该任务尚无正文结果。");
            this.renderRunCitations(aiSearchCitations, run.citations);
            this.renderCitationVerification(aiSearchVerification, run, { onUpdated: (next) => showAiSearchRun(next, { resume: false }) });
          },
          onDone: (run) => {
            if (this.state.pageRunIds.search !== run.id) return;
            aiSearchRunScope.textContent = legalQueryScopeSummary(run);
            if (run.content || run.html) renderRenderedContent(aiSearchOutput, run.html, run.content, "该任务尚无正文结果。");
            this.renderRunCitations(aiSearchCitations, run.citations);
            this.renderCitationVerification(aiSearchVerification, run, { onUpdated: (next) => showAiSearchRun(next, { resume: false }) });
            refreshAiSearchHistory();
          }
        });
      } catch (error) {
        setStatus(aiSearchStatus, apiErrorMessage(error), "danger");
      } finally {
        aiSearchButton.disabled = false;
      }
    });

    const renderAiSearchMaterialPicker = (selectedValues = aiSearchPicker?.values?.() || []) => {
      const page = this.state.aiMaterialsPage;
      aiSearchPicker = this.renderAiMaterialPicker(this.state.aiMaterials, {
        title: "选择材料（默认脱敏版）",
        selectedValues,
        hasMore: Boolean(page.nextCursor),
        total: page.total,
        corruptCount: page.corruptCount,
        errorMessage: page.error,
        onLoadMore: async (preservedValues) => {
          await this.loadAiMaterials({ append: true });
          renderAiSearchMaterialPicker(preservedValues);
          syncAiSearchModel({ preserveModel: true });
        },
        onChange: () => {
          aiSearchRangePicker?.syncSources();
          aiSearchScopeGeneration += 1;
        }
      });
      replaceChildren(aiSearchMaterialHost, [aiSearchPicker]);
      aiSearchRangePicker?.syncSources();
    };

    let aiSurfaceLoad = null;
    const loadAiSurface = async () => {
      if (aiSurfaceLoad) return aiSurfaceLoad;
      aiSurfaceLoad = (async () => {
        await Promise.all([
          this.loadProvidersInto(providerSelect, "chat"),
          this.loadProvidersInto(aiSearchProvider, "chat")
        ]);
        syncProviderModel({ preserveModel: true });
        syncAiSearchModel({ preserveModel: true });
        await this.loadAiMaterials();
        renderAiSearchMaterialPicker();
        syncAiSearchModel({ preserveModel: true });
        await refreshAiSearchHistory();
      })().catch((error) => {
        setStatus(aiSearchStatus, apiErrorMessage(error), "danger");
      }).finally(() => {
        aiSurfaceLoad = null;
      });
      return aiSurfaceLoad;
    };
    const loadCaseSurface = async () => {
      await this.loadCaseStatus(caseStatus);
    };

    setMode(this.state.legalMode);
    void loadLegalFilters();
    const pendingCitation = this.state.pendingCitation;
    this.state.pendingCitation = null;
    if (pendingCitation?.article) this.loadArticle(pendingCitation.article, detail);
    else if (pendingCitation?.legalCase) this.loadCase(pendingCitation.legalCase, detail);
  }

  cancelLegalRequests() {
    this.state.legalSearchAbort?.abort();
    this.state.legalDetailAbort?.abort();
    this.state.legalSearchAbort = null;
    this.state.legalDetailAbort = null;
    this.state.legalSearchGeneration += 1;
    this.state.legalDetailGeneration += 1;
  }

  teardownLegalViewport() {
    const cleanup = this.state.legalViewportCleanup;
    this.state.legalViewportCleanup = null;
    cleanup?.();
  }

  beginLegalSearch() {
    this.state.legalSearchAbort?.abort();
    const controller = new AbortController();
    this.state.legalSearchAbort = controller;
    this.state.legalSearchGeneration += 1;
    this.state.legalDetailAbort?.abort();
    this.state.legalDetailAbort = null;
    this.state.legalDetailGeneration += 1;
    return this.state.legalSearchGeneration;
  }

  async searchCaseResults({ queryText, caseType = CASE_TYPES.all, includeWithdrawn = false, offset = 0, results, detail, pagination, responseMeta, interpretation, onPage, status }) {
    const generation = this.beginLegalSearch();
    const normalizedType = [CASE_TYPES.guiding, CASE_TYPES.reference, CASE_TYPES.typical].includes(caseType) ? caseType : CASE_TYPES.all;
    const parsedOffset = Number.isFinite(Number(offset)) && Number(offset) >= 0 ? Math.floor(Number(offset)) : 0;
    this.state.legalCaseQuery = String(queryText || "").trim();
    this.state.legalCaseType = normalizedType;
    this.state.legalIncludeWithdrawn = includeWithdrawn === true;
    this.state.legalCaseOffset = parsedOffset;
    try {
      const params = legalCaseSearchParams(this.state.legalCaseQuery, normalizedType, parsedOffset, this.state.legalIncludeWithdrawn);
      const response = await this.api.request(`/legal/cases${queryString(params)}`, { signal: this.state.legalSearchAbort.signal });
      if (generation !== this.state.legalSearchGeneration) return generation;
      this.renderCaseResponse(response, { results, detail, pagination, responseMeta, interpretation, onPage, offset: parsedOffset });
      const normalized = normalizeCaseSearchResponse(response, { offset: parsedOffset, limit: 20 });
      setStatus(status, `找到 ${normalized.total} 条案例，本页显示 ${normalized.cases.length} 条。`, "success");
    } catch (error) {
      if (generation !== this.state.legalSearchGeneration || error?.name === "AbortError") return generation;
      setStatus(status, apiErrorMessage(error), "danger");
    } finally {
      if (generation === this.state.legalSearchGeneration) this.state.legalSearchAbort = null;
    }
    return generation;
  }

  async understandCase({ queryText, providerId, model, caseType = CASE_TYPES.all, includeWithdrawn = false, results, detail, pagination, responseMeta, interpretation, onPage, status }) {
    const generation = this.beginLegalSearch();
    const normalizedType = [CASE_TYPES.guiding, CASE_TYPES.reference, CASE_TYPES.typical].includes(caseType) ? caseType : CASE_TYPES.all;
    this.state.legalCaseQuery = String(queryText || "").trim();
    this.state.legalCaseType = normalizedType;
    this.state.legalIncludeWithdrawn = includeWithdrawn === true;
    try {
      const body = caseUnderstandPayload(this.state.legalCaseQuery, providerId, model, normalizedType, this.state.legalIncludeWithdrawn);
      const response = await this.api.request("/legal/cases/understand", { method: "POST", body, signal: this.state.legalSearchAbort.signal });
      if (generation !== this.state.legalSearchGeneration) return generation;
      this.renderCaseInterpretation(response, interpretation);
      const interpretedQuery = structuredText(response?.interpreted_query) || this.state.legalCaseQuery;
      const aiPage = (offset) => onPage(offset, interpretedQuery);
      this.renderCaseResponse(response?.results, { results, detail, pagination, responseMeta, interpretation, onPage: aiPage, offset: 0 });
      const normalized = normalizeCaseSearchResponse(response?.results, { offset: 0, limit: 20 });
      setStatus(status, `已理解案情并找到 ${normalized.total} 条案例。`, "success");
    } catch (error) {
      if (generation !== this.state.legalSearchGeneration || error?.name === "AbortError") return generation;
      setStatus(status, apiErrorMessage(error), "danger");
    } finally {
      if (generation === this.state.legalSearchGeneration) this.state.legalSearchAbort = null;
    }
    return generation;
  }

  renderCaseResponse(response, { results, detail, pagination, responseMeta, interpretation, onPage, offset = 0, limit = 20 }) {
    const normalized = normalizeCaseSearchResponse(response, { offset, limit });
    this.state.legalCaseResponse = normalized;
    this.state.legalCases = normalized.cases;
    this.state.legalResults = normalized.cases;
    this.state.legalCaseOffset = normalized.offset;
    this.renderCaseResults(normalized.cases, results, detail);
    const meta = [`匹配案例：${normalized.total} 条`, `本页 ${normalized.cases.length} 条`];
    if (normalized.databaseVersion) meta.push(`数据库版本：${normalized.databaseVersion}`);
    replaceChildren(responseMeta, [node("p", { className: "muted small", text: meta.join(" · ") }), ...caseWarningList(normalized.warnings).map((warning) => node("p", { className: "status-message warning", text: `提示：${warning}` }))]);
    this.renderCasePagination(normalized, pagination, onPage);
    replaceChildren(detail, [emptyState("选择一条案例查看原文详情。")]);
  }

  renderCaseInterpretation(response, target) {
    const interpreted = structuredText(response?.interpreted_query);
    const issues = caseTextList(response?.issues);
    const warnings = caseWarningList(response?.warnings);
    const children = [heading(3, "本次 AI 理解")];
    if (interpreted) children.push(node("p", { className: "case-interpreted-query", text: `检索表达：${interpreted}` }));
    if (issues.length) {
      children.push(node("p", { className: "muted small", text: "识别的争议问题" }));
      children.push(node("ul", { className: "case-bullet-list" }, issues.map((issue) => node("li", { text: issue }))));
    }
    if (warnings.length) {
      children.push(node("p", { className: "muted small", text: "提示" }));
      children.push(node("ul", { className: "case-bullet-list warning-list" }, warnings.map((warning) => node("li", { text: warning }))));
    }
    if (!interpreted && !issues.length && !warnings.length) {
      replaceChildren(target);
      target.hidden = true;
      return;
    }
    replaceChildren(target, children);
    target.hidden = false;
  }

  renderCasePagination(response, target, onPage) {
    const totalPages = response.total > 0 ? Math.ceil(response.total / response.limit) : 0;
    const currentPage = totalPages ? Math.floor(response.offset / response.limit) + 1 : 0;
    const previous = button("上一页", () => onPage?.(Math.max(0, response.offset - response.limit)), "button subtle");
    const next = button("下一页", () => onPage?.(response.offset + response.limit), "button subtle");
    previous.disabled = response.offset <= 0;
    next.disabled = response.offset + response.limit >= response.total || !response.total;
    const label = totalPages ? `第 ${currentPage} / ${totalPages} 页` : "暂无分页结果";
    replaceChildren(target, [previous, node("span", { className: "muted small", text: label }), next]);
  }

  renderCaseResults(items, target, detail) {
    if (!items.length) {
      replaceChildren(target, [emptyState("没有找到匹配案例，可尝试更宽泛的案由或争议焦点。")]);
      return;
    }
    const rows = items.map((item) => {
      const id = caseId(item);
      const title = caseTitle(item);
      const type = caseTypeLabel(field(item, ["caseType", "case_type"]));
      const guidingNumber = textValue(field(item, ["guidingNumber", "guiding_number"]));
      const referenceNumber = textValue(field(item, ["referenceNumber", "reference_number"]));
      const caseNumber = textValue(field(item, ["caseNumber", "case_number"]));
      const court = textValue(field(item, ["court", "courtName", "court_name"]));
      const publicationDate = textValue(field(item, ["publicationDate", "publication_date"]));
      const status = caseStatusLabel(field(item, ["status"]));
      const source = caseSourceLabel(item);
      const number = guidingNumber || referenceNumber;
      const titleNode = id ? button(title, () => this.loadCase(id, detail), "result-button") : node("strong", { text: title });
      const metadata = [
        `来源：${source}`,
        type,
        number ? `编号：${number}` : "",
        court ? `法院：${court}` : "",
        caseNumber ? `案号：${caseNumber}` : "",
        publicationDate ? `发布日期：${publicationDate}` : "",
        status ? `状态：${status}` : ""
      ].filter(Boolean);
      const historical = ["withdrawn", "deprecated"].includes(String(field(item, ["status"])).toLowerCase());
      const children = [titleNode, historical ? node("span", { className: "status-pill danger", text: "不再参照" }) : null, node("p", { className: "result-meta", text: metadata.join(" · ") })].filter(Boolean);
      const keywords = caseTextList(field(item, ["keywords"]));
      const keyPoints = caseTextList(field(item, ["keyPoints", "key_points"])).join("；");
      const matchedText = textValue(field(item, ["matchedText", "matched_text"]));
      if (keywords.length) children.push(node("p", { className: "case-keywords", text: `关键词：${keywords.join("、")}` }));
      if (keyPoints) children.push(node("p", { className: "case-key-points", text: `裁判要点：${keyPoints}` }));
      if (matchedText) children.push(node("p", { className: "case-match", text: `匹配内容：${matchedText}` }));
      const sourceUrl = safeExternalUrl(field(item, ["sourceUrl", "source_url"]));
      if (sourceUrl) {
        const link = node("a", { className: "external-link", href: sourceUrl, text: "打开官方页面" });
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        children.push(link);
      }
      return node("article", { className: "result-card case-result-card" }, children);
    });
    replaceChildren(target, rows);
  }

  async loadCase(id, detail) {
    if (!id) return;
    this.state.legalDetailAbort?.abort();
    const controller = new AbortController();
    this.state.legalDetailAbort = controller;
    this.state.legalDetailGeneration += 1;
    const generation = this.state.legalDetailGeneration;
    replaceChildren(detail, [emptyState("正在加载案例原文详情…")]);
    try {
      const response = await this.api.request(`/legal/cases/${pathId(id)}`, { signal: controller.signal });
      if (generation !== this.state.legalDetailGeneration) return;
      const item = response?.case && typeof response.case === "object" ? response.case : response;
      this.state.selectedCase = item;
      this.renderCaseDetail(item, detail);
    } catch (error) {
      if (generation !== this.state.legalDetailGeneration || error?.name === "AbortError") return;
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    } finally {
      if (generation === this.state.legalDetailGeneration) this.state.legalDetailAbort = null;
    }
  }

  renderCaseDetail(item, detail) {
    const title = caseTitle(item);
    const type = caseTypeLabel(field(item, ["caseType", "case_type"]));
    const guidingNumber = textValue(field(item, ["guidingNumber", "guiding_number"]));
    const referenceNumber = textValue(field(item, ["referenceNumber", "reference_number"]));
    const number = guidingNumber || referenceNumber;
    const court = textValue(field(item, ["court", "courtName", "court_name"]));
    const caseNumber = textValue(field(item, ["caseNumber", "case_number"]));
    const publicationDate = textValue(field(item, ["publicationDate", "publication_date"]));
    const status = caseStatusLabel(field(item, ["status"]));
    const source = caseSourceLabel(item);
    const fetchedAt = textValue(field(item, ["fetchedAt", "fetched_at"]));
    const headingBlock = node("div", { className: "detail-heading" }, [heading(2, title), node("p", { className: "muted", text: [source, type, number ? `编号：${number}` : ""].filter(Boolean).join(" · ") })]);
    const metadata = node("dl", { className: "case-detail-meta" });
    const metadataRows = [
      ["来源", source],
      ["案例类型", type],
      ["编号", number],
      ["法院", court],
      ["案号", caseNumber],
      ["发布日期", publicationDate],
      ["状态", status],
      ["抓取时间", fetchedAt ? formatDate(fetchedAt) : "暂无"]
    ].filter(([, value]) => value);
    metadata.append(...metadataRows.flatMap(([label, value]) => [node("dt", { text: label }), node("dd", { text: value })]));
    const actions = node("div", { className: "button-row" });
    const copy = button("复制案例引用", async () => {
      try {
        await copyText(`${title}${number ? `（${number}）` : ""}${caseNumber ? `，案号：${caseNumber}` : ""}`);
        copy.textContent = "已复制";
        setTimeout(() => { copy.textContent = "复制案例引用"; }, 1500);
      } catch {
        copy.textContent = "浏览器不支持复制";
      }
    }, "button secondary");
    actions.append(copy);
    const sourceUrl = safeExternalUrl(field(item, ["sourceUrl", "source_url"]));
    if (sourceUrl) {
      const sourceLink = node("a", { className: "button subtle", href: sourceUrl, text: "打开官方原文" });
      sourceLink.target = "_blank";
      sourceLink.rel = "noopener noreferrer";
      actions.append(sourceLink);
    }

    const section = (titleText, value, className = "case-detail-section") => {
      const text = Array.isArray(value) ? caseTextList(value).join("\n") : structuredText(value);
      if (!text) return null;
      return node("section", { className }, [heading(3, titleText), node("pre", { className: "legal-text", text })]);
    };
    const relatedLaws = caseTextList(field(item, ["relatedLaws", "related_laws"])).join("；");
    const content = [
      section("裁判要点", field(item, ["keyPoints", "key_points"])),
      section("基本事实", field(item, ["basicFacts", "basic_facts"])),
      section("裁判结果", field(item, ["judgmentResult", "judgment_result"])),
      section("裁判理由", field(item, ["reasoning"])),
      section("关联法律", relatedLaws),
      section("原文详情", field(item, ["fullText", "full_text", "content", "text"]), "case-detail-section case-full-text")
    ].filter(Boolean);
    replaceChildren(detail, [headingBlock, actions, metadata, ...(content.length ? content : [emptyState("该案例暂未提供可展示的详情文本。")])]);
  }

  async loadCaseStatus(target) {
    try {
      const response = await this.api.request("/legal/cases/status");
      this.state.legalCaseStatus = response;
      const available = response?.available === true;
      const databaseVersion = textValue(response?.databaseVersion);
      const fetchedAt = textValue(response?.lastFetchedAt);
      if (!available) {
        setStatus(target, "本地案例库暂不可用；可使用上方官方入口检索。", "warning");
        return;
      }
      const number = (value) => {
        const parsed = Number(value);
        return Number.isFinite(parsed) && parsed >= 0 ? String(Math.floor(parsed)) : "未知";
      };
      const typicalCount = field(response, ["typicalCount", "typical_count"]);
      const parts = [`已收录 ${number(response?.total)} 个案例记录`, `指导案例 ${number(response?.guidingCount)}`, `参考案例 ${number(response?.referenceCount)}`, `典型案例合集 ${number(typicalCount)}`];
      if (databaseVersion) parts.push(`数据库版本：${databaseVersion}`);
      parts.push(`最近抓取：${fetchedAt ? formatDate(fetchedAt) : "暂无"}`);
      if (Number(response?.referenceCount) === 0) parts.push("本地暂未收录参考案例，可去人民法院案例库查看");
      const warnings = caseWarningList(response?.warnings);
      if (warnings.length) parts.push(`提示：${warnings.join("；")}`);
      setStatus(target, parts.join(" · "), warnings.length ? "warning" : "success");
    } catch (error) {
      setStatus(target, apiErrorMessage(error), "danger");
    }
  }

  renderLegalPage(page, target, detail, { includeHistory = true, includeRelations = true, queryContext = null, onPage, onGroupPage } = {}) {
    const normalized = page && page.items ? page : normalizeLegalPageResponse(page);
    if (normalized.groups.length && normalized.view === "grouped") {
      const groups = normalized.groups.map((group) => {
        const law = group?.law && typeof group.law === "object" ? group.law : group;
        const groupItems = responseList(group, ["articles", "topArticles", "top_articles", "items", "results"]);
        const groupTitle = textValue(field(law, ["documentTitle", "document_title", "title", "name"]), "未命名法律");
        const documentId = textValue(field(law, ["documentId", "document_id", "id"]));
        const count = Number(field(group, ["matchedArticleCount", "matched_article_count", "articleCount", "article_count"], groupItems.length));
        const summarySource = textValue(field(law, ["summary", "description", "snippet", "contentPreview", "content_preview"]))
          || textValue(field(group, ["summary", "description", "snippet", "contentPreview", "content_preview"]))
          || textValue(field(groupItems[0], ["snippet", "summary", "contentPreview", "content_preview"]));
        const summary = summarySource.replace(/\s+/gu, " ").trim().slice(0, 180);
        const authority = textValue(field(law, ["authorityName", "authority_name"]));
        const levelKey = textValue(field(law, ["effectivenessLevel", "effectiveness_level"]));
        const level = levelKey ? legalFacetLabel("level", levelKey) : "";
        const statusKey = textValue(field(law, ["status"]));
        const status = statusKey ? legalStatusLabel(statusKey) : "";
        const metadata = [authority, level, status, count > 0 ? `${count} 条命中条文` : "暂无命中条文"].filter(Boolean).join(" · ");
        const groupBody = node("div", { className: "legal-group-articles", hidden: true }, [emptyState("点击上方按钮读取命中条文。")]);
        const groupPagination = node("div", { className: "case-pagination", hidden: true });
        const groupActions = node("div", { className: "button-row legal-group-actions" });
        const openGroup = () => {
          if (!documentId || !onGroupPage) return;
          groupBody.hidden = false;
          groupPagination.hidden = false;
          void onGroupPage(documentId, 0, groupBody, groupPagination);
        };
        const title = documentId && onGroupPage
          ? node("h3", {}, [button(groupTitle, openGroup, "result-button legal-group-title")])
          : heading(3, groupTitle);
        if (documentId && onGroupPage) groupActions.append(button("查看命中条文", openGroup, "button subtle"));
        return node("section", { className: "result-card legal-result-group" }, [
          node("div", { className: "legal-group-heading" }, [title, node("span", { className: "muted small", text: metadata })]),
          summary ? node("p", { className: "legal-group-summary", text: summary }) : null,
          groupActions,
          groupBody,
          groupPagination
        ]);
      });
      replaceChildren(target, groups);
    } else {
      this.renderLegalResults(normalized.items, target, detail, queryContext);
    }
    if (!normalized.items.length && !normalized.groups.length) replaceChildren(target, [emptyState("没有找到匹配条文，可调整筛选条件或搜索词。")]);
    // These flags are retained on the page for the next selected article;
    // the detail loader reads them when opened.
    this.state.legalDetailOptions = { includeHistory, includeRelations };
    if (onPage) this.state.legalArticlePageHandler = onPage;
  }

  renderLegalPagination(response, target, onPage) {
    const totalPages = response.total > 0 ? Math.ceil(response.total / response.limit) : 0;
    const currentPage = totalPages ? Math.floor(response.offset / response.limit) + 1 : 0;
    const previous = button("上一页", () => onPage?.(Math.max(0, response.offset - response.limit)), "button subtle");
    const next = button("下一页", () => onPage?.(response.offset + response.limit), "button subtle");
    previous.disabled = response.offset <= 0;
    next.disabled = response.offset + response.limit >= response.total || !response.total;
    const label = totalPages ? `第 ${currentPage} / ${totalPages} 页` : "暂无分页结果";
    replaceChildren(target, [previous, node("span", { className: "muted small", text: `${label} · 每页 ${response.limit} 条` }), next]);
  }

  renderLegalArticleCard(article, detail, queryContext = null) {
    const id = articleId(article);
    const title = legalArticleDisplayTitle(article);
    const source = textValue(field(article, ["documentTitle", "document_title", "lawName", "law_name"]));
    const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
    const statusKey = textValue(field(article, ["versionStatus", "version_status", "status"]));
    const status = statusKey ? legalStatusLabel(statusKey) : "";
    const relevance = field(article, ["relevance", "score", "rank"], "");
    const titleNode = id ? button(title, () => this.loadArticle(id, detail, queryContext), "result-button") : node("strong", { text: title });
    const effectiveLabel = legalDateValue(effective) ? `生效：${effective}` : "生效日期：未知";
    const metadata = [source, effectiveLabel, status ? `状态：${status}` : "", relevance !== "" ? `相关性：${textValue(relevance)}` : ""].filter(Boolean).join(" · ");
    const snippet = textValue(field(article, ["snippet", "summary", "content_preview"]));
    return node("article", { className: "result-card legal-article-card" }, [titleNode, metadata ? node("p", { className: "result-meta", text: metadata }) : null, snippet ? node("p", { className: "legal-snippet", text: snippet }) : null]);
  }

  renderLegalResults(items, target, detail, queryContext = null) {
    if (!items.length) {
      replaceChildren(target, [emptyState("没有找到匹配条文。")]);
      return;
    }
    const rows = items.map((article) => this.renderLegalArticleCard(article, detail, queryContext));
    replaceChildren(target, rows);
  }

  async loadArticle(id, detail, queryContext = null) {
    if (!id) return;
    replaceChildren(detail, [emptyState("正在加载条文…")]);
    try {
      const scoped = legalScopedReadParams(queryContext || {});
      if (scoped.versionScope === "as_of" && !scoped.caseDate) {
        replaceChildren(detail, [statusBox("检索结果未返回有效适用日期，不能在未确定日期下读取历史条文。", "warning")]);
        return;
      }
      const response = await this.api.request(`/legal/articles/${pathId(id)}${queryString(scoped)}`);
      const article = response?.article && typeof response.article === "object" ? response.article : response;
      this.state.selectedArticle = article;
      this.renderArticleDetail(article, detail, queryContext);
    } catch (error) {
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderArticleDetail(article, detail, queryContext = null) {
    const id = articleId(article);
    const documentId = legalArticleDocumentId(article);
    const title = legalArticleDisplayTitle(article);
    const content = textValue(field(article, ["content", "text", "body", "articleText"]), "暂无正文。");
    const source = textValue(field(article, ["documentTitle", "document_title"]));
    const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
    const statusKey = textValue(field(article, ["versionStatus", "version_status", "status"]));
    const status = legalStatusLabel(statusKey);
    const effectiveLabel = legalDateValue(effective) ? `生效：${effective}` : "生效日期：未知";
    const headingBlock = node("div", { className: "detail-heading" }, [heading(2, title), node("p", { className: "muted", text: [source, effectiveLabel, status ? `状态：${status}` : ""].filter(Boolean).join(" · ") })]);
    const queryScope = queryContext && typeof queryContext === "object"
      ? node("p", { className: "muted small", text: `本条文来自检索范围：${legalMatchMode(queryContext.matchMode) === "all" ? "全部词均匹配" : legalMatchMode(queryContext.matchMode) === "any" ? "任一词匹配" : "完整短语匹配"} · ${legalVersionScope(queryContext.versionScope) === "as_of" ? `适用日期 ${legalDateValue(queryContext.asOf) || "未知"}` : legalVersionScope(queryContext.versionScope) === "all" ? "全部版本" : "当前有效版本"}` })
      : null;
    const actions = node("div", { className: "button-row" });
    const bookmark = button("收藏条文", async () => {
      bookmark.disabled = true;
      try {
        await this.api.request("/bookmarks", { method: "POST", body: { article_id: id, title } });
        bookmark.textContent = "已收藏";
      } catch (error) {
        bookmark.textContent = apiErrorMessage(error);
        bookmark.disabled = false;
      }
    }, "button secondary");
    const copy = button("复制引用", async () => {
      try {
        await copyText(textValue(field(article, ["canonicalLabel", "canonical_label"]), `${title}${source ? `（${source}）` : ""}`));
        copy.textContent = "已复制";
        setTimeout(() => { copy.textContent = "复制引用"; }, 1500);
      } catch {
        copy.textContent = "浏览器不支持复制";
      }
    }, "button secondary");
    const historyToggle = node("input", { type: "checkbox", checked: this.state.legalDetailOptions?.includeHistory !== false, ariaLabel: "显示历史版本" });
    const relationToggle = node("input", { type: "checkbox", checked: this.state.legalDetailOptions?.includeRelations !== false, ariaLabel: "显示关联法规" });
    const historyLabel = node("label", { className: "checkbox-label detail-toggle" }, [historyToggle, node("span", { text: "查看历史版本" })]);
    const relationLabel = node("label", { className: "checkbox-label detail-toggle" }, [relationToggle, node("span", { text: "查看关联法规" })]);
    actions.append(bookmark, copy, historyLabel, relationLabel);
    const text = node("pre", { className: "legal-text", text: content });
    const versionBox = node("div", { className: "related-box" });
    const relationBox = node("div", { className: "related-box" });
    replaceChildren(detail, [headingBlock, queryScope, actions, text, versionBox, relationBox]);
    let versionRequestGeneration = 0;
    const scopedRead = legalScopedReadParams(queryContext || {});
    const missingAsOfDate = scopedRead.versionScope === "as_of" && !scopedRead.caseDate;
    const historyReadable = scopedRead.versionScope !== "current" && !missingAsOfDate;
    const historyHeading = historyReadable ? "历史版本" : "历史版本（元数据）";

    const loadHistory = async () => {
      const generation = ++versionRequestGeneration;
      if (!historyToggle.checked) {
        replaceChildren(versionBox);
        return;
      }
      if (!documentId) {
        replaceChildren(versionBox, [heading(3, historyHeading), emptyState("该条文没有可用的法律文书 ID。")]);
        return;
      }
      replaceChildren(versionBox, [heading(3, historyHeading), statusBox("正在读取历史版本…")]);
      try {
        const response = await this.api.request(`/legal/versions/${pathId(documentId)}`);
        if (generation !== versionRequestGeneration || !historyToggle.checked) return;
        const items = responseList(response, ["versions", "items"]);
        if (!items.length) {
          replaceChildren(versionBox, [heading(3, historyHeading), emptyState("没有历史版本记录。")]);
          return;
        }
        const versionContent = node("pre", { className: "legal-text version-content", text: "点击版本查看该版本的具体条文内容。" });
        const versionPagination = node("div", { className: "case-pagination version-pagination" });
        const selectedNumber = textValue(field(article, ["articleNumber", "article_number"]));
        const selectedTitle = textValue(field(article, ["articleTitle", "article_title", "title", "name"]));
        const renderVersionBody = (articles, fallback = "暂无该版本正文。") => {
          const rows = Array.isArray(articles) ? articles.filter((item) => item && typeof item === "object") : [];
          const matchesSelected = (candidate) => {
            const candidateId = articleId(candidate);
            const candidateNumber = textValue(field(candidate, ["articleNumber", "article_number"]));
            const candidateTitle = textValue(field(candidate, ["articleTitle", "article_title", "title", "name"]));
            return (id && candidateId === id)
              || (selectedNumber && candidateNumber === selectedNumber && (!selectedTitle || !candidateTitle || candidateTitle === selectedTitle));
          };
          rows.sort((left, right) => Number(matchesSelected(right)) - Number(matchesSelected(left)));
          const body = rows.map((candidate) => {
            const number = textValue(field(candidate, ["articleNumber", "article_number"]));
            const headingText = textValue(field(candidate, ["articleTitle", "article_title", "title", "name"]));
            const value = textValue(field(candidate, ["content", "text", "body", "articleText"]));
            const marker = matchesSelected(candidate) ? "【当前条文】" : "";
            return [marker, number, headingText, value].filter(Boolean).join(" ");
          }).filter(Boolean).join("\n\n");
          versionContent.textContent = body || fallback;
        };
        const loadVersionPage = async (versionId, offset = 0, fallback = "暂无该版本正文。", trigger = null) => {
          const generation = ++versionRequestGeneration;
          const safeOffset = Math.max(0, Number(offset) || 0);
          if (trigger) trigger.disabled = true;
          versionContent.textContent = "正在读取该版本正文…";
          replaceChildren(versionPagination);
          try {
            const pageSize = adaptiveLegalPageSize(versionContent, 12);
            const loaded = await this.api.request(`/legal/version-articles/${pathId(versionId)}${queryString({ ...scopedRead, limit: pageSize, offset: safeOffset })}`);
            if (generation !== versionRequestGeneration) return;
            const loadedArticles = Array.isArray(loaded?.articles)
              ? loaded.articles
              : Array.isArray(loaded?.items)
                ? loaded.items
                : loaded?.article && typeof loaded.article === "object"
                  ? [loaded.article]
                  : loaded && typeof loaded === "object" && field(loaded, ["content", "text", "body", "articleText"])
                    ? [loaded]
                    : [];
            renderVersionBody(loadedArticles, fallback);
            const totalValue = Number(loaded?.total ?? loaded?.totalArticles ?? loadedArticles.length);
            const total = Number.isFinite(totalValue) && totalValue >= 0 ? Math.floor(totalValue) : loadedArticles.length;
            this.renderLegalPagination({ total, limit: pageSize, offset: safeOffset }, versionPagination, (nextOffset) => loadVersionPage(versionId, nextOffset, fallback));
          } catch (error) {
            if (generation === versionRequestGeneration) versionContent.textContent = apiErrorMessage(error);
          } finally {
            if (trigger) trigger.disabled = false;
          }
        };
        const rows = items.map((version) => {
          const versionId = textValue(field(version, ["versionId", "version_id", "id"]));
          const versionTitle = textValue(field(version, ["versionLabel", "version_label", "title", "name"]), "历史版本");
          const versionStatus = textValue(field(version, ["status", "versionStatus", "version_status"]));
          const from = textValue(field(version, ["effectiveFrom", "effective_from", "date", "publishedAt", "published_at"]), "日期未知");
          const to = textValue(field(version, ["effectiveTo", "effective_to"]));
          const metadata = [versionTitle, versionStatus ? legalStatusLabel(versionStatus) : "", from, to ? `至 ${to}` : ""].filter(Boolean).join(" · ");
          const show = button(metadata, async () => {
            if (!historyReadable) {
              versionContent.textContent = missingAsOfDate
                ? "检索结果未返回有效适用日期，不能读取历史正文。"
                : "当前有效版本范围只显示历史版本元数据。请在法律检索中选择“按日期范围”或“全部版本”后，再读取历史正文。";
              replaceChildren(versionPagination);
              return;
            }
            const fallback = textValue(field(version, ["content", "text", "body"]), "暂无该版本正文。");
            if (versionId) await loadVersionPage(versionId, 0, fallback, show);
            else renderVersionBody([version], fallback);
          }, "version-button");
          return node("div", { className: "version-item" }, [show]);
        });
        replaceChildren(versionBox, [heading(3, historyHeading), node("div", { className: "version-list" }, rows), versionContent, versionPagination]);
        // Loading the first entry makes the default-open switch useful without
        // requiring a second click merely to see whether content is available.
        versionBox.querySelector(".version-button")?.click();
      } catch (error) {
        if (generation === versionRequestGeneration && historyToggle.checked) replaceChildren(versionBox, [heading(3, historyHeading), statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    const loadRelations = async () => {
      if (!relationToggle.checked) {
        replaceChildren(relationBox);
        return;
      }
      if (!documentId) {
        replaceChildren(relationBox, [heading(3, "关联法规"), emptyState("该条文没有可用的法律文书 ID。")]);
        return;
      }
      replaceChildren(relationBox, [heading(3, "关联法规"), statusBox("正在读取关联法规…")]);
      try {
        const response = await this.api.request(`/legal/relations/${pathId(documentId)}`);
        const items = responseList(response, ["relations", "items"]);
        replaceChildren(relationBox, [heading(3, "关联法规"), ...(items.length ? items.map((related) => {
          const target = legalRelationTarget(related, documentId);
          const relationText = [textValue(field(related, ["relationType", "relation_type"])), textValue(field(related, ["description"])), textValue(field(related, ["sourceReference", "source_reference"]))].filter(Boolean).join(" · ");
          const targetButton = button(target.title, () => this.loadArticle(target.documentId, detail, queryContext), "link-button");
          return node("div", { className: "version-item" }, [targetButton, relationText ? node("p", { className: "result-meta", text: relationText }) : null]);
        }) : [emptyState("没有关联法规记录。")])]);
      } catch (error) {
        replaceChildren(relationBox, [heading(3, "关联法规"), statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    historyToggle.addEventListener("change", loadHistory);
    relationToggle.addEventListener("change", loadRelations);
    if (historyToggle.checked) loadHistory();
    if (relationToggle.checked) loadRelations();
  }

  async loadBookmarks(target) {
    try {
      const response = await this.api.request("/bookmarks");
      this.state.legalBookmarks = parseJsonList(response?.bookmarks);
      if (!this.state.legalBookmarks.length) {
        replaceChildren(target, [emptyState("还没有收藏条文。")]);
        return;
      }
      const rows = this.state.legalBookmarks.map((bookmark) => {
        const id = textValue(field(bookmark, ["id", "bookmarkId"]));
        const article = textValue(field(bookmark, ["article_id", "articleId"]));
        const title = textValue(field(bookmark, ["title"]), "未命名条文");
        const remove = button("移除", async () => {
          remove.disabled = true;
          try {
            await this.api.request(`/bookmarks/${pathId(id)}`, { method: "DELETE" });
            await this.loadBookmarks(target);
          } catch (error) {
            remove.disabled = false;
            target.prepend(statusBox(apiErrorMessage(error), "danger"));
          }
        }, "button subtle");
        return node("div", { className: "bookmark-row" }, [node("span", { text: title }), node("span", { className: "muted small", text: article }), remove]);
      });
      replaceChildren(target, rows);
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  async renderWriting(main) {
    const renderScope = this.state.activeRenderScope;
    const renderSessionEpoch = this.state.sessionEpoch;
    const isCurrentWritingRender = () => this.isSessionCurrent(renderSessionEpoch) && this.state.activeRenderScope === renderScope;
    let activeWritingDraft = this.activateWritingDraft("writing-current");
    let writingSelectionGeneration = 0;
    let writingInputGeneration = 0;
    let writingFormGeneration = 0;
    let writingFormDirty = false;
    let writingDraftLoadGeneration = 0;
    const title = node("div", { className: "page-title" }, [heading(1, "文书写作"), node("p", { text: "描述案件和写作要求，由模型先检索依据再生成文书；预览为渲染后的正文，默认导出 PDF。" })]);
    const layout = node("div", { className: "workspace-grid template-grid" });
    const editorColumn = node("div", { className: "workspace-column" });
    const previewColumn = node("div", { className: "workspace-column" });
    layout.append(editorColumn, previewColumn);
    main.append(title, layout);
    const draftLoad = this.loadWritingDraft(activeWritingDraft, { sessionEpoch: renderSessionEpoch });

    const editor = panel("案件与写作要求");
    const form = node("form", { className: "stack-form" });
    const documentType = node("select", { required: true });
    for (const value of ["民事起诉状", "民事答辩状", "劳动仲裁申请书", "律师函", "合同审查意见", "法律意见书"]) appendOption(documentType, value, value);
    const caseDescription = node("textarea", { rows: 10, placeholder: "说明当事人、时间、事实经过、争议焦点、请求和证据。可以直接粘贴已脱敏材料摘要。", required: true });
    const requirements = node("textarea", { rows: 5, placeholder: "例如：使用正式法律文书格式；缺失事实标记为【待补充】；引用现行有效法条。" });
    const caseDate = node("input", { type: "date", ariaLabel: "文书适用日期" });
    const providerSelect = node("select", { required: true });
    appendOption(providerSelect, "", "选择写作模型服务");
    const modelInput = node("select", { required: true, ariaLabel: "文书写作模型" });
    appendOption(modelInput, "", "选择 Provider 后载入模型");
    const materialHost = node("div", { className: "ai-material-host" }, [emptyState("正在加载可用材料…")]);
    let materialPicker = null;
    let writingRangePicker = null;
    let writingScopeGeneration = 0;
    // The run and source-selection generation that dispatched the currently
    // visible context plan. A terminal poll may clear the picker warning only
    // while that exact selection is still on screen.
    let latestWritingContextSubmission = null;
    let hasLocalDraftInput = false;
    // Programmatic source selection during initial recovery must not be
    // treated as a user edit: it would overwrite a dirty body before it can
    // be restored. User input is recorded immediately and flushed once the
    // recovery sequence reaches a stable snapshot.
    let writingDraftReady = false;
    let queueDraft = () => {};
    const noteDraftInput = () => {
      hasLocalDraftInput = true;
      writingFormGeneration += 1;
      writingFormDirty = true;
      if (writingDraftReady) queueDraft();
    };
    const attachmentPicker = this.renderAiAttachmentPicker({ onChange: () => {
      writingRangePicker?.syncSources();
      writingScopeGeneration += 1;
      noteDraftInput();
    } });
    writingRangePicker = this.renderContextRangePicker({
      title: "文书材料与附件范围",
      getMaterials: () => materialPicker?.values?.() || [],
      getAttachmentIds: () => attachmentPicker.attachmentIds?.() || [],
      onChanged: () => {
        writingScopeGeneration += 1;
        noteDraftInput();
        setStatus(status, "材料范围已修改；此前预检结果已失效。", "warning");
      }
    });
    const writingContextEstimate = node("div", { className: "context-estimate" }, [emptyState("提交前会显示本次采用的材料、页码或段落范围及上下文预算。")]);
    const generateButton = formButton("生成文书", "button primary");
    const status = statusBox();
    const draftStatus = statusBox("正在恢复本机加密草稿…", "muted");
    const retryDraft = button("重试保存草稿", () => {
      this.queueWritingDraft(draftSnapshot(), draftStatus, activeWritingDraft);
      void this.flushWritingDraft(activeWritingDraft);
    }, "button subtle");
    retryDraft.hidden = true;
    draftStatus.retryControl = retryDraft;
    const conflictPanel = node("div", { className: "draft-conflict-panel", hidden: true });
    form.append(labelFor("文书类型", documentType), labelFor("案情描述", caseDescription), labelFor("写作要求", requirements), labelFor("文书适用日期（可选；修改已有文书后须保存为新版本）", caseDate), labelFor("Provider", providerSelect), labelFor("模型", modelInput), materialHost, attachmentPicker, writingRangePicker, writingContextEstimate, generateButton, status, draftStatus, retryDraft, conflictPanel);
    editor.append(form);
    editorColumn.append(editor);

    const previewPanel = panel("预览与导出", [], "panel preview-panel");
    const runStatus = statusBox("尚未生成文书。", "muted");
    const preview = node("article", { className: "document-preview document-rendered" }, [emptyState("填写案件并生成文书。")]);
    const contentEditor = node("textarea", { className: "document-content-editor", rows: 22, hidden: true, placeholder: "在此修改 Markdown 正文后保存" });
    let pendingExportSnapshot = null;
    let writingCitationPending = false;
    let writingDateChanged = false;
    let renderWritingCitation = () => {};
    const applyDraftSnapshot = (value, { keepEditor = true } = {}) => {
      const snapshot = writingDraftContent(value);
      documentType.value = [...documentType.options].some((option) => option.value === snapshot.document_type) ? snapshot.document_type : documentType.value;
      caseDescription.value = snapshot.prompt;
      requirements.value = snapshot.requirements;
      caseDate.value = legalDateValue(snapshot.case_date);
      attachmentPicker.setAttachments(snapshot.attachment_ids.map((id) => ({ id })));
      if (materialPicker) renderWritingMaterialPicker(snapshot.materials);
      writingRangePicker.setContextRanges(snapshot.context_ranges);
      if (snapshot.provider_id && [...providerSelect.options].some((option) => option.value === snapshot.provider_id)) providerSelect.value = snapshot.provider_id;
      providerModel({ preserveModel: true });
      if (snapshot.model && [...modelInput.options].some((option) => option.value === snapshot.model)) modelInput.value = snapshot.model;
      if (keepEditor && snapshot.run_id && snapshot.content) {
        contentEditor.value = snapshot.content;
        contentEditor.dataset.runId = snapshot.run_id;
        contentEditor.dataset.expectedRevision = String(snapshot.run_revision ?? aiRunRevision(this.state.runsById.get(snapshot.run_id)));
        contentEditor.dataset.documentId = writingDocumentId(this.state.runsById.get(snapshot.run_id) || { id: snapshot.run_id });
        contentEditor.hidden = false;
        saveContent.hidden = false;
        writingCitationPending = true;
      }
      writingInputGeneration += 1;
      writingFormDirty = false;
      return snapshot;
    };
    const conflictBody = (remote, candidate) => {
      const remoteText = textValue(remote);
      const candidateText = textValue(candidate);
      if (!candidateText || candidateText === remoteText) return remoteText;
      if (!remoteText) return candidateText;
      return `${remoteText}\n\n--- 本窗口冲突副本 ---\n\n${candidateText}`;
    };
    const renderDraftConflicts = (items = activeWritingDraft.conflicts) => {
      if (!isCurrentWritingRender() || activeWritingDraft !== this.state.writingDraft) return;
      const rows = Array.isArray(items) ? items.filter((item) => item?.id) : [];
      const hasMore = Boolean(activeWritingDraft.conflictNextCursor);
      conflictPanel.hidden = rows.length === 0 && !hasMore;
      if (!rows.length && !hasMore) {
        replaceChildren(conflictPanel);
        return;
      }
      const actionsFor = (candidate) => {
        // All conflict actions belong to the candidate and document displayed
        // when the control was created.  An async read that returns after the
        // user selected another history row must neither change nor save that
        // other document.
        const actionDraft = activeWritingDraft;
        const actionDraftId = actionDraft.id;
        const actionSelectionGeneration = writingSelectionGeneration;
        const actionInputGeneration = writingInputGeneration;
        const actionFormGeneration = writingFormGeneration;
        const actionPageRunId = textValue(this.state.pageRunIds.writing);
        const actionDocumentId = writingDocumentId(this.pageRun("writing"))
          || (actionDraftId.startsWith("writing-") && actionDraftId !== "writing-current" ? actionDraftId.slice("writing-".length) : "");
        const canApplyAction = () => {
          const currentPageRun = this.pageRun("writing");
          return isCurrentWritingRender()
          && activeWritingDraft === actionDraft
          && this.state.writingDraft === actionDraft
          && actionDraft.id === actionDraftId
          && writingSelectionGeneration === actionSelectionGeneration
          && writingInputGeneration === actionInputGeneration
          && writingFormGeneration === actionFormGeneration
          && textValue(this.state.pageRunIds.writing) === actionPageRunId
          && (!actionDocumentId || !currentPageRun || writingDocumentId(currentPageRun) === actionDocumentId);
        };
        const readRecord = async (id) => {
          const response = await this.api.getAiDraft(id);
          if (!canApplyAction()) throw staleAsyncError();
          return response?.draft || response || {};
        };
        const bindSnapshotRun = async (value) => {
          const snapshot = writingDraftContent(value);
          if (!snapshot.run_id) return snapshot;
          let bound = this.state.runsById.get(snapshot.run_id);
          if (!bound) {
            const response = await this.api.getAiRun(snapshot.run_id);
            if (!canApplyAction()) throw staleAsyncError();
            bound = normalizeAiRun(response?.run || response);
          } else bound = normalizeAiRun(bound);
          const snapshotRevision = snapshot.run_revision;
          const expectedDocument = actionDocumentId;
          if (bound.kind !== AI_RUN_KINDS.writing
            || (expectedDocument && writingDocumentId(bound) !== expectedDocument)
            || (Number.isSafeInteger(snapshotRevision) && snapshotRevision >= 0 && aiRunRevision(bound) !== snapshotRevision)) {
            throw new ApiError("draft_run_binding_invalid", false, 409);
          }
          if (!canApplyAction()) throw staleAsyncError();
          const remembered = this.rememberAiRun(bound);
          return writingDraftContent({ ...snapshot, run_id: remembered.id, run_revision: aiRunRevision(remembered) });
        };
        const restore = button("恢复冲突草稿", async () => {
          try {
            const record = await readRecord(candidate.id);
            if (!canApplyAction()) throw staleAsyncError();
            const snapshot = await bindSnapshotRun(record.content || record);
            if (!canApplyAction()) throw staleAsyncError();
            applyDraftSnapshot(snapshot);
            setStatus(draftStatus, "已恢复冲突副本；请确认后生成文书或保存新的文书版本。", "warning");
          } catch (error) {
            if (error?.name !== "AbortError" && canApplyAction()) setStatus(draftStatus, `冲突副本未恢复：${apiErrorMessage(error)}`, "danger");
          }
        }, "button subtle");
        const adopt = button("采用远端草稿", async () => {
          try {
            const record = await readRecord(actionDraftId);
            if (!canApplyAction()) throw staleAsyncError();
            const snapshot = await bindSnapshotRun(record.content || record);
            if (!canApplyAction()) throw staleAsyncError();
            actionDraft.revision = aiRunRevision(record, actionDraft.revision);
            applyDraftSnapshot(snapshot);
            setStatus(draftStatus, "已采用远端草稿；独立冲突副本仍被保留。", "success");
          } catch (error) {
            if (error?.name !== "AbortError" && canApplyAction()) setStatus(draftStatus, `远端草稿未恢复：${apiErrorMessage(error)}`, "danger");
          }
        }, "button subtle");
        const merge = button("合并冲突草稿", async () => {
          try {
            const [remoteRecord, candidateRecord] = await Promise.all([readRecord(actionDraftId), readRecord(candidate.id)]);
            if (!canApplyAction()) throw staleAsyncError();
            const [remote, local] = await Promise.all([
              bindSnapshotRun(remoteRecord.content || remoteRecord),
              bindSnapshotRun(candidateRecord.content || candidateRecord)
            ]);
            if (!canApplyAction()) throw staleAsyncError();
            actionDraft.revision = aiRunRevision(remoteRecord, actionDraft.revision);
            const merged = writingDraftContent({
              ...remote,
              prompt: conflictBody(remote.prompt, local.prompt),
              requirements: conflictBody(remote.requirements, local.requirements),
              content: conflictBody(remote.content, local.content),
              dirty: Boolean(remote.dirty || local.dirty)
            });
            applyDraftSnapshot(merged);
            this.queueWritingDraft(merged, draftStatus, actionDraft);
            void this.flushWritingDraft(actionDraft);
            setStatus(draftStatus, "已将远端草稿和冲突副本并列合并，正在保存为新的加密草稿。", "info");
          } catch (error) {
            if (error?.name !== "AbortError" && canApplyAction()) setStatus(draftStatus, `草稿未合并：${apiErrorMessage(error)}`, "danger");
          }
        }, "button subtle");
        const retain = button("保留独立草稿", () => {
          if (canApplyAction()) setStatus(draftStatus, "独立冲突副本已加密保留，可稍后恢复、采用或合并。", "success");
        }, "button subtle");
        return node("div", { className: "button-row draft-conflict-actions" }, [restore, adopt, merge, retain]);
      };
      const body = [
        heading(3, "发现加密冲突草稿"),
        node("p", { className: "muted small", text: "冲突副本未覆盖远端草稿；请明确选择恢复、采用、合并或保留。" }),
        ...rows.map((candidate) => node("div", { className: "draft-conflict-row" }, [
          node("p", { className: "result-meta", text: `副本 ${candidate.id.slice(-8)} · 修订 ${candidate.revision}` }),
          actionsFor(candidate)
        ]))
      ];
      if (activeWritingDraft.conflictCorruptCount > 0) body.push(statusBox(`检测到 ${activeWritingDraft.conflictCorruptCount} 个损坏冲突草稿，未显示。`, "warning"));
      if (hasMore) body.push(button(`加载更多冲突草稿${activeWritingDraft.conflictTotal ? `（共 ${activeWritingDraft.conflictTotal} 条）` : ""}`, async (event) => {
        const control = event.currentTarget;
        control.disabled = true;
        try {
          await this.loadWritingDraftConflicts(activeWritingDraft, { sessionEpoch: renderSessionEpoch, append: true });
        } catch (error) {
          if (error?.name !== "AbortError" && isCurrentWritingRender() && activeWritingDraft === this.state.writingDraft) setStatus(draftStatus, `更多冲突草稿未载入：${apiErrorMessage(error)}`, "danger");
        } finally {
          if (isCurrentWritingRender() && activeWritingDraft === this.state.writingDraft) control.disabled = false;
        }
      }, "button subtle"));
      replaceChildren(conflictPanel, body);
    };
    activeWritingDraft.onConflictsChanged = renderDraftConflicts;
    // Serialized by logical document rather than by the save button. A
    // save-and-export request therefore owns its captured body and cannot
    // consume another document's in-flight button promise.
    const contentSaveChains = new Map();
    const captureContentSaveRequest = ({ expectedDocumentId = "" } = {}) => {
      const editingRunId = textValue(contentEditor.dataset.runId);
      const run = editingRunId ? this.state.runsById.get(editingRunId) : null;
      const documentId = textValue(contentEditor.dataset.documentId) || writingDocumentId(run);
      if (!run?.id || !documentId || (expectedDocumentId && documentId !== expectedDocumentId)) return null;
      const expectedRevision = Number(contentEditor.dataset.expectedRevision);
      return {
        run: normalizeAiRun(run),
        documentId,
        expectedRevision: Number.isSafeInteger(expectedRevision) ? expectedRevision : aiRunRevision(run),
        content: contentEditor.value,
        changedDate: writingDateChanged ? (legalDateValue(caseDate.value) || null) : undefined,
        sessionEpoch: this.state.sessionEpoch,
        inputGeneration: writingInputGeneration,
        formGeneration: writingFormGeneration,
        renderScope: this.state.activeRenderScope
      };
    };
    const performContentSave = (request) => {
      if (!request) return Promise.resolve(null);
      const predecessor = contentSaveChains.get(request.documentId);
      const chained = (async () => {
        const previous = predecessor ? await predecessor : null;
        const source = previous?.id ? previous : request.run;
        const expectedRevision = previous?.id ? aiRunRevision(previous) : request.expectedRevision;
        const response = await this.api.updateAiRunContent(source.id, request.content, expectedRevision, { caseDate: request.changedDate });
        if (!this.isSessionCurrent(request.sessionEpoch)) throw staleAsyncError();
        const saved = this.rememberAiRun(response?.run || response);
        // Delivery of a saved version is intentionally independent from UI
        // selection. Export can consume it after a history switch, while UI
        // mutations still require the exact render/document/input identity.
        const canApply = this.state.activeRenderScope === request.renderScope
          && this.state.pageRunIds.writing
          && writingDocumentId(this.pageRun("writing")) === request.documentId
          && textValue(contentEditor.dataset.documentId) === request.documentId
          && writingInputGeneration === request.inputGeneration;
        if (!canApply) return saved;
        this.selectPageRun("writing", saved);
        this.rememberWritingRunPointer(saved);
        contentEditor.dataset.runId = saved.id;
        contentEditor.dataset.expectedRevision = String(aiRunRevision(saved));
        contentEditor.dataset.documentId = writingDocumentId(saved);
        const formChangedDuringSave = writingFormGeneration !== request.formGeneration;
        if (request.changedDate !== undefined && !formChangedDuringSave) caseDate.value = legalDateValue(field(saved, ["case_date", "caseDate"])) || request.changedDate || "";
        if (!formChangedDuringSave) {
          writingCitationPending = false;
          writingDateChanged = false;
        }
        renderRenderedContent(preview, saved.html, saved.content);
        renderWritingCitation(saved);
        await refreshHistory();
        if (!isCurrentWritingRender() || writingInputGeneration !== request.inputGeneration || writingDocumentId(this.pageRun("writing")) !== request.documentId) return saved;
        setStatus(runStatus, request.changedDate === undefined ? "正文修改已保存。" : "正文与文书适用日期已保存为新版本。", "success");
        if (!formChangedDuringSave) {
          contentEditor.hidden = true;
          saveContent.hidden = true;
          writingFormDirty = false;
        }
        // Form edits made while the request was in flight remain in the
        // encrypted draft, including a later case date and requirements.
        this.queueWritingDraft(draftSnapshot(), draftStatus, activeWritingDraft);
        void this.flushWritingDraft(activeWritingDraft);
        return saved;
      })();
      contentSaveChains.set(request.documentId, chained);
      const clearChain = () => {
        if (contentSaveChains.get(request.documentId) === chained) contentSaveChains.delete(request.documentId);
      };
      void chained.then(clearChain, clearChain);
      return chained;
    };
    const saveContent = button("保存正文修改", async () => {
      const request = captureContentSaveRequest();
      if (!request) return;
      saveContent.disabled = true;
      try {
        saveContent.savePromise = performContentSave(request);
        await saveContent.savePromise;
      } catch (error) {
        if (error?.name !== "AbortError" && isCurrentWritingRender()) setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        saveContent.disabled = false;
      }
    }, "button secondary");
    saveContent.hidden = true;
    const editContent = button("编辑正文", () => {
      const run = this.pageRun("writing");
      if (!run?.id) return;
      contentEditor.value = run.content;
      contentEditor.dataset.runId = run.id;
      contentEditor.dataset.expectedRevision = String(aiRunRevision(run));
      contentEditor.dataset.documentId = writingDocumentId(run);
      contentEditor.hidden = false;
      saveContent.hidden = false;
      contentEditor.focus();
    }, "button subtle");
    const exportRow = node("div", { className: "button-row" });
    const format = node("select");
    appendOption(format, "pdf", "PDF（默认）", true);
    appendOption(format, "docx", "DOCX");
    appendOption(format, "txt", "TXT");
    appendOption(format, "md", "Markdown");
    const exportChoices = node("div", { className: "draft-export-choices", hidden: true });
    const exportRunSnapshot = async (sourceRun, formatValue = format.value) => {
      const exportSessionEpoch = this.state.sessionEpoch;
      const snapshot = normalizeAiRun(sourceRun);
      const selectedFormat = ["pdf", "docx", "txt", "md"].includes(String(formatValue)) ? String(formatValue) : "pdf";
      if (!snapshot.id) throw new ApiError("run_id_missing", false, 200);
      const verification = normalizeCitationVerification(snapshot.citationVerification);
      const verificationPending = verification.state !== "passed";
      if (verificationPending) setStatus(runStatus, "引用机械核验待复核，仍可导出；当前导出在界面中标记为待复核。", "warning");
      const blob = await this.api.exportAiRun(snapshot.id, selectedFormat, aiRunRevision(snapshot));
      if (!this.isSessionCurrent(exportSessionEpoch)) throw staleAsyncError();
      await downloadBlob(blob, safeFilename(snapshot.title || "文书", selectedFormat));
      if (isCurrentWritingRender() && writingDocumentId(this.pageRun("writing")) === writingDocumentId(snapshot)) setStatus(runStatus, verificationPending ? `已导出 ${selectedFormat.toUpperCase()}；引用机械核验仍待复核。` : `已导出 ${selectedFormat.toUpperCase()}。`, verificationPending ? "warning" : "success");
    };
    const exportSavedVersion = button("导出已保存版本", async () => {
      const choice = pendingExportSnapshot;
      if (!choice?.run?.id) return;
      pendingExportSnapshot = null;
      exportChoices.hidden = true;
      exportButton.disabled = true;
      try {
        await exportRunSnapshot(choice.run, choice.format);
      } catch (error) {
        if (error?.name !== "AbortError") setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        exportButton.disabled = false;
      }
    }, "button secondary");
    const saveThenExport = button("保存并导出", async () => {
      const choice = pendingExportSnapshot;
      if (!choice?.run?.id || contentEditor.hidden) return;
      pendingExportSnapshot = null;
      exportChoices.hidden = true;
      exportButton.disabled = true;
      try {
        // Do not delegate to the shared button promise: it may belong to an
        // older A save, or to a different document after a history switch.
        const request = captureContentSaveRequest({ expectedDocumentId: choice.documentId });
        const saved = await performContentSave(request);
        if (!saved?.id) return;
        await exportRunSnapshot(saved, choice.format);
      } catch (error) {
        if (error?.name !== "AbortError") setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        exportButton.disabled = false;
      }
    }, "button secondary");
    exportChoices.append(node("p", { className: "muted small", text: "正文有未保存修改。请选择固定导出快照。" }), exportSavedVersion, saveThenExport);
    const exportButton = button("导出", async () => {
      const run = this.pageRun("writing");
      if (!run?.id) {
        setStatus(runStatus, "请先生成文书。", "warning");
        return;
      }
      const dirtyCurrentDocument = !contentEditor.hidden
        && textValue(contentEditor.dataset.documentId) === writingDocumentId(run);
      if (dirtyCurrentDocument) {
        pendingExportSnapshot = { run: normalizeAiRun(run), format: format.value, documentId: writingDocumentId(run) };
        exportChoices.hidden = false;
        setStatus(runStatus, "正文有未保存修改。请明确选择导出已保存版本，或保存并导出。", "warning");
        return;
      }
      exportButton.disabled = true;
      try {
        await exportRunSnapshot(run, format.value);
      } catch (error) {
        if (error?.name !== "AbortError") setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        exportButton.disabled = false;
      }
    }, "button secondary");
    exportRow.append(editContent, format, exportButton);
    const citations = node("div", { className: "citation-list" });
    const citationVerification = node("div", { className: "citation-verification" });
    const toolSteps = node("details", { className: "tool-steps" }, [node("summary", { text: "查看检索过程" })]);
    previewPanel.append(runStatus, preview, contentEditor, saveContent, citations, citationVerification, toolSteps, exportRow, exportChoices);
    previewColumn.append(previewPanel);

    const historyPanel = panel("写作历史", [], "panel ai-history-panel");
    const historyList = node("div", { className: "ai-history-list" }, [emptyState("正在加载历史记录…")]);
    historyPanel.append(historyList);
    editorColumn.append(historyPanel);
    const persistActiveDraft = (snapshot = null) => {
      if (!writingDraftReady) return;
      const value = snapshot || draftSnapshot();
      this.queueWritingDraft(value, draftStatus, activeWritingDraft);
      void this.flushWritingDraft(activeWritingDraft);
    };
    const activateDraftForRun = async (run, { previousSnapshot = null } = {}) => {
      const draftId = writingDraftIdForRun(run);
      if (activeWritingDraft.id !== draftId) {
        if (previousSnapshot) persistActiveDraft(previousSnapshot);
        activeWritingDraft = this.activateWritingDraft(draftId);
        activeWritingDraft.onConflictsChanged = renderDraftConflicts;
      }
      const target = activeWritingDraft;
      const loadGeneration = ++writingDraftLoadGeneration;
      let snapshot = await this.loadWritingDraft(target, { sessionEpoch: renderSessionEpoch });
      if (!isCurrentWritingRender() || activeWritingDraft !== target || loadGeneration !== writingDraftLoadGeneration) return snapshot;

      // v1.2.1 stored every draft in writing-current. If its run belongs to
      // this document, copy it once to the canonical per-document key while
      // deliberately retaining the legacy source for recovery and audit.
      if (target.id !== "writing-current" && !target.exists) {
        const legacy = this.writingDraftState("writing-current");
        const legacySnapshot = legacy.loaded
          ? await Promise.resolve(writingDraftContent(legacy.lastContent || {}))
          : await this.loadWritingDraft(legacy, { sessionEpoch: renderSessionEpoch });
        const legacyRun = this.state.runsById.get(legacySnapshot.run_id);
        const legacyMatches = legacySnapshot.run_id && (
          legacySnapshot.run_id === run.id
          || (legacyRun && writingDocumentId(legacyRun) === writingDocumentId(run))
        );
        if (legacyMatches) {
          try {
            const response = await this.api.saveAiDraft(target.id, { expected_revision: 0, content: legacySnapshot });
            if (!isCurrentWritingRender() || activeWritingDraft !== target || loadGeneration !== writingDraftLoadGeneration) return snapshot;
            const record = response?.draft || response || {};
            target.revision = aiRunRevision(record, 1);
            target.loaded = true;
            target.exists = true;
            target.lastContent = legacySnapshot;
            snapshot = legacySnapshot;
          } catch (error) {
            if (error?.name !== "AbortError") setStatus(draftStatus, `旧版文书草稿未迁移：${apiErrorMessage(error)}`, "warning");
          }
        }
      }
      target.lastContent = snapshot;
      void this.loadWritingDraftConflicts(target, { sessionEpoch: renderSessionEpoch });
      if (!isCurrentWritingRender() || activeWritingDraft !== target || loadGeneration !== writingDraftLoadGeneration) return snapshot;
      if (snapshot.dirty && (snapshot.prompt || snapshot.requirements || snapshot.content || snapshot.materials.length || snapshot.attachment_ids.length)) {
        applyDraftSnapshot(snapshot);
        setStatus(draftStatus, "已恢复该文书的本机加密草稿。", "success");
      }
      return snapshot;
    };
    const renderWritingRunContextPlan = (run) => {
      const plan = field(run, ["context_plan", "contextPlan"]);
      if (!plan || typeof plan !== "object") return false;
      this.renderContextEstimate(writingContextEstimate, plan);
      return true;
    };
    const showWritingRun = (run, { resume = true, selectionIntent = null } = {}) => {
      const loaded = this.rememberAiRun(run);
      if (!isCurrentWritingRender()) return loaded;
      if (selectionIntent !== null && selectionIntent !== writingSelectionGeneration) return loaded;
      const previous = this.pageRun("writing");
      const previousDocumentId = writingDocumentId(previous);
      const nextDocumentId = writingDocumentId(loaded);
      const switchingDocument = previousDocumentId !== nextDocumentId;
      const previousSnapshot = switchingDocument && writingDraftReady ? draftSnapshot() : null;
      const dirtySameDocument = !contentEditor.hidden && textValue(contentEditor.dataset.documentId) === nextDocumentId;
      this.selectPageRun("writing", loaded);
      this.rememberWritingRunPointer(loaded);
      if (previous?.id && previous.id !== loaded.id) {
        writingCitationPending = false;
        writingDateChanged = false;
      }
      if (switchingDocument) {
        // A dirty-export decision is for the document visible when the choice
        // opened. Do not leave its controls actionable after a history switch.
        pendingExportSnapshot = null;
        exportChoices.hidden = true;
      }
      if (switchingDocument && contentEditor.dataset.runId) {
        contentEditor.hidden = true;
        saveContent.hidden = true;
        delete contentEditor.dataset.runId;
        delete contentEditor.dataset.expectedRevision;
        delete contentEditor.dataset.documentId;
      }
      renderRenderedContent(preview, loaded.html, loaded.content, "该任务尚无正文结果。");
      if (!writingDateChanged) caseDate.value = legalDateValue(field(loaded, ["case_date", "caseDate"]));
      if (!dirtySameDocument) contentEditor.value = loaded.content;
      this.renderRunCitations(citations, loaded.citations);
      renderWritingCitation(loaded);
      replaceChildren(toolSteps, [node("summary", { text: "查看检索过程" }), ...(loaded.tool_steps || []).map((step) => node("p", { className: "tool-step", text: textValue(field(step, ["summary", "query", "action"]), aiToolLabel(field(step, ["tool", "name"]))) }))]);
      setStatus(runStatus, `${aiRunKindLabel(loaded.kind)}：${aiRunStatusLabel(loaded.status)}${loaded.stage ? ` · ${pipelineStageLabel(loaded.stage)}` : ""} · ${aiRunProgressText(loaded)}`, loaded.status === "completed" ? "success" : aiRunIsTerminal(loaded) ? "warning" : "info");
      renderWritingRunContextPlan(loaded);
      if (switchingDocument || activeWritingDraft.id !== writingDraftIdForRun(loaded)) {
        void activateDraftForRun(loaded, { previousSnapshot }).catch((error) => {
          if (error?.name !== "AbortError" && isCurrentWritingRender()) setStatus(draftStatus, `草稿未恢复：${apiErrorMessage(error)}`, "danger");
        });
      }
      if (resume && !aiRunIsTerminal(loaded)) this.pollAiRun(loaded.id, {
        status: runStatus,
        onUpdate: (next) => {
          if (this.state.pageRunIds.writing === next.id) showWritingRun(next, { resume: false });
        }
      });
      return loaded;
    };
    const applyPolledWritingRun = (run, { terminal = false, submission = null } = {}) => {
      const loaded = normalizeAiRun(run);
      // A result for a history row that is no longer selected must remain in
      // the cache only. In particular it may not replace a dirty editor, its
      // title/status, or its current range readiness message.
      if (!isCurrentWritingRender() || this.state.pageRunIds.writing !== loaded.id) return false;
      showWritingRun(loaded, { resume: false });
      const submissionMatches = terminal
        && loaded.status === "completed"
        && submission === latestWritingContextSubmission
        && submission?.runId === loaded.id
        && submission.scopeGeneration === writingScopeGeneration
        && submission.sessionEpoch === renderSessionEpoch
        && submission.renderScope === renderScope;
      // Applying a range deliberately warns that a new plan is needed. Once
      // the matching run completes, a plain re-render removes only that stale
      // warning; it does not change the selected sources or ranges.
      if (submissionMatches && renderWritingRunContextPlan(loaded)) writingRangePicker.syncSources();
      return true;
    };
    renderWritingCitation = (run) => {
      const activeRun = normalizeAiRun(run || this.pageRun("writing"));
      const isCurrentRun = Boolean(activeRun.id && activeRun.id === this.pageRun("writing")?.id);
      const hasUnsavedBody = Boolean(activeRun.id && activeRun.id === textValue(contentEditor.dataset.runId) && writingCitationPending);
      this.renderCitationVerification(citationVerification, activeRun, {
        locallyPending: Boolean((isCurrentRun && writingDateChanged) || hasUnsavedBody),
        onUpdated: async (next) => {
          writingCitationPending = false;
          writingDateChanged = false;
          showWritingRun(next, { resume: false });
          await refreshHistory();
          setStatus(runStatus, "引用机械核验已更新；论证相关性仍需人工复核。", "success");
        }
      });
    };
    const continueWritingRun = async (run) => {
      try {
        const response = await this.api.continueAiRun(run.id);
        const next = normalizeAiRun(response?.run || response?.new_run || response);
        if (!next.id) throw new ApiError("run_id_missing", false, 200);
        showWritingRun(next);
        await refreshHistory();
        setStatus(runStatus, "已继续文书写作任务。", "info");
      } catch (error) {
        setStatus(runStatus, apiErrorMessage(error), "danger");
      }
    };
    const openRun = async (run) => {
      const selectionIntent = ++writingSelectionGeneration;
      const requestSessionEpoch = this.state.sessionEpoch;
      try {
        const response = await this.api.getAiRun(run.id);
        if (!this.isSessionCurrent(requestSessionEpoch) || !isCurrentWritingRender()) return;
        const loaded = this.rememberAiRun(response?.run || response);
        if (selectionIntent !== writingSelectionGeneration) return;
        showWritingRun(loaded, { selectionIntent });
      } catch (error) {
        if (error?.name !== "AbortError" && this.isSessionCurrent(requestSessionEpoch) && isCurrentWritingRender() && selectionIntent === writingSelectionGeneration) setStatus(runStatus, apiErrorMessage(error), "danger");
      }
    };
    let restoredWritingPointerAttempted = false;
    const refreshHistory = async ({ append = false } = {}) => {
      const historySessionEpoch = this.state.sessionEpoch;
      try {
        const page = await this.loadAiRunPage("writing", { append, limit: 20 });
        if (!this.isSessionCurrent(historySessionEpoch) || !isCurrentWritingRender()) return;
        const runs = page.items;
        const rows = runs.length ? runs.map((run) => {
          const open = button(`${run.title || documentType.value} · ${aiRunStatusLabel(run.status)}`, () => openRun(run), "conversation-item");
          const row = node("div", { className: "ai-history-row" }, [open]);
          if (["paused", "interrupted", "failed"].includes(String(run.status).toLowerCase())) row.append(button("继续", () => continueWritingRun(run), "button subtle"));
          row.append(button("删除", async () => {
            try { await this.api.deleteAiRun(run.id); await refreshHistory(); }
            catch (error) { setStatus(runStatus, apiErrorMessage(error), "danger"); }
          }, "button danger"));
          return row;
        }) : [emptyState("还没有文书写作记录。")] ;
        if (page.corruptCount > 0) rows.unshift(statusBox(`检测到 ${page.corruptCount} 个损坏文书记录，未显示。`, "warning"));
        if (page.nextCursor) rows.push(button("加载更多文书历史", () => refreshHistory({ append: true }), "button subtle"));
        replaceChildren(historyList, rows);
        const pointer = this.restoredWritingRunPointer();
        if (!restoredWritingPointerAttempted && !this.pageRun("writing")?.id && pointer) {
          restoredWritingPointerAttempted = true;
          const summary = runs.find((item) => item.id === pointer);
          // The safe pointer names one document, while history is paged.  A
          // restart must not depend on the document fitting in the first page.
          void openRun(summary || { id: pointer, kind: AI_RUN_KINDS.writing, title: "恢复的文书", status: "completed" });
        }
      } catch (error) {
        if (this.isSessionCurrent(historySessionEpoch) && isCurrentWritingRender() && error?.name !== "AbortError") replaceChildren(historyList, [statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    const providerModel = ({ preserveModel = false, syncMaterialTrust = true } = {}) => {
      const provider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
      const previous = preserveModel ? modelInput.value : "";
      const models = providerModelIds(provider);
      const configured = aiDefaultSelection(this.state.aiDefaults, "writing");
      const preferred = preserveModel && models.includes(previous)
        ? previous
        : provider && textValue(field(provider, ["id"])) === configured.providerId && models.includes(configured.model)
          ? configured.model
          : models[0] || "";
      replaceChildren(modelInput);
      appendOption(modelInput, "", provider ? "选择模型" : "选择 Provider 后载入模型");
      for (const model of models) appendOption(modelInput, model, model, model === preferred);
      modelInput.value = preferred;
      modelInput.disabled = !provider || !models.length;
      modelInput.title = models.length ? "可选择该 Provider 已启用的模型" : "该 Provider 尚未启用模型";
      if (syncMaterialTrust) this.applyMaterialTrust(materialPicker, provider, { notify: writingDraftReady });
      return provider;
    };
    const draftSnapshot = () => writingDraftContent({
      document_type: documentType.value,
      prompt: caseDescription.value,
      requirements: requirements.value,
      case_date: legalDateValue(caseDate.value),
      provider_id: providerSelect.value,
      model: modelInput.value,
      materials: materialPicker?.values?.() || [],
      attachment_ids: attachmentPicker.attachmentIds?.() || [],
      context_ranges: writingRangePicker.contextRanges().ranges,
      run_id: textValue(contentEditor.dataset.runId, this.pageRun("writing")?.id || ""),
      run_revision: Number(contentEditor.dataset.expectedRevision) || aiRunRevision(this.pageRun("writing")),
      content: contentEditor.value,
      dirty: !contentEditor.hidden || writingFormDirty
    });
    queueDraft = () => {
      if (activeWritingDraft.loaded) this.queueWritingDraft(draftSnapshot(), draftStatus, activeWritingDraft);
    };
    documentType.addEventListener("change", noteDraftInput);
    caseDescription.addEventListener("input", noteDraftInput);
    requirements.addEventListener("input", noteDraftInput);
    caseDate.addEventListener("change", () => {
      writingDateChanged = Boolean(this.pageRun("writing")?.id);
      if (writingDateChanged) {
        if (contentEditor.hidden) {
          const run = this.pageRun("writing");
          contentEditor.value = run.content;
          contentEditor.dataset.runId = run.id;
          contentEditor.dataset.expectedRevision = String(aiRunRevision(run));
          contentEditor.dataset.documentId = writingDocumentId(run);
          contentEditor.hidden = false;
          saveContent.hidden = false;
        }
        writingCitationPending = true;
        renderWritingCitation(this.pageRun("writing"));
        setStatus(runStatus, "文书适用日期已修改；旧版本未改变，请保存正文与日期修改以创建新版本。", "warning");
      }
      noteDraftInput();
    });
    contentEditor.addEventListener("input", () => {
      writingInputGeneration += 1;
      hasLocalDraftInput = true;
      if (writingDraftReady) queueDraft();
      if (!contentEditor.hidden && contentEditor.dataset.runId) {
        writingCitationPending = true;
        renderWritingCitation(this.state.runsById.get(contentEditor.dataset.runId));
      }
    });
    providerSelect.addEventListener("change", () => {
      providerModel();
      noteDraftInput();
    });
    modelInput.addEventListener("change", noteDraftInput);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const provider = providerModel({ preserveModel: true, syncMaterialTrust: false });
      const prompt = caseDescription.value.trim();
      if (!provider || !providerSelect.value) {
        setStatus(status, "请先在设置中选择写作模型服务。", "warning");
        return;
      }
      if (!prompt) {
        setStatus(status, "请填写案情描述。", "warning");
        return;
      }
      generateButton.disabled = true;
      setStatus(status, "正在检索法律依据并生成文书…");
      try {
        const model = modelInput.value.trim();
        if (!model || !providerModelIds(provider).includes(model)) {
          setStatus(status, "所选模型未启用，请前往设置勾选后重试。", "warning");
          return;
        }
        const writingDate = legalDateValue(caseDate.value);
        const scope = writingRangePicker.contextRanges();
        if (scope.error) {
          setStatus(status, scope.error, "warning");
          return;
        }
        const scopeGeneration = writingScopeGeneration;
        const payload = { kind: AI_RUN_KINDS.writing, prompt, provider_id: providerSelect.value, model, document_type: documentType.value, requirements: requirements.value.trim(), ...(writingDate ? { case_date: writingDate } : {}), materials: materialPicker?.values?.() || [], attachment_ids: attachmentPicker.attachmentIds?.() || [], context_ranges: scope.ranges };
        const contextEstimate = await this.preflightAiContext(payload, writingContextEstimate, status);
        if (!contextEstimate) return;
        if (scopeGeneration !== writingScopeGeneration) {
          setStatus(status, "材料、附件或范围在预检期间已修改；旧预检结果未被提交。", "warning");
          return;
        }
        payload.context_plan_hash = contextEstimate.planHash;
        const preCreationDraft = draftSnapshot();
        const contextSubmission = {
          runId: "",
          scopeGeneration,
          sessionEpoch: renderSessionEpoch,
          renderScope
        };
        latestWritingContextSubmission = contextSubmission;
        const created = await this.createAiRun(payload, {
          page: "writing",
          status,
          onUpdate: (run) => {
            if (!contextSubmission.runId) contextSubmission.runId = textValue(run?.id);
            applyPolledWritingRun(run, { submission: contextSubmission });
          },
          onDone: (run) => {
            if (!contextSubmission.runId) contextSubmission.runId = textValue(run?.id);
            if (!applyPolledWritingRun(run, { terminal: true, submission: contextSubmission })) return;
            const scopeStillCurrent = contextSubmission === latestWritingContextSubmission
              && contextSubmission.scopeGeneration === writingScopeGeneration;
            setStatus(status, run.status === "completed"
              ? scopeStillCurrent ? "文书已生成并保存历史记录。" : "文书已生成；当前材料或范围已修改，需重新预检后再生成。"
              : `任务状态：${aiRunStatusLabel(run.status)}`,
            run.status === "completed" && scopeStillCurrent ? "success" : "warning");
            void refreshHistory();
          }
        });
        contextSubmission.runId = created.id;
        if (!isCurrentWritingRender()) return;
        this.rememberWritingRunPointer(created);
        await activateDraftForRun(created, { previousSnapshot: preCreationDraft });
        if (isCurrentWritingRender() && activeWritingDraft.id === writingDraftIdForRun(created)) queueDraft();
      } catch (error) {
        if (error?.name !== "AbortError") setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        generateButton.disabled = false;
      }
    });
    let restoredDraft = writingDraftContent();
    try {
      restoredDraft = await draftLoad;
      if (!isCurrentWritingRender()) return;
      if (hasLocalDraftInput) {
        setStatus(draftStatus, "已保留本次输入，正在加密保存。", "info");
        queueDraft();
      } else {
        setStatus(draftStatus, restoredDraft.prompt || restoredDraft.requirements || restoredDraft.materials.length || restoredDraft.attachment_ids.length ? "已恢复本机加密草稿。" : "暂无已保存草稿。", "success");
      }
    } catch (error) {
      activeWritingDraft.loaded = true;
      if (error?.name !== "AbortError") setStatus(draftStatus, `草稿未恢复：${apiErrorMessage(error)}`, "danger");
      if (hasLocalDraftInput) queueDraft();
    }
    if (!hasLocalDraftInput) {
      documentType.value = [...documentType.options].some((option) => option.value === restoredDraft.document_type) ? restoredDraft.document_type : documentType.value;
      caseDescription.value = restoredDraft.prompt;
      requirements.value = restoredDraft.requirements;
      caseDate.value = legalDateValue(restoredDraft.case_date);
      attachmentPicker.setAttachments(restoredDraft.attachment_ids.map((id) => ({ id })));
    }
    await this.loadProvidersInto(providerSelect, "writing");
    if (!hasLocalDraftInput && restoredDraft.provider_id && [...providerSelect.options].some((option) => option.value === restoredDraft.provider_id)) providerSelect.value = restoredDraft.provider_id;
    await this.loadAiMaterials();
    const renderWritingMaterialPicker = (selectedValues) => {
      const page = this.state.aiMaterialsPage;
      materialPicker = this.renderAiMaterialPicker(this.state.aiMaterials, {
        title: "选择材料（默认脱敏版）",
        selectedValues,
        hasMore: Boolean(page.nextCursor),
        total: page.total,
        corruptCount: page.corruptCount,
        errorMessage: page.error,
        onLoadMore: async (preservedValues) => {
          await this.loadAiMaterials({ append: true });
          renderWritingMaterialPicker(preservedValues);
        },
        onChange: () => {
          writingRangePicker?.syncSources();
          writingScopeGeneration += 1;
          noteDraftInput();
        }
      });
      replaceChildren(materialHost, [materialPicker]);
      writingRangePicker?.syncSources();
    };
    renderWritingMaterialPicker(hasLocalDraftInput ? [] : restoredDraft.materials);
    if (!hasLocalDraftInput) writingRangePicker.setContextRanges(restoredDraft.context_ranges);
    providerModel({ preserveModel: true });
    if (!hasLocalDraftInput && restoredDraft.model && [...modelInput.options].some((option) => option.value === restoredDraft.model)) modelInput.value = restoredDraft.model;
    await refreshHistory();
    const restorePlan = writingDraftRestorePlan(
      restoredDraft,
      this.state.runsById.get(restoredDraft.run_id),
      { hasLocalInput: hasLocalDraftInput }
    );
    if (restorePlan) {
      try {
        // The page list intentionally contains summary records without a
        // document body. Always fetch the specific run before binding the
        // editor, while taking the unsaved body only from the encrypted draft.
        const response = await this.api.getAiRun(restorePlan.runId);
        const restoredRun = showWritingRun(response?.run || response, { resume: false });
        contentEditor.value = restorePlan.content;
        contentEditor.dataset.runId = restoredRun.id || restorePlan.runId;
        contentEditor.dataset.expectedRevision = String(restorePlan.expectedRevision ?? aiRunRevision(restoredRun));
        contentEditor.hidden = false;
        saveContent.hidden = false;
        setStatus(draftStatus, "已恢复未提交的文书正文修改。", "success");
      } catch (error) {
        setStatus(draftStatus, `文书正文草稿待恢复：${apiErrorMessage(error)}`, "warning");
      }
    }
    writingDraftReady = true;
    activeWritingDraft.onConflictsChanged = renderDraftConflicts;
    void this.loadWritingDraftConflicts(activeWritingDraft, { sessionEpoch: renderSessionEpoch });
    if (hasLocalDraftInput) queueDraft();
  }

  async renderAiChat(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "AI 对话"), node("p", { text: "标题由首次完整对话自动生成，可手动修改；仅发送你明确选择的材料，并可调用法律检索工具。" })]);
    const layout = node("div", { className: "workspace-grid chat-grid" });
    const conversationsColumn = node("div", { className: "workspace-column" });
    const chatColumn = node("div", { className: "workspace-column" });
    layout.append(conversationsColumn, chatColumn);
    main.append(title, layout);

    const conversationsPanel = panel("会话");
    const createForm = node("form", { className: "inline-form" });
    const createButton = formButton("新建会话", "button secondary");
    createForm.append(createButton);
    const conversationStatus = statusBox();
    const conversationList = node("div", { className: "conversation-list" }, [emptyState("正在加载会话…")]);
    conversationsPanel.append(createForm, conversationStatus, conversationList);
    conversationsColumn.append(conversationsPanel);

    const chatPanel = panel("对话", [], "panel chat-panel");
    const selectedTitle = node("div", { className: "selected-conversation-title" }, [node("strong", { text: "请选择或新建会话" })]);
    const renameForm = node("form", { className: "inline-form" });
    const renameInput = node("input", { type: "text", placeholder: "修改会话标题" });
    const renameButton = formButton("修改标题", "button subtle");
    renameForm.append(renameInput, renameButton);
    const providerSelect = node("select", { required: true });
    appendOption(providerSelect, "", "选择模型服务");
    const modelInput = node("select", { required: true, ariaLabel: "AI 对话模型" });
    appendOption(modelInput, "", "选择 Provider 后载入模型");
    const materialHost = node("div", { className: "ai-material-host" }, [emptyState("正在加载可用材料…")]);
    let materialPicker = null;
    let queueConversationContext = () => {};
    let chatRangePicker = null;
    const attachmentPicker = this.renderAiAttachmentPicker({ onChange: () => {
      chatRangePicker?.syncSources();
      void queueConversationContext();
    } });
    chatRangePicker = this.renderContextRangePicker({
      title: "会话材料与附件范围",
      getMaterials: () => materialPicker?.values?.() || [],
      getAttachmentIds: () => attachmentPicker.attachmentIds?.() || [],
      onChanged: () => {
        void queueConversationContext();
      }
    });
    const contextStatus = statusBox("会话材料由本机服务保存。", "muted");
    const contextManifest = node("div", { className: "conversation-context-manifest" }, [emptyState("选择会话后显示本次发送清单。")]);
    const chatContextEstimate = node("div", { className: "context-estimate" }, [emptyState("发送前会显示本次采用的会话材料、历史范围及上下文预算。")]);
    const messages = node("div", { className: "message-list", ariaLive: "polite" }, [emptyState("选择或新建会话。")]);
    const composer = node("form", { className: "composer" });
    const messageInput = node("textarea", { rows: 5, placeholder: "输入问题；助手可调用本地法律检索工具查找相关法条。", required: true });
    const sendButton = formButton("发送", "button primary");
    const cancelButton = button("取消生成", async () => {
      if (!this.state.currentChatRunId) return;
      cancelButton.disabled = true;
      try {
        await this.api.cancelAiRun(this.state.currentChatRunId);
        setStatus(chatStatus, "已请求取消生成；后台会继续保存最终状态。", "warning");
      } catch (error) {
        setStatus(chatStatus, apiErrorMessage(error), "danger");
        cancelButton.disabled = false;
      }
    }, "button subtle");
    cancelButton.disabled = true;
    const chatStatus = statusBox();
    composer.append(labelFor("消息", messageInput), node("div", { className: "button-row" }, [providerSelect, modelInput, sendButton, cancelButton]), chatStatus);
    chatPanel.append(selectedTitle, renameForm, labelFor("材料上下文", materialHost), attachmentPicker, chatRangePicker, contextStatus, contextManifest, chatContextEstimate, messages, composer);
    chatColumn.append(chatPanel);

    const renderChatMessages = (items) => {
      const list = Array.isArray(items) ? items : [];
      if (!list.length) {
        replaceChildren(messages, [emptyState("还没有消息。")]);
        return;
      }
      replaceChildren(messages, list.map((message) => {
        const isUser = textValue(message?.role) === "user";
        const content = node("div", { className: "message-content" });
        if (isUser) content.textContent = textValue(message?.content);
        else renderRenderedContent(content, message?.html, textValue(message?.content));
        return node("article", { className: `chat-message ${isUser ? "user" : "assistant"}` }, [node("span", { className: "message-role", text: isUser ? "我" : "助手" }), content, message?.run_id ? node("span", { className: "muted small", text: `任务：${message.run_id}` }) : null]);
      }));
      messages.lastElementChild?.scrollIntoView?.({ block: "nearest" });
    };

    let contextWrite = Promise.resolve();
    let contextSaveError = null;
    let contextPrepareGeneration = 0;
    let preparedContext = null;
    const currentConversationId = () => textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
    const renderContextManifest = (manifest, message = "") => {
      const source = manifest?.context || manifest || {};
      const materialItems = Array.isArray(source.materials) ? source.materials : [];
      const attachmentItems = Array.isArray(source.attachments)
        ? source.attachments
        : Array.isArray(source.attachment_ids) ? source.attachment_ids.map((id) => ({ id })) : [];
      const rows = [];
      for (const item of materialItems) {
        const name = textValue(field(item, ["name", "material_name", "materialName"]), textValue(field(item, ["id", "material_id", "materialId"]), "未命名材料"));
        const sourceLabel = textValue(field(item, ["source"]), "待核验") === "original" ? "原文" : "脱敏版";
        rows.push(node("li", { text: `${name} · ${sourceLabel}` }));
      }
      for (const item of attachmentItems) {
        const name = textValue(field(item, ["name", "filename"]), textValue(field(item, ["id", "attachment_id", "attachmentId"]), "已保存附件"));
        rows.push(node("li", { text: `${name} · 附件` }));
      }
      const ranges = normalizedDraftContextRanges({ context_ranges: source.context_ranges ?? source.contextRanges });
      for (const range of ranges) {
        const label = range.source_kind === "material"
          ? `材料 ${textValue(field(materialItems.find((item) => textValue(field(item, ["id", "material_id", "materialId"])) === range.source_id), ["name", "material_name", "materialName"]), range.source_id)}`
          : `附件 ${textValue(field(attachmentItems.find((item) => textValue(field(item, ["id", "attachment_id", "attachmentId"])) === range.source_id), ["name", "filename"]), range.source_id)}`;
        const detail = range.mode === "all" ? "全部" : `${range.mode === "pages" ? "页" : "段落"} ${range.ranges.map((item) => item.start === item.end ? item.start : `${item.start}-${item.end}`).join("、")}`;
        rows.push(node("li", { text: `${label} · ${detail}` }));
      }
      replaceChildren(contextManifest, [
        heading(3, "发送前服务器最终清单"),
        message ? node("p", { className: "muted small", text: message }) : null,
        rows.length ? node("ul", { className: "context-manifest-list" }, rows) : node("p", { className: "muted small", text: "本轮不发送材料或附件。" })
      ]);
    };
    const renderConversationContext = (conversation) => {
      const context = conversation || {};
      const selectedValues = Array.isArray(context.materials) ? context.materials : [];
      const page = this.state.aiMaterialsPage;
      materialPicker = this.renderAiMaterialPicker(this.state.aiMaterials, {
        title: "会话材料（取消勾选会立即从后续轮次移除）",
        selectedValues,
        hasMore: Boolean(page.nextCursor),
        total: page.total,
        corruptCount: page.corruptCount,
        errorMessage: page.error,
        onLoadMore: async (preservedValues) => {
          const attachmentIds = attachmentPicker.attachmentIds?.() || [];
          const current = { ...(this.state.selectedConversation || context), materials: preservedValues, attachment_ids: attachmentIds, context_ranges: chatRangePicker?.contextRanges().ranges || [] };
          await this.loadAiMaterials({ append: true });
          renderConversationContext(current);
          const selectedProvider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
          this.applyMaterialTrust(materialPicker, selectedProvider);
        },
        onChange: () => {
          chatRangePicker?.syncSources();
          void queueConversationContext();
        }
      });
      replaceChildren(materialHost, [materialPicker]);
      attachmentPicker.setAttachments((Array.isArray(context.attachment_ids) ? context.attachment_ids : []).map((id) => {
        const existing = this.state.aiAttachments.find((attachment) => attachment.id === id);
        return existing || { id };
      }));
      chatRangePicker.setContextRanges(context.context_ranges ?? context.contextRanges);
      renderContextManifest(context, "正在等待本机服务按当前模型核验。");
    };
    const prepareConversationContext = async ({ announce = false, waitForContext = true } = {}) => {
      if (waitForContext) await contextWrite;
      if (contextSaveError) return null;
      const conversationId = currentConversationId();
      const providerId = providerSelect.value;
      const model = modelInput.value;
      if (!conversationId || !providerId || !model) return null;
      const expectedRevision = conversationContextRevision(this.state.selectedConversation);
      const generation = ++contextPrepareGeneration;
      if (announce) setStatus(contextStatus, "正在核验发送材料清单…", "info");
      try {
        const response = await this.api.prepareAiConversationContext(conversationId, {
          provider_id: providerId,
          model,
          expected_revision: expectedRevision
        });
        if (generation !== contextPrepareGeneration || conversationId !== currentConversationId()) return null;
        const manifest = response?.manifest || response?.context_manifest || response;
        const revision = conversationContextRevision(response, conversationContextRevision(manifest, expectedRevision));
        const preparationHash = textValue(field(response, ["preparation_hash", "preparationHash"]));
        if (!Number.isSafeInteger(revision) || revision < 0 || !preparationHash) throw new ApiError("invalid_response", false, 200);
        preparedContext = { conversationId, providerId, model, revision, preparationHash, manifest };
        renderContextManifest(manifest, "此清单由本机服务核验；发送时会再次校验版本和材料状态。");
        setStatus(contextStatus, "发送材料清单已由本机服务核验。", "success");
        return preparedContext;
      } catch (error) {
        if (generation === contextPrepareGeneration) {
          preparedContext = null;
          setStatus(contextStatus, `无法核验发送清单：${apiErrorMessage(error)}`, "danger");
        }
        return null;
      }
    };
    queueConversationContext = () => {
      const conversationId = currentConversationId();
      if (!conversationId || !materialPicker) return Promise.resolve();
      preparedContext = null;
      contextPrepareGeneration += 1;
      contextSaveError = null;
      setStatus(contextStatus, "会话材料或范围已变更；原准备结果已失效，正在保存清单…", "warning");
      const initialScope = chatRangePicker.contextRanges();
      if (initialScope.error) {
        const error = new ApiError("context_scope_invalid", false, 400);
        contextSaveError = error;
        setStatus(contextStatus, `会话材料未保存：${initialScope.error}`, "danger");
        return Promise.resolve();
      }
      contextWrite = contextWrite.catch(() => {}).then(async () => {
        const activeId = currentConversationId();
        if (!activeId || activeId !== conversationId) return;
        const scope = chatRangePicker.contextRanges();
        if (scope.error) throw new ApiError("context_scope_invalid", false, 400);
        const expectedRevision = conversationContextRevision(this.state.selectedConversation);
        setStatus(contextStatus, "正在保存会话材料清单…", "info");
        const response = await this.api.updateAiConversationContext(activeId, {
          expected_revision: expectedRevision,
          materials: materialPicker.values(),
          attachment_ids: attachmentPicker.attachmentIds(),
          context_ranges: scope.ranges
        });
        const conversation = response?.conversation || response;
        if (activeId !== currentConversationId()) return;
        this.state.selectedConversation = conversation;
        const cancelled = Array.isArray(response?.cancelled_run_ids) ? response.cancelled_run_ids.length : 0;
        setStatus(contextStatus, cancelled ? `会话材料清单已保存；已停止 ${cancelled} 个未完成任务。已发送的内容无法撤回。` : "会话材料清单已保存。", "success");
        void prepareConversationContext({ waitForContext: false });
      }).catch((error) => {
        contextSaveError = error;
        preparedContext = null;
        setStatus(contextStatus, `会话材料未保存：${apiErrorMessage(error)}`, "danger");
      });
      return contextWrite;
    };

    const openConversation = async (id) => {
      if (!id) return;
      try {
        // A failed write or prepared manifest belongs only to the conversation
        // it was made for.  It must not block a newly selected conversation.
        contextSaveError = null;
        preparedContext = null;
        contextPrepareGeneration += 1;
        const response = await this.api.getAiConversation(id);
        const conversation = response?.conversation || response;
        this.state.selectedConversation = conversation;
        const conversationTitle = textValue(field(conversation, ["title", "name"]), "未命名会话");
        selectedTitle.firstElementChild.textContent = conversationTitle;
        renameInput.value = conversationTitle;
        renderChatMessages(parseJsonList(conversation?.messages));
        renderConversationContext(conversation);
        const selectedProvider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
        this.applyMaterialTrust(materialPicker, selectedProvider);
        this.state.currentChatRunId = "";
        for (const item of conversationList.querySelectorAll(".conversation-item")) item.classList.toggle("active", item.dataset.conversationId === id);
        void prepareConversationContext();
      } catch (error) {
        setStatus(chatStatus, apiErrorMessage(error), "danger");
      }
    };
    const loadConversationList = async (preferredId = "", { append = false } = {}) => {
      try {
        const previous = this.state.conversationPage;
        const cursor = append ? textValue(previous.nextCursor) : "";
        if (append && !cursor) return;
        const response = await this.api.listAiConversations({ limit: 20, cursor });
        const page = normalizeCursorPage(response, ["conversations"]);
        const conversations = append ? appendUniqueById(this.state.conversations, page.items) : page.items;
        this.state.conversations = conversations;
        this.state.conversationPage = { nextCursor: page.nextCursor, total: page.total, corruptCount: page.corruptCount, loaded: true };
        if (!this.state.conversations.length) {
          replaceChildren(conversationList, [emptyState("还没有会话，点击“新建会话”。")]);
          this.state.selectedConversation = null;
          selectedTitle.firstElementChild.textContent = "请选择或新建会话";
          replaceChildren(messages, [emptyState("选择或新建会话。")] );
          return;
        }
        const activeId = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
        const selectedId = preferredId || activeId || textValue(field(this.state.conversations[0], ["id", "conversationId"]));
        const rows = this.state.conversations.map((conversation) => {
          const id = textValue(field(conversation, ["id", "conversationId"]));
          const item = button(textValue(field(conversation, ["title", "name"]), "未命名会话"), () => openConversation(id), `conversation-item${id === selectedId ? " active" : ""}`);
          item.dataset.conversationId = id;
          return item;
        });
        if (this.state.conversationPage.corruptCount > 0) rows.unshift(statusBox(`检测到 ${this.state.conversationPage.corruptCount} 个损坏会话记录，未显示。`, "warning"));
        if (this.state.conversationPage.nextCursor) rows.push(button("加载更多会话", () => loadConversationList(selectedId, { append: true }), "button subtle"));
        replaceChildren(conversationList, rows);
        if (!append || !activeId) await openConversation(selectedId);
      } catch (error) {
        replaceChildren(conversationList, [statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      createButton.disabled = true;
      try {
        const response = await this.api.createAiConversation({});
        const conversation = response?.conversation || response;
        setStatus(conversationStatus, "会话已创建，首次完整回答后自动命名。", "success");
        await loadConversationList(textValue(field(conversation, ["id", "conversationId"])));
      } catch (error) {
        setStatus(conversationStatus, apiErrorMessage(error), "danger");
      } finally {
        createButton.disabled = false;
      }
    });
    renameForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const id = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
      const value = renameInput.value.trim();
      if (!id || !value) return;
      renameButton.disabled = true;
      try {
        const response = await this.api.renameAiConversation(id, value);
        this.state.selectedConversation = response?.conversation || response;
        selectedTitle.firstElementChild.textContent = value;
        await loadConversationList(id);
        setStatus(conversationStatus, "会话标题已修改。", "success");
      } catch (error) {
        setStatus(conversationStatus, apiErrorMessage(error), "danger");
      } finally {
        renameButton.disabled = false;
      }
    });
    const syncChatModel = ({ preserveModel = false } = {}) => {
      const provider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
      const previous = preserveModel ? modelInput.value : "";
      const models = providerModelIds(provider);
      const configured = aiDefaultSelection(this.state.aiDefaults, "chat");
      const preferred = preserveModel && models.includes(previous)
        ? previous
        : provider && textValue(field(provider, ["id"])) === configured.providerId && models.includes(configured.model)
          ? configured.model
          : models[0] || "";
      replaceChildren(modelInput);
      appendOption(modelInput, "", provider ? "选择模型" : "选择 Provider 后载入模型");
      for (const model of models) appendOption(modelInput, model, model, model === preferred);
      modelInput.value = preferred;
      modelInput.disabled = !provider || !models.length;
      modelInput.title = models.length ? "可选择该 Provider 已启用的模型" : "该 Provider 尚未启用模型";
      this.applyMaterialTrust(materialPicker, provider);
    };
    providerSelect.addEventListener("change", () => {
      syncChatModel();
      void prepareConversationContext();
    });
    modelInput.addEventListener("change", () => void prepareConversationContext());
    const finishChatRun = async (next, conversationId) => {
      if (currentConversationId() === conversationId) {
        setStatus(chatStatus, next.status === "completed" ? "回答已生成并保存。" : `任务状态：${aiRunStatusLabel(next.status)}`, next.status === "completed" ? "success" : "warning");
        cancelButton.disabled = true;
        this.state.currentChatRunId = "";
        await openConversation(conversationId);
      }
      await loadConversationList(currentConversationId());
    };
    composer.addEventListener("submit", async (event) => {
      event.preventDefault();
      const conversationId = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
      const provider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
      const prompt = messageInput.value.trim();
      if (!conversationId) {
        setStatus(chatStatus, "请先新建或选择一个会话。", "warning");
        return;
      }
      if (!provider || !providerSelect.value) {
        setStatus(chatStatus, "请先选择已配置的模型服务。", "warning");
        return;
      }
      if (!prompt) return;
      const model = modelInput.value.trim();
      if (!model) {
        setStatus(chatStatus, "所选模型服务尚未选择模型。", "warning");
        return;
      }
      if (!providerModelIds(provider).includes(model)) {
        setStatus(chatStatus, "所选模型未启用，请前往设置勾选后重试。", "warning");
        return;
      }
      sendButton.disabled = true;
      try {
        const prepared = await prepareConversationContext({ announce: true });
        if (!prepared || prepared.conversationId !== conversationId || prepared.providerId !== providerSelect.value || prepared.model !== model) {
          setStatus(chatStatus, "发送前材料清单尚未通过本机服务核验。", "warning");
          return;
        }
        const payload = { kind: AI_RUN_KINDS.chat, prompt, provider_id: providerSelect.value, model, conversation_id: conversationId, context_revision: prepared.revision, context_preparation_hash: prepared.preparationHash };
        const contextEstimate = await this.preflightAiContext(payload, chatContextEstimate, chatStatus);
        if (!contextEstimate) return;
        payload.context_plan_hash = contextEstimate.planHash;
        const current = parseJsonList(this.state.selectedConversation?.messages);
        messageInput.value = "";
        renderChatMessages([...current, { role: "user", content: prompt }, { role: "assistant", content: "正在检索法律依据并生成回答…" }]);
        cancelButton.disabled = false;
        const run = await this.createAiRun(payload, {
          page: "chat",
          status: chatStatus,
          onUpdate: (next) => {
            if (currentConversationId() !== conversationId || this.state.pageRunIds.chat !== next.id) return;
            const answer = next.content || "正在检索法律依据并生成回答…";
            renderChatMessages([...current, { role: "user", content: prompt }, { role: "assistant", content: answer, run_id: next.id }]);
          },
          onDone: (next) => finishChatRun(next, conversationId)
        });
        this.state.currentChatRunId = run.id;
      } catch (error) {
        setStatus(chatStatus, apiErrorMessage(error), "danger");
      } finally {
        sendButton.disabled = false;
        if (!this.state.currentChatRunId) cancelButton.disabled = true;
      }
    });
    await this.loadProvidersInto(providerSelect, "chat");
    syncChatModel({ preserveModel: true });
    await this.loadAiMaterials();
    await loadConversationList();
    try {
      const activeRuns = normalizeAiRunList(await this.api.listAiRuns("chat", { limit: 50 }));
      const selectedId = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
      const active = activeRuns.find((run) => !aiRunIsTerminal(run) && textValue(field(run, ["conversation_id", "conversationId"])) === selectedId);
      if (active) {
        this.selectPageRun("chat", active);
        this.state.currentChatRunId = active.id;
        setStatus(chatStatus, `${aiRunKindLabel(active.kind)}：${aiRunStatusLabel(active.status)}${active.stage ? ` · ${pipelineStageLabel(active.stage)}` : ""} · ${aiRunProgressText(active)}`, "info");
        this.pollAiRun(active.id, {
          status: chatStatus,
          onUpdate: (next) => {
            if (currentConversationId() !== selectedId || this.state.pageRunIds.chat !== next.id) return;
            setStatus(chatStatus, `${aiRunKindLabel(next.kind)}：${aiRunStatusLabel(next.status)}${next.stage ? ` · ${pipelineStageLabel(next.stage)}` : ""} · ${aiRunProgressText(next)}`, "info");
          },
          onDone: (next) => finishChatRun(next, selectedId)
        });
      }
    } catch {
      // History remains usable when the optional recovery check is unavailable.
    }
  }

  async renderSettings(main) {
    const title = node("div", { className: "page-title" }, [heading(1, "设置"), node("p", { text: "管理模型服务、MCP 客户端和本机运行状态。" })]);
    const layout = node("div", { className: "settings-grid" });
    const providerSection = panel("模型服务", [], "panel settings-panel");
    const mcpSection = panel("MCP 客户端", [], "panel settings-panel");
    const statusSection = panel("运行状态", [], "panel settings-panel");
    layout.append(providerSection, mcpSection, statusSection);
    mcpSection.append(node("p", { className: "muted small", text: "MCP 提供公开法律与案例检索工具 7 个；隐私工作区工具 10 个。公开工具只返回可发布法律资源，隐私工具仍按客户端分组权限工作。" }));
    main.append(title, layout);
    await this.renderAiProviders(providerSection);
    await this.renderMcpClients(mcpSection);
    this.renderRuntimeStatus(statusSection);
  }

  async renderAiProviders(target) {
    const list = node("div", { className: "provider-list" }, [emptyState("正在加载模型服务…")]);
    const form = node("form", { className: "provider-form ai-provider-form" });
    const id = node("input", { type: "text", placeholder: "新建时留空；编辑已有配置时填写" });
    const preset = node("select", { required: true });
    const presetOptions = AI_PROVIDER_PRESETS;
    for (const item of presetOptions) appendOption(preset, item.preset, item.name);
    const name = node("input", { type: "text", placeholder: "服务名称", required: true });
    const baseUrl = node("input", { type: "url", placeholder: "https://…", required: true });
    const apiKey = node("input", { type: "password", placeholder: "留空表示不修改密钥", autocomplete: "new-password" });
    const modelSearch = node("input", { type: "search", placeholder: "筛选模型列表" });
    const fetchModels = button("联网获取模型列表", async () => {
      fetchModels.disabled = true;
      setStatus(status, "正在连接模型服务并获取模型列表…");
      try {
        const response = await this.api.discoverAiModels({ provider_id: id.value.trim() || undefined, preset: preset.value, base_url: baseUrl.value.trim(), api_key: apiKey.value || undefined });
        const models = Array.isArray(response?.models) ? response.models : [];
        modelItems = models;
        renderModels();
        setStatus(status, models.length ? `已获取 ${models.length} 个模型，请勾选启用模型。` : "服务未返回可用模型。", models.length ? "success" : "warning");
      } catch (error) {
        setStatus(status, `获取模型列表失败：${apiErrorMessage(error)}`, "danger");
      } finally {
        fetchModels.disabled = false;
      }
    }, "button secondary");
    const modelHost = node("div", { className: "model-selection" }, [emptyState("输入 API Key 后点击联网获取模型列表。")]);
    let modelItems = [];
    let enabledModels = new Set();
    let modelCapabilities = new Map();
    const capabilityInputPresent = (value) => {
      const source = value && typeof value === "object" ? value : {};
      return Boolean(textValue(source.contextWindowTokens ?? source.context_window_tokens)
        || textValue(source.maxOutputTokens ?? source.max_output_tokens)
        || source.supportsToolsPresent === true
        || source.supportsStructuredOutputPresent === true
        || source.supportsVisionPresent === true
        || Object.hasOwn(source, "supports_tools")
        || Object.hasOwn(source, "supportsTools")
        || Object.hasOwn(source, "supports_structured_output")
        || Object.hasOwn(source, "supportsStructuredOutput")
        || Object.hasOwn(source, "supports_vision")
        || Object.hasOwn(source, "supportsVision"));
    };
    const editableCapabilities = (value) => {
      const source = value && typeof value === "object" ? value : {};
      const declared = (names, presenceName) => ({
        value: field(source, names) === true ? true : field(source, names) === false ? false : null,
        present: source[presenceName] === true
      });
      const tools = declared(["supports_tools", "supportsTools"], "supportsToolsPresent");
      const structured = declared(["supports_structured_output", "supportsStructuredOutput"], "supportsStructuredOutputPresent");
      const vision = declared(["supports_vision", "supportsVision"], "supportsVisionPresent");
      return {
        contextWindowTokens: textValue(field(source, ["context_window_tokens", "contextWindowTokens"])),
        maxOutputTokens: textValue(field(source, ["max_output_tokens", "maxOutputTokens"])),
        supportsTools: tools.value,
        supportsToolsPresent: tools.present,
        supportsStructuredOutput: structured.value,
        supportsStructuredOutputPresent: structured.present,
        supportsVision: vision.value,
        supportsVisionPresent: vision.present
      };
    };
    const restoreModelCapabilities = (value) => {
      const entries = value && typeof value === "object" && !Array.isArray(value) ? Object.entries(value) : [];
      modelCapabilities = new Map(entries.map(([modelId, capability]) => [textValue(modelId), editableCapabilities(capability)]).filter(([modelId]) => modelId));
    };
    const capabilityDeclarationSelect = (modelId, label, value) => {
      const select = node("select", { ariaLabel: `${modelId}${label}能力声明` });
      appendOption(select, "unknown", "未知（未声明）", value === null);
      appendOption(select, "supported", "支持（配置声明）", value === true);
      appendOption(select, "unsupported", "不支持（明确阻断）", value === false);
      select.value = value === true ? "supported" : value === false ? "unsupported" : "unknown";
      return select;
    };
    const declarationValue = (select) => select.value === "supported" ? true : select.value === "unsupported" ? false : null;
    const renderModels = () => {
      const filter = modelSearch.value.trim().toLowerCase();
      const visible = modelItems.filter((model) => {
        const modelId = textValue(field(model, ["id", "name"]));
        return !filter || modelId.toLowerCase().includes(filter);
      });
      if (!visible.length) {
        replaceChildren(modelHost, [emptyState(modelItems.length ? "没有符合筛选条件的模型。" : "尚未获取模型列表。")]);
        return;
      }
      replaceChildren(modelHost, visible.map((model) => {
        const modelId = textValue(field(model, ["id", "name"]));
        let capability = editableCapabilities(modelCapabilities.get(modelId) || {});
        const checked = node("input", { type: "checkbox", checked: enabledModels.has(modelId), ariaLabel: `启用${modelId}` });
        checked.dataset.modelId = modelId;
        checked.addEventListener("change", () => { if (checked.checked) enabledModels.add(modelId); else enabledModels.delete(modelId); });
        const contextWindow = node("input", { type: "number", min: "1", step: "1", value: capability.contextWindowTokens, placeholder: "上下文窗口 tokens" });
        const maxOutput = node("input", { type: "number", min: "1", step: "1", value: capability.maxOutputTokens, placeholder: "最大输出 tokens" });
        const tools = capabilityDeclarationSelect(modelId, "工具调用", capability.supportsTools);
        const structured = capabilityDeclarationSelect(modelId, "结构化输出", capability.supportsStructuredOutput);
        const vision = capabilityDeclarationSelect(modelId, "视觉", capability.supportsVision);
        const persistCapabilities = (changedDeclaration = "") => {
          const next = {
            contextWindowTokens: contextWindow.value,
            maxOutputTokens: maxOutput.value,
            supportsTools: declarationValue(tools),
            supportsToolsPresent: changedDeclaration === "tools" ? true : capability.supportsToolsPresent,
            supportsStructuredOutput: declarationValue(structured),
            supportsStructuredOutputPresent: changedDeclaration === "structured" ? true : capability.supportsStructuredOutputPresent,
            supportsVision: declarationValue(vision),
            supportsVisionPresent: changedDeclaration === "vision" ? true : capability.supportsVisionPresent
          };
          capability = next;
          if (capabilityInputPresent(next)) modelCapabilities.set(modelId, next); else modelCapabilities.delete(modelId);
        };
        contextWindow.addEventListener("input", persistCapabilities);
        maxOutput.addEventListener("input", persistCapabilities);
        tools.addEventListener("change", () => persistCapabilities("tools"));
        structured.addEventListener("change", () => persistCapabilities("structured"));
        vision.addEventListener("change", () => persistCapabilities("vision"));
        const hasKnownCapability = Boolean(capability.contextWindowTokens || capability.maxOutputTokens
          || capability.supportsTools !== null || capability.supportsStructuredOutput !== null || capability.supportsVision !== null);
        const explicitBlocks = [
          capability.supportsTools === false ? "工具调用" : "",
          capability.supportsStructuredOutput === false ? "结构化输出" : "",
          capability.supportsVision === false ? "视觉附件" : ""
        ].filter(Boolean);
        const option = node("div", { className: "model-option" }, [
          node("label", { className: "checkbox-label" }, [checked, node("span", { text: modelId }), node("span", { className: "muted small", text: textValue(field(model, ["owned_by", "description"])) })]),
          node("details", { className: "model-capability-config", open: hasKnownCapability }, [
            node("summary", { text: "配置上下文能力（可选）" }),
            node("p", { className: "muted small", text: "未配置容量时按输入 16k、输出 4k 保守预检；容量需成对填写。能力状态可分别保留未知、支持声明或明确不支持。支持只是配置声明，不等于已对服务实测；明确不支持会在提交前阻断对应功能，需人工确认后才能更正。" }),
            explicitBlocks.length ? statusBox(`已明确阻断：${explicitBlocks.join("、")}。保持阻断，直到你在上方作出明确更正并保存。`, "warning") : null,
            node("div", { className: "model-capability-fields" }, [fieldInput("上下文窗口", contextWindow), fieldInput("最大输出", maxOutput)]),
            node("div", { className: "model-capability-flags" }, [labelFor("工具调用", tools), labelFor("结构化输出", structured), labelFor("视觉", vision)])
          ])
        ]);
        return option;
      }));
    };
    modelSearch.addEventListener("input", renderModels);
    const defaultModel = node("input", { type: "text", placeholder: "默认模型 ID（可从启用列表中选择）", required: true });
    const trustRaw = node("input", { type: "checkbox", checked: true, ariaLabel: "允许发送原文" });
    const privateNetwork = node("input", { type: "checkbox", ariaLabel: "允许访问私有网络" });
    const save = formButton("保存模型服务", "button primary");
    const status = statusBox();
    const trustNotice = statusBox("国内官方预设默认信任原文；自定义服务需明确确认，其他服务默认发送脱敏材料。", "muted");
    form.append(fieldInput("ID（可选）", id), fieldSelect("供应商预设", { }), fieldInput("名称", name), fieldInput("Base URL", baseUrl), fieldInput("API Key", apiKey), node("div", { className: "model-fetch-row" }, [modelSearch, fetchModels]), modelHost, fieldInput("默认模型", defaultModel), labelFor("允许发送原文（请确认服务归属）", trustRaw), labelFor("允许访问私有网络（默认关闭）", privateNetwork), trustNotice, save, status);
    const presetLabel = form.children[1];
    presetLabel.replaceChildren(node("span", { text: "供应商预设" }), preset);
    const setPreset = () => {
      const selected = presetOptions.find((item) => item.preset === preset.value) || presetOptions[presetOptions.length - 1];
      name.value = selected.name;
      baseUrl.value = selected.base_url;
      trustRaw.checked = selected.domestic === true;
    };
    const rejudgeTrustFromBaseUrl = () => {
      const matched = providerPresetForBaseUrl(baseUrl.value);
      if (matched) {
        preset.value = matched.preset;
        trustRaw.checked = matched.domestic === true;
        return;
      }
      preset.value = "custom";
      trustRaw.checked = false;
    };
    preset.addEventListener("change", setPreset);
    baseUrl.addEventListener("change", rejudgeTrustFromBaseUrl);
    setPreset();
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      // Re-evaluate the endpoint even when the browser submits before the
      // input's change event (for example via keyboard).
      rejudgeTrustFromBaseUrl();
      const selectedModels = [...enabledModels];
      if (!defaultModel.value.trim() && selectedModels.length) defaultModel.value = selectedModels[0];
      if (!defaultModel.value.trim()) {
        setStatus(status, "请先联网获取并启用至少一个模型，或填写默认模型 ID。", "warning");
        return;
      }
      const configuredModels = selectedModels.length ? selectedModels : [defaultModel.value.trim()];
      const serializedCapabilities = {};
      const invalidCapabilityModels = [];
      for (const modelId of configuredModels) {
        const capability = modelCapabilities.get(modelId);
        if (!capabilityInputPresent(capability)) continue;
        const payload = modelCapabilitiesPayload(capability);
        if (!payload) invalidCapabilityModels.push(modelId);
        else serializedCapabilities[modelId] = payload;
      }
      if (invalidCapabilityModels.length) {
        setStatus(status, `模型能力配置不完整：${invalidCapabilityModels.join("、")}。请同时填写上下文窗口和最大输出，且前者必须更大。`, "warning");
        return;
      }
      save.disabled = true;
      try {
        const body = { id: id.value.trim() || undefined, name: name.value.trim(), preset: preset.value, base_url: baseUrl.value.trim(), enabled_models: configuredModels, model: defaultModel.value.trim(), trust_raw: trustRaw.checked, allow_private_network: privateNetwork.checked, model_capabilities: serializedCapabilities };
        if (apiKey.value) body.api_key = apiKey.value;
        const response = await this.api.saveAiProvider(body);
        apiKey.value = "";
        setStatus(status, "模型服务已保存。", "success");
        await refreshList(response?.provider?.id || response?.id || id.value.trim());
        await loadDefaults();
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        save.disabled = false;
      }
    });
    target.append(list, form);

    const defaultsPanel = node("div", { className: "ai-defaults-panel" });
    const defaultSelectors = {};
    for (const role of ["chat", "redaction", "writing", "ocr"]) {
      const select = node("select", { ariaLabel: `${role}默认模型` });
      defaultSelectors[role] = select;
      defaultsPanel.append(labelFor({ chat: "默认对话模型", redaction: "默认脱敏模型", writing: "默认写作模型", ocr: "OCR 模型" }[role], select));
    }
    const saveDefaults = button("保存默认模型设置", async () => {
      saveDefaults.disabled = true;
      try {
        const defaults = Object.fromEntries(Object.entries(defaultSelectors).map(([role, select]) => {
          const [providerId, ...rest] = select.value.split("::");
          return [role, { provider_id: providerId || "", model: rest.join("::") || "" }];
        }));
        await this.api.updateAiDefaults(defaults);
        this.state.aiDefaults = defaults;
        setStatus(defaultsStatus, "默认模型设置已保存。", "success");
      } catch (error) {
        setStatus(defaultsStatus, apiErrorMessage(error), "danger");
      } finally {
        saveDefaults.disabled = false;
      }
    }, "button secondary");
    const defaultsStatus = statusBox();
    target.append(heading(3, "默认模型与 OCR"), defaultsPanel, saveDefaults, defaultsStatus);

    const loadDefaults = async () => {
      try {
        const response = await this.api.listAiProviders();
        const providers = Array.isArray(response?.providers) ? response.providers : this.state.providers;
        this.state.providers = providers;
        this.state.aiDefaults = response?.defaults || this.state.aiDefaults || {};
        for (const select of Object.values(defaultSelectors)) {
          replaceChildren(select, [node("option", { value: "", text: "未设置" })]);
          for (const provider of providers) for (const modelId of providerModelIds(provider)) appendOption(select, `${textValue(provider.id)}::${modelId}`, `${textValue(provider.name, "服务")} · ${modelId}`);
        }
        for (const role of Object.keys(defaultSelectors)) {
          const value = this.state.aiDefaults?.[role];
          const providerId = textValue(field(value, ["provider_id", "providerId"]));
          const modelId = textValue(field(value, ["model"]));
          if (providerId && modelId) defaultSelectors[role].value = `${providerId}::${modelId}`;
        }
      } catch (error) {
        setStatus(defaultsStatus, apiErrorMessage(error), "danger");
      }
    };
    const refreshList = async (selectId = "") => {
      try {
        const response = await this.api.listAiProviders();
        const providers = Array.isArray(response?.providers) ? response.providers : [];
        this.state.providers = providers;
        this.state.aiDefaults = response?.defaults || this.state.aiDefaults || {};
        const presets = Array.isArray(response?.presets) && response.presets.length ? response.presets : presetOptions;
        const declarationSummary = (provider) => {
          const model = textValue(provider.model);
          const metadata = field(provider, ["capability_metadata", "capabilityMetadata"]);
          const declaration = metadata && typeof metadata === "object" ? metadata[model] : null;
          if (!declaration || typeof declaration !== "object") return "模型能力未知（未声明）";
          const state = textValue(field(declaration, ["verification_state", "verificationState"]), "unknown");
          const declaredAt = Number(field(declaration, ["declared_at", "declaredAt"]));
          const when = Number.isSafeInteger(declaredAt) && declaredAt > 0
            ? new Date(declaredAt * 1000).toLocaleString("zh-CN", { hour12: false }) : "时间未记录";
          const bindingChanged = Boolean(field(declaration, ["current_config_binding", "currentConfigBinding"])) || declaration.needs_review === true;
          if (state === "declared") return `能力为配置声明（${when}，${bindingChanged ? "配置绑定待复核" : "绑定当前配置"}；未实测）`;
          if (state === "legacy") return "能力来自旧配置，待人工复核";
          return "模型能力未知（未声明）";
        };
        replaceChildren(list, providers.length ? providers.map((provider) => {
          const pid = textValue(provider.id);
          const edit = button("编辑", () => {
            id.value = pid; name.value = textValue(provider.name); baseUrl.value = textValue(field(provider, ["base_url", "baseUrl"])); preset.value = textValue(provider.preset, "custom"); apiKey.value = ""; privateNetwork.checked = provider.allow_private_network === true; trustRaw.checked = provider.trust_raw === true; enabledModels = new Set(providerModelIds(provider)); defaultModel.value = textValue(provider.model) || [...enabledModels][0] || ""; modelItems = [...enabledModels].map((value) => ({ id: value })); restoreModelCapabilities(field(provider, ["model_capabilities", "modelCapabilities"])); renderModels(); }, "button subtle");
          const test = button("连接测试", async () => {
            test.disabled = true;
            try { await this.api.testAiProvider({ provider_id: pid, model: textValue(provider.model) }); setStatus(status, `${textValue(provider.name, "模型服务")} 连接测试成功。`, "success"); } catch (error) { setStatus(status, apiErrorMessage(error), "danger"); } finally { test.disabled = false; }
          }, "button subtle");
          const capabilityMap = field(provider, ["model_capabilities", "modelCapabilities"]);
          const capabilityCount = capabilityMap && typeof capabilityMap === "object" && !Array.isArray(capabilityMap) ? Object.keys(capabilityMap).length : 0;
          return node("div", { className: "provider-row" }, [node("strong", { text: textValue(provider.name, "未命名服务") }), node("span", { className: "muted small", text: `${textValue(provider.model, "未设置模型")} · ${provider.key_configured ? "API Key 已配置" : "未配置 API Key"} · ${capabilityCount ? `已配置 ${capabilityCount} 个模型能力` : "模型能力待核实"} · ${declarationSummary(provider)} · ${providerTrustLabel(provider)}` }), edit, test]);
        }) : [emptyState("尚未配置模型服务。")]);
        if (selectId) {
          const found = providers.find((provider) => textValue(provider.id) === selectId);
          if (found) { id.value = textValue(found.id); name.value = textValue(found.name); baseUrl.value = textValue(field(found, ["base_url", "baseUrl"])); }
        }
        await loadDefaults();
      } catch (error) {
        replaceChildren(list, [statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    await refreshList();
  }

  async renderMcpClients(target) {
    const list = node("div", { className: "mcp-list" }, [emptyState("正在加载 MCP 客户端…")]);
    const form = node("form", { className: "inline-form" });
    const name = node("input", { type: "text", placeholder: "客户端名称", required: true });
    const group = node("select", { required: true });
    appendOption(group, "", "选择材料分组");
    const create = formButton("创建客户端", "button secondary");
    const status = statusBox();
    form.append(name, group, create);
    const loadMoreGroups = button("加载更多分组", async () => {
      loadMoreGroups.disabled = true;
      try {
        await loadGroups({ append: true });
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        loadMoreGroups.disabled = false;
      }
    }, "button subtle");
    loadMoreGroups.hidden = true;
    target.append(list, form, loadMoreGroups, status);
    const renderGroups = () => {
      const selectedGroupId = group.value;
      replaceChildren(group);
      for (const item of this.state.groups) appendOption(group, groupId(item), textValue(field(item, ["name"]), "未命名分组"), groupId(item) === selectedGroupId);
      if (selectedGroupId && [...group.options].some((option) => option.value === selectedGroupId)) group.value = selectedGroupId;
      loadMoreGroups.hidden = !this.state.groupsPage.nextCursor;
      if (this.state.groupsPage.corruptCount > 0) setStatus(status, `检测到 ${this.state.groupsPage.corruptCount} 个损坏分组记录，未显示。`, "warning");
    };
    const loadGroups = async ({ append = false } = {}) => {
      await this.loadGroupsPage({ append });
      renderGroups();
    };
    try {
      await loadGroups();
    } catch (error) {
      setStatus(status, apiErrorMessage(error), "danger");
    }
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      create.disabled = true;
      try {
        const response = await this.api.request("/mcp/clients", { method: "POST", body: { name: name.value.trim(), group_id: group.value } });
        const token = textValue(response?.token);
        this.state.pendingMcpToken = token || null;
        setStatus(status, token ? "客户端已创建。令牌只显示一次，请立即下载配置。" : "客户端已创建。", "success");
        if (token) this.renderMcpToken(target, token, response?.client);
        name.value = "";
        await this.refreshMcpList(list);
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        create.disabled = false;
      }
    });
    await this.refreshMcpList(list);
  }

  async copyMcpInbox(inbox, status) {
    if (!inbox) return;
    try {
      await copyText(inbox);
      setStatus(status, "收件目录已复制。", "success");
    } catch {
      setStatus(status, "当前浏览器不支持复制，请手动选中收件目录。", "warning");
    }
  }

  renderMcpToken(target, token, client = {}) {
    const existing = target.querySelector(".mcp-token-box");
    existing?.remove();
    const details = mcpClientDetails(client, this.state.groups);
    const copyStatus = statusBox();
    const copy = button("复制收件目录", () => this.copyMcpInbox(details.inbox, copyStatus), "button subtle");
    copy.disabled = !details.inbox;
    const inbox = node("div", { className: "mcp-inbox" }, [
      node("span", { className: "muted small", text: "收件目录" }),
      node("code", { className: "mcp-path", text: details.inbox || "后端未返回收件目录。" }),
      copy,
      copyStatus
    ]);
    const group = node("p", { className: "muted small", text: `材料分组：${details.groupName}（${details.groupId || "无 ID"}）` });
    const box = node("div", { className: "mcp-token-box" }, [heading(3, "新客户端令牌"), node("p", { className: "token-text", text: token }), node("p", { className: "muted small", text: "令牌只显示一次；收件目录用于放入待脱敏材料，请立即下载配置并妥善保管。" }), group, inbox]);
    const download = button("下载 MCP 配置", async () => {
      const payload = { mcp: { url: `${globalThis.location?.origin || ""}/api/v1/mcp`, token } };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      await downloadBlob(blob, "lawyer-assistance-mcp.json");
      this.state.pendingMcpToken = null;
    }, "button secondary");
    box.append(download);
    target.prepend(box);
  }

  async refreshMcpList(target) {
    try {
      const response = await this.api.request("/mcp/clients");
      this.state.mcpClients = parseJsonList(response?.clients);
      if (!this.state.mcpClients.length) {
        replaceChildren(target, [emptyState("尚未创建 MCP 客户端。")]);
        return;
      }
      replaceChildren(target, this.state.mcpClients.map((client) => {
        const id = textValue(field(client, ["id"]));
        const details = mcpClientDetails(client, this.state.groups);
        const copyStatus = statusBox();
        const copy = button("复制目录", () => this.copyMcpInbox(details.inbox, copyStatus), "button subtle");
        copy.disabled = !details.inbox;
        const revoke = button("撤销", async () => {
          revoke.disabled = true;
          try {
            await this.api.request(`/mcp/clients/${pathId(id)}`, { method: "DELETE" });
            await this.refreshMcpList(target);
          } catch (error) {
            target.prepend(statusBox(apiErrorMessage(error), "danger"));
            revoke.disabled = false;
          }
        }, "button danger");
        const detailsPanel = node("div", { className: "mcp-details" }, [
          node("span", { className: "muted small", text: `${client.enabled === false ? "已停用" : "已启用"} · 分组：${details.groupName}（${details.groupId || "无 ID"}）` }),
          node("code", { className: "mcp-path", text: details.inbox || "后端未返回收件目录。" }),
          node("div", { className: "button-row" }, [copy, copyStatus])
        ]);
        return node("div", { className: "mcp-row" }, [node("strong", { text: textValue(field(client, ["name"]), "未命名客户端") }), detailsPanel, revoke]);
      }));
    } catch (error) {
      replaceChildren(target, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderRuntimeStatus(target) {
    const health = this.state.health;
    const rows = [
      ["服务", textValue(health?.status, "未知")],
      ["法律库", health?.legal_ready ? "已就绪" : "不可用"],
      ["版本", textValue(health?.version, "未知")],
      ["OCR", health?.ocr?.available ? "可用（请在上方选择 OCR 模型）" : "未配置 OCR 模型"]
    ];
    target.append(node("dl", { className: "status-list" }, rows.flatMap(([label, value]) => [node("dt", { text: label }), node("dd", { text: value })])));
    target.append(node("p", { className: "muted small", text: "数据保存在后台服务配置的本机工作区；浏览器不会使用本地存储保存材料。" }));
  }
}

if (typeof document !== "undefined") {
  const root = document.getElementById("app");
  if (root) {
    const app = new WebApp(root);
    app.start();
  }
}
