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
    tool_steps: toolSteps,
    error_code: textValue(field(run, ["error_code", "errorCode"])),
    usage: run.usage && typeof run.usage === "object" ? run.usage : null
  };
}

export function normalizeAiRunList(response) {
  const items = Array.isArray(response) ? response : response?.runs || response?.items || response?.tasks || [];
  return Array.isArray(items) ? items.map(normalizeAiRun) : [];
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

export function legalSearchPageParams({ query = "", documentId = "", caseDate = "", type = "", level = "", region = "", status = "", sort = "relevance", view = "grouped", pageSize = 20, offset = 0, includeHistory = true, includeRelations = true } = {}) {
  const safePageSize = Math.max(1, Math.min(100, Number.isFinite(Number(pageSize)) ? Math.floor(Number(pageSize)) : 20));
  const safeOffset = Math.max(0, Number.isFinite(Number(offset)) ? Math.floor(Number(offset)) : 0);
  return {
    query: String(query || "").trim(),
    ...(String(documentId || "").trim() ? { document_id: String(documentId).trim() } : {}),
    ...(String(caseDate || "").trim() ? { case_date: String(caseDate).trim() } : {}),
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
    hasMore: root.has_more === true || root.hasMore === true || offset + limit < total
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
  if (options.accept) element.accept = options.accept;
  if (options.autocomplete) element.autocomplete = options.autocomplete;
  if (options.href) element.href = options.href;
  if (options.download) element.download = options.download;
  if (options.hidden !== undefined) element.hidden = Boolean(options.hidden);
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
      view: "privacy",
      health: null,
      groups: [],
      selectedGroupId: "",
      materials: [],
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
      legalArticlePage: null,
      legalViewportCleanup: null,
      legalDetailOptions: { includeHistory: true, includeRelations: true },
      legalDetailGeneration: 0,
      legalDetailAbort: null,
      providers: [],
      aiDefaults: {},
      aiMaterials: [],
      aiAttachments: [],
      aiRuns: [],
      selectedAiRun: null,
      conversations: [],
      selectedConversation: null,
      mcpClients: [],
      taskTimer: null,
      chatAbort: null,
      aiRunTimers: new Map(),
      pendingMcpToken: null,
      pendingCitation: null
    };
    this.api.onUnauthenticated = () => this.requireLogin();
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
  }

  requireLogin() {
    this.state.authenticated = false;
    this.state.csrfToken = "";
    this.api.setCsrfToken("");
    this.renderLogin("会话已失效，请使用新的本地访问链接。", true);
  }

  async loadHealth() {
    try {
      this.state.health = await this.api.request("/health");
    } catch {
      this.state.health = null;
    }
  }

  navigate(view) {
    if (!Object.prototype.hasOwnProperty.call(VIEWS, view)) return;
    this.state.view = view;
    this.render();
  }

  render() {
    this.teardownLegalViewport();
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
    groupPanel.append(groupRow);
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

  async loadPrivacyData(groupSelect, materialsList, detail, dictionaryList, dictionaryStatus) {
    try {
      const result = await this.api.request("/groups");
      this.state.groups = parseJsonList(result?.groups);
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

  async loadPrivacyMaterials(groupSelect, materialsList, detail) {
    if (!groupSelect.value) return;
    replaceChildren(materialsList, [emptyState("正在加载材料…")]);
    try {
      const response = await this.api.request(`/materials${queryString({ group_id: groupSelect.value })}`);
      this.state.materials = parseJsonList(response?.materials);
      const rows = [];
      for (const material of this.state.materials) {
        const id = textValue(field(material, ["id", "materialId", "material_id"]));
        const checkbox = node("input", { type: "checkbox", ariaLabel: `选择${materialName(material)}` });
        checkbox.dataset.materialId = id;
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
        const materialIds = [...materialsList.querySelectorAll("input[data-material-id]:checked")].map((input) => input.dataset.materialId).filter(Boolean);
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
      replaceChildren(materialsList, [exportBar, ...rows]);
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
    const poll = async () => {
      try {
        const task = await this.api.request(`/tasks/${pathId(taskId)}`);
        const taskStatus = textValue(field(task, ["status"]));
        setStatus(status, `任务：${statusLabel(taskStatus)}`, materialStatusTone(taskStatus));
        const done = ["completed", "failed", "cancelled", "ready", "partial", "needs_review", "awaiting_consent"].includes(taskStatus.toLowerCase());
        if (!done) {
          this.state.taskTimer = setTimeout(poll, 1500);
        } else if (groupSelect && materialsList && detail) {
          await this.loadPrivacyData(groupSelect, materialsList, detail);
        } else if (detail && this.state.selectedMaterial) {
          const selectedId = textValue(field(this.state.selectedMaterial, ["id", "materialId"]));
          if (selectedId) await this.loadMaterialDetail(selectedId, detail);
        }
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      }
    };
    poll();
  }

  async loadAiProviders() {
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
  }

  async loadAiMaterials() {
    try {
      const response = await this.api.listAiMaterials();
      this.state.aiMaterials = normalizeAiMaterials(response);
    } catch {
      // A missing AI route should not make the regular material page unusable.
      this.state.aiMaterials = [];
    }
    return this.state.aiMaterials;
  }

  renderAiMaterialPicker(materials = this.state.aiMaterials, { multiple = true, title = "选择材料", preferRedacted = true } = {}) {
    const picker = node("div", { className: "ai-material-picker" });
    const selected = new Set();
    const rows = Array.isArray(materials) ? materials.filter((material) => material.id) : [];
    if (!rows.length) {
      picker.append(emptyState("暂无可用材料；请先在“材料脱敏”中完成处理。"));
      picker.values = () => [];
      picker.refresh = (next) => this.renderAiMaterialPicker(next, { multiple, title, preferRedacted });
      return picker;
    }
    const header = node("div", { className: "picker-heading" }, [node("strong", { text: title }), node("span", { className: "muted small", text: `${rows.length} 个材料` })]);
    picker.append(header);
    for (const material of rows) {
      const check = node("input", { type: multiple ? "checkbox" : "radio", name: multiple ? undefined : `ai-material-${title}`, ariaLabel: `选择${material.name}` });
      check.dataset.materialId = material.id;
      const source = node("select", { className: "material-source", ariaLabel: `${material.name}发送版本` });
      const hasRedacted = Boolean(material.result_id) && ["ready", "completed"].includes(String(material.status).toLowerCase());
      if (hasRedacted) appendOption(source, "redacted", "发送脱敏版", preferRedacted);
      if (material.has_original || !hasRedacted) appendOption(source, "original", "发送原文", !hasRedacted && !preferRedacted);
      if (!source.options.length) source.disabled = true;
      const label = node("label", { className: "material-picker-row" }, [check, node("span", { className: "material-picker-name", text: material.name }), node("span", { className: `status-pill ${materialStatusTone(material.status)}`, text: statusLabel(material.status) }), source]);
      picker.append(label);
      check.addEventListener("change", () => {
        if (!multiple) {
          for (const other of picker.querySelectorAll("input[data-material-id]")) if (other !== check) other.checked = false;
        }
        if (check.checked) selected.add(material.id); else selected.delete(material.id);
      });
    }
    picker.values = () => [...picker.querySelectorAll("input[data-material-id]:checked")].map((input) => {
      const row = input.closest(".material-picker-row");
      const material = rows.find((item) => item.id === input.dataset.materialId);
      const source = row?.querySelector(".material-source")?.value || aiMaterialSource(material, preferRedacted);
      return { id: input.dataset.materialId, source };
    });
    return picker;
  }

  applyMaterialTrust(picker, provider) {
    if (!picker) return;
    const allowRaw = provider?.trust_raw === true || provider?.trustRaw === true;
    for (const source of picker.querySelectorAll(".material-source")) {
      const hasOriginal = [...source.options].some((option) => option.value === "original");
      if (allowRaw && hasOriginal) source.value = "original";
      else if ([...source.options].some((option) => option.value === "redacted")) source.value = "redacted";
    }
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

  renderAiAttachmentPicker({ accept = ".txt,.docx,.pdf,.png,.jpg,.jpeg,.webp", multiple = true } = {}) {
    const wrapper = node("div", { className: "ai-attachment-picker" });
    const input = node("input", { type: "file", accept, multiple });
    const status = statusBox("附件仅在点击生成/发送后随任务提交。", "muted");
    const list = node("div", { className: "attachment-list" });
    const selected = new Map();
    const renderSelected = () => {
      replaceChildren(list, [...selected.values()].map((item) => {
        const remove = button("移除", () => {
          selected.delete(item.id);
          renderSelected();
        }, "button subtle attachment-remove");
        return node("span", { className: "attachment-chip" }, [node("span", { text: item.name }), remove]);
      }));
    };
    input.addEventListener("change", async () => {
      const uploaded = await this.uploadAiFiles(input.files, status);
      for (const item of uploaded) selected.set(item.id, item);
      renderSelected();
      input.value = "";
    });
    wrapper.append(labelFor("上传附件", input), list, status);
    wrapper.attachmentIds = () => [...selected.keys()];
    return wrapper;
  }

  async createAiRun(payload, { status, onUpdate, onDone } = {}) {
    const response = await this.api.createAiRun(payload);
    const run = normalizeAiRun(response?.run || response);
    if (!run.id) throw new ApiError("run_id_missing", false, 200);
    this.state.selectedAiRun = run;
    if (run.kind === AI_RUN_KINDS.chat) this.state.currentChatRunId = run.id;
    setStatus(status, `任务已创建：${aiRunStatusLabel(run.status)}`, "info");
    this.pollAiRun(run.id, { status, onUpdate, onDone });
    return run;
  }

  pollAiRun(id, { status, onUpdate, onDone } = {}) {
    const key = String(id || "");
    if (!key) return;
    const old = this.state.aiRunTimers.get(key);
    if (old) clearTimeout(old);
    const poll = async () => {
      try {
        const response = await this.api.getAiRun(key);
        const run = normalizeAiRun(response?.run || response);
        this.state.selectedAiRun = run;
        onUpdate?.(run);
        const terminal = aiRunIsTerminal(run);
        setStatus(status, `${aiRunKindLabel(run.kind)}：${aiRunStatusLabel(run.status)}${run.stage ? ` · ${pipelineStageLabel(run.stage)}` : ""} · ${aiRunProgressText(run)}`, terminal && run.status === "completed" ? "success" : terminal ? "warning" : "info");
        if (terminal) {
          this.state.aiRunTimers.delete(key);
          onDone?.(run);
          return;
        }
        this.state.aiRunTimers.set(key, setTimeout(poll, 1500));
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
        this.state.aiRunTimers.set(key, setTimeout(poll, 3000));
      }
    };
    poll();
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
    const query = node("input", { type: "search", placeholder: "输入法条、关键词或文号", required: true, autocomplete: "off" });
    const caseDate = node("input", { type: "date" });
    const caseType = node("select", { required: true });
    appendOption(caseType, CASE_TYPES.all, "全部（指导、参考及典型案例）", this.state.legalCaseType === CASE_TYPES.all);
    appendOption(caseType, CASE_TYPES.guiding, "仅指导案例", this.state.legalCaseType === CASE_TYPES.guiding);
    appendOption(caseType, CASE_TYPES.reference, "仅参考案例", this.state.legalCaseType === CASE_TYPES.reference);
    appendOption(caseType, CASE_TYPES.typical, "仅典型案例合集", this.state.legalCaseType === CASE_TYPES.typical);
    const includeWithdrawn = node("input", { type: "checkbox", checked: this.state.legalIncludeWithdrawn === true, ariaLabel: "包含不再参照的历史案例" });
    const includeWithdrawnLabel = node("label", { className: "checkbox-label" }, [includeWithdrawn, node("span", { text: "包含不再参照的历史案例" })]);
    const lawOptions = node("div", { className: "legal-law-options" }, [labelFor("案件日期（可选）", caseDate)]);
    const caseOptions = node("div", { className: "legal-case-options" }, [labelFor("案例分类", caseType), includeWithdrawnLabel]);
    const statuteFilters = node("div", { className: "legal-statute-filters" });
    const typeFilter = node("select", { ariaLabel: "法律类型" });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.type) appendOption(typeFilter, value, label);
    const levelFilter = node("select", { ariaLabel: "效力层级" });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.level) appendOption(levelFilter, value, label);
    const regionFilter = node("input", { type: "search", placeholder: "地域（可选）", ariaLabel: "地域" });
    const statusFilter = node("select", { ariaLabel: "有效状态" });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.status) appendOption(statusFilter, value, label);
    const sortFilter = node("select", { ariaLabel: "排序方式" });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.sort) appendOption(sortFilter, value, label);
    const viewFilter = node("select", { ariaLabel: "结果视图" });
    for (const [value, label] of LEGAL_FILTER_OPTIONS.view) appendOption(viewFilter, value, label, value === "grouped");
    const includeHistory = node("input", { type: "checkbox", checked: true, ariaLabel: "显示历史版本" });
    const includeRelations = node("input", { type: "checkbox", checked: true, ariaLabel: "显示关联法规" });
    const filterToggles = node("div", { className: "legal-filter-toggles" }, [
      node("label", { className: "checkbox-label" }, [includeHistory, node("span", { text: "查看历史版本" })]),
      node("label", { className: "checkbox-label" }, [includeRelations, node("span", { text: "查看关联法规" })])
    ]);
    const jurisdictionList = node("datalist", { id: "legal-jurisdictions" });
    regionFilter.setAttribute("list", "legal-jurisdictions");
    statuteFilters.append(labelFor("法律类型", typeFilter), labelFor("效力层级", levelFilter), labelFor("地域", regionFilter), jurisdictionList, labelFor("有效状态", statusFilter), labelFor("排序", sortFilter), labelFor("显示方式", viewFilter), filterToggles);
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
    const aiSearchMaterialHost = node("div", { className: "ai-material-host" }, [emptyState("正在加载可用材料…")]);
    let aiSearchPicker = null;
    const aiSearchAttachment = this.renderAiAttachmentPicker();
    const aiSearchButton = formButton("开始 AI 法律搜索", "button primary");
    const aiSearchStatus = statusBox();
    const aiSearchOutput = node("article", { className: "ai-run-output" }, [emptyState("提交案情后显示检索结果。")]);
    const aiSearchCitations = node("div", { className: "citation-list" });
    const aiSearchHistory = node("div", { className: "ai-history-list" });
    aiSearchForm.append(labelFor("Provider", aiSearchProvider), labelFor("模型", aiSearchModel), labelFor("案情或事件", aiSearchPrompt), aiSearchMaterialHost, aiSearchAttachment, aiSearchButton, aiSearchStatus, aiSearchOutput, aiSearchCitations, heading(3, "AI 搜索历史"), aiSearchHistory);
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
      this.cancelLegalRequests();
      this.state.legalMode = nextMode;
      this.state.legalCaseOffset = 0;
      this.state.legalArticleOffset = 0;
      this.state.legalCaseResponse = null;
      this.state.selectedArticle = null;
      this.state.selectedCase = null;
      this.state.legalArticlePage = null;
      this.state.legalArticleQuery = "";
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

    searchForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (this.state.legalMode === LEGAL_SEARCH_MODES.case) {
        await runCasePage(0);
        return;
      }
      const queryText = query.value.trim();
      if (!queryText) {
        setStatus(searchStatus, "请输入法条关键词。", "warning");
        return;
      }
      this.state.legalArticleQuery = queryText;
      searchButton.disabled = true;
      setStatus(searchStatus, "正在查询法条…");
      this.state.legalArticleOffset = 0;
      const generation = this.beginLegalSearch();
      try {
        const pageSize = adaptiveLegalPageSize(results, 12);
        const pageParams = legalSearchPageParams({
          query: queryText,
          caseDate: caseDate.value,
          type: typeFilter.value,
          level: levelFilter.value,
          region: regionFilter.value,
          status: statusFilter.value,
          sort: sortFilter.value,
          view: viewFilter.value,
          pageSize,
          offset: this.state.legalArticleOffset || 0,
          includeHistory: includeHistory.checked,
          includeRelations: includeRelations.checked
        });
        const response = await this.api.request(`/legal/search/page${queryString(pageParams)}`, { signal: this.state.legalSearchAbort.signal });
        if (generation !== this.state.legalSearchGeneration) return;
        const normalized = normalizeLegalPageResponse(response, { pageSize, offset: pageParams.offset, view: viewFilter.value });
        this.state.legalResults = normalized.items;
        this.state.legalArticlePage = normalized;
        this.state.legalArticleOffset = normalized.offset;
        this.renderLegalPage(normalized, results, detail, { includeHistory: includeHistory.checked, includeRelations: includeRelations.checked, onPage: runArticlePage, onGroupPage: runGroupPage });
        const resultCount = normalized.view === "grouped" ? normalized.totalLaws : normalized.totalArticles;
        replaceChildren(responseMeta, [node("span", { className: "muted small", text: normalized.view === "grouped" ? `命中 ${resultCount} 部法律 · ${normalized.totalArticles} 条文` : `命中 ${resultCount} 条文` })]);
        replaceChildren(interpretation);
        interpretation.hidden = true;
        this.renderLegalPagination(normalized, pagination, runArticlePage);
        setStatus(searchStatus, normalized.view === "grouped" ? `找到 ${normalized.totalLaws} 部法律，本页显示 ${normalized.groups.length} 部。` : `找到 ${normalized.totalArticles} 条法条，本页显示 ${normalized.items.length} 条。`, "success");
      } catch (error) {
        if (generation !== this.state.legalSearchGeneration || error?.name === "AbortError") return;
        setStatus(searchStatus, apiErrorMessage(error), "danger");
      } finally {
        if (generation === this.state.legalSearchGeneration) {
          this.state.legalSearchAbort = null;
          searchButton.disabled = false;
        }
      }
    });

    const runArticlePage = async (offset = 0, { pageSizeOverride = 0, reason = "" } = {}) => {
      const queryText = query.value.trim();
      if (!queryText) return;
      this.state.legalArticleQuery = queryText;
      this.state.legalArticleOffset = Math.max(0, Number(offset) || 0);
      searchButton.disabled = true;
      setStatus(searchStatus, reason === "resize" ? "窗口已调整，正在保持当前位置重新加载…" : this.state.legalArticleOffset ? "正在加载下一页法条…" : "正在查询法条…");
      const pageSize = Number(pageSizeOverride) > 0
        ? Math.max(1, Math.min(100, Math.floor(Number(pageSizeOverride))))
        : adaptiveLegalPageSize(results, 12);
      const generation = this.beginLegalSearch();
      try {
        const params = legalSearchPageParams({ query: queryText, caseDate: caseDate.value, type: typeFilter.value, level: levelFilter.value, region: regionFilter.value, status: statusFilter.value, sort: sortFilter.value, view: viewFilter.value, pageSize, offset: this.state.legalArticleOffset, includeHistory: includeHistory.checked, includeRelations: includeRelations.checked });
        const response = await this.api.request(`/legal/search/page${queryString(params)}`, { signal: this.state.legalSearchAbort.signal });
        if (generation !== this.state.legalSearchGeneration) return;
        const normalized = normalizeLegalPageResponse(response, { pageSize, offset: params.offset, view: viewFilter.value });
        this.state.legalResults = normalized.items;
        this.state.legalArticlePage = normalized;
        this.state.legalArticleOffset = normalized.offset;
        this.renderLegalPage(normalized, results, detail, { includeHistory: includeHistory.checked, includeRelations: includeRelations.checked, onPage: runArticlePage, onGroupPage: runGroupPage });
        this.renderLegalPagination(normalized, pagination, runArticlePage);
        const resultCount = normalized.view === "grouped" ? normalized.totalLaws : normalized.totalArticles;
        replaceChildren(responseMeta, [node("span", { className: "muted small", text: normalized.view === "grouped" ? `命中 ${resultCount} 部法律 · ${normalized.totalArticles} 条文` : `命中 ${resultCount} 条文` })]);
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
        const params = legalSearchPageParams({ documentId, query: queryText, caseDate: caseDate.value, type: typeFilter.value, level: levelFilter.value, region: regionFilter.value, status: statusFilter.value, sort: sortFilter.value, view: "flat", pageSize, offset: safeOffset });
        const response = await this.api.request(`/legal/search/page${queryString(params)}`);
        const normalized = normalizeLegalPageResponse(response, { pageSize, offset: safeOffset, view: "flat" });
        this.renderLegalResults(normalized.items, groupTarget, detail);
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
      const normalized = normalizeAiRun(run);
      this.state.selectedAiRun = normalized;
      renderRenderedContent(aiSearchOutput, normalized.html, normalized.content, "该任务尚无正文结果。");
      this.renderRunCitations(aiSearchCitations, normalized.citations);
      setStatus(aiSearchStatus, `${aiRunKindLabel(normalized.kind)}：${aiRunStatusLabel(normalized.status)}${normalized.stage ? ` · ${pipelineStageLabel(normalized.stage)}` : ""} · ${aiRunProgressText(normalized)}`, normalized.status === "completed" ? "success" : aiRunIsTerminal(normalized) ? "warning" : "info");
      if (resume && !aiRunIsTerminal(normalized)) this.pollAiRun(normalized.id, { status: aiSearchStatus, onUpdate: (next) => showAiSearchRun(next, { resume: false }) });
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
    const refreshAiSearchHistory = async () => {
      try {
        const response = await this.api.listAiRuns("search");
        const runs = normalizeAiRunList(response);
        this.state.aiRuns = [...this.state.aiRuns.filter((item) => item.kind !== "search"), ...runs];
        replaceChildren(aiSearchHistory, runs.length ? runs.slice(0, 10).map((run) => {
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
        }) : [emptyState("还没有 AI 法律搜索记录。 ")]);
      } catch (error) {
        replaceChildren(aiSearchHistory, [statusBox(apiErrorMessage(error), "danger")]);
      }
    };
    aiSearchProvider.addEventListener("change", () => syncAiSearchModel());
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
      aiSearchButton.disabled = true;
      try {
        await this.createAiRun({ kind: AI_RUN_KINDS.search, prompt, provider_id: aiSearchProvider.value, model, materials: aiSearchPicker?.values?.() || [], attachment_ids: aiSearchAttachment.attachmentIds?.() || [], case_date: caseDate.value || undefined }, {
          status: aiSearchStatus,
          onUpdate: (run) => {
            if (run.content || run.html) renderRenderedContent(aiSearchOutput, run.html, run.content, "该任务尚无正文结果。");
            this.renderRunCitations(aiSearchCitations, run.citations);
          },
          onDone: (run) => {
            if (run.content || run.html) renderRenderedContent(aiSearchOutput, run.html, run.content, "该任务尚无正文结果。");
            this.renderRunCitations(aiSearchCitations, run.citations);
            refreshAiSearchHistory();
          }
        });
      } catch (error) {
        setStatus(aiSearchStatus, apiErrorMessage(error), "danger");
      } finally {
        aiSearchButton.disabled = false;
      }
    });

    setMode(this.state.legalMode);
    await this.loadProvidersInto(providerSelect, "chat");
    await this.loadProvidersInto(aiSearchProvider, "chat");
    syncProviderModel();
    syncAiSearchModel();
    loadLegalFilters();
    const aiMaterials = await this.loadAiMaterials();
    aiSearchPicker = this.renderAiMaterialPicker(aiMaterials, { title: "选择材料（默认脱敏版）" });
    replaceChildren(aiSearchMaterialHost, [aiSearchPicker]);
    syncAiSearchModel({ preserveModel: true });
    refreshAiSearchHistory();
    syncProviderModel({ preserveModel: true });
    this.loadCaseStatus(caseStatus);
    await this.loadBookmarks(bookmarks);
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

  renderLegalPage(page, target, detail, { includeHistory = true, includeRelations = true, onPage, onGroupPage } = {}) {
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
      this.renderLegalResults(normalized.items, target, detail);
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

  renderLegalArticleCard(article, detail) {
    const id = articleId(article);
    const title = legalArticleDisplayTitle(article);
    const source = textValue(field(article, ["documentTitle", "document_title", "lawName", "law_name"]));
    const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
    const statusKey = textValue(field(article, ["versionStatus", "version_status", "status"]));
    const status = statusKey ? legalStatusLabel(statusKey) : "";
    const relevance = field(article, ["relevance", "score", "rank"], "");
    const titleNode = id ? button(title, () => this.loadArticle(id, detail), "result-button") : node("strong", { text: title });
    const metadata = [source, effective ? `生效：${effective}` : "", status ? `状态：${status}` : "", relevance !== "" ? `相关性：${textValue(relevance)}` : ""].filter(Boolean).join(" · ");
    const snippet = textValue(field(article, ["snippet", "summary", "content_preview"]));
    return node("article", { className: "result-card legal-article-card" }, [titleNode, metadata ? node("p", { className: "result-meta", text: metadata }) : null, snippet ? node("p", { className: "legal-snippet", text: snippet }) : null]);
  }

  renderLegalResults(items, target, detail) {
    if (!items.length) {
      replaceChildren(target, [emptyState("没有找到匹配条文。")]);
      return;
    }
    const rows = items.map((article) => this.renderLegalArticleCard(article, detail));
    replaceChildren(target, rows);
  }

  async loadArticle(id, detail) {
    if (!id) return;
    replaceChildren(detail, [emptyState("正在加载条文…")]);
    try {
      const response = await this.api.request(`/legal/articles/${pathId(id)}`);
      const article = response?.article && typeof response.article === "object" ? response.article : response;
      this.state.selectedArticle = article;
      this.renderArticleDetail(article, detail);
    } catch (error) {
      replaceChildren(detail, [statusBox(apiErrorMessage(error), "danger")]);
    }
  }

  renderArticleDetail(article, detail) {
    const id = articleId(article);
    const documentId = legalArticleDocumentId(article);
    const title = legalArticleDisplayTitle(article);
    const content = textValue(field(article, ["content", "text", "body", "articleText"]), "暂无正文。");
    const source = textValue(field(article, ["documentTitle", "document_title"]));
    const effective = textValue(field(article, ["effectiveFrom", "effective_from"]));
    const statusKey = textValue(field(article, ["versionStatus", "version_status", "status"]));
    const status = legalStatusLabel(statusKey);
    const headingBlock = node("div", { className: "detail-heading" }, [heading(2, title), node("p", { className: "muted", text: [source, effective ? `生效：${effective}` : "", status ? `状态：${status}` : ""].filter(Boolean).join(" · ") })]);
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
    replaceChildren(detail, [headingBlock, actions, text, versionBox, relationBox]);
    let versionRequestGeneration = 0;

    const loadHistory = async () => {
      const generation = ++versionRequestGeneration;
      if (!historyToggle.checked) {
        replaceChildren(versionBox);
        return;
      }
      if (!documentId) {
        replaceChildren(versionBox, [heading(3, "历史版本"), emptyState("该条文没有可用的法律文书 ID。")]);
        return;
      }
      replaceChildren(versionBox, [heading(3, "历史版本"), statusBox("正在读取历史版本…")]);
      try {
        const response = await this.api.request(`/legal/versions/${pathId(documentId)}`);
        if (generation !== versionRequestGeneration || !historyToggle.checked) return;
        const items = responseList(response, ["versions", "items"]);
        if (!items.length) {
          replaceChildren(versionBox, [heading(3, "历史版本"), emptyState("没有历史版本记录。")]);
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
            const loaded = await this.api.request(`/legal/version-articles/${pathId(versionId)}${queryString({ limit: pageSize, offset: safeOffset })}`);
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
            const fallback = textValue(field(version, ["content", "text", "body"]), "暂无该版本正文。");
            if (versionId) await loadVersionPage(versionId, 0, fallback, show);
            else renderVersionBody([version], fallback);
          }, "version-button");
          return node("div", { className: "version-item" }, [show]);
        });
        replaceChildren(versionBox, [heading(3, "历史版本"), node("div", { className: "version-list" }, rows), versionContent, versionPagination]);
        // Loading the first entry makes the default-open switch useful without
        // requiring a second click merely to see whether content is available.
        versionBox.querySelector(".version-button")?.click();
      } catch (error) {
        if (generation === versionRequestGeneration && historyToggle.checked) replaceChildren(versionBox, [heading(3, "历史版本"), statusBox(apiErrorMessage(error), "danger")]);
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
          const targetButton = button(target.title, () => this.loadArticle(target.documentId, detail), "link-button");
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
    const title = node("div", { className: "page-title" }, [heading(1, "文书写作"), node("p", { text: "描述案件和写作要求，由模型先检索依据再生成文书；预览为渲染后的正文，默认导出 PDF。" })]);
    const layout = node("div", { className: "workspace-grid template-grid" });
    const editorColumn = node("div", { className: "workspace-column" });
    const previewColumn = node("div", { className: "workspace-column" });
    layout.append(editorColumn, previewColumn);
    main.append(title, layout);

    const editor = panel("案件与写作要求");
    const form = node("form", { className: "stack-form" });
    const documentType = node("select", { required: true });
    for (const value of ["民事起诉状", "民事答辩状", "劳动仲裁申请书", "律师函", "合同审查意见", "法律意见书"]) appendOption(documentType, value, value);
    const caseDescription = node("textarea", { rows: 10, placeholder: "说明当事人、时间、事实经过、争议焦点、请求和证据。可以直接粘贴已脱敏材料摘要。", required: true });
    const requirements = node("textarea", { rows: 5, placeholder: "例如：使用正式法律文书格式；缺失事实标记为【待补充】；引用现行有效法条。" });
    const providerSelect = node("select", { required: true });
    appendOption(providerSelect, "", "选择写作模型服务");
    const modelInput = node("select", { required: true, ariaLabel: "文书写作模型" });
    appendOption(modelInput, "", "选择 Provider 后载入模型");
    const materialHost = node("div", { className: "ai-material-host" }, [emptyState("正在加载可用材料…")]);
    let materialPicker = null;
    const attachmentPicker = this.renderAiAttachmentPicker();
    const generateButton = formButton("生成文书", "button primary");
    const status = statusBox();
    form.append(labelFor("文书类型", documentType), labelFor("案情描述", caseDescription), labelFor("写作要求", requirements), labelFor("Provider", providerSelect), labelFor("模型", modelInput), materialHost, attachmentPicker, generateButton, status);
    editor.append(form);
    editorColumn.append(editor);

    const previewPanel = panel("预览与导出", [], "panel preview-panel");
    const runStatus = statusBox("尚未生成文书。", "muted");
    const preview = node("article", { className: "document-preview document-rendered" }, [emptyState("填写案件并生成文书。")]);
    const contentEditor = node("textarea", { className: "document-content-editor", rows: 22, hidden: true, placeholder: "在此修改 Markdown 正文后保存" });
    const saveContent = button("保存正文修改", async () => {
      const run = this.state.selectedAiRun;
      if (!run?.id) return;
      saveContent.disabled = true;
      try {
        const response = await this.api.updateAiRunContent(run.id, contentEditor.value);
        this.state.selectedAiRun = normalizeAiRun(response?.run || response);
        renderRenderedContent(preview, this.state.selectedAiRun.html, this.state.selectedAiRun.content);
        await refreshHistory();
        setStatus(runStatus, "正文修改已保存。", "success");
        contentEditor.hidden = true;
        saveContent.hidden = true;
      } catch (error) {
        setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        saveContent.disabled = false;
      }
    }, "button secondary");
    saveContent.hidden = true;
    const editContent = button("编辑正文", () => {
      const run = this.state.selectedAiRun;
      if (!run?.id) return;
      contentEditor.value = run.content;
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
    const exportButton = button("导出", async () => {
      const run = this.state.selectedAiRun;
      if (!run?.id) {
        setStatus(runStatus, "请先生成文书。", "warning");
        return;
      }
      exportButton.disabled = true;
      try {
        const blob = await this.api.exportAiRun(run.id, format.value);
        await downloadBlob(blob, safeFilename(run.title || documentType.value || "文书", format.value));
        setStatus(runStatus, `已导出 ${format.value.toUpperCase()}。`, "success");
      } catch (error) {
        setStatus(runStatus, apiErrorMessage(error), "danger");
      } finally {
        exportButton.disabled = false;
      }
    }, "button secondary");
    exportRow.append(editContent, format, exportButton);
    const citations = node("div", { className: "citation-list" });
    const toolSteps = node("details", { className: "tool-steps" }, [node("summary", { text: "查看检索过程" })]);
    previewPanel.append(runStatus, preview, contentEditor, saveContent, citations, toolSteps, exportRow);
    previewColumn.append(previewPanel);

    const historyPanel = panel("写作历史", [], "panel ai-history-panel");
    const historyList = node("div", { className: "ai-history-list" }, [emptyState("正在加载历史记录…")]);
    historyPanel.append(historyList);
    editorColumn.append(historyPanel);
    const showWritingRun = (run, { resume = true } = {}) => {
      const loaded = normalizeAiRun(run);
      this.state.selectedAiRun = loaded;
      renderRenderedContent(preview, loaded.html, loaded.content, "该任务尚无正文结果。");
      contentEditor.value = loaded.content;
      this.renderRunCitations(citations, loaded.citations);
      replaceChildren(toolSteps, [node("summary", { text: "查看检索过程" }), ...(loaded.tool_steps || []).map((step) => node("p", { className: "tool-step", text: textValue(field(step, ["summary", "query", "action"]), aiToolLabel(field(step, ["tool", "name"]))) }))]);
      setStatus(runStatus, `${aiRunKindLabel(loaded.kind)}：${aiRunStatusLabel(loaded.status)}${loaded.stage ? ` · ${pipelineStageLabel(loaded.stage)}` : ""} · ${aiRunProgressText(loaded)}`, loaded.status === "completed" ? "success" : aiRunIsTerminal(loaded) ? "warning" : "info");
      if (resume && !aiRunIsTerminal(loaded)) this.pollAiRun(loaded.id, { status: runStatus, onUpdate: (next) => showWritingRun(next, { resume: false }) });
      return loaded;
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
      try {
        const response = await this.api.getAiRun(run.id);
        showWritingRun(response?.run || response);
      } catch (error) {
        setStatus(runStatus, apiErrorMessage(error), "danger");
      }
    };
    const refreshHistory = async () => {
      try {
        const response = await this.api.listAiRuns("writing");
        const runs = normalizeAiRunList(response);
        this.state.aiRuns = [...this.state.aiRuns.filter((item) => item.kind !== "writing"), ...runs];
        replaceChildren(historyList, runs.length ? runs.slice(0, 20).map((run) => {
          const open = button(`${run.title || documentType.value} · ${aiRunStatusLabel(run.status)}`, () => openRun(run), "conversation-item");
          const row = node("div", { className: "ai-history-row" }, [open]);
          if (["paused", "interrupted", "failed"].includes(String(run.status).toLowerCase())) row.append(button("继续", () => continueWritingRun(run), "button subtle"));
          row.append(button("删除", async () => {
            try { await this.api.deleteAiRun(run.id); await refreshHistory(); }
            catch (error) { setStatus(runStatus, apiErrorMessage(error), "danger"); }
          }, "button danger"));
          return row;
        }) : [emptyState("还没有文书写作记录。")] );
      } catch (error) {
        replaceChildren(historyList, [statusBox(apiErrorMessage(error), "danger")]);
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
      if (syncMaterialTrust) this.applyMaterialTrust(materialPicker, provider);
      return provider;
    };
    providerSelect.addEventListener("change", () => providerModel());
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
        await this.createAiRun({ kind: AI_RUN_KINDS.writing, prompt, provider_id: providerSelect.value, model, document_type: documentType.value, requirements: requirements.value.trim(), materials: materialPicker?.values?.() || [], attachment_ids: attachmentPicker.attachmentIds?.() || [] }, {
          status,
          onUpdate: (run) => {
            this.state.selectedAiRun = run;
            if (run.content || run.html) { renderRenderedContent(preview, run.html, run.content, "该任务尚无正文结果。"); contentEditor.value = run.content; }
            this.renderRunCitations(citations, run.citations);
            replaceChildren(toolSteps, [node("summary", { text: "查看检索过程" }), ...(run.tool_steps || []).map((step) => node("p", { className: "tool-step", text: textValue(field(step, ["summary", "query", "action"]), aiToolLabel(field(step, ["tool", "name"]))) }))]);
          },
          onDone: (run) => {
            this.state.selectedAiRun = run;
            if (run.content || run.html) { renderRenderedContent(preview, run.html, run.content, "该任务尚无正文结果。"); contentEditor.value = run.content; }
            this.renderRunCitations(citations, run.citations);
            setStatus(status, run.status === "completed" ? "文书已生成并保存历史记录。" : `任务状态：${aiRunStatusLabel(run.status)}`, run.status === "completed" ? "success" : "warning");
            refreshHistory();
          }
        });
      } catch (error) {
        setStatus(status, apiErrorMessage(error), "danger");
      } finally {
        generateButton.disabled = false;
      }
    });
    await this.loadProvidersInto(providerSelect, "writing");
    const materials = await this.loadAiMaterials();
    materialPicker = this.renderAiMaterialPicker(materials, { title: "选择材料（默认脱敏版）" });
    replaceChildren(materialHost, [materialPicker]);
    providerModel({ preserveModel: true });
    await refreshHistory();
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
    const attachmentPicker = this.renderAiAttachmentPicker();
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
    chatPanel.append(selectedTitle, renameForm, labelFor("材料上下文", materialHost), attachmentPicker, messages, composer);
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

    const openConversation = async (id) => {
      if (!id) return;
      try {
        const response = await this.api.getAiConversation(id);
        const conversation = response?.conversation || response;
        this.state.selectedConversation = conversation;
        const conversationTitle = textValue(field(conversation, ["title", "name"]), "未命名会话");
        selectedTitle.firstElementChild.textContent = conversationTitle;
        renameInput.value = conversationTitle;
        renderChatMessages(parseJsonList(conversation?.messages));
        for (const item of conversationList.querySelectorAll(".conversation-item")) item.classList.toggle("active", item.dataset.conversationId === id);
      } catch (error) {
        setStatus(chatStatus, apiErrorMessage(error), "danger");
      }
    };
    const loadConversationList = async (preferredId = "") => {
      try {
        const response = await this.api.listAiConversations();
        const conversations = Array.isArray(response) ? response : response?.conversations || response?.items || [];
        this.state.conversations = Array.isArray(conversations) ? conversations : [];
        if (!this.state.conversations.length) {
          replaceChildren(conversationList, [emptyState("还没有会话，点击“新建会话”。")]);
          this.state.selectedConversation = null;
          selectedTitle.firstElementChild.textContent = "请选择或新建会话";
          replaceChildren(messages, [emptyState("选择或新建会话。")]);
          return;
        }
        const selectedId = preferredId || textValue(field(this.state.selectedConversation, ["id", "conversationId"]), textValue(field(this.state.conversations[0], ["id", "conversationId"])));
        replaceChildren(conversationList, this.state.conversations.map((conversation) => {
          const id = textValue(field(conversation, ["id", "conversationId"]));
          const item = button(textValue(field(conversation, ["title", "name"]), "未命名会话"), () => openConversation(id), `conversation-item${id === selectedId ? " active" : ""}`);
          item.dataset.conversationId = id;
          return item;
        }));
        await openConversation(selectedId);
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
    providerSelect.addEventListener("change", () => syncChatModel());
    const finishChatRun = async (next, conversationId) => {
      setStatus(chatStatus, next.status === "completed" ? "回答已生成并保存。" : `任务状态：${aiRunStatusLabel(next.status)}`, next.status === "completed" ? "success" : "warning");
      cancelButton.disabled = true;
      this.state.currentChatRunId = "";
      await openConversation(conversationId);
      await loadConversationList(conversationId);
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
      cancelButton.disabled = false;
      messageInput.value = "";
      const current = parseJsonList(this.state.selectedConversation?.messages);
      const pendingMessages = [...current, { role: "user", content: prompt }, { role: "assistant", content: "正在检索法律依据并生成回答…" }];
      renderChatMessages(pendingMessages);
      try {
        const run = await this.createAiRun({ kind: AI_RUN_KINDS.chat, prompt, provider_id: providerSelect.value, model, conversation_id: conversationId, materials: materialPicker?.values?.() || [], attachment_ids: attachmentPicker.attachmentIds?.() || [] }, {
          status: chatStatus,
          onUpdate: (next) => {
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
    const materials = await this.loadAiMaterials();
    materialPicker = this.renderAiMaterialPicker(materials, { title: "选择材料（默认脱敏版）" });
    replaceChildren(materialHost, [materialPicker]);
    const selectedProvider = this.state.providers.find((item) => textValue(field(item, ["id"])) === providerSelect.value);
    this.applyMaterialTrust(materialPicker, selectedProvider);
    await loadConversationList();
    try {
      const activeRuns = normalizeAiRunList(await this.api.listAiRuns("chat"));
      const selectedId = textValue(field(this.state.selectedConversation, ["id", "conversationId"]));
      const active = activeRuns.find((run) => !aiRunIsTerminal(run) && textValue(field(run, ["conversation_id", "conversationId"])) === selectedId);
      if (active) {
        this.state.currentChatRunId = active.id;
        setStatus(chatStatus, `${aiRunKindLabel(active.kind)}：${aiRunStatusLabel(active.status)}${active.stage ? ` · ${pipelineStageLabel(active.stage)}` : ""} · ${aiRunProgressText(active)}`, "info");
        this.pollAiRun(active.id, { status: chatStatus, onUpdate: (next) => setStatus(chatStatus, `${aiRunKindLabel(next.kind)}：${aiRunStatusLabel(next.status)}${next.stage ? ` · ${pipelineStageLabel(next.stage)}` : ""} · ${aiRunProgressText(next)}`, "info"), onDone: (next) => finishChatRun(next, selectedId) });
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
        const checked = node("input", { type: "checkbox", checked: enabledModels.has(modelId), ariaLabel: `启用${modelId}` });
        checked.dataset.modelId = modelId;
        checked.addEventListener("change", () => { if (checked.checked) enabledModels.add(modelId); else enabledModels.delete(modelId); });
        return node("label", { className: "model-option" }, [checked, node("span", { text: modelId }), node("span", { className: "muted small", text: textValue(field(model, ["owned_by", "description"])) })]);
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
      save.disabled = true;
      try {
        const body = { id: id.value.trim() || undefined, name: name.value.trim(), preset: preset.value, base_url: baseUrl.value.trim(), enabled_models: selectedModels.length ? selectedModels : [defaultModel.value.trim()], model: defaultModel.value.trim(), trust_raw: trustRaw.checked, allow_private_network: privateNetwork.checked };
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
        replaceChildren(list, providers.length ? providers.map((provider) => {
          const pid = textValue(provider.id);
          const edit = button("编辑", () => {
            id.value = pid; name.value = textValue(provider.name); baseUrl.value = textValue(field(provider, ["base_url", "baseUrl"])); preset.value = textValue(provider.preset, "custom"); apiKey.value = ""; privateNetwork.checked = provider.allow_private_network === true; trustRaw.checked = provider.trust_raw === true; enabledModels = new Set(providerModelIds(provider)); defaultModel.value = textValue(provider.model) || [...enabledModels][0] || ""; modelItems = [...enabledModels].map((value) => ({ id: value })); renderModels(); }, "button subtle");
          const test = button("连接测试", async () => {
            test.disabled = true;
            try { await this.api.testAiProvider({ provider_id: pid, model: textValue(provider.model) }); setStatus(status, `${textValue(provider.name, "模型服务")} 连接测试成功。`, "success"); } catch (error) { setStatus(status, apiErrorMessage(error), "danger"); } finally { test.disabled = false; }
          }, "button subtle");
          return node("div", { className: "provider-row" }, [node("strong", { text: textValue(provider.name, "未命名服务") }), node("span", { className: "muted small", text: `${textValue(provider.model, "未设置模型")} · ${provider.key_configured ? "API Key 已配置" : "未配置 API Key"} · ${providerTrustLabel(provider)}` }), edit, test]);
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
    target.append(list, form, status);
    try {
      const groups = await this.api.request("/groups");
      this.state.groups = parseJsonList(groups?.groups);
      replaceChildren(group);
      for (const item of this.state.groups) appendOption(group, groupId(item), textValue(field(item, ["name"]), "未命名分组"));
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
