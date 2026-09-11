const API_PREFIX = "/api/v1";

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const READ_METHODS = new Set(["GET", "HEAD"]);

export const ERROR_MESSAGES = Object.freeze({
  unauthenticated: "会话已失效，请重新打开本地访问链接。",
  unauthorized: "当前操作未获授权。",
  session_required: "本机会话已失效，请重新打开访问链接。",
  session_limit: "本机活动会话已达到上限，请稍后重试。",
  session_failed: "本机会话创建失败，请重试。",
  forbidden: "当前会话没有执行此操作的权限。",
  origin_rejected: "请求来源不符合本机安全策略。",
  csrf_invalid: "页面会话校验失败，请刷新后重试。",
  csrf_rejected: "页面会话校验失败，请刷新后重试。",
  invalid_request: "提交内容不完整或格式不正确。",
  invalid_response: "服务返回了无法识别的结果。",
  request_failed: "请求未完成，请稍后重试。",
  network_error: "无法连接本机服务或模型服务，请检查服务状态后重试。",
  invalid_upload: "上传内容或字段格式不正确。",
  file_required: "请选择要上传的文件。",
  document_too_large: "文书内容超过允许大小。",
  template_fields_invalid: "文书字段不完整或格式不正确。",
  group_required: "请选择材料分组。",
  request_id_required: "缺少本次导入请求编号，请重试。",
  invalid_identifier: "标识格式不正确。",
  not_found: "请求的内容不存在或已被撤销。",
  legal_query_failed: "法律库查询失败，请稍后重试。",
  invalid_search_request: "法律检索条件无效，请调整后重试。",
  invalid_pagination: "分页参数无效，请重新加载。",
  storage_object_corrupt: "本机存储中存在损坏记录，已跳过该记录；可检查工作区备份后重试。",
  legal_database_missing: "本地法律库尚未配置，请检查法律库文件后重试。",
  legal_database_unavailable: "本地法律库暂不可用，可使用官方入口查看案例。",
  unsupported_schema_version: "服务数据版本不兼容，请更新本机程序后重试。",
  page: "分页页码无效，请重新加载。",
  legal_tool_failed: "法律工具执行失败，请稍后重试。",
  legal_tool_unavailable: "法律工具暂不可用，请稍后重试。",
  judicial_case_database_incompatible: "案例库版本不兼容，请更新案例库后重试。",
  case_database_missing: "本地案例库尚未配置，可使用官方入口检索案例。",
  case_database_unavailable: "本地案例库暂不可用，可使用官方入口检索案例。",
  case_search_busy: "案例检索正在进行，请稍后再试。",
  case_understanding_invalid: "案例理解请求无效，请检查案情和检索条件后重试。",
  conflict: "内容已发生变化，请刷新后再提交。",
  revision_conflict: "材料已被其他操作更新，请重新打开后再复核。",
  idempotency_conflict: "相同请求编号对应了不同文件，请更换请求后重试。",
  task_busy: "任务正在处理中，请稍后再操作。",
  material_not_reviewable: "当前材料还不能复核，请等待提取完成。",
  source_integrity_failed: "原始文件校验失败，材料未继续处理。",
  input_changed: "收件目录中的文件在读取期间发生变化，请重试。",
  input_path_rejected: "收件路径不符合安全边界。",
  cloud_consent_required: "该材料需要先授权本批次云辅助，或手动复核。",
  manual_review_required: "该材料需要人工复核后才能发布。",
  cloud_authorization_revoked: "云辅助授权已撤销，材料需要重新处理。",
  cloud_authorization_changed: "云辅助授权绑定已变化，材料未发送。",
  cloud_response_invalid: "云端模型返回内容无法核验，材料需要重试或人工复核。",
  cloud_authorization_invalid: "云辅助授权参数无效。",
  material_changed: "材料在云辅助期间发生变化，请重新处理。",
  no_pending_materials: "当前任务没有可继续处理的材料。",
  cancelled: "任务已取消。",
  client_disconnected: "连接已断开，生成未完成。",
  privacy_text_invalid_input: "脱敏规则输入无效，请检查词语、类别和别名。",
  privacy_text_input_rejected: "文件内容未通过安全检查。",
  privacy_text_invalid_text_encoding: "文本编码无效，请指定正确编码后重试。",
  privacy_text_unsupported_text_encoding: "不支持该文本编码，请选择 UTF-8、GB18030 或 UTF-16。",
  privacy_text_unsupported_export_format: "不支持该导出格式。",
  privacy_text_cloud_finding_absent: "云辅助结果无法对应原文，材料需要人工复核。",
  privacy_text_analysis_failed: "本地脱敏识别失败，请重试或补充词典。",
  privacy_text_too_many_findings: "检测到的敏感项过多，材料需要分批处理。",
  privacy_text_result_needs_review: "脱敏结果仍需人工复核。",
  privacy_text_residual_risk: "残留敏感信息检查未通过，结果未发布。",
  privacy_text_export_verification_failed: "导出文件复核未通过，请重试。",
  extraction_failed: "文件内容提取失败，请检查文件结构后重试。",
  pdf_render_failed: "PDF 页面渲染失败，请检查文件后重试。",
  pdfium_unavailable: "PDF 处理组件不可用，请检查便携包依赖。",
  docx_extraction_incomplete: "DOCX 未完整提取（可能含图片、修订、附属文本或不支持结构），未发布完整结果；可准备纯文本 DOCX/TXT 后重试。",
  docx_corrupt_or_encrypted: "DOCX 文件损坏或已加密，无法安全提取；请准备可正常打开的纯文本 DOCX/TXT。",
  docx_unsafe_package: "DOCX 包含超限压缩包、活动内容或不安全结构，已阻止处理；请准备安全的纯文本 DOCX/TXT。",
  redaction_failed: "脱敏识别失败，请重试或补充词典。",
  redaction_requires_trusted_provider: "AI 脱敏需要已确认的可信模型服务。",
  ai_response_invalid: "模型返回内容无法核验，材料已暂停处理，可重试或人工复核。",
  ai_review_evidence_missing: "此前的 AI 识别记录需要更新，请重新处理材料后再复核。",
  review_evidence_invalid: "复核记录与当前原文不一致，请重新处理材料。",
  ai_dispatch_interrupted: "AI 脱敏任务中断，材料需要继续处理或人工复核。",
  ocr_model_not_configured: "尚未配置 OCR 模型，请先在设置中选择。",
  ocr_asset_limit_exceeded: "待识别图片页数或大小超过限制。",
  ocr_requires_trusted_provider: "OCR 模型服务未确认可发送原文，请确认服务归属。",
  ocr_response_invalid: "OCR 模型返回格式无效，请重试。",
  ocr_incomplete: "OCR 返回不完整，材料需要重试或人工复核。",
  sensitive_content_blocked: "残留敏感信息检查未通过，结果未发布。",
  batch_too_large: "批次文件过多或总大小超过 100 MB。",
  file_too_large: "单个文件超过 20 MB。",
  invalid_filename: "文件名包含不允许的路径字符。",
  unsupported_format: "不支持该文件或导出格式。",
  text_limit_exceeded: "文本内容超过允许大小。",
  result_not_ready: "脱敏结果尚未可用。",
  result_revoked: "脱敏结果已撤销，不能继续读取。",
  result_expired: "脱敏结果已过期，请重新处理材料。",
  result_integrity_failed: "脱敏结果校验失败，不能继续读取。",
  export_failed: "导出失败，请稍后重试。",
  provider_configuration_invalid: "模型服务地址或配置无效。",
  provider_authorization_invalid: "模型服务授权请求无效，请检查服务地址和 API Key。",
  provider_auth_failed: "模型服务认证失败，请检查 API Key。",
  provider_network_failed: "模型服务网络连接失败，请检查网络或稍后重试。",
  provider_timeout: "模型服务响应超时，请稍后重试。",
  provider_rate_limited: "模型服务已限流，请稍后重试。",
  provider_model_or_request_invalid: "模型或请求参数不被该服务支持。",
  model_list_invalid: "模型服务返回的模型列表格式无效。",
  enabled_models_required: "请至少启用一个模型。",
  invalid_model_purpose: "默认模型用途不受支持。",
  ai_model_required: "尚未配置可用的 AI 模型，请先前往设置。",
  model_not_enabled: "所选模型未启用，请在设置中勾选后重试。",
  invalid_ai_request: "AI 任务参数无效，请检查输入和材料。",
  case_description_required: "请提供案情描述或选择至少一份材料。",
  original_material_requires_trusted_provider: "当前模型服务未确认可发送原文，请改用脱敏材料或确认服务归属。",
  redacted_material_not_ready: "所选材料的脱敏结果尚未准备好。",
  invalid_material_source: "材料发送版本无效，请重新选择。",
  attachment_requires_trusted_provider: "当前模型服务未确认可发送附件，请改用已脱敏材料或确认服务归属。",
  invalid_attachment: "附件为空、过大或文件名不符合要求。",
  one_attachment_per_upload: "每次只能上传一个附件。",
  attachment_required: "请选择要上传的附件。",
  ai_run_interrupted: "模型任务中断，可点击继续。",
  ai_run_reauthorization_required: "继续任务前需要重新确认材料发送策略，请重新提交。",
  source_changed: "所选材料在任务期间发生变化，请重新提交。",
  invalid_binding: "任务材料校验失败，请重新选择材料。",
  material_revoked: "所选材料已撤销，请重新选择可用材料。",
  conversation_required: "请先创建或选择一个会话。",
  document_not_ready: "文书尚未生成完成，暂不能编辑或导出。",
  ai_answer_json_invalid: "模型返回格式无效，任务可继续重试。",
  ai_answer_content_missing: "模型没有返回可用正文，任务可继续重试。",
  ai_answer_content_invalid: "模型返回正文无效，任务可继续重试。",
  citation_identifier_missing: "模型返回的法律引用缺少标识。",
  citation_not_retrieved: "模型引用了未经过本地法律库核验的内容。",
  citation_not_found: "模型引用的法条或案例已无法在本地库中找到。",
  citation_quote_mismatch: "模型引用的原文与本地法律库不一致。",
  unverified_law_in_answer: "回答包含未经过本地法律库核验的法名，请重试。",
  invalid_api_key: "API Key 格式无效。",
  api_key_required: "该模型服务尚未配置 API Key。",
  api_key_required_for_new_endpoint: "更换模型服务地址后必须重新输入 API Key。",
  credential_write_failed: "API Key 保存或恢复失败，请在模型设置中重新填写并保存。",
  credential_read_failed: "API Key 读取失败。",
  provider_changed: "所选模型服务配置已变化，请重新选择 Provider 或刷新设置后重试。",
  provider_unavailable: "模型服务暂时不可用，请稍后重试。",
  provider_request_failed: "模型服务请求失败，请稍后重试。",
  provider_response_invalid: "模型服务返回格式无效。",
  provider_response_incomplete: "模型服务连接未完整结束，请稍后重试。",
  provider_response_too_large: "模型服务返回内容过大。",
  provider_empty_response: "模型服务没有返回内容。",
  provider_save_failed: "模型服务保存失败，请检查配置后重试。",
  provider_secret_echo_blocked: "模型服务返回了受保护凭据，响应已阻断。",
  internal_contract_error: "本机服务内部数据格式异常，请重试。",
  export_integrity_failed: "导出内容校验失败，请重试。",
  output_path_rejected: "导出路径不符合本机安全策略。",
  unsupported_export_format: "不支持该导出格式。",
  pdf_runtime_missing: "PDF 排版组件不可用，请检查便携包依赖。",
  pdf_runtime_failed: "PDF 排版失败，请稍后重试。",
  pdf_render_timeout: "PDF 排版超时，请稍后重试。",
  ai_cache_invalid: "模型任务缓存无法核验，请重试。",
  invalid_tool_arguments: "法律工具参数无效，请重试。",
  tool_not_allowed: "当前任务不能调用该法律工具。",
  revision_required: "缺少材料版本信息，请重新打开材料。",
  unsupported_text_encoding: "不支持该文本编码，请选择 UTF-8、GB18030 或 UTF-16。",
  conversation_busy: "该会话正在生成，请等待或取消当前生成。",
  invalid_title: "会话标题不能为空或过长。",
  context_too_large: "选择的上下文过大，请减少材料或法条。",
  capacity_exceeded: "当前任务已达到处理上限，请等待任务结束后重试。",
  context_budget_exceeded: "所选材料、附件或历史超过当前模型的上下文预算，请缩小页/段落范围后重新预检。",
  context_scope_invalid: "页或段落范围无效、已过期或不属于当前来源；请重新检查范围后再预检。",
  document_worker_timeout: "本机文档处理超时，请缩小页范围或检查文件后重试。",
  document_worker_exited: "本机文档处理意外结束，请检查文件和便携包依赖后重试。",
  invalid_model_capabilities: "模型容量超出允许范围，或输出预留不小于上下文窗口；请更正设置后保存。",
  model_tools_unsupported: "当前模型被明确声明为不支持工具调用；请更换模型，或在确认后更正能力声明。",
  model_structured_output_unsupported: "当前模型被明确声明为不支持结构化输出；请更换模型，或在确认后更正能力声明。",
  model_vision_unsupported: "当前模型被明确声明为不支持视觉附件；请移除视觉附件、更换模型，或在确认后更正能力声明。",
  context_source_removed: "准备后的材料或附件已被移除，发送前核验已停止；请重新选择范围并准备。",
  context_revision_required: "会话材料或范围已变化，原准备结果不能继续使用；请重新准备后发送。",
  context_prepare_required: "发送前范围尚未由本机服务准备并绑定；请先完成准备。",
  search_scope_conflict: "法律检索范围与本次任务已记录的范围冲突；请统一日期、版本范围和筛选条件后重试。",
  chat_authorization_failed: "对话授权失败，未发送上下文。",
  article_not_found: "所选法条不存在。",
  invalid_purpose: "云辅助用途无效。",
  not_ready: "当前内容还未准备好。",
  run_id_missing: "模型任务未返回任务编号，请重试。",
  dictionary_too_large: "分组词典条目过多。",
  dictionary_invalid: "分组词典包含无效条目，请检查敏感词类别和别名。",
  absolute_path_required: "工作区路径配置无效。",
  data_directory_unavailable: "本机数据目录不可用，请检查工作区配置。",
  runtime_unavailable: "本机运行环境不可用，请检查便携包依赖。",
  port_in_use: "本机服务端口已被占用，请关闭占用程序后重试。",
  invalid_origin: "访问来源不符合本机安全策略。",
  mcp_configuration_invalid: "MCP 配置无效，请检查本机设置。",
  server_failed: "本机服务启动失败，请检查运行日志。",
  server_not_running: "本机服务尚未运行。",
  login_unavailable: "本机登录入口暂不可用，请重新打开访问链接。",
  shutdown_unavailable: "本机服务暂不能停止。",
  shutdown_timeout: "本机服务停止超时，请稍后检查状态。",
  browser_open_failed: "无法自动打开浏览器，请复制本机访问链接。",
  windows_required: "该功能需要在 Windows 本机服务中运行。",
  workspace_backup_failed: "工作区备份失败，升级未继续。",
  privacy_backend_unavailable: "材料工作区暂时不可用，请稍后重试。",
  daemon_offline: "本机后台服务未运行，请重新启动服务。",
  backend_invalid_response: "本机后台返回内容无法核验，请重试。",
  backend_rejected: "本机后台拒绝了请求，请检查服务状态后重试。",
  invalid_daemon_configuration: "本机后台配置无效，请检查工作区设置。",
  legal_configuration_invalid: "法律库配置无效。",
  workspace_unavailable: "工作区暂时不可用，请稍后重试。",
  storage_failed: "工作区存储失败，请稍后重试。",
  storage_unavailable: "工作区存储暂时不可用。",
  file_operation_failed: "文件操作失败，请重试。",
  invalid_data: "工作区数据格式无效。",
  local_encryption_failed: "本机加密失败，数据未继续处理。",
  encrypted_object_invalid: "本机加密数据校验失败。",
  object_too_large: "工作区对象超过允许大小。",
  legacy_workspace_rejected: "检测到旧工作区，本版本不会直接打开。",
  workspace_in_use: "工作区正在被另一个进程使用。",
  unsupported_workspace_schema: "工作区版本不受支持。",
  invalid_cursor: "结果分页游标无效。",
  task_not_found: "任务不存在或不属于当前 MCP 客户端。",
  result_not_found: "结果不存在或不属于当前 MCP 客户端。",
  server_error: "服务暂时不可用，请稍后重试。"
});

export class ApiError extends Error {
  constructor(code, retryable = false, status = 0) {
    super(ERROR_MESSAGES[code] || "请求未完成，请稍后重试。");
    this.name = "ApiError";
    this.code = code || "request_failed";
    this.retryable = Boolean(retryable);
    this.status = status;
  }
}

export function apiErrorMessage(error) {
  if (error instanceof ApiError) return error.message;
  return "请求未完成，请稍后重试。";
}

function isJsonResponse(response) {
  return (response.headers.get("content-type") || "").toLowerCase().includes("application/json");
}

async function readJsonOrNull(response) {
  if (!isJsonResponse(response)) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function errorFromBody(body, status) {
  const details = body && typeof body === "object" && body.error && typeof body.error === "object"
    ? body.error
    : {};
  const fallback = status === 401 ? "unauthenticated" : status === 403 ? "forbidden" : status >= 500 ? "server_error" : "request_failed";
  return new ApiError(typeof details.code === "string" ? details.code : fallback, details.retryable === true, status);
}

function joinApiPath(path) {
  if (/^https?:\/\//iu.test(path)) return path;
  const normalized = String(path || "").startsWith("/") ? path : `/${path}`;
  return `${API_PREFIX}${normalized}`;
}

function staleSessionAbortError() {
  const error = new Error("stale_session_response");
  error.name = "AbortError";
  return error;
}

function joinedAbortSignal(...signals) {
  const active = signals.filter((signal) => signal && typeof signal.addEventListener === "function");
  if (!active.length) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => controller.abort();
  for (const signal of active) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

export class ApiClient {
  constructor({ fetchImpl, csrfToken = "", onUnauthenticated = () => {}, sessionEpoch = 0 } = {}) {
    const defaultFetch = globalThis.fetch;
    this.fetchImpl = fetchImpl || (typeof defaultFetch === "function" ? defaultFetch.bind(globalThis) : defaultFetch);
    this.csrfToken = csrfToken;
    this.onUnauthenticated = onUnauthenticated;
    // A response belongs to the browser session that started its fetch.  It
    // must never log out a newer session after the user has re-authenticated.
    this.sessionEpoch = Number.isSafeInteger(sessionEpoch) && sessionEpoch >= 0 ? sessionEpoch : 0;
    this.sessionReadController = new AbortController();
  }

  setCsrfToken(token) {
    this.csrfToken = typeof token === "string" ? token : "";
  }

  setSessionEpoch(epoch) {
    if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch === this.sessionEpoch) return;
    this.sessionEpoch = epoch;
    // Only requests that read data are attached to this signal. A write may
    // already have been accepted by the local service and must not imply that
    // its durable background task is cancelled when the browser re-auths.
    this.sessionReadController.abort();
    this.sessionReadController = new AbortController();
  }

  isSessionEpochCurrent(epoch) {
    return epoch === this.sessionEpoch;
  }

  async request(path, { method = "GET", body, headers = {}, signal } = {}) {
    const requestSessionEpoch = this.sessionEpoch;
    const upperMethod = method.toUpperCase();
    const requestSignal = READ_METHODS.has(upperMethod)
      ? joinedAbortSignal(signal, this.sessionReadController.signal)
      : signal;
    const requestHeaders = new Headers(headers);
    const hasBody = body !== undefined && body !== null;
    let requestBody = body;
    if (hasBody && !(body instanceof FormData) && !(body instanceof Blob) && typeof body !== "string") {
      requestHeaders.set("Content-Type", "application/json");
      requestBody = JSON.stringify(body);
    }
    if (WRITE_METHODS.has(upperMethod) && this.csrfToken) requestHeaders.set("X-CSRF-Token", this.csrfToken);
    requestHeaders.set("Accept", "application/json");

    let response;
    try {
      response = await this.fetchImpl(joinApiPath(path), {
        method: upperMethod,
        headers: requestHeaders,
        body: requestBody,
        credentials: "include",
        cache: "no-store",
        signal: requestSignal
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError("network_error", true, 0);
    }

    if (response.status === 401 && this.isSessionEpochCurrent(requestSessionEpoch)) this.onUnauthenticated();
    if (!response.ok) {
      const details = await readJsonOrNull(response);
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      throw errorFromBody(details, response.status);
    }
    if (response.status === 204) {
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      return null;
    }
    const result = isJsonResponse(response) ? await response.json() : await response.text();
    if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
    return result;
  }

  async download(path, options = {}) {
    const requestSessionEpoch = this.sessionEpoch;
    const upperMethod = (options.method || "GET").toUpperCase();
    const requestSignal = READ_METHODS.has(upperMethod)
      ? joinedAbortSignal(options.signal, this.sessionReadController.signal)
      : options.signal;
    const requestHeaders = new Headers(options.headers || {});
    const body = options.body;
    let requestBody = body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && !(body instanceof Blob) && typeof body !== "string") {
      requestHeaders.set("Content-Type", "application/json");
      requestBody = JSON.stringify(body);
    }
    if (WRITE_METHODS.has(upperMethod) && this.csrfToken) requestHeaders.set("X-CSRF-Token", this.csrfToken);
    let response;
    try {
      response = await this.fetchImpl(joinApiPath(path), {
        method: upperMethod,
        headers: requestHeaders,
        body: requestBody,
        credentials: "include",
        cache: "no-store",
        signal: requestSignal
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError("network_error", true, 0);
    }
    if (response.status === 401 && this.isSessionEpochCurrent(requestSessionEpoch)) this.onUnauthenticated();
    if (!response.ok) {
      const details = await readJsonOrNull(response);
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      throw errorFromBody(details, response.status);
    }
    const blob = await response.blob();
    if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
    return blob;
  }

  // The AI surface deliberately lives behind one small set of helpers.  Keeping
  // these here means every caller gets the same JSON/CSRF/session handling while
  // the UI can still use request() for extension fields added by the service.
  async listAiProviders(options = {}) {
    return this.request("/ai/providers", options);
  }

  async listGroups({ limit, cursor, ...options } = {}) {
    return this.request(`/groups${queryString({ limit, cursor })}`, options);
  }

  async saveAiProvider(provider, options = {}) {
    return this.request("/ai/providers", { ...options, method: "POST", body: provider });
  }

  async discoverAiModels(payload, options = {}) {
    return this.request("/ai/providers/models", { ...options, method: "POST", body: payload });
  }

  async testAiProvider(payload, options = {}) {
    return this.request("/ai/providers/test", { ...options, method: "POST", body: payload });
  }

  async updateAiDefaults(defaults, options = {}) {
    return this.request("/ai/defaults", { ...options, method: "PUT", body: defaults });
  }

  async listMaterials(groupId = "", { limit, cursor, ...options } = {}) {
    return this.request(`/materials${queryString({ group_id: groupId, limit, cursor })}`, options);
  }

  async listAiMaterials({ limit, cursor, ...options } = {}) {
    return this.request(`/ai/materials${queryString({ limit, cursor })}`, options);
  }

  async uploadAiAttachment(formData, options = {}) {
    return this.request("/ai/attachments", { ...options, method: "POST", body: formData });
  }

  async createAiRun(payload, options = {}) {
    return this.request("/ai/runs", { ...options, method: "POST", body: payload });
  }

  async estimateAiContext(payload, options = {}) {
    return this.request("/ai/context/estimate", { ...options, method: "POST", body: payload });
  }

  async inspectAiContextSource(payload, options = {}) {
    return this.request("/ai/context/inspect", { ...options, method: "POST", body: payload });
  }

  async listAiRuns(kind = "", { limit, cursor, ...options } = {}) {
    const path = `/ai/runs${queryString({ kind, limit, cursor })}`;
    return this.request(path, options);
  }

  async getAiRun(id, options = {}) {
    return this.request(`/ai/runs/${pathId(id)}`, options);
  }

  async deleteAiRun(id, options = {}) {
    return this.request(`/ai/runs/${pathId(id)}`, { ...options, method: "DELETE" });
  }

  async cancelAiRun(id, options = {}) {
    return this.request(`/ai/runs/${pathId(id)}/cancel`, { ...options, method: "POST", body: options.body || {} });
  }

  async continueAiRun(id, options = {}) {
    return this.request(`/ai/runs/${pathId(id)}/continue`, { ...options, method: "POST", body: options.body || {} });
  }

  async updateAiRunContent(id, content, expectedRevision, { caseDate, ...options } = {}) {
    const body = { content, expected_revision: expectedRevision };
    if (caseDate !== undefined) body.case_date = caseDate;
    return this.request(`/ai/runs/${pathId(id)}/content`, { ...options, method: "PUT", body });
  }

  async recheckAiRunCitations(id, expectedRevision, options = {}) {
    return this.request(`/ai/runs/${pathId(id)}/citations/recheck`, { ...options, method: "POST", body: { expected_revision: expectedRevision } });
  }

  async exportAiRun(id, format = "pdf", expectedRevision, options = {}) {
    return this.download(`/ai/runs/${pathId(id)}/export${queryString({ format, expected_revision: expectedRevision })}`, options);
  }

  async listAiConversations({ limit, cursor, ...options } = {}) {
    return this.request(`/ai/conversations${queryString({ limit, cursor })}`, options);
  }

  async createAiConversation(payload = {}, options = {}) {
    return this.request("/ai/conversations", { ...options, method: "POST", body: payload });
  }

  async getAiConversation(id, options = {}) {
    return this.request(`/ai/conversations/${pathId(id)}`, options);
  }

  async renameAiConversation(id, title, options = {}) {
    return this.request(`/ai/conversations/${pathId(id)}`, { ...options, method: "PATCH", body: { title } });
  }

  async updateAiConversationContext(id, payload, options = {}) {
    return this.request(`/ai/conversations/${pathId(id)}/context`, { ...options, method: "PUT", body: payload });
  }

  async prepareAiConversationContext(id, payload, options = {}) {
    return this.request(`/ai/conversations/${pathId(id)}/context/prepare`, { ...options, method: "POST", body: payload });
  }

  async getAiDraft(id, options = {}) {
    return this.request(`/ai/drafts/${pathId(id)}`, options);
  }

  async saveAiDraft(id, payload, options = {}) {
    return this.request(`/ai/drafts/${pathId(id)}`, { ...options, method: "PUT", body: payload });
  }

  async deleteAiDraft(id, expectedRevision, options = {}) {
    return this.request(`/ai/drafts/${pathId(id)}${queryString({ expected_revision: expectedRevision })}`, { ...options, method: "DELETE" });
  }

  async listAiDraftConflicts(id, { limit, cursor, ...options } = {}) {
    return this.request(`/ai/drafts/${pathId(id)}/conflicts${queryString({ limit, cursor })}`, options);
  }

  async streamChat(path, payload, { onDelta, onDone, onError, signal } = {}) {
    const requestSessionEpoch = this.sessionEpoch;
    const requestHeaders = new Headers({
      "Accept": "text/event-stream",
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    });
    if (this.csrfToken) requestHeaders.set("X-CSRF-Token", this.csrfToken);
    let response;
    try {
      response = await this.fetchImpl(joinApiPath(path), {
        method: "POST",
        headers: requestHeaders,
        body: JSON.stringify(payload),
        credentials: "include",
        cache: "no-store",
        signal
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError("network_error", true, 0);
    }
    if (response.status === 401 && this.isSessionEpochCurrent(requestSessionEpoch)) this.onUnauthenticated();
    if (!response.ok) {
      const details = await readJsonOrNull(response);
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      throw errorFromBody(details, response.status);
    }
    if (!response.body || typeof response.body.getReader !== "function") throw new ApiError("server_error", true, response.status);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const consumeLine = (line) => {
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(":")) return;
      const data = trimmed.startsWith("data:") ? trimmed.slice(5).trim() : "";
      if (!data) return;
      let event;
      try {
        event = JSON.parse(data);
      } catch {
        onError?.(new ApiError("server_error", true, response.status));
        return;
      }
      if (event.type === "delta" && typeof event.text === "string") onDelta?.(event.text);
      else if (event.type === "done") onDone?.(event);
      else if (event.type === "error") onError?.(new ApiError(typeof event.code === "string" ? event.code : "server_error", false, response.status));
    };

    while (true) {
      const { value, done } = await reader.read();
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) {
        await reader.cancel().catch(() => {});
        throw staleSessionAbortError();
      }
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const lines = buffer.split(/\r?\n/u);
      buffer = lines.pop() || "";
      for (const line of lines) consumeLine(line);
      if (done) break;
    }
    if (buffer) {
      if (!this.isSessionEpochCurrent(requestSessionEpoch)) throw staleSessionAbortError();
      consumeLine(buffer);
    }
  }
}

export function pathId(id) {
  return encodeURIComponent(String(id));
}

export function splitIds(value) {
  return String(value || "")
    .split(/[\s,，、]+/u)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function queryString(values) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values || {})) {
    if (value !== undefined && value !== null && String(value).trim()) params.set(key, String(value).trim());
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}
