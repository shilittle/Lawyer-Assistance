const API_PREFIX = "/api/v1";

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

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
  invalid_upload: "上传内容或字段格式不正确。",
  group_required: "请选择材料分组。",
  request_id_required: "缺少本次导入请求编号，请重试。",
  invalid_identifier: "标识格式不正确。",
  not_found: "请求的内容不存在或已被撤销。",
  legal_query_failed: "法律库查询失败，请稍后重试。",
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
  docx_extraction_incomplete: "DOCX 未完整提取（可能含图片、修订、附属文本或不支持结构），未发布完整结果；可准备纯文本 DOCX/TXT 后重试。",
  docx_corrupt_or_encrypted: "DOCX 文件损坏或已加密，无法安全提取；请准备可正常打开的纯文本 DOCX/TXT。",
  docx_unsafe_package: "DOCX 包含超限压缩包、活动内容或不安全结构，已阻止处理；请准备安全的纯文本 DOCX/TXT。",
  redaction_failed: "脱敏识别失败，请重试或补充词典。",
  sensitive_content_blocked: "残留敏感信息检查未通过，结果未发布。",
  batch_too_large: "批次文件过多或总大小超过 100 MB。",
  file_too_large: "单个文件超过 20 MB。",
  invalid_filename: "文件名包含不允许的路径字符。",
  unsupported_format: "不支持该文件或导出格式。",
  result_not_ready: "脱敏结果尚未可用。",
  result_revoked: "脱敏结果已撤销，不能继续读取。",
  result_expired: "脱敏结果已过期，请重新处理材料。",
  result_integrity_failed: "脱敏结果校验失败，不能继续读取。",
  export_failed: "导出失败，请稍后重试。",
  provider_configuration_invalid: "模型服务地址或配置无效。",
  invalid_api_key: "API Key 格式无效。",
  api_key_required: "该模型服务尚未配置 API Key。",
  credential_write_failed: "API Key 保存失败。",
  credential_read_failed: "API Key 读取失败。",
  provider_changed: "模型服务配置已变化，请重新提交。",
  provider_unavailable: "模型服务暂时不可用，请稍后重试。",
  provider_request_failed: "模型服务请求失败，请稍后重试。",
  provider_response_invalid: "模型服务返回格式无效。",
  provider_response_incomplete: "模型服务连接未完整结束，请稍后重试。",
  provider_response_too_large: "模型服务返回内容过大。",
  provider_empty_response: "模型服务没有返回内容。",
  provider_secret_echo_blocked: "模型服务返回了受保护凭据，响应已阻断。",
  conversation_busy: "该会话正在生成，请等待或取消当前生成。",
  context_too_large: "选择的上下文过大，请减少材料或法条。",
  chat_authorization_failed: "对话授权失败，未发送上下文。",
  article_not_found: "所选法条不存在。",
  invalid_purpose: "云辅助用途无效。",
  not_ready: "当前内容还未准备好。",
  dictionary_too_large: "分组词典条目过多。",
  dictionary_invalid: "分组词典包含无效条目，请检查敏感词类别和别名。",
  absolute_path_required: "工作区路径配置无效。",
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

export class ApiClient {
  constructor({ fetchImpl, csrfToken = "", onUnauthenticated = () => {} } = {}) {
    const defaultFetch = globalThis.fetch;
    this.fetchImpl = fetchImpl || (typeof defaultFetch === "function" ? defaultFetch.bind(globalThis) : defaultFetch);
    this.csrfToken = csrfToken;
    this.onUnauthenticated = onUnauthenticated;
  }

  setCsrfToken(token) {
    this.csrfToken = typeof token === "string" ? token : "";
  }

  async request(path, { method = "GET", body, headers = {}, signal } = {}) {
    const upperMethod = method.toUpperCase();
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
        signal
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError("network_error", true, 0);
    }

    if (response.status === 401) this.onUnauthenticated();
    if (!response.ok) throw errorFromBody(await readJsonOrNull(response), response.status);
    if (response.status === 204) return null;
    if (isJsonResponse(response)) return response.json();
    return response.text();
  }

  async download(path, options = {}) {
    const upperMethod = (options.method || "GET").toUpperCase();
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
        signal: options.signal
      });
    } catch (error) {
      if (error && error.name === "AbortError") throw error;
      throw new ApiError("network_error", true, 0);
    }
    if (response.status === 401) this.onUnauthenticated();
    if (!response.ok) throw errorFromBody(await readJsonOrNull(response), response.status);
    return response.blob();
  }

  async streamChat(path, payload, { onDelta, onDone, onError, signal } = {}) {
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
    if (response.status === 401) this.onUnauthenticated();
    if (!response.ok) throw errorFromBody(await readJsonOrNull(response), response.status);
    if (!response.body || typeof response.body.getReader !== "function") throw new ApiError("server_error", true, response.status);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const consumeLine = (line) => {
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
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const lines = buffer.split(/\r?\n/u);
      buffer = lines.pop() || "";
      for (const line of lines) consumeLine(line);
      if (done) break;
    }
    if (buffer) consumeLine(buffer);
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
