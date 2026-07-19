const INTERNAL_FIELD_PATTERN =
  /\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|request[_-]?uuid|score|snippet|snnipet)\b|\b(?:article|attachment|artifact|case|citation|conversation|document|evidence|fact|file|issue|message|model|project|proposal|provider|record|request|run|source|tool(?:_?call)?|user|version)[_-]?id\b|\b(?:base[_-]?case[_-]?digest|generation[_-]?hash|input[_-]?audit|output[_-]?audit|provider[_-]?snapshot|schema[_-]?version|sha(?:256)?|source[_-]?audit)\b/iu;

const MACHINE_KEY_LINE_PATTERN =
  /^\s*(?:\{|\[|,)?\s*["']?(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|request[_-]?uuid|score|snippet|snnipet|(?:article|attachment|artifact|case|citation|conversation|document|evidence|fact|file|issue|message|model|project|proposal|provider|record|request|run|source|tool(?:_?call)?|user|version)[_-]?id|base[_-]?case[_-]?digest|generation[_-]?hash|input[_-]?audit|output[_-]?audit|provider[_-]?snapshot|schema[_-]?version|sha(?:256)?|source[_-]?audit)["']?\s*[:=]/iu;

const WINDOWS_PATH_PATTERN = /\b[A-Za-z]:[\\/](?:[^\s<>:"|?*]+[\\/]?)+/gu;
const UNC_PATH_PATTERN = /\\\\[^\s\\/]+[\\/][^\s<>:"|?*]+/gu;
const FILE_URI_PATTERN = /\bfile:\/{1,3}[^\s<>)\]}]+/giu;
const QUOTED_LOCAL_PATH_PATTERN =
  /(["'`])(?:file:\/{1,3}|[A-Za-z]:[\\/]|\\\\)[^"'`\r\n]+\1/giu;
const POSIX_PATH_PATTERN =
  /(?<![\w:/])\/(?:Users|home|tmp|var|opt|private|ProgramData|workspace|mnt)(?:\/[^\s<>)\]}]+)+/giu;
const MARKDOWN_LOCAL_LINK_PATTERN =
  /\[([^\]\r\n]*)\]\((?:file:\/{1,3}|[A-Za-z]:[\\/]|\\\\|\/(?:Users|home|tmp|var|opt|private|ProgramData|workspace|mnt)\/)[^)\r\n]+\)/giu;
const LOCAL_ENDPOINT_PATTERN = /\bhttps?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/[^\s<>)\]}]*)?/giu;
const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/giu;
const LONG_DIGEST_PATTERN = /\b(?:sha(?:256)?[:=]?)?[0-9a-f]{32,}\b/giu;
const OPAQUE_INTERNAL_ID_PATTERN =
  /\b(?:art|att|doc|file|msg|proj|prop|rec|req|run|src)[_-][0-9a-f]{12,}\b|\bservice-[0-9a-f]{8,64}-\d+\b/giu;
const RAW_CITATION_MARKER_PATTERN = /(?:\[|【)(?:SRC|CIT)(?::[^\]】\r\n]+)+(?:\]|】)/giu;
const INLINE_MACHINE_FIELD_PATTERN =
  /\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|request[_-]?uuid|score|snippet|snnipet|(?:article|attachment|artifact|case|citation|conversation|document|evidence|fact|file|issue|message|model|project|proposal|provider|record|request|run|source|tool(?:_?call)?|user|version)[_-]?id|base[_-]?case[_-]?digest|generation[_-]?hash|input[_-]?audit|output[_-]?audit|provider[_-]?snapshot|schema[_-]?version|sha(?:256)?|source[_-]?audit)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|\{[^}\r\n]*\}|\[[^\]\r\n]*\]|[^\s,;，；}]+)/giu;
const BARE_MACHINE_FIELD_PATTERN =
  /\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|request[_-]?uuid|score|snippet|snnipet|(?:article|attachment|artifact|case|citation|conversation|document|evidence|fact|file|issue|message|model|project|proposal|provider|record|request|run|source|tool(?:_?call)?|user|version)[_-]?id|base[_-]?case[_-]?digest|generation[_-]?hash|input[_-]?audit|output[_-]?audit|provider[_-]?snapshot|schema[_-]?version|sha(?:256)?|source[_-]?audit)\b/giu;
const HIDDEN_TABLE_COLUMN_PATTERN =
  /\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|request[_-]?uuid|score|snippet|snnipet|(?:article|attachment|artifact|case|citation|conversation|document|evidence|fact|file|issue|message|model|project|proposal|provider|record|request|run|source|tool(?:_?call)?|user|version)[_-]?id|base[_-]?case[_-]?digest|generation[_-]?hash|input[_-]?audit|output[_-]?audit|provider[_-]?snapshot|schema[_-]?version|sha(?:256)?|source[_-]?audit)\b|(?:稳定记录|内部记录|机器记录)\s*ID/iu;
const RAW_PARAMETER_EXPLANATION_PATTERN =
  /(?:参数|字段|实际传入|不(?:被)?支持|协议|内部调用|机器返回|原始请求|版本).*(?:\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|score|schema[_-]?version)\b)|(?:\b(?:as[_-]?of|case[_-]?date|cursor|limit|metadata|query|score|schema[_-]?version)\b).*(?:参数|字段|实际传入|不(?:被)?支持|协议|内部调用|机器返回|原始请求|版本)/iu;
const PUBLIC_PROCESS_DETAIL_PATTERN =
  /(?:结构化文书预览|模型措辞|\blegal[_-]?search\b)/iu;
const UNTITLED_PATTERN =
  /^(?:[—–-]?\s*[（(]?\s*)?(?:无标题|未命名|untitled|null|undefined|n\/a)(?:\s*[）)]\s*)?$/iu;

const PUBLIC_ERROR_BY_TYPE: Readonly<Record<string, string>> = {
  invalid_input: "输入内容不符合要求，请检查后重试。",
  not_found: "未找到所需内容，请刷新后重试。",
  permission_denied: "当前操作未获授权，请检查权限后重试。",
  limit_exceeded: "本次内容超出处理限制，请精简后重试。",
  cancelled: "操作已取消。",
  conflict: "内容已发生变化，请刷新后重试。",
  unsupported: "当前内容或操作暂不受支持。",
  provider_failure: "模型服务暂时不可用，请稍后重试。",
  citation_validation_failed: "法律引用未通过校验，结果未保存。",
  legal_paragraph_unresolved:
    "该条文包含多款，当前资料不能准确确定款次；请另选能够明确定位至具体款次的条文。",
  confirmation_required: "请先完成明确确认。",
  internal: "操作未完成，请稍后重试；如仍失败，请导出诊断报告。",
};

function recordValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function parseRecord(value: string): Record<string, unknown> | null {
  try {
    return recordValue(JSON.parse(value));
  } catch {
    return null;
  }
}

function structuredErrorType(error: unknown): string | null {
  const direct = recordValue(error);
  const parsed =
    typeof error === "string"
      ? parseRecord(error)
      : error instanceof Error
        ? parseRecord(error.message)
        : null;
  for (const candidate of [direct, parsed]) {
    if (!candidate) continue;
    for (const key of ["errorType", "error_type", "code"] as const) {
      const value = candidate[key];
      if (typeof value === "string" && value.trim()) return value.trim();
    }
  }
  return null;
}

/**
 * Public UI errors are selected from a closed vocabulary. Raw IPC/provider
 * messages belong to diagnostics and must never be rendered into the product.
 */
export function publicErrorMessage(
  error: unknown,
  fallback = "操作未完成，请重试；如仍失败，请导出诊断报告。",
): string {
  const errorType = structuredErrorType(error);
  return (errorType && PUBLIC_ERROR_BY_TYPE[errorType]) || fallback;
}

export function hasInternalEngineeringDetail(value: string): boolean {
  return (
    INTERNAL_FIELD_PATTERN.test(value) ||
    PUBLIC_PROCESS_DETAIL_PATTERN.test(value) ||
    value.search(QUOTED_LOCAL_PATH_PATTERN) >= 0 ||
    value.search(MARKDOWN_LOCAL_LINK_PATTERN) >= 0 ||
    value.search(WINDOWS_PATH_PATTERN) >= 0 ||
    value.search(UNC_PATH_PATTERN) >= 0 ||
    value.search(FILE_URI_PATTERN) >= 0 ||
    value.search(POSIX_PATH_PATTERN) >= 0 ||
    value.search(LOCAL_ENDPOINT_PATTERN) >= 0 ||
    value.search(UUID_PATTERN) >= 0 ||
    value.search(LONG_DIGEST_PATTERN) >= 0 ||
    value.search(OPAQUE_INTERNAL_ID_PATTERN) >= 0 ||
    value.search(RAW_CITATION_MARKER_PATTERN) >= 0
  );
}

function redactInlineEngineeringDetail(value: string): string {
  return cleanRedactionArtifacts(
    value
    .replace(MARKDOWN_LOCAL_LINK_PATTERN, "$1")
    .replace(QUOTED_LOCAL_PATH_PATTERN, "")
    .replace(FILE_URI_PATTERN, "")
    .replace(WINDOWS_PATH_PATTERN, "")
    .replace(UNC_PATH_PATTERN, "")
    .replace(POSIX_PATH_PATTERN, "")
    .replace(LOCAL_ENDPOINT_PATTERN, "")
    .replace(UUID_PATTERN, "")
    .replace(LONG_DIGEST_PATTERN, "")
    .replace(OPAQUE_INTERNAL_ID_PATTERN, "")
    .replace(RAW_CITATION_MARKER_PATTERN, "")
    .replace(INLINE_MACHINE_FIELD_PATTERN, "")
    .replace(/\s*\bsnippet\b\s*/giu, "内容")
    .replace(/\blegal[_-]?search\b/giu, "法律检索")
    .replace(/结构化文书预览/gu, "文书内容")
    .replace(/模型措辞/gu, "文书表述")
    .replace(/[—–-]?\s*[（(]?\s*(?:无标题|未命名|untitled)\s*[）)]?/giu, "相关条文")
    .replace(BARE_MACHINE_FIELD_PATTERN, "")
    .replace(/[（(]\s*(?:稳定记录|内部记录|机器记录)?\s*ID\s*[）)]/giu, ""),
  );
}

function cleanRedactionArtifacts(value: string): string {
  return value
    .replace(/[ \t]+([，。；：])/gu, "$1")
    .replace(/(?:[，,；;]\s*){2,}/gu, "，")
    .replace(/[，,；;]\s*([。！？!?])/gu, "$1")
    .replace(/[：:]\s*(?=[，,；;。！？!?])/gu, "")
    .replace(/[（(]\s*[）)]/gu, "")
    .replace(/\{\s*[,，]?\s*\}|\[\s*[,，]?\s*\]/gu, "")
    .replace(/\s+([|])/gu, " $1")
    .replace(/[，,；;]\s*$/gu, "")
    .replace(/[ \t]{2,}/gu, " ")
    .trimEnd();
}

function isRawParameterExplanation(value: string): boolean {
  return RAW_PARAMETER_EXPLANATION_PATTERN.test(value);
}

function markdownCells(value: string): string[] | null {
  const trimmed = value.trim();
  if (!trimmed.includes("|")) return null;
  const withoutEdges = trimmed.replace(/^\|/u, "").replace(/\|$/u, "");
  const cells = withoutEdges.split("|").map((cell) => cell.trim());
  return cells.length > 1 ? cells : null;
}

function isMarkdownSeparator(cells: readonly string[]): boolean {
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/u.test(cell));
}

function isUntitledCell(value: string): boolean {
  return UNTITLED_PATTERN.test(value.trim());
}

function sanitizedMarkdownRow(cells: readonly string[]): string {
  return `| ${cells.join(" | ")} |`;
}

function sanitizeMarkdownTable(rows: readonly string[][]): string[] {
  const header = rows[0];
  if (!header || rows.length < 2) return rows.map(sanitizedMarkdownRow);

  const hiddenIndexes = new Set<number>();
  header.forEach((cell, index) => {
    if (HIDDEN_TABLE_COLUMN_PATTERN.test(cell)) hiddenIndexes.add(index);
  });
  const titleIndex = header.findIndex((cell) => /(?:法条|法律|案例)?名称/u.test(cell));
  const sourceIndex = header.findIndex((cell) =>
    /^(?:所属文件|法律文件|来源文件|裁判文书)$/u.test(cell.trim()),
  );
  let previousSource = "";

  return rows
    .map((row, rowIndex) => {
      const cells = [...row];
      if (rowIndex >= 2 && titleIndex >= 0 && sourceIndex >= 0) {
        const source = cells[sourceIndex]?.trim() ?? "";
        if (source && source !== "同上") previousSource = source;
        if (isUntitledCell(cells[titleIndex] ?? "")) {
          cells[titleIndex] = source === "同上" ? previousSource || "相关条文" : source;
        }
      }
      const visible = cells
        .filter((_, index) => !hiddenIndexes.has(index))
        .map((cell) =>
          isMarkdownSeparator(row)
            ? cell
            : redactInlineEngineeringDetail(cell),
        );
      return visible.length > 0 ? sanitizedMarkdownRow(visible) : "";
    })
    .filter(Boolean);
}

function sanitizeMarkdownTables(lines: readonly string[]): string[] {
  const result: string[] = [];
  let index = 0;
  while (index < lines.length) {
    const header = markdownCells(lines[index] ?? "");
    const separator = markdownCells(lines[index + 1] ?? "");
    if (!header || !separator || !isMarkdownSeparator(separator)) {
      result.push(lines[index] ?? "");
      index += 1;
      continue;
    }

    const rows = [header, separator];
    index += 2;
    while (index < lines.length) {
      const row = markdownCells(lines[index] ?? "");
      if (!row) break;
      rows.push(row);
      index += 1;
    }
    result.push(...sanitizeMarkdownTable(rows));
  }
  return result;
}

function meaningfulPublicLine(value: string): boolean {
  if (value.trim() === "") return true;
  const normalized = value.replace(/[：:，,。；;、\s()[\]（）]+/gu, "");
  return !/^(?:文件|材料|结果|内容)?(?:位于|保存于|存储于|路径)?$/u.test(
    normalized,
  );
}

function isStructuredMachinePayload(value: string): boolean {
  const trimmed = value.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed !== null && typeof parsed === "object";
  } catch {
    return false;
  }
}

/**
 * Final model/artifact text crosses the public-output boundary here. Machine
 * payloads and machine-only fields are withheld; ordinary prose is preserved.
 */
export function sanitizePublicGeneratedText(
  value: string,
  fallback = "内容已完成处理，请在相应成果中查看。",
): string {
  const normalized = value.replace(/\r\n?/gu, "\n").trim();
  if (!normalized) return fallback;
  if (isStructuredMachinePayload(normalized)) return fallback;

  const keptLines = sanitizeMarkdownTables(normalized.split("\n")).filter(
    (line) =>
      !MACHINE_KEY_LINE_PATTERN.test(line) && !isRawParameterExplanation(line),
  );
  const redacted = keptLines
    .map(redactInlineEngineeringDetail)
    .filter(meaningfulPublicLine)
    .join("\n")
    .replace(/\n{3,}/gu, "\n\n")
    .trim();
  return redacted || fallback;
}

/** Source snippets are supporting prose, never a place for raw machine data. */
export function publicContentSummary(
  value: string | null | undefined,
  fallback = "内容摘要暂不可用，请打开来源查看正文。",
): string {
  if (!value?.trim()) return fallback;
  if (!/[\p{Script=Han}]/u.test(value)) return fallback;
  const normalized = sanitizePublicGeneratedText(value, fallback)
    .replace(/\s+/gu, " ")
    .trim();
  if (!/[\p{Script=Han}]/u.test(normalized)) return fallback;
  return normalized.length > 240 ? `${normalized.slice(0, 239)}…` : normalized;
}

/** Empty, placeholder, or machine-generated titles receive a semantic label. */
export function publicTitle(
  value: string | null | undefined,
  fallback: string,
): string {
  const normalized = value?.replace(/\s+/gu, " ").trim() ?? "";
  if (
    !normalized ||
    UNTITLED_PATTERN.test(normalized) ||
    hasInternalEngineeringDetail(normalized)
  ) {
    return fallback;
  }
  return normalized;
}
