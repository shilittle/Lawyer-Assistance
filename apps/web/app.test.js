import test from "node:test";
import assert from "node:assert/strict";
import { materialReviewDecision } from "./app.js";
import { ApiClient, ApiError, ERROR_MESSAGES, pathId, queryString, splitIds } from "./api.js";
import { AI_RUN_KINDS, CASE_TYPES, ENTITY_KINDS, adaptiveLegalPageSize, aiDefaultSelection, aiRunProgress, aiRunProgressText, aiRunStatusLabel, caseUnderstandPayload, caseSourceLabel, caseStatusLabel, caseTypeLabel, caseWarningLabel, field, legalArticleDisplayTitle, legalArticleDocumentId, legalCaseSearchParams, legalFacetLabel, legalRelationTarget, legalSearchPageParams, markdownPlainText, markdownToHtml, materialStatusTone, mcpClientDetails, normalizeAiRun, normalizeCaseSearchResponse, normalizeLegalPageResponse, optionalAlias, pipelineStageLabel, providerModelIds, providerPresetForBaseUrl, reasonLabel, safeExternalUrl, statusLabel, textValue } from "./app.js";

test("status presentation has safe Chinese labels and tones", () => {
  assert.equal(statusLabel("needs_review"), "待复核");
  assert.equal(statusLabel("completed"), "已完成");
  assert.equal(statusLabel("awaiting_consent"), "等待云辅助授权");
  assert.equal(statusLabel("partial"), "部分完成");
  assert.equal(statusLabel("unknown_status"), "待核验");
  assert.equal(reasonLabel("ai_dispatch_interrupted"), "AI 任务中断");
  assert.equal(pipelineStageLabel("ocr_running"), "视觉 OCR 识别中");
  assert.equal(legalFacetLabel("type", "law"), "法律");
  assert.equal(materialStatusTone("ready"), "success");
  assert.equal(materialStatusTone("needs_review"), "warning");
  assert.equal(materialStatusTone("failed"), "danger");
  assert.equal(materialStatusTone("processing"), "info");
});

test("privacy kinds and aliases follow the workspace service vocabulary", () => {
  assert.ok(ENTITY_KINDS.includes("person_name"));
  assert.ok(ENTITY_KINDS.includes("organization_name"));
  assert.ok(ENTITY_KINDS.includes("phone_number"));
  assert.equal(optionalAlias("  "), null);
  assert.equal(optionalAlias("[PERSON_abc]"), "[PERSON_abc]");
});

test("manual review preserves completed replacements and requires explicit dismissal", () => {
  const name = { id: "name", text: "合成姓名", kind: "person_name", source: "local_ner", alias: "[PERSON_a]", resolved: true, dismissed: false };
  assert.deepEqual(materialReviewDecision(name), { canDismiss: true, ignored: false, dismissedId: null, entry: null });
  assert.equal(materialReviewDecision(name, "[PERSON_b]").entry.alias, "[PERSON_b]");
  const role = { id: "role", text: "原告", kind: "custom", source: "ai", alias: "[CUSTOM_a]", resolved: false, dismissed: false };
  assert.equal(materialReviewDecision(role).dismissedId, null);
  assert.deepEqual(materialReviewDecision(role, role.alias, true), { canDismiss: true, ignored: true, dismissedId: "role", entry: null });
  const phone = { ...name, kind: "phone_number", source: "deterministic" };
  assert.equal(materialReviewDecision(phone, phone.alias, true).dismissedId, null);
});

test("backend static failure codes keep actionable user messages", () => {
  assert.match(ERROR_MESSAGES.privacy_text_invalid_text_encoding, /指定/);
  assert.match(ERROR_MESSAGES.revision_conflict, /重新打开/);
  assert.match(ERROR_MESSAGES.result_revoked, /撤销/);
  assert.match(ERROR_MESSAGES.result_expired, /过期/);
  assert.match(ERROR_MESSAGES.provider_configuration_invalid, /地址/);
  assert.match(ERROR_MESSAGES.provider_response_incomplete, /未完整结束/);
  assert.match(ERROR_MESSAGES.provider_network_failed, /网络/);
  assert.match(ERROR_MESSAGES.provider_timeout, /超时/);
  assert.match(ERROR_MESSAGES.provider_rate_limited, /限流/);
  assert.match(ERROR_MESSAGES.original_material_requires_trusted_provider, /脱敏材料/);
  assert.match(ERROR_MESSAGES.ocr_model_not_configured, /OCR/);
  assert.match(ERROR_MESSAGES.case_search_busy, /稍后/);
  assert.match(ERROR_MESSAGES.case_understanding_invalid, /案情/);
  assert.match(ERROR_MESSAGES.legal_database_missing, /法律库/);
  assert.match(ERROR_MESSAGES.provider_changed, /Provider/);
  assert.match(ERROR_MESSAGES.dictionary_invalid, /词典/);
  assert.match(ERROR_MESSAGES.docx_extraction_incomplete, /未完整提取/);
  assert.match(ERROR_MESSAGES.docx_corrupt_or_encrypted, /损坏或已加密/);
  assert.match(ERROR_MESSAGES.docx_unsafe_package, /不安全结构/);
  assert.match(ERROR_MESSAGES.ai_run_reauthorization_required, /确认/);
  assert.match(ERROR_MESSAGES.material_revoked, /撤销/);
});

test("request helpers preserve identifiers and omit empty query values", () => {
  assert.equal(pathId("a/b?c"), "a%2Fb%3Fc");
  assert.deepEqual(splitIds("a, b\n中文，c"), ["a", "b", "中文", "c"]);
  assert.equal(queryString({ query: "  人民法  ", case_date: "", page: 0 }), "?query=%E4%BA%BA%E6%B0%91%E6%B3%95&page=0");
});

test("field and textValue avoid turning objects into visible sensitive text", () => {
  const source = { name: "合同.txt", revision: 4 };
  assert.equal(field(source, ["missing", "name"]), "合同.txt");
  assert.equal(textValue(source), "");
  assert.equal(textValue(null, "缺省"), "缺省");
});

test("MCP client details expose the authenticated inbox and resolved group label", () => {
  const details = mcpClientDetails(
    { group_id: "group-1", inbox: "C:\\LawyerAssistance\\inbox\\client-1" },
    [{ id: "group-1", name: "测试材料组" }],
  );
  assert.deepEqual(details, {
    groupId: "group-1",
    groupName: "测试材料组",
    inbox: "C:\\LawyerAssistance\\inbox\\client-1",
  });
  const missing = mcpClientDetails({ group_id: "group-404" }, []);
  assert.equal(missing.groupName, "未找到分组");
  assert.equal(missing.inbox, "");
});

test("legal result helpers use article and document identifiers from the camelCase service contract", () => {
  const article = {
    articleId: "civil-code-465",
    documentId: "civil-code",
    documentTitle: "中华人民共和国民法典",
    articleNumber: "第四百六十五条",
    articleTitle: "依法成立合同的效力",
  };
  assert.equal(legalArticleDocumentId(article), "civil-code");
  assert.equal(legalArticleDisplayTitle(article), "中华人民共和国民法典 · 第四百六十五条 · 依法成立合同的效力");
  assert.deepEqual(
    legalRelationTarget({ fromDocumentId: "civil-code", fromTitle: "民法典", toDocumentId: "contract-law", toTitle: "合同法" }, "civil-code"),
    { documentId: "contract-law", title: "合同法" },
  );
});

test("case search helpers keep the API contract and normalize bounded responses", () => {
  assert.deepEqual(legalCaseSearchParams("  劳动关系  ", CASE_TYPES.guiding, 40), {
    query: "劳动关系",
    case_type: "guiding",
    limit: 20,
    offset: 40,
    include_withdrawn: false
  });
  assert.equal(legalCaseSearchParams("历史", CASE_TYPES.all, 0, true).include_withdrawn, true);
  assert.deepEqual(caseUnderstandPayload(" 案情 ", "provider-1", "model-a", CASE_TYPES.reference), {
    query: "案情",
    provider_id: "provider-1",
    model: "model-a",
    include_withdrawn: false,
    case_type: "reference"
  });
  assert.equal(caseUnderstandPayload("历史案情", "provider-1", "model-a", CASE_TYPES.all, true).include_withdrawn, true);
  assert.equal(caseTypeLabel("guiding"), "指导案例");
  assert.equal(caseTypeLabel("reference"), "参考案例");
  assert.equal(caseTypeLabel("typical"), "典型案例合集");
  assert.deepEqual(legalCaseSearchParams("合集", CASE_TYPES.typical, 20).case_type, "typical");
  assert.equal(caseUnderstandPayload("合集案情", "provider-1", "model-a", CASE_TYPES.typical).case_type, "typical");
  assert.equal(caseStatusLabel("published"), "已发布");
  assert.equal(caseStatusLabel("withdrawn"), "不再参照");
  assert.equal(caseStatusLabel("unknown_machine_code"), "待核验");
  assert.equal(caseWarningLabel("ai_interpretation_requires_review"), "AI 理解结果需要人工核验。");
  assert.equal(caseSourceLabel({ sourceUrl: "https://www.court.gov.cn/shenpan/gengduo/77.html" }), "最高人民法院官网");
  assert.equal(caseSourceLabel({ sourceUrl: "https://rmfyalk.court.gov.cn/" }), "人民法院案例库");
  assert.deepEqual(normalizeCaseSearchResponse({ results: { cases: [{ caseId: "c-1" }], total: 1, databaseVersion: "v1", warnings: ["提示"] } }), {
    schemaVersion: "",
    cases: [{ caseId: "c-1" }],
    total: 1,
    limit: 20,
    offset: 0,
    databaseVersion: "v1",
    warnings: ["提示"]
  });
  assert.equal(normalizeCaseSearchResponse({ cases: [], total: 41 }, { offset: 20, limit: 20 }).offset, 20);
});

test("case source links allow only safe absolute HTTP(S) URLs", () => {
  assert.equal(safeExternalUrl("https://rmfyalk.court.gov.cn/case?id=1"), "https://rmfyalk.court.gov.cn/case?id=1");
  assert.equal(safeExternalUrl("javascript:alert(1)"), "");
  assert.equal(safeExternalUrl("data:text/html,<h1>bad</h1>"), "");
  assert.equal(safeExternalUrl("https://user:password@example.com/"), "");
});

test("ApiClient sends JSON writes with CSRF and credentials", async () => {
  const calls = [];
  const client = new ApiClient({
    csrfToken: "csrf-test",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  const response = await client.request("/groups", { method: "POST", body: { name: "测试分组" } });
  assert.deepEqual(response, { ok: true });
  assert.equal(calls[0].url, "/api/v1/groups");
  assert.equal(calls[0].options.credentials, "include");
  assert.equal(calls[0].options.cache, "no-store");
  assert.equal(calls[0].options.headers.get("X-CSRF-Token"), "csrf-test");
  assert.equal(calls[0].options.headers.get("Content-Type"), "application/json");
  assert.deepEqual(JSON.parse(calls[0].options.body), { name: "测试分组" });
});

test("ApiClient keeps structured backend error code and retryability", async () => {
  const client = new ApiClient({
    fetchImpl: async () => new Response(JSON.stringify({ error: { code: "cloud_consent_required", retryable: false } }), { status: 409, headers: { "content-type": "application/json" } })
  });
  await assert.rejects(() => client.request("/imports"), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, "cloud_consent_required");
    assert.equal(error.retryable, false);
    assert.match(error.message, /云辅助/);
    return true;
  });
});

test("streamChat parses split SSE frames and exposes deltas without HTML rendering", async () => {
  const encoder = new TextEncoder();
  const chunks = [
    encoder.encode('data: {"type":"delta","text":"你好"}\n\n'),
    encoder.encode('data: {"type":"delta","text":"，当事人"}\n\n'),
    encoder.encode('data: {"type":"done"}\n\n')
  ];
  const stream = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    }
  });
  const deltas = [];
  let done = false;
  const client = new ApiClient({ fetchImpl: async () => new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } }) });
  await client.streamChat("/chat", { message: "问题" }, { onDelta: (text) => deltas.push(text), onDone: () => { done = true; } });
  assert.deepEqual(deltas, ["你好", "，当事人"]);
  assert.equal(done, true);
});

test("AI and legal page helpers keep wire values bounded and Chinese labels readable", () => {
  assert.equal(AI_RUN_KINDS.writing, "writing");
  assert.equal(aiRunStatusLabel("running"), "生成中");
  assert.deepEqual(normalizeAiRun({ run_id: "run-1", kind: "writing", status: "completed", markdown: "# 文书" }), {
    run_id: "run-1", kind: "writing", status: "completed", markdown: "# 文书", id: "run-1", stage: "", prompt: "", title: "未命名任务", content: "# 文书", html: "", citations: [], tool_steps: [], error_code: "", usage: null
  });
  assert.deepEqual(legalSearchPageParams({ query: " 合同 ", type: "local", sort: "relevance", pageSize: 500, offset: -4 }), {
    query: "合同", document_type: "local", sort: "relevance", view: "grouped", limit: 100, offset: 0
  });
  const page = normalizeLegalPageResponse({ laws: [{ law: { title: "民法典" }, matchedArticleCount: 2, topArticles: [{ articleId: "a-1" }] }], total: 41, totalLaws: 41, totalArticles: 64, limit: 12, offset: 24, view: "grouped" });
  assert.equal(page.total, 41);
  assert.equal(page.limit, 12);
  assert.equal(page.offset, 24);
  assert.equal(page.totalArticles, 64);
  assert.equal(page.groups[0].topArticles[0].articleId, "a-1");
  assert.equal(aiRunProgress({ status: "running", stage: "正在读取材料" }), 20);
  assert.match(aiRunProgressText({ status: "completed" }), /进度 100%/u);
  assert.equal(markdownPlainText("# 标题\n\n- 内容\n\n[法条](https://example.com)"), "标题\n\n内容\n\n法条");
  assert.match(markdownToHtml("# 标题\n\n<script>alert(1)</script>"), /&lt;script&gt;/u);
  assert.doesNotMatch(markdownToHtml("# 标题\n\n<script>alert(1)</script>"), /<script>/u);
});

test("adaptive legal page size uses the visible container and measured result rows", () => {
  const row = (height) => ({ hidden: false, offsetHeight: height, getBoundingClientRect: () => ({ height }) });
  const target = {
    clientHeight: 300,
    dataset: {},
    children: [row(120), row(86)],
    getBoundingClientRect: () => ({ top: 200, height: 300 })
  };
  assert.equal(adaptiveLegalPageSize(target, 12), 2);
  const placeholder = { hidden: false, classList: { contains: (name) => name === "empty-state" }, getBoundingClientRect: () => ({ height: 52 }) };
  assert.equal(adaptiveLegalPageSize({ clientHeight: 300, dataset: { rowHeight: "120" }, children: [placeholder], getBoundingClientRect: () => ({ top: 0, height: 300 }) }, 12), 2);
  assert.equal(adaptiveLegalPageSize({ clientHeight: 0, children: [], getBoundingClientRect: () => ({ top: 0, height: 0 }) }, 12), 12);
  assert.equal(adaptiveLegalPageSize({ clientHeight: 1, children: [], getBoundingClientRect: () => ({ top: 0, height: 1 }) }, 12), 1);
});

test("provider model choices honor enabled lists, role defaults, and trusted preset URLs", () => {
  assert.deepEqual(providerModelIds({ enabled_models: ["glm-5.3-flash", "glm-4"], model: "glm-5.3-flash" }), ["glm-5.3-flash", "glm-4"]);
  assert.deepEqual(providerModelIds({ enabledModels: ["m-1", "m-2"], model: "m-1" }), ["m-1", "m-2"]);
  const defaults = {
    writing: { provider_id: "p1", model: "m-writing" },
    ocr: { provider_id: "p1", model: "m-ocr" }
  };
  assert.deepEqual(aiDefaultSelection(defaults, "writing"), { providerId: "p1", model: "m-writing" });
  assert.deepEqual(aiDefaultSelection(defaults, "ocr"), { providerId: "p1", model: "m-ocr" });
  assert.equal(providerPresetForBaseUrl("https://open.bigmodel.cn/api/paas/v4/" )?.preset, "glm");
  assert.equal(providerPresetForBaseUrl("https://open.bigmodel.cn.evil.example/api/paas/v4"), null);
});

test("AI client wrappers use the unified /api/v1/ai contract", async () => {
  const calls = [];
  const client = new ApiClient({
    csrfToken: "csrf-ai",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ ok: true, models: [] }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  await client.discoverAiModels({ preset: "zhipu", base_url: "https://example.com" });
  await client.updateAiDefaults({ ocr: { provider_id: "p1", model: "glm-5.3-flash" } });
  await client.getAiRun("run/1");
  assert.equal(calls[0].url, "/api/v1/ai/providers/models");
  assert.equal(calls[0].options.headers.get("X-CSRF-Token"), "csrf-ai");
  assert.equal(calls[1].url, "/api/v1/ai/defaults");
  assert.equal(calls[2].url, "/api/v1/ai/runs/run%2F1");
});
