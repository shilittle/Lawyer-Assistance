import test from "node:test";
import assert from "node:assert/strict";
import { materialReviewDecision } from "./app.js";
import { ApiClient, ApiError, ERROR_MESSAGES, pathId, queryString, splitIds } from "./api.js";
import { AI_RUN_KINDS, AI_RUN_POLL_MAX_CONSECUTIVE_FAILURES, AiRunPoller, CASE_TYPES, ENTITY_KINDS, adaptiveLegalPageSize, aiRunPollBackoffDelay, aiDefaultSelection, aiRunProgress, aiRunProgressText, aiRunRevision, aiRunStatusLabel, caseUnderstandPayload, caseSourceLabel, caseStatusLabel, caseTypeLabel, caseWarningLabel, conversationContextRevision, field, isRetryableAiPollError, legalArticleDisplayTitle, legalArticleDocumentId, legalCaseSearchParams, legalDateValue, legalFacetLabel, legalMatchMode, legalRelationTarget, legalQueryScopeSummary, legalScopedReadParams, legalSearchPageParams, legalVersionScope, markdownPlainText, markdownToHtml, materialStatusTone, mcpClientDetails, normalizeAiRun, normalizeCaseSearchResponse, normalizeCursorPage, normalizeLegalPageResponse, optionalAlias, pipelineStageLabel, providerModelIds, providerPresetForBaseUrl, reasonLabel, safeExternalUrl, statusLabel, textValue, writingDraftContent, writingDraftRestorePlan, citationCheckLabel, citationErrorCategoryLabel, citationVerificationReasonLabel, citationVerificationStateLabel, contextBudgetStageLabel, contextEstimateCanProceed, contextOmissionReasonLabel, modelCapabilitiesPayload, normalizeAiContextEstimate, normalizeCitationVerification } from "./app.js";

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
  assert.match(ERROR_MESSAGES.storage_object_corrupt, /损坏/);
  assert.match(ERROR_MESSAGES.invalid_pagination, /分页/);
  assert.match(ERROR_MESSAGES.workspace_backup_failed, /备份/);
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
    run_id: "run-1", kind: "writing", status: "completed", markdown: "# 文书", id: "run-1", stage: "", prompt: "", title: "未命名任务", content: "# 文书", html: "", citations: [], citationVerification: { state: "legacy_pending", reasons: [], bodySha256: "", runRevision: 0, caseDate: "", verifiedAt: "", sources: [] }, tool_steps: [], error_code: "", usage: null
  });
  assert.deepEqual(legalSearchPageParams({ query: " 合同 ", type: "local", sort: "relevance", pageSize: 500, offset: -4 }), {
    query: "合同", matchMode: "all", versionScope: "current", document_type: "local", sort: "relevance", view: "grouped", limit: 100, offset: 0
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

test("legal search modes preserve an explicit valid date scope and fail closed for unknown dates", () => {
  assert.equal(legalDateValue("2024-02-29"), "2024-02-29");
  assert.equal(legalDateValue("2023-02-29"), "");
  assert.equal(legalDateValue("未知"), "");
  assert.equal(legalMatchMode("any"), "any");
  assert.equal(legalMatchMode("or"), "all");
  assert.equal(legalVersionScope("as_of"), "as_of");
  assert.equal(legalVersionScope("historical"), "current");
  assert.deepEqual(legalSearchPageParams({
    query: "劳动 合同",
    documentId: "law-1",
    matchMode: "phrase",
    versionScope: "as_of",
    versionStatus: "amended",
    caseDate: "2024-02-29",
    pageSize: 15,
    offset: 30
  }), {
    query: "劳动 合同",
    document_id: "law-1",
    case_date: "2024-02-29",
    matchMode: "phrase",
    versionScope: "as_of",
    versionStatus: "amended",
    sort: "relevance",
    view: "grouped",
    limit: 15,
    offset: 30
  });
  const current = legalSearchPageParams({ query: "劳动 合同", caseDate: "2024-02-29", versionScope: "current", versionStatus: "amended" });
  assert.equal("case_date" in current, false);
  assert.equal("versionStatus" in current, false);
  const invalidDate = legalSearchPageParams({ query: "劳动 合同", caseDate: "未知", versionScope: "as_of" });
  assert.equal("case_date" in invalidDate, false);
});

test("scoped legal reads and AI run metadata retain their recorded range", () => {
  assert.deepEqual(legalScopedReadParams({ versionScope: "as_of", asOf: "2020-02-29" }), { versionScope: "as_of", caseDate: "2020-02-29" });
  assert.deepEqual(legalScopedReadParams({ version_scope: "as_of", case_date: "未知" }), { versionScope: "as_of" });
  assert.deepEqual(legalScopedReadParams({ versionScope: "all", asOf: "2020-02-29" }), { versionScope: "all" });
  assert.equal(legalQueryScopeSummary({ match_mode: "phrase", version_scope: "as_of", case_date: "2021-05-01", version_status: "amended" }), "检索条件：完整短语匹配 · 适用日期 2021-05-01 · 状态 已修订");
  assert.equal(legalQueryScopeSummary({ id: "old-run" }), "该历史任务未记录检索范围。");
});

test("cursor pages normalize additive pagination fields without inventing records", () => {
  assert.deepEqual(normalizeCursorPage({ materials: [{ id: "m-1" }], next_cursor: "opaque-next", total: 61, corrupt_count: 2 }, ["materials"]), {
    items: [{ id: "m-1" }], nextCursor: "opaque-next", total: 61, corruptCount: 2
  });
  assert.deepEqual(normalizeCursorPage({ conversations: "not-an-array", total: -1, corruptCount: -1 }, ["conversations"]), {
    items: [], nextCursor: "", total: 0, corruptCount: 0
  });
});

test("legal page response retains server-applied scope and selectable law-name ambiguities", () => {
  const page = normalizeLegalPageResponse({
    items: [],
    total: 0,
    limit: 20,
    offset: 0,
    appliedQuery: { matchMode: "phrase", versionScope: "as_of", asOf: "2020-01-01", resolvedDocumentId: "law-2", exactArticleNumber: "12" },
    ambiguities: [{ query: "劳动法", candidates: [{ documentId: "law-1", title: "中华人民共和国劳动法" }, { document_id: "law-2", document_title: "劳动合同法" }] }]
  });
  assert.deepEqual(page.appliedQuery, { matchMode: "phrase", versionScope: "as_of", asOf: "2020-01-01", resolvedDocumentId: "law-2", exactArticleNumber: "12" });
  assert.deepEqual(page.ambiguities, [{ query: "劳动法", candidates: [{ documentId: "law-1", title: "中华人民共和国劳动法" }, { documentId: "law-2", title: "劳动合同法" }] }]);
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

test("cursor-list wrappers preserve opaque cursors across workspace lists", async () => {
  const calls = [];
  const client = new ApiClient({
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  await client.listGroups({ limit: 50, cursor: "group-next/+" });
  await client.listMaterials("group/1", { limit: 50, cursor: "material-next" });
  await client.listAiMaterials({ limit: 50, cursor: "ai-material-next" });
  await client.listAiRuns("writing", { limit: 20, cursor: "run-next" });
  await client.listAiConversations({ limit: 20, cursor: "conversation-next" });
  assert.deepEqual(calls.map((call) => call.url), [
    "/api/v1/groups?limit=50&cursor=group-next%2F%2B",
    "/api/v1/materials?group_id=group%2F1&limit=50&cursor=material-next",
    "/api/v1/ai/materials?limit=50&cursor=ai-material-next",
    "/api/v1/ai/runs?kind=writing&limit=20&cursor=run-next",
    "/api/v1/ai/conversations?limit=20&cursor=conversation-next"
  ]);
});

test("revision-bound draft, context, edit, recheck, estimate, and export wrappers preserve their contracts", async () => {
  const calls = [];
  const client = new ApiClient({
    csrfToken: "csrf-revision",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  await client.updateAiRunContent("run/1", "修订正文", 7);
  await client.updateAiRunContent("run/1", "修改日期", 8, { caseDate: null });
  await client.recheckAiRunCitations("run/1", 8);
  await client.estimateAiContext({ kind: "writing", prompt: "案情", provider_id: "p-1", model: "m-1" });
  await client.exportAiRun("run/1", "pdf", 8);
  await client.updateAiConversationContext("conversation/1", { expected_revision: 3, materials: [], attachment_ids: ["a-1"] });
  await client.prepareAiConversationContext("conversation/1", { expected_revision: 3, provider_id: "p-1", model: "m-1" });
  await client.getAiDraft("writing/current");
  await client.saveAiDraft("writing/current", { expected_revision: 4, content: { dirty: true } });
  await client.deleteAiDraft("writing/current", 5);

  assert.equal(calls[0].url, "/api/v1/ai/runs/run%2F1/content");
  assert.deepEqual(JSON.parse(calls[0].options.body), { content: "修订正文", expected_revision: 7 });
  assert.deepEqual(JSON.parse(calls[1].options.body), { content: "修改日期", expected_revision: 8, case_date: null });
  assert.equal(calls[2].url, "/api/v1/ai/runs/run%2F1/citations/recheck");
  assert.deepEqual(JSON.parse(calls[2].options.body), { expected_revision: 8 });
  assert.equal(calls[3].url, "/api/v1/ai/context/estimate");
  assert.deepEqual(JSON.parse(calls[3].options.body), { kind: "writing", prompt: "案情", provider_id: "p-1", model: "m-1" });
  assert.equal(calls[4].url, "/api/v1/ai/runs/run%2F1/export?format=pdf&expected_revision=8");
  assert.equal(calls[5].url, "/api/v1/ai/conversations/conversation%2F1/context");
  assert.deepEqual(JSON.parse(calls[5].options.body), { expected_revision: 3, materials: [], attachment_ids: ["a-1"] });
  assert.equal(calls[6].url, "/api/v1/ai/conversations/conversation%2F1/context/prepare");
  assert.equal(calls[7].url, "/api/v1/ai/drafts/writing%2Fcurrent");
  assert.equal(calls[8].url, "/api/v1/ai/drafts/writing%2Fcurrent");
  assert.deepEqual(JSON.parse(calls[8].options.body), { expected_revision: 4, content: { dirty: true } });
  assert.equal(calls[9].url, "/api/v1/ai/drafts/writing%2Fcurrent?expected_revision=5");
});

test("citation verification exposes only mechanical checks and safe bindings", () => {
  const verification = normalizeCitationVerification({
    state: "passed",
    reasons: ["quote_mismatch", "internal_stack_trace"],
    body_sha256: "abcdef0123456789abcdef0123456789",
    run_revision: 6,
    case_date: "2026-09-10",
    verified_at: "2026-09-10T08:00:00Z",
    sources: [{
      source_kind: "legal_article",
      source_id: "civil-code-465",
      document_id: "civil-code",
      citation_locator: "page:2",
      source_full_text_sha256: "1234567890abcdef1234567890abcdef",
      quote_sha256: "fedcba0987654321fedcba0987654321",
      matched_ranges: [{ start_byte: 20, end_byte: 44 }],
      source_exists: "passed",
      full_text_read: "unavailable",
      citation_match: "ambiguous",
      time_check: "outside_case_date",
      source_content: "changed",
      error_category: "citation_source_unavailable"
    }, {
      source_kind: "material",
      source_id: "m-1",
      citation_locator: "C:\\private\\source.txt",
      source_exists: "not_found",
      full_text_read: "not_read",
      citation_match: "not_provided",
      time_check: "unknown",
      error_category: "citation_not_found"
    }]
  });
  assert.equal(verification.state, "passed");
  assert.equal(verification.bodySha256, "abcdef0123456789abcdef0123456789");
  assert.equal(verification.sources[0].citationLocator, "page:2");
  assert.deepEqual(verification.sources[0].matchedRanges, [{ start: 20, end: 44 }]);
  assert.equal(verification.sources[0].source_content, undefined);
  assert.equal(verification.sources[0].sourceExists, "passed");
  assert.equal(verification.sources[0].fullTextRead, "unavailable");
  assert.equal(verification.sources[0].citationMatch, "ambiguous");
  assert.equal(verification.sources[0].timeCheck, "outside_case_date");
  assert.equal(verification.sources[0].sourceContentState, "changed");
  assert.equal(verification.sources[0].errorCategory, "citation_source_unavailable");
  assert.equal(verification.sources[1].citationLocator, "");
  assert.equal(verification.sources[1].sourceExists, "not_found");
  assert.equal(verification.sources[1].citationMatch, "not_provided");
  const lawLocator = normalizeCitationVerification({ sources: [{ source_kind: "legal_article", source_id: "a-1", citation_locator: "law-article:civil-code:v2026:第四百六十五条" }, { source_kind: "judicial_case", source_id: "case-1", citation_locator: "judicial-case:case-1" }] });
  assert.deepEqual(lawLocator.sources.map((source) => source.citationLocator), ["law-article:civil-code:v2026:第四百六十五条", "judicial-case:case-1"]);
  assert.equal(citationVerificationStateLabel("stale"), "正文或日期已变化，待机械复核");
  assert.equal(citationVerificationReasonLabel("internal_stack_trace"), "需要重新机械核验");
  assert.equal(citationCheckLabel("fullTextRead", "unavailable"), "全文不可用");
  assert.equal(citationCheckLabel("citationMatch", "not_requested"), "未提供引文");
  assert.equal(citationCheckLabel("timeCheck", "outside_case_date"), "不在文书日期范围");
  assert.equal(citationErrorCategoryLabel("citation_source_unavailable"), "引用来源当前不可用");
});

test("context estimate keeps bounded safe scope and distinguishes configured from conservative budgets", () => {
  const estimate = normalizeAiContextEstimate({
    provider_id: "provider-1",
    model: "model-1",
    plan_hash: "plan-locked-1",
    stage: "scope_required",
    capabilities: { verified: false, max_input_tokens: 16000, max_output_tokens: 4000 },
    estimate: { input_tokens: 15000, reserved_output_tokens: 4000, history_tokens: 90, material_tokens: 12000, attachment_tokens: 2910, tool_reserve_tokens: 0 },
    selected_scope: { materials: [{ id: "m-1", source: "redacted", locators: ["page:2", "C:\\private\\source.txt"] }], attachments: [{ id: "a-1", format: "pdf", locators: ["paragraph:4"] }], history_run_ids: ["run-1"] },
    omitted_scope: [{ source_kind: "attachment", source_id: "a-2", reason: "ocr_page_scope_required", estimated_tokens: 3200 }]
  });
  assert.equal(estimate.stage, "scope_required");
  assert.equal(estimate.planHash, "plan-locked-1");
  assert.equal(contextEstimateCanProceed(estimate), false);
  assert.equal(contextBudgetStageLabel(estimate.stage), "需要缩小范围");
  assert.equal(contextOmissionReasonLabel(estimate.omittedScope[0].reason), "材料超出预算，请拆分文件或减少材料");
  assert.deepEqual(estimate.selectedScope.materials[0].locators, ["page:2"]);
  assert.equal(estimate.capabilities.verified, false);
  assert.deepEqual(modelCapabilitiesPayload({ contextWindowTokens: "20000", maxOutputTokens: "4000", supportsTools: true }), {
    context_window_tokens: 20000,
    max_output_tokens: 4000,
    supports_tools: true,
    supports_structured_output: false,
    supports_vision: false
  });
  assert.equal(modelCapabilitiesPayload({ contextWindowTokens: "4000", maxOutputTokens: "4000" }), null);
});

test("writing drafts retain only the strict encrypted-record fields and current run revision", () => {
  assert.deepEqual(writingDraftContent({
    documentType: "律师函",
    prompt: "案情",
    requirements: "简洁",
    caseDate: "2026-09-10",
    providerId: "provider-1",
    model: "model-1",
    materials: [{ materialId: "m-original", source: "original" }, { id: "m-invalid", source: "temporary" }],
    attachmentIds: ["a-1", "", null],
    runId: "run-1",
    runRevision: 6,
    content: "未提交正文",
    dirty: true,
    ignored: "must not persist"
  }), {
    document_type: "律师函",
    prompt: "案情",
    requirements: "简洁",
    case_date: "2026-09-10",
    provider_id: "provider-1",
    model: "model-1",
    materials: [{ id: "m-original", source: "original" }],
    attachment_ids: ["a-1"],
    run_id: "run-1",
    run_revision: 6,
    content: "未提交正文",
    dirty: true
  });
  assert.equal(aiRunRevision({ revision: 8 }), 8);
  assert.equal(conversationContextRevision({ context_revision: 9 }), 9);
  assert.equal(writingDraftContent({ run_id: "", run_revision: 0 }).run_id, null);
  assert.equal(writingDraftContent({ run_id: "", run_revision: 0 }).run_revision, null);
  assert.equal(isRetryableAiPollError(new ApiError("server_error", true, 500)), true);
  assert.equal(isRetryableAiPollError(new ApiError("not_found", true, 404)), false);
});

test("summary-only writing history cannot replace an encrypted unsaved document draft", () => {
  const summaryOnly = { id: "run-summary", kind: "writing", status: "completed", title: "摘要记录", revision: 7 };
  assert.equal(normalizeAiRun(summaryOnly).content, "", "paged history intentionally has no document content");
  assert.deepEqual(writingDraftRestorePlan({
    run_id: "run-summary",
    run_revision: 7,
    content: "# 未提交正文\n\n应从草稿恢复。",
    dirty: true
  }, summaryOnly), {
    runId: "run-summary",
    expectedRevision: 7,
    content: "# 未提交正文\n\n应从草稿恢复。"
  });
  assert.equal(writingDraftRestorePlan({ run_id: "run-summary", run_revision: 7, content: "正文", dirty: true }, summaryOnly, { hasLocalInput: true }), null);
});

test("AiRunPoller bounds exponential retry failures, resets after success, and ignores disposed callbacks", async () => {
  const settle = async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  };
  assert.equal(AI_RUN_POLL_MAX_CONSECUTIVE_FAILURES, 5);
  assert.deepEqual([1, 2, 3, 4, 5].map((count) => aiRunPollBackoffDelay(count, { baseDelayMs: 1000, maxDelayMs: 5000 })), [1000, 2000, 4000, 5000, 5000]);

  const timers = [];
  const retryErrors = [];
  const retrying = new AiRunPoller({
    getRun: () => { throw new ApiError("server_error", true, 500); },
    maxConsecutiveFailures: 3,
    retryBaseDelayMs: 10,
    retryMaxDelayMs: 25,
    setTimer: (callback, delay) => {
      const timer = { callback, delay };
      timers.push(timer);
      return timer;
    },
    clearTimer: () => {}
  });
  retrying.subscribe("retry-run", { onError: (_error, detail) => retryErrors.push(detail) });
  await settle();
  assert.deepEqual(timers.map((timer) => timer.delay), [10]);
  timers.shift().callback();
  await settle();
  assert.deepEqual(timers.map((timer) => timer.delay), [20]);
  timers.shift().callback();
  await settle();
  assert.equal(retrying.entries.size, 0, "the third consecutive failure stops polling");
  assert.deepEqual(retryErrors.map((detail) => [detail.consecutiveFailures, detail.retryDelayMs, detail.exhausted]), [[1, 10, false], [2, 20, false], [3, null, true]]);

  // Keep the success-reset assertion deterministic without relying on wall clock.
  const successTimers = [];
  let successAttempt = 0;
  const success = new AiRunPoller({
    getRun: () => ++successAttempt === 1 ? Promise.reject(new ApiError("server_error", true, 500)) : Promise.resolve({ id: "success-run", status: "running" }),
    retryBaseDelayMs: 10,
    setTimer: (callback, delay) => {
      const timer = { callback, delay };
      successTimers.push(timer);
      return timer;
    },
    clearTimer: () => {}
  });
  success.subscribe("success-run");
  await settle();
  const retryTimer = successTimers.shift();
  assert.equal(retryTimer.delay, 10);
  retryTimer.callback();
  await settle();
  assert.equal(success.entries.get("success-run").consecutiveFailures, 0);
  assert.equal(successTimers.shift().delay, 1500);
  success.stop("success-run");

  let resolveDisposed;
  const disposedUpdates = [];
  const disposed = new AiRunPoller({
    getRun: () => new Promise((resolve) => { resolveDisposed = resolve; }),
    setTimer: () => { throw new Error("disposed callback must not schedule"); },
    clearTimer: () => {}
  });
  disposed.subscribe("disposed-run", { scope: "gone", onUpdate: (run) => disposedUpdates.push(run.id) });
  await settle();
  disposed.disposeScope("gone");
  resolveDisposed({ id: "disposed-run", status: "running" });
  await settle();
  assert.deepEqual(disposedUpdates, []);
  assert.equal(disposed.entries.size, 0);
});

test("AiRunPoller deduplicates a run, updates scoped subscribers, and stops terminal or missing runs", async () => {
  const pending = [];
  const timers = [];
  const updates = [];
  const poller = new AiRunPoller({
    getRun: (id) => new Promise((resolve) => pending.push({ id, resolve })),
    setTimer: (callback, delay) => {
      timers.push({ callback, delay });
      return callback;
    },
    clearTimer: () => {}
  });
  const settle = async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  };

  poller.subscribe("run-1", { scope: "writing", onUpdate: (run) => updates.push(`writing:${run.status}`) });
  poller.subscribe("run-1", { scope: "search", onUpdate: (run) => updates.push(`search:${run.status}`) });
  assert.equal(pending.length, 1, "one HTTP poll serves both scoped listeners");
  pending.shift().resolve({ id: "run-1", status: "running" });
  await settle();
  assert.deepEqual(updates, ["writing:running", "search:running"]);
  assert.equal(timers.length, 1);
  assert.equal(timers[0].delay, 1500);

  timers.shift().callback();
  assert.equal(pending.length, 1);
  pending.shift().resolve({ id: "run-1", status: "completed" });
  await settle();
  assert.equal(poller.entries.size, 0);

  const errors = [];
  const missing = new AiRunPoller({
    getRun: async () => { throw new ApiError("not_found", false, 404); },
    setTimer: () => { throw new Error("a missing run must not be retried"); },
    clearTimer: () => {}
  });
  missing.subscribe("deleted-run", { onError: (error) => errors.push(error.code) });
  await settle();
  assert.deepEqual(errors, ["not_found"]);
  assert.equal(missing.entries.size, 0);
});
