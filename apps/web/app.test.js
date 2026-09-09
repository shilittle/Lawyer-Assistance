import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient, ApiError, ERROR_MESSAGES, pathId, queryString, splitIds } from "./api.js";
import { ENTITY_KINDS, field, legalArticleDisplayTitle, legalArticleDocumentId, legalRelationTarget, materialStatusTone, mcpClientDetails, optionalAlias, statusLabel, textValue } from "./app.js";

test("status presentation has safe Chinese labels and tones", () => {
  assert.equal(statusLabel("needs_review"), "待复核");
  assert.equal(statusLabel("completed"), "已完成");
  assert.equal(statusLabel("awaiting_consent"), "等待云辅助授权");
  assert.equal(statusLabel("partial"), "部分完成");
  assert.equal(statusLabel("unknown_status"), "unknown_status");
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

test("backend static failure codes keep actionable user messages", () => {
  assert.match(ERROR_MESSAGES.privacy_text_invalid_text_encoding, /指定/);
  assert.match(ERROR_MESSAGES.revision_conflict, /重新打开/);
  assert.match(ERROR_MESSAGES.result_revoked, /撤销/);
  assert.match(ERROR_MESSAGES.result_expired, /过期/);
  assert.match(ERROR_MESSAGES.provider_configuration_invalid, /地址/);
  assert.match(ERROR_MESSAGES.provider_response_incomplete, /未完整结束/);
  assert.match(ERROR_MESSAGES.dictionary_invalid, /词典/);
  assert.match(ERROR_MESSAGES.docx_extraction_incomplete, /未完整提取/);
  assert.match(ERROR_MESSAGES.docx_corrupt_or_encrypted, /损坏或已加密/);
  assert.match(ERROR_MESSAGES.docx_unsafe_package, /不安全结构/);
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
