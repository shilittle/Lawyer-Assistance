// HTTP/MCP/AI agreement on a synthetic fixture, against the real Windows daemon.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "search-native");
await fs.mkdir(output, { recursive: true });
const directory = await fs.mkdtemp(path.join(output, "fixture-"));
const legalPath = path.join(directory, "legal.sqlite");
execFileSync("python", ["-c", String.raw`
import sqlite3, pathlib, sys
root, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
c = sqlite3.connect(target)
c.executescript((root/'data/schema/legal_core.sql').read_text(encoding='utf-8'))
c.executescript((root/'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8'))
c.execute("INSERT INTO law_documents(id,title,document_type,authority_id,jurisdiction,effectiveness_level,status,summary) VALUES('audit-law','审查合成法','law','npc','CN','national_law','in_force','Synthetic only')")
versions=[('audit-old','repealed','2010-01-01','2020-12-31'),('audit-now','in_force','2021-01-01',None),('audit-future','not_yet_effective','2099-01-01',None),('audit-unknown','in_force','',None)]
for vid,status,start,end in versions:
    c.execute("INSERT INTO law_versions(id,document_id,version_label,status,effective_from,effective_to,published_on,source_reference) VALUES(?,?,?,?,?,?,?,?)",(vid,'audit-law',vid,status,start,end,'2009-01-01','Synthetic only'))
    c.execute("INSERT INTO law_articles(id,document_id,version_id,article_number,article_order,title,content,updated_on) VALUES(?,?,?,?,?,?,?,?)",(vid+'-1','audit-law',vid,'第一条',1,'合成标记','合成标记：合同解除。','2026-09-10'))
for aid,no,content in [('audit-now-2','第二条','合同成立。'),('audit-now-3','第三条','解除条件。')]:
    c.execute("INSERT INTO law_articles(id,document_id,version_id,article_number,article_order,title,content,updated_on) VALUES(?,?,?,?,?,?,?,?)",(aid,'audit-law','audit-now',no,2 if aid.endswith('2') else 3,'一般规定',content,'2026-09-10'))
c.execute("INSERT INTO law_aliases(id,document_id,alias,normalized_alias) VALUES('audit-alias','audit-law','合成法','合成法')")
c.commit(); c.close()
`, root, legalPath], { windowsHide: true, encoding: "utf8" });

const checks = [];
const ids = response => response.articles.map(a => a.articleId ?? a.id).sort();
let service, providerId;
const modelMessages = [];
const mock = http.createServer(async (req, res) => {
  let raw = "";
  for await (const bytes of req) raw += bytes;
  const request = JSON.parse(raw);
  modelMessages.push(request.messages);
  const hasTool = request.messages.some(m => m.role === "tool");
  const message = hasTool
    ? { role: "assistant", content: JSON.stringify({ title: "合成检索验收", content: "检索记录已读取。", citations: [] }) }
    : { role: "assistant", content: null, tool_calls: [{ id: "audit-call", type: "function", function: { name: "legal_search", arguments: JSON.stringify({ query: "合成标记" }) } }] };
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ model: "audit-mock", choices: [{ finish_reason: hasTool ? "stop" : "tool_calls", message }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
try {
  const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
  service = await startServer(path.join(directory, "workspace"), executable, legalPath, { portable: true });
  const client = service.client;
  const page = params => client.request(`/api/v1/legal/search/page?${new URLSearchParams({ query: "", view: "flat", ...params })}`);
  for (const query of ["民法典 第四百六十五条", "民法典第465条", "民法典第４６５条"]) {
    const result = await page({ query });
    assert.deepEqual(ids(result), ["civil-code-465"]);
    assert.equal(result.totalArticles, 1);
  }
  checks.push("exact_law_and_article_intersection_chinese_arabic_fullwidth");
  const all = await page({ query: "合同 解除", document_id: "audit-law", match_mode: "all" });
  const any = await page({ query: "合同 解除", document_id: "audit-law", match_mode: "any" });
  const phrase = await page({ query: "合同解除", document_id: "audit-law", match_mode: "phrase" });
  assert.deepEqual(ids(all), ["audit-now-1"]);
  assert.deepEqual(ids(any), ["audit-now-1", "audit-now-2", "audit-now-3"]);
  assert.deepEqual(ids(phrase), ["audit-now-1"]);
  checks.push("all_any_phrase_literal_results");
  const current = await page({ query: "合成标记" });
  assert.deepEqual(ids(current), ["audit-now-1"]);
  const historical = await page({ query: "合成标记", case_date: "2019-12-31", version_scope: "as_of" });
  assert.deepEqual(ids(historical), ["audit-old-1"]);
  const grouped = await page({ query: "合成标记", view: "grouped", case_date: "2019-12-31", version_scope: "as_of" });
  assert.deepEqual(grouped.laws.flatMap(g => g.topArticles.map(a => a.articleId)).sort(), ["audit-old-1"]);
  const broad = await page({ query: "合成标记", version_scope: "all" });
  assert.deepEqual(ids(broad), ["audit-future-1", "audit-now-1", "audit-old-1", "audit-unknown-1"]);
  const boundary = await page({ query: "合成标记", case_date: "2020-12-31", version_scope: "as_of" });
  assert.deepEqual(ids(boundary), ["audit-old-1"]);
  checks.push("current_historical_grouped_unknown_and_date_boundary");
  const oldDetail = await client.request("/api/v1/legal/articles/audit-old-1?version_scope=as_of&case_date=2019-12-31");
  assert.equal(oldDetail.article.versionId, "audit-old");
  const oldBody = await client.request("/api/v1/legal/version-articles/audit-old?version_scope=as_of&case_date=2019-12-31");
  assert.deepEqual(ids(oldBody), ["audit-old-1"]);
  const outOfScope = await fetch(`${client.origin}/api/v1/legal/articles/audit-old-1`, { headers: { cookie: client.cookie } });
  assert.equal(outOfScope.status, 404);
  checks.push("detail_and_version_body_keep_search_date_scope");
  const paged = [];
  for (let offset = 0; offset < 3; offset++) {
    const next = await page({ query: "合同 解除", document_id: "audit-law", match_mode: "any", limit: "1", offset: String(offset) });
    assert.equal(next.totalArticles, 3);
    paged.push(...ids(next));
  }
  assert.deepEqual(paged.sort(), ids(any));
  checks.push("exact_count_and_disjoint_complete_pages");
  for (const params of [{ case_date: "2026-02-30" }, { version_scope: "as_of" }, { version_scope: "all", case_date: "2019-01-01" }]) {
    const response = await fetch(`${client.origin}/api/v1/legal/search/page?${new URLSearchParams({ query: "合成标记", ...params })}`, { headers: { cookie: client.cookie } });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "invalid_search_request");
  }
  checks.push("invalid_date_and_conflicting_scope_rejected_http_400");
  const oldRoute = await client.request(`/api/v1/legal/search?${new URLSearchParams({ query: "合成标记", case_date: "2019-12-31" })}`);
  assert.deepEqual(ids(oldRoute), ids(historical));
  const mcpResponse = await fetch(`${client.origin}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "legal_search", arguments: { schema_version:1, query: "合成标记", case_date: "2019-12-31", limit: 50 } } }) });
  const mcp = await mcpResponse.json();
  assert(!mcp.error && !mcp.result?.isError, JSON.stringify(mcp));
  const result = mcp.result.structuredContent ?? JSON.parse(mcp.result.content[0].text);
  assert.deepEqual(result["内容"]["相关条文"].map(article => [article["法律名称"], article["条文"], article["施行日期"], article["终止日期"]]), historical.articles.map(article => [article.documentTitle, article.articleNumber, article.effectiveFrom, article.effectiveTo]));
  checks.push("http_legacy_and_mcp_v1_share_query_core");
  const provider = await client.request("/api/v1/ai/providers", "POST", { preset: "custom", name: "合成检索 mock", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["audit-mock"], api_key: "audit-synthetic-only", allow_private_network: true, trust_raw: false });
  providerId = provider.id;
  const run = await client.request("/api/v1/ai/runs", "POST", { kind: "search", prompt: "检索合成标记", provider_id: providerId, model: "audit-mock", materials: [], attachment_ids: [], case_date: "2019-12-31", match_mode: "all", version_scope: "as_of" });
  let completed;
  for (let n = 0; n < 200; n++) {
    completed = await client.request(`/api/v1/ai/runs/${run.id}`);
    if (!["queued", "running"].includes(completed.status)) break;
    await sleep(100);
  }
  assert.equal(completed.status, "completed", completed.error_code);
  const toolMessages = modelMessages.flat().filter(m => m.role === "tool").map(m => JSON.parse(m.content));
  assert(toolMessages.length > 0);
  assert.deepEqual(ids(toolMessages[0]), ids(historical));
  checks.push("actual_ai_tool_payload_uses_visible_date_and_query_plan");
  const report = { passed: true, checks, model: "local synthetic mock only", model_calls: modelMessages.length };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error) }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  if (service) {
    if (providerId) await service.client.request("/api/v1/providers", "POST", { id: providerId, name: "audit-cleanup", base_url: "https://cleanup.invalid", model: "cleanup", api_key: "", allow_private_network: false }).catch(() => {});
    await service.stop();
  }
  await new Promise(resolve => mock.close(resolve));
}
