// Real HTTP/model-dispatch evidence for LA12/13/14. No paid endpoint or user workspace.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chromium } from "@playwright/test";
import { connection, root, startServer, sleep } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "context-citations-native");
await fs.mkdir(output, { recursive: true });
const directory = await fs.mkdtemp(path.join(output, "fixture-"));
const legalPath = path.join(directory, "legal.sqlite");
execFileSync("python", ["-c", "import pathlib,sqlite3,sys; r=pathlib.Path(sys.argv[1]); c=sqlite3.connect(sys.argv[2]); c.executescript((r/'data/schema/legal_core.sql').read_text(encoding='utf-8')); c.executescript((r/'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8')); c.close()", root, legalPath], { windowsHide: true });
const checks = [], requests = [], connections = new Set();
const marker = "SYNTHETIC_REMOVED_ATTACHMENT_72C9";
let service, providerId, browser, page;
const pageErrors = [];
const mock = http.createServer(async (req, res) => {
  connections.add(res); res.on("close", () => connections.delete(res));
  let raw = "";
  for await (const chunk of req) { raw += chunk; assert(Buffer.byteLength(raw) <= 2 * 1024 * 1024); }
  const body = JSON.parse(raw), text = JSON.stringify(body.messages);
  requests.push(body);
  if (text.includes("NATIVE_HOLD_CONTEXT")) return;
  const cite = text.includes("NATIVE_CITATION");
  const toolRead = body.messages.some(message => message.role === "tool");
  let message;
  if (cite && !toolRead) message = { role: "assistant", content: null, tool_calls: [{ id: "native-article", type: "function", function: { name: "legal_get_article", arguments: JSON.stringify({ article_id: "civil-code-465" }) } }] };
  else message = { role: "assistant", content: JSON.stringify({ title: "合成核验", content: cite ? "依法成立的合同，受法律保护。" : text.includes(marker) ? `Synthetic answer depends on ${marker}.` : "Synthetic bounded answer.", citations: cite ? [{ article_id: "civil-code-465", quote: "依法成立的合同，受法律保护。", reason: "仅为合成核验" }] : [] }) };
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ model: "audit-context", choices: [{ finish_reason: text.includes("NATIVE_LENGTH") ? "length" : message.tool_calls ? "tool_calls" : "stop", message }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
const providerRequest = () => ({ id: providerId, preset: "custom", name: "Synthetic context audit", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["audit-context"], api_key: "audit-synthetic-only", trust_raw: true, allow_private_network: true });
const selection = () => ({ provider_id: providerId, model: "audit-context" });
const hash = text => createHash("sha256").update(text).digest("hex");
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
function verifyActualPlan(plan) {
  const value = { schema_version: 1, preflight_plan_hash: plan.plan_hash, stage: plan.stage, capabilities: plan.capabilities, estimate: plan.estimate, selected_scope: plan.selected_scope, omitted_scope: plan.omitted_scope };
  assert.equal(plan.actual_plan_hash, hash(JSON.stringify(canonical(value))), "actual ranges and budget ledger must match the actual plan hash");
}
async function until(predicate, label, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const value = await predicate(); if (value) return value; await sleep(100); }
  throw new Error(`${label}_timeout`);
}
async function terminal(id) {
  return until(async () => { const run = await service.client.request(`/api/v1/ai/runs/${id}`); return !["queued", "running"].includes(run.status) && run; }, "terminal", 30000);
}
async function writeRun(prompt, extra = {}) {
  return service.client.request("/api/v1/ai/runs", "POST", { kind: "writing", prompt, ...selection(), ...extra });
}
async function upload(text) {
  const form = new FormData(); form.append("file", new Blob([text], { type: "text/plain" }), "synthetic-context.txt");
  return service.client.request("/api/v1/ai/attachments", "POST", form);
}
async function chat(conversation, prompt) {
  const prepared = await service.client.request(`/api/v1/ai/conversations/${conversation.id}/context/prepare`, "POST", { expected_revision: conversation.context_revision, ...selection() });
  const request = { kind: "chat", prompt, ...selection(), conversation_id: conversation.id, context_revision: prepared.manifest.revision, context_preparation_hash: prepared.preparation_hash };
  const plan = await service.client.request("/api/v1/ai/context/estimate", "POST", request);
  return service.client.request("/api/v1/ai/runs", "POST", { ...request, context_plan_hash: plan.plan_hash });
}
try {
  const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
  service = await startServer(path.join(directory, "workspace"), executable, legalPath);
  const client = service.client;
  providerId = (await client.request("/api/v1/ai/providers", "POST", providerRequest())).id;
  const estimate = await client.request("/api/v1/ai/context/estimate", "POST", { kind: "writing", prompt: "合成容量预检", ...selection() });
  assert.equal(estimate.capabilities.max_input_tokens, 16384);
  assert.equal(estimate.capabilities.max_output_tokens, 4096);
  assert.equal(estimate.capabilities.verified, false);
  assert.equal(requests.length, 0);
  checks.push("unknown_model_visible_16k_input_4k_output_without_dispatch");

  await assert.rejects(() => writeRun("X".repeat(30000)), /context_budget_exceeded/u);
  assert.equal(requests.length, 0);
  checks.push("oversized_prompt_rejected_before_model_dispatch");
  for (const [name, type] of [["synthetic-budget.pdf", "application/pdf"], ["synthetic-budget.png", "image/png"]]) {
    // Intentionally unparsed bytes: summary preflight must reject before format decoding.
    const form = new FormData(); form.append("file", new Blob([Buffer.alloc(2 * 1024 * 1024, 65)], { type }), name);
    const attachment = await client.request("/api/v1/ai/attachments", "POST", form);
    const request = { kind: "writing", prompt: "Synthetic visual scope preflight", ...selection(), attachment_ids: [attachment.id] };
    const plan = await client.request("/api/v1/ai/context/estimate", "POST", request);
    assert.equal(plan.stage, "scope_required");
    assert(plan.omitted_scope.some(item => item.source_id === attachment.id && item.reason === "ocr_page_scope_required"));
    await assert.rejects(() => client.request("/api/v1/ai/runs", "POST", { ...request, context_plan_hash: plan.plan_hash }), /context_budget_exceeded/u);
    assert.equal(requests.length, 0);
  }
  checks.push("oversized_visual_preflight_enforced_before_parsing_and_model_dispatch");

  const lengthRun = await writeRun("NATIVE_LENGTH valid JSON but truncated completion");
  const lengthDone = await terminal(lengthRun.id);
  assert.notEqual(lengthDone.status, "completed");
  assert.match(lengthDone.error_code || "", /truncat|incomplete|length/u);
  assert.equal(requests.at(-1).max_tokens, 4096);
  checks.push("length_finish_reason_never_completed_and_actual_output_cap_applied");

  const beforeUnsupported = requests.length;
  await client.request("/api/v1/ai/providers", "POST", { ...providerRequest(), model_capabilities: { "audit-context": { context_window_tokens: 20480, max_output_tokens: 4096, supports_tools: false } } });
  await assert.rejects(() => writeRun("Explicit unsupported tool model"), /model_tools_unsupported/u);
  assert.equal(requests.length, beforeUnsupported);
  await client.request("/api/v1/ai/providers", "POST", providerRequest());
  checks.push("explicit_model_capability_rejected_before_dispatch");

  const created = await writeRun("NATIVE_CITATION read the source then cite it", { case_date: "2026-09-10" });
  const original = await terminal(created.id);
  assert.equal(original.status, "completed", original.error_code);
  const evidence = original.citation_verification;
  assert.equal(evidence.body_sha256, hash(original.content));
  assert.equal(evidence.run_revision, original.revision);
  assert.equal(evidence.case_date, "2026-09-10");
  assert.equal(evidence.sources.length, 1);
  const source = evidence.sources[0];
  assert.equal(source.version_id, "civil-code-v1");
  assert.equal(source.source_full_text_sha256, hash("依法成立的合同，受法律保护。"));
  for (const field of ["source_exists", "full_text_read", "time_check"]) assert.equal(source[field], "passed", field);
  assert.equal(source.citation_match, "matched");
  assert.equal(source.relevance, "manual_review_required");
  assert(!("content" in source));
  checks.push("citation_evidence_binds_source_version_body_revision_date_independent_states");

  // Read the completed run through the real bundled Web UI. This verifies the
  // public string-state contract rather than recreating labels from HTTP data.
  const descriptor = connection(path.join(directory, "workspace"));
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.on("pageerror", error => pageErrors.push(String(error)));
  await page.goto(`${descriptor.origin}#token=${descriptor.bootstrap}`);
  await page.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true }).click();
  const originalHistoryRow = page.locator(".ai-history-list .conversation-item").filter({ hasText: "合成核验" }).first();
  await originalHistoryRow.waitFor();
  await originalHistoryRow.click();
  await page.waitForFunction(() => {
    const text = document.querySelector(".citation-verification")?.textContent || "";
    return text.includes("来源存在：已找到")
      && text.includes("全文读取：已读取")
      && text.includes("引文匹配：已匹配")
      && text.includes("时间核验：通过");
  });
  const renderedEvidence = await page.locator(".citation-verification").textContent();
  assert.match(renderedEvidence || "", /来源存在：已找到/u);
  assert.match(renderedEvidence || "", /全文读取：已读取/u);
  assert.match(renderedEvidence || "", /引文匹配：已匹配/u);
  assert.match(renderedEvidence || "", /时间核验：通过/u);
  checks.push("browser_real_writing_run_renders_four_citation_string_states");

  await page.getByRole("button", { name: "编辑正文", exact: true }).click();
  await page.locator(".document-content-editor").fill(`${original.content}\n\n浏览器本地未保存的核验编辑。`);
  await page.waitForFunction(() => {
    const text = document.querySelector(".citation-verification")?.textContent || "";
    return text.includes("正文或日期已变化，待机械复核") && !text.includes("机械校验通过");
  });
  const localEditEvidence = await page.locator(".citation-verification").textContent();
  assert.match(localEditEvidence || "", /正文或日期已变化，待机械复核/u);
  assert.doesNotMatch(localEditEvidence || "", /机械校验通过/u);
  checks.push("browser_local_unsaved_edit_immediately_marks_citation_stale");

  const edited = await client.request(`/api/v1/ai/runs/${original.id}/content`, "PUT", { expected_revision: original.revision, content: original.content + "\n\nSynthetic manual edit.", case_date: "2020-12-31" });
  assert.notEqual(edited.id, original.id);
  assert.notEqual(edited.citation_verification.state, "passed");
  const beforeExport = requests.length;
  const exported = await client.request(`/api/v1/ai/runs/${edited.id}/export?format=txt&expected_revision=${edited.revision}`, "GET", undefined, true);
  assert(exported.toString("utf8").includes("Synthetic manual edit."));
  assert.equal(requests.length, beforeExport);
  const checked = await client.request(`/api/v1/ai/runs/${edited.id}/citations/recheck`, "POST", { expected_revision: edited.revision });
  assert.notEqual(checked.citation_verification.state, "passed");
  assert.notEqual(checked.citation_verification.sources[0].time_check, "passed");
  assert.equal(checked.citation_verification.body_sha256, hash(edited.content));
  await assert.rejects(() => client.request(`/api/v1/ai/runs/${edited.id}/export?format=txt&expected_revision=${edited.revision + 1}`, "GET", undefined, true), /revision_conflict/u);
  checks.push("edit_and_date_invalidate_old_evidence_pending_export_allowed_revision_checked");

  execFileSync("python", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE law_articles SET content=content || ' Synthetic source drift.' WHERE id='civil-code-465'\"); c.commit(); c.close()", legalPath], { windowsHide: true });
  const drift = await client.request(`/api/v1/ai/runs/${original.id}/citations/recheck`, "POST", { expected_revision: original.revision });
  assert.equal(drift.citation_verification.sources[0].source_content, "changed");
  assert.notEqual(drift.citation_verification.state, "passed");
  checks.push("source_text_drift_detected_by_full_text_hash");

  const attachment = await upload(`Synthetic confidential test content ${marker}.`);
  let conversation = await client.request("/api/v1/ai/conversations", "POST", { title: "Synthetic context removal" });
  const replace = attachments => client.request(`/api/v1/ai/conversations/${conversation.id}/context`, "PUT", { expected_revision: conversation.context_revision, materials: [], attachment_ids: attachments });
  conversation = (await replace([attachment.id])).conversation;
  const withSource = await chat(conversation, "NATIVE_CONTEXT summarize my selected synthetic source");
  const sourceDone = await terminal(withSource.id);
  assert.equal(sourceDone.status, "completed");
  verifyActualPlan(sourceDone.context_plan);
  assert(JSON.stringify(requests.at(-1).messages).includes(marker));
  const followup = await chat(conversation, "NATIVE_CONTEXT follow up using the complete earlier turn");
  const followupDone = await terminal(followup.id);
  assert.equal(followupDone.status, "completed");
  assert(followupDone.context_plan.selected_scope.history_run_ids.includes(withSource.id));
  assert(followupDone.context_plan.estimate.history_tokens > 0);
  verifyActualPlan(followupDone.context_plan);
  checks.push("actual_context_hash_binds_adopted_ranges_and_nonzero_complete_history_budget");
  conversation = (await replace([])).conversation;
  const beforeRemoved = requests.length;
  const removed = await chat(conversation, "NATIVE_AFTER_REMOVE respond without earlier material");
  assert.equal((await terminal(removed.id)).status, "completed");
  for (const body of requests.slice(beforeRemoved)) assert(!JSON.stringify(body.messages).includes(marker), "removed material must leave both source and dependent assistant history");
  const history = await client.request(`/api/v1/ai/conversations/${conversation.id}`);
  assert(JSON.stringify(history).includes(marker), "local historical display remains available");
  checks.push("removed_attachment_and_dependent_history_absent_from_actual_model_messages");

  conversation = (await replace([attachment.id])).conversation;
  const beforeHold = requests.length;
  const held = await chat(conversation, "NATIVE_HOLD_CONTEXT wait for removal");
  await until(() => requests.length > beforeHold, "held_model_dispatch");
  const removedDuringRun = await replace([]);
  assert(removedDuringRun.cancelled_run_ids.includes(held.id));
  assert.equal((await terminal(held.id)).status, "cancelled");
  await until(() => connections.size === 0, "provider_connection_cancelled");
  checks.push("context_removal_cancels_inflight_provider_connection");
  const health = await client.request("/api/v1/health");
  assert.equal(health.status, "ready");
  assert.deepEqual(pageErrors, []);
  const report = { passed: true, checks, browser_checks: 2, page_errors: pageErrors, model: "localhost synthetic mock only", model_calls: requests.length, raw_model_messages_saved: false };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  if (page && !page.isClosed()) await page.screenshot({ path: path.join(output, "failure.png"), fullPage: true }).catch(() => {});
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error), page_errors: pageErrors, model_calls: requests.length }, null, 2));
  console.error(error); process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  for (const response of connections) response.destroy();
  if (service) {
    if (providerId) await service.client.request("/api/v1/providers", "POST", { id: providerId, name: "audit-cleanup", base_url: "https://cleanup.invalid", model: "cleanup", api_key: "", allow_private_network: false }).catch(() => {});
    await service.stop();
  }
  await new Promise(resolve => mock.close(resolve));
}
