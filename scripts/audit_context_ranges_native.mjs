// Local daemon, isolated synthetic sources, and localhost model only. Evidence
// records scope assertions and hashes; model messages stay in test-process memory.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chromium } from "@playwright/test";
import { root, startServer, sleep, connection } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "context-ranges-native");
await fs.mkdir(output, { recursive: true });
try { await fs.access(path.join(output, "report.json")); throw new Error("evidence_directory_already_used"); } catch (error) { if (error.code !== "ENOENT") throw error; }
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
const legalDb = path.join(output, "legal.sqlite");
execFileSync("python", ["-c", "import pathlib,sqlite3,sys; r=pathlib.Path(sys.argv[1]); c=sqlite3.connect(sys.argv[2]); c.executescript((r/'data/schema/legal_core.sql').read_text(encoding='utf-8')); c.executescript((r/'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8')); c.close()", root, legalDb], { windowsHide: true });
const hash = data => createHash("sha256").update(data).digest("hex");
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const markers = ["RANGE_FIRST_SOURCE_B372", "RANGE_SECOND_SOURCE_918A", "RANGE_THIRD_SOURCE_94CB"];
const requests = [], connections = new Set(), checks = [], observedPlans = [];
const planned = ["inspect_text_no_dispatch", "paragraph_selection_matches_actual_plan", "normalize_and_reject_invalid_ranges", "source_binding_and_old_plan_rejected", "pdf_metadata_no_model", "pdf_text_selection_skips_visual_pages", "pdf_scan_and_mixed_selection_ocr_only_selected", "over_budget_can_reduce_scope", "conversation_range_change_invalidates_preparation", "range_shrink_cancels_and_excludes_dependent_history", "empty_manifest_clears_all_ranges", "service_ready_and_resources_released", "bundled_browser_selects_range_and_actual_dispatch_matches"];
let service, selection, attachment, inspected, pdfAttachment, pdfInspection;
const started = new Date().toISOString();
const mock = http.createServer(async (request, response) => {
  connections.add(response); response.on("close", () => connections.delete(response));
  let raw = "";
  for await (const chunk of request) { raw += chunk; if (Buffer.byteLength(raw) > 20 * 1024 * 1024) { response.writeHead(413).end(); return; } }
  const body = JSON.parse(raw);
  const text = JSON.stringify(body.messages);
  const ocr = body.messages.some(message => Array.isArray(message.content) && message.content.some(part => part.type === "image_url"));
  requests.push({ ocr, messages: body.messages, max_tokens: body.max_tokens });
  if (text.includes("RANGE_HOLD_DISPATCH")) return;
  const content = ocr ? { text: "OCR_SELECTED_PAGE_28E1", complete: true, warnings: [] } : { title: "Synthetic range result", content: markers.filter(marker => text.includes(marker)).join(" ") || "Synthetic selected scope result.", citations: [] };
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ model: "range-mock", choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(content) } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
async function until(operation, label, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const value = await operation(); if (value) return value; await sleep(50); }
  throw new Error(`${label}_timeout`);
}
async function check(id, operation) {
  const start = performance.now();
  try { const evidence = await operation(); checks.push({ id, status: "passed", elapsed_ms: performance.now() - start, evidence }); }
  catch (error) { checks.push({ id, status: "failed", elapsed_ms: performance.now() - start, error: String(error) }); throw error; }
}
const call = (...args) => service.client.request(...args);
async function upload(bytes, name) {
  const form = new FormData(); form.append("file", new Blob([bytes]), name);
  return call("/api/v1/ai/attachments", "POST", form);
}
const source = item => ({ source_kind: "attachment", source_id: item.id });
const inspect = item => call("/api/v1/ai/context/inspect", "POST", source(item));
const range = (item, metadata, mode, ranges) => ({ ...source(item), mode, ranges, inspection_hash: metadata.inspection_hash });
const request = (item, ranges, prompt = "Summarize only the selected synthetic scope.") => ({ kind: "writing", prompt, ...selection, attachment_ids: [item.id], context_ranges: ranges });
const estimate = body => call("/api/v1/ai/context/estimate", "POST", body);
async function complete(body) {
  const plan = await estimate(body);
  const created = await call("/api/v1/ai/runs", "POST", { ...body, context_plan_hash: plan.plan_hash });
  const done = await until(async () => { const value = await call(`/api/v1/ai/runs/${created.id}`); return !["queued", "running"].includes(value.status) && value; }, "run_terminal");
  assert.equal(done.status, "completed", done.error_code);
  return done;
}
function verifyPlan(plan) {
  observedPlans.push(plan);
  assert.equal(plan.schema_version, 2, "new scoped execution must expose its hash schema");
  assert(plan.requested_scope, "requested scope must remain independently bound");
  assert(plan.actual_plan_hash);
  const data = { schema_version: plan.schema_version || 1, preflight_plan_hash: plan.plan_hash, stage: plan.stage, capabilities: plan.capabilities, estimate: plan.estimate, requested_scope: plan.requested_scope, selected_scope: plan.selected_scope, omitted_scope: plan.omitted_scope };
  assert.equal(plan.actual_plan_hash, hash(JSON.stringify(canonical(data))));
}
function pdf() {
  const objects = ["<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"], pages = [];
  for (const [index, kind] of ["text", "scan", "mixed"].entries()) {
    const pageId = objects.length + 1; pages.push(`${pageId} 0 R`); objects.push("");
    const streamId = objects.length + 1;
    const content = (kind !== "scan" ? `BT /F1 12 Tf 36 740 Td (PDF_PAGE_${index + 1}_ONLY Synthetic contract payment and delivery terms with sufficient searchable text.) Tj ET\n` : "") + (kind !== "text" ? "q 400 0 0 600 36 60 cm /Im1 Do Q\n" : "");
    objects.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}endstream`);
    let image = "";
    if (kind !== "text") { const id = objects.length + 1, hex = "FFFFFF000000000000FFFFFF>"; objects.push(`<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /ASCIIHexDecode /Length ${hex.length} >>\nstream\n${hex}\nendstream`); image = `/XObject << /Im1 ${id} 0 R >>`; }
    objects[pageId - 1] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> ${image} >> /Contents ${streamId} 0 R >>`;
  }
  objects[1] = `<< /Type /Pages /Count 3 /Kids [${pages.join(" ")}] >>`;
  let data = "%PDF-1.4\n"; const offsets = [];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(data)); data += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(data);
  data += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` + offsets.map(offset => `${String(offset).padStart(10, "0")} 00000 n \n`).join("") + `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(data);
}
try {
  service = await startServer(workspace, executable, legalDb, { portable: process.argv.includes("--portable") });
  const provider = await call("/api/v1/ai/providers", "POST", { preset: "custom", name: "Synthetic range mock", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["range-mock"], api_key: "synthetic-only", trust_raw: true, allow_private_network: true });
  selection = { provider_id: provider.id, model: "range-mock" };
  await call("/api/v1/ai/defaults", "PUT", { writing: selection, chat: selection, ocr: selection });
  attachment = await upload(Buffer.from(markers.join("\n\n")), "three-paragraphs.txt");
  await check(planned[0], async () => {
    inspected = await inspect(attachment);
    assert.equal(inspected.unit_kind, "paragraph"); assert.equal(inspected.unit_count, 3); assert(inspected.inspection_hash);
    assert(inspected.estimated_input_tokens > 0); assert(!JSON.stringify(inspected).includes(markers[0])); assert.equal(requests.length, 0);
    return inspected;
  });
  const second = () => range(attachment, inspected, "paragraphs", [{ start: 2, end: 2 }]);
  await check(planned[1], async () => {
    const before = requests.length, done = await complete(request(attachment, [second()]));
    const sent = JSON.stringify(requests.slice(before));
    assert(sent.includes(markers[1])); assert(!sent.includes(markers[0])); assert(!sent.includes(markers[2])); verifyPlan(done.context_plan);
    return { run_id: done.id, plan: done.context_plan };
  });
  await check(planned[2], async () => {
    const unnormalized = range(attachment, inspected, "paragraphs", [{ start: 2, end: 3 }, { start: 1, end: 2 }, { start: 2, end: 2 }]);
    const normalized = range(attachment, inspected, "paragraphs", [{ start: 1, end: 3 }]);
    assert.equal((await estimate(request(attachment, [unnormalized]))).plan_hash, (await estimate(request(attachment, [normalized]))).plan_hash);
    for (const intervals of [[], [{ start: 0, end: 1 }], [{ start: 3, end: 2 }], [{ start: 4, end: 4 }]]) await assert.rejects(() => estimate(request(attachment, [range(attachment, inspected, "paragraphs", intervals)])), /context_range|context_scope|invalid_context/u);
  });
  await check(planned[3], async () => {
    const oldPlan = await estimate(request(attachment, [second()]));
    const changed = request(attachment, [range(attachment, inspected, "paragraphs", [{ start: 1, end: 1 }])]);
    await assert.rejects(() => call("/api/v1/ai/runs", "POST", { ...changed, context_plan_hash: oldPlan.plan_hash }), /context_prepare_required|context_plan/u);
    const other = await upload(Buffer.from("A changed source version."), "changed.txt");
    await assert.rejects(() => estimate(request(other, [range(other, inspected, "paragraphs", [{ start: 1, end: 1 }])])), /context_prepare_required|context_inspection/u);
  });
  await check(planned[4], async () => {
    pdfAttachment = await upload(pdf(), "three-pages.pdf"); const before = requests.length;
    pdfInspection = await inspect(pdfAttachment);
    assert.equal(pdfInspection.unit_kind, "page"); assert.equal(pdfInspection.unit_count, 3); assert.equal(requests.length, before);
    assert(!JSON.stringify(pdfInspection).includes("PDF_PAGE_")); return pdfInspection;
  });
  await check(planned[5], async () => {
    const before = requests.length;
    const done = await complete(request(pdfAttachment, [range(pdfAttachment, pdfInspection, "pages", [{ start: 1, end: 1 }])]));
    const sent = requests.slice(before); assert.equal(sent.filter(item => item.ocr).length, 0);
    assert(JSON.stringify(sent).includes("PDF_PAGE_1_ONLY")); assert(!JSON.stringify(sent).includes("PDF_PAGE_3_ONLY")); verifyPlan(done.context_plan);
    return { run_id: done.id, plan: done.context_plan, ocr_calls: 0 };
  });
  await check(planned[6], async () => {
    const evidence = [];
    for (const page of [2, 3]) {
      const before = requests.length;
      const done = await complete(request(pdfAttachment, [range(pdfAttachment, pdfInspection, "pages", [{ start: page, end: page }])]));
      const sent = requests.slice(before); assert.equal(sent.filter(item => item.ocr).length, 1);
      assert(!JSON.stringify(sent).includes("PDF_PAGE_1_ONLY")); assert(JSON.stringify(sent).includes("OCR_SELECTED_PAGE_28E1")); verifyPlan(done.context_plan);
      evidence.push({ page, run_id: done.id, plan: done.context_plan, ocr_calls: 1 });
    }
    return evidence;
  });
  await check(planned[7], async () => {
    const large = await upload(Buffer.from(Array.from({ length: 90 }, (_, index) => `SYNTHETIC_PARAGRAPH_${index} ` + "bounded text ".repeat(45)).join("\n\n")), "large.txt");
    const metadata = await inspect(large), before = requests.length;
    const full = request(large, [{ ...source(large), mode: "all" }]);
    await assert.rejects(() => call("/api/v1/ai/runs", "POST", full), /context_budget_exceeded/u); assert.equal(requests.length, before);
    const done = await complete(request(large, [range(large, metadata, "paragraphs", [{ start: 1, end: 1 }])]));
    assert.equal(done.status, "completed"); return { unit_count: metadata.unit_count, run_id: done.id };
  });
  let conversation = await call("/api/v1/ai/conversations", "POST", { title: "Synthetic range conversation" });
  const replace = ranges => call(`/api/v1/ai/conversations/${conversation.id}/context`, "PUT", { expected_revision: conversation.context_revision, materials: [], attachment_ids: [attachment.id], context_ranges: ranges });
  const prepare = () => call(`/api/v1/ai/conversations/${conversation.id}/context/prepare`, "POST", { expected_revision: conversation.context_revision, ...selection });
  const chatBody = (prepared, prompt) => ({ kind: "chat", prompt, ...selection, conversation_id: conversation.id, context_revision: prepared.manifest.revision, context_preparation_hash: prepared.preparation_hash });
  await check(planned[8], async () => {
    conversation = (await replace([{ ...source(attachment), mode: "all" }])).conversation;
    const prepared = await prepare();
    conversation = (await replace([second()])).conversation;
    const before = requests.length;
    await assert.rejects(() => call("/api/v1/ai/runs", "POST", chatBody(prepared, "Old prepared scope must be rejected.")), /revision_conflict|context_prepare_required|context_revision/u);
    assert.equal(requests.length, before);
    assert(conversation.context_revision > prepared.manifest.revision);
  });
  await check(planned[9], async () => {
    conversation = (await replace([{ ...source(attachment), mode: "all" }])).conversation;
    let prepared = await prepare();
    const earlier = await complete(chatBody(prepared, "Use every selected paragraph in the synthetic answer."));
    assert(earlier.content.includes(markers[0]));
    prepared = await prepare(); const beforeHold = requests.length;
    const held = await call("/api/v1/ai/runs", "POST", chatBody(prepared, "RANGE_HOLD_DISPATCH"));
    await until(() => requests.length > beforeHold, "held_dispatch");
    const changed = await replace([second()]); conversation = changed.conversation;
    assert(changed.cancelled_run_ids.includes(held.id));
    await until(async () => (await call(`/api/v1/ai/runs/${held.id}`)).status === "cancelled", "cancelled_run");
    await until(() => connections.size === 0, "closed_provider_connection");
    prepared = await prepare(); const before = requests.length;
    const done = await complete(chatBody(prepared, "Only the remaining selected range is allowed."));
    for (const sent of requests.slice(before)) { const text = JSON.stringify(sent.messages); assert(text.includes(markers[1])); assert(!text.includes(markers[0])); assert(!text.includes(markers[2])); }
    const history = await call(`/api/v1/ai/conversations/${conversation.id}`); assert(JSON.stringify(history).includes(markers[0]));
    return { held_run_id: held.id, previous_run_id: earlier.id, next_run_id: done.id, actual_plan: done.context_plan };
  });
  await check(planned[10], async () => {
    const value = await call(`/api/v1/ai/conversations/${conversation.id}/context`, "PUT", { expected_revision: conversation.context_revision, materials: [], attachment_ids: [], context_ranges: [] });
    conversation = value.conversation; const prepared = await prepare();
    assert.deepEqual(prepared.manifest.context_ranges, []); assert.deepEqual(prepared.manifest.materials, []); assert.deepEqual(prepared.manifest.attachment_ids, []);
  });
  await check(planned[11], async () => {
    const health = await until(async () => { const value = await call("/api/v1/health"); return value.resources.ai.active === 0 && value.resources.parse.active === 0 && value; }, "permits_released");
    assert.equal(health.status, "ready"); return { status: health.status, resources: health.resources };
  });
  await check(planned[12], async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    const pageErrors = []; page.on("pageerror", error => pageErrors.push(String(error)));
    try {
      const descriptor = connection(workspace);
      await page.goto(`${descriptor.origin}#token=${descriptor.bootstrap}`);
      await page.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true }).click();
      await page.locator("textarea").first().fill("Only use the paragraph selected below.");
      await page.locator(".ai-attachment-picker input[type=file]").setInputFiles({ name: "browser-three-paragraphs.txt", mimeType: "text/plain", buffer: Buffer.from(markers.join("\n\n")) });
      const row = page.locator(".context-range-row");
      await row.getByRole("button", { name: "检查页/段落", exact: true }).click();
      await row.locator("select option[value=paragraphs]").waitFor({ state: "attached" });
      await row.locator("select").selectOption("paragraphs");
      await row.locator("input[type=text]").fill("2");
      await row.getByRole("button", { name: "应用范围", exact: true }).click();
      const before = requests.length;
      const accepted = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/ai/runs" && response.request().method() === "POST");
      await page.getByRole("button", { name: "生成文书", exact: true }).click();
      const response = await accepted; assert.equal(response.status(), 200);
      const created = await response.json();
      const done = await until(async () => { const value = await call(`/api/v1/ai/runs/${created.id}`); return !["queued", "running"].includes(value.status) && value; }, "browser_run_terminal");
      assert.equal(done.status, "completed", done.error_code);
      const sent = JSON.stringify(requests.slice(before)); assert(sent.includes(markers[1])); assert(!sent.includes(markers[0])); assert(!sent.includes(markers[2]));
      assert.equal(done.context_plan.requested_scope[0].mode, "paragraphs"); assert.deepEqual(done.context_plan.requested_scope[0].ranges, [{ start: 2, end: 2 }]); verifyPlan(done.context_plan);
      await page.locator(".document-preview").filter({ hasText: markers[1] }).waitFor();
      await page.locator(".context-estimate .context-scope-list").filter({ hasText: "paragraph:2" }).waitFor({ timeout: 5000 });
      assert(!(await page.locator(".preview-panel").innerText()).includes("尚未生成文书"));
      assert(!(await row.innerText()).includes("需要新预检或准备后才能发送"));
      assert.deepEqual(pageErrors, []);
      await page.screenshot({ path: path.join(output, "browser-selected-paragraph.png"), fullPage: true });
      return { run_id: done.id, plan: done.context_plan, page_errors: pageErrors };
    } catch (error) {
      await page.screenshot({ path: path.join(output, "browser-range-failure.png"), fullPage: true }).catch(() => {});
      throw error;
    } finally { await browser.close(); }
  });
} catch (error) { console.error(error); process.exitCode = 1; }
finally {
  for (const response of connections) response.destroy();
  if (service) await service.stop();
  await new Promise(resolve => mock.close(resolve));
  for (const id of planned) if (!checks.some(check => check.id === id)) checks.push({ id, status: "not_run" });
  const report = { schema_version: 1, status: checks.every(check => check.status === "passed") ? "passed" : "failed", started_at: started, completed_at: new Date().toISOString(), source_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), program_sha256: hash(await fs.readFile(executable)), script_sha256: hash(await fs.readFile(new URL(import.meta.url))), node: process.version, model_calls: requests.length, model_endpoint: "localhost synthetic mock only", raw_model_messages_saved: false, observed_plans: observedPlans, checks };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ status: report.status, passed: checks.filter(check => check.status === "passed").length, failed: checks.filter(check => check.status === "failed").length, not_run: checks.filter(check => check.status === "not_run").length, output }));
}
