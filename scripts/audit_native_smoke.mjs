// Real Windows daemon + Chromium, using an in-process mock model and new workspace.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { chromium } from "@playwright/test";
import { startServer, connection, sleep, root } from "./ai_test_client.mjs";

const output = path.join(root, "work/audit-repair/native-smoke");
await fs.mkdir(output, { recursive: true });
const dataDir = await fs.mkdtemp(path.join(output, "workspace-"));
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
let modelCalls = 0;
const mock = http.createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 2 * 1024 * 1024) { res.writeHead(413).end(); return; }
  }
  modelCalls++;
  JSON.parse(body);
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ model: "audit-mock", choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify({ title: "原生验收文书 A", content: "# 合成材料说明\n\n合成金额为 126800 元，日期为 2026 年 8 月 11 日。", citations: [] }) } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
let service;
let browser;
let page;
let providerId;
const checks = [];
const pageErrors = [];
const httpErrors = [];
function observe(current) {
  current.on("pageerror", e => pageErrors.push(String(e)));
  current.on("response", async response => {
    if (response.status() >= 400 && new URL(response.url()).pathname.startsWith("/api/")) {
      const value = await response.json().catch(() => ({}));
      httpErrors.push({ path: new URL(response.url()).pathname, status: response.status(), code: value.error?.code });
    }
  });
}
try {
  service = await startServer(dataDir, executable, path.join(root, "data/runtime/legal_core.sqlite"), { portable: process.argv.includes("--portable") });
  const client = service.client;
  const provider = await client.request("/api/v1/ai/providers", "POST", { preset: "custom", name: "审查本机合成模型", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["audit-mock"], api_key: "audit-synthetic-key-only", trust_raw: false, allow_private_network: true });
  providerId = provider.id;
  const selection = { provider_id: providerId, model: "audit-mock" };
  await client.request("/api/v1/ai/defaults", "PUT", { chat: selection, writing: selection });
  const run = await client.request("/api/v1/ai/runs", "POST", { kind: "writing", prompt: "只整理合成材料。", ...selection, materials: [], attachment_ids: [] });
  let completed;
  for (let n = 0; n < 200; n++) {
    completed = await client.request(`/api/v1/ai/runs/${run.id}`);
    if (!["queued", "running"].includes(completed.status)) break;
    await sleep(100);
  }
  assert.equal(completed.status, "completed", completed.error_code);
  checks.push("real_daemon_mock_writing_completed");

  const descriptor = connection(dataDir);
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  observe(page);
  await page.goto(`${descriptor.origin}#token=${descriptor.bootstrap}`);
  await page.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true }).click();
  await page.locator("textarea").first().fill("原生验收的加密草稿，重启浏览器应恢复。");
  await page.waitForFunction(() => document.body.textContent.includes("草稿已加密保存到本机"));
  const draft = await client.request("/api/v1/ai/drafts/writing-current");
  assert.equal(draft.content.prompt, "原生验收的加密草稿，重启浏览器应恢复。");
  await browser.close();
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  observe(page);
  await page.goto(`${descriptor.origin}#token=${descriptor.bootstrap}`);
  await page.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true }).click();
  await page.waitForFunction(() => document.querySelector("textarea")?.value === "原生验收的加密草稿，重启浏览器应恢复。");
  checks.push("encrypted_form_restored_after_browser_restart");

  await page.getByRole("button", { name: "原生验收文书 A · 已完成", exact: true }).click();
  await page.getByRole("button", { name: "编辑正文", exact: true }).click();
  const edited = "# 合成材料说明\n\n126800 元。用户尚未保存的正文修改。";
  await page.locator(".document-content-editor").fill(edited);
  await page.waitForFunction(() => document.body.textContent.includes("草稿已加密保存到本机"));
  // Confirm the storage snapshot, not an older success badge, before reloading.
  let persisted;
  for (let n = 0; n < 60; n++) {
    persisted = await client.request("/api/v1/ai/drafts/writing-current");
    if (persisted.content.content === edited) break;
    await sleep(100);
  }
  assert.equal(persisted.content.content, edited);
  await page.reload();
  await page.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true }).click();
  await page.waitForFunction(text => document.querySelector(".document-content-editor")?.value === text, edited);
  checks.push("unsaved_document_edit_restored_after_reload");
  await page.getByRole("button", { name: "保存正文修改", exact: true }).click();
  await page.waitForFunction(() => document.querySelector(".document-preview")?.textContent.includes("用户尚未保存的正文修改"));
  let savedDraft;
  for (let n = 0; n < 60; n++) {
    savedDraft = await client.request("/api/v1/ai/drafts/writing-current");
    if (savedDraft.content.dirty === false && savedDraft.content.run_id !== run.id) break;
    await sleep(100);
  }
  assert.equal(savedDraft.content.dirty, false);
  const savedId = savedDraft.content.run_id;
  assert.notEqual(savedId, run.id);
  const savedRun = await client.request(`/api/v1/ai/runs/${savedId}`);
  assert.equal(savedRun.content, edited);
  const callsBeforeExport = modelCalls;
  const bytes = await client.request(`/api/v1/ai/runs/${savedId}/export?format=txt&expected_revision=${savedRun.revision}`, "GET", undefined, true);
  assert.equal(bytes.toString("utf8").replace(/^\uFEFF/u, "").trim(), "合成材料说明\n\n126800 元。用户尚未保存的正文修改。");
  assert.equal(modelCalls, callsBeforeExport);
  checks.push("save_rebinds_snapshot_and_export_does_not_regenerate");
  const pdf = await client.request(`/api/v1/ai/runs/${savedId}/export?format=pdf&expected_revision=${savedRun.revision}`, "GET", undefined, true);
  assert.equal(pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  assert(pdf.length > 1024 && pdf.subarray(-64).includes(Buffer.from("%%EOF")));
  const docx = await client.request(`/api/v1/ai/runs/${savedId}/export?format=docx&expected_revision=${savedRun.revision}`, "GET", undefined, true);
  const docxPath = path.join(dataDir, "synthetic-export.docx");
  await fs.writeFile(docxPath, docx);
  execFileSync("python", ["-c", "import sys,zipfile,xml.etree.ElementTree as E; z=zipfile.ZipFile(sys.argv[1]); r=E.fromstring(z.read('word/document.xml')); text=''.join(r.itertext()); assert '126800' in text and '\u7528\u6237\u5c1a\u672a\u4fdd\u5b58\u7684\u6b63\u6587\u4fee\u6539' in text", docxPath], { windowsHide: true });
  assert.equal(modelCalls, callsBeforeExport);
  checks.push("native_typst_pdf_and_docx_export_same_saved_revision_without_model");
  const health = await client.request("/api/v1/health");
  assert.equal(health.status, "ready");
  assert.equal(health.supervision.material_worker.ready, true);
  assert.deepEqual(pageErrors, []);
  await page.screenshot({ path: path.join(output, "document-native.png"), fullPage: true });
  const report = { passed: true, checks, page_errors: pageErrors, model: "local synthetic mock only", model_calls: modelCalls };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  if (page && !page.isClosed()) await page.screenshot({ path: path.join(output, "failure.png"), fullPage: true }).catch(() => {});
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error), page_errors: pageErrors, http_errors: httpErrors }, null, 2));
  throw error;
} finally {
  if (browser) await browser.close();
  if (service) {
    if (providerId) await service.client.request("/api/v1/providers", "POST", { id: providerId, name: "audit-cleanup", base_url: "https://cleanup.invalid", model: "cleanup", api_key: "", allow_private_network: false }).catch(() => {});
    await service.stop();
  }
  await new Promise(resolve => mock.close(resolve));
}
