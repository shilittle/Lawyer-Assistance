// Actual Windows daemon/Pdfium process isolation. All documents and model replies are synthetic.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "document-worker-native");
await fs.mkdir(output, { recursive: true });
const dataDir = await fs.mkdtemp(path.join(output, "workspace-"));
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const checks = [], requests = [], connections = new Set();
let service, providerId, holdOcr = false;

function pdf(kinds, seed) {
  const objects = ["<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"];
  const pages = [];
  for (const [index, kind] of kinds.entries()) {
    const pageId = objects.length + 1;
    pages.push(`${pageId} 0 R`);
    objects.push("");
    const streamId = objects.length + 1;
    const text = kind !== "scan" ? `BT /F1 12 Tf 36 740 Td (Synthetic contract ${seed} page ${index + 1}. Payment is 126800 units. The delivery date is fixed by this synthetic agreement.) Tj ET\n` : "";
    const graphics = kind !== "text" ? "q 400 0 0 600 36 60 cm /Im1 Do Q\n" : "";
    const content = text + graphics;
    objects.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}endstream`);
    let xobjects = "";
    if (kind !== "text") {
      const imageId = objects.length + 1;
      const hex = "FFFFFF000000000000FFFFFF>";
      objects.push(`<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /ASCIIHexDecode /Length ${hex.length} >>\nstream\n${hex}\nendstream`);
      xobjects = `/XObject << /Im1 ${imageId} 0 R >>`;
    }
    objects[pageId - 1] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> ${xobjects} >> /Contents ${streamId} 0 R >>`;
  }
  objects[1] = `<< /Type /Pages /Count ${pages.length} /Kids [${pages.join(" ")}] >>`;
  let data = "%PDF-1.4\n", offsets = [0];
  objects.forEach((object, i) => { offsets.push(Buffer.byteLength(data)); data += `${i + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(data);
  data += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  data += offsets.slice(1).map(offset => `${String(offset).padStart(10, "0")} 00000 n \n`).join("");
  data += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(data);
}

function powershell(script, environment = {}) {
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { windowsHide: true, encoding: "utf8", env: { ...process.env, ...environment } }).trim();
}
function children() {
  const rows = powershell("$ErrorActionPreference='Stop'; $items=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $env:AUDIT_PARENT_PID) | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine); ConvertTo-Json -InputObject $items -Compress", { AUDIT_PARENT_PID: String(service.server.pid) });
  return JSON.parse(rows || "[]");
}
function ownedWorkers() {
  return children().filter(child => child.ParentProcessId === service.server.pid && path.resolve(child.ExecutablePath || "").toLowerCase() === path.resolve(service.server.spawnfile).toLowerCase() && /document-worker/u.test(child.CommandLine || ""));
}
async function until(predicate, timeout = 15000, label = "condition") {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const value = await predicate(); if (value) return value; await sleep(100); }
  throw new Error(`${label}_timeout`);
}
const mock = http.createServer(async (req, res) => {
  connections.add(res);
  res.on("close", () => connections.delete(res));
  let raw = "";
  for await (const bytes of req) { raw += bytes; if (Buffer.byteLength(raw) > 20 * 1024 * 1024) { res.writeHead(413).end(); return; } }
  const body = JSON.parse(raw);
  const ocr = body.messages.some(message => Array.isArray(message.content) && message.content.some(part => part.type === "image_url"));
  requests.push({ ocr, messages: body.messages });
  if (ocr && holdOcr) return;
  const result = ocr ? { text: "Synthetic OCR contract: payment 126800 units.", complete: true, warnings: [] } : { title: "Synthetic PDF audit", content: "Synthetic document completed.", citations: [] };
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ model: "audit-document", choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(result) } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));

async function upload(bytes, name) {
  const form = new FormData();
  form.append("file", new Blob([bytes], { type: "application/pdf" }), name);
  return service.client.request("/api/v1/ai/attachments", "POST", form);
}
async function runPdf(kinds, seed) {
  const attachment = await upload(pdf(kinds, seed), `${seed}.pdf`);
  return service.client.request("/api/v1/ai/runs", "POST", { kind: "writing", prompt: "Summarize the synthetic contract.", provider_id: providerId, model: "audit-document", attachment_ids: [attachment.id] });
}
async function terminal(id) {
  return until(async () => { const run = await service.client.request(`/api/v1/ai/runs/${id}`); return !["queued", "running"].includes(run.status) && run; }, 30000, "terminal");
}
async function assertHealthyAndReaped() {
  await until(() => ownedWorkers().length === 0, 10000, "worker_reap");
  const health = await service.client.request("/api/v1/health");
  assert.equal(health.status, "ready");
  assert.equal(health.resources.ai.active, 0);
  assert.equal(health.resources.parse.active, 0);
}
try {
  service = await startServer(dataDir, executable, undefined, { portable: process.argv.includes("--portable") });
  const provider = await service.client.request("/api/v1/ai/providers", "POST", { preset: "custom", name: "Synthetic document worker audit", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["audit-document"], api_key: "audit-synthetic-only", trust_raw: true, allow_private_network: true });
  providerId = provider.id;
  const selection = { provider_id: providerId, model: "audit-document" };
  await service.client.request("/api/v1/ai/defaults", "PUT", { writing: selection, ocr: selection });
  for (const [label, kinds, expectedOcr] of [["text", ["text"], 0], ["scanned", ["scan"], 1], ["mixed", ["text", "mixed"], 1]]) {
    const before = requests.length;
    const started = await runPdf(kinds, label);
    const done = await terminal(started.id);
    assert.equal(done.status, "completed", done.error_code);
    const sent = requests.slice(before);
    assert.equal(sent.filter(request => request.ocr).length, expectedOcr, label);
    assert.equal(sent.filter(request => !request.ocr).length, 1);
    if (expectedOcr === 0) assert(JSON.stringify(sent[0].messages).includes("Payment is 126800"));
    await assertHealthyAndReaped();
    checks.push(`${label}_page_selective_ocr`);
  }
  const modules = powershell("$ErrorActionPreference='Stop'; (Get-Process -Id ([int]$env:AUDIT_PARENT_PID)).Modules | ForEach-Object ModuleName", { AUDIT_PARENT_PID: String(service.server.pid) });
  assert(!modules.toLowerCase().includes("pdfium"), "parent must not load Pdfium DLL");
  checks.push("parent_process_never_loaded_pdfium");

  for (const action of ["cancel", "crash"]) {
    holdOcr = true;
    const before = requests.length;
    const started = await runPdf(Array(8).fill("scan"), action);
    await until(() => requests.slice(before).some(request => request.ocr), 15000, "ocr_dispatch");
    const worker = await until(() => ownedWorkers()[0], 15000, "document_worker");
    const start = Date.now();
    if (action === "cancel") await service.client.request(`/api/v1/ai/runs/${started.id}/cancel`, "POST", {});
    else {
      // Only the just-observed same-executable document child of our fresh test daemon.
      assert(ownedWorkers().some(current => current.ProcessId === worker.ProcessId));
      process.kill(worker.ProcessId);
    }
    const done = await terminal(started.id);
    assert.equal(done.status, action === "cancel" ? "cancelled" : "failed", done.error_code);
    await assertHealthyAndReaped();
    await until(() => connections.size === 0, 10000, "mock_connection_close");
    assert(Date.now() - start < 15000, "child exit/cancel must interrupt the held model request");
    assert.equal(requests.slice(before).filter(request => !request.ocr).length, 0);
    checks.push(`worker_${action}_reaped_model_closed_parent_ready`);
    holdOcr = false;
  }
  const malformed = await upload(Buffer.from("%PDF-1.4\ninvalid synthetic PDF\n"), "broken.pdf");
  const started = await service.client.request("/api/v1/ai/runs", "POST", { kind: "writing", prompt: "Synthetic invalid PDF", ...selection, attachment_ids: [malformed.id] });
  const done = await terminal(started.id);
  assert.equal(done.status, "failed");
  await assertHealthyAndReaped();
  checks.push("malformed_document_fails_without_service_exit");
  const report = { passed: true, checks, native_pdfium: true, model: "localhost synthetic mock only", model_calls: requests.length, original_crash_root_cause: "not established; these are injected child failures" };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error), model_calls: requests.length }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const response of connections) response.destroy();
  if (service) {
    if (providerId) await service.client.request("/api/v1/providers", "POST", { id: providerId, name: "audit-cleanup", base_url: "https://cleanup.invalid", model: "cleanup", api_key: "", allow_private_network: false }).catch(() => {});
    await service.stop();
  }
  await new Promise(resolve => mock.close(resolve));
}
