// Windows-native evidence for the default-off document worker fault build. Every input and model
// response is synthetic; the script never contacts a paid provider or opens a user workspace.
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const faultEnv = "LAWYER_ASSISTANCE_DOCUMENT_WORKER_FAULT";
const memoryLimit = 512 * 1024 * 1024;
const argumentsByName = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!name?.startsWith("--") || !value || argumentsByName.has(name)) throw new Error("fault_audit_invalid_arguments");
  argumentsByName.set(name, value);
}
if (argumentsByName.size !== 3 || process.argv.length !== 8) throw new Error("fault_audit_usage");
const faultExecutable = path.resolve(argumentsByName.get("--fault-exe") || "");
const productionExecutable = path.resolve(argumentsByName.get("--production-exe") || "");
const output = path.resolve(argumentsByName.get("--output") || "");
for (const executable of [faultExecutable, productionExecutable]) {
  const metadata = await fs.stat(executable).catch(() => null);
  if (!metadata?.isFile()) throw new Error("fault_audit_executable_missing");
}
if (await fs.stat(path.join(output, "report.json")).then(() => true).catch(() => false)) {
  throw new Error("fault_audit_output_exists");
}
await fs.mkdir(output, { recursive: true });

const checks = [];
const evidence = { production: {}, memory: {}, stall: {} };
const executableEvidence = Object.fromEntries(await Promise.all([
  ["fault_test", faultExecutable], ["production", productionExecutable],
].map(async ([kind, executable]) => {
  const bytes = await fs.readFile(executable);
  return [kind, { path: executable, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }];
})));
const requests = [];
const connections = new Set();

function pdf(kinds, seed) {
  const objects = ["<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"];
  const pages = [];
  for (const [index, kind] of kinds.entries()) {
    const pageId = objects.length + 1;
    pages.push(`${pageId} 0 R`);
    objects.push("");
    const streamId = objects.length + 1;
    const text = kind !== "scan" ? `BT /F1 12 Tf 36 740 Td (Synthetic fault audit ${seed} page ${index + 1}.) Tj ET\n` : "";
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
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(data)); data += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(data);
  data += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  data += offsets.slice(1).map(offset => `${String(offset).padStart(10, "0")} 00000 n \n`).join("");
  data += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(data);
}

function powershell(script, environment = {}) {
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    windowsHide: true, encoding: "utf8", env: { ...process.env, ...environment },
  }).trim();
}
function ownedWorkers(service) {
  const rows = powershell("$ErrorActionPreference='Stop'; $items=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId = ' + $env:AUDIT_PARENT_PID) | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine); ConvertTo-Json -InputObject $items -Compress", { AUDIT_PARENT_PID: String(service.server.pid) });
  const children = JSON.parse(rows || "[]");
  return children.filter(child => child.ParentProcessId === service.server.pid
    && path.resolve(child.ExecutablePath || "").toLowerCase() === path.resolve(service.server.spawnfile).toLowerCase()
    && /document-worker/u.test(child.CommandLine || ""));
}
async function until(predicate, timeout = 15000, label = "condition") {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const value = await predicate();
    if (value) return value;
    await sleep(100);
  }
  throw new Error(`${label}_timeout`);
}
async function assertReadyAndReaped(service) {
  await until(() => ownedWorkers(service).length === 0, 15000, "worker_reap");
  const health = await service.client.request("/api/v1/health");
  assert.equal(health.status, "ready");
  assert.equal(health.resources.ai.active, 0);
  assert.equal(health.resources.parse.active, 0);
  return health;
}
async function startWithFaultEnvironment(dataDir, executable, mode) {
  const prior = process.env[faultEnv];
  if (mode === undefined) delete process.env[faultEnv];
  else process.env[faultEnv] = mode;
  try {
    return await startServer(dataDir, executable);
  } finally {
    if (prior === undefined) delete process.env[faultEnv];
    else process.env[faultEnv] = prior;
  }
}
async function configure(service, label) {
  const provider = await service.client.request("/api/v1/ai/providers", "POST", {
    preset: "custom", name: `Synthetic ${label}`, base_url: `http://127.0.0.1:${mock.address().port}/v1`,
    enabled_models: ["audit-document"], api_key: "audit-synthetic-only", trust_raw: true, allow_private_network: true,
  });
  const selection = { provider_id: provider.id, model: "audit-document" };
  await service.client.request("/api/v1/ai/defaults", "PUT", { writing: selection, ocr: selection });
  return selection;
}
async function upload(service, bytes, name) {
  const form = new FormData();
  form.append("file", new Blob([bytes], { type: "application/pdf" }), name);
  return service.client.request("/api/v1/ai/attachments", "POST", form);
}
async function startPdfRun(service, selection, attachmentId, prompt) {
  return service.client.request("/api/v1/ai/runs", "POST", {
    kind: "writing", prompt, ...selection, attachment_ids: [attachmentId],
  });
}
async function terminal(service, id) {
  return until(async () => {
    const run = await service.client.request(`/api/v1/ai/runs/${id}`);
    return !["queued", "running"].includes(run.status) && run;
  }, 30000, "terminal");
}

const mock = http.createServer(async (request, response) => {
  connections.add(response);
  response.on("close", () => connections.delete(response));
  let raw = "";
  for await (const bytes of request) {
    raw += bytes;
    if (Buffer.byteLength(raw) > 20 * 1024 * 1024) { response.writeHead(413).end(); return; }
  }
  const body = JSON.parse(raw);
  const ocr = body.messages.some(message => Array.isArray(message.content)
    && message.content.some(part => part.type === "image_url"));
  requests.push({ ocr });
  const result = ocr
    ? { text: "Synthetic OCR fault-audit result.", complete: true, warnings: [] }
    : { title: "Synthetic fault audit", content: "Synthetic document completed.", citations: [] };
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ model: "audit-document", choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(result) } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));

async function runProductionNegativeChecks() {
  const command = spawnSync(productionExecutable, ["document-worker-fault", "memory"], {
    windowsHide: true, encoding: "utf8", timeout: 10000, env: { ...process.env, [faultEnv]: "memory" },
  });
  const diagnostic = `${command.stdout || ""}${command.stderr || ""}`;
  assert.notEqual(command.status, 0, "production command must not succeed");
  assert.match(diagnostic, /unrecognized subcommand|unknown subcommand/i, "production command must be absent");
  evidence.production.command_rejected = { exit_code: command.status, timed_out: Boolean(command.error) };
  checks.push("production_binary_rejects_fault_command");

  const dataDir = await fs.mkdtemp(path.join(output, "production-workspace-"));
  let service;
  try {
    service = await startWithFaultEnvironment(dataDir, productionExecutable, "memory");
    const selection = await configure(service, "production fault env ignored");
    const health = await service.client.request("/api/v1/health");
    assert.equal(Object.hasOwn(health.ocr.document_worker, "fault_injection"), false);
    const before = requests.length;
    const attachment = await upload(service, pdf(["scan"], "production-env"), "production-env.pdf");
    const run = await startPdfRun(service, selection, attachment.id, "Summarize synthetic PDF.");
    const complete = await terminal(service, run.id);
    assert.equal(complete.status, "completed", complete.error_code);
    assert.equal(requests.slice(before).filter(request => request.ocr).length, 1);
    assert.equal(requests.slice(before).filter(request => !request.ocr).length, 1);
    await assertReadyAndReaped(service);
    evidence.production.env_ignored_normal_pdf_completed = true;
    checks.push("production_binary_ignores_fault_environment");
  } finally {
    if (service) await service.stop();
  }
}

async function runFaultScenario(mode) {
  const dataDir = await fs.mkdtemp(path.join(output, `${mode}-workspace-`));
  let service;
  try {
    service = await startWithFaultEnvironment(dataDir, faultExecutable, mode);
    const selection = await configure(service, `${mode} fault injection`);
    const initial = await service.client.request("/api/v1/health");
    const initialFault = initial.ocr.document_worker.fault_injection;
    assert.equal(initialFault.enabled, true);
    assert.equal(initialFault.configured_fault, mode);
    assert.equal(initialFault.armed, true);
    assert.equal(initialFault.last_report, null);

    const attachment = await upload(service, pdf(["scan"], `${mode}-metadata`), `${mode}-metadata.pdf`);
    const inspection = await service.client.request("/api/v1/ai/context/inspect", "POST", {
      source_kind: "attachment", source_id: attachment.id,
    });
    assert.equal(inspection.format, "pdf");
    assert.equal(inspection.unit_kind, "page");
    assert.equal(inspection.unit_count, 1);
    const afterMetadata = await service.client.request("/api/v1/health");
    assert.equal(afterMetadata.ocr.document_worker.fault_injection.armed, true, "metadata must not consume render fault");
    assert.equal(afterMetadata.ocr.document_worker.fault_injection.last_report, null);
    checks.push(`${mode}_metadata_did_not_consume_render_fault`);

    const beforeFault = requests.length;
    const failedRun = await startPdfRun(service, selection, attachment.id, "Summarize synthetic PDF.");
    const failed = await terminal(service, failedRun.id);
    assert.equal(failed.status, "failed", failed.error_code);
    assert.equal(requests.length, beforeFault, "fault request must stop before OCR or writing provider dispatch");
    const health = await assertReadyAndReaped(service);
    const faultStatus = health.ocr.document_worker.fault_injection;
    assert.equal(faultStatus.armed, false, "only one render request may consume the fault");
    if (mode === "memory") {
      assert.equal(failed.error_code, "document_worker_memory_limit_rejected");
      const report = faultStatus.last_report;
      assert.notEqual(report, null, "memory Job evidence requires a VirtualAlloc rejection report");
      assert.equal(report.fault, "memory");
      assert.equal(report.outcome, "memory_limit_rejected");
      assert(report.target_bytes > memoryLimit);
      assert.equal(report.attempted_bytes, report.target_bytes);
      assert(report.touched_bytes > 0);
      assert(report.touched_bytes < report.target_bytes);
      assert(report.first_rejection_bytes > 0);
      assert(report.first_rejection_bytes <= report.attempted_bytes);
      assert(Number.isInteger(report.win32_error) && report.win32_error > 0);
      evidence.memory = { error_code: failed.error_code, report, worker_reaped: true, permits_after_failure: health.resources };
      checks.push("memory_fault_virtualalloc_rejection_attempted_touched_win32_and_reaped");
    } else {
      assert.equal(failed.error_code, "document_worker_timeout");
      assert.equal(faultStatus.last_report, null);
      evidence.stall = { error_code: failed.error_code, worker_reaped: true, permits_after_failure: health.resources };
      checks.push("stall_fault_short_deadline_failed_reaped_parent_ready");
    }

    const beforeRecovery = requests.length;
    const recoveryAttachment = await upload(service, pdf(["scan"], `${mode}-recovery`), `${mode}-recovery.pdf`);
    const recoveryRun = await startPdfRun(service, selection, recoveryAttachment.id, "Summarize synthetic recovery PDF.");
    const recovery = await terminal(service, recoveryRun.id);
    assert.equal(recovery.status, "completed", recovery.error_code);
    assert.equal(requests.slice(beforeRecovery).filter(request => request.ocr).length, 1);
    assert.equal(requests.slice(beforeRecovery).filter(request => !request.ocr).length, 1);
    await assertReadyAndReaped(service);
    checks.push(`${mode}_same_daemon_next_pdf_completed`);
  } finally {
    if (service) await service.stop();
  }
}

try {
  await runProductionNegativeChecks();
  await runFaultScenario("memory");
  await runFaultScenario("stall");
  const report = {
    passed: true, checks, evidence, native_pdfium: true, model: "localhost synthetic mock only",
    executables: executableEvidence, model_calls: requests.length,
    original_crash_root_cause: "not established; these are feature-gated injected worker failures",
  };
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report));
} catch (error) {
  const report = { passed: false, checks, evidence, executables: executableEvidence, error: String(error), model_calls: requests.length };
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`).catch(() => {});
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const response of connections) response.destroy();
  await new Promise(resolve => mock.close(resolve));
}
