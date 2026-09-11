// Diagnostics evidence only: synthetic documents, fresh workspaces and a localhost mock.
// An injected exit is never evidence of the original, still unidentified incident.
import assert from "node:assert/strict";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const options = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index], value = process.argv[index + 1];
  if (!key?.startsWith("--") || !value || options.has(key)) throw new Error("diagnostic_audit_arguments");
  options.set(key, value);
}
assert.deepEqual([...options.keys()].filter(key => key !== "--scope").sort(), ["--fault-exe", "--output", "--production-exe"]);
const scope = options.get("--scope") || "all";
assert(["all", "process"].includes(scope));
const output = path.resolve(options.get("--output"));
const faultExe = path.resolve(options.get("--fault-exe"));
const productionExe = path.resolve(options.get("--production-exe"));
await fs.mkdir(path.dirname(output), { recursive: true });
await fs.mkdir(output); // Attempts are immutable, including failed attempts.
const identities = {};
for (const [role, filename] of [["fault_test", faultExe], ["production", productionExe]]) {
  const bytes = await fs.readFile(filename);
  identities[role] = { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
}
const startedAt = new Date().toISOString();
const checks = [], scenarios = [];
const plannedChecks = [
  "explicit_safe_diagnostic_entry", "unwritable_log_explicit_failure",
  "hidden_launch_panic_persistent_safe_frames", "production_has_no_diagnostic_fault_commands",
  "hidden_launch_start_failure_persisted", "externally_terminated_daemon_cannot_claim_normal_stop",
  "normal_stop_has_daemon_terminal_record",
  ...(scope === "all" ? ["worker_panic_exit_not_overwritten_by_cleanup", "worker_nonzero_exit_not_misclassified_as_oom",
    "worker_windows_shaped_exit_code_preserved_without_causal_claim", "worker_stderr_flood_bounded_and_private",
    "worker_timeout_intent_precedes_kill", "worker_cancel_intent_precedes_kill",
    "worker_external_exit_observed_without_claiming_cause"] : []),
];
function passedGate(name) {
  checks.push(name);
  console.log(JSON.stringify({ gate: name, status: "passed", at: new Date().toISOString() }));
}
function gateRecords(failed = false) {
  const firstIncomplete = plannedChecks.find(name => !checks.includes(name));
  return plannedChecks.map(id => ({ id, status: checks.includes(id) ? "passed" : failed && id === firstIncomplete ? "failed" : "not_run" }));
}
const faultEnvironment = "LAWYER_ASSISTANCE_DOCUMENT_WORKER_FAULT";
const connections = new Set();
let holdOcr = false;
let ocrCalls = 0;

// Every scenario uses these exact bytes; fresh workspaces isolate the OCR cache.
function syntheticPdf() {
  const graphics = "q 400 0 0 600 36 60 cm /Im1 Do Q\n";
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>",
    `<< /Length ${Buffer.byteLength(graphics)} >>\nstream\n${graphics}endstream`,
    "<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /ASCIIHexDecode /Length 25 >>\nstream\nFFFFFF000000000000FFFFFF>\nendstream",
  ];
  let document = "%PDF-1.4\n", offsets = [0];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(document)); document += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(document);
  document += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  document += offsets.slice(1).map(offset => `${String(offset).padStart(10, "0")} 00000 n \n`).join("");
  document += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(document);
}
const pdfBytes = syntheticPdf();
const inputIdentity = { sha256: createHash("sha256").update(pdfBytes).digest("hex"), bytes: pdfBytes.length, synthetic: true };

async function until(predicate, label, milliseconds = 20000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await sleep(50);
  }
  throw new Error(`${label}_timeout`);
}
function powershell(script, environment = {}) {
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    windowsHide: true, encoding: "utf8", env: { ...process.env, ...environment }, timeout: 15000,
  }).trim();
}
function ownedWorkers(service) {
  const raw = powershell("$ErrorActionPreference='Stop'; $items=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId = '+$env:AUDIT_PARENT_PID) | Select-Object ProcessId,ParentProcessId,ExecutablePath); ConvertTo-Json -InputObject $items -Compress", { AUDIT_PARENT_PID: String(service.server.pid) });
  return JSON.parse(raw || "[]").filter(child => child.ParentProcessId === service.server.pid
    && path.resolve(child.ExecutablePath || "").toLowerCase() === path.resolve(service.server.spawnfile).toLowerCase());
}
async function readProcessLogs(workspace) {
  const directory = path.join(workspace, "diagnostics", "process");
  const files = [];
  async function visit(base) {
    for (const entry of await fs.readdir(base, { withFileTypes: true })) {
      const filename = path.join(base, entry.name);
      if (entry.isDirectory()) await visit(filename);
      else if (entry.isFile() && /\.jsonl(?:\.[0-9]+)?$/u.test(entry.name)) files.push(filename);
    }
  }
  await visit(directory);
  assert(files.length > 0, "missing diagnostic logs must fail the gate");
  const events = [];
  for (const filename of files.sort()) {
    const bytes = await fs.readFile(filename);
    assert(bytes.length <= 256 * 1024, "bounded diagnostic file");
    const text = bytes.toString("utf8");
    for (const forbidden of ["audit-synthetic-only", "DIAGNOSTIC_PRIVATE_SENTINEL", "data:image/", "image_url", "Bearer ", "connection.dpapi"]) {
      assert(!text.includes(forbidden), `diagnostic privacy violation: ${forbidden}`);
    }
    for (const line of text.split(/\r?\n/u).filter(Boolean)) events.push(JSON.parse(line));
  }
  return { files, events };
}
async function saveSafeLogs(label, logs, workspace) {
  const destination = path.join(output, "safe-logs", label);
  await fs.mkdir(destination, { recursive: true });
  const inventory = [];
  for (const filename of logs.files) {
    const bytes = await fs.readFile(filename);
    const relative = path.relative(path.join(workspace, "diagnostics", "process"), filename);
    const copy = path.join(destination, relative);
    await fs.mkdir(path.dirname(copy), { recursive: true });
    await fs.writeFile(copy, bytes, { flag: "wx" });
    inventory.push({ path: path.relative(output, copy).replaceAll("\\", "/"), bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  return inventory;
}
async function startWithMode(workspace, executable, mode) {
  const previous = process.env[faultEnvironment];
  if (mode) process.env[faultEnvironment] = mode;
  else delete process.env[faultEnvironment];
  try { return await startServer(workspace, executable); }
  finally {
    if (previous === undefined) delete process.env[faultEnvironment];
    else process.env[faultEnvironment] = previous;
  }
}
async function configure(service) {
  const provider = await service.client.request("/api/v1/ai/providers", "POST", {
    preset: "custom", name: "Synthetic process diagnosis", base_url: `http://127.0.0.1:${mock.address().port}/v1`,
    enabled_models: ["audit-document"], api_key: "audit-synthetic-only", trust_raw: true, allow_private_network: true,
  });
  const selection = { provider_id: provider.id, model: "audit-document" };
  await service.client.request("/api/v1/ai/defaults", "PUT", { writing: selection, ocr: selection });
  return selection;
}
async function beginRun(service, selection) {
  const form = new FormData();
  form.append("file", new Blob([pdfBytes], { type: "application/pdf" }), "synthetic-identical.pdf");
  const attachment = await service.client.request("/api/v1/ai/attachments", "POST", form);
  return service.client.request("/api/v1/ai/runs", "POST", {
    kind: "writing", prompt: "Synthetic bounded process diagnostic.", ...selection, attachment_ids: [attachment.id],
  });
}
async function terminal(service, id) {
  return until(async () => {
    const run = await service.client.request(`/api/v1/ai/runs/${id}`);
    return !["queued", "running"].includes(run.status) && run;
  }, "task_terminal", 30000);
}

const mock = http.createServer(async (request, response) => {
  connections.add(response);
  response.on("close", () => connections.delete(response));
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 20 * 1024 * 1024) { response.writeHead(413).end(); return; }
  }
  const body = JSON.parse(raw);
  const ocr = body.messages.some(message => Array.isArray(message.content) && message.content.some(part => part.type === "image_url"));
  if (ocr) { ocrCalls += 1; if (holdOcr) return; }
  const result = ocr ? { text: "Synthetic process diagnostic OCR.", complete: true, warnings: [] }
    : { title: "Synthetic diagnostic", content: "Synthetic completed document.", citations: [] };
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ model: "audit-document", choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(result) } }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
});

// The remainder binds assertions to the structured process schema, never stderr text.
function eventRows(logs, name) { return logs.events.filter(event => event.event === name); }
function verifyIdentities(logs, service, operationId) {
  const parent = logs.events.find(event => event.pid === service.server.pid);
  assert(parent?.launch_id, "daemon launch identity");
  assert.equal(parent.exe_sha256, identities.fault_test.sha256);
  const child = logs.events.find(event => event.role === "document_worker"
    && event.parent_pid === service.server.pid);
  assert(child, "worker own persistent identity");
  assert.equal(child.parent_launch_id, parent.launch_id);
  assert.notEqual(child.launch_id, parent.launch_id);
  assert(logs.events.some(event => event.operation_id === operationId && event.event === "child_started"), "actual run id linked to child launch");
  assert(child.memory?.working_set_bytes > 0 && child.memory.private_commit_bytes > 0, "worker resource sample");
  return Object.fromEntries(["build_revision", "exe_sha256", "launch_id", "parent_launch_id", "pid", "parent_pid", "role"].map(key => [key, child[key]]));
}
async function workerScenario(label, mode, action) {
  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  const row = { id: label, status: "failed", input: inputIdentity, operation_id: null };
  scenarios.push(row);
  let service;
  try {
    holdOcr = Boolean(action);
    service = await startWithMode(workspace, faultExe, mode);
    const selection = await configure(service);
    const previousCalls = ocrCalls;
    const run = await beginRun(service, selection);
    row.operation_id = run.id;
    if (action) {
      await until(() => ocrCalls > previousCalls, "worker_waiting_for_ocr");
      const child = await until(() => ownedWorkers(service)[0], "owned_worker");
      if (action === "cancel") await service.client.request(`/api/v1/ai/runs/${run.id}/cancel`, "POST", {});
      else {
        assert(ownedWorkers(service).some(value => value.ProcessId === child.ProcessId));
        row.external_termination = { pid: child.ProcessId, parent_pid: service.server.pid, initiated_at: new Date().toISOString(), source: "test_harness" };
        process.kill(child.ProcessId);
      }
    }
    const completed = await terminal(service, run.id);
    const expected = action === "cancel" ? "cancelled" : "failed";
    assert.equal(completed.status, expected, completed.error_code);
    await until(() => ownedWorkers(service).length === 0, "child_reaped");
    const health = await service.client.request("/api/v1/health");
    assert.equal(health.status, "ready");
    assert.equal(health.resources.ai.active, 0);
    assert.equal(health.resources.parse.active, 0);
    const logs = await readProcessLogs(workspace);
    const childIdentity = verifyIdentities(logs, service, run.id);
    const exits = eventRows(logs, "child_exit").filter(event => event.operation_id === run.id);
    assert(exits.length > 0, "raw worker exit must be persisted");
    const exit = exits.at(-1);
    assert.equal(exit.child_reaped, true);
    assert.match(exit.exit_code_hex, /^0x[0-9A-Fa-f]{8}$/u);
    const intents = eventRows(logs, "termination_intent").filter(event => event.operation_id === run.id);
    if (action === "cancel" || mode === "stall") {
      assert(intents.some(event => event.termination_intent === (action === "cancel" ? "cancelled" : "timeout")));
      assert.equal(exit.exit_source, "after_cleanup");
      assert(intents.every(event => event.timestamp_unix_ms <= exit.timestamp_unix_ms), "intent logged before observed cleanup exit");
    } else {
      assert.equal(exit.exit_source, "natural");
      assert.equal(intents.length, 0, "already exited child must not acquire a cleanup cause");
    }
    if (mode === "panic") {
      assert.equal(exit.native_exit_code, 101);
      const panic = eventRows(logs, "panic").find(event => event.pid === childIdentity.pid);
      assert(panic, "worker panic persisted before EOF cleanup");
    }
    if (mode === "nonzero") assert.equal(exit.native_exit_code, 23);
    if (mode === "native-exit") {
      assert.equal(exit.exit_code_hex, "0xC0000005");
      row.exit_code_simulation = "ExitProcess status only; no SEH exception or actual access violation triggered";
    }
    if (mode === "stderr-flood") {
      assert.equal(exit.native_exit_code, 74);
      assert(exit.stderr_discarded_bytes >= 256 * 1024, "flood drained without persistence");
    }
    assert.equal(exit.memory_limit_exceeded, undefined, "nonzero exit alone never establishes OOM");
    row.observed = { task_status: completed.status, error_code: completed.error_code, child_identity: childIdentity, exit, termination_intents: intents };
    // An identical failed source must be usable next on the same daemon, with the one-shot
    // injection disarmed. This is a recovery gate, not an old/new incident comparison.
    {
      holdOcr = false;
      for (const response of connections) response.destroy();
      const recovery = await beginRun(service, selection);
      const recovered = await terminal(service, recovery.id);
      assert.equal(recovered.status, "completed");
      await until(() => ownedWorkers(service).length === 0, "recovery_reaped");
      row.recovery_same_input = "passed";
      row.recovery = { operation_id: recovery.id, status: recovered.status };
    }
    row.logs = await saveSafeLogs(label, await readProcessLogs(workspace), workspace);
    row.status = "passed";
    passedGate(label);
  } finally {
    holdOcr = false;
    for (const response of connections) response.destroy();
    if (service) await service.stop();
  }
}

async function directDiagnosticScenario() {
  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  const result = spawnSync(productionExe, ["diagnostics", "--data-dir", workspace], { windowsHide: true, encoding: "utf8", timeout: 15000 });
  assert.equal(result.status, 0, result.stderr);
  const status = JSON.parse(result.stdout);
  assert.equal(status.identity.exe_sha256, identities.production.sha256);
  assert.equal(status.ready, true);
  const logs = await readProcessLogs(workspace);
  scenarios.push({ id: "explicit_safe_diagnostic_entry", status: "passed", diagnostic: status, logs: await saveSafeLogs("diagnostics", logs, workspace) });
  passedGate("explicit_safe_diagnostic_entry");
  const noLogWorkspace = await fs.mkdtemp(path.join(output, "workspace-"));
  await fs.mkdir(path.join(noLogWorkspace, "diagnostics"));
  await fs.writeFile(path.join(noLogWorkspace, "diagnostics", "process"), "synthetic blocked directory");
  const failed = spawnSync(productionExe, ["diagnostics", "--data-dir", noLogWorkspace], { windowsHide: true, encoding: "utf8", timeout: 15000 });
  const failure = JSON.parse(failed.stdout);
  assert.equal(failed.status, 1, "unwritable log must also fail the diagnostic command");
  assert.equal(failure.ready, false, "unwritable log must not be reported as successful diagnosis");
  scenarios.push({ id: "unwritable_log_explicit_failure", status: "passed", exit_code: failed.status, diagnostic: failure });
  passedGate("unwritable_log_explicit_failure");
}

async function panicScenario() {
  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  const result = spawnSync(faultExe, ["process-diagnostic-fault", "panic", "--data-dir", workspace], { windowsHide: true, encoding: "utf8", timeout: 15000 });
  assert.equal(result.status, 101);
  assert(!`${result.stderr}${result.stdout}`.includes("DIAGNOSTIC_PRIVATE_SENTINEL"));
  const logs = await readProcessLogs(workspace);
  const panic = eventRows(logs, "panic")[0];
  assert(panic, "hidden-console panic must have a persistent record");
  assert(panic.panic?.raw_stack?.length > 0, "fixed raw stack addresses available for exact symbols");
  assert.match(panic.pdb_identity || "", /^rsds-[0-9a-f]{32}-[0-9]+$/u, "main executable has a CodeView binding");
  assert(panic.panic.raw_stack.some(frame => frame.module_binding === "main_executable" && frame.module_offset_hex));
  for (const frame of panic.panic.raw_stack) {
    assert(!/[\\/]/u.test(frame.module_name || ""), "module identity excludes arbitrary paths");
    assert(["main_executable", "unbound_module", "unresolved_module"].includes(frame.module_binding));
  }
  scenarios.push({ id: "hidden_launch_panic_persistent_safe_frames", status: "passed", exit_code: result.status, logs: await saveSafeLogs("panic", logs, workspace) });
  passedGate("hidden_launch_panic_persistent_safe_frames");
  for (const command of ["process-diagnostic-fault", "document-worker-fault"]) {
    const rejected = spawnSync(productionExe, [command, "panic"], { windowsHide: true, encoding: "utf8", timeout: 15000 });
    assert.equal(rejected.status, 2);
    assert.match(rejected.stderr, /unrecognized subcommand|unknown subcommand/iu);
  }
  passedGate("production_has_no_diagnostic_fault_commands");
}

async function startupFailureScenario() {
  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  const legalDb = process.env.LAWYER_AUDIT_LEGAL_DB || path.join(process.env.LAWYER_AUDIT_CORPUS || path.join(root, "data/runtime"), "legal_core.sqlite");
  const result = spawnSync(productionExe, ["serve", "--port", String(mock.address().port), "--data-dir", workspace, "--legal-db", legalDb], { windowsHide: true, encoding: "utf8", timeout: 15000 });
  assert.equal(result.status, 1, result.stderr);
  const logs = await readProcessLogs(workspace);
  assert(eventRows(logs, "startup_failed").some(event => event.error_code === "port_in_use"));
  scenarios.push({ id: "hidden_launch_start_failure_persisted", status: "passed", exit_code: result.status, logs: await saveSafeLogs("launch-failure", logs, workspace) });
  passedGate("hidden_launch_start_failure_persisted");
}

async function mainProcessExitScenario() {
  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  let service;
  let collector;
  try {
    service = await startWithMode(workspace, productionExe);
    const before = await readProcessLogs(workspace);
    assert(before.events.some(event => event.pid === service.server.pid && event.phase === "serving"));
    const reportFile = path.join(output, "external-main-process-capture.json");
    collector = spawn("python", [path.join(root, "scripts/collect_crash_diagnostics.py"), "--pid", String(service.server.pid),
      "--duration-seconds", "3", "--interval-ms", "100", "--channel", "Application", "--output", reportFile,
      "--diagnostics-dir", path.join(workspace, "diagnostics", "process")],
    { cwd: root, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    const collectorFinished = new Promise((resolve, reject) => { collector.once("error", reject); collector.once("exit", resolve); });
    await sleep(1000); // Leave a bounded initial sampling interval before the deliberate exit.
    assert.equal(collector.exitCode, null, "collector must be sampling the live process before injection");
    const injectedAt = new Date().toISOString();
    service.server.kill();
    await until(() => service.server.exitCode !== null || service.server.signalCode !== null, "external_main_exit");
    const captureExit = await collectorFinished;
    const capture = JSON.parse(await fs.readFile(reportFile, "utf8"));
    assert.equal(capture.status, "failed", "a disappeared target is an incomplete/failed window, never success");
    assert.equal(captureExit, 1);
    assert(capture.observations?.includes("target_exited"));
    assert(capture.sample_count >= 2);
    assert(capture.samples.some(sample => sample.processes.some(process => process.pid === service.server.pid && process.working_set_bytes > 0)));
    const logs = await readProcessLogs(workspace);
    assert(!logs.events.some(event => event.pid === service.server.pid && event.event === "normal_stop"));
    scenarios.push({ id: "externally_terminated_daemon_cannot_claim_normal_stop", status: "passed", pid: service.server.pid, injected_at: injectedAt,
      harness_exit_code: service.server.exitCode, harness_exit_signal: service.server.signalCode, collector_report: path.basename(reportFile), logs: await saveSafeLogs("external-daemon", logs, workspace) });
    passedGate("externally_terminated_daemon_cannot_claim_normal_stop");
  } finally {
    if (collector?.exitCode === null) collector.kill();
    if (service) await service.stop();
  }
  service = undefined;
  const normalWorkspace = await fs.mkdtemp(path.join(output, "workspace-"));
  try {
    service = await startWithMode(normalWorkspace, productionExe);
    const stopped = spawnSync(service.server.spawnfile, ["stop", "--data-dir", normalWorkspace], { windowsHide: true, encoding: "utf8", timeout: 15000 });
    assert.equal(stopped.status, 0, stopped.stderr);
    await until(() => service.server.exitCode !== null, "normal_main_stop");
    const logs = await readProcessLogs(normalWorkspace);
    assert(logs.events.some(event => event.pid === service.server.pid && event.event === "normal_stop"));
    scenarios.push({ id: "normal_stop_has_daemon_terminal_record", status: "passed", exit_code: service.server.exitCode,
      logs: await saveSafeLogs("normal-stop", logs, normalWorkspace) });
    passedGate("normal_stop_has_daemon_terminal_record");
  } finally {
    if (service) await service.stop();
  }
}

await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
try {
  await directDiagnosticScenario();
  await panicScenario();
  await startupFailureScenario();
  await mainProcessExitScenario();
  if (scope === "all") {
    await workerScenario("worker_panic_exit_not_overwritten_by_cleanup", "panic");
    await workerScenario("worker_nonzero_exit_not_misclassified_as_oom", "nonzero");
    await workerScenario("worker_windows_shaped_exit_code_preserved_without_causal_claim", "native-exit");
    await workerScenario("worker_stderr_flood_bounded_and_private", "stderr-flood");
    await workerScenario("worker_timeout_intent_precedes_kill", "stall");
    await workerScenario("worker_cancel_intent_precedes_kill", undefined, "cancel");
    await workerScenario("worker_external_exit_observed_without_claiming_cause", undefined, "external");
  }
  assert.deepEqual(checks, plannedChecks, "every planned diagnostic gate executed");
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify({ passed: true, status: "passed", scope, started_at: startedAt, ended_at: new Date().toISOString(), checks, gates: gateRecords(), scenarios, executables: identities, original_incident: { status: "not_run", root_cause: "unconfirmed", reason: "original action/version/time/affected role unknown" } }, null, 2)}\n`);
  console.log(JSON.stringify({ passed: true, checks, output }));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify({ passed: false, status: "failed", scope, started_at: startedAt, ended_at: new Date().toISOString(), checks, gates: gateRecords(true), scenarios, executables: identities, error: String(error), original_crash_root_cause: "unconfirmed" }, null, 2)}\n`).catch(() => {});
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const response of connections) response.destroy();
  await new Promise(resolve => mock.close(resolve));
}
