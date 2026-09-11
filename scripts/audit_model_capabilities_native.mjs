// R07 real HTTP configuration round trips. No model dispatch is authorized here.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { root, startServer } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "model-capabilities-native");
await fs.mkdir(output, { recursive: true });
try { await fs.access(path.join(output, "report.json")); throw new Error("evidence_directory_already_used"); } catch (error) { if (error.code !== "ENOENT") throw error; }
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
const legalDb = path.join(output, "legal.sqlite");
execFileSync("python", ["-c", "import pathlib,sqlite3,sys; r=pathlib.Path(sys.argv[1]); c=sqlite3.connect(sys.argv[2]); c.executescript((r/'data/schema/legal_core.sql').read_text(encoding='utf-8')); c.executescript((r/'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8')); c.close()", root, legalDb], { windowsHide: true });
let service, providerId, dispatches = 0;
const checks = [], started = new Date().toISOString();
const planned = ["capacity_only_preserves_unknown", "capacity_patch_preserves_explicit_false", "omitted_map_does_not_clear_capabilities", "explicit_null_changes_only_named_feature", "unknown_capacity_uses_16k_4k", "configuration_survives_daemon_restart"];
const mock = http.createServer((request, response) => { dispatches++; response.writeHead(500).end(); });
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
const base = () => ({ id: providerId, preset: "custom", name: "Synthetic capability declaration", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["capability-mock"], api_key: "synthetic-only", allow_private_network: true });
const save = capabilities => service.client.request("/api/v1/ai/providers", "POST", { ...base(), ...(capabilities === undefined ? {} : { model_capabilities: { "capability-mock": capabilities } }) });
async function configured() { const response = await service.client.request("/api/v1/ai/providers"); const value = response.providers.find(provider => provider.id === providerId); assert(value); return value.model_capabilities["capability-mock"]; }
const estimate = () => service.client.request("/api/v1/ai/context/estimate", "POST", { kind: "writing", prompt: "Synthetic configuration preflight only.", provider_id: providerId, model: "capability-mock" });
const startRun = () => service.client.request("/api/v1/ai/runs", "POST", { kind: "writing", prompt: "Synthetic request must be rejected before dispatch.", provider_id: providerId, model: "capability-mock" });
async function check(id, operation) {
  const start = performance.now();
  try { const evidence = await operation(); assert.equal(dispatches, 0); checks.push({ id, status: "passed", elapsed_ms: performance.now() - start, evidence }); }
  catch (error) { checks.push({ id, status: "failed", elapsed_ms: performance.now() - start, error: String(error) }); throw error; }
}
try {
  service = await startServer(workspace, executable, legalDb, { portable: process.argv.includes("--portable") });
  await check(planned[0], async () => {
    providerId = (await save({ context_window_tokens: 32768, max_output_tokens: 4096 })).id;
    const value = await configured();
    for (const key of ["supports_tools", "supports_structured_output", "supports_vision"]) assert.equal(value[key] ?? null, null);
    assert.equal(value.context_window_tokens, 32768); return value;
  });
  await check(planned[1], async () => {
    await save({ supports_tools: false, supports_vision: false });
    await save({ context_window_tokens: 65536, max_output_tokens: 8192 });
    const value = await configured(); assert.equal(value.supports_tools, false); assert.equal(value.supports_vision, false); assert.equal(value.context_window_tokens, 65536);
    await assert.rejects(() => startRun(), /model_tools_unsupported/u); return value;
  });
  await check(planned[2], async () => {
    await save(); const value = await configured(); assert.equal(value.supports_tools, false); assert.equal(value.supports_vision, false); assert.equal(value.context_window_tokens, 65536);
    await assert.rejects(() => startRun(), /model_tools_unsupported/u); return value;
  });
  await check(planned[3], async () => {
    await save({ supports_tools: null }); const value = await configured(); assert.equal(value.supports_tools ?? null, null); assert.equal(value.supports_vision, false); assert.equal(value.max_output_tokens, 8192);
    const plan = await estimate(); assert.equal(plan.capabilities.supports_tools ?? null, null); return value;
  });
  await check(planned[4], async () => {
    await save({ context_window_tokens: null, max_output_tokens: null }); const plan = await estimate();
    assert.equal(plan.capabilities.max_input_tokens, 16384); assert.equal(plan.capabilities.max_output_tokens, 4096); assert.equal(plan.capabilities.verified, false); return plan.capabilities;
  });
  await check(planned[5], async () => {
    const before = await configured(); await service.stop(); service = undefined;
    service = await startServer(workspace, executable, legalDb, { portable: process.argv.includes("--portable") });
    assert.deepEqual(await configured(), before); assert.equal((await estimate()).capabilities.max_input_tokens, 16384);
  });
} catch (error) { console.error(error); process.exitCode = 1; }
finally {
  if (service) await service.stop();
  await new Promise(resolve => mock.close(resolve));
  for (const id of planned) if (!checks.some(check => check.id === id)) checks.push({ id, status: "not_run" });
  const hash = bytes => createHash("sha256").update(bytes).digest("hex");
  const report = { schema_version: 1, status: checks.every(check => check.status === "passed") ? "passed" : "failed", started_at: started, completed_at: new Date().toISOString(), source_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), program_sha256: hash(await fs.readFile(executable)), script_sha256: hash(await fs.readFile(new URL(import.meta.url))), node: process.version, dispatches, checks };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ status: report.status, passed: checks.filter(check => check.status === "passed").length, failed: checks.filter(check => check.status === "failed").length, not_run: checks.filter(check => check.status === "not_run").length, output }));
}
