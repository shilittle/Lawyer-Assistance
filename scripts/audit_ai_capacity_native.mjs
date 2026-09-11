// Hold a localhost mock open to verify AI admission and actual transport cancellation.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "ai-capacity-native");
await fs.mkdir(output, { recursive: true });
const directory = await fs.mkdtemp(path.join(output, "workspace-"));
const live = new Set();
let calls = 0;
const mock = http.createServer(async (req, res) => {
  for await (const _ of req) { /* synthetic request is intentionally not persisted */ }
  calls++;
  live.add(res);
  res.on("close", () => live.delete(res));
});
await new Promise(resolve => mock.listen(0, "127.0.0.1", resolve));
let service;
let providerId;
const runs = [];
const checks = [];
try {
  service = await startServer(directory, path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe")), path.resolve(process.env.LAWYER_AUDIT_LEGAL_DB || path.join(process.env.LAWYER_AUDIT_CORPUS || path.join(root, "work/retest-121/public-corpus"), "legal_core.sqlite")), { portable: true });
  const client = service.client;
  const provider = await client.request("/api/v1/ai/providers", "POST", { preset: "custom", name: "容量验收本机 mock", base_url: `http://127.0.0.1:${mock.address().port}/v1`, enabled_models: ["audit-mock"], api_key: "audit-synthetic-only", allow_private_network: true, trust_raw: false });
  providerId = provider.id;
  const body = { kind: "writing", prompt: "生成合成验收文书", document_type: "合成验收", provider_id: providerId, model: "audit-mock", materials: [], attachment_ids: [] };
  for (let n = 0; n < 8; n++) runs.push(await client.request("/api/v1/ai/runs", "POST", body));
  for (let n = 0; n < 100 && calls < 2; n++) await sleep(20);
  assert.equal(calls, 2);
  const saturated = (await client.request("/api/v1/health")).resources.ai;
  assert.equal(saturated.active, 2);
  assert.equal(saturated.waiting, 6);
  const rejected = await fetch(client.origin + "/api/v1/ai/runs", { method: "POST", headers: { cookie: client.cookie, "x-csrf-token": client.csrf, "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal(rejected.status, 429);
  assert.equal((await rejected.json()).error.code, "capacity_exceeded");
  assert.equal((await client.request("/api/v1/ai/runs?kind=writing")).total, 8, "rejected submission must not create a durable run");
  checks.push("two_ai_active_six_waiting_ninth_rejected_without_new_run");
  for (const run of runs.slice(2)) await client.request(`/api/v1/ai/runs/${run.id}/cancel`, "POST", {});
  await sleep(100);
  assert.equal(calls, 2, "cancelled waiters must never reach the model transport");
  checks.push("queued_cancellation_prevents_model_dispatch");
  const started = Date.now();
  for (const run of runs.slice(0, 2)) await client.request(`/api/v1/ai/runs/${run.id}/cancel`, "POST", {});
  let resources;
  for (let n = 0; n < 150; n++) {
    resources = (await client.request("/api/v1/health")).resources.ai;
    if (resources.active === 0 && resources.waiting === 0 && live.size === 0) break;
    await sleep(20);
  }
  assert.equal(resources.active, 0);
  assert.equal(resources.waiting, 0);
  assert.equal(live.size, 0, "underlying provider HTTP connections must close");
  for (const run of runs) assert.equal((await client.request(`/api/v1/ai/runs/${run.id}`)).status, "cancelled");
  checks.push("active_cancellation_closes_model_transport_and_preserves_terminal_state");
  const report = { passed: true, checks, model_calls: calls, drain_ms: Date.now() - started, model: "local synthetic mock only" };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error), model_calls: calls }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const response of live) response.destroy();
  if (service) {
    if (providerId) await service.client.request("/api/v1/providers", "POST", { id: providerId, name: "audit-cleanup", base_url: "https://cleanup.invalid", model: "cleanup", api_key: "", allow_private_network: false }).catch(() => {});
    await service.stop();
  }
  await new Promise(resolve => mock.close(resolve));
}
