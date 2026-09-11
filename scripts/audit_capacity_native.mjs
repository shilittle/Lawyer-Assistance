// Exercise admission and real SQLite cancellation on the public corpus.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { root, startServer, sleep } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "capacity-native");
await fs.mkdir(output, { recursive:true });
try { await fs.access(path.join(output, "report.json")); throw new Error("evidence_directory_already_used"); } catch (error) { if (error.code !== "ENOENT") throw error; }
const data = await fs.mkdtemp(path.join(output, "workspace-"));
let service;
const controllers = [];
const requests = [];
const snapshots = [];
const checks = [];
const drainSamples = [];
try {
  const corpus = path.resolve(process.argv[3] || process.env.LAWYER_AUDIT_CORPUS || path.join(root,"work/retest-121/public-corpus"));
  service = await startServer(data, path.resolve(process.argv[2] || path.join(root,"target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe")), path.join(corpus,"legal_core.sqlite"), { portable:true });
  const client = service.client;
  const health = async () => {
    const result = await client.request("/api/v1/health");
    const snapshot = { elapsed_ms:Date.now(), resources:result.resources };
    snapshots.push(snapshot);
    return result.resources;
  };
  const initial = await health();
  assert.deepEqual(initial.search.limits, { active:2, waiting:16 });
  assert.deepEqual(initial.ai.limits, { active:2, waiting:6 });
  assert.deepEqual(initial.parse.limits, { active:1, waiting:2 });
  checks.push("configured_resource_budgets");
  // One Han character followed by digits has no necessary indexed bigram and
  // forces the authoritative scan. Every synthetic caller gets a distinct key.
  for (let n = 0; n < 18; n++) {
    const controller = new AbortController();
    controllers.push(controller);
    requests.push(fetch(`${client.origin}/api/v1/legal/search/page?${new URLSearchParams({query:`龘${process.pid}${n}`,view:"flat",version_scope:"all"})}`, {headers:{cookie:client.cookie},signal:controller.signal}).then(async response => ({status:response.status,body:await response.json()})).catch(error => ({aborted:error.name === "AbortError", error:error.name})));
  }
  let full;
  for (let n = 0; n < 50; n++) {
    full = await health();
    assert(full.search.active <= 2 && full.search.waiting <= 16);
    if (full.search.active === 2 && full.search.waiting === 16) break;
    await sleep(50);
  }
  assert.equal(full.search.active, 2);
  assert.equal(full.search.waiting, 16);
  const overflow = await fetch(`${client.origin}/api/v1/legal/search/page?query=capacity-overflow`, {headers:{cookie:client.cookie}});
  assert.equal(overflow.status, 429);
  assert.equal((await overflow.json()).error.code, "capacity_exceeded");
  checks.push("two_active_sixteen_waiting_overflow_is_429");
  const cancelledAt = Date.now();
  controllers.forEach(controller => controller.abort());
  const outcomes = await Promise.all(requests);
  assert(outcomes.every(outcome => outcome.aborted), "all saturation probes must still be pending when cancelled; an error response is not cancellation evidence");
  let drained;
  for (let n = 0; n < 100; n++) {
    drained = await health();
    if (drained.search.active === 0 && drained.search.waiting === 0) break;
    await sleep(50);
  }
  assert.equal(drained.search.active, 0, "SQLite workers must finish, not only HTTP promises");
  assert.equal(drained.search.waiting, 0);
  const drainMs = Date.now() - cancelledAt;
  assert(drainMs < 6000);
  drainSamples.push(drainMs);
  checks.push("disconnect_cancels_waiters_and_underlying_sqlite_workers");
  const sharedQuery = `${client.origin}/api/v1/legal/search/page?${new URLSearchParams({query:`龘${process.pid}99999`,view:"flat",version_scope:"all"})}`;
  const ownerController = new AbortController();
  controllers.push(ownerController);
  const owner = fetch(sharedQuery, { headers:{cookie:client.cookie}, signal:ownerController.signal }).then(async response => ({status:response.status,body:await response.json()})).catch(error => ({aborted:error.name === "AbortError"}));
  await sleep(30);
  const subscriber = fetch(sharedQuery, { headers:{cookie:client.cookie}, signal:AbortSignal.timeout(30000) }).then(async response => ({status:response.status,body:await response.json()}));
  for (let n = 0; n < 30; n++) {
    if ((await health()).search.active === 2) break;
    await sleep(10);
  }
  await sleep(50);
  ownerController.abort();
  assert.equal((await owner).aborted, true);
  const surviving = await subscriber;
  assert.equal(surviving.status, 200, "one caller leaving must not interrupt the remaining shared-query subscriber");
  assert.equal(surviving.body.totalArticles, 0);
  for (let n = 0; n < 20 && (await health()).search.active; n++) await sleep(20);
  assert.equal((await health()).search.active, 0);
  checks.push("shared_query_survives_owner_disconnect_until_last_subscriber_finishes");
  // Repeat with new keys so cancellation latency describes several actual
  // SQLite workloads, rather than cached empty pages or just fetch abortion.
  for (let trial = 1; trial <= 4; trial++) {
    const burstControllers = Array.from({ length: 18 }, () => new AbortController());
    controllers.push(...burstControllers);
    const burst = burstControllers.map((controller, n) => fetch(`${client.origin}/api/v1/legal/search/page?${new URLSearchParams({ query:`龘${process.pid}${trial}888${n}`, view:"flat", version_scope:"all" })}`, { headers:{cookie:client.cookie}, signal:controller.signal }).then(async response => ({ status:response.status, body:await response.json() })).catch(error => ({ aborted:error.name === "AbortError", error:error.name })));
    let occupied;
    for (let attempt = 0; attempt < 100; attempt++) {
      occupied = await health();
      assert(occupied.search.active <= 2 && occupied.search.waiting <= 16);
      if (occupied.search.active === 2 && occupied.search.waiting === 16) break;
      await sleep(10);
    }
    assert.equal(occupied.search.active, 2);
    assert.equal(occupied.search.waiting, 16);
    const began = performance.now();
    burstControllers.forEach(controller => controller.abort());
    assert((await Promise.all(burst)).every(outcome => outcome.aborted));
    let released;
    for (let attempt = 0; attempt < 100; attempt++) {
      released = await health();
      if (released.search.active === 0 && released.search.waiting === 0) break;
      await sleep(20);
    }
    assert.equal(released.search.active, 0);
    assert.equal(released.search.waiting, 0);
    const elapsed = performance.now() - began;
    assert(elapsed < 6000);
    drainSamples.push(elapsed);
  }
  checks.push("five_distinct_full_queue_cancellations_release_underlying_work");
  assert.equal((await client.request("/api/v1/health")).status, "ready");
  const sorted = [...drainSamples].sort((a,b) => a-b);
  const cancellation = { samples_ms:drainSamples, count:sorted.length, p50_ms:sorted[Math.ceil(sorted.length*.5)-1], p95_ms:sorted[Math.ceil(sorted.length*.95)-1], measure:"abort initiated until server search active/waiting both zero" };
  const report = {passed:true,checks,drain_ms:drainMs,cancellation,snapshots};
  await fs.writeFile(path.join(output,"report.json"),JSON.stringify(report,null,2));
  console.log(JSON.stringify({passed:true,checks,drain_ms:drainMs}));
} catch (error) {
  controllers.forEach(controller => controller.abort());
  await fs.writeFile(path.join(output,"report.json"),JSON.stringify({passed:false,checks,error:String(error),drain_samples_ms:drainSamples,snapshots},null,2));
  throw error;
} finally {
  if (service) await service.stop();
}
