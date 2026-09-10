// Measure the actual paged HTTP engine on the local public corpus.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { root, startServer } from "./ai_test_client.mjs";

const label = process.argv[2] || "candidate";
assert.match(label, /^[a-z0-9_-]+$/u);
const output = path.join(root, "work/audit-repair/paged-benchmark", label);
await fs.mkdir(output, { recursive: true });
const dataDir = await fs.mkdtemp(path.join(output, "workspace-"));
const executable = path.resolve(process.argv[3] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const legal = path.resolve(process.argv[4] || path.join(root, "data/runtime/legal_core.sqlite"));
const count = Number(process.argv[5] || 10);
assert(Number.isInteger(count) && count >= 3 && count <= 100);
const samples = [];
let service;
function memory(pid) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$p=[Diagnostics.Process]::GetProcessById([int]$env:LA_BENCHMARK_PID); [Console]::Write(('{\"rss\":'+$p.WorkingSet64+',\"peak_rss\":'+$p.PeakWorkingSet64+',\"private_bytes\":'+$p.PrivateMemorySize64+'}'))"], { windowsHide: true, encoding: "utf8", env: { ...process.env, LA_BENCHMARK_PID: String(pid) } });
  assert.equal(result.status, 0);
  return JSON.parse(result.stdout);
}
function distribution(values) {
  const sorted = [...values].sort((a,b) => a-b);
  return { count: sorted.length, min_ms: sorted[0], p50_ms: sorted[Math.ceil(sorted.length * .5)-1], p95_ms: sorted[Math.ceil(sorted.length * .95)-1], max_ms: sorted.at(-1) };
}
try {
  service = await startServer(dataDir, executable, legal, { portable: true });
  const before = memory(service.server.pid);
  // Cold here means a fresh query/view/page cache key. Shared exact counts may
  // already be warm from another view. OS file-cache state is not reset.
  for (const query of ["民法典第五百七十七条", "合同 解除", "合同解除", "劳动 合同", "不可抗力"]) {
    for (const view of ["flat", "grouped"]) {
      for (let n = 0; n < count; n++) {
        const offset = n === count - 1 ? 20 : 0;
        const started = performance.now();
        const result = await service.client.request(`/api/v1/legal/search/page?${new URLSearchParams({ query, view, limit:"20", offset:String(offset) })}`);
        const elapsed = performance.now() - started;
        const sample = { query, view, cache_state: n === 0 ? "query_key_cold" : offset ? "next_page" : "hot", offset, elapsed_ms: elapsed, total: result.total, total_laws: result.totalLaws, total_articles: result.totalArticles, metrics: result.metrics ?? result.diagnostics ?? null, warnings: result.warnings, memory: memory(service.server.pid) };
        assert.equal(result.total, view === "flat" ? result.totalArticles : result.totalLaws);
        assert(result.totalLaws <= result.totalArticles, "matched laws must come from matched articles");
        if (!label.startsWith("baseline")) {
          assert(sample.metrics, "candidate must report actual cache/candidate/lock diagnostics");
          assert(sample.metrics.cacheRetainedBytes <= 128 * 1024 * 1024);
          if (offset && !result.appliedQuery.exactArticleNumber) {
            assert.equal(sample.metrics.countCacheHit, true, "a new page must reuse the exact count for the same logical search");
          }
          const prior = samples.find(s => s.query === query);
          if (prior) {
            assert.equal(result.totalArticles, prior.total_articles, "all pages and both views must share an exact count");
            assert.equal(result.totalLaws, prior.total_laws);
          }
        }
        samples.push(sample);
        console.log(JSON.stringify({ query, view, iteration:n, elapsed_ms:Math.round(elapsed), rss:sample.memory.rss, total:sample.total }));
      }
    }
  }
  const after = memory(service.server.pid);
  const metrics = Object.fromEntries(["query_key_cold", "hot", "next_page"].map(state => [state, distribution(samples.filter(s => s.cache_state === state).map(s => s.elapsed_ms))]));
  const report = { label, passed:true, generated_at:new Date().toISOString(), engine:"actual /api/v1/legal/search/page", build:executable, corpus:legal, cache_note:"Cold means first query/view/page cache key; shared exact counts may be warm from another view. OS file cache was not flushed. Hot repeats offset 0; next_page requests offset 20 for the first time.", before, after, metrics, samples };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ label, metrics, after }));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ label, passed:false, error:String(error), samples }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  if (service) await service.stop();
}
