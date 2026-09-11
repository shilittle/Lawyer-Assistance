// Read-only full-corpus equivalence, using independent copies with/without the derived index.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { root, startServer } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "index-equivalence");
await fs.mkdir(output, { recursive: true });
const run = await fs.mkdtemp(path.join(output, "run-"));
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const services = [];
const evidence = [];
async function pages(client, options, view) {
  const rows = [];
  let expected;
  let counts;
  let firstMetrics;
  for (let offset = 0; ; offset += 50) {
    const response = await client.request(`/api/v1/legal/search/page?${new URLSearchParams({ ...options, view, offset: String(offset), limit: "50" })}`);
    counts ??= { laws: response.totalLaws, articles: response.totalArticles };
    assert.deepEqual({ laws: response.totalLaws, articles: response.totalArticles }, counts);
    expected ??= response.total;
    firstMetrics ??= response.metrics;
    const batch = view === "flat" ? response.articles : response.laws;
    assert(batch.length <= 50);
    rows.push(...batch);
    if (rows.length >= expected) break;
    assert(batch.length > 0, "pagination must not stop before its exact total");
  }
  assert.equal(rows.length, expected);
  const ids = rows.map(row => view === "flat" ? row.articleId ?? row.article_id : row.law.documentId ?? row.law.document_id);
  assert(ids.every(Boolean), "each row must have a stable identity");
  assert.equal(new Set(ids).size, ids.length, "pages must not overlap");
  return { rows, counts, firstMetrics };
}
try {
  for (const indexed of [true, false]) {
    const directory = path.join(run, indexed ? "indexed" : "fallback");
    await fs.mkdir(directory);
    const legal = path.join(directory, "legal_core.sqlite");
    await fs.copyFile(path.join(root, "data/runtime/legal_core.sqlite"), legal);
    if (indexed) await fs.copyFile(path.join(root, "data/runtime/legal_search_index.sqlite"), path.join(directory, "legal_search_index.sqlite"));
    const service = await startServer(path.join(directory, "workspace"), executable, legal, { portable: true });
    services.push(service);
  }
  const seed = await services[0].client.request("/api/v1/legal/search/page?query=" + encodeURIComponent("民法典第五百七十七条") + "&view=flat");
  assert.equal(seed.totalArticles, 1);
  const document = seed.articles[0].document_id ?? seed.articles[0].documentId;
  assert(document);
  const probes = [
    { query: "民法典第五百七十七条" },
    { query: "合同 解除", document_id: document, match_mode: "all" },
    { query: "合同 解除", document_id: document, match_mode: "any" },
    { query: "合同解除", document_id: document, match_mode: "phrase" },
    { query: "不可抗力", document_id: document, case_date: "2021-01-01", version_scope: "as_of" },
  ];
  for (const options of probes) {
    const views = [];
    for (const view of ["flat", "grouped"]) {
      // Sequential to make work/resource attribution unambiguous.
      const indexed = await pages(services[0].client, options, view);
      const fallback = await pages(services[1].client, options, view);
      assert.deepEqual(indexed.counts, fallback.counts);
      assert.deepEqual(indexed.rows, fallback.rows, "index may change work, never result identity/order/content");
      views.push(indexed);
      evidence.push({ options, view, count: indexed.rows.length, totals: indexed.counts, indexed: indexed.firstMetrics, fallback: fallback.firstMetrics });
      console.log(JSON.stringify(evidence.at(-1)));
    }
    assert.deepEqual(views[0].counts, views[1].counts, "flat/grouped must count the same matched article set");
    assert.equal(views[1].rows.reduce((sum, law) => sum + (law.matched_article_count ?? law.matchedArticleCount), 0), views[0].rows.length);
  }
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: true, corpus: "complete local public corpus; bounded queries, every matching page", evidence }, null, 2));
  console.log(JSON.stringify({ passed: true, checks: evidence.length }));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, error: String(error), evidence }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const service of services) await service.stop();
}
