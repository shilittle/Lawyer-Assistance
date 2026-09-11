// Read-only full-corpus equivalence, using independent copies with/without the derived index.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { root, startServer } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "index-equivalence");
await fs.mkdir(output, { recursive: true });
try { await fs.access(path.join(output, "report.json")); throw new Error("evidence_directory_already_used"); } catch (error) { if (error.code !== "ENOENT") throw error; }
const run = await fs.mkdtemp(path.join(output, "run-"));
const executable = path.resolve(process.argv[2] || path.join(root, "target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe"));
const corpus = path.resolve(process.argv[3] || process.env.LAWYER_AUDIT_CORPUS || path.join(root, "work/retest-121/public-corpus"));
const services = [];
const evidence = [];
async function hashFile(filename) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(filename)) digest.update(chunk);
  return digest.digest("hex");
}
const identities = { program_sha256: await hashFile(executable), corpus_sha256: await hashFile(path.join(corpus, "legal_core.sqlite")), index_sha256: await hashFile(path.join(corpus, "legal_search_index.sqlite")), script_sha256: await hashFile(new URL(import.meta.url)), node: process.version };
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
    await fs.copyFile(path.join(corpus, "legal_core.sqlite"), legal);
    assert.equal(await hashFile(legal), identities.corpus_sha256);
    if (indexed) {
      const copiedIndex = path.join(directory, "legal_search_index.sqlite");
      await fs.copyFile(path.join(corpus, "legal_search_index.sqlite"), copiedIndex);
      assert.equal(await hashFile(copiedIndex), identities.index_sha256);
    }
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
    { query: "民法典 不可抗力", document_id: document, match_mode: "all" },
    { query: "合同解除", match_mode: "phrase" },
    { query: "劳动 仲裁时效", match_mode: "all" },
    { query: "债务 加入", match_mode: "all" },
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
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: true, status: "passed", ...identities, corpus: "independent byte-verified copies of complete public corpus; every matching page of the listed queries", evidence }, null, 2));
  console.log(JSON.stringify({ passed: true, checks: evidence.length }));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, status: "failed", ...identities, error: String(error), evidence }, null, 2));
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const service of services) await service.stop();
}
