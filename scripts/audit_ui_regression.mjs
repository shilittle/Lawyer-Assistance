// Regression of LA-01/02/03/15 using real Chromium and synthetic API responses.
// No provider, credential, private workspace, or production database is used.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { chromium } from "@playwright/test";

const root = path.resolve(import.meta.dirname, "..");
const web = path.join(root, "apps/web");
const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "ui-regression");
await fs.mkdir(output, { recursive: true });
let pollReply = { id: "browser-poll", kind: "writing", status: "completed", revision: 1 };
const server = http.createServer(async (req, res) => {
  try {
    if (req.url === "/") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end('<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/styles.css"><div id="audit-root"></div>');
      return;
    }
    const pathname = new URL(req.url, "http://localhost").pathname;
    if (pathname === "/api/v1/audit-poll") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(pollReply));
      return;
    }
    const file = path.resolve(web, `.${pathname}`);
    if (!file.startsWith(`${web}${path.sep}`) || !/\.(?:js|css)$/u.test(file)) throw new Error("not_found");
    res.setHeader("content-type", file.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8");
    res.end(await fs.readFile(file));
  } catch {
    res.statusCode = 404;
    res.end();
  }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors = [];
page.on("pageerror", error => errors.push(String(error)));
const checks = [];
try {
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.evaluate(async () => {
    const { WebApp } = await import("/app.js");
    const { ApiError } = await import("/api.js");
    window.ApiError = ApiError;
    window.calls = [];
    window.drafts = {};
    window.runs = {
      writing_A: { id: "writing_A", kind: "writing", title: "已选中的起诉状 A", status: "completed", revision: 1, content: "文书 A 的正式正文", html: "", citations: [], tool_steps: [] },
      search_B: { id: "search_B", kind: "search", title: "后台搜索 B", status: "completed", revision: 1, content: "后台搜索 B 的法律分析", html: "", citations: [], tool_steps: [] }
    };
    window.api = {
      setCsrfToken() {},
      async request(route) {
        calls.push(["request", route]);
        if (route.startsWith("/bookmarks")) return { bookmarks: [] };
        if (route.startsWith("/groups")) return { groups: [] };
        if (route.startsWith("/materials")) return { materials: [] };
        if (route.startsWith("/legal/filters")) return { documentTypes: ["law"], effectivenessLevels: ["national_law"], statuses: ["in_force"], jurisdictions: ["全国"] };
        if (route.startsWith("/legal/cases/status")) return { available: true };
        return {};
      },
      async listAiProviders() { calls.push(["listAiProviders"]); return { providers: [], defaults: {} }; },
      async listAiMaterials() { calls.push(["listAiMaterials"]); return { materials: [] }; },
      async listAiRuns(kind) { calls.push(["listAiRuns", kind]); return { runs: kind === "writing" ? [runs.writing_A] : [] }; },
      async getAiRun(id) { calls.push(["getAiRun", id]); return runs[id]; },
      async exportAiRun(id, format) { calls.push(["exportAiRun", id, format]); return new Blob(["synthetic"]); },
      async updateAiRunContent(id, content, revision) { calls.push(["updateAiRunContent", id, content, revision]); return { ...runs[id], id: "writing_A_revision2", revision: 2, content }; },
      async listAiConversations() { return { conversations: [] }; },
      async getAiDraft(id) { calls.push(["getAiDraft", id]); if (!drafts[id]) throw new ApiError("not_found", false, 404); return drafts[id]; },
      async saveAiDraft(id, payload) { calls.push(["saveAiDraft", id]); return drafts[id] = { id, revision: (drafts[id]?.revision || 0) + 1, content: payload.content, updated_at: 1 }; },
      async deleteAiDraft(id) { delete drafts[id]; return { ok: true }; }
    };
    window.app = new WebApp(document.getElementById("audit-root"), api);
    app.state.authenticated = true;
    app.state.health = { status: "ready" };
    app.navigate("templates");
  });
  const facts = page.locator("textarea").first();
  await facts.fill("未提交的合成案件事实应保持不变。");
  await page.evaluate(() => app.navigate("legal"));
  await page.locator(".search-form input[type=search]").first().waitFor();
  await page.evaluate(() => app.navigate("templates"));
  await page.waitForFunction(() => document.querySelector("textarea")?.value === "未提交的合成案件事实应保持不变。");
  checks.push("draft_survives_navigation");

  await page.getByRole("button", { name: "已选中的起诉状 A · 已完成", exact: true }).click();
  await page.waitForFunction(() => document.querySelector(".document-preview")?.textContent.includes("文书 A 的正式正文"));
  await page.evaluate(async () => { await app.pollAiRun("search_B"); });
  await page.getByRole("button", { name: "编辑正文", exact: true }).click();
  assert.equal(await page.locator(".document-content-editor").inputValue(), "文书 A 的正式正文");
  await page.getByRole("button", { name: "导出", exact: true }).click();
  assert.equal(await page.evaluate(() => calls.some(c => c[0] === "exportAiRun")), false, "dirty document must choose an export snapshot");
  await page.getByRole("button", { name: "导出已保存版本", exact: true }).click();
  await page.waitForFunction(() => calls.some(c => c[0] === "exportAiRun"));
  assert.equal(await page.evaluate(() => calls.find(c => c[0] === "exportAiRun")[1]), "writing_A");
  checks.push("background_search_cannot_change_document_edit_or_export");
  await page.screenshot({ path: path.join(output, "document-binding.png"), fullPage: true });

  await page.evaluate(() => { calls.length = 0; app.navigate("legal"); });
  await page.locator(".search-form input[type=search]").first().fill("劳动合同 解除");
  assert.equal(await page.evaluate(() => calls.filter(c => ["listAiProviders", "listAiMaterials", "listAiRuns"].includes(c[0])).length), 0);
  checks.push("statute_page_has_no_ai_dependencies");
  await page.locator(".search-form input[type=date]").fill("2020-01-01");
  await page.getByRole("tab", { name: "AI搜索", exact: true }).click();
  const aiDate = page.locator(".ai-search-panel input[type=date]");
  await aiDate.waitFor({ state: "visible" });
  assert.equal(await aiDate.inputValue(), "");
  checks.push("ai_date_is_visible_and_independent");
  await page.getByRole("tab", { name: "法条", exact: true }).click();
  await page.evaluate(() => { app.navigate("templates"); app.navigate("legal"); });
  await page.waitForFunction(() => document.querySelector(".search-form input[type=search]")?.value === "劳动合同 解除");
  checks.push("legal_query_survives_navigation");

  await page.evaluate(async () => {
    window.notFoundCalls = 0;
    api.getAiRun = async () => { notFoundCalls++; throw new ApiError("not_found", false, 404); };
    await app.pollAiRun("deleted_run");
    app.requireLogin();
  });
  await page.waitForTimeout(3200);
  assert.equal(await page.evaluate(() => notFoundCalls), 1);
  checks.push("not_found_and_logout_stop_polling");

  await page.context().setOffline(true);
  await page.evaluate(async () => {
    const { AiRunPoller } = await import("/app.js");
    const { ApiClient } = await import("/api.js");
    const pollClient = new ApiClient();
    window.offlinePoll = { calls: 0, active: 0, maxActive: 0, delays: [], errors: [], updates: [] };
    window.offlinePoller = new AiRunPoller({
      getRun: async (_id, options) => {
        offlinePoll.calls++;
        offlinePoll.maxActive = Math.max(offlinePoll.maxActive, ++offlinePoll.active);
        try { return await pollClient.request("/audit-poll", options); }
        finally { offlinePoll.active--; }
      },
      setTimer: (callback, delay) => { offlinePoll.delays.push(delay); return setTimeout(callback, 20); },
      clearTimer: clearTimeout
    });
    for (const scope of ["writing", "search"]) offlinePoller.subscribe("browser-poll", { scope, onError: error => offlinePoll.errors.push(error.code || error.name), onUpdate: run => offlinePoll.updates.push([scope, run.status]) });
  });
  await page.waitForFunction(() => offlinePoll.calls > 1 && offlinePoller.entries.size === 0, null, { timeout: 10000 });
  const offline = await page.evaluate(() => offlinePoll);
  assert(offline.calls <= 6, "offline retries must be finite");
  assert.equal(offline.maxActive, 1, "two subscribers share one request");
  assert(offline.delays.length >= 2 && offline.delays[1] > offline.delays[0], "temporary network errors use exponential backoff");
  await page.waitForTimeout(100);
  assert.equal(await page.evaluate(() => offlinePoll.calls), offline.calls, "retry exhaustion stops polling");
  await page.context().setOffline(false);
  pollReply = { ...pollReply, status: "completed" };
  await page.evaluate(() => offlinePoller.subscribe("browser-poll", { scope: "retry", onUpdate: run => offlinePoll.updates.push(["retry", run.status]) }));
  await page.waitForFunction(() => offlinePoll.updates.some(([scope, status]) => scope === "retry" && status === "completed"));
  assert.equal(await page.evaluate(() => offlinePoller.entries.size), 0);
  checks.push("browser_offline_finite_exponential_retry_shared_request_and_manual_recovery");
  assert.deepEqual(errors, []);
  const report = { passed: true, browser: browser.version(), checks, page_errors: errors };
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report));
} catch (error) {
  await page.screenshot({ path: path.join(output, "failure.png"), fullPage: true });
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error), page_errors: errors }, null, 2));
  throw error;
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}
