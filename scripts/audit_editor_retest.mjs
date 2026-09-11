// Deterministic Chromium reconstruction for the editor-state findings R01-R04/R09.
// It loads the shipped Web modules unchanged and supplies only synthetic API replies.
// Run a baseline with: node scripts/audit_editor_retest.mjs
// A failing exit code is expected before the editor repair; report.json is still written.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { chromium } from "@playwright/test";

const execFileAsync = promisify(execFile);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRoot = path.resolve(scriptDirectory, "..");

function usage() {
  return "Usage: node scripts/audit_editor_retest.mjs [--root <repo>] [--output <directory>] [--postfix]";
}

function parseArgs(argv) {
  const options = { root: defaultRoot, output: "", postfix: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--root" || value === "--output") {
      const next = argv[++index];
      if (!next) throw new Error(`${value} requires a value\n${usage()}`);
      options[value.slice(2)] = path.resolve(next);
    } else if (value === "--postfix") {
      options.postfix = true;
    } else if (value === "--help" || value === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    } else throw new Error(`Unknown argument: ${value}\n${usage()}`);
  }
  if (!options.output) options.output = path.join(options.root, "work", "retest-121", "baseline", "editor");
  return options;
}

const options = parseArgs(process.argv.slice(2));
const webRoot = path.join(options.root, "apps", "web");
const reportPath = path.join(options.output, "report.json");
const logPath = path.join(options.output, "report.md");
await fs.mkdir(options.output, { recursive: true });

async function sha256(file) {
  return createHash("sha256").update(await fs.readFile(file)).digest("hex");
}

async function gitValue(...args) {
  try {
    const { stdout } = await execFileAsync("git", ["-C", options.root, ...args], { windowsHide: true });
    return stdout.trim();
  } catch (error) {
    return `unavailable: ${error.message}`;
  }
}

const report = {
  schema_version: 1,
  suite: "editor-retest-reconstruction",
  source: {
    root: options.root,
    commit: await gitValue("rev-parse", "HEAD"),
    branch: await gitValue("branch", "--show-current"),
    status: await gitValue("status", "--short"),
    hashes: {
      "apps/web/app.js": await sha256(path.join(webRoot, "app.js")),
      "apps/web/api.js": await sha256(path.join(webRoot, "api.js")),
      "scripts/audit_editor_retest.mjs": await sha256(fileURLToPath(import.meta.url))
    }
  },
  started_at: new Date().toISOString(),
  environment: { node: process.version, browser: "", fixture: "synthetic-api/no-production-data" },
  postfix_mode: options.postfix,
  scenarios: [],
  planned_postfix_gaps: [],
  // These are deliberately reported as planned on df1a000. They run only with
  // --postfix, after the corresponding UI and API behavior exists.
  planned_postfix_scenarios: options.postfix ? [] : [
    {
      id: "r04_new_form_conflict_candidate_refresh_restore",
      reason: "Requires an encrypted writing-current-c-32hex candidate, GET /ai/drafts/{baseId}/conflicts, and an explicit restore action after a browser refresh."
    },
    {
      id: "r09_dirty_export_saved_version_bytes",
      reason: "Requires the dirty-export chooser action 导出已保存版本 and checks the returned Blob UTF-8 bytes."
    },
    {
      id: "r09_dirty_export_save_then_export_bytes",
      reason: "Requires the dirty-export chooser action 保存并导出 and checks that the saved returned run version, rather than stale data, is exported."
    },
    {
      id: "r04_conflict_actions_bind_draft_selection_and_input",
      reason: "Requires async conflict actions to retain their draft, history-selection, and input identities after delayed reads."
    },
    {
      id: "r04_candidate_old_version_binds_detail_before_save",
      reason: "Requires candidate restore to fetch and verify an uncached prior writing run before editor rebinding and saving."
    },
    {
      id: "r09_export_choice_is_invalidated_on_document_switch",
      reason: "Requires a dirty-export choice to be bound to, or invalidated with, the document that opened it."
    },
    {
      id: "r09_save_export_owns_current_snapshot_and_document",
      reason: "Requires save-and-export to create its own fixed save request rather than await a shared button promise."
    },
    {
      id: "r02_form_changes_during_save_remain_dirty_and_restore",
      reason: "Requires form and date generations to persist newer input and direct last-run detail recovery beyond the first history page."
    },
    {
      id: "r04_conflict_pagination_loads_and_restores_twenty_first_candidate",
      reason: "Requires the next_cursor conflict metadata page to be loaded before a later candidate can be restored."
    }
  ]
};

async function writeReport() {
  report.completed_at = new Date().toISOString();
  report.summary = {
    passed: report.scenarios.filter((item) => item.status === "passed").length,
    failed: report.scenarios.filter((item) => item.status === "failed").length,
    planned: report.planned_postfix_scenarios.length || report.planned_postfix_gaps.length
  };
  await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  const rows = [
    "# Editor retest reconstruction",
    "",
    `- Commit: ${report.source.commit}`,
    `- Branch: ${report.source.branch}`,
    `- Synthetic fixture only: no production daemon, workspace, provider, credential, or case material was used.`,
    "",
    "| Scenario | Status | Assertion or error | Screenshot |",
    "|---|---|---|---|",
    ...report.scenarios.map((item) => `| ${item.id} | ${item.status} | ${String(item.detail || "").replaceAll("|", "\\|")} | ${item.screenshot || ""} |`),
    "",
    "## Post-fix scenarios intentionally not asserted on this baseline",
    "",
    ...(report.planned_postfix_scenarios.length ? report.planned_postfix_scenarios : report.planned_postfix_gaps).map((item) => `- ${item.id}: ${item.reason}`)
  ];
  await fs.writeFile(logPath, `${rows.join("\n")}\n`, "utf8");
}

const staticServer = http.createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url || "/", "http://127.0.0.1");
    if (requestUrl.pathname === "/") {
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.end('<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/styles.css"><div id="audit-root"></div>');
      return;
    }
    const file = path.resolve(webRoot, `.${requestUrl.pathname}`);
    if (!file.startsWith(`${webRoot}${path.sep}`) || !/\.(?:js|css)$/u.test(file)) throw new Error("not_found");
    response.setHeader("content-type", file.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8");
    response.end(await fs.readFile(file));
  } catch {
    response.statusCode = 404;
    response.end();
  }
});
await new Promise((resolve) => staticServer.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${staticServer.address().port}`;

function scenarioCheck(entry, condition, name, detail = "") {
  const check = { name, passed: Boolean(condition), detail };
  entry.checks.push(check);
  assert.ok(condition, `${name}${detail ? `: ${detail}` : ""}`);
}

function createSharedDraftService() {
  const drafts = new Map();
  let failCandidateWrites = false;
  let conflictNextBaseWrite = false;
  const copy = (value) => JSON.parse(JSON.stringify(value));
  const failure = (code, status, retryable = false) => ({ error: { code, status, retryable } });
  const snapshot = () => Object.fromEntries([...drafts.entries()].map(([id, value]) => [id, copy(value)]));
  const seed = (id, revision, content) => drafts.set(id, { id, revision, content: copy(content), updated_at: Date.now() });
  const dispatch = async (method, payload = {}) => {
    const id = String(payload.id || "");
    if (method === "get") {
      const record = drafts.get(id);
      return record ? { value: copy(record) } : failure("not_found", 404);
    }
    if (method === "list") {
      const prefix = `${id}-c-`;
      const records = [...drafts.values()]
        .filter((record) => record.id.startsWith(prefix) && /^[a-f0-9]{32}$/u.test(record.id.slice(prefix.length)))
        .sort((left, right) => right.updated_at - left.updated_at || left.id.localeCompare(right.id));
      const offset = Number.parseInt(String(payload.cursor || "0"), 10);
      const start = Number.isSafeInteger(offset) && offset >= 0 ? offset : 0;
      const limit = Math.max(1, Number(payload.limit) || 20);
      const page = records.slice(start, start + limit);
      return {
        value: {
          drafts: page.map((record) => ({ id: record.id, revision: record.revision, updated_at: record.updated_at })),
          next_cursor: start + page.length < records.length ? String(start + page.length) : "",
          total: records.length,
          corrupt_count: 0
        }
      };
    }
    if (method === "save") {
      if (failCandidateWrites && /-c-[a-f0-9]{32}$/u.test(id)) return failure("server_error", 500, true);
      const existing = drafts.get(id);
      if (conflictNextBaseWrite && !/-c-[a-f0-9]{32}$/u.test(id)) {
        conflictNextBaseWrite = false;
        drafts.set(id, { id, revision: (existing?.revision || 0) + 1, content: { ...(existing?.content || {}), prompt: "合并期间远端更新" }, updated_at: Date.now() });
        return failure("revision_conflict", 409);
      }
      if ((existing && existing.revision !== payload.expected_revision) || (!existing && payload.expected_revision !== 0)) return failure("revision_conflict", 409);
      const record = { id, revision: (existing?.revision || 0) + 1, content: copy(payload.content), updated_at: Date.now() };
      drafts.set(id, record);
      return { value: copy(record) };
    }
    if (method === "delete") {
      const existing = drafts.get(id);
      if (!existing) return failure("not_found", 404);
      if (existing.revision !== payload.expected_revision) return failure("revision_conflict", 409);
      drafts.delete(id);
      return { value: { deleted: true, id, revision: payload.expected_revision } };
    }
    return failure("server_error", 500, true);
  };
  return {
    dispatch,
    seed,
    snapshot,
    failCandidateWrites: (value) => { failCandidateWrites = Boolean(value); },
    conflictNextBaseWrite: () => { conflictNextBaseWrite = true; }
  };
}

async function bootstrap(page, fixture = {}) {
  const initialDraftStore = fixture.draftStore || {};
  if (fixture.sharedDraftService && !page.__editorRetestSharedDraft) {
    await page.exposeFunction("__editorRetestSharedDraft", (method, payload) => fixture.sharedDraftService.dispatch(method, payload));
    page.__editorRetestSharedDraft = true;
  }
  await page.goto(origin);
  await page.evaluate(async (seed) => {
    const [{ WebApp }, { ApiError }] = await Promise.all([import("/app.js"), import("/api.js")]);
    const copy = (value) => JSON.parse(JSON.stringify(value));
    const sharedDraft = seed.sharedDraftService
      ? async (method, payload) => {
        const result = await window.__editorRetestSharedDraft(method, payload);
        if (result?.error) throw new ApiError(result.error.code, result.error.retryable, result.error.status);
        return copy(result?.value);
      }
      : null;
    const makeRun = (id, title, revision, content, documentId) => ({
      id, kind: "writing", title, status: "completed", revision, content, document_id: documentId,
      html: "", citations: [], tool_steps: []
    });
    const control = {
      calls: { requests: [], getRuns: [], updates: [], drafts: [], exports: [] },
      runs: {
        writing_A: makeRun("writing_A", "文书 A", 1, "A 已保存正文", "document_A"),
        writing_C: makeRun("writing_C", "文书 C", 1, "C 已保存正文", "document_C")
      },
      historyRuns: Array.isArray(seed.historyRuns) ? copy(seed.historyRuns) : null,
      draftStore: copy(seed.draftStore || {}),
      deferredGets: [],
      deferredDraftGets: [],
      deferredUpdates: [],
      deferGetIds: new Set(),
      deferDraftGetIds: new Set(),
      deferGet(id) { this.deferGetIds.add(id); },
      deferDraftGet(id) { this.deferDraftGetIds.add(id); },
      resolveGet(id, value) {
        const next = this.deferredGets.find((item) => item.id === id && !item.settled);
        if (!next) throw new Error(`no pending get for ${id}`);
        next.settled = true;
        next.resolve(copy(value));
      },
      rejectGet(id, code = "server_error", retryable = true, status = 500) {
        const next = this.deferredGets.find((item) => item.id === id && !item.settled);
        if (!next) throw new Error(`no pending get for ${id}`);
        next.settled = true;
        next.reject(new ApiError(code, retryable, status));
      },
      resolveDraftGet(id, value) {
        const next = this.deferredDraftGets.find((item) => item.id === id && !item.settled);
        if (!next) throw new Error(`no pending draft get for ${id}`);
        next.settled = true;
        next.resolve(copy(value));
      },
      resolveUpdate(index, value) {
        const next = this.deferredUpdates[index];
        if (!next || next.settled) throw new Error(`no pending update ${index}`);
        next.settled = true;
        if (value?.id) this.runs[value.id] = copy(value);
        next.resolve(copy(value));
      },
      externalDraft(id, revision, content) { this.draftStore[id] = { id, revision, content: copy(content), updated_at: 1 }; },
      candidateId(baseId, hex = "a".repeat(32)) { return `${baseId}-c-${hex}`; },
      listDraftConflicts(baseId, { limit = 20, cursor = "" } = {}) {
        this.calls.conflicts.push({ id: baseId, limit, cursor });
        const candidatePrefix = `${baseId}-c-`;
        const all = Object.values(this.draftStore)
          .filter((draft) => draft.id.startsWith(candidatePrefix) && /^[a-f0-9]{32}$/u.test(draft.id.slice(candidatePrefix.length)))
          .sort((left, right) => right.updated_at - left.updated_at || left.id.localeCompare(right.id));
        const offset = Number.parseInt(String(cursor || "0"), 10);
        const start = Number.isSafeInteger(offset) && offset >= 0 ? offset : 0;
        const page = all.slice(start, start + limit);
        return {
          drafts: page.map((draft) => ({ id: draft.id, revision: draft.revision, updated_at: draft.updated_at })),
          next_cursor: start + page.length < all.length ? String(start + page.length) : "",
          total: all.length,
          corrupt_count: 0
        };
      }
    };
    if (seed.runs && typeof seed.runs === "object") Object.assign(control.runs, copy(seed.runs));
    control.calls.conflicts = [];
    const api = {
      setCsrfToken() {},
      async request(route, requestOptions = {}) {
        control.calls.requests.push([route, requestOptions.method || "GET"]);
        const conflictRoute = route.match(/^\/ai\/drafts\/([^/]+)\/conflicts(?:\?.*)?$/u);
        if (conflictRoute) {
          const query = new URLSearchParams(route.split("?")[1] || "");
          const id = decodeURIComponent(conflictRoute[1]);
          return sharedDraft
            ? sharedDraft("list", { id, limit: Number(query.get("limit") || 20), cursor: query.get("cursor") || "" })
            : control.listDraftConflicts(id, { limit: Number(query.get("limit") || 20), cursor: query.get("cursor") || "" });
        }
        if (route === "/session") return { authenticated: true, csrf_token: "csrf-relogin" };
        if (route.startsWith("/bookmarks")) return { bookmarks: [] };
        if (route.startsWith("/groups")) return { groups: [] };
        if (route.startsWith("/materials")) return { materials: [] };
        if (route.startsWith("/legal/filters")) return { documentTypes: [], effectivenessLevels: [], statuses: [], jurisdictions: [] };
        if (route.startsWith("/legal/cases/status")) return { available: true };
        return {};
      },
      async listAiProviders() { return { providers: [], defaults: {} }; },
      async listAiMaterials() { return { materials: [] }; },
      async listAiRuns(kind) {
        control.calls.getRuns.push(kind);
        return { runs: kind === "writing" ? copy(control.historyRuns || [control.runs.writing_A, control.runs.writing_C]) : [] };
      },
      async getAiRun(id) {
        if (control.deferGetIds.has(id)) {
          return new Promise((resolve, reject) => control.deferredGets.push({ id, resolve, reject, settled: false }));
        }
        if (!control.runs[id]) throw new ApiError("not_found", false, 404);
        return copy(control.runs[id]);
      },
      async updateAiRunContent(id, content, expectedRevision) {
        control.calls.updates.push({ id, content, expected_revision: expectedRevision });
        return new Promise((resolve, reject) => control.deferredUpdates.push({ id, content, expectedRevision, resolve, reject, settled: false }));
      },
      async exportAiRun(id, format, expectedRevision) {
        const blob = new Blob([control.runs[id]?.content || "synthetic export"], { type: "application/octet-stream" });
        control.calls.exports.push({
          id,
          format,
          expected_revision: expectedRevision,
          bytes: Array.from(new Uint8Array(await blob.arrayBuffer()))
        });
        return blob;
      },
      async getAiDraft(id) {
        if (sharedDraft) return sharedDraft("get", { id });
        if (control.deferDraftGetIds.has(id)) {
          return new Promise((resolve, reject) => control.deferredDraftGets.push({ id, resolve, reject, settled: false }));
        }
        const value = control.draftStore[id];
        if (!value) throw new ApiError("not_found", false, 404);
        return copy(value);
      },
      async saveAiDraft(id, payload) {
        control.calls.drafts.push({ id, expected_revision: payload.expected_revision, content: copy(payload.content) });
        if (sharedDraft) return sharedDraft("save", { id, expected_revision: payload.expected_revision, content: payload.content });
        const existing = control.draftStore[id];
        if ((existing && existing.revision !== payload.expected_revision) || (!existing && payload.expected_revision !== 0)) {
          throw new ApiError("revision_conflict", false, 409);
        }
        const next = { id, revision: (existing?.revision || 0) + 1, content: copy(payload.content), updated_at: Date.now() };
        control.draftStore[id] = next;
        return copy(next);
      },
      async deleteAiDraft(id, expectedRevision) {
        if (sharedDraft) return sharedDraft("delete", { id, expected_revision: expectedRevision });
        const existing = control.draftStore[id];
        if (!existing) throw new ApiError("not_found", false, 404);
        if (existing.revision !== expectedRevision) throw new ApiError("revision_conflict", false, 409);
        delete control.draftStore[id];
        return { deleted: true, id, revision: expectedRevision };
      },
      async listAiDraftConflicts(id, { limit = 20, cursor = "" } = {}) {
        const params = new URLSearchParams({ limit: String(limit) });
        if (cursor) params.set("cursor", cursor);
        return this.request(`/ai/drafts/${encodeURIComponent(id)}/conflicts?${params}`, { method: "GET" });
      },
      async getAiDraftConflicts(id, options = {}) { return this.listAiDraftConflicts(id, options); },
      async listAiConversations() { return { conversations: [] }; },
      async getAiConversation() { throw new ApiError("not_found", false, 404); }
    };
    window.__editorRetest = control;
    window.app = new WebApp(document.getElementById("audit-root"), api);
    app.state.authenticated = true;
    app.state.health = { status: "ready" };
    app.navigate("templates");
  }, {
    draftStore: initialDraftStore,
    historyRuns: fixture.historyRuns,
    runs: fixture.runs,
    sharedDraftService: Boolean(fixture.sharedDraftService)
  });
  await page.getByRole("heading", { name: "文书写作", exact: true }).waitFor();
  if (fixture.expectWritingA !== false) await page.getByRole("button", { name: /文书 A/u }).waitFor();
  await page.waitForFunction(() => window.app?.state?.writingDraft?.loaded === true);
}

async function openWritingRun(page, id) {
  const label = id === "writing_A" ? /文书 A/u : /文书 C/u;
  await page.getByRole("button", { name: label }).first().click();
  await page.waitForFunction((runId) => window.app.state.pageRunIds.writing === runId, id);
}

async function editCurrentRun(page, content) {
  await page.getByRole("button", { name: "编辑正文", exact: true }).click();
  const editor = page.locator("textarea.document-content-editor");
  await editor.waitFor({ state: "visible" });
  await editor.fill(content);
  return editor;
}

async function beginSave(page) {
  await page.getByRole("button", { name: "保存正文修改", exact: true }).click();
  await page.waitForFunction(() => window.__editorRetest.calls.updates.length > 0);
}

async function runScenario(browser, id, action) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const entry = { id, status: "running", checks: [], errors: [], screenshot: "" };
  report.scenarios.push(entry);
  page.on("pageerror", (error) => entry.errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") entry.errors.push(`console: ${message.text()}`);
  });
  try {
    await bootstrap(page);
    await action(page, entry);
    scenarioCheck(entry, entry.errors.length === 0, "browser_has_no_page_or_console_error", entry.errors.join("; "));
    entry.status = "passed";
    entry.detail = "all assertions passed";
  } catch (error) {
    entry.status = "failed";
    entry.detail = String(error?.message || error);
    entry.errors.push(entry.detail);
  } finally {
    const filename = `${id}-${entry.status}.png`;
    try {
      await page.screenshot({ path: path.join(options.output, filename), fullPage: true });
      entry.screenshot = filename;
    } catch (error) {
      entry.errors.push(`screenshot: ${error.message}`);
    }
    await page.close();
    await writeReport();
  }
}

let browser;
try {
  browser = await chromium.launch({ headless: true });
  report.environment.browser = browser.version();

  await runScenario(browser, "r01_late_save_a_c", async (page, entry) => {
    await openWritingRun(page, "writing_A");
    await editCurrentRun(page, "A 待保存正文");
    await beginSave(page);
    await openWritingRun(page, "writing_C");
    const editor = await editCurrentRun(page, "C 不可丢失草稿");
    await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
      ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A 待保存正文"
    }));
    await page.waitForTimeout(60);
    const state = await page.evaluate(() => ({
      selected: window.app.state.pageRunIds.writing,
      editorRunId: document.querySelector("textarea.document-content-editor")?.dataset.runId || "",
      editorHidden: document.querySelector("textarea.document-content-editor")?.hidden,
      cached: window.app.state.runsById.has("writing_A_v2")
    }));
    scenarioCheck(entry, state.selected === "writing_C", "late_A_save_does_not_reselect_C", JSON.stringify(state));
    scenarioCheck(entry, state.editorRunId === "writing_C" && state.editorHidden === false, "late_A_save_does_not_rebind_C_editor", JSON.stringify(state));
    scenarioCheck(entry, await editor.inputValue() === "C 不可丢失草稿", "late_A_save_keeps_C_body", await editor.inputValue());
    scenarioCheck(entry, state.cached, "late_A_save_still_updates_A_cache", JSON.stringify(state));
  });

  await runScenario(browser, "r01_same_a_newer_input", async (page, entry) => {
    await openWritingRun(page, "writing_A");
    const editor = await editCurrentRun(page, "A 第一次输入");
    await beginSave(page);
    await editor.fill("A 保存后继续输入");
    await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
      ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A 第一次输入"
    }));
    await page.waitForTimeout(60);
    const state = await page.evaluate(() => ({
      selected: window.app.state.pageRunIds.writing,
      logicalDocumentId: window.app.state.runsById.get(window.app.state.pageRunIds.writing)?.document_id || "",
      hidden: document.querySelector("textarea.document-content-editor")?.hidden
    }));
    // A fixed client may retain the original run selection while caching A_v2.
    // The invariant is that the visible editor remains bound to document A.
    scenarioCheck(entry, state.logicalDocumentId === "document_A", "newer_input_stays_with_same_logical_document", JSON.stringify(state));
    scenarioCheck(entry, state.hidden === false, "old_save_cannot_mark_newer_input_clean", JSON.stringify(state));
    scenarioCheck(entry, await editor.inputValue() === "A 保存后继续输入", "old_save_cannot_replace_newer_A_body", await editor.inputValue());
  });

  await runScenario(browser, "r01_out_of_order_saves", async (page, entry) => {
    await openWritingRun(page, "writing_A");
    const editor = await editCurrentRun(page, "A 第一份保存");
    await beginSave(page);
    await editor.fill("A 第二份保存");
    await page.evaluate(() => {
      const save = [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "保存正文修改");
      save.disabled = false; // Test seam: submits a second logical snapshot while the first request is pending.
    });
    await beginSave(page);
    await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
      ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A 第一份保存"
    }));
    await page.waitForFunction(() => window.__editorRetest.calls.updates.length === 2);
    const second = await page.evaluate(() => window.__editorRetest.calls.updates[1]);
    scenarioCheck(entry,
      second.id === "writing_A_v2" && second.expected_revision === 2 && second.content === "A 第二份保存",
      "newer_save_waits_for_prior_version_then_uses_fresh_cas",
      JSON.stringify(second)
    );
    await page.evaluate(() => window.__editorRetest.resolveUpdate(1, {
      ...window.__editorRetest.runs.writing_A, id: "writing_A_v3", revision: 3, content: "A 第二份保存"
    }));
    await page.waitForTimeout(60);
    const selected = await page.evaluate(() => window.app.state.pageRunIds.writing);
    scenarioCheck(entry, selected === "writing_A_v3", "older_save_completion_cannot_replace_newer_save", selected);
  });

  await runScenario(browser, "r02_repeated_dirty_history", async (page, entry) => {
    await openWritingRun(page, "writing_A");
    const editor = await editCurrentRun(page, "A 未保存正文");
    await page.getByRole("button", { name: /文书 A/u }).first().click();
    await page.waitForTimeout(40);
    scenarioCheck(entry, await editor.inputValue() === "A 未保存正文", "reopening_current_history_does_not_replace_dirty_body", await editor.inputValue());
    scenarioCheck(entry, await editor.isVisible(), "reopening_current_history_keeps_editor_open");
  });

  await runScenario(browser, "r02_inverse_detail_responses", async (page, entry) => {
    await page.evaluate(() => {
      window.__editorRetest.deferGet("writing_A");
      window.__editorRetest.deferGet("writing_C");
    });
    await page.getByRole("button", { name: /文书 A/u }).first().click();
    await page.getByRole("button", { name: /文书 C/u }).first().click();
    await page.waitForFunction(() => window.__editorRetest.deferredGets.length === 2);
    await page.evaluate(() => window.__editorRetest.resolveGet("writing_C", window.__editorRetest.runs.writing_C));
    await page.waitForFunction(() => window.app.state.pageRunIds.writing === "writing_C");
    await page.evaluate(() => window.__editorRetest.resolveGet("writing_A", window.__editorRetest.runs.writing_A));
    await page.waitForTimeout(50);
    const selected = await page.evaluate(() => window.app.state.pageRunIds.writing);
    scenarioCheck(entry, selected === "writing_C", "older_detail_response_cannot_steal_latest_selection", selected);
  });

  await runScenario(browser, "r03_auth_late_success_failure_relogin", async (page, entry) => {
    await page.evaluate(() => {
      const chatAbort = new AbortController();
      const legalSearchAbort = new AbortController();
      const legalDetailAbort = new AbortController();
      window.__editorRetestSessionSignals = { chatAbort, legalSearchAbort, legalDetailAbort };
      window.app.state.groups = [{ id: "session-secret-group" }];
      window.app.state.materials = [{ id: "session-secret-material", content: "session-secret-body" }];
      window.app.state.selectedMaterial = { id: "session-secret-selected", content: "session-secret-body" };
      window.app.state.providers = [{ id: "session-secret-provider" }];
      window.app.state.aiMaterials = [{ id: "session-secret-ai-material" }];
      window.app.state.aiAttachments = [{ id: "session-secret-attachment" }];
      window.app.state.conversations = [{ id: "session-secret-conversation" }];
      window.app.state.selectedConversation = { id: "session-secret-conversation", content: "session-secret-body" };
      window.app.state.mcpClients = [{ id: "session-secret-mcp" }];
      window.app.state.pendingMcpToken = "session-secret-token";
      window.app.state.pendingCitation = { article: "session-secret-citation" };
      window.app.state.legalCaseQuery = "session-secret-case-query";
      window.app.state.legalArticleQuery = "session-secret-article-query";
      window.app.state.legalCaseResponse = { content: "session-secret-body" };
      window.app.state.legalCaseStatus = { content: "session-secret-body" };
      window.app.state.legalQueryFilters.caseDate = "2026-01-01";
      window.app.state.aiSearchFilters.caseDate = "2026-01-01";
      window.app.state.writingDraft.lastContent = { prompt: "session-secret-draft", content: "session-secret-body" };
      window.app.state.writingDraft.conflicts = [{ id: "writing-current-c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", revision: 1 }];
      window.app.state.chatAbort = chatAbort;
      window.app.state.legalSearchAbort = legalSearchAbort;
      window.app.state.legalDetailAbort = legalDetailAbort;
      window.app.state.taskTimer = setTimeout(() => { window.__editorRetest.taskTimerFired = true; }, 5000);
      window.__editorRetest.deferGet("old-success");
      window.app.pollAiRun("old-success");
    });
    await page.waitForFunction(() => window.__editorRetest.deferredGets.some((item) => item.id === "old-success"));
    await page.evaluate(() => window.app.requireLogin());
    await page.evaluate(() => window.__editorRetest.resolveGet("old-success", {
      id: "old-success", kind: "writing", status: "completed", revision: 1, content: "old session content"
    }));
    await page.waitForTimeout(50);
    const loginToken = page.getByPlaceholder("粘贴本地访问令牌");
    await loginToken.fill("synthetic-local-token");
    await page.getByRole("button", { name: "进入工作台", exact: true }).click();
    await page.getByRole("heading", { name: "文书写作", exact: true }).waitFor();
    const afterSuccess = await page.evaluate(() => ({
      oldRunCached: window.app.state.runsById.has("old-success"),
      pollEntries: window.app.aiRunPoller.entries.size,
      sensitiveCollectionsCleared: [
        window.app.state.groups,
        window.app.state.materials,
        window.app.state.aiMaterials,
        window.app.state.aiAttachments,
        window.app.state.conversations,
        window.app.state.mcpClients
      ].every((items) => items.length === 0),
      selectedCleared: !window.app.state.selectedMaterial && !window.app.state.selectedConversation
        && !window.app.state.pendingMcpToken && !window.app.state.pendingCitation,
      legalQueryCleared: !window.app.state.legalCaseQuery && !window.app.state.legalArticleQuery
        && !window.app.state.legalCaseResponse && !window.app.state.legalCaseStatus
        && !window.app.state.legalQueryFilters.caseDate && !window.app.state.aiSearchFilters.caseDate,
      controllersAborted: window.__editorRetestSessionSignals.chatAbort.signal.aborted
        && window.__editorRetestSessionSignals.legalSearchAbort.signal.aborted
        && window.__editorRetestSessionSignals.legalDetailAbort.signal.aborted
        && window.app.state.taskTimer === null,
      draftBodyCleared: [...window.app.state.writingDrafts.values()].every((draft) => !draft.lastContent?.prompt && !draft.lastContent?.content && draft.conflicts.length === 0),
      noSensitiveDom: !document.body.textContent.includes("session-secret")
    }));
    scenarioCheck(entry, afterSuccess.oldRunCached === false && afterSuccess.pollEntries === 0, "late_old_success_cannot_cross_session", JSON.stringify(afterSuccess));
    scenarioCheck(entry,
      afterSuccess.sensitiveCollectionsCleared && afterSuccess.selectedCleared && afterSuccess.legalQueryCleared && afterSuccess.controllersAborted && afterSuccess.draftBodyCleared && afterSuccess.noSensitiveDom,
      "logout_clears_sensitive_memory_and_aborts_background_work",
      JSON.stringify(afterSuccess)
    );

    await page.evaluate(() => {
      window.__editorRetest.deferGet("old-failure");
      window.app.pollAiRun("old-failure");
    });
    await page.waitForFunction(() => window.__editorRetest.deferredGets.some((item) => item.id === "old-failure"));
    await page.evaluate(() => window.app.requireLogin());
    await page.evaluate(() => window.__editorRetest.rejectGet("old-failure"));
    await page.waitForTimeout(50);
    const afterFailure = await page.evaluate(() => ({
      oldRunCached: window.app.state.runsById.has("old-failure"),
      pollEntries: window.app.aiRunPoller.entries.size
    }));
    scenarioCheck(entry, afterFailure.oldRunCached === false && afterFailure.pollEntries === 0, "late_old_failure_cannot_leave_poll_or_session_state", JSON.stringify(afterFailure));
  });

  await runScenario(browser, "r04_draft409_forks_before_any_stale_retry", async (page, entry) => {
    await page.evaluate(() => window.__editorRetest.externalDraft("writing-current", 2, {
      document_type: "民事起诉状", prompt: "另一窗口正文", requirements: "", case_date: "", provider_id: null,
      model: null, materials: [], attachment_ids: [], run_id: null, run_revision: null, content: "", dirty: true
    }));
    await page.getByPlaceholder(/说明当事人/u).fill("本窗口冲突候选");
    await page.waitForFunction(() => window.__editorRetest.calls.drafts.some((item) => /^writing-current-c-[a-f0-9]{32}$/u.test(item.id)));
    const calls = await page.evaluate(() => window.__editorRetest.calls.drafts.map((item) => ({ id: item.id, expected_revision: item.expected_revision, prompt: item.content.prompt })));
    scenarioCheck(entry,
      calls.filter((item) => item.id === "writing-current" && item.expected_revision === 0).length === 1,
      "draft409_does_not_repeat_stale_canonical_write",
      JSON.stringify(calls)
    );
    scenarioCheck(entry,
      calls.some((item) => /^writing-current-c-[a-f0-9]{32}$/u.test(item.id) && item.expected_revision === 0 && item.prompt === "本窗口冲突候选"),
      "draft409_persists_encrypted_candidate_before_recovery_action",
      JSON.stringify(calls)
    );
  });

  await runScenario(browser, "r09_dirty_export_must_not_be_direct", async (page, entry) => {
    await openWritingRun(page, "writing_A");
    await editCurrentRun(page, "A 仅本地的未保存正文");
    await page.getByRole("button", { name: "导出", exact: true }).click();
    await page.waitForTimeout(50);
    const calls = await page.evaluate(() => window.__editorRetest.calls.exports);
    scenarioCheck(entry, calls.length === 0, "dirty_export_requires_explicit_saved_or_save_and_export_choice", JSON.stringify(calls));
  });

  if (options.postfix) {
    await runScenario(browser, "r04_new_form_conflict_candidate_refresh_restore", async (page, entry) => {
      const baseId = "writing-current";
      await page.evaluate((id) => window.__editorRetest.externalDraft(id, 2, {
        document_type: "民事起诉状", prompt: "另一窗口正文", requirements: "", case_date: "", provider_id: null,
        model: null, materials: [], attachment_ids: [], run_id: null, run_revision: null, content: "", dirty: true
      }), baseId);
      await page.getByPlaceholder(/说明当事人/u).fill("本窗口冲突候选");
      await page.waitForFunction((id) => window.__editorRetest.calls.drafts.some((call) => {
        const prefix = `${id}-c-`;
        return call.id.startsWith(prefix) && /^[a-f0-9]{32}$/u.test(call.id.slice(prefix.length));
      }), baseId);
      const beforeRefresh = await page.evaluate((id) => {
        const prefix = `${id}-c-`;
        const candidate = window.__editorRetest.calls.drafts.find((call) => (
          call.id.startsWith(prefix) && /^[a-f0-9]{32}$/u.test(call.id.slice(prefix.length))
        ));
        return {
          candidate,
          conflictPage: window.__editorRetest.listDraftConflicts(id),
          draftStore: JSON.parse(JSON.stringify(window.__editorRetest.draftStore))
        };
      }, baseId);
      scenarioCheck(entry, Boolean(beforeRefresh.candidate), "draft409_creates_discoverable_candidate", JSON.stringify(beforeRefresh.candidate));
      scenarioCheck(entry, beforeRefresh.candidate?.content?.prompt === "本窗口冲突候选", "candidate_preserves_new_form_input", JSON.stringify(beforeRefresh.candidate?.content));
      scenarioCheck(entry,
        Array.isArray(beforeRefresh.conflictPage.drafts)
          && beforeRefresh.conflictPage.total === 1
          && beforeRefresh.conflictPage.corrupt_count === 0
          && beforeRefresh.conflictPage.next_cursor === ""
          && beforeRefresh.conflictPage.drafts.every((draft) => (
            Object.keys(draft).sort().join(",") === "id,revision,updated_at"
              && /^writing-current-c-[a-f0-9]{32}$/u.test(draft.id)
          )),
        "conflict_list_has_metadata_only_real_api_shape",
        JSON.stringify(beforeRefresh.conflictPage)
      );

      // A re-created WebApp with the same encrypted server drafts represents a
      // browser refresh. No form body is placed in browser persistence here.
      await bootstrap(page, { draftStore: beforeRefresh.draftStore });
      await page.waitForFunction((id) => window.__editorRetest.calls.requests.some(([route, method]) => (
        method === "GET" && route.startsWith(`/ai/drafts/${encodeURIComponent(id)}/conflicts?`)
      )), baseId);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).click();
      const prompt = page.getByPlaceholder(/说明当事人/u);
      await prompt.waitFor({ state: "visible" });
      scenarioCheck(entry, await prompt.inputValue() === "本窗口冲突候选", "reopen_restores_candidate_into_new_form", await prompt.inputValue());
    });

    await runScenario(browser, "r02_restart_restores_last_document_draft", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      await page.waitForFunction(() => window.app.state.writingDraft.id === "writing-document_A");
      await editCurrentRun(page, "A 重启后必须恢复的正文");
      await page.waitForFunction(() => window.__editorRetest.calls.drafts.some((call) => call.id === "writing-document_A"));
      const persisted = await page.evaluate(() => JSON.parse(JSON.stringify(window.__editorRetest.draftStore)));
      await bootstrap(page, { draftStore: persisted });
      await page.waitForFunction(() => window.app.state.pageRunIds.writing === "writing_A");
      const restoredEditor = page.locator("textarea.document-content-editor");
      await restoredEditor.waitFor({ state: "visible" });
      scenarioCheck(entry,
        await restoredEditor.inputValue() === "A 重启后必须恢复的正文",
        "safe_last_run_pointer_reopens_document_and_canonical_draft_restores_body",
        await restoredEditor.inputValue()
      );
    });

    await runScenario(browser, "r04_shared_windows_second_conflict_candidate", async (page, entry) => {
      const shared = createSharedDraftService();
      const secondPage = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
      try {
        await bootstrap(page, { sharedDraftService: shared });
        await bootstrap(secondPage, { sharedDraftService: shared });
        await page.getByPlaceholder(/说明当事人/u).fill("窗口 A 的远端草稿");
        await page.waitForFunction(() => window.__editorRetest.calls.drafts.some((call) => call.id === "writing-current"));
        await secondPage.getByPlaceholder(/说明当事人/u).fill("窗口 B 的冲突草稿");
        await secondPage.waitForFunction(() => window.__editorRetest.calls.drafts.some((call) => /^writing-current-c-[a-f0-9]{32}$/u.test(call.id)));
        const afterFirstConflict = shared.snapshot();
        const firstCandidates = Object.values(afterFirstConflict).filter((record) => /^writing-current-c-[a-f0-9]{32}$/u.test(record.id));
        scenarioCheck(entry,
          afterFirstConflict["writing-current"]?.revision === 1 && firstCandidates.length === 1 && firstCandidates[0].content.prompt === "窗口 B 的冲突草稿",
          "shared_server_cas_keeps_A_and_persists_B_candidate",
          JSON.stringify(afterFirstConflict)
        );

        // Rebuild B against the same fake encrypted service: this is a real
        // second browser page refresh, not a local in-memory helper call.
        await bootstrap(secondPage, { sharedDraftService: shared });
        await secondPage.waitForFunction(() => window.__editorRetest.calls.requests.some(([route, method]) => method === "GET" && route.startsWith("/ai/drafts/writing-current/conflicts?")));
        await secondPage.getByRole("button", { name: "恢复冲突草稿", exact: true }).click();
        scenarioCheck(entry,
          await secondPage.getByPlaceholder(/说明当事人/u).inputValue() === "窗口 B 的冲突草稿",
          "second_window_refresh_discovers_and_restores_candidate"
        );

        // The base changes after B reads it for merge. The UI must fork a new
        // candidate instead of losing the merged text or retrying stale CAS.
        shared.conflictNextBaseWrite();
        await secondPage.getByRole("button", { name: "合并冲突草稿", exact: true }).click();
        await secondPage.waitForFunction(() => window.__editorRetest.calls.drafts.filter((call) => /^writing-current-c-[a-f0-9]{32}$/u.test(call.id)).length >= 1);
        const afterSecondConflict = shared.snapshot();
        const candidates = Object.values(afterSecondConflict).filter((record) => /^writing-current-c-[a-f0-9]{32}$/u.test(record.id));
        scenarioCheck(entry,
          afterSecondConflict["writing-current"]?.revision === 2 && candidates.length === 2 && candidates.every((record) => record.content.prompt),
          "merge_second_cas_conflict_creates_another_retained_candidate",
          JSON.stringify(afterSecondConflict)
        );
      } finally {
        await secondPage.close();
      }
    });

    await runScenario(browser, "r04_candidate_write_failure_is_explicit_unsaved", async (page, entry) => {
      const shared = createSharedDraftService();
      await bootstrap(page, { sharedDraftService: shared });
      shared.seed("writing-current", 3, {
        document_type: "民事起诉状", prompt: "另一窗口正文", requirements: "", case_date: "", provider_id: null,
        model: null, materials: [], attachment_ids: [], run_id: null, run_revision: null, content: "", dirty: true
      });
      shared.failCandidateWrites(true);
      await page.getByPlaceholder(/说明当事人/u).fill("无法落盘的本窗口输入");
      await page.waitForFunction(() => document.body.textContent.includes("冲突副本也未保存"));
      const records = shared.snapshot();
      scenarioCheck(entry,
        Object.keys(records).every((id) => !/-c-[a-f0-9]{32}$/u.test(id)),
        "candidate_write_failure_does_not_claim_persistence",
        JSON.stringify(records)
      );
      scenarioCheck(entry, await page.getByRole("button", { name: "重试保存草稿", exact: true }).isVisible(), "candidate_write_failure_exposes_retry");
    });

    await runScenario(browser, "r09_dirty_export_saved_version_bytes", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      await editCurrentRun(page, "A 仅本地的未保存正文");
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await page.getByRole("button", { name: "导出已保存版本", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.calls.exports.length === 1);
      const result = await page.evaluate(() => {
        const call = window.__editorRetest.calls.exports[0];
        return { ...call, utf8: new TextDecoder().decode(new Uint8Array(call.bytes)) };
      });
      scenarioCheck(entry,
        result.id === "writing_A" && result.expected_revision === 1 && result.utf8 === "A 已保存正文",
        "saved_version_choice_exports_saved_run_blob_bytes",
        JSON.stringify(result)
      );
    });

  await runScenario(browser, "r09_dirty_export_save_then_export_bytes", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      await editCurrentRun(page, "A 保存后导出正文");
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await page.getByRole("button", { name: "保存并导出", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.calls.updates.length === 1);
      await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
        ...window.__editorRetest.runs.writing_A,
        id: "writing_A_v2",
        revision: 2,
        content: "A 保存后导出正文"
      }));
      await page.waitForFunction(() => window.__editorRetest.calls.exports.length === 1);
      const result = await page.evaluate(() => {
        const call = window.__editorRetest.calls.exports[0];
        return { ...call, utf8: new TextDecoder().decode(new Uint8Array(call.bytes)) };
      });
    scenarioCheck(entry,
      result.id === "writing_A_v2" && result.expected_revision === 2 && result.utf8 === "A 保存后导出正文",
      "save_then_export_uses_returned_run_and_blob_bytes",
      JSON.stringify(result)
    );
  });

    await runScenario(browser, "r04_conflict_actions_bind_draft_selection_and_input", async (page, entry) => {
      const currentCandidate = `writing-current-c-${"1".repeat(32)}`;
      await page.evaluate((id) => {
        window.__editorRetest.externalDraft(id, 1, {
          document_type: "民事起诉状", prompt: "冲突副本旧输入", requirements: "", case_date: "", provider_id: null,
          model: null, materials: [], attachment_ids: [], run_id: null, run_revision: null, content: "", dirty: true
        });
        return window.app.loadWritingDraftConflicts(window.app.state.writingDraft);
      }, currentCandidate);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).waitFor();
      await page.evaluate((id) => window.__editorRetest.deferDraftGet(id), currentCandidate);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.deferredDraftGets.length === 1);
      await page.getByPlaceholder(/说明当事人/u).fill("同一文书的较新输入");
      await page.evaluate((id) => window.__editorRetest.resolveDraftGet(id, window.__editorRetest.draftStore[id]), currentCandidate);
      await page.waitForTimeout(50);
      scenarioCheck(entry,
        await page.getByPlaceholder(/说明当事人/u).inputValue() === "同一文书的较新输入",
        "late_restore_cannot_replace_newer_same_document_form_input"
      );

      await bootstrap(page);
      await openWritingRun(page, "writing_A");
      const candidateA = `writing-document_A-c-${"2".repeat(32)}`;
      await page.evaluate((id) => {
        window.__editorRetest.externalDraft(id, 1, {
          document_type: "民事起诉状", prompt: "A 的冲突副本", requirements: "", case_date: "", provider_id: null,
          model: null, materials: [], attachment_ids: [], run_id: "writing_A", run_revision: 1, content: "A 冲突正文", dirty: true
        });
        return window.app.loadWritingDraftConflicts(window.app.state.writingDraft);
      }, candidateA);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).waitFor();
      await page.evaluate((id) => window.__editorRetest.deferDraftGet(id), candidateA);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.deferredDraftGets.length === 1);
      await openWritingRun(page, "writing_C");
      await page.evaluate((id) => window.__editorRetest.resolveDraftGet(id, window.__editorRetest.draftStore[id]), candidateA);
      await page.waitForTimeout(50);
      const switched = await page.evaluate((id) => ({
        selected: window.app.state.pageRunIds.writing,
        activeDraft: window.app.state.writingDraft.id,
        candidateRetained: Boolean(window.__editorRetest.draftStore[id])
      }), candidateA);
      scenarioCheck(entry,
        switched.selected === "writing_C" && switched.activeDraft === "writing-document_C" && switched.candidateRetained,
        "late_A_conflict_action_cannot_apply_or_save_into_C_and_retains_candidate",
        JSON.stringify(switched)
      );
      scenarioCheck(entry,
        await page.getByPlaceholder(/说明当事人/u).inputValue() !== "A 的冲突副本",
        "late_A_conflict_action_cannot_replace_C_form"
      );
    });

    await runScenario(browser, "r04_candidate_old_version_binds_detail_before_save", async (page, entry) => {
      await page.evaluate(() => localStorage.removeItem("lawyer-assistance.writing.last-run.v1"));
      await openWritingRun(page, "writing_A");
      await page.waitForTimeout(650);
      const candidateId = `writing-document_A-c-${"3".repeat(32)}`;
      await page.evaluate((id) => {
        window.app.state.runsById.delete("writing_A");
        window.__editorRetest.externalDraft(id, 1, {
          document_type: "民事起诉状", prompt: "旧版本候选案情", requirements: "旧版本候选要求", case_date: "2026-07-07", provider_id: null,
          model: null, materials: [], attachment_ids: [], run_id: "writing_A", run_revision: 1, content: "旧版本候选正文", dirty: true
        });
        return window.app.loadWritingDraftConflicts(window.app.state.writingDraft);
      }, candidateId);
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).click();
      const editor = page.locator("textarea.document-content-editor");
      await page.waitForTimeout(100);
      const restoredUi = await page.evaluate(() => ({
        hidden: document.querySelector("textarea.document-content-editor")?.hidden,
        value: document.querySelector("textarea.document-content-editor")?.value,
        statuses: [...document.querySelectorAll(".status-box")].map((item) => item.textContent)
      }));
      scenarioCheck(entry, restoredUi.hidden === false && restoredUi.value === "旧版本候选正文", "old_candidate_restore_rebinds_editor", JSON.stringify(restoredUi));
      await editor.waitFor({ state: "visible" });
      const binding = await page.evaluate(() => ({
        cached: window.app.state.runsById.has("writing_A"),
        editorRun: document.querySelector("textarea.document-content-editor")?.dataset.runId,
        documentId: document.querySelector("textarea.document-content-editor")?.dataset.documentId
      }));
      scenarioCheck(entry,
        binding.cached && binding.editorRun === "writing_A" && binding.documentId === "document_A",
        "candidate_restore_fetches_uncached_old_run_and_binds_its_logical_document",
        JSON.stringify(binding)
      );
      await page.getByRole("button", { name: "保存正文修改", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.calls.updates.length === 1);
      const update = await page.evaluate(() => window.__editorRetest.calls.updates[0]);
      scenarioCheck(entry,
        update.id === "writing_A" && update.expected_revision === 1 && update.content === "旧版本候选正文",
        "restored_uncached_candidate_can_save_against_verified_old_run",
        JSON.stringify(update)
      );
      await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
        ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "旧版本候选正文", document_id: "document_A"
      }));
    });

    await runScenario(browser, "r09_export_choice_is_invalidated_on_document_switch", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      await editCurrentRun(page, "A 未保存导出选择");
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await page.getByRole("button", { name: "导出已保存版本", exact: true }).waitFor();
      await openWritingRun(page, "writing_C");
      const state = await page.evaluate(() => ({
        choicesHidden: document.querySelector(".draft-export-choices")?.hidden,
        exports: window.__editorRetest.calls.exports
      }));
      scenarioCheck(entry,
        state.choicesHidden === true && state.exports.length === 0,
        "switching_documents_invalidates_A_dirty_export_snapshot_before_C_can_export",
        JSON.stringify(state)
      );
    });

    await runScenario(browser, "r09_save_export_owns_current_snapshot_and_document", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      const editor = await editCurrentRun(page, "A1 普通保存");
      await beginSave(page);
      await editor.fill("A2 保存并导出");
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await page.getByRole("button", { name: "保存并导出", exact: true }).click();
      await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
        ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A1 普通保存"
      }));
      await page.waitForFunction(() => window.__editorRetest.calls.updates.length === 2);
      const second = await page.evaluate(() => window.__editorRetest.calls.updates[1]);
      scenarioCheck(entry,
        second.id === "writing_A_v2" && second.expected_revision === 2 && second.content === "A2 保存并导出",
        "save_export_starts_a_newer_A_snapshot_after_A1_settles",
        JSON.stringify(second)
      );
      await page.evaluate(() => window.__editorRetest.resolveUpdate(1, {
        ...window.__editorRetest.runs.writing_A, id: "writing_A_v3", revision: 3, content: "A2 保存并导出"
      }));
      await page.waitForFunction(() => window.__editorRetest.calls.exports.length === 1);
      const aExport = await page.evaluate(() => {
        const call = window.__editorRetest.calls.exports[0];
        return { ...call, utf8: new TextDecoder().decode(new Uint8Array(call.bytes)) };
      });
      scenarioCheck(entry,
        aExport.id === "writing_A_v3" && aExport.utf8 === "A2 保存并导出",
        "save_export_exports_its_A2_saved_version_not_A1",
        JSON.stringify(aExport)
      );

      await bootstrap(page);
      await openWritingRun(page, "writing_A");
      await editCurrentRun(page, "A 在途保存");
      await beginSave(page);
      await openWritingRun(page, "writing_C");
      await editCurrentRun(page, "C 保存并导出");
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await page.getByRole("button", { name: "保存并导出", exact: true }).click();
      await page.waitForFunction(() => window.__editorRetest.calls.updates.length === 2);
      const cRequest = await page.evaluate(() => window.__editorRetest.calls.updates[1]);
      scenarioCheck(entry,
        cRequest.id === "writing_C" && cRequest.content === "C 保存并导出",
        "C_save_export_never_consumes_A_inflight_save_promise",
        JSON.stringify(cRequest)
      );
      await page.evaluate(() => window.__editorRetest.resolveUpdate(1, {
        ...window.__editorRetest.runs.writing_C, id: "writing_C_v2", revision: 2, content: "C 保存并导出"
      }));
      await page.waitForFunction(() => window.__editorRetest.calls.exports.length === 1);
      const cExport = await page.evaluate(() => window.__editorRetest.calls.exports[0]);
      scenarioCheck(entry, cExport.id === "writing_C_v2", "C_save_export_exports_C_saved_version", JSON.stringify(cExport));
      await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
        ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A 在途保存"
      }));
    });

    await runScenario(browser, "r02_form_changes_during_save_remain_dirty_and_restore", async (page, entry) => {
      await openWritingRun(page, "writing_A");
      await page.locator('input[type="date"]').evaluate((input) => {
        input.value = "2026-08-07";
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
      const dateEditor = page.locator("textarea.document-content-editor");
      await dateEditor.waitFor({ state: "visible" });
      scenarioCheck(entry, await dateEditor.isVisible(), "date_only_edit_opens_the_existing_document_version_save_path");
      await dateEditor.fill("A 保存前正文");
      await beginSave(page);
      await page.getByPlaceholder(/说明当事人/u).fill("保存中修改的案件事实");
      await page.getByPlaceholder(/使用正式法律文书格式/u).fill("保存中修改的写作要求");
      await page.locator('input[type="date"]').evaluate((input) => {
        input.value = "2026-08-08";
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
      await page.evaluate(() => window.__editorRetest.resolveUpdate(0, {
        ...window.__editorRetest.runs.writing_A, id: "writing_A_v2", revision: 2, content: "A 保存前正文", document_id: "document_A"
      }));
      await page.waitForFunction(() => window.__editorRetest.calls.drafts.some((call) => (
        call.id === "writing-document_A" && call.content.prompt === "保存中修改的案件事实"
          && call.content.requirements === "保存中修改的写作要求" && call.content.case_date === "2026-08-08" && call.content.dirty === true
      )));
      const persisted = await page.evaluate(() => ({
        draftStore: JSON.parse(JSON.stringify(window.__editorRetest.draftStore)),
        saved: JSON.parse(JSON.stringify(window.__editorRetest.runs.writing_A_v2))
      }));
      await page.evaluate(() => localStorage.setItem("lawyer-assistance.writing.last-run.v1", "writing_A_v2"));
      const historyRuns = Array.from({ length: 20 }, (_, index) => ({
        id: `writing_history_${index}`, kind: "writing", title: `历史 ${index}`, status: "completed", revision: 1, document_id: `history_${index}`
      }));
      await bootstrap(page, {
        draftStore: persisted.draftStore,
        runs: { writing_A_v2: persisted.saved },
        historyRuns,
        expectWritingA: false
      });
      await page.waitForFunction(() => window.app.state.pageRunIds.writing === "writing_A_v2");
      const restored = await page.evaluate(() => ({
        prompt: document.querySelector('textarea[placeholder*="说明当事人"]')?.value,
        requirements: document.querySelector('textarea[placeholder*="使用正式法律文书格式"]')?.value,
        caseDate: document.querySelector('input[type="date"]')?.value,
        editor: document.querySelector("textarea.document-content-editor")?.value,
        visible: !document.querySelector("textarea.document-content-editor")?.hidden
      }));
      scenarioCheck(entry,
        restored.prompt === "保存中修改的案件事实" && restored.requirements === "保存中修改的写作要求"
          && restored.caseDate === "2026-08-08" && restored.editor === "A 保存前正文" && restored.visible,
        "form_and_date_changed_during_save_remain_dirty_across_restart",
        JSON.stringify(restored)
      );
      scenarioCheck(entry,
        await page.evaluate(() => window.app.state.pageRunIds.writing === "writing_A_v2"),
        "safe_last_pointer_fetches_detail_when_run_is_absent_from_first_history_page"
      );
    });

    await runScenario(browser, "r04_conflict_pagination_loads_and_restores_twenty_first_candidate", async (page, entry) => {
      await page.evaluate(async () => {
        const content = (index) => ({
          document_type: "民事起诉状", prompt: `第 ${index} 条冲突草稿`, requirements: "", case_date: "", provider_id: null,
          model: null, materials: [], attachment_ids: [], run_id: null, run_revision: null, content: "", dirty: true
        });
        for (let index = 0; index < 21; index += 1) {
          const id = `writing-current-c-${index.toString(16).padStart(32, "0")}`;
          window.__editorRetest.draftStore[id] = { id, revision: index + 1, updated_at: index + 1, content: content(index) };
        }
        await window.app.loadWritingDraftConflicts(window.app.state.writingDraft);
      });
      await page.waitForFunction(() => document.querySelectorAll(".draft-conflict-actions").length === 20);
      await page.getByRole("button", { name: /加载更多冲突草稿/u }).click();
      await page.waitForFunction(() => document.querySelectorAll(".draft-conflict-actions").length === 21);
      const conflictPage = await page.evaluate(() => ({
        calls: window.__editorRetest.calls.conflicts,
        rows: document.querySelectorAll(".draft-conflict-actions").length
      }));
      scenarioCheck(entry,
        conflictPage.calls.some((call) => call.cursor === "20") && conflictPage.rows === 21,
        "conflict_metadata_pagination_requests_next_cursor_and_renders_twenty_first",
        JSON.stringify(conflictPage)
      );
      await page.getByRole("button", { name: "恢复冲突草稿", exact: true }).last().click();
      scenarioCheck(entry,
        await page.getByPlaceholder(/说明当事人/u).inputValue() === "第 0 条冲突草稿",
        "twenty_first_candidate_is_reopenable_after_pagination"
      );
    });
  }
} finally {
  if (browser) await browser.close();
  await new Promise((resolve) => staticServer.close(resolve));
  await writeReport();
}

process.stdout.write(`${JSON.stringify({ report: reportPath, summary: report.summary, commit: report.source.commit })}\n`);
if (report.scenarios.some((item) => item.status === "failed")) process.exitCode = 1;
