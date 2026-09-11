// Native Chromium regression for the editor/export race around R09.
//
// The daemon and browser are real.  The legal database is generated from the
// repository's public schema/fixture and the only model endpoint is a local
// in-process mock.  The mock chooses A/C titles from the prompt in memory, but
// does not retain, print, or put request messages or credentials in evidence.
//
// Usage:
//   node scripts/audit_editor_export_native.mjs [exe] --output <new-dir>
//   node scripts/audit_editor_export_native.mjs --exe <exe> --output <new-dir>
//
// A supplied executable is used as-is (startServer may make its normal locked
// test copy).  This harness does not build or select a production binary.
import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { connection, root, sleep, startServer } from "./ai_test_client.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const A_PROMPT = "EDITOR_EXPORT_A_PROMPT_4DA7";
const C_PROMPT = "EDITOR_EXPORT_C_PROMPT_7B92";
const A_TITLE = "EDITOR_EXPORT_A_TITLE_4DA7";
const C_TITLE = "EDITOR_EXPORT_C_TITLE_7B92";
const A_BASE_MARKER = "EDITOR_EXPORT_A_BASE_6E21";
const C_BASE_MARKER = "EDITOR_EXPORT_C_BASE_93B4";
const A_SAVE_MARKER = "EDITOR_EXPORT_A_SAVE_SNAPSHOT_8C17";
const C_DIRTY_MARKER = "EDITOR_EXPORT_C_DIRTY_BUFFER_51D9";
const TEST_TIMEOUT_MS = 10_000;

function usage() {
  return "Usage: node scripts/audit_editor_export_native.mjs [exe] --output <new-dir> [--portable] [--headed]";
}

function parseArgs(argv) {
  const configuredOutput = process.env.LAWYER_AUDIT_OUTPUT
    ? path.resolve(process.env.LAWYER_AUDIT_OUTPUT)
    : path.join(root, "work", "retest-121", "editor-export-native");
  const options = { executable: "", output: configuredOutput, portable: false, headed: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--portable") {
      options.portable = true;
      continue;
    }
    if (value === "--headed") {
      options.headed = true;
      continue;
    }
    if (value === "--help" || value === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (value === "--output" || value === "--exe" || value === "--executable") {
      const next = argv[++index];
      if (!next) throw new Error(`${value} requires a value\n${usage()}`);
      if (value === "--output") options.output = path.resolve(next);
      else options.executable = path.resolve(next);
      continue;
    }
    if (value.startsWith("--output=") || value.startsWith("--exe=") || value.startsWith("--executable=")) {
      const separator = value.indexOf("=");
      const next = value.slice(separator + 1);
      if (!next) throw new Error(`${value.slice(0, separator)} requires a value\n${usage()}`);
      if (value.startsWith("--output=")) options.output = path.resolve(next);
      else options.executable = path.resolve(next);
      continue;
    }
    if (value.startsWith("-")) throw new Error(`Unknown argument: ${value}\n${usage()}`);
    if (options.executable) throw new Error(`Unexpected positional argument: ${value}\n${usage()}`);
    options.executable = path.resolve(value);
  }
  if (!options.executable) options.executable = path.join(root, "target", "x86_64-pc-windows-msvc", "debug", "lawyer-assistance.exe");
  return options;
}

const options = parseArgs(process.argv.slice(2));
const output = options.output;
const reportPath = path.join(output, "report.json");
const auditLogPath = path.join(output, "audit.log");
const screenshotsDir = path.join(output, "screenshots");
const resourceDir = path.join(output, "resources");
const workspacePrefix = path.join(output, "workspace-");
const browserProfilePrefix = path.join(output, "browser-profile-");
const legalDb = path.join(resourceDir, "synthetic-public-fixture.sqlite");
const legalSchema = path.join(root, "data", "schema", "legal_core.sql");
const legalFixture = path.join(root, "crates", "legal-services", "tests", "fixtures", "legal_core.sql");

await fs.mkdir(output, { recursive: true });
await fs.mkdir(screenshotsDir, { recursive: true });
await fs.mkdir(resourceDir, { recursive: true });

async function sha256(file) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(file)) digest.update(chunk);
  return digest.digest("hex");
}

async function optionalSha256(file) {
  try {
    return await sha256(file);
  } catch (error) {
    return `unavailable:${error.code || error.name || "read_failed"}`;
  }
}

function gitValue(...args) {
  try {
    return execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      windowsHide: true,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "unavailable";
  }
}

function failureCode(error) {
  if (error?.auditCode) return String(error.auditCode);
  const raw = error?.message || error?.code || error || "unknown_error";
  return String(raw)
    .replaceAll("audit-synthetic-key-only", "[credential]")
    .replaceAll(/https?:\/\/127\.0\.0\.1:\d+/gu, "http://127.0.0.1:[port]")
    .split("\n", 1)[0]
    .slice(0, 300);
}

function fail(code, detail = "") {
  const error = new Error(detail ? `${code}: ${detail}` : code);
  error.auditCode = code;
  return error;
}

function ensure(condition, code, detail = "") {
  if (!condition) throw fail(code, detail);
}

function ensureEqual(actual, expected, code) {
  if (!Object.is(actual, expected)) throw fail(code, `actual=${String(actual)} expected=${String(expected)}`);
}

function runValue(value) {
  return value?.run || value?.new_run || value;
}

async function terminal(client, id, timeout = 180_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const run = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(id)}`));
    if (!['queued', 'running'].includes(String(run.status))) return run;
    await sleep(100);
  }
  throw fail("writing_run_timeout", id);
}

function makeSyntheticLegalDb() {
  const script = String.raw`
import pathlib, sqlite3, sys
repo, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
target.parent.mkdir(parents=True, exist_ok=True)
connection = sqlite3.connect(target)
connection.executescript((repo / 'data/schema/legal_core.sql').read_text(encoding='utf-8'))
connection.executescript((repo / 'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8'))
connection.commit()
connection.close()
`;
  execFileSync("python", ["-c", script, root, legalDb], {
    windowsHide: true,
    stdio: "ignore"
  });
}

function cleanHeaders(headers) {
  const result = { ...headers };
  delete result["content-length"];
  delete result["content-encoding"];
  delete result["transfer-encoding"];
  return result;
}

function textWithoutBom(value) {
  return value.replace(/^\uFEFF/u, "");
}

function summarizeRun(run) {
  return {
    id: typeof run?.id === "string" ? run.id : "",
    revision: Number.isInteger(run?.revision) ? run.revision : null,
    document_id: typeof run?.document_id === "string" ? run.document_id : "",
    title: typeof run?.title === "string" ? run.title : "",
    status: typeof run?.status === "string" ? run.status : ""
  };
}

async function withTimeout(promise, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(fail(code)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const source = {
  root,
  commit: gitValue("rev-parse", "HEAD"),
  branch: gitValue("branch", "--show-current"),
  status: gitValue("status", "--short"),
  hashes: {
    script: await optionalSha256(scriptPath),
    executable: await optionalSha256(options.executable),
    legal_schema: await optionalSha256(legalSchema),
    legal_fixture: await optionalSha256(legalFixture)
  }
};

const report = {
  schema_version: 1,
  suite: "editor-export-native",
  started_at: new Date().toISOString(),
  source,
  executable: {
    path: options.executable,
    sha256: source.hashes.executable,
    portable: options.portable
  },
  fixture: {
    output,
    workspace: "",
    browser_profile: "",
    legal_db: legalDb,
    synthetic_material_only: true,
    public_fixture_inputs_only: true,
    user_workspace_used: false,
    raw_model_messages_saved: false,
    credentials_logged: false
  },
  environment: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    browser: "Chromium via Playwright",
    headed: options.headed,
    timeout_ms: TEST_TIMEOUT_MS
  },
  checks: [],
  events: [],
  screenshots: [],
  model: {
    name: "editor-export-native-mock",
    transport: "localhost-only",
    calls: 0,
    calls_before_browser: null,
    raw_messages_saved: false
  },
  network: {
    browser_requests: [],
    browser_responses: [],
    request_failures: [],
    page_errors: [],
    console_errors: []
  }
};

function event(type, fields = {}) {
  report.events.push({ at: new Date().toISOString(), type, ...fields });
}

let stopChecks = false;
async function check(id, operation) {
  if (stopChecks) {
    report.checks.push({ id, status: "not_run", reason: "previous_check_failed" });
    event("check_not_run", { id, reason: "previous_check_failed" });
    return false;
  }
  const started = Date.now();
  try {
    await operation();
    report.checks.push({ id, status: "passed", elapsed_ms: Date.now() - started });
    event("check_passed", { id });
    return true;
  } catch (error) {
    const code = failureCode(error);
    report.checks.push({ id, status: "failed", elapsed_ms: Date.now() - started, error: code });
    report.failure = report.failure || { check: id, code };
    event("check_failed", { id, error: code });
    stopChecks = true;
    if (page && !page.isClosed()) await screenshot(page, `${id}-failure`);
    return false;
  }
}

async function screenshot(currentPage, name) {
  if (!currentPage || currentPage.isClosed()) return "";
  const file = path.join(screenshotsDir, `${name}.png`);
  try {
    await currentPage.screenshot({ path: file, fullPage: true });
    report.screenshots.push(file);
    event("screenshot", { name, path: file });
    return file;
  } catch (error) {
    event("screenshot_failed", { name, error: failureCode(error) });
    return "";
  }
}

function observePage(currentPage, label) {
  currentPage.on("pageerror", error => {
    report.network.page_errors.push({ page: label, error: failureCode(error) });
  });
  currentPage.on("console", message => {
    if (message.type() === "error") report.network.console_errors.push({ page: label, text: failureCode(new Error(message.text())) });
  });
  currentPage.on("request", request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) report.network.browser_requests.push({ page: label, method: request.method(), path: url.pathname });
  });
  currentPage.on("response", response => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/api/")) report.network.browser_responses.push({ page: label, method: response.request().method(), path: url.pathname, status: response.status() });
  });
  currentPage.on("requestfailed", request => {
    const url = new URL(request.url());
    report.network.request_failures.push({ page: label, method: request.method(), path: url.pathname, error: failureCode(new Error(request.failure()?.errorText || "request_failed")) });
  });
}

async function openWritingPage(currentPage, descriptor, { bootstrap = true } = {}) {
  await currentPage.goto(`${descriptor.origin}/${bootstrap ? `#token=${encodeURIComponent(descriptor.bootstrap)}` : ""}`);
  const nav = currentPage.getByRole("navigation").getByRole("button", { name: "文书写作", exact: true });
  await nav.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
  await nav.click();
  await currentPage.getByRole("heading", { name: "文书写作", exact: true }).waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
  await currentPage.locator(".ai-history-list .conversation-item").first().waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
}

async function openRun(currentPage, title) {
  const button = currentPage.getByRole("button", { name: `${title} · 已完成`, exact: true });
  await button.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
  await button.click();
  const preview = currentPage.locator(".document-preview");
  await preview.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
  return { button, preview };
}

// A successful first sequence creates a new immutable A version with the same
// title as the original.  The history button currently exposes the title but
// no run id, so locate the intended history entry through its rendered body
// marker.  This is observable DOM content and does not depend on random-id
// ordering or a hidden application state object.
async function openRunWithRenderedMarker(currentPage, title, marker) {
  const candidates = currentPage.locator(".ai-history-list .conversation-item").filter({ hasText: `${title} · 已完成` });
  const count = await candidates.count();
  ensure(count > 0, "history_entry_for_marker_missing", title);
  const preview = currentPage.locator(".document-preview");
  for (let index = 0; index < count; index += 1) {
    const button = candidates.nth(index);
    await button.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    await button.click();
    await preview.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    try {
      await currentPage.waitForFunction(expected => document.querySelector(".document-preview")?.textContent.includes(expected), marker, { timeout: 2_000 });
      return { button, preview, candidate_index: index, candidate_count: count };
    } catch {
      // A same-title saved version is a valid candidate, but not the original
      // A fixture needed by this sequence.  Try the other rendered entry.
    }
  }
  throw fail("history_entry_marker_not_found", marker);
}

async function setEditor(currentPage, value) {
  await currentPage.getByRole("button", { name: "编辑正文", exact: true }).click();
  const editor = currentPage.locator("textarea.document-content-editor");
  await editor.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
  await editor.fill(value);
  await currentPage.waitForFunction(expected => document.querySelector("textarea.document-content-editor")?.value === expected, value, { timeout: TEST_TIMEOUT_MS });
  return editor;
}

async function installHeldSaveRoute(currentPage, targetRunId) {
  const targetPath = `/api/v1/ai/runs/${encodeURIComponent(targetRunId)}/content`;
  let resolveFetched;
  let rejectFetched;
  const fetched = new Promise((resolve, reject) => {
    resolveFetched = resolve;
    rejectFetched = reject;
  });
  let releaseResolve;
  const releasePromise = new Promise(resolve => { releaseResolve = resolve; });
  let matched = 0;
  let completed = false;
  let doneResolve;
  const done = new Promise(resolve => { doneResolve = resolve; });
  const routeHandler = async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() !== "PUT" || url.pathname !== targetPath) {
      await route.continue();
      return;
    }
    matched += 1;
    event("save_route_matched", { method: request.method(), path: url.pathname });
    try {
      // route.fetch sends the real PUT to the real daemon before the browser
      // sees its response.  The response itself remains held below.
      const upstream = await route.fetch();
      const body = await upstream.body();
      let value;
      try {
        value = JSON.parse(body.toString("utf8"));
      } catch {
        throw fail("held_save_response_not_json");
      }
      resolveFetched({ status: upstream.status(), value, body });
      await releasePromise;
      await route.fulfill({ status: upstream.status(), headers: cleanHeaders(upstream.headers()), body });
      completed = true;
      doneResolve();
      event("save_route_released", { status: upstream.status() });
    } catch (error) {
      rejectFetched(error);
      doneResolve();
      await route.abort().catch(() => {});
    }
  };
  await currentPage.route("**/api/v1/ai/runs/*/content", routeHandler);
  return {
    fetched,
    release() { releaseResolve(); },
    done,
    matched: () => matched,
    completed: () => completed,
    async remove() {
      releaseResolve();
      await withTimeout(done, TEST_TIMEOUT_MS, "held_save_route_did_not_finish").catch(() => {});
      await currentPage.unroute("**/api/v1/ai/runs/*/content", routeHandler).catch(() => {});
    }
  };
}

let service;
let mock;
let browser;
let page;
let pageTwo;
let providerId = "";
let modelCalls = 0;
let runA;
let runC;
let heldRoute;
let downloadOutcome;
let exportPath = "";
let mockPort = null;

try {
  makeSyntheticLegalDb();
  report.resources = {
    kind: "synthetic_database_from_public_schema_and_fixture",
    legal_db: { path: legalDb, sha256: await sha256(legalDb) },
    legal_schema: { path: legalSchema, sha256: await sha256(legalSchema) },
    legal_fixture: { path: legalFixture, sha256: await sha256(legalFixture) }
  };
  event("synthetic_resource_ready", { legal_db_sha256: report.resources.legal_db.sha256 });

  mock = http.createServer(async (request, response) => {
    let body = "";
    try {
      for await (const chunk of request) {
        body += chunk;
        if (Buffer.byteLength(body) > 2 * 1024 * 1024) {
          response.writeHead(413).end();
          return;
        }
      }
    } catch {
      response.destroy();
      return;
    }
    let requestValue = null;
    try { requestValue = JSON.parse(body); } catch { /* response remains deterministic */ }
    const promptText = JSON.stringify(requestValue || "");
    const isC = promptText.includes(C_PROMPT);
    const title = isC ? C_TITLE : A_TITLE;
    const marker = isC ? C_BASE_MARKER : A_BASE_MARKER;
    modelCalls += 1;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({
      model: "editor-export-native-mock",
      choices: [{
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: JSON.stringify({
            title,
            content: `# ${title}\n\n${marker}\n固定合成正文。`,
            citations: []
          })
        }
      }],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 }
    }));
  });
  await new Promise((resolve, reject) => {
    mock.once("error", reject);
    mock.listen(0, "127.0.0.1", resolve);
  });
  mockPort = mock.address().port;
  event("localhost_mock_ready", { port: mockPort });

  const workspace = await fs.mkdtemp(workspacePrefix);
  const browserProfile = await fs.mkdtemp(browserProfilePrefix);
  report.fixture.workspace = workspace;
  report.fixture.browser_profile = browserProfile;
  service = await startServer(workspace, options.executable, legalDb, { portable: options.portable });
  const client = service.client;
  event("daemon_ready", { origin: client.origin });

  const provider = await client.request("/api/v1/ai/providers", "POST", {
    preset: "custom",
    name: "编辑导出原生本地合成模型",
    base_url: `http://127.0.0.1:${mockPort}/v1`,
    enabled_models: ["editor-export-native-mock"],
    api_key: "audit-synthetic-key-only",
    trust_raw: false,
    allow_private_network: true
  });
  providerId = provider.id;
  ensure(typeof providerId === "string" && providerId.length > 0, "provider_id_missing");
  await client.request("/api/v1/ai/defaults", "PUT", {
    writing: { provider_id: providerId, model: "editor-export-native-mock" }
  });

  await check("native_daemon_creates_unique_completed_A_C", async () => {
    const create = async prompt => runValue(await client.request("/api/v1/ai/runs", "POST", {
      kind: "writing",
      prompt,
      document_type: "合成民事文书",
      requirements: "固定合成要求，不读取用户材料。",
      provider_id: providerId,
      model: "editor-export-native-mock",
      materials: [],
      attachment_ids: []
    }));
    const startedA = await create(A_PROMPT);
    const startedC = await create(C_PROMPT);
    ensure(typeof startedA?.id === "string" && typeof startedC?.id === "string", "writing_run_id_missing");
    runA = await terminal(client, startedA.id);
    runC = await terminal(client, startedC.id);
    ensureEqual(runA.status, "completed", "writing_A_not_completed");
    ensureEqual(runC.status, "completed", "writing_C_not_completed");
    ensureEqual(runA.title, A_TITLE, "writing_A_title_not_unique");
    ensureEqual(runC.title, C_TITLE, "writing_C_title_not_unique");
    ensure(runA.id !== runC.id, "writing_A_C_ids_collide");
    ensure(runA.document_id && runC.document_id && runA.document_id !== runC.document_id, "writing_A_C_document_ids_not_distinct");
    report.runs = { A: summarizeRun(runA), C: summarizeRun(runC) };
    report.model.calls_before_browser = modelCalls;
    event("writing_runs_ready", { A: summarizeRun(runA), C: summarizeRun(runC) });
  });

  const descriptor = connection(workspace);
  await check("chromium_opens_A_and_enters_dirty_snapshot", async () => {
    browser = await chromium.launchPersistentContext(browserProfile, {
      headless: !options.headed,
      viewport: { width: 1440, height: 1000 },
      acceptDownloads: true
    });
    page = await browser.newPage();
    observePage(page, "primary");
    await openWritingPage(page, descriptor);
    await openRun(page, A_TITLE);
    await page.waitForFunction(marker => document.querySelector(".document-preview")?.textContent.includes(marker), A_BASE_MARKER, { timeout: TEST_TIMEOUT_MS });
    const editor = await setEditor(page, `${A_SAVE_MARKER}\n\nA 保存快照固定正文。`);
    await page.locator(".preview-panel select").selectOption("txt");
    ensureEqual(await editor.inputValue(), `${A_SAVE_MARKER}\n\nA 保存快照固定正文。`, "A_dirty_snapshot_not_entered");
    await screenshot(page, "primary-A-dirty-before-save");
  });

  await check("A_put_route_fetches_real_save_then_holds_response", async () => {
    heldRoute = await installHeldSaveRoute(page, runA.id);
    const downloadPromise = page.waitForEvent("download", { timeout: TEST_TIMEOUT_MS })
      .then(download => ({ download }))
      .catch(error => ({ error }));
    downloadOutcome = downloadPromise;
    await page.getByRole("button", { name: "导出", exact: true }).click();
    const choices = page.locator(".draft-export-choices");
    await choices.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    const saveThenExport = choices.getByRole("button", { name: "保存并导出", exact: true });
    await saveThenExport.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    // Playwright's click waits for the DOM event, while the app's async
    // handler continues through the held route.  Keep the promise observed so
    // a rejected handler cannot become an unhandled rejection.
    void saveThenExport.click().catch(error => event("save_export_click_failed", { error: failureCode(error) }));
    const fetched = await withTimeout(heldRoute.fetched, TEST_TIMEOUT_MS, "A_save_route_fetch_timeout");
    const fetchedRun = runValue(fetched.value);
    ensureEqual(fetched.status, 200, "A_save_route_status_not_ok");
    ensure(fetchedRun?.id && fetchedRun.id !== runA.id, "A_save_did_not_return_new_fixed_id");
    ensure(Number.isInteger(fetchedRun.revision) && fetchedRun.revision > runA.revision, "A_save_did_not_return_new_revision");
    ensureEqual(fetchedRun.document_id, runA.document_id, "A_save_changed_document_id");
    report.primary = report.primary || {};
    report.primary.held_save_response = summarizeRun(fetchedRun);
    event("A_save_accepted_and_held", { run: summarizeRun(fetchedRun) });
  });

  await check("switches_to_C_and_keeps_C_dirty_while_A_response_held", async () => {
    const cButton = page.getByRole("button", { name: `${C_TITLE} · 已完成`, exact: true });
    await cButton.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    await cButton.click();
    await page.waitForFunction(marker => document.querySelector(".document-preview")?.textContent.includes(marker), C_BASE_MARKER, { timeout: TEST_TIMEOUT_MS });
    const editor = await setEditor(page, `${C_DIRTY_MARKER}\n\nC 切换后的未保存正文。`);
    ensureEqual(await editor.inputValue(), `${C_DIRTY_MARKER}\n\nC 切换后的未保存正文。`, "C_dirty_snapshot_not_entered_while_held");
    ensureEqual(await editor.getAttribute("data-run-id"), runC.id, "C_editor_bound_to_wrong_run_while_held");
    await screenshot(page, "primary-C-dirty-while-A-response-held");
    event("C_dirty_entered_while_A_response_held", { run_id: runC.id });
  });

  // Release even if the C step failed.  This is cleanup for an accepted real
  // backend write and must happen before closing the browser.
  if (heldRoute) heldRoute.release();

  await check("released_save_downloads_A_snapshot_without_C", async () => {
    const outcome = await withTimeout(downloadOutcome, TEST_TIMEOUT_MS, "save_and_export_no_download");
    if (outcome.error) throw fail("save_and_export_no_download", failureCode(outcome.error));
    const download = outcome.download;
    exportPath = path.join(output, "exports", "A-save-then-export.txt");
    await fs.mkdir(path.dirname(exportPath), { recursive: true });
    await download.saveAs(exportPath);
    const text = textWithoutBom(await fs.readFile(exportPath, "utf8"));
    const expected = `${A_SAVE_MARKER}\n\nA 保存快照固定正文。`;
    ensureEqual(text.trim(), expected, "downloaded_txt_is_not_A_save_snapshot");
    ensure(!text.includes(C_DIRTY_MARKER) && !text.includes(C_BASE_MARKER), "downloaded_txt_contains_C_content");
    report.primary = report.primary || {};
    report.primary.download = { path: exportPath, suggested_filename: download.suggestedFilename(), bytes: Buffer.byteLength(text) };
    await screenshot(page, "primary-after-A-download");
  });

  await check("GET_new_A_id_matches_saved_revision_and_content", async () => {
    const saved = runValue((await heldRoute.fetched).value);
    const persisted = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(saved.id)}`));
    ensureEqual(persisted.id, saved.id, "saved_A_get_id_changed");
    ensureEqual(persisted.revision, saved.revision, "saved_A_get_revision_changed");
    ensureEqual(persisted.document_id, runA.document_id, "saved_A_get_document_id_changed");
    ensureEqual(persisted.content, `${A_SAVE_MARKER}\n\nA 保存快照固定正文。`, "saved_A_get_content_changed");
    report.primary = report.primary || {};
    report.primary.persisted_saved_run = summarizeRun(persisted);
  });

  await check("C_editor_buffer_remains_dirty_after_A_release", async () => {
    const editor = page.locator("textarea.document-content-editor");
    await editor.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    ensureEqual(await editor.inputValue(), `${C_DIRTY_MARKER}\n\nC 切换后的未保存正文。`, "C_dirty_buffer_lost_after_A_release");
    ensureEqual(await editor.getAttribute("data-run-id"), runC.id, "C_editor_rebound_after_A_release");
    ensureEqual(modelCalls, report.model.calls_before_browser, "model_requested_during_save_export_switch");
  });

  if (heldRoute) {
    await heldRoute.remove();
    heldRoute = undefined;
  }

  await check("open_A_export_choice_then_switch_C_cannot_export_C", async () => {
    pageTwo = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    observePage(pageTwo, "choice-switch");
    // The second tab shares the established HttpOnly session. Reposting the
    // bootstrap token would rotate the cookie while the first tab still has
    // its old CSRF token, which is unrelated to the export identity under test.
    await openWritingPage(pageTwo, descriptor, { bootstrap: false });
    // The first sequence may have added an immutable A version with the same
    // title.  Select the original by its rendered base marker instead of
    // guessing which duplicate appears first.
    const selectedA = await openRunWithRenderedMarker(pageTwo, A_TITLE, A_BASE_MARKER);
    await pageTwo.waitForFunction(marker => document.querySelector(".document-preview")?.textContent.includes(marker), A_BASE_MARKER, { timeout: TEST_TIMEOUT_MS });
    await setEditor(pageTwo, `${A_SAVE_MARKER}_CHOICE\n\nA 导出选择快照。`);
    await pageTwo.locator(".preview-panel select").selectOption("txt");
    await pageTwo.getByRole("button", { name: "导出", exact: true }).click();
    const choices = pageTwo.locator(".draft-export-choices");
    await choices.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
    await pageTwo.getByRole("button", { name: `${C_TITLE} · 已完成`, exact: true }).click();
    await pageTwo.waitForFunction(marker => document.querySelector(".document-preview")?.textContent.includes(marker), C_BASE_MARKER, { timeout: TEST_TIMEOUT_MS });
    const visibleActions = await choices.locator("button").evaluateAll(buttons => buttons.filter(button => {
      const style = getComputedStyle(button);
      return !button.hidden && !button.disabled && style.display !== "none" && style.visibility !== "hidden";
    }).map(button => button.textContent.trim()));
    if (visibleActions.length === 0 || !(await choices.isVisible())) {
      report.choice_switch = { behavior: "choice_invalidated_after_document_switch", visible_actions: visibleActions };
      await screenshot(pageTwo, "choice-switch-invalidated");
    } else {
      const savedChoice = choices.getByRole("button", { name: "导出已保存版本", exact: true });
      await savedChoice.waitFor({ state: "visible", timeout: TEST_TIMEOUT_MS });
      const choiceDownload = pageTwo.waitForEvent("download", { timeout: TEST_TIMEOUT_MS })
        .then(download => ({ download }))
        .catch(error => ({ error }));
      await savedChoice.click();
      const outcome = await withTimeout(choiceDownload, TEST_TIMEOUT_MS, "choice_export_no_download");
      if (outcome.error) throw fail("choice_export_no_download", failureCode(outcome.error));
      const choicePath = path.join(output, "exports", "A-choice-after-C-switch.txt");
      await fs.mkdir(path.dirname(choicePath), { recursive: true });
      await outcome.download.saveAs(choicePath);
      const text = textWithoutBom(await fs.readFile(choicePath, "utf8"));
      // The explicit choice is "导出已保存版本": the unsaved CHOICE body
      // must not be exported.  Since selectedA was the original A marker,
      // require that exact saved body and exclude both dirty A and C.
      const expectedSavedA = `${A_TITLE}\n\n${A_BASE_MARKER}\n固定合成正文。`;
      ensureEqual(text.trim(), expectedSavedA, "choice_export_not_bound_to_selected_A_saved_version");
      ensure(!text.includes(`${A_SAVE_MARKER}_CHOICE`), "choice_export_included_A_unsaved_choice_body");
      ensure(!text.includes(C_BASE_MARKER) && !text.includes(C_DIRTY_MARKER), "choice_export_bound_to_C");
      report.choice_switch = { behavior: "choice_remained_bound_to_A", selected_candidate_index: selectedA.candidate_index, path: choicePath, suggested_filename: outcome.download.suggestedFilename() };
      await screenshot(pageTwo, "choice-switch-exported-A");
    }
    ensureEqual(modelCalls, report.model.calls_before_browser, "model_requested_during_choice_switch");
  });
} catch (error) {
  const code = failureCode(error);
  report.failure = report.failure || { scope: "setup", code };
  event("run_failed", { error: code });
} finally {
  if (heldRoute) {
    await heldRoute.remove().catch(error => event("held_route_cleanup_failed", { error: failureCode(error) }));
    heldRoute = undefined;
  }
  if (pageTwo && !pageTwo.isClosed()) await pageTwo.close().catch(() => {});
  if (browser) await browser.close().catch(() => {});
  if (service) await service.stop().catch(error => event("daemon_stop_failed", { error: failureCode(error) }));
  if (mock) await new Promise(resolve => mock.close(resolve)).catch(error => event("mock_stop_failed", { error: failureCode(error) }));
  report.model.calls = modelCalls;
  report.completed_at = new Date().toISOString();
  report.status = report.failure || report.checks.some(item => item.status === "failed") ? "failed" : "passed";
  report.passed = report.status === "passed";
  report.summary = {
    passed: report.checks.filter(item => item.status === "passed").length,
    failed: report.checks.filter(item => item.status === "failed").length,
    not_run: report.checks.filter(item => item.status === "not_run").length,
    total: report.checks.length
  };
  report.logs = {
    audit: { path: auditLogPath },
    server: { path: report.fixture.workspace ? path.join(report.fixture.workspace, "server-test.log") : "" }
  };
  report.logs.server.sha256 = await optionalSha256(report.logs.server.path);
  await fs.writeFile(auditLogPath, `${report.events.map(item => JSON.stringify(item)).join("\n")}\n`, "utf8");
  report.logs.audit.sha256 = await sha256(auditLogPath);
  report.source.hashes.script = await optionalSha256(scriptPath);
  report.source.hashes.executable = await optionalSha256(options.executable);
  report.executable.sha256 = report.source.hashes.executable;
  report.source.status = gitValue("status", "--short");
  await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  const outputLine = { status: report.status, report: reportPath, checks: report.summary, model_calls: modelCalls };
  if (report.status === "passed") console.log(JSON.stringify(outputLine));
  else console.error(JSON.stringify(outputLine));
  if (report.status !== "passed") process.exitCode = 1;
}
