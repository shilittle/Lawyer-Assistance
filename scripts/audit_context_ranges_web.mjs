// Deterministic Chromium checks for the R07/R08 context-range UI.  This uses
// only synthetic opaque IDs and mock API replies; no workspace, provider, or
// model is contacted.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chromium } from "@playwright/test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({ options: {
  root: { type: "string", default: root },
  output: { type: "string", default: path.join(root, "work", "retest-121", "stage2-context-web") }
} });
const source = path.resolve(values.root);
const output = path.resolve(values.output);
const webRoot = path.join(source, "apps", "web");
const appBytes = await fs.readFile(path.join(webRoot, "app.js"));
const apiBytes = await fs.readFile(path.join(webRoot, "api.js"));
const styleBytes = await fs.readFile(path.join(webRoot, "styles.css"));
try { await fs.access(path.join(output, "report.json")); throw new Error("evidence_directory_already_used"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
await fs.mkdir(output, { recursive: true });

const server = http.createServer((request, response) => {
  const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
  response.setHeader("cache-control", "no-store");
  if (pathname === "/") { response.setHeader("content-type", "text/html; charset=utf-8"); response.end('<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/styles.css"><div id="audit-root"></div>'); return; }
  if (pathname === "/app.js") { response.setHeader("content-type", "text/javascript; charset=utf-8"); response.end(appBytes); return; }
  if (pathname === "/api.js") { response.setHeader("content-type", "text/javascript; charset=utf-8"); response.end(apiBytes); return; }
  if (pathname === "/styles.css") { response.setHeader("content-type", "text/css; charset=utf-8"); response.end(styleBytes); return; }
  response.statusCode = 404; response.end();
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const report = {
  schema_version: 1,
  suite: "context-ranges-web",
  synthetic_only: true,
  source_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim(),
  hashes: Object.fromEntries([["apps/web/app.js", appBytes], ["apps/web/api.js", apiBytes], ["scripts/audit_context_ranges_web.mjs", await fs.readFile(fileURLToPath(import.meta.url))]].map(([name, bytes]) => [name, createHash("sha256").update(bytes).digest("hex")])),
  started_at: new Date().toISOString(),
  checks: []
};

async function bootstrap(page, view = "templates") {
  await page.goto(origin);
  await page.evaluate(async (initialView) => {
    const [{ WebApp }, { ApiError }] = await Promise.all([import("/app.js"), import("/api.js")]);
    const copy = (value) => JSON.parse(JSON.stringify(value));
    const provider = {
      id: "provider_synthetic", name: "Synthetic provider", base_url: "https://synthetic.example/v1", model: "model_synthetic", enabled_models: ["model_synthetic"], trust_raw: false, key_configured: true,
      model_capabilities: { model_synthetic: { supports_tools: false } },
      capability_metadata: { model_synthetic: { declaration_source: "user_configuration", declared_at: 1700000000, config_binding: "binding-synthetic", declaration_hash: "hash-synthetic", verification_state: "declared", needs_review: true, fields_needing_review: ["supports_tools"], provider_revision: 4, current_config_binding: "binding-current" } }
    };
    const material = { id: "material_scope_1", name: "合成材料甲", result_id: "redacted_scope_1", status: "completed", has_original: true };
    const requestedWritingPlan = {
      stage: "ready", plan_hash: "plan-current", capabilities: { verified: false },
      estimate: { input_tokens: 111, reserved_output_tokens: 4000, history_tokens: 0, material_tokens: 0, attachment_tokens: 111, tool_reserve_tokens: 0 },
      selected_scope: { materials: [], attachments: [{ source_kind: "attachment", source_id: "attachment_scope_1", locators: ["paragraph:1"] }], history_run_ids: [] },
      omitted_scope: []
    };
    const completedWritingPlan = {
      schema_version: 1, plan_hash: "plan-current", actual_plan_hash: "actual-plan-synthetic", stage: "ready",
      capabilities: { verified: true, max_input_tokens: 48000, max_output_tokens: 4000 },
      estimate: { input_tokens: 240, reserved_output_tokens: 4000, history_tokens: 0, material_tokens: 0, attachment_tokens: 240, tool_reserve_tokens: 0 },
      selected_scope: { materials: [], attachments: [{ source_kind: "attachment", source_id: "attachment_scope_1", format: "txt", locators: ["paragraph:2"] }], history_run_ids: [] },
      omitted_scope: []
    };
    let runNumber = 0;
    const control = {
      calls: { inspect: [], estimates: [], creates: [], contextUpdates: [], prepares: [], providerSaves: [], draftSaves: [] },
      runs: {},
      draftStore: {
        "writing-current": {
          id: "writing-current", revision: 1,
          content: {
            document_type: "律师函", prompt: "合成案情", requirements: "合成要求", provider_id: provider.id, model: provider.model,
            materials: [{ id: material.id, source: "redacted" }], attachment_ids: ["attachment_scope_1"],
            context_ranges: [
              { source_kind: "material", source_id: material.id, source: "redacted", mode: "pages", ranges: [{ start: 2, end: 3 }], inspection_hash: "restored-inspection-material" },
              { source_kind: "attachment", source_id: "attachment_scope_1", mode: "all" }
            ], dirty: true
          }
        }
      },
      conversation: {
        id: "conversation_scope_1", title: "合成范围会话", messages: [], context_revision: 1,
        materials: [{ id: material.id, source: "redacted" }], attachment_ids: ["attachment_scope_1"],
        context_ranges: [
          { source_kind: "material", source_id: material.id, source: "redacted", mode: "all" },
          { source_kind: "attachment", source_id: "attachment_scope_1", mode: "all" }
        ]
      },
      deferEstimate: false,
      deferredEstimate: [],
      resolveEstimate() { for (const item of this.deferredEstimate.splice(0)) item.resolve({ stage: "ready", plan_hash: "plan-current", capabilities: { verified: false }, estimate: {}, selected_scope: {}, omitted_scope: [] }); }
    };
    const api = {
      setCsrfToken() {}, setSessionEpoch() {},
      async request(route) {
        if (route.startsWith("/legal/filters")) return { documentTypes: [], effectivenessLevels: [], statuses: [], jurisdictions: [] };
        if (route.startsWith("/legal/cases/status")) return { available: true };
        if (route.startsWith("/bookmarks")) return { bookmarks: [] };
        if (route.startsWith("/groups") || route.startsWith("/materials")) return { groups: [], materials: [] };
        return {};
      },
      async listAiProviders() { return { providers: [copy(provider)], defaults: { writing: { provider_id: provider.id, model: provider.model }, chat: { provider_id: provider.id, model: provider.model } } }; },
      async saveAiProvider(value) { control.calls.providerSaves.push(copy(value)); return { provider: copy(provider) }; },
      async discoverAiModels() { return { models: [{ id: provider.model }] }; },
      async testAiProvider() { return { ok: true }; },
      async updateAiDefaults() { return {}; },
      async listAiMaterials() { return { materials: [copy(material)], next_cursor: "", total: 1, corrupt_count: 0 }; },
      async listAiRuns() { return { runs: [] }; },
      async getAiRun(id) {
        const created = control.runs[id];
        if (!created) return { id, kind: "writing", status: "completed", revision: 1, content: "synthetic", document_id: "document_scope" };
        return {
          ...copy(created), status: "completed", revision: 2, title: "合成范围文书", content: "合成正文：仅采用附件第 2 段。",
          context_plan: copy(completedWritingPlan), citations: [], tool_steps: []
        };
      },
      async getAiDraft(id) { const record = control.draftStore[id]; if (!record) throw new ApiError("not_found", false, 404); return copy(record); },
      async saveAiDraft(id, payload) { const previous = control.draftStore[id]; const record = { id, revision: (previous?.revision || 0) + 1, content: copy(payload.content) }; control.draftStore[id] = record; control.calls.draftSaves.push(copy(record)); return copy(record); },
      async listAiDraftConflicts() { return { drafts: [], next_cursor: "", total: 0, corrupt_count: 0 }; },
      async inspectAiContextSource(payload) {
        control.calls.inspect.push(copy(payload));
        return { ...copy(payload), format: "txt", unit_kind: payload.source_kind === "attachment" ? "paragraph" : "page", unit_count: 6, unit_version: "synthetic-v1", inspection_hash: `inspect-${payload.source_kind}-${payload.source_id}`, estimated_input_tokens: 42, estimate_basis: "synthetic-structural-only" };
      },
      async estimateAiContext(payload) {
        control.calls.estimates.push(copy(payload));
        if (control.deferEstimate) return new Promise((resolve) => control.deferredEstimate.push({ resolve }));
        return copy(requestedWritingPlan);
      },
      async createAiRun(payload) {
        control.calls.creates.push(copy(payload));
        runNumber += 1;
        const run = { id: `run_synthetic_${runNumber}`, kind: payload.kind, status: "running", revision: 1, title: "合成范围文书", content: "", document_id: "document_scope", citations: [], tool_steps: [] };
        control.runs[run.id] = copy(run);
        return copy(run);
      },
      async listAiConversations() { return { conversations: [copy(control.conversation)] }; },
      async getAiConversation(id) { if (id !== control.conversation.id) throw new Error("unexpected_conversation_id"); return copy(control.conversation); },
      async updateAiConversationContext(id, payload) {
        if (id !== control.conversation.id) throw new Error("unexpected_conversation_id"); control.calls.contextUpdates.push(copy(payload));
        control.conversation = { ...control.conversation, materials: copy(payload.materials), attachment_ids: copy(payload.attachment_ids), context_ranges: copy(payload.context_ranges), context_revision: control.conversation.context_revision + 1 };
        return { conversation: copy(control.conversation), cancelled_run_ids: [] };
      },
      async prepareAiConversationContext(id, payload) {
        if (id !== control.conversation.id) throw new Error("unexpected_conversation_id"); control.calls.prepares.push(copy(payload));
        return { manifest: copy(control.conversation), revision: control.conversation.context_revision, preparation_hash: `prepared-${control.conversation.context_revision}` };
      }
    };
    window.__contextRangeAudit = control;
    window.app = new WebApp(document.getElementById("audit-root"), api);
    app.state.authenticated = true;
    app.state.health = { status: "ready" };
    app.navigate(initialView);
  }, view);
}

async function check(browser, id, operation) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.setDefaultTimeout(8000);
  const entry = { id, status: "running", assertions: [], errors: [], screenshot: "" };
  report.checks.push(entry);
  page.on("pageerror", (error) => entry.errors.push(error.message));
  try {
    await operation(page, entry);
    assert.deepEqual(entry.errors, []);
    entry.status = "passed";
  } catch (error) {
    entry.status = "failed";
    entry.error = String(error?.stack || error);
  } finally {
    const file = `${id}.png`;
    await page.screenshot({ path: path.join(output, file), fullPage: true }).catch(() => {});
    entry.screenshot = file;
    await page.close();
  }
}

function asserted(entry, condition, detail) { entry.assertions.push({ passed: Boolean(condition), detail }); assert.ok(condition, detail); }

const browser = await chromium.launch({ headless: true });
try {
  await check(browser, "R07_tri_state_capacity_does_not_clear_untouched_false", async (page, entry) => {
    await bootstrap(page, "settings");
    await page.locator(".provider-row").waitFor();
    const result = await page.evaluate(async () => {
      const appModule = await import("/app.js");
      return {
        capacityOnly: appModule.modelCapabilitiesPayload({ contextWindowTokens: "32768", maxOutputTokens: "4096", supportsTools: false, supportsToolsPresent: false }),
        explicitCorrection: appModule.modelCapabilitiesPayload({ supportsTools: null, supportsToolsPresent: true })
      };
    });
    asserted(entry, !Object.hasOwn(result.capacityOnly, "supports_tools"), "capacity-only update omits untouched false declaration");
    asserted(entry, result.explicitCorrection.supports_tools === null, "explicit unknown correction is serialized as null");
    const text = await page.locator(".provider-row").textContent();
    asserted(entry, /配置声明/.test(text) && /未实测/.test(text) && /待复核/.test(text), "provider metadata exposes declaration provenance and review state");
    await page.getByRole("button", { name: "编辑", exact: true }).click();
    await page.locator("input[placeholder='上下文窗口 tokens']").fill("32768");
    await page.locator("input[placeholder='最大输出 tokens']").fill("4096");
    asserted(entry, /已明确阻断/.test(await page.locator(".model-capability-config").textContent()), "existing false remains visibly blocked until an explicit correction");
    await page.getByRole("button", { name: "保存模型服务", exact: true }).click();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.providerSaves.length === 1);
    const capacitySave = await page.evaluate(() => window.__contextRangeAudit.calls.providerSaves[0]);
    asserted(entry, !Object.hasOwn(capacitySave.model_capabilities.model_synthetic, "supports_tools"), "capacity-only UI save does not mark existing false as touched");
    await page.locator("select[aria-label='model_synthetic工具调用能力声明']").selectOption("unknown");
    await page.getByRole("button", { name: "保存模型服务", exact: true }).click();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.providerSaves.length === 2);
    const corrected = await page.evaluate(() => window.__contextRangeAudit.calls.providerSaves[1]);
    asserted(entry, corrected.model_capabilities.model_synthetic.supports_tools === null, "explicit user correction sends null rather than silently changing another capability");
  });

  await check(browser, "R08_safe_actionable_messages", async (page, entry) => {
    await bootstrap(page, "settings");
    const messages = await page.evaluate(async () => (await import("/api.js")).ERROR_MESSAGES);
    for (const code of ["capacity_exceeded", "context_budget_exceeded", "document_worker_timeout", "document_worker_exited", "invalid_model_capabilities", "model_tools_unsupported", "model_structured_output_unsupported", "model_vision_unsupported", "context_source_removed", "context_revision_required", "context_prepare_required", "search_scope_conflict"]) asserted(entry, typeof messages[code] === "string" && messages[code].length > 8, `${code} has a safe actionable message`);
  });

  await check(browser, "R07_writing_draft_restores_scope_and_nonchat_payload", async (page, entry) => {
    await bootstrap(page, "templates");
    await page.getByRole("heading", { name: "文书写作", exact: true }).waitFor();
    await page.waitForFunction(() => window.app?.state?.writingDraft?.loaded === true);
    await page.locator("form.stack-form textarea").first().fill("合成案情更新");
    await page.evaluate(() => window.app.flushWritingDraft());
    await page.waitForFunction(() => window.__contextRangeAudit.calls.draftSaves.length >= 1);
    await page.getByRole("button", { name: "生成文书", exact: true }).click();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.creates.length === 1);
    const payloads = await page.evaluate(() => ({ estimate: window.__contextRangeAudit.calls.estimates[0], create: window.__contextRangeAudit.calls.creates[0], draft: window.__contextRangeAudit.calls.draftSaves.at(-1).content }));
    const expected = payloads.create.context_ranges.find((item) => item.source_kind === "material");
    asserted(entry, expected?.mode === "pages" && expected.ranges?.[0]?.start === 2 && expected.inspection_hash === "restored-inspection-material", "encrypted draft scope is restored into writing estimate and run");
    asserted(entry, payloads.draft.context_ranges.some((item) => item.mode === "pages" && item.inspection_hash === "restored-inspection-material"), "writing draft save retains the restored scoped selection");
    asserted(entry, JSON.stringify(payloads.estimate.context_ranges) === JSON.stringify(payloads.create.context_ranges), "estimate and creation bind identical scope");
  });

  await check(browser, "R07_completed_writing_renders_actual_scope_and_clears_matching_range_warning", async (page, entry) => {
    await bootstrap(page, "templates");
    await page.getByRole("heading", { name: "文书写作", exact: true }).waitFor();
    await page.waitForFunction(() => window.app?.state?.writingDraft?.loaded === true);
    const attachmentRow = page.locator(".context-range-row").nth(1);
    await attachmentRow.getByRole("button", { name: "检查页/段落", exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll(".context-range-row")[1]?.querySelector("select")?.querySelector("option[value='paragraphs']"));
    const refreshedAttachmentRow = page.locator(".context-range-row").nth(1);
    await refreshedAttachmentRow.locator("select").selectOption("paragraphs");
    await refreshedAttachmentRow.locator("input[type=text]").fill("2");
    await refreshedAttachmentRow.getByRole("button", { name: "应用范围", exact: true }).click();
    await page.locator("form.stack-form textarea").first().fill("使用附件第二段的合成案情");
    await page.getByRole("button", { name: "生成文书", exact: true }).click();
    await page.waitForFunction(() => {
      const preview = document.querySelector(".preview-panel")?.textContent || "";
      const estimate = document.querySelector(".context-estimate")?.textContent || "";
      const ranges = document.querySelector(".context-range-picker")?.textContent || "";
      return !preview.includes("尚未生成文书")
        && estimate.includes("paragraph:2")
        && !ranges.includes("需重新预检或准备后才能发送");
    });
    const result = await page.evaluate(async () => {
      const { normalizeAiRun } = await import("/app.js");
      const run = normalizeAiRun(normalizeAiRun(window.app.pageRun("writing")));
      return {
        preview: document.querySelector(".preview-panel")?.textContent || "",
        estimate: document.querySelector(".context-estimate")?.textContent || "",
        ranges: document.querySelector(".context-range-picker")?.textContent || "",
        paragraph: run.context_plan?.selected_scope?.attachments?.[0]?.locators?.[0] || ""
      };
    });
    asserted(entry, !result.preview.includes("尚未生成文书"), "completed current run replaces the initial preview status");
    asserted(entry, result.estimate.includes("paragraph:2") && result.estimate.includes("预计输入 240 tokens") && !result.estimate.includes("paragraph:1"), "completed run renders the server actual context plan rather than the preflight request");
    asserted(entry, !result.ranges.includes("需重新预检或准备后才能发送"), "matching completed run clears only the stale range-preflight warning");
    asserted(entry, result.paragraph === "paragraph:2", "repeated run normalization preserves context_plan for the current run");
  });

  await check(browser, "R07_inspect_converts_page_unit_to_pages_and_invalidates_old_preflight", async (page, entry) => {
    await bootstrap(page, "templates");
    await page.getByRole("heading", { name: "文书写作", exact: true }).waitFor();
    await page.waitForFunction(() => window.app?.state?.writingDraft?.loaded === true);
    await page.getByRole("button", { name: "检查页/段落", exact: true }).first().click();
    const mode = page.locator("select[aria-label$='范围模式']").first();
    await page.waitForFunction(() => [...document.querySelectorAll("select[aria-label$='范围模式'] option")].some((item) => item.value === "pages"));
    await mode.selectOption("pages");
    await page.locator(".context-range-row input[type=text]").first().fill("1-2");
    await page.getByRole("button", { name: "应用范围", exact: true }).first().click();
    await page.locator("form.stack-form textarea").first().fill("合成案情更新");
    await page.evaluate(() => { window.__contextRangeAudit.deferEstimate = true; });
    await page.getByRole("button", { name: "生成文书", exact: true }).click();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.estimates.length === 1);
    await mode.selectOption("all");
    await page.evaluate(() => window.__contextRangeAudit.resolveEstimate());
    await page.waitForTimeout(50);
    const state = await page.evaluate(() => ({ creates: window.__contextRangeAudit.calls.creates.length, inspected: window.__contextRangeAudit.calls.inspect[0], status: document.body.textContent }));
    asserted(entry, state.inspected?.source_kind === "material", "inspect request contains opaque material identity only");
    asserted(entry, state.creates === 0 && /旧预检结果未被提交/.test(state.status), "range change invalidates a pending nonchat preflight");
  });

  await check(browser, "R07_chat_scope_update_retains_attachment_and_task_uses_manifest_only", async (page, entry) => {
    await bootstrap(page, "chat");
    await page.getByRole("heading", { name: "AI 对话", exact: true }).waitFor();
    await page.waitForFunction(() => window.app?.state?.selectedConversation?.id === "conversation_scope_1");
    const material = page.locator("input[data-material-id='material_scope_1']");
    await material.uncheck();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.contextUpdates.length >= 1);
    const update = await page.evaluate(() => window.__contextRangeAudit.calls.contextUpdates.at(-1));
    asserted(entry, update.materials.length === 0 && update.attachment_ids[0] === "attachment_scope_1", "clearing materials retains attachment source");
    asserted(entry, update.context_ranges.length === 1 && update.context_ranges[0].source_kind === "attachment", "clearing materials retains only attachment range");
    await page.waitForFunction(() => window.__contextRangeAudit.calls.prepares.length >= 1);
    await page.locator("textarea[required]").fill("合成会话问题");
    await page.getByRole("button", { name: "发送", exact: true }).click();
    await page.waitForFunction(() => window.__contextRangeAudit.calls.creates.length === 1);
    const chat = await page.evaluate(() => ({ create: window.__contextRangeAudit.calls.creates[0], prepare: window.__contextRangeAudit.calls.prepares.at(-1) }));
    asserted(entry, !Object.hasOwn(chat.create, "materials") && !Object.hasOwn(chat.create, "attachment_ids") && !Object.hasOwn(chat.create, "context_ranges"), "chat task carries only prepared manifest binding");
    asserted(entry, Object.keys(chat.prepare).sort().join(",") === "expected_revision,model,provider_id", "prepare has no raw range payload");
  });
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
  report.completed_at = new Date().toISOString();
  report.status = report.checks.every((item) => item.status === "passed") ? "passed" : "failed";
  report.summary = { passed: report.checks.filter((item) => item.status === "passed").length, failed: report.checks.filter((item) => item.status === "failed").length };
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ status: report.status, ...report.summary, output }));
  if (report.status !== "passed") process.exitCode = 1;
}
