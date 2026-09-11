// Reconstructed R07/R08/R10 assertions. Source is unchanged except exposing the
// private sanitizer to the test module. No model, credentials or workspace data.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { parseArgs } from "node:util";
import { execFileSync } from "node:child_process";
import { chromium } from "@playwright/test";

const root = path.resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { source: { type: "string", default: root }, output: { type: "string", default: "work/retest-121/contracts" }, only: { type: "string" } } });
const selectedGroups = values.only ? values.only.split(",") : null;
if (selectedGroups?.some(group => !["R07", "R08", "R10"].includes(group))) throw new Error("only_must_be_R07_R08_or_R10");
const source = path.resolve(values.source);
const output = path.resolve(values.output);
await fs.mkdir(output, { recursive: true });
const app = await fs.readFile(path.join(source, "apps/web/app.js"));
const api = await fs.readFile(path.join(source, "apps/web/api.js"));
const hashes = Object.fromEntries([["app.js", app], ["api.js", api]].map(([name, bytes]) => [name, crypto.createHash("sha256").update(bytes).digest("hex")]));
const server = http.createServer((request, response) => {
  const pathname = new URL(request.url, "http://localhost").pathname;
  response.setHeader("cache-control", "no-store");
  if (pathname === "/") {
    response.setHeader("content-type", "text/html; charset=utf-8");
    response.end("<!doctype html><meta charset=utf-8><div id=target></div>");
  } else if (pathname === "/app.js" || pathname === "/api.js") {
    response.setHeader("content-type", "text/javascript; charset=utf-8");
    response.end(pathname === "/app.js" ? app.toString("utf8") + "\nexport { sanitizeRenderedHtml };\n" : api);
  } else { response.statusCode = 404; response.end(); }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const checks = [];
async function check(id, operation) {
  if (selectedGroups && !selectedGroups.some(group => id.startsWith(`${group}_`))) { checks.push({ id, status: "not_run", reason: "phase_filter" }); return; }
  const start = performance.now();
  try { await operation(); checks.push({ id, status: "passed", assertions: true, elapsed_ms: performance.now() - start }); }
  catch (error) { checks.push({ id, status: "failed", assertions: false, error: String(error), elapsed_ms: performance.now() - start }); }
}
try {
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.evaluate(async () => { window.subject = await import("/app.js"); window.apiSubject = await import("/api.js"); });
  await check("R07_capacity_only_preserves_unknown", async () => {
    const payload = await page.evaluate(() => subject.modelCapabilitiesPayload({ context_window_tokens: 131072, max_output_tokens: 8192 }));
    assert.equal(payload.context_window_tokens, 131072);
    for (const key of ["supports_tools", "supports_structured_output", "supports_vision"]) assert.equal(payload[key] ?? null, null, `${key} must remain unknown`);
  });
  await check("R07_explicit_false_preserved_without_changing_other_capabilities", async () => {
    const payload = await page.evaluate(() => subject.modelCapabilitiesPayload({ context_window_tokens: 131072, max_output_tokens: 8192, supports_tools: false }));
    assert.equal(payload.supports_tools, false);
    assert.equal(payload.supports_structured_output ?? null, null);
    assert.equal(payload.supports_vision ?? null, null);
  });
  const codes = ["capacity_exceeded", "context_budget_exceeded", "document_worker_timeout", "document_worker_exited", "invalid_model_capabilities", "model_tools_unsupported", "model_structured_output_unsupported", "model_vision_unsupported", "context_source_removed", "context_revision_required", "context_prepare_required", "search_scope_conflict"];
  for (const code of codes) await check(`R08_${code}`, async () => {
    const text = await page.evaluate(code => apiSubject.ERROR_MESSAGES[code], code);
    assert.equal(typeof text, "string", `${code} needs a public explanation`);
    assert(text.trim().length > 8);
    assert.notEqual(text, "请求未完成，请稍后重试。");
  });
  for (const [name, markup, expectedText, assertSafeContent] of [
    ["nested_unknown", '<div><img src=x onerror="window.injected=1"><a href="javascript:window.injected=1" onclick="window.injected=1">合成链接</a></div>', "合成链接", null],
    ["deep_unknown", '<custom-a><custom-b><p id="unsafe-id" class="unsafe-class" style="color:red" onmouseover="window.injected=1">合成文本</p><a href="data:text/html,unsafe">数据链接</a><script>window.injected=1</script><style>body{outline:1px solid red}</style><iframe></iframe><object></object><svg></svg></custom-b></custom-a>', "合成文本数据链接", null],
    ["safe_content", '<custom-a><p id="unsafe-id" class="unsafe-class" style="color:red">安全段落 <strong>保留强调</strong></p><a href="https://example.com/ok">安全链接</a><ol start="3"><li>第三项</li></ol></custom-a>', "安全段落 保留强调安全链接第三项", { href: "https://example.com/ok", target: "_blank", rel: "noopener noreferrer", start: "3" }]
  ]) await check(`R10_${name}`, async () => {
    const actual = await page.evaluate(markup => {
      const target = document.getElementById("target");
      target.replaceChildren(...subject.sanitizeRenderedHtml(markup));
      const descendants = [...target.querySelectorAll("*")];
      const unsafeAttributes = descendants.flatMap(element => [...element.attributes]
        .filter(attribute => attribute.name.startsWith("on")
          || ["style", "class", "id"].includes(attribute.name)
          || (attribute.name === "href" && !/^https?:\/\//i.test(attribute.value)))
        .map(attribute => `${element.tagName.toLowerCase()}.${attribute.name}`));
      return {
        unsafe: unsafeAttributes,
        dangerous: descendants.filter(element => ["base", "embed", "iframe", "link", "meta", "object", "script", "style", "svg", "img"].includes(element.tagName.toLowerCase())).map(element => element.tagName.toLowerCase()),
        wrappers: descendants.filter(element => ["custom-a", "custom-b"].includes(element.tagName.toLowerCase())).map(element => element.tagName.toLowerCase()),
        safe: {
          href: target.querySelector("a")?.getAttribute("href") || "",
          target: target.querySelector("a")?.getAttribute("target") || "",
          rel: target.querySelector("a")?.getAttribute("rel") || "",
          start: target.querySelector("ol")?.getAttribute("start") || ""
        },
        text: target.textContent
      };
    }, markup);
    assert.deepEqual(actual.unsafe, []);
    assert.deepEqual(actual.dangerous, []);
    assert.deepEqual(actual.wrappers, []);
    assert.equal(actual.text, expectedText);
    if (assertSafeContent) assert.deepEqual(actual.safe, assertSafeContent);
  });
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
  const result = { schema_version: 1, reconstructed_from_report: true, independent_original_json_available: false, source_root: source, source_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), source_hashes: hashes, node: process.version, generated_at: new Date().toISOString(), production_csp_test: false, selected_groups: selectedGroups, status: checks.every(c => ["passed", "not_run"].includes(c.status)) ? "passed" : "failed", checks };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({ status: result.status, passed: checks.filter(c => c.status === "passed").length, failed: checks.filter(c => c.status === "failed").length, not_run: checks.filter(c => c.status === "not_run").length, output }));
  process.exitCode = result.status === "passed" ? 0 : 1;
}
