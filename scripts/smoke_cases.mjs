// Run against a disposable workspace. The corpus may be the read-only official runtime.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { createServer } from "node:http";
import { resolve, join } from "node:path";

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, item, i, all) => {
  if (item.startsWith("--")) pairs.push([item.slice(2), all[i + 1]]);
  return pairs;
}, []));
assert(args["data-dir"] && args["legal-db"] && args.binary, "--data-dir, --legal-db and --binary are required");
const unpack = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
  "Add-Type -AssemblyName System.Security; $b=[IO.File]::ReadAllBytes($env:LA_CASE_SMOKE_DESCRIPTOR); $e=[Text.Encoding]::ASCII.GetBytes('LawyerAssistance/privacy/local-protected-blob/v1'); [Console]::Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)))"],
{ env: { ...process.env, LA_CASE_SMOKE_DESCRIPTOR: join(resolve(args["data-dir"]), "connection.dpapi") }, encoding: "utf8", windowsHide: true });
assert.equal(unpack.status, 0, "disposable workspace descriptor decrypts");
const { origin, bootstrap } = JSON.parse(unpack.stdout);
assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/u);
let cookie, csrf;
async function api(path, body, method = body === undefined ? "GET" : "POST") {
  const response = await fetch(`${origin}/api/v1${path}`, {
    method, headers: { "content-type": "application/json", ...(cookie ? { cookie, "x-csrf-token": csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(90000),
  });
  const value = await response.json();
  assert.equal(response.status, 200, `${path} succeeds: ${value.error?.code ?? ""}`);
  assert.equal(response.headers.get("cache-control"), "no-store");
  if (path === "/session") { cookie = response.headers.get("set-cookie").split(";")[0]; csrf = value.csrf_token; }
  return value;
}
await api("/session", { token: bootstrap });
const status = await api("/legal/cases/status");
assert.equal(status.available, true);
assert(status.guidingCount > 0);
const search = await api(`/legal/cases?query=${encodeURIComponent("指导案例1号")}`);
assert.equal(search.cases[0].guidingNumber, 1);
const detail = await api(`/legal/cases/${search.cases[0].caseId}`);
assert(detail.case.fullText.length > 200);
assert.match(detail.case.sourceUrl, /^https:\/\/[^/]*court\.gov\.cn\//u);
const references = await api(`/legal/cases?query=${encodeURIComponent("诈骗")}&case_type=reference`);
assert(references.cases.length > 0, "official reference cases are searchable");
const historical = await api(`/legal/cases?query=${encodeURIComponent("指导案例9号")}&include_withdrawn=true`);
assert.equal(historical.cases[0].status, "withdrawn");
const filtered = await api(`/legal/cases?query=${encodeURIComponent("指导案例9号")}`);
assert.equal(filtered.cases.length, 0);
let archiveChecks;
if(args.archive === 'true') {
  assert.equal(status.total,759);assert.equal(status.guidingCount,279);assert.equal(status.referenceCount,61);assert.equal(status.typicalCount,419);
  const missingOldCase=await api(`/legal/cases?query=${encodeURIComponent('指导案例45号')}`);
  assert.equal(missingOldCase.cases[0].guidingNumber,45);
  const localReprint=await api(`/legal/cases/${missingOldCase.cases[0].caseId}`);
  assert.match(localReprint.case.sourceUrl,/^https:\/\/hnlyzy\.hncourt\.gov\.cn\//u);
  const latest=await api(`/legal/cases?query=${encodeURIComponent('指导案例279号')}`);assert.equal(latest.cases[0].guidingNumber,279);
  const typical=await api(`/legal/cases?query=${encodeURIComponent('典型')}&case_type=typical`);assert(typical.total>20);assert(typical.cases.every(c=>c.caseType==='typical'));
  const second=await api(`/legal/cases?query=${encodeURIComponent('典型')}&case_type=typical&offset=20`);assert(second.cases.every(c=>!typical.cases.some(first=>first.caseId===c.caseId)));
  const largest=await api('/legal/cases/spc-typical-typical-13447');assert.equal(Buffer.byteLength(largest.case.fullText,'utf8'),213294);
  archiveChecks={largest_case_id:largest.case.caseId,largest_body_bytes:213294,source45:localReprint.case.sourceUrl,typical_matches:typical.total};
}

const seen = [];
let malformed = false;
const mock = createServer(async (request, response) => {
  let raw = "";
  for await (const part of request) raw += part;
  seen.push(JSON.parse(raw));
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ model: "case-smoke-model", choices: [{ message: {
    content: malformed ? '{"query":"劳动关系","issues":[],"cases":["invented"]}' : JSON.stringify({ query: "劳动关系", issues: ["是否建立劳动关系"] }),
  } }] }));
});
await new Promise(resolveListen => mock.listen(0, "127.0.0.1", resolveListen));
let provider;
try {
  provider = await api("/providers", { name: "Disposable case smoke provider", model: "case-smoke-model", base_url: `http://127.0.0.1:${mock.address().port}/v1`, api_key: "case-smoke-synthetic-key", allow_private_network: true });
  const understood = await api("/legal/cases/understand", { query: "外卖骑手与平台之间是不是劳动关系", provider_id: provider.id, model: "case-smoke-model" });
  assert.equal(understood.interpreted_query, "劳动关系");
  assert(understood.results.cases.length > 0);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].messages.length, 2, "only system instruction and explicit input sent");
  assert.equal(seen[0].messages[1].content, "外卖骑手与平台之间是不是劳动关系");
  malformed = true;
  const rejected = await fetch(`${origin}/api/v1/legal/cases/understand`, {
    method: "POST", headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
    body: JSON.stringify({ query: "劳动关系", provider_id: provider.id, model: "case-smoke-model" }),
  });
  assert.equal((await rejected.json()).error.code, "case_understanding_invalid");
  if (args.browser === "true") {
    malformed = false;
    const { chromium } = await import("@playwright/test");
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      await page.goto(`${origin}/#token=${encodeURIComponent(bootstrap)}`);
      await page.getByRole("button", { name: "法律检索", exact: true }).click();
      await page.getByRole("tab", { name: "案例", exact: true }).click();
      await page.getByLabel("关键词", { exact: true }).fill("指导案例1号");
      await page.getByRole("button", { name: "检索案例", exact: true }).click();
      await page.locator(".case-result-card .result-button").first().click();
      await page.getByRole("link", { name: "打开官方原文", exact: true }).waitFor();
      await page.getByRole("heading", { name: "裁判要点", exact: true }).waitFor();
      await page.screenshot({ path: join(resolve(args["data-dir"]), "case-detail.png"), fullPage: false });
      await page.getByLabel("关键词", { exact: true }).fill("外卖骑手与平台之间是不是劳动关系");
      await page.getByLabel("Provider", { exact: true }).selectOption(provider.id);
      await page.getByRole("button", { name: "AI理解并搜索", exact: true }).click();
      await page.getByRole("heading", { name: "本次 AI 理解", exact: true }).waitFor();
      assert(await page.locator(".case-result-card").count() > 0);
      assert.equal(errors.length, 0, `browser has no uncaught errors: ${errors.join(", ")}`);
      await page.screenshot({ path: join(resolve(args["data-dir"]), "case-ai-search.png"), fullPage: false });
    } finally {
      await browser.close();
    }
  }
} finally {
  if (provider) await api("/providers", { id: provider.id, name: "Disposable credential removed", base_url: "https://cleanup.invalid/v1", model: "case-smoke-model", api_key: "", allow_private_network: false });
  await new Promise(resolveClose => mock.close(resolveClose));
}

const child = spawn(resolve(args.binary), ["--privacy-profile", "public_law_only", "--legal-db", resolve(args["legal-db"]), "stdio"], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
child.stderr.resume();
let seq = 0;
const pending = new Map();
const exited = new Promise(resolveExit => child.on("exit", resolveExit));
createInterface({ input: child.stdout }).on("line", line => {
  const value = JSON.parse(line);
  pending.get(value.id)?.(value);
});
async function rpc(method, params) {
  const id = ++seq;
  let timer;
  const received = new Promise(resolveReply => pending.set(id, resolveReply));
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  try { return await Promise.race([received, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("MCP timeout")), 30000); })]); }
  finally { clearTimeout(timer); pending.delete(id); }
}
try {
  await rpc("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "case-smoke", version: "1" } });
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  const listed = await rpc("tools/list", {});
  assert.equal(listed.result.tools.length, 7);
  for (const [name, arguments_] of [
    ["legal_search_cases", { schema_version: 1, query: "指导案例1号" }],
    ["legal_get_case", { schema_version: 1, case_id: search.cases[0].caseId }],
    ...(archiveChecks ? [["legal_search_cases",{schema_version:1,query:"典型",case_type:"typical"}],["legal_get_case",{schema_version:1,case_id:archiveChecks.largest_case_id}]] : []),
  ]) {
    const result = await rpc("tools/call", { name, arguments: arguments_ });
    assert(!result.error && !result.result.isError, `${name} passes public output boundary`);
    assert(result.result.structuredContent || result.result.content?.length);
    if(archiveChecks && arguments_.case_id===archiveChecks.largest_case_id){assert.equal(Buffer.byteLength(result.result.structuredContent['内容']['案例全文'],'utf8'),213294);}
  }
} finally {
  child.stdin.end();
  let killTimer;
  try { await Promise.race([exited, new Promise(resolveKill => { killTimer = setTimeout(() => { child.kill(); resolveKill(); }, 3000); })]); }
  finally { clearTimeout(killTimer); }
}
process.stdout.write(JSON.stringify({ passed: true, total: status.total, guiding: status.guidingCount, reference: status.referenceCount, typical:status.typicalCount,archiveChecks, http: true, aiMock: true, mcpStdio: true }) + "\n");
