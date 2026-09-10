// Run only against a freshly created synthetic test workspace, never a user's working data.
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

function usage() {
  return "Usage: node scripts/smoke_mcp.mjs --data-dir <synthetic-workspace> --legal-db <synthetic-legal-core.sqlite> [--binary <mcp-binary>]";
}

function optionsFrom(argv) {
  const options = { dataDir: "", legalDb: "", binary: "" };
  const legacyNames = ["dataDir", "binary", "legalDb"];
  let legacyIndex = 0;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    const named = /^(--data-dir|--legal-db|--binary)=(.+)$/u.exec(argument);
    if (named) {
      options[{ "--data-dir": "dataDir", "--legal-db": "legalDb", "--binary": "binary" }[named[1]]] = named[2];
      continue;
    }
    if (["--data-dir", "--legal-db", "--binary"].includes(argument)) {
      const value = argv[index + 1];
      assert(value && !value.startsWith("--"), `missing value for ${argument}`);
      options[{ "--data-dir": "dataDir", "--legal-db": "legalDb", "--binary": "binary" }[argument]] = value;
      index += 1;
      continue;
    }
    assert(!argument.startsWith("--"), `unknown option: ${argument}`);
    assert(legacyIndex < legacyNames.length, usage());
    options[legacyNames[legacyIndex]] = argument;
    legacyIndex += 1;
  }
  assert(options.dataDir, "--data-dir is required for the synthetic workspace");
  assert(options.legalDb, "--legal-db is required; this smoke must not use data/runtime");
  return options;
}

const options = optionsFrom(process.argv.slice(2));
const root = resolve(options.dataDir);
const binary = resolve(options.binary || "target/x86_64-pc-windows-msvc/release/lawyer-assistance-mcp.exe");
const legal = resolve(options.legalDb);
const unpack = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
  "Add-Type -AssemblyName System.Security; $b=[IO.File]::ReadAllBytes($env:LA_MCP_SMOKE_DESCRIPTOR); $e=[Text.Encoding]::ASCII.GetBytes('LawyerAssistance/privacy/local-protected-blob/v1'); [Console]::Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)))"],
  { env: { ...process.env, LA_MCP_SMOKE_DESCRIPTOR: join(root, "connection.dpapi") }, encoding: "utf8", windowsHide: true });
assert.equal(unpack.status, 0, "test descriptor must decrypt");
const { origin, bootstrap } = JSON.parse(unpack.stdout);
assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/);
let cookie, csrf, sequence = 0;
async function api(path, body, method = "POST") {
  const response = await fetch(`${origin}/api/v1${path}`, { method, headers: {
    "content-type": "application/json", ...(cookie ? { cookie, "x-csrf-token": csrf } : {})
  }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  const result = await response.json();
  assert.equal(response.status, 200, "synthetic setup API must succeed");
  if (path === "/session") { cookie = response.headers.get("set-cookie").split(";")[0]; csrf = result.csrf_token; }
  return result;
}
const initialize = { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "synthetic-mcp-smoke", version: "1" } };
const publicToolNames = [
  "system_status",
  "legal_search",
  "legal_get_article",
  "legal_get_versions",
  "legal_get_relations",
  "legal_search_cases",
  "legal_get_case",
];
const privateToolNames = [
  ...publicToolNames,
  "privacy_workspace.submit",
  "privacy_workspace.status",
  "privacy_workspace.read_result",
];
async function http(method, params, token) {
  const response = await fetch(`${origin}/mcp`, { method: "POST", headers: {
    "content-type": "application/json", accept: "application/json, text/event-stream",
    "mcp-protocol-version": "2025-11-25", ...(token ? { authorization: `Bearer ${token}` } : {})
  }, body: JSON.stringify({ jsonrpc: "2.0", id: ++sequence, method, params }), signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, "MCP HTTP must respond");
  assert.equal(response.headers.get("cache-control"), "no-store");
  return response.json();
}
function payload(response) {
  assert(!response.error, "MCP protocol call must succeed");
  assert(!response.result?.isError, "MCP business call must succeed");
  return response.result.structuredContent ?? JSON.parse(response.result.content[0].text);
}
function stdio(profile, token, daemon = origin) {
  const child = spawn(binary, ["--privacy-profile", profile, "--legal-db", legal, "--daemon-url", daemon, "stdio"], {
    env: { ...process.env, MCP_TOKEN: token ?? "" }, windowsHide: true, stdio: ["pipe", "pipe", "pipe"]
  });
  child.stderr.resume();
  const pending = new Map();
  const exited = new Promise((resolveExit) => child.on("exit", resolveExit));
  createInterface({ input: child.stdout }).on("line", line => {
    let value;
    try { value = JSON.parse(line); } catch { for (const p of pending.values()) p.reject(new Error("non-JSON stdout")); return; }
    if (value.id !== undefined && pending.has(value.id)) { pending.get(value.id).resolve(value); pending.delete(value.id); }
  });
  return {
    async request(method, params) {
      const id = ++sequence;
      const result = new Promise((resolveCall, reject) => pending.set(id, { resolve: resolveCall, reject }));
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      let timeout;
      try { return await Promise.race([result, new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("stdio timeout")), 30000); })]); }
      finally { clearTimeout(timeout); pending.delete(id); }
    },
    initialized() { child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`); },
    async close() { child.stdin.end(); await Promise.race([exited, delay(3000)]); if (child.exitCode === null) child.kill(); }
  };
}

await api("/session", { token: bootstrap });
const group = await api("/groups", { name: "Synthetic MCP transport smoke" });
const client = await api("/mcp/clients", { name: "Synthetic MCP transport", group_id: group.id });
const token = client.token;
await writeFile(join(client.client.inbox, "synthetic.txt"), "请在联系时使用号码 13800138000。", "utf8");
const publicClient = stdio("public_law_only");
const privateClient = stdio("privacy_workspace", token);
const offlineClient = stdio("privacy_workspace", token, "http://127.0.0.1:1");
try {
  for (const [transport, names] of [[publicClient, publicToolNames], [privateClient, privateToolNames]]) {
    const init = await transport.request("initialize", initialize);
    assert.equal(init.result.protocolVersion, "2025-11-25"); transport.initialized();
    const list = await transport.request("tools/list", {});
    assert.deepEqual(list.result.tools.map(tool => tool.name), names);
  }
  payload(await publicClient.request("tools/call", { name: "system_status", arguments: { schemaVersion: 1 } }));
  for (const [credential, names] of [[undefined, publicToolNames], [token, privateToolNames]]) {
    assert.equal((await http("initialize", initialize, credential)).result.protocolVersion, "2025-11-25");
    assert.deepEqual(
      (await http("tools/list", {}, credential)).result.tools.map(tool => tool.name),
      names,
    );
  }
  const args = { request_id: `synthetic_transport_${Date.now()}`, inbox_relative_paths: ["synthetic.txt"] };
  const submitted = payload(await privateClient.request("tools/call", { name: "privacy_workspace.submit", arguments: args }));
  const repeat = payload(await http("tools/call", { name: "privacy_workspace.submit", arguments: args }, token));
  assert.equal(repeat.task_id, submitted.task_id);
  let status;
  for (let i = 0; i < 100; i++) {
    status = payload(await http("tools/call", { name: "privacy_workspace.status", arguments: { task_id: submitted.task_id } }, token));
    if (status.status === "ready") break;
    await delay(100);
  }
  assert.equal(status.status, "ready");
  assert(!JSON.stringify(status).includes("synthetic.txt"));
  const resultId = status.materials[0].result_id;
  const read = payload(await privateClient.request("tools/call", { name: "privacy_workspace.read_result", arguments: { result_id: resultId } }));
  assert.equal(typeof read.text, "string"); assert(!read.text.includes("13800138000"));
  assert(!JSON.stringify(read).includes(client.client.inbox));
  const denied = await publicClient.request("tools/call", { name: "privacy_workspace.read_result", arguments: { result_id: resultId } });
  assert(denied.error || denied.result?.isError);
  await offlineClient.request("initialize", initialize); offlineClient.initialized();
  const offline = await offlineClient.request("tools/call", { name: "privacy_workspace.status", arguments: { task_id: submitted.task_id } });
  assert(offline.error || offline.result?.isError, "offline daemon must fail explicitly");
  await api(`/mcp/clients/${client.client.id}`, undefined, "DELETE");
  const revoked = await privateClient.request("tools/call", { name: "privacy_workspace.read_result", arguments: { result_id: resultId } });
  assert(revoked.error || revoked.result?.isError);
  process.stdout.write("MCP smoke PASS: public 7/private 10, HTTP + stdio, submit/replay/status/read, scope isolation, offline daemon, revoked token.\n");
} finally {
  await Promise.all([publicClient.close(), privateClient.close(), offlineClient.close()]);
}
