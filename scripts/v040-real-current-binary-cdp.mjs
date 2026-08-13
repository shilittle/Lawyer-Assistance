import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import path from "node:path";

class HarnessError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new HarnessError(code);
}

function parseArguments(values) {
  if (values.length % 2 !== 0) fail("ARGUMENTS_INVALID");
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name.startsWith("--") || !value || result.has(name)) fail("ARGUMENTS_INVALID");
    result.set(name, value);
  }
  return result;
}

function required(args, name) {
  const value = args.get(name);
  if (!value || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail("ARGUMENT_INVALID");
  }
  return value;
}

function requiredHash(args, name) {
  const value = required(args, name);
  if (!/^[0-9a-f]{64}$/u.test(value)) fail("HASH_INVALID");
  return value;
}

function boundedInteger(args, name, minimum, maximum) {
  const value = Number(required(args, name));
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail("INTEGER_INVALID");
  }
  return value;
}

async function ordinaryCanonicalPath(value, directory) {
  if (!path.isAbsolute(value)) fail("PATH_NOT_ABSOLUTE");
  const canonical = await realpath(value).catch(() => fail("PATH_UNAVAILABLE"));
  if (path.resolve(value).toLowerCase() !== canonical.toLowerCase()) fail("PATH_NOT_CANONICAL");
  const metadata = await stat(canonical).catch(() => fail("PATH_UNAVAILABLE"));
  if ((directory && !metadata.isDirectory()) || (!directory && !metadata.isFile())) {
    fail("PATH_KIND_INVALID");
  }
  return canonical;
}

async function sha256File(value) {
  const { readFile } = await import("node:fs/promises");
  return createHash("sha256").update(await readFile(value)).digest("hex");
}

function sha256Text(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForPageTarget(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await fetchJson(`http://127.0.0.1:${port}/json/list`, 1_000);
    if (Array.isArray(targets)) {
      const matching = targets.filter((target) => {
        const title = typeof target?.title === "string" ? target.title : "";
        const url = typeof target?.url === "string" ? target.url.toLowerCase() : "";
        return target?.type === "page" &&
          (title.startsWith("Lawyer Assistance") || url.includes("tauri.localhost"));
      });
      if (matching.length > 1) fail("CDP_PAGE_TARGET_AMBIGUOUS");
      if (matching.length === 1) {
        const value = matching[0].webSocketDebuggerUrl;
        try {
          const parsed = new URL(value);
          if (
            parsed.protocol === "ws:" &&
            ["127.0.0.1", "localhost"].includes(parsed.hostname) &&
            Number(parsed.port) === port &&
            parsed.pathname.startsWith("/devtools/")
          ) return parsed.toString();
        } catch {
          // Continue until the bounded deadline.
        }
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  fail("CDP_PAGE_TARGET_TIMEOUT");
}

class CdpClient {
  constructor(url) {
    this.url = url;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async open() {
    if (typeof globalThis.WebSocket !== "function") fail("NODE_WEBSOCKET_UNAVAILABLE");
    this.socket = new WebSocket(this.url);
    await new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => rejectPromise(new HarnessError("CDP_CONNECT_TIMEOUT")), 10_000);
      this.socket.addEventListener("open", () => {
        clearTimeout(timeout);
        resolvePromise();
      }, { once: true });
      this.socket.addEventListener("error", () => {
        clearTimeout(timeout);
        rejectPromise(new HarnessError("CDP_CONNECT_FAILED"));
      }, { once: true });
    });
    this.socket.addEventListener("message", async (event) => {
      let raw;
      if (typeof event.data === "string") raw = event.data;
      else if (event.data instanceof ArrayBuffer) raw = Buffer.from(event.data).toString("utf8");
      else if (ArrayBuffer.isView(event.data)) raw = Buffer.from(event.data.buffer, event.data.byteOffset, event.data.byteLength).toString("utf8");
      else if (event.data && typeof event.data.text === "function") raw = await event.data.text();
      else {
        this.rejectAll("CDP_MESSAGE_INVALID");
        return;
      }
      let message;
      try {
        message = JSON.parse(raw);
      } catch {
        this.rejectAll("CDP_MESSAGE_INVALID");
        return;
      }
      if (!Number.isInteger(message?.id)) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timeout);
      if (message.error) pending.reject(new HarnessError("CDP_PROTOCOL_ERROR"));
      else pending.resolve(message.result);
    });
    this.socket.addEventListener("close", () => this.rejectAll("CDP_CONNECTION_CLOSED"));
  }

  call(method, params = {}) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new HarnessError("CDP_CONNECTION_NOT_OPEN"));
    }
    const id = this.nextId++;
    return new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        rejectPromise(new HarnessError("CDP_CALL_TIMEOUT"));
      }, 30_000);
      this.pending.set(id, { resolve: resolvePromise, reject: rejectPromise, timeout });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  rejectAll(code) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new HarnessError(code));
    }
    this.pending.clear();
  }

  close() {
    if (this.socket && this.socket.readyState < WebSocket.CLOSING) this.socket.close();
    this.rejectAll("CDP_CLIENT_CLOSED");
  }
}

function assertionExpression(expected) {
  return `
(async () => {
  "use strict";
  const expected = ${JSON.stringify(expected)};
  const reject = (code) => { throw new Error("R3_V040_ASSERT_" + code); };
  const sha256 = async (value) => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  };
  const internals = globalThis.__TAURI_INTERNALS__;
  const descriptor = Object.getOwnPropertyDescriptor(internals || {}, "invoke");
  if (!descriptor || typeof descriptor.value !== "function" || descriptor.writable !== false || descriptor.configurable !== false) {
    reject("INVOKE_BOUNDARY_INVALID");
  }
  if (internals.metadata?.currentWindow?.label !== "main" || internals.metadata?.currentWebview?.label !== "main") {
    reject("MAIN_WINDOW_INVALID");
  }
  const invoke = descriptor.value;
  const appVersion = await invoke("plugin:app|version");
  const appIdentifier = await invoke("plugin:app|identifier");
  if (appVersion !== expected.appVersion || appIdentifier !== expected.appIdentifier) reject("APP_IDENTITY_INVALID");

  const health = await invoke("health_check");
  if (health?.status !== "ok" || health?.appName !== "Lawyer Assistance" || health?.architecture !== "x86_64") {
    reject("HEALTH_INVALID");
  }
  const projects = await invoke("list_case_projects");
  if (!Array.isArray(projects?.projects) || projects.projects.length !== 1) reject("PROJECT_LIST_INVALID");
  const project = projects.projects[0];
  if (project.projectId !== expected.projectId || project.status !== "active" || await sha256(project.title) !== expected.projectTitleSha256) {
    reject("PROJECT_INVALID");
  }
  const workspace = (await invoke("get_case_workspace", { request: { projectId: expected.projectId } }))?.workspace;
  if (!workspace?.project || workspace.project.projectId !== expected.projectId || await sha256(workspace.project.title) !== expected.projectTitleSha256) {
    reject("WORKSPACE_INVALID");
  }
  const conversations = await invoke("list_assistant_conversations", { request: { includeArchived: true, limit: 100 } });
  if (!Array.isArray(conversations?.conversations) || conversations.conversations.length !== 1) reject("CONVERSATION_LIST_INVALID");
  const conversation = conversations.conversations[0];
  if (conversation.conversationId !== expected.conversationId || conversation.projectId !== expected.projectId || await sha256(conversation.title) !== expected.conversationTitleSha256) {
    reject("CONVERSATION_INVALID");
  }
  const detail = (await invoke("get_assistant_conversation", { request: { conversationId: expected.conversationId } }))?.detail;
  if (!detail?.conversation || !Array.isArray(detail.messages) || detail.messages.length !== 1) reject("DETAIL_INVALID");
  const message = detail.messages[0];
  if (message.messageId !== expected.messageId || message.role !== "user" || message.kind !== "text" || await sha256(message.textSummary) !== expected.messageTextSha256) {
    reject("MESSAGE_INVALID");
  }
  const unassigned = await invoke("list_unassigned_case_materials", { request: { projectId: expected.projectId } });
  if (!Array.isArray(unassigned) || unassigned.length !== 1) reject("UNASSIGNED_LIST_INVALID");
  const material = unassigned[0];
  if (
    material.materialId !== expected.materialId ||
    material.sourceKind !== "local_review" ||
    material.migrationStatus !== "unassigned" ||
    material.state !== "review_required" ||
    material.generationCount !== 1 ||
    material.assignable !== true ||
    material.displayName !== "未归属本地材料" ||
    material.historicalIdentity !== "missing" ||
    !Number.isSafeInteger(material.rowVersion) || material.rowVersion < 1 ||
    material.deletedAt !== null
  ) reject("UNASSIGNED_MATERIAL_INVALID");

  const assertionSha256 = await sha256([
    appVersion, appIdentifier, expected.projectId, expected.projectTitleSha256,
    expected.conversationId, expected.conversationTitleSha256, expected.messageId,
    expected.messageTextSha256, expected.materialId, material.rowVersion,
  ].join("\\0"));
  return {
    schemaVersion: "lawyer-assistance-v040-real-current-binary-cdp-attestation-v1",
    appVersion,
    appIdentifier,
    projectCount: projects.projects.length,
    conversationCount: conversations.conversations.length,
    messageCount: detail.messages.length,
    unassignedMaterialCount: unassigned.length,
    assertionSha256,
  };
})()`;
}

function readEvaluation(result) {
  const value = result?.result?.value;
  if (result?.exceptionDetails || result?.result?.type !== "object" || !value) fail("CDP_EVALUATION_FAILED");
  return value;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const expectedExeSha256 = requiredHash(args, "--exe-sha256");
  const executable = await ordinaryCanonicalPath(required(args, "--exe"), false);
  const appRoot = await ordinaryCanonicalPath(required(args, "--app-root"), true);
  const expectedPid = boundedInteger(args, "--pid", 1, 4_294_967_295);
  const port = boundedInteger(args, "--port", 1024, 65_535);
  const expected = {
    appVersion: required(args, "--app-version"),
    appIdentifier: required(args, "--app-identifier"),
    projectId: required(args, "--project-id"),
    projectTitleSha256: requiredHash(args, "--project-title-sha256"),
    conversationId: required(args, "--conversation-id"),
    conversationTitleSha256: requiredHash(args, "--conversation-title-sha256"),
    messageId: required(args, "--message-id"),
    messageTextSha256: requiredHash(args, "--message-text-sha256"),
    materialId: required(args, "--material-id"),
  };
  if ((await sha256File(executable)) !== expectedExeSha256) fail("EXE_HASH_MISMATCH");
  try { process.kill(expectedPid, 0); } catch { fail("CURRENT_BINARY_PROCESS_NOT_LIVE"); }

  let cdp;
  try {
    cdp = new CdpClient(await waitForPageTarget(port, 120_000));
    await cdp.open();
    await cdp.call("Runtime.enable");
    const value = readEvaluation(await cdp.call("Runtime.evaluate", {
      expression: assertionExpression(expected),
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    }));
    if (
      value.schemaVersion !== "lawyer-assistance-v040-real-current-binary-cdp-attestation-v1" ||
      value.appVersion !== expected.appVersion || value.appIdentifier !== expected.appIdentifier ||
      value.projectCount !== 1 || value.conversationCount !== 1 || value.messageCount !== 1 ||
      value.unassignedMaterialCount !== 1 || !/^[0-9a-f]{64}$/u.test(value.assertionSha256)
    ) fail("CDP_ATTESTATION_INVALID");
    if ((await realpath(appRoot)).toLowerCase() !== appRoot.toLowerCase()) fail("APP_ROOT_CHANGED");
    if ((await sha256File(executable)) !== expectedExeSha256) fail("EXE_CHANGED_DURING_ACCEPTANCE");
    try { process.kill(expectedPid, 0); } catch { fail("CURRENT_BINARY_PROCESS_NOT_LIVE_AFTER_READ"); }
    process.stdout.write("R3_V040_REAL_CURRENT_BINARY_CDP=PASS\n");
    process.stdout.write(`R3_V040_REAL_CURRENT_BINARY_ASSERTION_SHA256=${value.assertionSha256}\n`);
    process.stdout.write(`R3_V040_REAL_CURRENT_BINARY_ATTESTATION_SHA256=${sha256Text(JSON.stringify(value))}\n`);
  } finally {
    cdp?.close();
  }
}

main().catch((error) => {
  const code = error instanceof HarnessError ? error.code : "UNEXPECTED_FAILURE";
  process.stderr.write("R3_V040_REAL_CURRENT_BINARY_CDP=FAIL\n");
  process.stderr.write(`R3_V040_REAL_CURRENT_BINARY_ERROR=${code}\n`);
  process.exitCode = 1;
});
