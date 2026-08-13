#!/usr/bin/env node

// Attaches only to the rebuilt, pinned v0.3.1 process that the Rust harness
// already owns. Fixture text remains in the WebView and is compared by SHA-256
// there; this process emits only fixed status codes and hashes. It never starts,
// closes, or terminates the application process.
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile, realpath } from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";

const REQUIRED_ARGUMENTS = new Set([
  "--exe",
  "--exe-sha256",
  "--app-root",
  "--app-identifier",
  "--pid",
  "--port",
  "--project-id",
  "--project-title-sha256",
  "--conversation-id",
  "--conversation-title-sha256",
  "--message-id",
  "--message-text-sha256",
  "--redaction-id",
  "--material-id",
  "--source-sha256",
  "--extraction-sha256",
  "--suggested-redacted-sha256",
  "--privacy-original-text-sha256",
  "--privacy-redacted-text-sha256",
]);

const OPTIONAL_ARGUMENTS = new Set(["--startup-timeout-ms"]);

const ALL_ARGUMENTS = new Set([...REQUIRED_ARGUMENTS, ...OPTIONAL_ARGUMENTS]);
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const DEFAULT_STARTUP_TIMEOUT_MS = 180_000;
const CDP_CALL_TIMEOUT_MS = 60_000;

class HarnessError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new HarnessError(code);
}

function parseArguments(argv) {
  if (argv.length === 0 || argv.length % 2 !== 0) {
    fail("ARGUMENT_SHAPE_INVALID");
  }

  const parsed = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!ALL_ARGUMENTS.has(name) || parsed.has(name) || value.length === 0) {
      fail("ARGUMENT_INVALID");
    }
    parsed.set(name, value);
  }
  for (const name of REQUIRED_ARGUMENTS) {
    if (!parsed.has(name)) {
      fail("ARGUMENT_REQUIRED");
    }
  }
  return parsed;
}

function requiredHash(argumentsMap, name) {
  const value = argumentsMap.get(name);
  if (!HASH_PATTERN.test(value)) {
    fail("EXPECTED_HASH_INVALID");
  }
  return value;
}

function requiredIdentifier(argumentsMap, name) {
  const value = argumentsMap.get(name);
  if (
    value.length < 1 ||
    value.length > 128 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail("EXPECTED_IDENTIFIER_INVALID");
  }
  return value;
}

function boundedInteger(argumentsMap, name, fallback, minimum, maximum) {
  const raw = argumentsMap.get(name);
  if (raw === undefined) {
    return fallback;
  }
  if (!/^[0-9]+$/u.test(raw)) {
    fail("INTEGER_ARGUMENT_INVALID");
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail("INTEGER_ARGUMENT_INVALID");
  }
  return value;
}

async function sha256File(filePath) {
  const hash = createHash("sha256");
  await new Promise((resolvePromise, rejectPromise) => {
    const input = createReadStream(filePath);
    input.on("data", (chunk) => hash.update(chunk));
    input.once("error", () => rejectPromise(new HarnessError("EXE_HASH_FAILED")));
    input.once("end", resolvePromise);
  });
  return hash.digest("hex");
}

function sha256Text(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function validateExecutable(candidate, expectedSha256) {
  if (!isAbsolute(candidate) || basename(candidate).toLowerCase() !== "lawyer-assistance.exe") {
    fail("EXE_PATH_INVALID");
  }
  const absolute = resolve(candidate);
  let metadata;
  let canonical;
  try {
    metadata = await lstat(absolute);
    canonical = await realpath(absolute);
  } catch {
    fail("EXE_PATH_INVALID");
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    resolve(canonical).toLowerCase() !== absolute.toLowerCase()
  ) {
    fail("EXE_PATH_INVALID");
  }
  if ((await sha256File(absolute)) !== expectedSha256) {
    fail("EXE_HASH_MISMATCH");
  }
  return absolute;
}

async function validateApplicationRoot(candidate) {
  if (
    !isAbsolute(candidate) ||
    !basename(candidate).startsWith("com.shilittle.lawyer-assistance.r3-")
  ) {
    fail("APP_ROOT_INVALID");
  }
  const absolute = resolve(candidate);
  let metadata;
  let canonical;
  try {
    metadata = await lstat(absolute);
    canonical = await realpath(absolute);
  } catch {
    fail("APP_ROOT_INVALID");
  }
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    resolve(canonical).toLowerCase() !== absolute.toLowerCase()
  ) {
    fail("APP_ROOT_INVALID");
  }
  const mcpConfig = join(absolute, "mcp", "server-config.json");
  return { absolute, mcpConfig };
}

async function assertSafeDefaultMcpConfig(configPath) {
  let parsed;
  try {
    const metadata = await lstat(configPath);
    const canonical = await realpath(configPath);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      resolve(canonical).toLowerCase() !== resolve(configPath).toLowerCase()
    ) {
      fail("MCP_DEFAULT_CONFIG_INVALID");
    }
    const bytes = await readFile(configPath);
    if (bytes.length < 2 || bytes.length > 128 * 1024) {
      fail("MCP_DEFAULT_CONFIG_INVALID");
    }
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    if (error instanceof HarnessError) throw error;
    fail("MCP_DEFAULT_CONFIG_INVALID");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    parsed.schemaVersion !== 1 ||
    parsed.autoStart !== false
  ) {
    fail("MCP_DEFAULT_CONFIG_INVALID");
  }
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
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function validatedDebuggerUrl(value, expectedPort) {
  if (typeof value !== "string") {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    parsed.protocol !== "ws:" ||
    !["127.0.0.1", "localhost"].includes(parsed.hostname) ||
    Number(parsed.port) !== expectedPort ||
    !parsed.pathname.startsWith("/devtools/")
  ) {
    return null;
  }
  return parsed.toString();
}

function isTauriPageTarget(target) {
  if (target === null || typeof target !== "object" || target.type !== "page") {
    return false;
  }
  const url = typeof target.url === "string" ? target.url.toLowerCase() : "";
  const title = typeof target.title === "string" ? target.title : "";
  return (
    url.startsWith("http://tauri.localhost") ||
    url.startsWith("https://tauri.localhost") ||
    url.startsWith("tauri://localhost") ||
    title.startsWith("Lawyer Assistance")
  );
}

async function waitForPageTarget(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await fetchJson(`http://127.0.0.1:${port}/json/list`, 1_000);
    if (Array.isArray(targets)) {
      const matching = targets.filter(isTauriPageTarget);
      if (matching.length > 1) {
        fail("CDP_PAGE_TARGET_AMBIGUOUS");
      }
      if (matching.length === 1) {
        const debuggerUrl = validatedDebuggerUrl(
          matching[0].webSocketDebuggerUrl,
          port,
        );
        if (debuggerUrl !== null) {
          return debuggerUrl;
        }
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  fail("CDP_PAGE_TARGET_TIMEOUT");
}

async function messageText(data) {
  if (typeof data === "string") {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data).toString("utf8");
  }
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  }
  if (data && typeof data.text === "function") {
    return await data.text();
  }
  fail("CDP_MESSAGE_INVALID");
}

class CdpClient {
  constructor(url) {
    this.url = url;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
    this.eventHandlers = new Map();
    this.messageTail = Promise.resolve();
    this.messageFailure = null;
    this.connectionFailure = null;
    this.terminal = null;
    this.terminalRequested = false;
  }

  async open() {
    if (typeof globalThis.WebSocket !== "function") {
      fail("NODE_WEBSOCKET_UNAVAILABLE");
    }
    const socket = new WebSocket(this.url);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    await new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(
        () => rejectPromise(new HarnessError("CDP_CONNECT_TIMEOUT")),
        CDP_CALL_TIMEOUT_MS,
      );
      socket.addEventListener(
        "open",
        () => {
          clearTimeout(timeout);
          resolvePromise();
        },
        { once: true },
      );
      socket.addEventListener(
        "error",
        () => {
          clearTimeout(timeout);
          rejectPromise(new HarnessError("CDP_CONNECT_FAILED"));
        },
        { once: true },
      );
    });
    socket.addEventListener("message", (event) => {
      this.messageTail = this.messageTail
        .then(() => this.handleMessage(event.data))
        .catch((error) => {
          this.messageFailure =
            error instanceof HarnessError
              ? error
              : new HarnessError("CDP_MESSAGE_INVALID");
          this.rejectPending(this.messageFailure.code);
          if (socket.readyState < WebSocket.CLOSING) {
            socket.close();
          }
        });
    });
    socket.addEventListener("close", () => {
      void this.finishTerminal(
        this.connectionFailure === null
          ? "CDP_CONNECTION_CLOSED"
          : this.connectionFailure.code,
      );
    });
    socket.addEventListener("error", () => {
      this.connectionFailure = new HarnessError("CDP_CONNECTION_FAILED");
      this.rejectPending(this.connectionFailure.code);
    });
  }

  async handleMessage(data) {
    const raw = await messageText(data);
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      fail("CDP_MESSAGE_INVALID");
    }
    if (message === null || typeof message !== "object") {
      fail("CDP_MESSAGE_INVALID");
    }
    if (Number.isInteger(message.id)) {
      const pending = this.pending.get(message.id);
      if (pending === undefined) {
        return;
      }
      this.pending.delete(message.id);
      clearTimeout(pending.timeout);
      if (message.error !== undefined) {
        pending.reject(new HarnessError("CDP_PROTOCOL_ERROR"));
      } else {
        pending.resolve(message.result);
      }
      return;
    }
    if (typeof message.method !== "string") {
      fail("CDP_MESSAGE_INVALID");
    }
    const handlers = this.eventHandlers.get(message.method) ?? [];
    for (const handler of handlers) {
      await handler(message.params);
    }
  }

  async finishTerminal(code) {
    if (this.terminalRequested) {
      return;
    }
    this.terminalRequested = true;
    // WebSocket `close` is ordered after every `message` event. Waiting for the
    // serialized tail makes every already-delivered binding authoritative
    // before a child exit can be adjudicated.
    await this.messageTail;
    this.rejectPending(code);
    this.terminal = { code };
  }

  addEventHandler(method, handler) {
    const handlers = this.eventHandlers.get(method) ?? [];
    handlers.push(handler);
    this.eventHandlers.set(method, handlers);
  }

  rejectPending(code) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new HarnessError(code));
    }
    this.pending.clear();
  }

  call(method, params = {}, timeoutMs = CDP_CALL_TIMEOUT_MS) {
    const socket = this.socket;
    if (socket === null || socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new HarnessError("CDP_CONNECTION_NOT_OPEN"));
    }
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        rejectPromise(new HarnessError("CDP_CALL_TIMEOUT"));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: resolvePromise,
        reject: rejectPromise,
        timeout,
      });
      try {
        socket.send(JSON.stringify({ id, method, params }));
      } catch {
        clearTimeout(timeout);
        this.pending.delete(id);
        rejectPromise(new HarnessError("CDP_SEND_FAILED"));
      }
    });
  }

  close() {
    if (this.socket !== null && this.socket.readyState < WebSocket.CLOSING) {
      this.socket.close();
    }
    this.rejectPending("CDP_CLIENT_CLOSED");
  }

  fatalError() {
    return this.messageFailure;
  }

  async drainMessages() {
    await this.messageTail;
  }
}

function readEvaluationValue(result) {
  if (
    result === null ||
    typeof result !== "object" ||
    result.exceptionDetails !== undefined ||
    result.result === null ||
    typeof result.result !== "object" ||
    result.result.type !== "object" ||
    result.result.value === null ||
    typeof result.result.value !== "object"
  ) {
    fail("CDP_EVALUATION_FAILED");
  }
  return result.result.value;
}

function assertionExpression(expected) {
  const encoded = JSON.stringify(expected);
  return `
(async () => {
  "use strict";
  const expected = ${encoded};
  const reject = (code) => { throw new Error("R3_ASSERT_" + code); };
  const sha256 = async (value) => {
    if (typeof value !== "string") reject("NON_STRING_HASH_INPUT");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  };
  const internals = globalThis.__TAURI_INTERNALS__;
  if (!internals || typeof internals !== "object") reject("TAURI_INTERNALS_MISSING");
  const invokeDescriptor = Object.getOwnPropertyDescriptor(internals, "invoke");
  if (
    !invokeDescriptor ||
    typeof invokeDescriptor.value !== "function" ||
    invokeDescriptor.writable !== false ||
    invokeDescriptor.configurable !== false
  ) reject("TAURI_INVOKE_BOUNDARY_INVALID");
  if (
    !internals.metadata ||
    !internals.metadata.currentWindow ||
    internals.metadata.currentWindow.label !== "main" ||
    !internals.metadata.currentWebview ||
    internals.metadata.currentWebview.label !== "main"
  ) reject("TAURI_MAIN_WINDOW_INVALID");
  const invoke = invokeDescriptor.value;

  const appVersion = await invoke("plugin:app|version");
  const appIdentifier = await invoke("plugin:app|identifier");
  if (
    appVersion !== expected.appVersion ||
    appIdentifier !== expected.appIdentifier
  ) reject("TAURI_APP_IDENTITY_INVALID");

  const providers = await invoke("list_provider_profiles");
  if (!providers || !Array.isArray(providers.profiles) || providers.profiles.length !== 0) {
    reject("PROVIDER_FIXTURE_NOT_EMPTY");
  }

  const projects = await invoke("list_case_projects");
  if (!projects || !Array.isArray(projects.projects) || projects.projects.length !== 1) {
    reject("PROJECT_LIST_INVALID");
  }
  const project = projects.projects[0];
  if (
    project.projectId !== expected.projectId ||
    project.status !== "active" ||
    await sha256(project.title) !== expected.projectTitleSha256
  ) reject("PROJECT_INVALID");

  const workspaceResponse = await invoke("get_case_workspace", {
    request: { projectId: expected.projectId },
  });
  const workspace = workspaceResponse && workspaceResponse.workspace;
  if (
    !workspace ||
    !workspace.project ||
    workspace.project.projectId !== expected.projectId ||
    await sha256(workspace.project.title) !== expected.projectTitleSha256
  ) reject("WORKSPACE_INVALID");

  const conversations = await invoke("list_assistant_conversations", {
    request: { includeArchived: true, limit: 100 },
  });
  if (
    !conversations ||
    !Array.isArray(conversations.conversations) ||
    conversations.conversations.length !== 1
  ) reject("CONVERSATION_LIST_INVALID");
  const conversation = conversations.conversations[0];
  if (
    conversation.conversationId !== expected.conversationId ||
    conversation.projectId !== expected.projectId ||
    conversation.status !== "open" ||
    await sha256(conversation.title) !== expected.conversationTitleSha256
  ) reject("CONVERSATION_INVALID");

  const detailResponse = await invoke("get_assistant_conversation", {
    request: { conversationId: expected.conversationId },
  });
  const detail = detailResponse && detailResponse.detail;
  if (
    !detail ||
    !detail.conversation ||
    detail.conversation.conversationId !== expected.conversationId ||
    !Array.isArray(detail.messages) ||
    detail.messages.length !== 1
  ) reject("CONVERSATION_DETAIL_INVALID");
  const message = detail.messages[0];
  if (
    message.messageId !== expected.messageId ||
    message.conversationId !== expected.conversationId ||
    message.role !== "user" ||
    message.kind !== "text" ||
    await sha256(message.textSummary) !== expected.messageTextSha256
  ) reject("MESSAGE_INVALID");

  const review = await invoke("load_latest_privacy_review");
  if (
    !review ||
    review.redactionId !== expected.redactionId ||
    review.materialId !== expected.materialId ||
    review.sourceSha256 !== expected.sourceSha256 ||
    review.extractionSha256 !== expected.extractionSha256 ||
    review.suggestedRedactedContentSha256 !== expected.suggestedRedactedSha256 ||
    review.reviewState !== "review_required" ||
    review.pageCount !== 1 ||
    !Array.isArray(review.pages) ||
    review.pages.length !== 1
  ) reject("PRIVACY_REVIEW_INVALID");
  const page = review.pages[0];
  if (
    page.pageNumber !== 1 ||
    await sha256(page.originalText) !== expected.privacyOriginalTextSha256 ||
    await sha256(page.redactedText) !== expected.privacyRedactedTextSha256
  ) reject("PRIVACY_PAGE_INVALID");

  const assertionSha256 = await sha256([
    expected.projectId,
    expected.projectTitleSha256,
    expected.conversationId,
    expected.conversationTitleSha256,
    expected.messageId,
    expected.messageTextSha256,
    expected.redactionId,
    expected.materialId,
    expected.sourceSha256,
    expected.extractionSha256,
    expected.suggestedRedactedSha256,
    expected.privacyOriginalTextSha256,
    expected.privacyRedactedTextSha256,
    expected.appVersion,
    expected.appIdentifier,
  ].join("\\0"));
  return {
    schemaVersion: "lawyer-assistance-v031-real-binary-cdp-attestation-v1",
    projectCount: projects.projects.length,
    conversationCount: conversations.conversations.length,
    messageCount: detail.messages.length,
    privacyPageCount: review.pages.length,
    providerCount: providers.profiles.length,
    appVersion,
    appIdentifier,
    assertionSha256,
  };
})()
`;
}

function expectedAssertionSha256(expected) {
  return sha256Text(
    [
      expected.projectId,
      expected.projectTitleSha256,
      expected.conversationId,
      expected.conversationTitleSha256,
      expected.messageId,
      expected.messageTextSha256,
      expected.redactionId,
      expected.materialId,
      expected.sourceSha256,
      expected.extractionSha256,
      expected.suggestedRedactedSha256,
      expected.privacyOriginalTextSha256,
      expected.privacyRedactedTextSha256,
      expected.appVersion,
      expected.appIdentifier,
    ].join("\0"),
  );
}

function validateEmbeddedExpressionSyntax() {
  const zeroHash = "0".repeat(64);
  const dummy = {
    appVersion: "0.3.1",
    appIdentifier: "com.shilittle.lawyer-assistance.r3-test",
    projectId: "r3-project",
    projectTitleSha256: zeroHash,
    conversationId: "r3-conversation",
    conversationTitleSha256: zeroHash,
    messageId: "r3-message",
    messageTextSha256: zeroHash,
    redactionId: "r3-redaction",
    materialId: "r3-material",
    sourceSha256: zeroHash,
    extractionSha256: zeroHash,
    suggestedRedactedSha256: zeroHash,
    privacyOriginalTextSha256: zeroHash,
    privacyRedactedTextSha256: zeroHash,
  };
  try {
    new Function(`"use strict"; return (${assertionExpression(dummy)});`);
  } catch {
    fail("EMBEDDED_EXPRESSION_SYNTAX_INVALID");
  }
}

async function main() {
  validateEmbeddedExpressionSyntax();
  const args = parseArguments(process.argv.slice(2));
  const expectedExeSha256 = requiredHash(args, "--exe-sha256");
  const expectedPid = boundedInteger(args, "--pid", 0, 1, 4_294_967_295);
  const port = boundedInteger(args, "--port", 0, 1024, 65_535);
  const startupTimeoutMs = boundedInteger(
    args,
    "--startup-timeout-ms",
    DEFAULT_STARTUP_TIMEOUT_MS,
    5_000,
    300_000,
  );
  const expected = {
    appVersion: "0.3.1",
    appIdentifier: requiredIdentifier(args, "--app-identifier"),
    projectId: requiredIdentifier(args, "--project-id"),
    projectTitleSha256: requiredHash(args, "--project-title-sha256"),
    conversationId: requiredIdentifier(args, "--conversation-id"),
    conversationTitleSha256: requiredHash(args, "--conversation-title-sha256"),
    messageId: requiredIdentifier(args, "--message-id"),
    messageTextSha256: requiredHash(args, "--message-text-sha256"),
    redactionId: requiredIdentifier(args, "--redaction-id"),
    materialId: requiredIdentifier(args, "--material-id"),
    sourceSha256: requiredHash(args, "--source-sha256"),
    extractionSha256: requiredHash(args, "--extraction-sha256"),
    suggestedRedactedSha256: requiredHash(args, "--suggested-redacted-sha256"),
    privacyOriginalTextSha256: requiredHash(args, "--privacy-original-text-sha256"),
    privacyRedactedTextSha256: requiredHash(args, "--privacy-redacted-text-sha256"),
  };
  const executable = await validateExecutable(args.get("--exe"), expectedExeSha256);
  const applicationRoot = await validateApplicationRoot(args.get("--app-root"));

  let cdp = null;
  try {
    try {
      process.kill(expectedPid, 0);
    } catch {
      fail("OLD_BINARY_PROCESS_NOT_LIVE");
    }
    const debuggerUrl = await waitForPageTarget(port, startupTimeoutMs);
    cdp = new CdpClient(debuggerUrl);
    await cdp.open();
    await cdp.call("Runtime.enable");
    const evaluated = readEvaluationValue(
      await cdp.call("Runtime.evaluate", {
        expression: assertionExpression(expected),
        awaitPromise: true,
        returnByValue: true,
        userGesture: true,
      }),
    );
    if (
      evaluated.schemaVersion !== "lawyer-assistance-v031-real-binary-cdp-attestation-v1" ||
      evaluated.projectCount !== 1 ||
      evaluated.conversationCount !== 1 ||
      evaluated.messageCount !== 1 ||
      evaluated.privacyPageCount !== 1 ||
      evaluated.providerCount !== 0 ||
      evaluated.appVersion !== expected.appVersion ||
      evaluated.appIdentifier !== expected.appIdentifier ||
      evaluated.assertionSha256 !== expectedAssertionSha256(expected)
    ) {
      fail("CDP_ATTESTATION_INVALID");
    }
    await assertSafeDefaultMcpConfig(applicationRoot.mcpConfig);
    if ((await sha256File(executable)) !== expectedExeSha256) {
      fail("EXE_CHANGED_DURING_ACCEPTANCE");
    }
    try {
      process.kill(expectedPid, 0);
    } catch {
      fail("OLD_BINARY_PROCESS_NOT_LIVE_AFTER_READ");
    }
    const attestation = {
      schemaVersion: "lawyer-assistance-v031-real-binary-cdp-read-result-v1",
      assertionSha256: evaluated.assertionSha256,
      executableSha256: expectedExeSha256,
      processId: expectedPid,
      appVersion: evaluated.appVersion,
      appIdentifier: evaluated.appIdentifier,
    };
    const attestationSha256 = sha256Text(JSON.stringify(attestation));
    cdp.close();
    cdp = null;
    process.stdout.write("R3_V031_REAL_BINARY_CDP=PASS\n");
    process.stdout.write(`R3_V031_REAL_BINARY_ASSERTION_SHA256=${attestation.assertionSha256}\n`);
    process.stdout.write(`R3_V031_REAL_BINARY_ATTESTATION_SHA256=${attestationSha256}\n`);
  } finally {
    if (cdp !== null) {
      cdp.close();
    }
  }
}

main().catch((error) => {
  const code = error instanceof HarnessError ? error.code : "UNEXPECTED_FAILURE";
  process.stderr.write("R3_V031_REAL_BINARY_CDP=FAIL\n");
  process.stderr.write(`R3_V031_REAL_BINARY_ERROR=${code}\n`);
  process.exitCode = 1;
});
