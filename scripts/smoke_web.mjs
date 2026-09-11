#!/usr/bin/env node

/**
 * End-to-end smoke for a running local Lawyer Assistance Web service.
 *
 * The script is deliberately dependency-free for its HTTP path.  A browser
 * pass is attempted only when Playwright is installed.  It never writes the
 * workspace or prints response bodies, tokens, source text, or exported text.
 */

import { spawnSync } from "node:child_process";
import process from "node:process";
import path from "node:path";

const HOST_ORIGIN = /^https?:\/\/127\.0\.0\.1(?::\d+)?$/u;
const TERMINAL_TASK_STATES = new Set(["ready", "needs_review", "awaiting_consent", "partial", "failed", "cancelled"]);
const EXPECTED_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const REDACTION_SOURCE = "请在联系时使用号码 13800138000。";
const REPLACEMENT_SOURCE = "请改用号码 13900139000。";
const BROWSER_SOURCE = "请在浏览器 smoke 中使用号码 13700137000。";

function fail(message) {
  throw new Error(message);
}

function check(condition, message) {
  if (!condition) fail(message);
}

function parseArgs(argv) {
  const options = {
    baseUrl: "",
    token: "",
    dataDir: "",
    noBrowser: false,
    requireBrowser: false,
    headed: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      options.help = true;
      continue;
    }
    if (argument === "--no-browser") {
      options.noBrowser = true;
      continue;
    }
    if (argument === "--require-browser") {
      options.requireBrowser = true;
      continue;
    }
    if (argument === "--headed") {
      options.headed = true;
      continue;
    }
    const match = /^(--base-url|--token|--data-dir)=(.*)$/u.exec(argument);
    if (match) {
      options[{ "--base-url": "baseUrl", "--token": "token", "--data-dir": "dataDir" }[match[1]]] = match[2];
      continue;
    }
    if (["--base-url", "--token", "--data-dir"].includes(argument)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) fail(`missing value for ${argument}`);
      options[{ "--base-url": "baseUrl", "--token": "token", "--data-dir": "dataDir" }[argument]] = value;
      index += 1;
      continue;
    }
    fail(`unknown option ${argument}`);
  }
  return options;
}

function printUsage() {
  process.stdout.write(
    "用法：node scripts/smoke_web.mjs --base-url http://127.0.0.1:8877 --token <token> [--no-browser]\n" +
    "或：node scripts/smoke_web.mjs --data-dir <全新测试工作区> [--no-browser]\n" +
    "  --require-browser  Playwright 不可用时令 smoke 失败\n" +
    "  --headed           以可见浏览器运行 UI smoke\n",
  );
}

function decryptConnectionDescriptor(dataDir) {
  check(process.platform === "win32", "--data-dir DPAPI 解密仅支持 Windows");
  check(dataDir, "缺少 --data-dir");
  const descriptor = path.resolve(dataDir, "connection.dpapi");
  const powershell = ["powershell.exe", "pwsh.exe"].find((command) => {
    const result = spawnSync(command, ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"], {
      stdio: "ignore",
      windowsHide: true,
    });
    return result.status === 0;
  });
  check(powershell, "找不到 PowerShell，无法读取本机连接描述符");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -AssemblyName System.Security",
    "$path = $env:LAWYER_ASSISTANCE_SMOKE_DPAPI",
    "$bytes = [IO.File]::ReadAllBytes($path)",
    "$entropy = [Text.Encoding]::ASCII.GetBytes('LawyerAssistance/privacy/local-protected-blob/v1')",
    "$plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))",
  ].join("; ");
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    env: { ...process.env, LAWYER_ASSISTANCE_SMOKE_DPAPI: descriptor },
    encoding: "utf8",
    windowsHide: true,
  });
  check(result.status === 0 && result.stdout, "无法解密本机连接描述符");
  let connection;
  try {
    connection = JSON.parse(result.stdout);
  } catch {
    fail("本机连接描述符格式无效");
  }
  check(typeof connection?.origin === "string" && typeof connection?.bootstrap === "string", "本机连接描述符字段无效");
  return connection;
}

function resolveConnection(options) {
  const descriptor = options.dataDir ? decryptConnectionDescriptor(options.dataDir) : null;
  const baseUrl = options.baseUrl || descriptor?.origin || "";
  const token = options.token || descriptor?.bootstrap || "";
  check(baseUrl && token, "请提供 --base-url 与 --token，或提供 --data-dir");
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    fail("本地服务地址无效");
  }
  check(parsed.protocol === "http:" && HOST_ORIGIN.test(parsed.origin), "服务地址必须是 127.0.0.1 HTTP 地址");
  return { baseUrl: parsed.origin, token };
}

function errorCode(result) {
  return typeof result?.data?.error?.code === "string" ? result.data.error.code : "";
}

function firstSetCookie(response) {
  if (typeof response.headers.getSetCookie === "function") return response.headers.getSetCookie()[0] || "";
  return response.headers.get("set-cookie") || "";
}

class LocalClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = "";
    this.csrf = "";
  }

  async request(endpoint, { method = "GET", body, headers = {}, csrf = true } = {}) {
    const requestHeaders = new Headers(headers);
    if (this.cookie) requestHeaders.set("cookie", this.cookie);
    if (csrf && this.csrf && !["GET", "HEAD"].includes(method.toUpperCase())) {
      requestHeaders.set("x-csrf-token", this.csrf);
    }
    let requestBody = body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && !(body instanceof Blob) && typeof body !== "string") {
      requestBody = JSON.stringify(body);
      requestHeaders.set("content-type", "application/json");
    }
    let response;
    try {
      response = await fetch(new URL(endpoint, this.baseUrl).href, {
        method,
        headers: requestHeaders,
        body: requestBody,
        cache: "no-store",
        redirect: "manual",
      });
    } catch {
      fail("无法连接本机 Web 服务");
    }
    const setCookie = firstSetCookie(response);
    if (setCookie) this.cookie = setCookie.split(";", 1)[0];
    const contentType = response.headers.get("content-type") || "";
    const text = await response.text();
    let data = null;
    if (contentType.toLowerCase().includes("json")) {
      try {
        data = JSON.parse(text);
      } catch {
        fail("服务返回了无效 JSON");
      }
    }
    return { response, data, text };
  }

  async login(token) {
    const result = await this.request("/api/v1/session", { method: "POST", body: { token }, csrf: false });
    check(result.response.status === 200, `登录失败:${errorCode(result) || result.response.status}`);
    check(Boolean(this.cookie), "登录未建立会话 Cookie");
    const cookieHeader = firstSetCookie(result.response);
    check(cookieHeader.includes("HttpOnly"), "会话 Cookie 未设置 HttpOnly");
    check(cookieHeader.includes("SameSite=Strict"), "会话 Cookie 未设置 SameSite");
    check(typeof result.data?.csrf_token === "string" && result.data.csrf_token.length > 20, "登录未返回 CSRF 令牌");
    this.csrf = result.data.csrf_token;
  }
}

function formWithFile(fields, fieldName, filename, text) {
  const form = new FormData();
  for (const [key, value] of Object.entries(fields)) form.append(key, value);
  form.append(fieldName, new Blob([text], { type: "text/plain;charset=utf-8" }), filename);
  return form;
}

async function pollTask(client, taskId) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const result = await client.request(`/api/v1/tasks/${encodeURIComponent(taskId)}`);
    check(result.response.status === 200, `任务状态请求失败:${errorCode(result) || result.response.status}`);
    const status = result.data?.status;
    if (TERMINAL_TASK_STATES.has(status)) {
      check(status === "ready", `任务未通过:${status}`);
      return result.data;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail("任务在限定时间内未完成");
}

async function runHttpSmoke(connection) {
  const client = new LocalClient(connection.baseUrl);
  const [index, app] = await Promise.all([fetch(`${connection.baseUrl}/`), fetch(`${connection.baseUrl}/app.js`)]);
  check(index.status === 200 && app.status === 200, "Web 入口或 app.js 不可用");
  check(index.headers.get("content-security-policy") === EXPECTED_CSP, "Web 入口 CSP 不符合发布策略");
  check(app.headers.get("content-security-policy") === EXPECTED_CSP, "app.js CSP 不符合发布策略");
  const wrongOrigin = await client.request("/api/v1/session", {
    method: "POST",
    body: { token: connection.token },
    headers: { origin: "http://evil.example" },
    csrf: false,
  });
  check(wrongOrigin.response.status === 403 && errorCode(wrongOrigin) === "origin_rejected", "错误 Origin 未被拒绝");

  await client.login(connection.token);
  const health = await client.request("/api/v1/health");
  check(health.response.status === 200, `健康检查失败:${errorCode(health) || health.response.status}`);
  check(health.response.headers.get("cache-control") === "no-store", "敏感 API 缺少 no-store");
  check(health.response.headers.get("x-content-type-options") === "nosniff", "API 缺少 nosniff");
  check(health.data?.ocr?.available === false, "未配置 OCR 模型的合成工作区不应报告已就绪");

  const missingCsrf = await client.request("/api/v1/groups", { method: "POST", body: { name: "csrf rejection" }, csrf: false });
  check(missingCsrf.response.status === 403 && errorCode(missingCsrf) === "csrf_rejected", "缺少 CSRF 未被拒绝");
  const groupResult = await client.request("/api/v1/groups", { method: "POST", body: { name: "HTTP smoke group" } });
  check(groupResult.response.status === 200 && typeof groupResult.data?.id === "string", "创建测试分组失败");
  const groupId = groupResult.data.id;

  const imported = await client.request("/api/v1/imports", {
    method: "POST",
    body: formWithFile({ group_id: groupId, request_id: "smoke-import-1", encoding: "utf-8" }, "files", "smoke.txt", REDACTION_SOURCE),
  });
  check(imported.response.status === 200 && typeof imported.data?.id === "string", `TXT 导入失败:${errorCode(imported) || imported.response.status}`);
  const taskId = imported.data.id;
  const materialId = imported.data?.materials?.[0]?.id;
  check(typeof materialId === "string", "导入未返回材料 ID");
  await pollTask(client, taskId);

  const material = await client.request(`/api/v1/materials/${encodeURIComponent(materialId)}`);
  check(material.response.status === 200, `材料详情失败:${errorCode(material) || material.response.status}`);
  check(material.data?.status === "ready", "本地脱敏未生成可用结果");
  check(material.data?.analysis?.needsReview === false, "确定性脱敏仍需复核");
  check(typeof material.data?.result_id === "string", "可用材料缺少结果 ID");
  const originalResultId = material.data.result_id;
  const originalRevision = material.data.revision;

  const exported = await client.request(`/api/v1/results/${encodeURIComponent(originalResultId)}/export?format=txt`);
  check(exported.response.status === 200, `脱敏结果导出失败:${errorCode(exported) || exported.response.status}`);
  check(exported.response.headers.get("cache-control") === "no-store", "结果导出缺少 no-store");
  check(!exported.text.includes("13800139000") && !exported.text.includes("13800138000"), "导出结果仍含合成敏感标识");

  const replacement = await client.request(`/api/v1/materials/${encodeURIComponent(materialId)}/replace`, {
    method: "POST",
    body: formWithFile({ revision: String(originalRevision), encoding: "utf-8" }, "file", "replacement.txt", REPLACEMENT_SOURCE),
  });
  check(replacement.response.status === 200, `替换源文件失败:${errorCode(replacement) || replacement.response.status}`);
  check(replacement.data?.id === materialId && replacement.data?.revision > originalRevision, "替换未生成新材料版本");
  const revoked = await client.request(`/api/v1/results/${encodeURIComponent(originalResultId)}/export?format=txt`);
  check(revoked.response.status === 400 && errorCode(revoked) === "result_revoked", "旧结果未撤销");
  await pollTask(client, replacement.data.task_id);

  const templates = await client.request("/api/v1/templates");
  check(templates.response.status === 200 && templates.data?.templates?.length === 6, "模板目录不完整");
  const templateInput = {
    title: "HTTP smoke 文书",
    party_a: "甲方",
    party_b: "乙方",
    facts: "测试事实经过",
    requests: "测试请求事项",
    evidence: "测试证据",
    requirements: "提交前复核",
  };
  const preview = await client.request("/api/v1/templates/preview", {
    method: "POST",
    body: { template_id: "complaint", input: templateInput },
  });
  check(preview.response.status === 200 && typeof preview.data?.text === "string" && preview.data.text.length > 0, "模板预览失败");
  const templateExport = await client.request("/api/v1/templates/export", {
    method: "POST",
    body: { template_id: "complaint", input: templateInput, format: "md" },
  });
  check(templateExport.response.status === 200 && (templateExport.response.headers.get("content-type") || "").startsWith("text/markdown"), "模板 Markdown 导出失败");

  const mcpClient = await client.request("/api/v1/mcp/clients", {
    method: "POST",
    body: { name: "HTTP smoke MCP", group_id: groupId },
  });
  check(mcpClient.response.status === 200 && typeof mcpClient.data?.token === "string", `MCP 客户端创建失败:${errorCode(mcpClient) || mcpClient.response.status}`);
  const mcpToken = mcpClient.data.token;
  const replacementMaterial = await client.request(`/api/v1/materials/${encodeURIComponent(materialId)}`);
  check(replacementMaterial.response.status === 200 && typeof replacementMaterial.data?.result_id === "string", "替换结果未发布");
  const mcpRead = await client.request("/api/v1/mcp/read-result", {
    method: "POST",
    body: { result_id: replacementMaterial.data.result_id },
    headers: { authorization: `Bearer ${mcpToken}` },
    csrf: false,
  });
  check(mcpRead.response.status === 200 && typeof mcpRead.data?.text === "string" && !mcpRead.data.text.includes("13900139000"), "MCP 未返回当前脱敏结果");
  const clients = await client.request("/api/v1/mcp/clients");
  check(clients.response.status === 200 && !clients.text.includes(mcpToken), "MCP 令牌被重复返回");
  const clientId = mcpClient.data?.client?.id;
  check(typeof clientId === "string", "MCP 客户端缺少 ID");
  const revokedClient = await client.request(`/api/v1/mcp/clients/${encodeURIComponent(clientId)}`, { method: "DELETE", body: {} });
  check(revokedClient.response.status === 200, "MCP 客户端撤销失败");
  const revokedRead = await client.request("/api/v1/mcp/read-result", {
    method: "POST",
    body: { result_id: replacementMaterial.data.result_id },
    headers: { authorization: `Bearer ${mcpToken}` },
    csrf: false,
  });
  check(revokedRead.response.status === 401, "撤销后的 MCP 令牌仍可读取");

  return { client, groupId, materialId };
}

async function waitForText(page, text, timeout = 10_000) {
  const locator = page.getByText(text, { exact: true });
  await locator.waitFor({ state: "visible", timeout });
  return locator;
}

async function waitForHeading(page, text, timeout = 10_000) {
  const locator = page.getByRole("heading", { name: text, exact: true });
  await locator.waitFor({ state: "visible", timeout });
  return locator;
}

async function runBrowserSmoke(connection, options) {
  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    try {
      playwright = await import("@playwright/test");
    } catch {
      if (options.requireBrowser) fail("未安装 Playwright，无法执行浏览器 smoke");
      return { status: "skipped", reason: "Playwright 未安装" };
    }
  }
  const browser = await playwright.chromium.launch({ headless: !options.headed });
  try {
    const page = await browser.newPage();
    await page.goto(`${connection.baseUrl}/#token=${encodeURIComponent(connection.token)}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "材料脱敏", exact: true }).waitFor({ state: "visible", timeout: 15_000 });
    for (const label of ["材料脱敏", "法律检索", "文书写作", "AI 对话", "设置"]) {
      check(await page.getByRole("button", { name: label, exact: true }).count() === 1, `页面入口缺失:${label}`);
    }

    const groupInput = page.getByPlaceholder("新分组名称");
    await groupInput.fill("浏览器 smoke group");
    await page.getByRole("button", { name: "新建分组", exact: true }).click();
    await waitForText(page, "分组已创建");
    const upload = page.locator('input[type="file"][accept*=".txt"]').first();
    await upload.setInputFiles({ name: "browser-smoke.txt", mimeType: "text/plain", buffer: Buffer.from(BROWSER_SOURCE, "utf8") });
    await page.getByRole("button", { name: "开始脱敏", exact: true }).click();
    const created = page.getByText(/任务已创建|任务：/u).first();
    await created.waitFor({ state: "visible", timeout: 15_000 });

    await page.getByRole("button", { name: "法律检索", exact: true }).click();
    await waitForHeading(page, "法律检索");
    // Current scope must be the default. Historical body access is an explicit
    // scope choice in 1.2.1; current-scope details show historical metadata only.
    const versionScope = page.getByRole("combobox", { name: "版本范围", exact: true });
    check(await versionScope.inputValue() === "current", "默认版本范围应为当前有效");
    await versionScope.selectOption("all");
    await page.getByPlaceholder("输入法条、关键词或文号").fill("合同");
    await page.getByRole("button", { name: "搜索法条", exact: true }).click();
    await page.getByText(/命中 [1-9]\d* 部法律/u).waitFor({ state: "visible", timeout: 20_000 });
    await page.getByRole("button", { name: "查看命中条文", exact: true }).first().click();
    // The expanded group keeps its law-title button in the DOM. Scope the
    // article click to the loaded group so the smoke does not click the title
    // again and mistake the search-panel history checkbox for detail state.
    const legalResult = page.locator(".legal-group-articles .legal-article-card .result-button").first();
    await legalResult.waitFor({ state: "visible", timeout: 10_000 });
    await legalResult.click();
    await page.getByRole("checkbox", { name: "显示历史版本", exact: true }).last().waitFor({ state: "visible", timeout: 15_000 });
    check(await page.getByRole("checkbox", { name: "显示历史版本", exact: true }).last().isChecked(), "历史版本默认开启");
    const historyHeading = await waitForText(page, "历史版本");
    const historyBody = page.locator(".detail-area .version-content");
    await historyBody.waitFor({ state: "visible", timeout: 15_000 });
    const historyBodyBefore = (await historyBody.innerText()).trim();
    check(historyBodyBefore.length > 20 && !historyBodyBefore.includes("正在读取"), "历史版本正文已加载");
    check(await page.getByRole("checkbox", { name: "显示关联法规", exact: true }).last().isChecked(), "关联法规默认开启");
    const relationHeading = await waitForText(page, "关联法规");
    // Keep the real detail mounted for a short interval. This catches a
    // result/resize callback that would silently replace the detail column
    // after the article request has completed.
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    check(await historyHeading.isVisible(), "历史版本正文稳定");
    check(await relationHeading.isVisible(), "关联法规正文稳定");
    const historyBodyAfter = (await historyBody.innerText()).trim();
    check(historyBodyAfter.length > 20 && !historyBodyAfter.includes("正在读取"), "历史版本正文三秒后仍在");
    await page.getByRole("button", { name: "文书写作", exact: true }).click();
    await waitForHeading(page, "文书写作");
    await page.getByRole("button", { name: "生成文书", exact: true }).waitFor({ state: "visible" });
    // The repair native suite separately verifies generation and TXT/PDF/DOCX
    // exports using a localhost synthetic model, without a paid endpoint.

    await page.getByRole("button", { name: "AI 对话", exact: true }).click();
    await waitForHeading(page, "AI 对话");
    await page.getByRole("button", { name: "设置", exact: true }).click();
    await waitForHeading(page, "设置");
    await page.getByPlaceholder("客户端名称").fill("浏览器 smoke MCP");
    const mcpGroup = page.getByRole("combobox").last();
    if (await mcpGroup.count() > 0) {
      const optionsInGroup = await mcpGroup.locator("option").count();
      if (optionsInGroup > 0) await mcpGroup.selectOption({ index: 0 });
    }
    await page.getByRole("button", { name: "创建客户端", exact: true }).click();
    await page.getByText(/客户端已创建/u).last().waitFor({ state: "visible", timeout: 10_000 });
    await page.getByText(/收件目录/u).last().waitFor({ state: "visible", timeout: 10_000 });
    await page.getByText(/材料分组：/u).last().waitFor({ state: "visible", timeout: 10_000 });
    await page.getByRole("button", { name: "复制收件目录", exact: true }).waitFor({ state: "visible", timeout: 10_000 });
    await page.close();
  } finally {
    await browser.close();
  }
  return { status: "passed" };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printUsage();
    return;
  }
  const connection = resolveConnection(options);
  await runHttpSmoke(connection);
  process.stdout.write("HTTP smoke: PASS\n");
  if (options.noBrowser) {
    process.stdout.write("Browser smoke: SKIPPED (--no-browser)\n");
    return;
  }
  const browser = await runBrowserSmoke(connection, options);
  process.stdout.write(`Browser smoke: ${browser.status.toUpperCase()}${browser.reason ? ` (${browser.reason})` : ""}\n`);
}

main().catch((error) => {
  process.stderr.write(`smoke failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
  process.exitCode = 1;
});
