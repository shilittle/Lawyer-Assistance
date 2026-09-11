// R10 native regression. The daemon reply headers are always read from the
// copied executable. For the same-origin DOM check, Playwright intercepts only
// /app.js?audit=r10 to append a test export while retaining that reply's CSP.
// No model, credential, user workspace, or external network is used.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chromium } from "@playwright/test";
import { connection, root, startServer } from "./ai_test_client.mjs";

const expectedCsp = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const defaultCorpus = path.join(process.env.LAWYER_AUDIT_CORPUS || path.join(root, "work", "retest-121", "public-corpus"), "legal_core.sqlite");
const { values } = parseArgs({ options: {
  exe: { type: "string", default: path.join(root, "target", "x86_64-pc-windows-msvc", "debug", "lawyer-assistance.exe") },
  "legal-db": { type: "string", default: process.env.LAWYER_AUDIT_LEGAL_DB || defaultCorpus },
  output: { type: "string", default: path.join(root, "work", "retest-121", "stage4", "sanitizer-postfix") }
} });
const executable = path.resolve(values.exe);
const legalDb = path.resolve(values["legal-db"]);
const output = path.resolve(values.output);
const sha256 = async (file) => createHash("sha256").update(await fs.readFile(file)).digest("hex");
const sourceFiles = {
  app_js: path.join(root, "apps", "web", "app.js"),
  native_script: fileURLToPath(import.meta.url)
};
const elapsedStart = performance.now();

async function reserveOutputDirectory(directory) {
  try {
    await fs.access(directory);
  } catch (error) {
    if (error?.code === "ENOENT") {
      await fs.mkdir(path.dirname(directory), { recursive: true });
      await fs.mkdir(directory, { recursive: false });
      return;
    }
    throw error;
  }
  throw new Error("evidence_output_already_exists");
}

await reserveOutputDirectory(output);

const checks = [];
const pageErrors = { daemon: [], same_origin: [], independent: [] };
const report = {
  schema_version: 2,
  suite: "sanitizer-native",
  synthetic_only: true,
  instrumentation: "same-origin Playwright route appends only `export { sanitizeRenderedHtml }` to /app.js?audit=r10; the original daemon response headers are retained and recorded",
  expected_after_fix: "all checks pass; neither CSP nor test instrumentation may mask unsafe DOM descendants",
  source_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  node: process.version,
  checks
};

function record(id, passed, detail = {}) {
  checks.push({ id, status: passed ? "passed" : "failed", ...detail });
  return passed;
}

async function installDomInspector(page) {
  await page.evaluate(() => {
    window.__r10InspectSanitizedDom = (target) => {
      const descendants = [...target.querySelectorAll("*")];
      return {
        unsafe_attributes: descendants.flatMap((element) => [...element.attributes]
          .filter((attribute) => attribute.name.toLowerCase().startsWith("on")
            || ["style", "class", "id"].includes(attribute.name.toLowerCase())
            || (attribute.name.toLowerCase() === "href" && !/^https?:\/\//iu.test(attribute.value)))
          .map((attribute) => `${element.tagName.toLowerCase()}.${attribute.name.toLowerCase()}`)),
        dangerous_descendants: descendants
          .filter((element) => ["base", "embed", "iframe", "link", "meta", "object", "script", "style", "svg", "img"].includes(element.tagName.toLowerCase()))
          .map((element) => element.tagName.toLowerCase()),
        unknown_wrappers: descendants
          .filter((element) => ["custom-a", "custom-b", "custom-c"].includes(element.tagName.toLowerCase()))
          .map((element) => element.tagName.toLowerCase()),
        safe: {
          href: target.querySelector("a[href^='https://']")?.getAttribute("href") || "",
          target: target.querySelector("a[href^='https://']")?.getAttribute("target") || "",
          rel: target.querySelector("a[href^='https://']")?.getAttribute("rel") || "",
          start: target.querySelector("ol")?.getAttribute("start") || ""
        },
        text: target.textContent || ""
      };
    };
  });
}

function isSafeDom(dom) {
  return dom.unsafe_attributes.length === 0
    && dom.dangerous_descendants.length === 0
    && dom.unknown_wrappers.length === 0
    && dom.safe.href === "https://example.com/ok"
    && dom.safe.target === "_blank"
    && dom.safe.rel === "noopener noreferrer"
    && dom.safe.start === "3"
    && dom.text.includes("合成深层文本")
    && dom.text.includes("保留安全内容");
}

const markup = [
  '<custom-a><custom-b><custom-c>',
  '<p id="unsafe-id" class="unsafe-class" style="color:red" onmouseover="window.__r10Event=true">合成深层文本</p>',
  '<a href="javascript:window.__r10Link=true" onclick="window.__r10Click=true">危险链接</a>',
  '<a href="data:text/html,unsafe">数据链接</a>',
  '<script>window.__r10Script=true</script><style>body{outline:1px solid red}</style><iframe></iframe><object></object><svg></svg><img src=x onerror="window.__r10Image=true">',
  '<p>保留安全内容 <strong>保留强调</strong></p><a href="https://example.com/ok">安全链接</a><ol start="3"><li>第三项</li></ol>',
  '</custom-c></custom-b></custom-a>'
].join("");

let daemon;
let browser;
let staticServer;
let daemonPage;
let independentPage;
try {
  await Promise.all([fs.access(executable), fs.access(legalDb)]);
  const preservedDir = path.join(output, "daemon");
  const preservedExecutable = path.join(preservedDir, "lawyer-assistance.exe");
  await fs.mkdir(preservedDir, { recursive: false });
  await fs.copyFile(executable, preservedExecutable);
  const [sourceProgramHash, preservedProgramHash, sourceProgramStat, sourceAppHash, scriptHash, legalDbHash] = await Promise.all([
    sha256(executable), sha256(preservedExecutable), fs.stat(executable), sha256(sourceFiles.app_js), sha256(sourceFiles.native_script), sha256(legalDb)
  ]);
  if (sourceProgramHash !== preservedProgramHash) throw new Error("preserved_daemon_hash_mismatch");
  report.identities = {
    source_app_js_sha256: sourceAppHash,
    source_script_sha256: scriptHash,
    daemon_source_sha256: sourceProgramHash,
    daemon_preserved_sha256: preservedProgramHash,
    public_corpus_sha256: legalDbHash
  };
  report.daemon = {
    source_file: executable,
    preserved_file: preservedExecutable,
    bytes: sourceProgramStat.size,
    legal_db: legalDb
  };

  const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
  daemon = await startServer(workspace, preservedExecutable, legalDb, { portable: true });
  const descriptor = connection(workspace);
  const [indexResponse, appResponse, apiResponse] = await Promise.all([
    fetch(`${descriptor.origin}/`), fetch(`${descriptor.origin}/app.js`), fetch(`${descriptor.origin}/api.js`)
  ]);
  const [daemonApp, daemonApi] = await Promise.all([appResponse.text(), apiResponse.text()]);
  report.embedded_web = {
    app_js_sha256: createHash("sha256").update(daemonApp).digest("hex"),
    api_js_sha256: createHash("sha256").update(daemonApi).digest("hex")
  };
  record("R10_daemon_csp_headers", indexResponse.status === 200
    && appResponse.status === 200
    && indexResponse.headers.get("content-security-policy") === expectedCsp
    && appResponse.headers.get("content-security-policy") === expectedCsp, {
    index_status: indexResponse.status,
    app_status: appResponse.status,
    index_csp: indexResponse.headers.get("content-security-policy") || "",
    app_csp: appResponse.headers.get("content-security-policy") || ""
  });
  if (!daemonApp.includes("function sanitizeRenderedHtml")) throw new Error("compiled_app_missing_sanitizer");

  browser = await chromium.launch({ headless: true });
  daemonPage = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  daemonPage.on("pageerror", (error) => pageErrors.daemon.push(String(error)));
  const documentResponse = await daemonPage.goto(`${descriptor.origin}/`, { waitUntil: "domcontentloaded" });
  const cspProbe = await daemonPage.evaluate(() => new Promise((resolve) => {
    window.__r10InlineProbe = false;
    const violations = [];
    const listener = (event) => violations.push({ directive: event.violatedDirective, blocked_uri: event.blockedURI });
    document.addEventListener("securitypolicyviolation", listener);
    const script = document.createElement("script");
    script.textContent = "window.__r10InlineProbe = true;";
    document.body.append(script);
    setTimeout(() => {
      script.remove();
      document.removeEventListener("securitypolicyviolation", listener);
      resolve({ inline_executed: window.__r10InlineProbe === true, violations });
    }, 100);
  }));
  const browserCsp = documentResponse?.headers()?.["content-security-policy"] || "";
  record("R10_daemon_csp_blocks_inline_probe", browserCsp === expectedCsp
    && cspProbe.inline_executed === false
    && cspProbe.violations.some((item) => String(item.directive).startsWith("script-src")), {
    browser_csp: browserCsp,
    csp_probe: cspProbe
  });
  await daemonPage.screenshot({ path: path.join(output, "daemon-csp.png"), fullPage: true });
  await installDomInspector(daemonPage);

  let instrumentedApp = null;
  daemonPage.on("pageerror", (error) => pageErrors.same_origin.push(String(error)));
  await daemonPage.route((url) => url.href === `${descriptor.origin}/app.js?audit=r10`, async (route) => {
    const response = await route.fetch();
    const body = await response.text();
    instrumentedApp = {
      status: response.status(),
      csp: response.headers()["content-security-policy"] || "",
      source_sha256: createHash("sha256").update(body).digest("hex")
    };
    await route.fulfill({ response, body: `${body}\nexport { sanitizeRenderedHtml };\n` });
  });
  const sameOriginDom = await daemonPage.evaluate(async (source) => {
    document.getElementById("app")?.remove();
    const subject = await import("/app.js?audit=r10");
    const target = document.createElement("div");
    target.id = "r10-same-origin-target";
    document.body.replaceChildren(target);
    target.replaceChildren(...subject.sanitizeRenderedHtml(source));
    return window.__r10InspectSanitizedDom(target);
  }, markup);
  const sameOriginSafe = isSafeDom(sameOriginDom);
  record("R10_daemon_same_origin_instrumented_sanitization", instrumentedApp?.status === 200
    && instrumentedApp?.csp === expectedCsp
    && sameOriginSafe
    && cspProbe.inline_executed === false, {
    actual: sameOriginDom,
    instrumentation_response: instrumentedApp,
    csp_cannot_mask_dom_leak: cspProbe.inline_executed === false && !sameOriginSafe
  });
  await daemonPage.screenshot({ path: path.join(output, "daemon-same-origin-dom.png"), fullPage: true });

  staticServer = http.createServer((request, response) => {
    const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
    response.setHeader("cache-control", "no-store");
    if (pathname === "/") {
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.end("<!doctype html><meta charset=utf-8><div id=target></div>");
    } else if (pathname === "/app.js") {
      response.setHeader("content-type", "text/javascript; charset=utf-8");
      response.end(`${daemonApp}\nexport { sanitizeRenderedHtml };\n`);
    } else if (pathname === "/api.js") {
      response.setHeader("content-type", "text/javascript; charset=utf-8");
      response.end(daemonApi);
    } else {
      response.statusCode = 404;
      response.end();
    }
  });
  await new Promise((resolve) => staticServer.listen(0, "127.0.0.1", resolve));
  const staticOrigin = `http://127.0.0.1:${staticServer.address().port}`;
  independentPage = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  independentPage.on("pageerror", (error) => pageErrors.independent.push(String(error)));
  await independentPage.goto(staticOrigin);
  await installDomInspector(independentPage);
  const independentDom = await independentPage.evaluate(async (source) => {
    const subject = await import("/app.js");
    const target = document.getElementById("target");
    target.replaceChildren(...subject.sanitizeRenderedHtml(source));
    return window.__r10InspectSanitizedDom(target);
  }, markup);
  const independentSafe = isSafeDom(independentDom);
  record("R10_independent_dom_sanitization", independentSafe, {
    actual: independentDom,
    independent_dom_only: true
  });
  await independentPage.screenshot({ path: path.join(output, "independent-dom.png"), fullPage: true });
} catch (error) {
  report.status = "error";
  report.error = String(error?.stack || error);
} finally {
  if (independentPage && !independentPage.isClosed()) await independentPage.close();
  if (daemonPage && !daemonPage.isClosed()) await daemonPage.close();
  if (browser) await browser.close();
  if (staticServer) await new Promise((resolve) => staticServer.close(resolve));
  if (daemon) await daemon.stop();
  report.page_errors = pageErrors;
  if (report.status !== "error") report.status = checks.every((item) => item.status === "passed") ? "passed" : "failed";
  report.passed = report.status === "passed";
  report.exit_compatible = report.passed ? 0 : 1;
  report.elapsed_ms = Number((performance.now() - elapsedStart).toFixed(3));
  report.completed_at = new Date().toISOString();
  await fs.writeFile(path.join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ status: report.status, passed: report.passed, exit_compatible: report.exit_compatible, elapsed_ms: report.elapsed_ms, checks: checks.map((item) => [item.id, item.status]), output }));
  if (!report.passed) process.exitCode = 1;
}
