import fs from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";
import { connection, root, sleep } from "./ai_test_client.mjs";

// This harness deliberately exercises only the local legal-search UI. It does
// not configure a model, upload a file, or serialize a session token.
const output = path.resolve(process.env.LEGAL_VIEWPORT_OUTPUT || path.join(root, "output/ai-upgrade-viewport"));
const defaultDataDir = process.env.LEGAL_VIEWPORT_DATA_DIR || process.env.AI_BROWSER_DATA_DIR || path.join(root, "output/ai-upgrade-live/workspace");
const viewports = [
  { width: 1366, height: 768 },
  { width: 1920, height: 1080 },
  { width: 720, height: 900 }
];

const report = {
  schema_version: 1,
  started_at: new Date().toISOString(),
  output_dir: path.relative(root, output),
  viewports,
  checks: [],
  searches: [],
  resizes: [],
  screens: [],
  errors: [],
  failures: []
};

function safeText(value) {
  return String(value ?? "")
    .replace(/(?:Bearer|api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+/giu, "$1=[REDACTED]")
    .replace(/[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gu, "[REDACTED]")
    .slice(0, 600);
}

function check(value, name, detail = "") {
  const passed = Boolean(value);
  report.checks.push({ name, passed, ...(detail ? { detail: safeText(detail) } : {}) });
  if (!passed) throw new Error(`${name}${detail ? `: ${safeText(detail)}` : ""}`);
}

function recordFailure(scope, error) {
  const message = safeText(error?.message || error);
  report.failures.push({ scope, message });
  return message;
}

async function waitVisible(locator, name, timeout = 120_000) {
  await locator.waitFor({ state: "visible", timeout });
  check(await locator.isVisible(), name);
  return locator;
}

async function waitUntil(description, predicate, timeout = 120_000, interval = 250) {
  const started = Date.now();
  let lastError = "";
  while (Date.now() - started < timeout) {
    try {
      const value = await predicate();
      if (value) return value;
    } catch (error) {
      lastError = safeText(error?.message || error);
    }
    await sleep(interval);
  }
  throw new Error(`${description}${lastError ? ` (${lastError})` : ""}`);
}

function legalSearchResponse(response) {
  if (response.request().method() !== "GET") return false;
  return response.url().includes("/api/v1/legal/search/page");
}

function bodyPage(body) {
  if (body?.page && typeof body.page === "object") return body.page;
  if (body?.data && typeof body.data === "object") return body.data;
  return body && typeof body === "object" ? body : {};
}

function bodyNumber(body, ...keys) {
  const page = bodyPage(body);
  for (const key of keys) {
    const value = Number(page[key]);
    if (Number.isFinite(value)) return Math.floor(value);
  }
  return null;
}

function bodyView(body) {
  return String(bodyPage(body).view || "").toLowerCase();
}

function responseRequest(response) {
  const url = new URL(response.url());
  return {
    path: url.pathname,
    query: url.searchParams.get("query") || "",
    document_id: url.searchParams.get("document_id") || "",
    view: url.searchParams.get("view") || "",
    sort: url.searchParams.get("sort") || "",
    limit: Number(url.searchParams.get("limit")),
    offset: Number(url.searchParams.get("offset"))
  };
}

async function noHorizontalOverflow(page, name) {
  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth
  }));
  check(dimensions.document <= dimensions.viewport + 2 && dimensions.body <= dimensions.viewport + 2, name, JSON.stringify(dimensions));
  return dimensions;
}

async function resultMetrics(page) {
  const target = page.locator(".results-panel .legal-results");
  return target.evaluate((element) => {
    const box = element.getBoundingClientRect();
    const cards = [...element.querySelectorAll(":scope > .result-card")];
    const rows = cards.map((card) => {
      const rect = card.getBoundingClientRect();
      return {
        text: String(card.textContent || "").replace(/\s+/gu, " ").trim().slice(0, 240),
        top: Math.round(rect.top),
        bottom: Math.round(rect.bottom),
        height: Math.round(rect.height),
        visible: !card.hidden && rect.bottom > box.top && rect.top < box.bottom && rect.right > box.left && rect.left < box.right
      };
    });
    return {
      container: { top: Math.round(box.top), height: Math.round(box.height), width: Math.round(box.width), scrollHeight: Math.round(element.scrollHeight) },
      cardCount: rows.length,
      visibleCardCount: rows.filter((row) => row.visible).length,
      rows
    };
  });
}

async function capture(page, viewport, label, extra = {}) {
  const filename = `${viewport.width}x${viewport.height}-${label.replace(/[^\p{Letter}\p{Number}_-]+/gu, "-")}.png`;
  await page.screenshot({ path: path.join(output, filename), fullPage: false });
  report.screens.push({ filename, viewport, label, ...extra });
  return filename;
}

async function navigateLegal(page) {
  const heading = page.getByRole("heading", { name: "法律检索", exact: true, level: 1 });
  if (!(await heading.count())) await page.getByRole("button", { name: "法律检索", exact: true }).click();
  await waitVisible(heading, "legal_heading");
  await waitVisible(page.locator('select[aria-label="结果视图"]'), "legal_view_selector");
  await waitVisible(page.locator(".results-panel .legal-results"), "legal_results_container");
}

async function searchLegal(page, viewport, query, view = "grouped") {
  await navigateLegal(page);
  const queryInput = page.getByPlaceholder("输入法条、关键词或文号");
  await queryInput.fill(query);
  await page.locator('select[aria-label="结果视图"]').selectOption(view);
  await page.locator('select[aria-label="排序方式"]').selectOption("relevance");
  const responsePromise = page.waitForResponse(legalSearchResponse, { timeout: 180_000 });
  await page.getByRole("button", { name: "搜索法条", exact: true }).click();
  const response = await responsePromise;
  check(response.ok(), `legal_search_http_${query}_${view}`, `${response.status()} ${response.url()}`);
  const body = await response.json();
  await waitVisible(page.locator(".results-panel .legal-results > .result-card").first(), `legal_results_${query}_${view}`, 180_000);
  const pageData = bodyPage(body);
  const request = responseRequest(response);
  const metrics = await resultMetrics(page);
  const texts = await page.locator(".results-panel .legal-results > .result-card").allTextContents();
  const totalLaws = bodyNumber(body, "total_laws", "totalLaws");
  const totalArticles = bodyNumber(body, "total_articles", "totalArticles");
  const limit = bodyNumber(body, "limit", "page_size", "pageSize") ?? request.limit;
  const offset = bodyNumber(body, "offset") ?? request.offset;
  const row = {
    viewport,
    query,
    view,
    request: { ...request, limit: request.limit, offset: request.offset },
    response: {
      view: bodyView(body),
      limit,
      offset,
      total: bodyNumber(body, "total", "count"),
      total_laws: totalLaws,
      total_articles: totalArticles
    },
    metrics,
    texts: texts.map((text) => safeText(text))
  };
  report.searches.push(row);
  check(request.limit >= 1 && Number.isFinite(request.limit), `legal_request_limit_${query}_${view}`, JSON.stringify(request));
  check(request.offset >= 0 && Number.isFinite(request.offset), `legal_request_offset_${query}_${view}`, JSON.stringify(request));
  check(metrics.cardCount > 0 && metrics.visibleCardCount > 0, `legal_visible_cards_${query}_${view}`, JSON.stringify(metrics));
  check(bodyView(body) === view, `legal_view_echo_${query}_${view}`, bodyView(body));
  await noHorizontalOverflow(page, `legal_no_overflow_${query}_${view}_${viewport.width}x${viewport.height}`);
  return { response, body, row, texts };
}

async function nextLegalPage(page, viewport, query, view, first) {
  const pagination = page.locator(".results-panel > .case-pagination");
  const buttons = pagination.locator("button");
  check(await buttons.count() >= 2, `legal_pagination_controls_${query}_${view}`, String(await buttons.count()));
  const next = buttons.nth(1);
  check(!(await next.isDisabled()), `legal_next_enabled_${query}_${view}`);
  const firstKeys = first.texts.map((text) => String(text).replace(/\s+/gu, " ").trim());
  const responsePromise = page.waitForResponse(legalSearchResponse, { timeout: 180_000 });
  await next.click();
  const response = await responsePromise;
  check(response.ok(), `legal_next_http_${query}_${view}`, `${response.status()} ${response.url()}`);
  const body = await response.json();
  await waitVisible(page.locator(".results-panel .legal-results > .result-card").first(), `legal_next_results_${query}_${view}`, 180_000);
  const texts = await page.locator(".results-panel .legal-results > .result-card").allTextContents();
  const secondKeys = texts.map((text) => String(text).replace(/\s+/gu, " ").trim());
  const request = responseRequest(response);
  const metrics = await resultMetrics(page);
  check(request.offset > first.row.request.offset, `legal_next_offset_${query}_${view}`, JSON.stringify(request));
  check(!firstKeys.some((text) => secondKeys.includes(text)), `legal_no_duplicate_pages_${query}_${view}`, JSON.stringify({ first: firstKeys.slice(0, 2), second: secondKeys.slice(0, 2) }));
  check(new Set(secondKeys).size === secondKeys.length, `legal_no_duplicate_cards_${query}_${view}`, JSON.stringify(secondKeys.slice(0, 5)));
  const row = {
    viewport,
    query,
    view,
    request,
    response: {
      view: bodyView(body),
      limit: bodyNumber(body, "limit", "page_size", "pageSize") ?? request.limit,
      offset: bodyNumber(body, "offset") ?? request.offset,
      total: bodyNumber(body, "total", "count"),
      total_laws: bodyNumber(body, "total_laws", "totalLaws"),
      total_articles: bodyNumber(body, "total_articles", "totalArticles")
    },
    metrics,
    texts: texts.map((text) => safeText(text))
  };
  report.searches.push(row);
  await noHorizontalOverflow(page, `legal_next_no_overflow_${query}_${view}_${viewport.width}x${viewport.height}`);
  return { response, body, row, texts };
}

async function resizeAndPreserveOffset(page, viewport, current) {
  const target = viewport.width <= 720 ? { width: 1366, height: 1080 } : { width: 720, height: 600 };
  const oldOffset = current.row.request.offset;
  const oldLimit = current.row.request.limit;
  const responsePromise = page.waitForResponse(legalSearchResponse, { timeout: 180_000 });
  await page.setViewportSize(target);
  const response = await responsePromise;
  check(response.ok(), "legal_resize_reload_http", `${response.status()} ${response.url()}`);
  const body = await response.json();
  await waitVisible(page.locator(".results-panel .legal-results > .result-card").first(), "legal_resize_results", 180_000);
  const request = responseRequest(response);
  const metrics = await resultMetrics(page);
  check(request.offset === oldOffset, "legal_resize_preserves_first_offset", JSON.stringify({ oldOffset, request }));
  check(request.limit >= 1 && Number.isFinite(request.limit), "legal_resize_limit_valid", JSON.stringify(request));
  check(metrics.visibleCardCount > 0, "legal_resize_visible_cards", JSON.stringify(metrics));
  await noHorizontalOverflow(page, `legal_resize_no_overflow_${target.width}x${target.height}`);
  const row = { from: viewport, to: target, old_limit: oldLimit, old_offset: oldOffset, request, response_limit: bodyNumber(body, "limit", "page_size", "pageSize"), metrics };
  report.resizes.push(row);
  check(request.limit !== oldLimit, "legal_resize_recomputes_limit", JSON.stringify({ oldLimit, newLimit: request.limit, target }));
  return { target, response, body, row };
}

async function restoreViewport(page, viewport, expectedOffset) {
  const responsePromise = page.waitForResponse(legalSearchResponse, { timeout: 180_000 });
  await page.setViewportSize(viewport);
  const response = await responsePromise;
  check(response.ok(), "legal_viewport_restore_http", `${response.status()} ${response.url()}`);
  const request = responseRequest(response);
  check(request.offset === expectedOffset, "legal_viewport_restore_preserves_offset", JSON.stringify({ expectedOffset, request }));
  await waitVisible(page.locator(".results-panel .legal-results > .result-card").first(), "legal_viewport_restore_results", 180_000);
  return request;
}

async function openGroupDetail(page, viewport, query) {
  const group = page.locator(".results-panel .legal-result-group").first();
  await waitVisible(group, `legal_group_${query}`);
  const groupTitle = safeText(await group.locator(".legal-group-title").innerText());
  check(!await group.locator(".legal-group-articles .legal-article-card").count(), `legal_group_compact_${query}`, groupTitle);
  const groupResponsePromise = page.waitForResponse((response) => {
    if (!legalSearchResponse(response)) return false;
    const request = responseRequest(response);
    return Boolean(request.document_id) && request.view === "flat";
  }, { timeout: 180_000 });
  await group.locator(".legal-group-title").click();
  const groupResponse = await groupResponsePromise;
  check(groupResponse.ok(), `legal_group_articles_http_${query}`, `${groupResponse.status()} ${groupResponse.url()}`);
  await waitVisible(group.locator(".legal-group-articles .legal-article-card").first(), `legal_group_articles_${query}`, 180_000);
  const article = group.locator(".legal-group-articles .legal-article-card").first();
  const articleResponsePromise = page.waitForResponse((response) => response.request().method() === "GET" && response.url().includes("/api/v1/legal/articles/"), { timeout: 180_000 });
  await article.locator(".result-button").first().click();
  const articleResponse = await articleResponsePromise;
  check(articleResponse.ok(), `legal_article_detail_http_${query}`, `${articleResponse.status()} ${articleResponse.url()}`);
  await waitVisible(page.locator(".detail-area .detail-heading"), `legal_article_detail_${query}`, 180_000);
  const toggles = page.locator('.detail-area input[aria-label="显示历史版本"], .detail-area input[aria-label="显示关联法规"]');
  check(await toggles.count() === 2, `legal_detail_toggles_${query}`);
  check(await toggles.nth(0).isChecked() && await toggles.nth(1).isChecked(), `legal_detail_toggles_default_${query}`);
  const detailText = await page.locator(".detail-area").innerText();
  check(detailText.length > 30, `legal_detail_text_${query}`, detailText.slice(0, 120));
  await page.locator(".detail-area .detail-heading").evaluate((element) => element.scrollIntoView({ block: "start", inline: "nearest" }));
  const filename = await capture(page, viewport, `${query}-detail`, { group_title: groupTitle, detail_chars: detailText.length });
  return { groupTitle, filename, detailChars: detailText.length, groupRequest: responseRequest(groupResponse), articleUrl: new URL(articleResponse.url()).pathname };
}

async function runViewport(browser, origin, token, viewport) {
  const page = await browser.newPage({ viewport });
  page.on("pageerror", (error) => report.errors.push({ viewport, kind: "pageerror", message: safeText(error.message) }));
  page.on("console", (message) => { if (message.type() === "error") report.errors.push({ viewport, kind: "console", message: safeText(message.text()) }); });
  page.on("requestfailed", (request) => report.errors.push({ viewport, kind: "requestfailed", path: safeText(new URL(request.url()).pathname), message: safeText(request.failure()?.errorText) }));
  try {
    await page.goto(`${origin}/#token=${encodeURIComponent(token)}`, { waitUntil: "domcontentloaded" });
    await waitVisible(page.getByRole("button", { name: "材料脱敏", exact: true }), `initial_shell_${viewport.width}x${viewport.height}`);
    await navigateLegal(page);

    const company = await searchLegal(page, viewport, "公司", "grouped");
    check(company.texts.some((text) => text.includes("中华人民共和国公司法")), `company_first_law_${viewport.width}x${viewport.height}`);
    await page.locator(".results-panel .legal-results").scrollIntoViewIfNeeded();
    await capture(page, viewport, "公司-结果", { limit: company.row.request.limit, offset: company.row.request.offset, visible_cards: company.row.metrics.visibleCardCount });
    const companyNext = await nextLegalPage(page, viewport, "公司", "grouped", company);
    const resized = await resizeAndPreserveOffset(page, viewport, companyNext);
    await page.evaluate(() => { document.documentElement.style.zoom = "1.25"; });
    await sleep(400);
    await noHorizontalOverflow(page, `legal_zoom_no_overflow_${viewport.width}x${viewport.height}`);
    const zoomMetrics = await resultMetrics(page);
    check(zoomMetrics.cardCount === new Set(zoomMetrics.rows.map((row) => row.text)).size, `legal_zoom_no_duplicate_${viewport.width}x${viewport.height}`);
    await page.evaluate(() => { document.documentElement.style.zoom = ""; });
    await restoreViewport(page, viewport, companyNext.row.request.offset);

    const contract = await searchLegal(page, viewport, "合同", "grouped");
    check(contract.texts.some((text) => text.includes("中华人民共和国民法典")), `contract_civil_code_first_law_${viewport.width}x${viewport.height}`);
    await page.locator(".results-panel .legal-results").scrollIntoViewIfNeeded();
    await capture(page, viewport, "合同-结果", { limit: contract.row.request.limit, offset: contract.row.request.offset, visible_cards: contract.row.metrics.visibleCardCount });
    const contractNext = await nextLegalPage(page, viewport, "合同", "grouped", contract);
    const detail = await openGroupDetail(page, viewport, "合同");
    await noHorizontalOverflow(page, `legal_final_no_overflow_${viewport.width}x${viewport.height}`);
    return {
      viewport,
      company: { first: company.row, next: companyNext.row, resize: resized.row, zoom_visible_cards: zoomMetrics.visibleCardCount },
      contract: { first: contract.row, next: contractNext.row, detail }
    };
  } finally {
    await page.close();
  }
}

function parseArgs(argv) {
  const args = { dataDir: defaultDataDir, baseUrl: "", token: "", headed: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      console.log("Usage: node scripts/verify_legal_viewport.mjs [--data-dir DIR | --base-url URL --token TOKEN] [--headed]");
      process.exit(0);
    }
    if (arg === "--headed") { args.headed = true; continue; }
    if (arg === "--data-dir") { args.dataDir = path.resolve(argv[++index] || ""); continue; }
    if (arg === "--base-url") { args.baseUrl = String(argv[++index] || ""); continue; }
    if (arg === "--token") { args.token = String(argv[++index] || ""); continue; }
    throw new Error(`unknown_argument:${arg}`);
  }
  return args;
}

async function run() {
  fs.mkdirSync(output, { recursive: true });
  let browser;
  try {
    const args = parseArgs(process.argv.slice(2));
    let origin = args.baseUrl;
    let token = args.token;
    if (!origin || !token) {
      if (!args.dataDir || !fs.existsSync(path.join(args.dataDir, "connection.dpapi"))) {
        throw new Error(`session_descriptor_missing: pass --data-dir DIR or --base-url URL --token TOKEN (default ${path.relative(root, args.dataDir)})`);
      }
      const descriptor = connection(args.dataDir);
      origin = descriptor.origin;
      token = descriptor.bootstrap;
    }
    origin = new URL(origin).origin;
    check(Boolean(origin && token), "local_session_available");
    report.origin = origin;
    report.workspace = args.dataDir ? path.relative(root, args.dataDir) : "explicit-base-url";
    browser = await chromium.launch({ headless: !args.headed });
    for (const viewport of viewports) {
      const started = Date.now();
      try {
        const result = await runViewport(browser, origin, token, viewport);
        report.runs = report.runs || [];
        report.runs.push({ ...result, duration_ms: Date.now() - started });
      } catch (error) {
        recordFailure(`viewport_${viewport.width}x${viewport.height}`, error);
      }
    }
    check(report.errors.length === 0, "legal_viewport_browser_errors", JSON.stringify(report.errors));
    check(report.failures.length === 0, "legal_viewport_failures", JSON.stringify(report.failures));
  } catch (error) {
    recordFailure("browser_setup", error);
  } finally {
    if (browser) await browser.close();
    report.completed_at = new Date().toISOString();
    const reportPath = path.join(output, "viewport-report.json");
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({
      report: path.relative(root, reportPath),
      screens: report.screens.length,
      searches: report.searches.length,
      resizes: report.resizes.length,
      passed_checks: report.checks.filter((item) => item.passed).length,
      failed_checks: report.checks.filter((item) => !item.passed).length,
      failures: report.failures.length,
      errors: report.errors.length
    }));
  }
  if (report.failures.length || report.errors.length || report.checks.some((item) => !item.passed)) process.exitCode = 1;
}

await run();
