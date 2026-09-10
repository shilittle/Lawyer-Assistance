import fs from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";
import { configureGlm, connection, root, sleep, startServer } from "./ai_test_client.mjs";

// This browser run is confined to the synthetic acceptance workspace. It
// configures the approved GLM provider without serialising the key or material
// contents into the report.
const output = path.join(root, "output/ai-upgrade-browser");
const dataDir = path.resolve(process.env.AI_BROWSER_DATA_DIR || path.join(root, "output/ai-upgrade-live/workspace"));
fs.mkdirSync(output, { recursive: true });

const viewports = [[1366, 768], [1920, 1080], [720, 900]];
const report = {
  schema_version: 2,
  started_at: new Date().toISOString(),
  workspace: path.relative(root, dataDir),
  model: "glm-5.3-flash",
  reasoning_effort: "low",
  viewports: viewports.map(([width, height]) => ({ width, height })),
  screens: [],
  checks: [],
  runs: [],
  errors: [],
  failures: []
};

function safeText(value) {
  return String(value ?? "")
    .replace(/(?:Bearer|api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+/giu, "$1=[REDACTED]")
    .replace(/[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gu, "[REDACTED]")
    .slice(0, 500);
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

async function waitVisible(locator, name, timeout = 30_000) {
  await locator.waitFor({ state: "visible", timeout });
  check(await locator.isVisible(), name);
  return locator;
}

async function waitUntil(description, predicate, timeout = 30_000, interval = 250) {
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

function apiResponsePredicate(pathPart, method = "GET") {
  return (response) => response.url().includes(`/api/v1/${pathPart}`) && response.request().method() === method;
}

async function responseJson(responsePromise, name) {
  const response = await responsePromise;
  check(response.ok(), `${name}_http_ok`, `${response.status()} ${new URL(response.url()).pathname}`);
  return { response, body: await response.json() };
}

function runIdFromResponse(response) {
  const run = response?.run || response?.new_run || response;
  return String(run?.id || run?.run_id || run?.runId || run?.new_run_id || run?.newRunId || "");
}

async function waitRunQuiet(client, id, timeout = 900_000) {
  return waitUntil(`run_${id}_terminal`, async () => {
    const response = await client.request(`/api/v1/ai/runs/${encodeURIComponent(id)}`);
    const run = response?.run || response;
    const status = String(run?.status || "").toLowerCase();
    if (["queued", "running", "pending"].includes(status)) return null;
    return run;
  }, timeout, 1_500);
}

async function noHorizontalOverflow(page, name) {
  const dimensions = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  check(dimensions.document <= dimensions.viewport + 2 && dimensions.body <= dimensions.viewport + 2, name, JSON.stringify(dimensions));
  return dimensions;
}

async function capture(page, width, height, label, extra = {}) {
  const filename = `${width}-${label.replace(/[^\p{Letter}\p{Number}_-]+/gu, "-")}.png`;
  await page.screenshot({ path: path.join(output, filename), fullPage: true });
  report.screens.push({ label, width, height, filename, ...extra });
  return filename;
}

async function clickNav(page, label) {
  const button = page.getByRole("button", { name: label, exact: true });
  await waitVisible(button, `nav_${label}`);
  await button.click();
  await waitVisible(page.getByRole("heading", { name: label, exact: true, level: 1 }), `heading_${label}`);
  // Page renderers load their data asynchronously after the heading is
  // mounted. Wait for the page-specific shell before the next navigation so
  // this harness does not race an in-flight renderer from the previous page.
  const ready = {
    材料脱敏: async () => (await page.locator('input[type="file"]').count()) > 0,
    法律检索: async () => (await page.locator('select[aria-label="结果视图"]').count()) > 0,
    文书写作: async () => (await page.locator('select[aria-label="文书写作模型"]').count()) > 0,
    "AI 对话": async () => (await page.locator('select[aria-label="AI 对话模型"]').count()) > 0,
    设置: async () => (await page.locator('.provider-list .provider-row, .provider-list .empty-state').count()) > 0
  };
  if (ready[label]) await waitUntil(`${label}_page_ready`, ready[label], 60_000, 250);
  await sleep(800);
}

async function searchStatute(page, query, options = {}) {
  await page.getByPlaceholder("输入法条、关键词或文号").fill(query);
  if (options.view) await page.locator('select[aria-label="结果视图"]').selectOption(options.view);
  if (options.type !== undefined) await page.locator('select[aria-label="法律类型"]').selectOption(options.type);
  if (options.sort) await page.locator('select[aria-label="排序方式"]').selectOption(options.sort);
  const responsePromise = page.waitForResponse(apiResponsePredicate("legal/search/page"), { timeout: 120_000 });
  await page.getByRole("button", { name: "搜索法条", exact: true }).click();
  const { response, body } = await responseJson(responsePromise, `legal_search_${query}_${options.view || "grouped"}`);
  await waitVisible(page.locator(".results-panel .legal-results .result-card").first(), `legal_results_${query}`, 120_000);
  const meta = await page.locator(".results-panel .case-response-meta").innerText();
  const expectedTotal = options.view === "flat" ? body.totalArticles ?? body.total : body.totalLaws ?? body.total;
  check(meta.includes(String(expectedTotal)), `legal_count_${query}_${options.view || "grouped"}`, meta);
  if (options.sort) check(new URL(response.url()).searchParams.get("sort") === options.sort, `legal_sort_${options.sort}`);
  return { response, body, meta, texts: await page.locator(".results-panel .legal-results .result-card").allTextContents() };
}

async function legalNextPage(page, query, view) {
  const buttons = page.locator(".results-panel .case-pagination button");
  check(await buttons.count() >= 2, `legal_pagination_controls_${query}_${view}`);
  const next = buttons.nth(1);
  check(!(await next.isDisabled()), `legal_next_enabled_${query}_${view}`);
  const firstPage = await page.locator(".results-panel .legal-results .result-card").allTextContents();
  const responsePromise = page.waitForResponse(apiResponsePredicate("legal/search/page"), { timeout: 120_000 });
  await next.click();
  const { response } = await responseJson(responsePromise, `legal_next_${query}_${view}`);
  await waitVisible(page.locator(".results-panel .legal-results .result-card").first(), `legal_next_results_${query}_${view}`, 120_000);
  const secondPage = await page.locator(".results-panel .legal-results .result-card").allTextContents();
  check(!firstPage.some((text) => secondPage.includes(text)), `legal_no_duplicate_pages_${query}_${view}`);
  check(new URL(response.url()).searchParams.get("offset") !== "0", `legal_next_offset_${query}_${view}`);
  return { firstPage, secondPage, response };
}

async function checkNoOverflowAfterMode(page, name) {
  await sleep(300);
  return noHorizontalOverflow(page, name);
}

async function runLegalWorkflow(page, height, client) {
  await clickNav(page, "法律检索");
  check(!(await page.locator(".ai-search-panel").isVisible()), "legal_ai_panel_collapsed_by_default");
  check(await page.locator(".results-panel").isVisible(), "legal_results_panel_visible_by_default");
  const searchBefore = await page.locator(".results-panel").boundingBox();
  check(Boolean(searchBefore && searchBefore.y < height), "legal_results_container_in_first_viewport", JSON.stringify(searchBefore));

  const groupedCompany = await searchStatute(page, "公司", { view: "grouped", sort: "relevance" });
  check(groupedCompany.texts.some((text) => text.includes("中华人民共和国公司法")), "company_law_first_group");
  const resultBox = await page.locator(".results-panel .legal-results .result-card").first().boundingBox();
  check(Boolean(resultBox && resultBox.y < height), "legal_first_result_in_first_viewport", JSON.stringify(resultBox));
  const companyGroupedNext = await legalNextPage(page, "公司", "grouped");

  const flatCompany = await searchStatute(page, "公司", { view: "flat", sort: "relevance" });
  check(flatCompany.body.view === "flat", "company_flat_view");
  const companyFlatNext = await legalNextPage(page, "公司", "flat");

  const filteredCompany = await searchStatute(page, "公司", { view: "flat", type: "law", sort: "effectiveness" });
  check(filteredCompany.body.view === "flat", "company_filtered_flat_view");
  check((filteredCompany.body.items || filteredCompany.body.articles || []).length > 0, "company_filtered_results_present");

  const groupedContract = await searchStatute(page, "合同", { view: "grouped", sort: "relevance" });
  check(groupedContract.texts.some((text) => text.includes("中华人民共和国民法典")), "contract_civil_code_first_group");
  const contractGroupedNext = await legalNextPage(page, "合同", "grouped");
  const flatContract = await searchStatute(page, "合同", { view: "flat", sort: "relevance" });
  check(flatContract.body.view === "flat", "contract_flat_view");
  const contractFlatNext = await legalNextPage(page, "合同", "flat");

  const articleButton = page.locator(".results-panel .legal-results .result-button").first();
  await waitVisible(articleButton, "legal_article_open_button");
  await articleButton.click();
  await waitVisible(page.locator(".detail-area .detail-heading"), "legal_article_detail", 120_000);
  const historyToggle = page.locator('.detail-area input[aria-label="显示历史版本"]');
  const relationsToggle = page.locator('.detail-area input[aria-label="显示关联法规"]');
  check(await historyToggle.isChecked(), "legal_history_toggle_default_on");
  check(await relationsToggle.isChecked(), "legal_relations_toggle_default_on");
  await waitVisible(page.locator(".detail-area h3").filter({ hasText: "历史版本" }), "legal_history_heading", 120_000);
  await waitVisible(page.locator(".detail-area h3").filter({ hasText: "关联法规" }), "legal_relations_heading", 120_000);
  const versionContent = page.locator(".detail-area .version-content");
  await waitUntil("legal_version_body_loaded", async () => {
    const text = await versionContent.textContent().catch(() => "");
    return text && !text.includes("点击版本查看") && !text.includes("正在读取") && text.length > 50;
  }, 120_000, 400);
  const firstVersionBody = await versionContent.innerText();
  check(firstVersionBody.length > 50, "legal_version_body_is_actual_text", firstVersionBody.slice(0, 100));
  const versionNext = page.locator(".version-pagination button").nth(1);
  check(await versionNext.count() >= 1 && !(await versionNext.isDisabled()), "legal_version_body_pagination_enabled");
  const versionResponsePromise = page.waitForResponse((response) => response.url().includes("/api/v1/legal/version-articles/") && response.request().method() === "GET", { timeout: 120_000 });
  await versionNext.click();
  await responseJson(versionResponsePromise, "legal_version_next");
  await waitUntil("legal_version_second_body_loaded", async () => {
    const text = await versionContent.textContent().catch(() => "");
    return text && text.length > 50 && text !== firstVersionBody;
  }, 120_000, 400);
  check((await versionContent.innerText()) !== firstVersionBody, "legal_version_body_page_changes");

  // Version-body paging leaves the long detail page scrolled near its bottom;
  // return to the mode switch just as a user would before choosing 案例.
  await page.evaluate(() => window.scrollTo(0, 0));
  // Chromium's actionability wait can keep retrying while the long version
  // pane is reflowing. The locator is still verified before dispatching the
  // same button click handler through the DOM.
  const caseModeButton = page.locator("button.legal-mode-button").filter({ hasText: "案例" });
  await waitVisible(caseModeButton, "case_mode_button_after_version_page");
  await caseModeButton.evaluate((button) => button.click());
  check(await page.locator(".results-panel").isVisible(), "case_results_panel_visible");
  const caseType = page.locator(".legal-case-options select");
  check(await caseType.locator('option[value="typical"]').count() === 1, "typical_case_filter_option");
  check((await caseType.locator("option").allTextContents()).some((text) => text.includes("典型案例合集")), "typical_case_filter_label");
  await caseType.selectOption("typical");
  const caseQuery = page.getByPlaceholder("输入案由、争议焦点、法条或脱敏案情");
  // The typical corpus is a collection record whose body may contain several
  // cases. Query its explicit corpus label so the filter and large-body
  // detail path are exercised independently of statute keyword ranking.
  await caseQuery.fill("典型");
  try {
    const caseResponsePromise = page.waitForResponse(apiResponsePredicate("legal/cases"), { timeout: 120_000 });
    await page.getByRole("button", { name: "检索案例", exact: true }).click();
    const { response: caseResponse, body: caseBody } = await responseJson(caseResponsePromise, "typical_case_search");
    check(new URL(caseResponse.url()).searchParams.get("case_type") === "typical", "typical_case_query_parameter");
    const caseTotal = Number(caseBody?.total);
    if (Number.isFinite(caseTotal) && caseTotal > 0) {
      await waitVisible(page.locator(".case-result-card").first(), "typical_case_results", 120_000);
      const typicalCard = page.locator(".case-result-card").first();
      check((await typicalCard.innerText()).includes("典型案例合集"), "typical_case_card_label");
      await typicalCard.locator(".result-button").first().click();
      await waitVisible(page.locator(".detail-area .detail-heading"), "typical_case_detail", 120_000);
      const typicalDetailText = await page.locator(".detail-area").innerText();
      check(typicalDetailText.includes("典型案例合集"), "typical_case_detail_type_label");
      const typicalBody = page.locator(".detail-area .case-full-text .legal-text");
      const typicalBodyChars = await typicalBody.count() ? (await typicalBody.innerText()).length : 0;
      report.legal = { ...(report.legal || {}), typicalCase: { total: caseTotal, detailChars: typicalBodyChars } };
      check(typicalBodyChars > 1000, "typical_case_detail_body_loaded", `chars=${typicalBodyChars}`);
    } else {
      check(false, "typical_case_corpus_available", `API returned total=${caseBody?.total ?? "unknown"}`);
    }
  } catch (error) {
    // Keep the rest of the browser run useful while preserving an explicit
    // failure until legal_audit imports the typical corpus/backend support.
    recordFailure("typical_case_workflow", error);
  }

  const aiModeButton = page.locator("button.legal-mode-button").filter({ hasText: "AI搜索" });
  await waitVisible(aiModeButton, "ai_mode_button_after_case_search");
  await aiModeButton.evaluate((button) => button.click());
  await checkNoOverflowAfterMode(page, "ai_search_layout_no_overflow");
  const aiPrompt = page.locator('.ai-search-panel textarea[placeholder="描述事件、争议焦点或想确认的法律问题"]');
  await waitVisible(aiPrompt, "ai_search_prompt");
  check(!(await page.locator(".results-panel").isVisible()), "ai_search_hides_ordinary_results");
  const attachment = page.locator('.ai-search-panel input[type="file"]');
  await attachment.setInputFiles({ name: "browser-ai-search.txt", mimeType: "text/plain", buffer: Buffer.from("合成验收材料：甲方拟与乙方订立设备买卖合同，约定付款和验收。", "utf8") });
  await waitUntil("ai_search_attachment_uploaded", async () => (await page.locator(".ai-search-panel .status-message").allTextContents()).some((text) => text.includes("已上传")), 60_000, 300);
  await aiPrompt.fill("甲乙双方拟订立设备买卖合同，想确认付款、验收和违约责任的适用法律依据。");
  const aiRunResponsePromise = page.waitForResponse(apiResponsePredicate("ai/runs", "POST"), { timeout: 120_000 });
  await page.getByRole("button", { name: "开始 AI 法律搜索", exact: true }).click();
  const { body: aiRunResponse } = await responseJson(aiRunResponsePromise, "ai_search_create");
  const aiRunId = runIdFromResponse(aiRunResponse);
  check(Boolean(aiRunId), "ai_search_run_id_returned");
  const aiRun = await waitRunQuiet(client, aiRunId);
  report.runs.push({ kind: "search", id: aiRunId, status: aiRun?.status, stage: aiRun?.stage, citations: Array.isArray(aiRun?.citations) ? aiRun.citations.length : 0, usage: aiRun?.usage || null });
  check(String(aiRun?.status).toLowerCase() === "completed", "ai_search_run_completed", aiRun?.error_code || aiRun?.status);
  check(Array.isArray(aiRun?.citations) && aiRun.citations.length > 0, "ai_search_has_citations");
  await waitUntil("ai_search_rendered_output", async () => (await page.locator(".ai-search-panel .ai-run-output").innerText().catch(() => "")).length > 40, 60_000, 500);
  await waitVisible(page.locator(".ai-search-panel .citation-list .link-button").first(), "ai_search_citation_link", 60_000);
  await page.locator(".ai-search-panel .citation-list .link-button").first().click();
  await waitVisible(page.locator(".detail-area .detail-heading"), "ai_search_citation_opens_original", 120_000);
  check(await page.locator(".detail-area .legal-text").count() > 0, "ai_search_citation_original_body");
  return { groupedCompany: { total: groupedCompany.body.total, page: groupedCompany.texts.length }, companyGroupedNext: { page: companyGroupedNext.secondPage.length }, companyFlat: { total: flatCompany.body.total, page: flatCompany.texts.length }, companyFlatNext: { page: companyFlatNext.secondPage.length }, filteredCompany: { total: filteredCompany.body.total, page: (filteredCompany.body.items || filteredCompany.body.articles || []).length }, groupedContract: { total: groupedContract.body.total, page: groupedContract.texts.length }, contractGroupedNext: { page: contractGroupedNext.secondPage.length }, flatContract: { total: flatContract.body.total, page: flatContract.texts.length }, contractFlatNext: { page: contractFlatNext.secondPage.length }, aiRunId };
}

async function runSettingsWorkflow(page) {
  await clickNav(page, "设置");
  const providerRow = page.locator(".provider-row").filter({ hasText: "GLM 实际验收" }).first();
  await waitVisible(providerRow, "settings_glm_provider_row", 60_000);
  await providerRow.getByRole("button", { name: "编辑", exact: true }).click();
  const fetchModels = page.getByRole("button", { name: "联网获取模型列表", exact: true });
  const fetchResponsePromise = page.waitForResponse(apiResponsePredicate("ai/providers/models", "POST"), { timeout: 120_000 });
  await fetchModels.click();
  const { body: fetchBody } = await responseJson(fetchResponsePromise, "settings_model_discovery");
  const modelCount = Number(fetchBody?.models?.length || 0);
  check(modelCount >= 2, "settings_online_model_discovery", `models=${modelCount}`);
  await waitVisible(page.locator(".model-selection .model-option").first(), "settings_model_options");
  const modelIds = await page.locator(".model-selection input[data-model-id]").evaluateAll((inputs) => inputs.map((input) => input.dataset.modelId).filter(Boolean));
  check(modelIds.includes("glm-5.3-flash"), "settings_glm_flash_in_model_list");
  const secondModel = modelIds.find((id) => id !== "glm-5.3-flash");
  check(Boolean(secondModel), "settings_second_enabled_model_available");
  for (const input of await page.locator(".model-selection input[data-model-id]").all()) {
    const id = await input.getAttribute("data-model-id");
    const shouldEnable = id === "glm-5.3-flash" || id === secondModel;
    if (shouldEnable && !(await input.isChecked())) await input.check();
    if (!shouldEnable && (await input.isChecked())) await input.uncheck();
  }
  await page.locator('input[placeholder="默认模型 ID（可从启用列表中选择）"]').fill("glm-5.3-flash");
  const saveProviderResponsePromise = page.waitForResponse(apiResponsePredicate("ai/providers", "POST"), { timeout: 120_000 });
  await page.getByRole("button", { name: "保存模型服务", exact: true }).click();
  await responseJson(saveProviderResponsePromise, "settings_provider_save");
  await waitUntil("settings_provider_saved", async () => (await page.locator(".ai-provider-form .status-message").allTextContents()).some((text) => text.includes("模型服务已保存")), 60_000, 300);

  const defaultSelectors = { chat: page.locator('select[aria-label="chat默认模型"]'), redaction: page.locator('select[aria-label="redaction默认模型"]'), writing: page.locator('select[aria-label="writing默认模型"]'), ocr: page.locator('select[aria-label="ocr默认模型"]') };
  for (const selector of Object.values(defaultSelectors)) await waitVisible(selector, "settings_default_selector");
  const defaultOptions = await defaultSelectors.chat.locator("option").evaluateAll((options) => options.map((option) => option.value).filter(Boolean));
  check(defaultOptions.length >= 2, "settings_defaults_expose_multiple_models");
  const flashOption = defaultOptions.find((value) => value.endsWith("::glm-5.3-flash"));
  const otherOption = defaultOptions.find((value) => value !== flashOption);
  check(Boolean(flashOption && otherOption), "settings_defaults_have_distinct_choices");
  await defaultSelectors.chat.selectOption(flashOption);
  await defaultSelectors.redaction.selectOption(flashOption);
  await defaultSelectors.writing.selectOption(flashOption);
  await defaultSelectors.ocr.selectOption(otherOption);
  const saveDefaultsResponsePromise = page.waitForResponse(apiResponsePredicate("ai/defaults", "PUT"), { timeout: 120_000 });
  await page.getByRole("button", { name: "保存默认模型设置", exact: true }).click();
  await responseJson(saveDefaultsResponsePromise, "settings_defaults_save");
  await waitUntil("settings_defaults_saved", async () => (await page.locator(".settings-panel .status-message").allTextContents()).some((text) => text.includes("默认模型设置已保存")), 60_000, 300);
  check(await defaultSelectors.writing.inputValue() === flashOption, "settings_writing_default_saved");
  check(await defaultSelectors.ocr.inputValue() === otherOption, "settings_ocr_default_saved_separately");

  const testButton = providerRow.getByRole("button", { name: "连接测试", exact: true });
  const testResponsePromise = page.waitForResponse(apiResponsePredicate("ai/providers/test", "POST"), { timeout: 120_000 });
  await testButton.click();
  await responseJson(testResponsePromise, "settings_provider_test");
  await waitUntil("settings_provider_test_success", async () => (await page.locator(".ai-provider-form .status-message").allTextContents()).some((text) => text.includes("连接测试成功")), 120_000, 400);
  await noHorizontalOverflow(page, "settings_no_horizontal_overflow");
  return { modelCount, enabledModels: ["glm-5.3-flash", secondModel], writingDefault: flashOption, ocrDefault: otherOption };
}

async function runWritingWorkflow(page) {
  await clickNav(page, "文书写作");
  const history = page.locator(".ai-history-list .conversation-item");
  await waitVisible(history.first(), "writing_history_present", 60_000);
  const beforeCount = await history.count();
  await history.first().click();
  const preview = page.locator(".document-preview");
  await waitUntil("writing_preview_rendered", async () => { const text = await preview.innerText().catch(() => ""); return text.length > 50 && !text.includes("填写案件并生成文书"); }, 60_000, 300);
  check(await preview.locator("h1,h2,h3,h4").count() > 0, "writing_preview_has_rendered_headings");
  const previewText = await preview.innerText();
  check(!/^#{1,6}\s/mu.test(previewText), "writing_preview_has_no_raw_markdown_headings");
  check(!previewText.includes("| --- |"), "writing_preview_has_no_raw_markdown_table");
  const format = page.locator(".preview-panel select");
  check(await format.inputValue() === "pdf", "writing_default_export_pdf");
  const downloadPromise = page.waitForEvent("download", { timeout: 120_000 });
  await page.getByRole("button", { name: "导出", exact: true }).click();
  const download = await downloadPromise;
  const exportPath = path.join(output, `browser-writing-${Date.now()}.pdf`);
  await download.saveAs(exportPath);
  check(fs.readFileSync(exportPath).subarray(0, 5).toString("ascii") === "%PDF-", "writing_pdf_export_is_pdf");
  await capture(page, 1366, 768, "文书写作-历史预览");

  await page.getByRole("button", { name: "编辑正文", exact: true }).click();
  const editor = page.locator("textarea.document-content-editor");
  await waitVisible(editor, "writing_content_editor");
  const oldContent = await editor.inputValue();
  await editor.fill(`${oldContent}\n\n浏览器验收编辑版本。`);
  const updateResponsePromise = page.waitForResponse(apiResponsePredicate("ai/runs/", "PUT"), { timeout: 120_000 });
  await page.getByRole("button", { name: "保存正文修改", exact: true }).click();
  const { body: updateBody } = await responseJson(updateResponsePromise, "writing_content_update");
  const updatedRun = updateBody?.run || updateBody;
  check(Boolean(updatedRun?.id || updatedRun?.run_id), "writing_edit_returns_version");
  await waitUntil("writing_edit_saved", async () => (await page.locator(".preview-panel .status-message").allTextContents()).some((text) => text.includes("正文修改已保存")), 60_000, 300);
  await waitUntil("writing_history_refresh_after_edit", async () => (await page.locator(".ai-history-list .conversation-item").count()) >= beforeCount, 60_000, 300);
  check(await page.locator(".ai-history-list .conversation-item").count() >= beforeCount, "writing_history_refreshed_after_edit");
  await noHorizontalOverflow(page, "writing_no_horizontal_overflow");
  return { historyBefore: beforeCount, editedRunId: String(updatedRun?.id || updatedRun?.run_id || ""), pdf: exportPath };
}

async function runChatWorkflow(page, client) {
  await clickNav(page, "AI 对话");
  const createResponsePromise = page.waitForResponse(apiResponsePredicate("ai/conversations", "POST"), { timeout: 120_000 });
  await page.getByRole("button", { name: "新建会话", exact: true }).click();
  const { body: createBody } = await responseJson(createResponsePromise, "chat_create_conversation");
  const createdConversation = createBody?.conversation || createBody;
  const conversationId = String(createdConversation?.id || createdConversation?.conversation_id || "");
  check(Boolean(conversationId), "chat_conversation_id_returned");
  const titleBefore = await page.locator(".selected-conversation-title strong").innerText();
  check(titleBefore.length > 0, "chat_auto_title_starts_without_required_input");

  const attachment = page.locator('.chat-panel input[type="file"]');
  await attachment.setInputFiles({ name: "browser-chat.txt", mimeType: "text/plain", buffer: Buffer.from("合成会话附件：设备买卖合同的验收期限和付款节点。", "utf8") });
  await waitUntil("chat_attachment_uploaded", async () => (await page.locator(".chat-panel .status-message").allTextContents()).some((text) => text.includes("已上传")), 60_000, 300);
  const message = page.locator('textarea[placeholder="输入问题；助手可调用本地法律检索工具查找相关法条。"]');
  await message.fill("设备买卖合同中，验收和付款争议通常需要核对哪些法律规定？请列出法条依据。");
  const runResponsePromise = page.waitForResponse(apiResponsePredicate("ai/runs", "POST"), { timeout: 120_000 });
  await page.getByRole("button", { name: "发送", exact: true }).click();
  const { body: runBody } = await responseJson(runResponsePromise, "chat_create_run");
  const chatRunId = runIdFromResponse(runBody);
  check(Boolean(chatRunId), "chat_run_id_returned");
  const chatRun = await waitRunQuiet(client, chatRunId);
  report.runs.push({ kind: "chat", id: chatRunId, status: chatRun?.status, stage: chatRun?.stage, citations: Array.isArray(chatRun?.citations) ? chatRun.citations.length : 0, usage: chatRun?.usage || null });
  check(String(chatRun?.status).toLowerCase() === "completed", "chat_run_completed", chatRun?.error_code || chatRun?.status);
  check(String(chatRun?.content || "").length > 40, "chat_run_has_answer");
  await waitUntil("chat_assistant_message_visible", async () => (await page.locator(".chat-message.assistant .message-content").last().innerText().catch(() => "")).length > 40, 120_000, 500);
  const titleAfter = await page.locator(".selected-conversation-title strong").innerText();
  check(titleAfter && titleAfter !== titleBefore && titleAfter !== "请选择或新建会话", "chat_title_auto_generated", titleAfter);
  const renamed = `浏览器验收会话-${Date.now()}`;
  await page.locator('input[placeholder="修改会话标题"]').fill(renamed);
  const renameResponsePromise = page.waitForResponse(apiResponsePredicate(`ai/conversations/${encodeURIComponent(conversationId)}`, "PATCH"), { timeout: 120_000 });
  await page.getByRole("button", { name: "修改标题", exact: true }).click();
  await responseJson(renameResponsePromise, "chat_rename");
  await waitUntil("chat_manual_title_update", async () => (await page.locator(".chat-panel .selected-conversation-title strong").innerText()).includes(renamed), 60_000, 300);
  check(await page.locator(".ai-material-picker").count() >= 1, "chat_graphical_material_picker_present");
  check(await page.locator(".chat-panel input[type=file]").count() === 1, "chat_attachment_picker_present");
  await noHorizontalOverflow(page, "chat_no_horizontal_overflow");
  return { conversationId, chatRunId, autoTitle: titleAfter, renamed };
}

async function run() {
  const session = await startServer(dataDir);
  let browser;
  try {
    const selection = await configureGlm(session.client);
    check(selection.model === "glm-5.3-flash", "glm_fixture_configured");
    browser = await chromium.launch({ headless: true });
    for (const [width, height] of viewports) {
      const page = await browser.newPage({ viewport: { width, height } });
      page.on("pageerror", (error) => report.errors.push({ kind: "pageerror", width, message: safeText(error.message) }));
      page.on("console", (message) => { if (message.type() === "error") report.errors.push({ kind: "console", width, message: safeText(message.text()) }); });
      page.on("requestfailed", (request) => report.errors.push({ kind: "requestfailed", width, path: safeText(new URL(request.url()).pathname), message: safeText(request.failure()?.errorText) }));
      try {
        const descriptor = connection(dataDir);
        await page.goto(`${descriptor.origin}/#token=${encodeURIComponent(descriptor.bootstrap)}`);
        await waitVisible(page.getByRole("button", { name: "材料脱敏", exact: true }), "initial_material_page");
        for (const label of ["材料脱敏", "法律检索", "文书写作", "AI 对话", "设置"]) {
          await clickNav(page, label);
          await noHorizontalOverflow(page, `${label}_no_horizontal_overflow_${width}`);
          if (label === "材料脱敏") {
            const accept = await page.locator('input[type="file"]').first().getAttribute("accept");
            check([".pdf", ".png", ".jpg", ".jpeg", ".webp"].every((ext) => String(accept).includes(ext)), `redaction_file_formats_${width}`, accept);
          }
          await capture(page, width, height, label);
        }
        if (width === 1366) {
          report.legal = await runLegalWorkflow(page, height, session.client);
          report.settings = await runSettingsWorkflow(page);
          report.writing = await runWritingWorkflow(page);
          report.chat = await runChatWorkflow(page, session.client);
        } else {
          await clickNav(page, "法律检索");
          const result = await searchStatute(page, "公司", { view: "grouped", sort: "relevance" });
          check(result.texts.some((text) => text.includes("中华人民共和国公司法")), `company_search_visible_${width}`);
          const box = await page.locator(".results-panel .legal-results .result-card").first().boundingBox();
          check(Boolean(box && box.y < height), `company_first_result_visible_${width}`, JSON.stringify(box));
          await capture(page, width, height, "法律检索-公司结果", { result_count: result.texts.length });
        }
      } catch (error) {
        const diagnostic = await page.locator("body").innerText().catch(() => "");
        report.diagnostics = report.diagnostics || [];
        report.diagnostics.push({ scope: `viewport_${width}x${height}`, buttons: await page.locator("button").evaluateAll((items) => items.map((item) => { const rect = item.getBoundingClientRect(); return { text: item.textContent.trim().slice(0, 80), visible: Boolean(item.offsetWidth || item.offsetHeight || item.getClientRects().length), disabled: item.disabled, rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height } }; })).catch(() => []), hit: await page.getByRole("button", { name: "案例", exact: true }).evaluate((item) => { const rect = item.getBoundingClientRect(); const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2); return { hit: hit?.outerHTML?.slice(0, 500), pointerEvents: getComputedStyle(item).pointerEvents, position: getComputedStyle(item).position, scrollY: window.scrollY }; }).catch(() => null), body: diagnostic.slice(0, 3000) });
        await page.screenshot({ path: path.join(output, `${width}-failure.png`), fullPage: true }).catch(() => {});
        recordFailure(`viewport_${width}x${height}`, error);
      } finally {
        await page.close();
      }
    }
    check(report.errors.length === 0, "browser_console_and_page_errors", JSON.stringify(report.errors));
    check(report.failures.length === 0, "browser_acceptance_failures", JSON.stringify(report.failures));
  } catch (error) {
    recordFailure("browser_setup", error);
  } finally {
    if (browser) await browser.close();
    await session.stop();
    report.completed_at = new Date().toISOString();
    fs.writeFileSync(path.join(output, "browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({ report: path.relative(root, path.join(output, "browser-report.json")), screens: report.screens.length, checks: report.checks.filter((item) => item.passed).length, failed_checks: report.checks.filter((item) => !item.passed).length, failures: report.failures.length, errors: report.errors.length, runs: report.runs.map((run) => ({ kind: run.kind, status: run.status, citations: run.citations })) }));
  }
  if (report.failures.length || report.errors.length || report.checks.some((item) => !item.passed)) process.exitCode = 1;
}

await run();
