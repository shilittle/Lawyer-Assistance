#!/usr/bin/env node
"use strict";

const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..", "..");
const FLK_BASE = "https://flk.npc.gov.cn";
const DEFAULT_CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

class WafChallengeError extends Error {
  constructor(url, sample) {
    super(`WAF JavaScript/CAPTCHA challenge from ${url}: ${sample}`);
    this.name = "WafChallengeError";
    this.url = url;
    this.sample = sample;
  }
}

class TransientSourceError extends Error {
  constructor(url, status, sample) {
    super(`Transient source response from ${url}: status=${status} ${sample}`);
    this.name = "TransientSourceError";
    this.url = url;
    this.status = status;
    this.sample = sample;
  }
}

function argValue(name, fallback = null) {
  const index = process.argv.indexOf(name);
  if (index === -1 || index + 1 >= process.argv.length) return fallback;
  return process.argv[index + 1];
}

function intArg(name, fallback) {
  return Number(argValue(name, String(fallback)));
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomDelay(minMs, maxMs) {
  if (maxMs <= minMs) return minMs;
  return minMs + Math.floor(Math.random() * (maxMs - minMs + 1));
}

function isWafChallenge(text) {
  return /请完成安全验证|验证码访问|JavaScript challenge|captcha|安全验证/i.test(text || "");
}

function isTransientSourceFailure(status, text) {
  return status >= 500 || /<title>\s*50[0-9]\s*<\/title>|502 Bad Gateway|503 Service Unavailable/i.test(text || "");
}

function isDetailContentText(content) {
  if (!content) return false;
  if (typeof content === "string") return content.trim().length > 0;
  if (Array.isArray(content)) return content.length > 0;
  if (typeof content === "object") {
    if (content.children && !content.text && !content.html && !content.body && !content.paragraphs) {
      return false;
    }
    return Boolean(content.text || content.html || content.body || content.paragraphs);
  }
  return false;
}

function signedUrlExtension(url) {
  try {
    const parsed = new URL(url);
    const ext = path.extname(parsed.pathname).toLowerCase();
    if ([".docx", ".doc", ".pdf"].includes(ext)) return ext.slice(1);
  } catch {
  }
  return "docx";
}

function isFreshStat(stat, maxAgeMs) {
  if (maxAgeMs < 0) return true;
  return Date.now() - stat.mtimeMs <= maxAgeMs;
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function writeJsonAtomic(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(`${filePath}.tmp`, JSON.stringify(value), "utf8");
  await fs.rename(`${filePath}.tmp`, filePath);
}

async function writeBytesAtomic(filePath, bytes) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(`${filePath}.tmp`, bytes);
  await fs.rename(`${filePath}.tmp`, filePath);
}

async function writeState(name, value) {
  const statePath = path.join(ROOT, "data", "build", "state", name);
  await writeJsonAtomic(statePath, value);
}

async function loadRows(pageSize) {
  const pageDir = path.join(ROOT, "data", "build", "cache", "flk", "pages", `size-${pageSize}`);
  const names = (await fs.readdir(pageDir)).filter((name) => name.endsWith(".json")).sort();
  const byId = new Map();
  for (const name of names) {
    const page = await readJson(path.join(pageDir, name));
    for (const row of page.rows || []) {
      if (row.bbbs && !byId.has(row.bbbs)) byId.set(row.bbbs, row);
    }
  }
  return Array.from(byId.values());
}

async function browserJson(page, url, retries) {
  let lastSample = "";
  let lastStatus = 0;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    const fetched = await page
      .evaluate(async (target) => {
        const response = await fetch(target, { credentials: "include" });
        const text = await response.text();
        return {
          status: response.status,
          contentType: response.headers.get("content-type") || "",
          text,
        };
      }, url)
      .catch((error) => ({ status: 0, contentType: "", text: String(error) }));
    lastStatus = fetched.status;
    lastSample = fetched.text.slice(0, 300);
    if (isWafChallenge(fetched.text)) {
      throw new WafChallengeError(url, lastSample);
    }
    if (fetched.contentType.includes("application/json") || fetched.text.trim().startsWith("{")) {
      return JSON.parse(fetched.text);
    }

    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60000 });
    await page.waitForTimeout(10000 + attempt * 5000);
    const bodyText = await page.locator("body").innerText({ timeout: 10000 }).catch(() => "");
    lastSample = bodyText.slice(0, 300);
    if (isWafChallenge(bodyText)) {
      throw new WafChallengeError(url, lastSample);
    }
    if (bodyText.trim().startsWith("{")) return JSON.parse(bodyText);
    if (isTransientSourceFailure(lastStatus, bodyText)) {
      throw new TransientSourceError(url, lastStatus, lastSample);
    }

    await page.goto(`${FLK_BASE}/index`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await page.waitForTimeout(10000 + attempt * 5000);
  }
  if (isTransientSourceFailure(lastStatus, lastSample)) {
    throw new TransientSourceError(url, lastStatus, lastSample);
  }
  throw new Error(`non-json response from ${url}: ${lastSample}`);
}

async function downloadSigned(url, outputPath) {
  const response = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" } });
  if (!response.ok) {
    const sample = (await response.text().catch(() => "")).slice(0, 500);
    return { ok: false, status: response.status, sample };
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0) return { ok: false, status: response.status, sample: "empty download" };
  await writeBytesAtomic(outputPath, bytes);
  return { ok: true, status: response.status, size: bytes.length, sample: "" };
}

async function hasCompleteCache(bbbs, missingRetryMs) {
  const detailPath = path.join(ROOT, "data", "build", "cache", "flk", "details", `${bbbs}.json`);
  const linkPath = path.join(ROOT, "data", "build", "cache", "flk", "download_links", `${bbbs}.json`);
  const pdfLinkPath = path.join(ROOT, "data", "build", "cache", "flk", "download_links", `${bbbs}.pdf.json`);
  const docPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.docx`);
  const legacyDocPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.doc`);
  const pdfPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.pdf`);
  const missingPath = path.join(ROOT, "data", "build", "cache", "flk", "missing_text", `${bbbs}.json`);
  if (!(await exists(detailPath))) return false;
  const detail = await readJson(detailPath);
  if (isDetailContentText(detail.data && detail.data.content)) return true;
  if (((await exists(linkPath)) && ((await exists(docPath)) || (await exists(legacyDocPath)))) || ((await exists(pdfLinkPath)) && (await exists(pdfPath)))) {
    return true;
  }
  try {
    const stat = await fs.stat(missingPath);
    return isFreshStat(stat, missingRetryMs);
  } catch {
    return false;
  }
}

async function main() {
  const pageSize = intArg("--page-size", 100);
  const fixedDelay = argValue("--delay-ms", null);
  const minDelayMs = intArg("--min-delay-ms", fixedDelay === null ? 3000 : Number(fixedDelay));
  const maxDelayMs = intArg("--max-delay-ms", fixedDelay === null ? 8000 : Number(fixedDelay));
  const limitRaw = argValue("--limit", null);
  const limit = limitRaw === null ? null : Number(limitRaw);
  const retries = intArg("--retries", 5);
  const batchSize = intArg("--batch-size", 700);
  const batchCooldownMs = intArg("--batch-cooldown-ms", 20 * 60 * 1000);
  const wafCooldownMs = intArg("--waf-cooldown-ms", 60 * 60 * 1000);
  const maxWafRetries = intArg("--max-waf-retries", 12);
  const networkCooldownMs = intArg("--network-cooldown-ms", 15 * 60 * 1000);
  const maxNetworkRetries = intArg("--max-network-retries", 12);
  const missingRetryMs = intArg("--missing-retry-ms", 7 * 24 * 60 * 60 * 1000);
  const chromePath = argValue("--chrome", DEFAULT_CHROME);
  const profileDir = argValue("--profile", path.join(os.tmpdir(), "flk-browser-hydrate-profile"));
  const headless = hasFlag("--headless");

  const rows = await loadRows(pageSize);
  const context = await chromium.launchPersistentContext(profileDir, {
    executablePath: chromePath,
    headless,
    viewport: { width: 1280, height: 900 },
  });
  const page = context.pages()[0] || (await context.newPage());
  await page.goto(`${FLK_BASE}/index`, { waitUntil: "domcontentloaded", timeout: 60000 });
  await page.waitForTimeout(5000);

  let skipped = 0;
  let hydrated = 0;
  let pdfFallback = 0;
  let missingText = 0;
  for (const row of rows) {
    const bbbs = row.bbbs;
    if (!bbbs) continue;
    if (await hasCompleteCache(bbbs, missingRetryMs)) {
      skipped += 1;
      continue;
    }

    const detailPath = path.join(ROOT, "data", "build", "cache", "flk", "details", `${bbbs}.json`);
    const linkPath = path.join(ROOT, "data", "build", "cache", "flk", "download_links", `${bbbs}.json`);
    const pdfLinkPath = path.join(ROOT, "data", "build", "cache", "flk", "download_links", `${bbbs}.pdf.json`);
    const docPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.docx`);
    const legacyDocPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.doc`);
    const pdfPath = path.join(ROOT, "data", "build", "cache", "flk", "documents", `${bbbs}.pdf`);
    const missingPath = path.join(ROOT, "data", "build", "cache", "flk", "missing_text", `${bbbs}.json`);

    let wafRetries = 0;
    let networkRetries = 0;
    while (true) {
      try {
        const detailUrl = `${FLK_BASE}/law-search/search/flfgDetails?bbbs=${encodeURIComponent(bbbs)}`;
        const detail = await browserJson(page, detailUrl, retries);
        await writeJsonAtomic(detailPath, detail);

        const hasDetailContent = isDetailContentText(detail.data && detail.data.content);
        if (!hasDetailContent && !(await exists(docPath)) && !(await exists(legacyDocPath)) && !(await exists(pdfPath))) {
          const missingAttempts = [];
          const linkUrl = `${FLK_BASE}/law-search/download/pc?format=docx&bbbs=${encodeURIComponent(bbbs)}&fileId=`;
          const link = await browserJson(page, linkUrl, retries);
          await writeJsonAtomic(linkPath, link);
          const signed = link.data && link.data.url;
          let wordOk = false;
          if (signed) {
            const wordExt = signedUrlExtension(signed);
            const wordPath = wordExt === "doc" ? legacyDocPath : docPath;
            const word = await downloadSigned(signed, wordPath);
            wordOk = word.ok;
            if (!word.ok) {
              missingAttempts.push({
                format: wordExt,
                status: word.status,
                sample: word.sample,
                signedUrlPath: new URL(signed).pathname,
              });
            }
          } else {
            missingAttempts.push({ format: "docx", status: "missing_signed_url", keys: Object.keys(link.data || {}) });
          }
          if (!wordOk) {
            const pdfUrl = `${FLK_BASE}/law-search/download/pc?format=pdf&bbbs=${encodeURIComponent(bbbs)}&fileId=`;
            const pdfLink = await browserJson(page, pdfUrl, retries);
            await writeJsonAtomic(pdfLinkPath, pdfLink);
            const signedPdf = pdfLink.data && pdfLink.data.url;
            if (signedPdf) {
              const pdf = await downloadSigned(signedPdf, pdfPath);
              if (!pdf.ok) {
                missingAttempts.push({
                  format: "pdf",
                  status: pdf.status,
                  sample: pdf.sample,
                  signedUrlPath: new URL(signedPdf).pathname,
                });
              } else {
                pdfFallback += 1;
              }
            } else {
              missingAttempts.push({ format: "pdf", status: "missing_signed_url", keys: Object.keys(pdfLink.data || {}) });
            }
          }
          if (!(await exists(docPath)) && !(await exists(legacyDocPath)) && !(await exists(pdfPath))) {
            await writeJsonAtomic(missingPath, {
              status: "official_text_unavailable",
              bbbs,
              title: row.title || (detail.data && detail.data.title) || "",
              ossFile: detail.data && detail.data.ossFile,
              attempts: missingAttempts,
              updatedAt: new Date().toISOString(),
            });
            missingText += 1;
          }
        }
        break;
      } catch (error) {
        if (error instanceof TransientSourceError) {
          await writeState("flk_browser_hydrate_network_wait.json", {
            status: "transient_source_failure",
            bbbs,
            url: error.url,
            httpStatus: error.status,
            sample: error.sample,
            hydrated,
            skipped,
            pdfFallback,
            missingText,
            total: rows.length,
            updatedAt: new Date().toISOString(),
          });
          if (networkRetries >= maxNetworkRetries) throw error;
          networkRetries += 1;
          console.log(
            JSON.stringify({
              status: "network_cooldown",
              bbbs,
              attempt: networkRetries,
              maxNetworkRetries,
              cooldownMs: networkCooldownMs,
              sample: error.sample,
            }),
          );
          await page.goto(`${FLK_BASE}/index`, { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
          await sleep(networkCooldownMs);
          continue;
        }
        if (!(error instanceof WafChallengeError)) throw error;
        await writeState("flk_browser_hydrate_blocked.json", {
          status: "blocked_waf_js_challenge",
          bbbs,
          url: error.url,
          sample: error.sample,
              hydrated,
              skipped,
              pdfFallback,
              missingText,
              total: rows.length,
              updatedAt: new Date().toISOString(),
            });
        if (wafRetries >= maxWafRetries) throw error;
        wafRetries += 1;
        console.log(
          JSON.stringify({
            status: "waf_cooldown",
            bbbs,
            attempt: wafRetries,
            maxWafRetries,
            cooldownMs: wafCooldownMs,
            sample: error.sample,
          }),
        );
        await page.goto(`${FLK_BASE}/index`, { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
        await sleep(wafCooldownMs);
      }
    }

    hydrated += 1;
    if (hydrated % 100 === 0) {
      console.log(JSON.stringify({ hydrated, skipped, pdfFallback, missingText, bbbs }));
    }
    if (limit !== null && hydrated >= limit) break;
    if (batchSize > 0 && hydrated % batchSize === 0) {
      console.log(JSON.stringify({ status: "batch_cooldown", hydrated, skipped, cooldownMs: batchCooldownMs }));
      await sleep(batchCooldownMs);
    }
    const delayMs = randomDelay(minDelayMs, maxDelayMs);
    if (delayMs > 0) await page.waitForTimeout(delayMs);
  }

  await context.close();
  console.log(JSON.stringify({ status: "complete", hydrated, skipped, pdfFallback, missingText, total: rows.length }));
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
