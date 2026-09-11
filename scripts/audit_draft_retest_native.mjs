// Real Windows daemon draft/version regression using only synthetic material and a
// localhost model.  A stale base save only exercises the normal CAS 409.  The
// client then writes each conflict as an independent encrypted candidate record;
// the candidate list is intentionally summary-only and bodies are fetched one at
// a time through the existing draft GET route.
//
// Usage:
//   node scripts/audit_draft_retest_native.mjs [exe] [--output <dir>] [--portable]
//
// The executable is deliberately supplied at run time.  This harness does not
// build or select a production binary for the caller.
import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import http from "node:http";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { root, sleep, startServer } from "./ai_test_client.mjs";

const scriptPath = fileURLToPath(import.meta.url);

function usage() {
  return "Usage: node scripts/audit_draft_retest_native.mjs [exe] [--output <dir>] [--portable]";
}

function parseArgs(argv) {
  const configuredOutput = process.env.LAWYER_AUDIT_OUTPUT
    ? path.resolve(process.env.LAWYER_AUDIT_OUTPUT)
    : path.join(root, "work", "retest-121");
  const options = { executable: "", output: configuredOutput, portable: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--portable") {
      options.portable = true;
      continue;
    }
    if (value === "--help" || value === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (value === "--output" || value === "--exe" || value === "--executable") {
      const next = argv[++index];
      if (!next) throw new Error(`${value} requires a value\n${usage()}`);
      if (value === "--output") options.output = path.resolve(next);
      else options.executable = path.resolve(next);
      continue;
    }
    if (value.startsWith("--output=") || value.startsWith("--exe=") || value.startsWith("--executable=")) {
      const separator = value.indexOf("=");
      const next = value.slice(separator + 1);
      if (!next) throw new Error(`${value.slice(0, separator)} requires a value\n${usage()}`);
      if (value.startsWith("--output=")) options.output = path.resolve(next);
      else options.executable = path.resolve(next);
      continue;
    }
    if (value.startsWith("-")) throw new Error(`Unknown argument: ${value}\n${usage()}`);
    if (options.executable) throw new Error(`Unexpected positional argument: ${value}\n${usage()}`);
    options.executable = path.resolve(value);
  }
  if (!options.executable) {
    options.executable = path.join(root, "target", "x86_64-pc-windows-msvc", "debug", "lawyer-assistance.exe");
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
const output = path.join(options.output, "draft-retest-native");
const reportPath = path.join(output, "report.json");
const auditLogPath = path.join(output, "audit.log");
await fs.mkdir(output, { recursive: true });
const workspace = await fs.mkdtemp(path.join(output, "workspace-"));
const resourceDir = path.join(output, "resources");
const legalDb = path.join(resourceDir, "synthetic-public-fixture.sqlite");
const legalSchema = path.join(root, "data", "schema", "legal_core.sql");
const legalFixture = path.join(root, "crates", "legal-services", "tests", "fixtures", "legal_core.sql");
const serverLogPath = path.join(workspace, "server-test.log");
await fs.mkdir(resourceDir, { recursive: true });

async function sha256(file) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(file)) digest.update(chunk);
  return digest.digest("hex");
}

async function optionalSha256(file) {
  try {
    return await sha256(file);
  } catch (error) {
    return `unavailable:${error.code || error.name || "read_failed"}`;
  }
}

function gitValue(...args) {
  try {
    return execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      windowsHide: true,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "unavailable";
  }
}

function fail(code) {
  const error = new Error(code);
  error.auditCode = code;
  return error;
}

function ensure(condition, code) {
  if (!condition) throw fail(code);
}

function ensureEqual(actual, expected, code) {
  if (!Object.is(actual, expected)) throw fail(code);
}

function ensureSetEqual(actual, expected, code) {
  const left = [...new Set(actual)].sort();
  const right = [...new Set(expected)].sort();
  ensure(left.length === right.length && left.every((value, index) => value === right[index]), code);
}

function failureCode(error) {
  if (error?.auditCode) return String(error.auditCode);
  if (error?.code && typeof error.code === "string") return error.code;
  const message = String(error?.message || error || "unknown_error").split("\n", 1)[0];
  return message.slice(0, 200).replaceAll("audit-synthetic-key-only", "[credential]");
}

const source = {
  root,
  commit: gitValue("rev-parse", "HEAD"),
  branch: gitValue("branch", "--show-current"),
  status: gitValue("status", "--short"),
  hashes: {
    script: await optionalSha256(scriptPath),
    executable: await optionalSha256(options.executable),
    legal_schema: await optionalSha256(legalSchema),
    legal_fixture: await optionalSha256(legalFixture)
  }
};

const report = {
  schema_version: 1,
  suite: "draft-retest-native",
  started_at: new Date().toISOString(),
  source,
  executable: { path: options.executable, portable: options.portable },
  fixture: {
    workspace,
    legal_db: legalDb,
    synthetic_material_only: true,
    public_fixture_inputs_only: true,
    user_workspace_used: false,
    raw_model_messages_saved: false,
    credentials_logged: false
  },
  environment: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    browser_observation: "skipped_api_contract_first_no_ui_labels_inferred"
  },
  checks: [],
  model: { name: "draft-audit-model", transport: "localhost-only", calls: 0, raw_messages_saved: false },
  events: []
};
report.executable.sha256 = report.source.hashes.executable;

function event(type, fields = {}) {
  report.events.push({ at: new Date().toISOString(), type, ...fields });
}

async function check(id, operation) {
  const started = Date.now();
  try {
    await operation();
    report.checks.push({ id, status: "passed", elapsed_ms: Date.now() - started });
    event("check_passed", { id });
  } catch (error) {
    report.checks.push({ id, status: "failed", elapsed_ms: Date.now() - started, error: failureCode(error) });
    event("check_failed", { id, error: failureCode(error) });
    throw error;
  }
}

function makeSyntheticLegalDb() {
  const script = String.raw`
import pathlib, sqlite3, sys
root, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
target.parent.mkdir(parents=True, exist_ok=True)
connection = sqlite3.connect(target)
connection.executescript((root / 'data/schema/legal_core.sql').read_text(encoding='utf-8'))
connection.executescript((root / 'crates/legal-services/tests/fixtures/legal_core.sql').read_text(encoding='utf-8'))
connection.commit()
connection.close()
`;
  execFileSync("python", ["-c", script, root, legalDb], {
    windowsHide: true,
    stdio: "ignore"
  });
}

function runValue(value) {
  return value?.run || value?.new_run || value;
}

async function rawRequest(client, route, method = "GET", body) {
  const headers = { cookie: client.cookie };
  if (client.csrf && method !== "GET") headers["x-csrf-token"] = client.csrf;
  let requestBody;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    requestBody = JSON.stringify(body);
  }
  const response = await fetch(`${client.origin}${route}`, {
    method,
    headers,
    body: requestBody,
    signal: AbortSignal.timeout(120000)
  });
  const text = await response.text();
  let value = null;
  try {
    value = JSON.parse(text);
  } catch {
    // The caller can still assert the HTTP status for a non-JSON response.
  }
  return { status: response.status, value };
}

async function terminal(client, id, timeout = 180000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const current = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(id)}`));
    if (!['queued', 'running'].includes(String(current.status))) return current;
    await sleep(100);
  }
  throw fail("run_timeout");
}

function draftContent(label, run, providerId) {
  return {
    document_type: "合成民事文书",
    prompt: `合成草稿 ${label}`,
    requirements: "保留合成金额与日期",
    case_date: "2026-09-10",
    provider_id: providerId,
    model: "draft-audit-model",
    materials: [],
    attachment_ids: [],
    run_id: run?.id || null,
    run_revision: Number.isInteger(run?.revision) ? run.revision : null,
    content: `# ${label}\n\nAUDIT_DRAFT_${label}`,
    dirty: true
  };
}

function draftRoute(id) {
  return `/api/v1/ai/drafts/${encodeURIComponent(id)}`;
}

async function listConflicts(client, baseId, limit = 1, cursor = "") {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return client.request(`${draftRoute(baseId)}/conflicts?${query}`);
}

function checkDraftSummaryPage(page, expectedLimit) {
  ensure(page && typeof page === "object", "draft_conflict_summary_missing");
  for (const key of ["drafts", "next_cursor", "total", "corrupt_count"]) {
    ensure(Object.prototype.hasOwnProperty.call(page, key), `draft_conflict_summary_missing_${key}`);
  }
  ensure(Array.isArray(page.drafts), "draft_conflict_summary_drafts_not_array");
  ensure(page.drafts.length <= expectedLimit, "draft_conflict_summary_limit_ignored");
  ensure(Number.isInteger(page.total) && page.total >= 0, "draft_conflict_summary_total_invalid");
  ensure(Number.isInteger(page.corrupt_count) && page.corrupt_count >= 0, "draft_conflict_summary_corrupt_count_invalid");
  for (const row of page.drafts) {
    ensureSetEqual(Object.keys(row), ["id", "revision", "updated_at"], "draft_conflict_summary_contains_body");
    ensure(typeof row.id === "string" && row.id.length > 0, "draft_conflict_summary_id_invalid");
    ensure(Number.isInteger(row.revision), "draft_conflict_summary_revision_invalid");
    ensure(typeof row.updated_at === "number" || typeof row.updated_at === "string", "draft_conflict_summary_updated_at_invalid");
  }
}

async function collectConflictPages(client, baseId, expectedTotal, candidatePattern) {
  const rows = [];
  const pages = [];
  let cursor = "";
  for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
    const page = await listConflicts(client, baseId, 1, cursor);
    checkDraftSummaryPage(page, 1);
    ensureEqual(page.total, expectedTotal, "draft_conflict_summary_total_changed_between_pages");
    ensureEqual(page.corrupt_count, 0, "draft_conflict_summary_corrupt_rows");
    const encoded = JSON.stringify(page);
    ensure(!encoded.includes("AUDIT_DRAFT_"), "draft_conflict_summary_leaked_body");
    for (const row of page.drafts) {
      ensure(candidatePattern.test(row.id), "draft_candidate_key_shape_invalid");
      rows.push(row);
    }
    pages.push(page);
    const next = page.next_cursor;
    if (next === null || next === "") {
      ensure(pageNumber > 0 || rows.length <= 1, "draft_conflict_summary_missing_cursor_for_multiple_rows");
      break;
    }
    ensure(typeof next === "string", "draft_conflict_summary_cursor_invalid");
    cursor = next;
    if (pageNumber === 19) throw fail("draft_conflict_summary_cursor_loop");
  }
  ensure(rows.length === expectedTotal, "draft_conflict_summary_missing_candidates");
  ensure(new Set(rows.map(row => row.id)).size === rows.length, "draft_conflict_summary_repeated_candidate");
  return { rows, pages };
}

let service;
let client;
let providerId;
let mock;
let failure;
let modelCalls = 0;

try {
  makeSyntheticLegalDb();
  report.resources = {
    kind: "synthetic_database_from_public_schema_and_fixture",
    legal_db: { path: legalDb, sha256: await sha256(legalDb) },
    legal_schema: { path: legalSchema, sha256: await sha256(legalSchema) },
    legal_fixture: { path: legalFixture, sha256: await sha256(legalFixture) }
  };
  event("synthetic_resource_ready");

  mock = http.createServer(async (_request, response) => {
    let bytes = 0;
    try {
      for await (const chunk of _request) {
        bytes += Buffer.byteLength(chunk);
        ensure(bytes <= 2 * 1024 * 1024, "mock_request_too_large");
      }
    } catch {
      response.destroy();
      return;
    }
    // Deliberately do not retain, print, or parse model messages.
    modelCalls += 1;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({
      model: "draft-audit-model",
      choices: [{
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: JSON.stringify({
            title: "合成原生文书",
            content: "# 合成原生文书\n\n合成金额为 126800 元，日期为 2026 年 8 月 11 日。",
            citations: []
          })
        }
      }],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 }
    }));
  });
  await new Promise((resolve, reject) => {
    mock.once("error", reject);
    mock.listen(0, "127.0.0.1", resolve);
  });
  event("localhost_mock_ready");

  service = await startServer(workspace, options.executable, legalDb, { portable: options.portable });
  client = service.client;
  event("daemon_ready");

  const provider = await client.request("/api/v1/ai/providers", "POST", {
    preset: "custom",
    name: "原生草稿合成模型",
    base_url: `http://127.0.0.1:${mock.address().port}/v1`,
    enabled_models: ["draft-audit-model"],
    api_key: "audit-synthetic-key-only",
    trust_raw: false,
    allow_private_network: true
  });
  providerId = provider.id;
  ensure(typeof providerId === "string" && providerId.length > 0, "provider_id_missing");
  await client.request("/api/v1/ai/defaults", "PUT", {
    writing: { provider_id: providerId, model: "draft-audit-model" }
  });

  let initialRun;
  await check("real_daemon_localmock_writing_completed", async () => {
    const started = runValue(await client.request("/api/v1/ai/runs", "POST", {
      kind: "writing",
      prompt: "仅生成合成验收文书。",
      document_type: "合成民事文书",
      requirements: "保留合成金额与日期。",
      provider_id: providerId,
      model: "draft-audit-model",
      materials: [],
      attachment_ids: []
    }));
    ensure(typeof started?.id === "string", "writing_run_id_missing");
    initialRun = await terminal(client, started.id);
    ensureEqual(initialRun.status, "completed", "writing_run_not_completed");
    ensure(typeof initialRun.document_id === "string" && initialRun.document_id.length > 0, "writing_document_id_missing");
  });

  const firstEditContent = "# 合成原生文书\n\nDOC_REVISION_ONE_A17E\n合成金额为 126800 元。";
  const secondEditContent = "# 合成原生文书\n\nDOC_REVISION_TWO_82F1\n合成金额为 126800 元，日期为 2026 年 8 月 11 日。";
  let firstEdit;
  let secondEdit;
  await check("document_id_stable_across_two_content_edits", async () => {
    firstEdit = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(initialRun.id)}/content`, "PUT", {
      expected_revision: initialRun.revision,
      content: firstEditContent
    }));
    secondEdit = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(firstEdit.id)}/content`, "PUT", {
      expected_revision: firstEdit.revision,
      content: secondEditContent
    }));
    ensure(typeof firstEdit.document_id === "string" && typeof secondEdit.document_id === "string", "edited_document_id_missing");
    ensureEqual(firstEdit.document_id, initialRun.document_id, "first_edit_changed_document_id");
    ensureEqual(secondEdit.document_id, initialRun.document_id, "second_edit_changed_document_id");
    ensure(firstEdit.id !== initialRun.id && secondEdit.id !== firstEdit.id, "document_edit_did_not_create_versions");
  });

  const exportDir = path.join(output, "exports");
  await fs.mkdir(exportDir, { recursive: true });
  const exportBytes = {};
  await check("fixed_revision_txt_pdf_docx_exports_without_model_regeneration", async () => {
    const callsBeforeExport = modelCalls;
    for (const format of ["txt", "pdf", "docx"]) {
      exportBytes[format] = await client.request(
        `/api/v1/ai/runs/${encodeURIComponent(secondEdit.id)}/export?${new URLSearchParams({ format, expected_revision: String(secondEdit.revision) })}`,
        "GET",
        undefined,
        true
      );
      await fs.writeFile(path.join(exportDir, `revision-two.${format}`), exportBytes[format]);
    }
    ensureEqual(modelCalls, callsBeforeExport, "export_regenerated_model_output");
    const txt = exportBytes.txt.toString("utf8").replace(/^\uFEFF/u, "").trim();
    const expectedTxt = secondEditContent.replace(/^# /u, "").trim();
    ensureEqual(txt, expectedTxt, "txt_export_content_changed");
    const pdf = exportBytes.pdf;
    ensure(pdf.subarray(0, 5).toString("ascii") === "%PDF-", "pdf_export_header_invalid");
    ensure(pdf.subarray(-256).includes(Buffer.from("%%EOF")), "pdf_export_eof_missing");
    ensure(pdf.length > 1024, "pdf_export_too_small");
    const pdfCheck = String.raw`import json, sys
markers = json.loads(sys.argv[2])
try:
    from pypdf import PdfReader
    text = "\n".join((page.extract_text() or "") for page in PdfReader(sys.argv[1]).pages)
except Exception:
    import fitz
    document = fitz.open(sys.argv[1])
    text = "\n".join(page.get_text() for page in document)
assert markers[0] in text and markers[1] in text and markers[2] not in text
`;
    execFileSync("python", ["-c", pdfCheck, path.join(exportDir, "revision-two.pdf"), JSON.stringify(["DOC_REVISION_TWO_82F1", "126800", "DOC_REVISION_ONE_A17E"])], { windowsHide: true, stdio: "ignore" });
    const docxCheck = String.raw`import sys, zipfile, xml.etree.ElementTree as ElementTree
archive = zipfile.ZipFile(sys.argv[1])
root = ElementTree.fromstring(archive.read("word/document.xml"))
text = "".join(root.itertext())
assert "DOC_REVISION_TWO_82F1" in text and "126800" in text
`;
    execFileSync("python", ["-c", docxCheck, path.join(exportDir, "revision-two.docx")], { windowsHide: true, stdio: "ignore" });
    const repeatedTxt = await client.request(
      `/api/v1/ai/runs/${encodeURIComponent(secondEdit.id)}/export?${new URLSearchParams({ format: "txt", expected_revision: String(secondEdit.revision) })}`,
      "GET",
      undefined,
      true
    );
    ensure(repeatedTxt.equals(exportBytes.txt), "repeated_revision_export_changed_bytes");
  });

  let continuedRun;
  await check("document_id_stable_through_completed_run_continue", async () => {
    const continued = runValue(await client.request(`/api/v1/ai/runs/${encodeURIComponent(secondEdit.id)}/continue`, "POST", {}));
    ensure(typeof continued?.id === "string", "continue_run_id_missing");
    ensureEqual(continued.document_id, initialRun.document_id, "continue_changed_document_id_before_completion");
    continuedRun = await terminal(client, continued.id);
    ensureEqual(continuedRun.status, "completed", "continued_run_not_completed");
    ensureEqual(continuedRun.document_id, initialRun.document_id, "continue_changed_document_id_after_completion");
    ensure(continuedRun.id !== secondEdit.id, "continue_reused_completed_run_id");
  });

  const documentBaseId = `writing-${initialRun.document_id}`;
  const alternateBaseId = "writing-current";
  const candidatePatternFor = baseId => new RegExp(`^${baseId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-c-[0-9a-f]{32}$`, "u");
  const candidatePattern = candidatePatternFor(documentBaseId);
  const alternateCandidatePattern = candidatePatternFor(alternateBaseId);
  const candidateMarkers = ["A_01", "A_02", "A_03"];
  const alternateMarker = "B_01";
  const candidateSuffixes = [
    "0123456789abcdef0123456789abcdef",
    "11111111111111111111111111111111",
    "22222222222222222222222222222222"
  ];
  const alternateSuffix = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const candidateById = new Map();
  let baseDraft;
  await check("draft_conflict_candidates_created_with_stale_cas", async () => {
    baseDraft = await client.request(draftRoute(documentBaseId), "PUT", {
      expected_revision: 0,
      content: draftContent("BASE_A", continuedRun, providerId)
    });
    ensureEqual(baseDraft.revision, 1, "draft_base_revision_not_one");
    for (const [index, marker] of candidateMarkers.entries()) {
      const outcome = await rawRequest(
        client,
        draftRoute(documentBaseId),
        "PUT",
        { expected_revision: 0, content: draftContent(marker, continuedRun, providerId) }
      );
      ensureEqual(outcome.status, 409, "stale_draft_write_did_not_conflict");
      ensureEqual(outcome.value?.error?.code, "revision_conflict", "stale_draft_write_wrong_error");
      const candidateId = `${documentBaseId}-c-${candidateSuffixes[index]}`;
      const candidate = await client.request(draftRoute(candidateId), "PUT", {
        expected_revision: 0,
        content: draftContent(marker, continuedRun, providerId)
      });
      ensureEqual(candidate.id, candidateId, "candidate_write_id_changed");
      ensureEqual(candidate.revision, 1, "candidate_write_revision_not_one");
      ensureEqual(candidate.content.content, `# ${marker}\n\nAUDIT_DRAFT_${marker}`, "candidate_write_body_changed");
      candidateById.set(candidateId, marker);
    }
    const alternateBase = await client.request(draftRoute(alternateBaseId), "PUT", {
      expected_revision: 0,
      content: draftContent("BASE_B", continuedRun, providerId)
    });
    ensureEqual(alternateBase.revision, 1, "alternate_base_revision_not_one");
    const staleAlternate = await rawRequest(client, draftRoute(alternateBaseId), "PUT", {
      expected_revision: 0,
      content: draftContent(alternateMarker, continuedRun, providerId)
    });
    ensureEqual(staleAlternate.status, 409, "alternate_stale_draft_write_did_not_conflict");
    ensureEqual(staleAlternate.value?.error?.code, "revision_conflict", "alternate_stale_draft_wrong_error");
    const alternateCandidateId = `${alternateBaseId}-c-${alternateSuffix}`;
    const alternateCandidate = await client.request(draftRoute(alternateCandidateId), "PUT", {
      expected_revision: 0,
      content: draftContent(alternateMarker, continuedRun, providerId)
    });
    ensureEqual(alternateCandidate.id, alternateCandidateId, "alternate_candidate_write_id_changed");
    ensureEqual(alternateCandidate.revision, 1, "alternate_candidate_write_revision_not_one");
    ensureEqual(alternateCandidate.content.content, `# ${alternateMarker}\n\nAUDIT_DRAFT_${alternateMarker}`, "alternate_candidate_write_body_changed");
  });

  let conflictRows;
  await check("draft_conflict_summary_is_summary_only_and_paged", async () => {
    const collected = await collectConflictPages(client, documentBaseId, candidateMarkers.length, candidatePattern);
    conflictRows = collected.rows;
    ensure(collected.pages.length >= 2, "draft_conflict_candidates_not_paged");
    ensureEqual(new Set(conflictRows.map(row => row.id)).size, candidateMarkers.length, "draft_conflict_candidate_count_invalid");
  });

  await check("draft_conflict_wrong_base_isolation", async () => {
    const alternate = await listConflicts(client, alternateBaseId, 100);
    checkDraftSummaryPage(alternate, 100);
    ensureEqual(alternate.total, 1, "alternate_base_candidate_count_invalid");
    ensure(alternate.drafts.every(row => !conflictRows.some(candidate => candidate.id === row.id)), "draft_candidate_cross_base_leak");
    ensure(alternate.drafts.every(row => alternateCandidatePattern.test(row.id)), "alternate_candidate_wrong_base_key");
    const unrelated = await listConflicts(client, "writing-unrelated-document", 100);
    checkDraftSummaryPage(unrelated, 100);
    ensureEqual(unrelated.total, 0, "unrelated_base_candidate_leak");
    ensureEqual(unrelated.drafts.length, 0, "unrelated_base_drafts_returned");
  });

  const survivingIds = conflictRows.slice(1).map(row => row.id);
  await check("draft_candidate_read_delete_cas", async () => {
    for (const row of conflictRows) {
      const loaded = await client.request(draftRoute(row.id));
      ensureEqual(loaded.id, row.id, "candidate_read_id_changed");
      ensureEqual(loaded.revision, row.revision, "candidate_read_revision_changed");
      const marker = /^# (A_0[1-3])\n\nAUDIT_DRAFT_\1$/u.exec(loaded.content?.content || "")?.[1];
      ensure(candidateMarkers.includes(marker), "candidate_read_body_changed");
      candidateById.set(row.id, marker);
    }
    ensureSetEqual([...candidateById.values()], candidateMarkers, "candidate_read_body_set_changed");
    const target = conflictRows[0];
    const stale = await rawRequest(client, `${draftRoute(target.id)}?expected_revision=${target.revision - 1}`, "DELETE");
    ensureEqual(stale.status, 409, "candidate_delete_stale_revision_not_rejected");
    ensureEqual(stale.value?.error?.code, "revision_conflict", "candidate_delete_stale_wrong_error");
    const deleted = await rawRequest(client, `${draftRoute(target.id)}?expected_revision=${target.revision}`, "DELETE");
    ensureEqual(deleted.status, 200, "candidate_delete_current_revision_failed");
    ensureEqual(deleted.value?.deleted, true, "candidate_delete_response_missing_deleted");
    const missing = await rawRequest(client, draftRoute(target.id), "GET");
    ensureEqual(missing.status, 404, "deleted_candidate_still_readable");
    const afterDelete = await listConflicts(client, documentBaseId, 100);
    checkDraftSummaryPage(afterDelete, 100);
    ensureEqual(afterDelete.total, survivingIds.length, "candidate_delete_did_not_update_summary");
    ensureSetEqual(afterDelete.drafts.map(row => row.id), survivingIds, "candidate_delete_removed_wrong_row");
  });

  await check("draft_candidates_restore_after_same_workspace_reopen", async () => {
    await service.stop();
    service = undefined;
    client = undefined;
    event("daemon_stopped_for_reopen");
    service = await startServer(workspace, options.executable, legalDb, { portable: options.portable });
    client = service.client;
    const restored = await listConflicts(client, documentBaseId, 100);
    checkDraftSummaryPage(restored, 100);
    ensureEqual(restored.total, survivingIds.length, "reopened_candidate_count_changed");
    ensureSetEqual(restored.drafts.map(row => row.id), survivingIds, "reopened_candidate_ids_changed");
    const restoredCandidate = await client.request(draftRoute(survivingIds[0]));
    ensureEqual(restoredCandidate.content.content, `# ${candidateById.get(survivingIds[0])}\n\nAUDIT_DRAFT_${candidateById.get(survivingIds[0])}`, "reopened_candidate_body_changed");
    const restoredBase = await client.request(draftRoute(documentBaseId));
    ensureEqual(restoredBase.revision, 1, "reopened_base_revision_changed");
    const health = await client.request("/api/v1/health");
    ensureEqual(health.status, "ready", "reopened_daemon_not_ready");
  });
} catch (error) {
  failure = error;
  report.failure = { code: failureCode(error) };
} finally {
  if (service) {
    await service.stop().catch(error => event("daemon_stop_failed", { error: failureCode(error) }));
    service = undefined;
  }
  if (mock) {
    await new Promise(resolve => mock.close(resolve)).catch(error => event("mock_stop_failed", { error: failureCode(error) }));
    mock = undefined;
  }
  report.model.calls = modelCalls;
  report.completed_at = new Date().toISOString();
  report.status = failure ? "failed" : "passed";
  report.passed = !failure;
  report.summary = {
    passed: report.checks.filter(item => item.status === "passed").length,
    failed: report.checks.filter(item => item.status === "failed").length,
    total: report.checks.length
  };
  report.resources = report.resources || {
    kind: "synthetic_database_setup_failed",
    legal_db: { path: legalDb, sha256: await optionalSha256(legalDb) }
  };
  report.logs = {
    audit: { path: auditLogPath },
    server: { path: serverLogPath, sha256: await optionalSha256(serverLogPath) }
  };
  await fs.writeFile(auditLogPath, `${report.events.map(item => JSON.stringify(item)).join("\n")}\n`, "utf8");
  report.logs.audit.sha256 = await sha256(auditLogPath);
  report.source.hashes.executable = await optionalSha256(options.executable);
  report.source.status = gitValue("status", "--short");
  await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  const outputLine = { status: report.status, report: reportPath, checks: report.summary, model_calls: modelCalls };
  if (failure) console.error(JSON.stringify(outputLine));
  else console.log(JSON.stringify(outputLine));
  if (failure) process.exitCode = 1;
}
