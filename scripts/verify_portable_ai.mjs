// Verify the extracted release using its own executables and local dependencies.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { root, startServer, configureGlm, check, sleep } from './ai_test_client.mjs';

const packageDir = path.resolve(process.argv[2] || '');
check(process.argv[2], 'extracted_package_directory_required');
const output = path.resolve(root, process.argv[3] || 'output/ai-upgrade-portable');
fs.mkdirSync(output, { recursive: true });
const dataDir = path.join(output, 'workspace');
const executable = path.join(packageDir, 'lawyer-assistance.exe');
const legalDb = path.join(packageDir, 'data/runtime/legal_core.sqlite');
const report = { started_at: new Date().toISOString(), model: 'glm-5.3-flash', checks: [], package_dir: packageDir };
const resumeMaterial = process.argv.includes('--resume-material');
if (resumeMaterial) {
  report.previous_attempt = JSON.parse(fs.readFileSync(path.join(output, 'portable-report.json'), 'utf8'));
}
let session;
const record = (name, detail = {}) => { report.checks.push({ name, ...detail }); console.log(JSON.stringify(report.checks.at(-1))); };
const save = () => fs.writeFileSync(path.join(output, 'portable-report.json'), JSON.stringify(report, null, 2));
try {
  for (const relative of ['tools/typst.exe', 'tools/pdfium.dll', 'tools/fonts/SourceHanSerifSC-Regular.otf', 'tools/fonts/SourceHanSerifSC-Bold.otf']) {
    check(fs.statSync(path.join(packageDir, relative)).size > 0, `missing_${relative}`);
  }
  session = await startServer(dataDir, executable, legalDb, { portable: true });
  let client = session.client;
  const health = await client.request('/api/v1/health');
  record('release_started_without_development_runtime_environment', { health });
  let materialId;
  if (resumeMaterial) {
    materialId = JSON.parse(fs.readFileSync(path.join(output, 'material.json'), 'utf8')).id;
  } else {
  await configureGlm(client);
  const materials = JSON.parse(fs.readFileSync(path.join(root, 'output/ai-upgrade-fixtures/manifest.json'), 'utf8')).materials;
  const fixture = materials.find(m => m.case_id === 'C01' && m.path.endsWith('_text_layer.pdf'));
  check(fixture, 'pdf_fixture_missing');
  const group = await client.request('/api/v1/groups', 'POST', { name: '便携包实际验收' });
  const form = new FormData();
  form.set('group_id', group.id);
  form.set('request_id', `portable-${Date.now()}`);
  form.append('files', new Blob([fs.readFileSync(path.join(root, 'output/ai-upgrade-fixtures', fixture.path))]), path.basename(fixture.path));
  const task = await client.request('/api/v1/imports', 'POST', form);
  materialId = task.materials[0].id;
  }
  let material;
  const started = Date.now();
  do {
    material = await client.request(`/api/v1/materials/${materialId}`);
    if (!['queued', 'running'].includes(material.status)) break;
    await sleep(1500);
  } while (Date.now() - started < 900000);
  fs.writeFileSync(path.join(output, 'material.json'), JSON.stringify(material, null, 2));
  record('pdf_ocr_redaction', { status: material.status, reason: material.reason_code, elapsed_ms: Date.now() - started });
  if (material.status === 'needs_review') {
    const unresolved = material.analysis.findings.filter(f => !f.resolved && !f.dismissed);
    // The original synthetic C01 source has been read during independent QA. These exact
    // procedural role labels are ordinary text, not names or sensitive identifiers.
    check(unresolved.length > 0 && unresolved.every(f => f.kind === 'custom' && ['原告', '被告'].includes(f.text)), 'portable_review_requires_independent_inspection');
    material = await client.request(`/api/v1/materials/${materialId}/review`, 'POST', {
      revision: material.revision, dictionary: [], dismissed: unresolved.map(f => f.id),
    });
    record('explicit_review_of_nonsensitive_procedural_role', { labels: unresolved.map(f => f.text), status: material.status });
  }
  check(material.status === 'ready', 'portable_pdf_not_ready');
  const redacted = await client.request(`/api/v1/results/${material.result_id}/export?format=txt`, 'GET', undefined, true);
  fs.writeFileSync(path.join(output, 'redacted.txt'), redacted);
  check(material.analysis?.findings.some(f => f.source === 'ai'), 'verified_ai_review_evidence_missing');
  material = await client.request(`/api/v1/materials/${materialId}/review`, 'POST', {
    revision: material.revision, dictionary: [], dismissed: material.analysis.findings.filter(f => f.dismissed).map(f => f.id),
  });
  check(material.status === 'ready', 'review_lost_ready_result');
  const reviewed = await client.request(`/api/v1/results/${material.result_id}/export?format=txt`, 'GET', undefined, true);
  check(reviewed.equals(redacted), 'review_changed_verified_ai_redaction');
  record('manual_review_preserves_verified_ai_entities');
  const selectable = await client.request('/api/v1/ai/materials');
  check(selectable.materials.some(m => m.id === materialId && m.result_id), 'completed_material_not_selectable');
  const created = await client.request('/api/v1/ai/runs', 'POST', {
    kind: 'writing', document_type: '催款函', materials: [{ id: materialId, source: 'redacted' }],
    prompt: '根据所选虚构买卖合同材料，为出卖人撰写不超过600字的催款函。先在本地法律库查找价款支付义务及违约责任，阅读至少一条原文即可成文；缺失事实写待补充，保留材料已有的金额和日期。',
  });
  let run = await client.waitRun(created.id);
  if (run.status === 'paused') {
    const continued = await client.request(`/api/v1/ai/runs/${run.id}/continue`, 'POST', {});
    run = await client.waitRun(continued.id);
  }
  fs.writeFileSync(path.join(output, 'writing.json'), JSON.stringify(run, null, 2));
  record('selected_redacted_material_writing', { id: run.id, status: run.status, citations: run.citations.length, tools: run.tool_steps.length });
  check(run.status === 'completed' && run.citations.length > 0, 'portable_writing_failed');
  const beforeExport = await client.request('/api/v1/ai/usage');
  for (const format of ['txt', 'docx', 'pdf']) {
    const bytes = await client.request(`/api/v1/ai/runs/${run.id}/export?format=${format}`, 'GET', undefined, true);
    fs.writeFileSync(path.join(output, `writing.${format}`), bytes);
    check(bytes.length > 100, `portable_${format}_empty`);
    if (format === 'pdf') check(bytes.subarray(0, 5).toString() === '%PDF-', 'portable_pdf_header_invalid');
    record('stored_document_export', { format, bytes: bytes.length });
  }
  check(JSON.stringify(beforeExport) === JSON.stringify(await client.request('/api/v1/ai/usage')), 'export_called_model');
  record('export_does_not_generate_again');
  const caseTask = await client.request('/api/v1/ai/runs', 'POST', {
    kind: 'search',
    prompt: '这是一项独立案例库验收：请用案例检索工具查找指导案例279号，读取完整案例，简述该案争议和裁判要点，并引用至少一段核验过的案例原文。不要与其他案件材料混合，也不必检索更多案例。',
  });
  const caseRun = await client.waitRun(caseTask.id);
  fs.writeFileSync(path.join(output, 'case-ai-search.json'), JSON.stringify(caseRun, null, 2));
  check(caseRun.status === 'completed' && caseRun.citations.length > 0, 'new_case_archive_ai_search_failed');
  check(caseRun.tool_steps.some(step => step.name === 'legal_search_cases' || step.tool === 'legal_search_cases'), 'case_tool_not_called');
  record('ai_reads_new_spc_archive', { status: caseRun.status, tools: caseRun.tool_steps.length, citations: caseRun.citations.length });
  await session.stop(); session = null;
  session = await startServer(dataDir, executable, legalDb, { portable: true });
  client = session.client;
  const reopened = await client.request(`/api/v1/ai/runs/${run.id}`);
  check(reopened.content === run.content && reopened.status === 'completed', 'history_restart_mismatch');
  check((await client.request(`/api/v1/materials/${materialId}`)).result_id === material.result_id, 'material_restart_mismatch');
  record('restart_preserves_material_and_writing_history');
  const log = fs.openSync(path.join(output, 'cases-mcp.log'), 'w');
  const process = spawn(globalThis.process.execPath, [path.join(root, 'scripts/smoke_cases.mjs'), '--data-dir', dataDir, '--legal-db', legalDb, '--binary', path.join(packageDir, 'lawyer-assistance-mcp.exe'), '--archive', 'true'], { windowsHide: true, cwd: packageDir, stdio: ['ignore', log, log] });
  const code = await new Promise(resolve => process.once('exit', resolve)); fs.closeSync(log);
  check(code === 0, 'portable_cases_mcp_failed'); record('spc_case_archive_http_and_mcp');
  report.usage = await client.request('/api/v1/ai/usage');
  report.completed_at = new Date().toISOString();
} catch (error) { report.error = error.message; process.exitCode = 1; console.error(error.message); }
finally { if (session) await session.stop(); save(); }
