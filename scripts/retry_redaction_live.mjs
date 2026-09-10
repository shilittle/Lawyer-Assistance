// Explicitly resume failed cloud requests in the existing synthetic workspace.
import fs from 'node:fs';
import path from 'node:path';
import { root, startServer, sleep, check } from './ai_test_client.mjs';

const original = path.resolve(root, process.argv[2] || 'output/ai-upgrade-redaction-final');
const output = path.resolve(root, process.argv[3] || 'output/ai-upgrade-redaction-retry');
check(original !== output, 'retry_evidence_directory_must_be_separate');
fs.mkdirSync(output, { recursive: true });
const report = JSON.parse(fs.readFileSync(path.join(original, 'redaction-report.json'), 'utf8'));
check(report.materials.every(m => !['queued', 'running'].includes(m.status)), 'original_batch_still_running');
report.previous_completed_at = report.completed_at;
report.retry_started_at = new Date().toISOString();
for (const material of report.materials) {
  for (const suffix of ['.json', '.txt']) {
    const file = path.join(original, material.material_id + suffix);
    if (fs.existsSync(file)) fs.copyFileSync(file, path.join(output, path.basename(file)));
  }
}
const retryable = new Set(['ai_response_invalid', 'provider_timeout', 'provider_rate_limited', 'provider_network_failed']);
const selected = report.materials.filter(m => m.status === 'failed' && retryable.has(m.reason_code));
const workspaceDir = process.argv[4] ? path.resolve(root, process.argv[4]) : path.join(original, 'workspace');
const session = await startServer(workspaceDir);
const client = session.client;
const save = () => fs.writeFileSync(path.join(output, 'redaction-report.json'), JSON.stringify(report, null, 2));
try {
  for (const material of selected) {
    material.previous_attempt = { status: material.status, reason_code: material.reason_code, elapsed_ms: material.elapsed_ms };
    await client.request(`/api/v1/tasks/${material.task_id}/retry`, 'POST', {});
    material.status = 'queued'; material.retry_submitted_at = Date.now();
  }
  save();
  const started = Date.now();
  while (Date.now() - started < 1800000) {
    for (const material of selected.filter(m => ['queued', 'running'].includes(m.status))) {
      const current = await client.request(`/api/v1/materials/${material.material_id}`);
      material.status = current.status; material.reason_code = current.reason_code;
      if (!['queued', 'running'].includes(current.status)) {
        material.result_id = current.result_id; material.retry_elapsed_ms = Date.now() - material.retry_submitted_at;
        fs.writeFileSync(path.join(output, `${material.material_id}.json`), JSON.stringify(current, null, 2));
        if (current.result_id) {
          const bytes = await client.request(`/api/v1/results/${current.result_id}/export?format=txt`, 'GET', undefined, true);
          fs.writeFileSync(path.join(output, `${material.material_id}.txt`), bytes); material.result_length = bytes.length;
        }
        console.log(JSON.stringify({ path: material.path, status: material.status, reason: material.reason_code, retry_ms: material.retry_elapsed_ms }));
      }
    }
    save();
    if (selected.every(m => !['queued', 'running'].includes(m.status))) break;
    await sleep(1500);
  }
  const ready = report.materials.filter(m => m.status === 'ready');
  for (const material of ready) check((await client.request(`/api/v1/materials/${material.material_id}`)).result_id === material.result_id, 'restart_result_identity_mismatch');
  report.restart_ready_results_checked = ready.length;
  report.completed_at = new Date().toISOString();
  report.retried_materials = selected.length;
} catch (error) { report.errors.push(error.message); process.exitCode = 1; }
finally { report.usage = await client.request('/api/v1/ai/usage'); save(); await session.stop(); }
