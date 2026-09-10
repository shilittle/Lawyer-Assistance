// Re-export the exact saved writing versions after a renderer change; never generate text.
import fs from 'node:fs';
import path from 'node:path';
import { root, startServer, check } from './ai_test_client.mjs';
const output = path.resolve(root, process.argv[2] || 'output/ai-upgrade-live-final');
const prior = JSON.parse(fs.readFileSync(path.join(output, 'resume-report.json'), 'utf8'));
const session = await startServer(path.join(output, 'workspace'));
const report = { exports: [], started_at: new Date().toISOString() };
try {
  const before = await session.client.request('/api/v1/ai/usage');
  for (const item of prior.exports) {
    const bytes = await session.client.request(`/api/v1/ai/runs/${item.id}/export?format=${item.format}`, 'GET', undefined, true);
    fs.writeFileSync(path.join(output, `verified-${item.id}.${item.format}`), bytes);
    report.exports.push({ ...item, bytes: bytes.length });
  }
  check(JSON.stringify(before) === JSON.stringify(await session.client.request('/api/v1/ai/usage')), 'export_called_model');
  report.no_model_calls = true;
} catch (error) { report.error = error.message; process.exitCode = 1; }
finally {
  await session.stop();
  fs.writeFileSync(path.join(output, 'export-refresh-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
}
