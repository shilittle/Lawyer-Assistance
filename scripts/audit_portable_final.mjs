// Verify the generated ZIP and run its actual executables with isolated synthetic data.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { root, startServer } from "./ai_test_client.mjs";

const output = path.join(path.resolve(process.env.LAWYER_AUDIT_OUTPUT || path.join(root, "work/retest-121")), "portable-final");
await fs.mkdir(path.dirname(output), { recursive: true });
// One attempt owns its complete logs, unpacked payload and report.
await fs.mkdir(output);
const directory = await fs.mkdtemp(path.join(output, "unpacked-"));
const archive = path.resolve(process.argv[2]);
const checks = [];
let service;
async function command(program, args, logName) {
  const log = await fs.open(path.join(output, logName), "w");
  const child = spawn(program, args, { cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  const chunks = [];
  for (const stream of [child.stdout, child.stderr]) stream.on("data", data => { chunks.push(data); });
  const status = await new Promise((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
  const bytes = Buffer.concat(chunks); await log.writeFile(bytes); await log.close();
  assert.equal(status, 0, `${program} failed; see ${logName}`);
  return bytes.toString("utf8");
}
try {
  const inventory = JSON.parse(await command("python", ["-c", String.raw`
import hashlib,json,pathlib,sys,zipfile
archive,target=map(pathlib.Path,sys.argv[1:])
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()
assert digest(archive)==archive.with_suffix('.zip.sha256').read_text(encoding='ascii').split()[0]
with zipfile.ZipFile(archive) as z:
 seen=set()
 for info in z.infolist():
  p=pathlib.PurePosixPath(info.filename)
  assert not p.is_absolute() and '..' not in p.parts and chr(92) not in info.filename and ':' not in info.filename
  assert info.filename not in seen
  seen.add(info.filename)
  assert ((info.external_attr >> 16) & 0o170000) != 0o120000
 z.extractall(target)
roots=list(target.iterdir()); assert len(roots)==1 and roots[0].is_dir()
base=roots[0]; expected=set()
for line in (base/'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
 if not line or line.startswith('#'): continue
 checksum,size,relative=line.split(maxsplit=2); source=(base/relative).resolve()
 assert source.is_relative_to(base.resolve()) and source.is_file() and not source.is_symlink()
 assert source.stat().st_nlink==1 and source.stat().st_size==int(size) and digest(source)==checksum
 expected.add(relative)
actual={p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()}
assert actual==expected|{'MANIFEST.sha256'}
manifest=json.loads((base/'portable.manifest.json').read_text(encoding='utf-8'))
assert manifest['version']=='1.2.1'
for relative in actual:
 assert not any(part in {'workspace','credentials','apikey.txt','connection.dpapi'} for part in pathlib.PurePosixPath(relative).parts)
notices=(base/'data/runtime/THIRD_PARTY_NOTICES.txt').read_text(encoding='utf-8')
for crate in ['zune-core 0.4.12','zune-jpeg 0.4.21']:
 line=next(line for line in notices.splitlines() if crate in line)
 assert 'SPDX-Apache-2.0:' in line
assert 'TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION' in notices
print(json.dumps({'package':str(base),'version':manifest['version'],'files_verified':len(expected),'archive_sha256':digest(archive),'zune_license_text':True}))
`, archive, directory], "inventory.log"));
  checks.push("archive_checksum_every_file_inventory_and_zune_license_text");
  const executable = path.join(inventory.package, "lawyer-assistance.exe");
  const version = await command(executable, ["--version"], "version.log");
  assert(version.includes("1.2.1"));
  const fixture = path.join(directory, "synthetic.sqlite");
  await command("python", ["scripts/prepare_web_smoke_db.py", "--output", fixture], "fixture.log");
  const workspace = path.join(directory, "synthetic-workspace");
  service = await startServer(workspace, executable, fixture, { portable: true });
  const health = await service.client.request("/api/v1/health");
  assert.equal(health.status, "ready");
  await command("node", ["scripts/smoke_web.mjs", "--data-dir", workspace, "--require-browser"], "web-smoke.log");
  checks.push("packaged_daemon_web_http_and_chromium");
  await command("node", ["scripts/smoke_mcp.mjs", "--data-dir", workspace, "--legal-db", fixture, "--binary", path.join(inventory.package, "lawyer-assistance-mcp.exe")], "mcp-smoke.log");
  checks.push("packaged_mcp_public_private_http_stdio_and_revocation");
  await service.stop(); service = undefined;
  service = await startServer(path.join(directory, "bundled-corpus-workspace"), executable, undefined, { portable: true, discoverLegalDb: true });
  const bundled = await service.client.request(`/api/v1/legal/search/page?${new URLSearchParams({ query: "民法典第五百七十七条", view: "flat", limit: "20" })}`);
  assert.equal(bundled.totalArticles, 1);
  assert.equal(bundled.totalLaws, 1);
  assert.equal(bundled.appliedQuery.exactArticleNumber, "第五百七十七条");
  checks.push("packaged_default_database_discovery_and_full_corpus_exact_query");
  await service.stop(); service = undefined;
  await command("node", ["scripts/audit_document_worker_native.mjs", executable, "--portable"], "document-worker.log");
  checks.push("packaged_pdfium_worker_selective_ocr_cancel_crash_and_reap");
  await command("node", ["scripts/audit_native_smoke.mjs", executable, "--portable"], "writing-smoke.log");
  checks.push("packaged_writing_editor_draft_and_export");
  const report = { passed: true, checks, ...inventory, unsigned_local_candidate: true, published: false };
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (error) {
  await fs.writeFile(path.join(output, "report.json"), JSON.stringify({ passed: false, checks, error: String(error) }, null, 2));
  console.error(error); process.exitCode = 1;
} finally {
  if (service) await service.stop();
}
