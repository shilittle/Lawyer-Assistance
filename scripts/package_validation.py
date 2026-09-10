"""Package an explicit QA evidence inventory, excluding all test/user workspaces."""
from pathlib import Path
import hashlib
import json
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# Explicit 1.2.1 repair inventory. Missing final evidence fails packaging; no old
# 1.2.0 success reports are silently reused as current validation.
FILES = [
    'docs/web/audit-1.2.1.md',
    'docs/web/audit-1.2.1-contracts.md',
    'docs/web/ai-upgrade.md',
    'work/audit-repair/original-evidence/original-review.zip',
    'work/audit-repair/original-evidence/original-review.md',
    'work/audit-repair/original-evidence/baseline-manifest-check.json',
    'work/audit-repair/stage2-tests-final.log',
    'work/audit-repair/stage2-clippy-final.log',
    'work/audit-repair/final-rust-tests.log',
    'work/audit-repair/final-clippy.log',
    'work/audit-repair/final-format.log',
    'work/audit-repair/final-web.log',
    'work/audit-repair/final-python.log',
    'work/audit-repair/final-native-pdfium.log',
    'work/audit-repair/final-formal-tests.log',
    'work/audit-repair/final-notices.log',
    'work/audit-repair/final-command-results.json',
    'work/audit-repair/final-build.log',
    'work/audit-repair/final-native-suite.log',
    'work/audit-repair/final-paged-benchmark.log',
    'work/audit-repair/final-packaging.log',
    'work/audit-repair/ui-regression/report.json',
    'work/audit-repair/native-smoke/report.json',
    'work/audit-repair/native-smoke/document-native.png',
    'work/audit-repair/search-native/report.json',
    'work/audit-repair/capacity-native/report.json',
    'work/audit-repair/ai-capacity-native/report.json',
    'work/audit-repair/index-equivalence/report.json',
    'work/audit-repair/document-worker-native/report.json',
    'work/audit-repair/context-citations-native/report.json',
    'work/audit-repair/portable-final/report.json',
    'work/audit-repair/portable-final/inventory.log',
    'work/audit-repair/portable-final/version.log',
    'work/audit-repair/portable-final/web-smoke.log',
    'work/audit-repair/portable-final/mcp-smoke.log',
    'work/audit-repair/portable-final/document-worker.log',
    'work/audit-repair/portable-final/writing-smoke.log',
    'work/audit-repair/paged-benchmark/baseline_stage1/report.json',
    'work/audit-repair/paged-benchmark/candidate_stage2/report.json',
    'work/audit-repair/paged-benchmark/candidate_stage2_quiet/report.json',
    'work/audit-repair/paged-benchmark/candidate_release/report.json',
    'scripts/audit_ui_regression.mjs',
    'scripts/audit_native_smoke.mjs',
    'scripts/audit_search_native.mjs',
    'scripts/audit_capacity_native.mjs',
    'scripts/audit_ai_capacity_native.mjs',
    'scripts/audit_index_equivalence.mjs',
    'scripts/audit_document_worker_native.mjs',
    'scripts/audit_context_citations_native.mjs',
    'scripts/audit_paged_benchmark.mjs',
    'scripts/audit_portable_final.mjs',
    'scripts/ai_test_client.mjs',
    'scripts/smoke_web.mjs',
    'scripts/smoke_mcp.mjs',
    'scripts/audit_validate.py',
    'scripts/package_validation.py',
]


def main():
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
    key_file = ROOT / 'apikey.txt'
    keys = [s.strip().encode() for s in key_file.read_text(encoding='utf-8-sig').splitlines() if len(s.strip()) > 32] if key_file.exists() else []
    payload = {}
    for name in FILES:
        source = (ROOT / name).resolve()
        if not source.is_relative_to(ROOT) or not source.is_file() or source.is_symlink():
            raise ValueError(f'Missing or unsafe QA evidence: {name}')
        content = source.read_bytes()
        if any(key in content for key in keys):
            raise ValueError(f'Credential matched QA evidence: {name}')
        payload[name] = content
    payload['EVIDENCE_MANIFEST.json'] = (json.dumps({
        'version': version,
        'note': 'Local 1.2.1 repair candidate. Synthetic evaluation and public-corpus benchmarks; includes original audit inputs and clearly labelled failed iterations. No user workspace, confidential attachments, API keys or raw model messages. Original crash root cause is not established.',
        'files': [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in payload.items()],
    }, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    out = ROOT / 'dist'
    out.mkdir(exist_ok=True)
    base = f'Lawyer-Assistance_{version}_validation'
    archive = out / f'{base}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(f'{base}/{name}', (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, data)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(json.dumps({'archive': str(archive), 'files': len(payload), 'bytes': archive.stat().st_size, 'sha256': digest}))


if __name__ == '__main__':
    main()
