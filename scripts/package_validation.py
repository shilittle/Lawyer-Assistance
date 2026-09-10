"""Package an explicit QA evidence inventory, excluding all test/user workspaces."""
from pathlib import Path
import hashlib
import json
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    'docs/web/ai-validation.md', 'docs/web/ai-upgrade.md',
    'data/generated/judicial_cases_manifest.json', 'data/runtime/CASE_DATA_SOURCES.md',
    'output/ai-upgrade-usage.json',
    'output/ai-upgrade-rust-tests-final.log', 'output/ai-upgrade-clippy-final.log',
    'output/ai-upgrade-web-final.log',
    'output/ai-upgrade-formal-tests.log',
    'output/ai-upgrade-regression/regression-report.json',
    'output/ai-upgrade-regression/smoke_web.log', 'output/ai-upgrade-regression/smoke_mcp.log',
    'output/ai-upgrade-legal/final-verification.json',
    'output/ai-upgrade-browser/browser-report.json',
    'output/ai-upgrade-viewport/viewport-report.json',
    'output/ai-upgrade-exports/layout-report.json', 'output/ai-upgrade-exports/visual-review.txt',
    'output/ai-upgrade-live-final/live-report.json', 'output/ai-upgrade-live-final/resume-report.json',
    'output/ai-upgrade-live-final/layout-report.json', 'output/ai-upgrade-live-final/visual-review.md',
    'output/ai-upgrade-live-final/export-refresh-report.json',
    'output/ai-upgrade-semantic-final/semantic-report.json',
    'output/ai-upgrade-semantic-final/semantic-report.md',
    'output/ai-upgrade-semantic-final/manual-assessment.md',
    'output/ai-upgrade-redaction-release/redaction-report.json',
    'output/ai-upgrade-redaction-release/gold-comparison.json',
    'output/ai-upgrade-redaction-release/gold-comparison-report.md',
    'output/ai-upgrade-redaction-repeat3-final/redaction-report.json',
    'output/ai-upgrade-redaction-repeat3-final/gold-comparison-report.md',
    'output/ai-upgrade-redaction-validation/final-independent-diagnostic.md',
    'output/ai-upgrade-response-diagnostic/diagnosis.md',
    'output/ai-upgrade-portable-final/portable-report.json',
    'output/ai-upgrade-portable-final/layout-check.json',
    'output/ai-upgrade-final-unpacked/inventory-report.json',
    'output/github-launcher-dialog-report.json',
    'output/github-release-unpacked/inventory-report.json',
    'output/github-launcher-runtime-report.json',
    'output/github-release-server-tests.log',
    'output/github-release-server-clippy.log',
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
        'note': 'Synthetic evaluation only. Includes failures and review findings; no workspace, original attachments, API keys or cloud raw responses.',
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
