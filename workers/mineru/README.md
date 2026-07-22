# Lawyer Assistance local MinerU worker

This directory contains the production `la-mineru-worker-v1` implementation.
It embeds MinerU 3.4.3 in one Windows process and communicates only over
newline-delimited JSON on inherited standard input/output.

Security properties:

- no HTTP server, CLI subprocess, remote model source, or cloud fallback;
- the MinerU PDF render `ProcessPoolExecutor` is replaced with an immediate,
  synchronous executor before MinerU parses a document;
- the host creates the launcher suspended, assigns it to a Windows Job with
  `ActiveProcessLimit=1` and `KillOnJobClose`, re-verifies the bound component
  and firewall evidence, and only then resumes it; `health` binds the exact
  host-enforced Job policy hash without claiming a second in-worker Job query;
- only `input.pdf`, `output/`, and bounded cache directories below the opaque
  job root are used;
- stdout is duplicated for protocol traffic and the original stdout/stderr
  descriptors are redirected to the null device before importing MinerU,
  Torch, Paddle, or OCR models;
- requests reject duplicate and unknown JSON fields and all paths are fixed by
  the protocol rather than supplied by document data;
- MinerU `content_list.json` and `middle.json` remain in the confined job output
  and are independently parsed and hashed again by the Rust host.

The release builder is `scripts/build_production_mineru_worker.py`. It copies a
pinned CPython 3.12.13 runtime, MinerU 3.4.3, PyTorch, exact local model trees,
worker sources, and distribution licenses into one self-contained tree. It
rejects secondary `.exe` files and emits deterministic SBOM, version, and
support manifests. The support manifest binds every staged file; production
trust additionally pins its hash and support-tree identity. The separate
deterministic `.laocrpkg` packager emits an unsigned catalog. Only the release
owner may sign that catalog offline with the project Minisign key. Signature or
support-integrity verification is never bypassed.

Run unit tests without OCR material:

```powershell
python -m unittest discover workers/mineru/tests -v
```

Run the real local synthetic probe after staging a development launcher:

```powershell
python scripts/build_production_mineru_worker.py dev-launcher `
  --python-home C:\path\to\cpython-3.12.13 `
  --site-packages C:\path\to\mineru\Lib\site-packages `
  --pipeline-model C:\path\to\models\pipeline `
  --vlm-model C:\path\to\models\vlm `
  --output .local-mineru-worker
python workers/mineru/scripts/protocol_probe.py `
  --worker .local-mineru-worker\worker\mineru-worker.exe `
  --pdf C:\path\to\synthetic-canary.pdf `
  --tools-config .local-mineru-worker\config.json `
  --model-root C:\path\to\common-model-root `
  --model-manifest .local-mineru-worker\model-manifest.json `
  --runtime-manifest .local-mineru-worker\runtime-manifest.json
```

Only synthetic canaries may be used by the probe. It does not accept a URL and
sets all supported offline flags before the worker starts. Its result contains
only counts, hashes, timings, page confidence, and warning codes (including
`low_resolution` and `low_confidence`); it never prints OCR text.

Build the self-contained, still-unsigned production staging tree:

```powershell
python scripts/build_production_mineru_worker.py stage `
  --python-home C:\path\to\cpython-3.12.13 `
  --site-packages C:\path\to\mineru\Lib\site-packages `
  --pipeline-model C:\path\to\models\pipeline `
  --vlm-model C:\path\to\models\vlm `
  --output C:\fixed-local-disk\mineru-production-stage
```

The development launcher is diagnostic-only and is deliberately not accepted
as a production component. App qualification requires the packaged and signed
self-contained tree, full support-manifest verification, exact model/config/
runtime bindings, Windows Firewall ActiveStore evidence, and the host Job
Object policy. Missing or drifting evidence fails closed; there is no remote
OCR, automatic model download, or cloud fallback.
