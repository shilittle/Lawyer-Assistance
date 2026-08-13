#!/usr/bin/env python3
"""Verify a Tauri updater signature against the checked-in public key."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__:
    from .verify_release_assets import (
        TAURI_SIGNATURE_COMMENT,
        VerificationError,
        _read_ordinary,
        decode_tauri_signature_envelope,
        verify_minisign,
    )
else:
    from verify_release_assets import (
        TAURI_SIGNATURE_COMMENT,
        VerificationError,
        _read_ordinary,
        decode_tauri_signature_envelope,
        verify_minisign,
    )


def verify_updater_signature(
    artifact: Path,
    signature: Path,
    public_key: Path,
    expected_filename: str,
) -> None:
    if artifact.name != expected_filename or Path(expected_filename).name != expected_filename:
        raise VerificationError(
            "updater_probe_filename",
            "Updater signature probe filename is not exact.",
        )
    content = _read_ordinary(artifact, max_bytes=16 * 1024 * 1024)
    envelope = _read_ordinary(signature, max_bytes=64 * 1024)
    decoded = decode_tauri_signature_envelope(envelope)
    verify_minisign(
        content,
        decoded,
        expected_filename=expected_filename,
        public_key_path=public_key,
        expected_untrusted_comment=TAURI_SIGNATURE_COMMENT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--expected-filename", required=True)
    arguments = parser.parse_args()
    try:
        verify_updater_signature(
            arguments.artifact,
            arguments.signature,
            arguments.public_key,
            arguments.expected_filename,
        )
    except (OSError, VerificationError) as error:
        code = error.code if isinstance(error, VerificationError) else "io_failure"
        print(f"updater signature verification failed [{code}]: {error}", file=sys.stderr)
        return 1
    print("updater signature verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
