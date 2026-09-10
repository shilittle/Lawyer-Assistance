#!/usr/bin/env python3
"""Fetch the pinned Windows Pdfium runtime used by the AI OCR pipeline.

The archive is downloaded only into the ignored ``output/runtime-tools`` tree.  The pinned
release and SHA-256 are deliberate: a portable package must never silently load a different
native PDF parser.  The application receives the resulting ``pdfium.dll`` path explicitly and
does not depend on a system Python installation at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from urllib.request import Request, urlopen


PDFIUM_TAG = "chromium/8044"
ARCHIVE_NAME = "pdfium-win-x64.tgz"
DOWNLOAD_URL = (
    "https://github.com/bblanchon/pdfium-binaries/releases/download/"
    f"{PDFIUM_TAG}/{ARCHIVE_NAME}"
)
ARCHIVE_SHA256 = "78a17d9a5f14467631c26a3ac8741b27a0471ecc05bd6a119b523598160a0537"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_LICENSE_BYTES = 8 * 1024 * 1024


class FetchError(RuntimeError):
    """A deterministic fetch or archive-validation failure."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def is_license_member(member: tarfile.TarInfo) -> bool:
    """Return whether an archive member is a text notice we must preserve.

    The upstream archive layout has changed between releases.  Match the root
    notice files and every regular file below a directory named ``licenses``
    instead of depending on one particular directory prefix.
    """

    if not member.isfile():
        return False
    path = PurePosixPath(member.name)
    basename = path.name.lower()
    if basename in {
        "license",
        "license.txt",
        "license.md",
        "copying",
        "notice",
        "notice.txt",
        "notices",
        "version",
    }:
        return True
    return any(part.lower() in {"licenses", "license"} for part in path.parts[:-1])


def read_member_bounded(
    bundle: tarfile.TarFile,
    member: tarfile.TarInfo,
    remaining: int,
) -> bytes:
    if member.size < 0 or member.size > remaining:
        raise FetchError("Pdfium license notices exceed the size limit")
    extracted = bundle.extractfile(member)
    if extracted is None:
        raise FetchError("Pdfium license notice could not be read")
    data = extracted.read(member.size + 1)
    if len(data) != member.size:
        raise FetchError("Pdfium license notice is truncated")
    return data


def fetch(destination: Path) -> Path:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lawyer-assistance-pdfium-") as temporary:
        archive = Path(temporary) / ARCHIVE_NAME
        request = Request(DOWNLOAD_URL, headers={"User-Agent": "Lawyer-Assistance-build"})
        try:
            with urlopen(request, timeout=60) as response, archive.open("wb") as output:
                total = 0
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_ARCHIVE_BYTES:
                        raise FetchError("Pdfium archive exceeds the size limit")
                    output.write(block)
        except FetchError:
            raise
        except OSError as error:
            raise FetchError("Pdfium archive download failed") from error

        if sha256(archive) != ARCHIVE_SHA256:
            raise FetchError("Pdfium archive SHA-256 mismatch")

        dll = destination / "pdfium.dll"
        version = destination / "pdfium.version.json"
        license_file = destination / "pdfium-LICENSE.txt"
        license_members = []
        license_payloads = []
        try:
            with tarfile.open(archive, "r:gz") as bundle:
                candidates = []
                for member in bundle.getmembers():
                    if not safe_member_name(member.name):
                        raise FetchError("Pdfium archive contains an unsafe path")
                    if member.isfile() and PurePosixPath(member.name).name.lower() == "pdfium.dll":
                        candidates.append(member)
                    if is_license_member(member):
                        license_members.append(member)
                if len(candidates) != 1:
                    raise FetchError("Pdfium archive does not contain exactly one DLL")
                if not license_members:
                    raise FetchError("Pdfium archive does not contain upstream license notices")
                extracted = bundle.extractfile(candidates[0])
                if extracted is None:
                    raise FetchError("Pdfium DLL could not be read")
                temporary_dll = Path(temporary) / "pdfium.dll"
                with temporary_dll.open("wb") as output:
                    shutil.copyfileobj(extracted, output, 1024 * 1024)
                license_bytes = 0
                for member in sorted(license_members, key=lambda item: item.name):
                    payload = read_member_bounded(
                        bundle,
                        member,
                        MAX_LICENSE_BYTES - license_bytes,
                    )
                    license_bytes += len(payload)
                    license_payloads.append((member.name, payload))
        except (OSError, tarfile.TarError) as error:
            raise FetchError("Pdfium archive could not be inspected") from error

        if temporary_dll.stat().st_size == 0:
            raise FetchError("Pdfium DLL is empty")
        temporary_license = Path(temporary) / "pdfium-LICENSE.txt"
        with temporary_license.open("wb") as output:
            for name, payload in license_payloads:
                output.write(b"===== Pdfium archive: ")
                output.write(name.encode("utf-8", errors="replace"))
                output.write(b" =====\n")
                output.write(payload.rstrip())
                output.write(b"\n\n")
        if temporary_license.stat().st_size == 0:
            raise FetchError("Pdfium license notices are empty")
        os.replace(temporary_dll, dll)
        os.replace(temporary_license, license_file)
        version.write_text(
            json.dumps(
                {
                    "tag": PDFIUM_TAG,
                    "archive": ARCHIVE_NAME,
                    "url": DOWNLOAD_URL,
                    "archive_sha256": ARCHIVE_SHA256,
                    "dll_sha256": sha256(dll),
                    "license_file": license_file.name,
                    "license_sha256": sha256(license_file),
                    "license_members": [name for name, _ in license_payloads],
                },
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return dll


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path("output") / "runtime-tools",
        help="ignored runtime directory (default: output/runtime-tools)",
    )
    args = parser.parse_args()
    try:
        dll = fetch(args.destination)
    except FetchError as error:
        parser.error(str(error))
    print(dll)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
