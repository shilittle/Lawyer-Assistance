from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "apps" / "desktop" / "src-tauri" / "resources" / "THIRD_PARTY_NOTICES.txt"
NOTICE_NAMES = re.compile(r"^(licen[cs]e|copying|copyright|notice)([._-].*)?$", re.IGNORECASE)

ALLOC_STDLIB_BSD = """Copyright (c) 2016 Dropbox, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""

UNIC_MIT = """Copyright 2017-2019 The UNIC Project Developers.

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE."""

WEBVIEW2_MIT = """MIT License

Copyright (c) 2021 Bill Avery

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    license_expression: str
    source: str
    texts: tuple[tuple[str, str], ...]


def canonical_text_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    canonical = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_notice_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).strip()


def readable_notices(directory: Path) -> tuple[tuple[str, str], ...]:
    notices: list[tuple[str, str]] = []
    if not directory.is_dir():
        return ()
    for candidate in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
        if not candidate.is_file() or not NOTICE_NAMES.match(candidate.name):
            continue
        try:
            text = normalize_notice_text(candidate.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            continue
        if text:
            notices.append((candidate.name, text))
    return tuple(notices)


def cargo_components() -> list[Component]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--filter-platform",
        "x86_64-pc-windows-msvc",
        "--format-version",
        "1",
    ]
    metadata = json.loads(
        subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
    )
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == "lawyer-assistance-desktop"
    ]
    if len(roots) != 1:
        raise RuntimeError("cannot identify the Lawyer Assistance desktop Cargo package")
    reachable: set[str] = set()
    pending = roots
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes_by_id[package_id]
        for dependency in node.get("deps", []):
            kinds = dependency.get("dep_kinds", [])
            if kinds and all(kind.get("kind") == "dev" for kind in kinds):
                continue
            pending.append(dependency["pkg"])

    components: list[Component] = []
    for package_id in sorted(reachable):
        package = packages_by_id[package_id]
        if not str(package.get("source", "")).startswith("registry+"):
            continue
        name, version = str(package["name"]), str(package["version"])
        directory = Path(package["manifest_path"]).parent
        license_expression = str(package.get("license") or "").strip()
        license_file = package.get("license_file")
        texts = list(readable_notices(directory))
        if license_file:
            license_path = Path(str(license_file))
            if license_path.is_file() and all(name != license_path.name for name, _ in texts):
                texts.append(
                    (
                        license_path.name,
                        normalize_notice_text(license_path.read_text(encoding="utf-8")),
                    )
                )
        if not license_expression and not texts:
            raise RuntimeError(f"Cargo dependency {name} {version} has neither license metadata nor notice text")
        components.append(
            Component(
                "Rust",
                name,
                version,
                license_expression or "see bundled license text",
                str(package.get("repository") or package.get("homepage") or "crates.io"),
                tuple(texts),
            )
        )
    return components


def npm_package_directories() -> list[Path]:
    desktop_modules = ROOT / "apps" / "desktop" / "node_modules"
    app_manifest_path = ROOT / "apps" / "desktop" / "package.json"
    app_manifest = json.loads(app_manifest_path.read_text(encoding="utf-8"))
    pending: list[tuple[Path, str, bool]] = [
        (desktop_modules, name, False)
        for name in sorted(app_manifest.get("dependencies", {}))
    ]
    candidates: dict[Path, Path] = {}
    while pending:
        owner, name, optional = pending.pop()
        parts = name.split("/")
        search_paths = [
            owner.joinpath(*parts),
            owner.joinpath("node_modules", *parts),
            owner.parent.joinpath(*parts),
            desktop_modules.joinpath(*parts),
        ]
        dependency = next((candidate for candidate in search_paths if candidate.is_dir()), None)
        if dependency is None:
            if optional:
                continue
            raise RuntimeError(f"npm production dependency is not installed: {name}")
        directory = dependency.resolve()
        if directory in candidates:
            continue
        candidates[directory] = directory
        manifest_path = directory / "package.json"
        if not manifest_path.is_file():
            raise RuntimeError(f"npm package manifest is missing: {directory}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pending.extend(
            (directory, child_name, False)
            for child_name in sorted(manifest.get("dependencies", {}))
        )
        pending.extend(
            (directory, child_name, True)
            for child_name in sorted(manifest.get("optionalDependencies", {}))
        )
    return sorted(candidates.values())


def npm_components() -> list[Component]:
    components: dict[tuple[str, str], Component] = {}
    for directory in npm_package_directories():
        manifest_path = directory / "package.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        name, version = str(manifest.get("name", "")).strip(), str(manifest.get("version", "")).strip()
        if not name or not version:
            continue
        license_value = manifest.get("license") or manifest.get("licenses") or ""
        if isinstance(license_value, list):
            license_expression = " OR ".join(
                str(value.get("type", value)) if isinstance(value, dict) else str(value)
                for value in license_value
            )
        elif isinstance(license_value, dict):
            license_expression = str(license_value.get("type", ""))
        else:
            license_expression = str(license_value)
        repository = manifest.get("repository", "npmjs.com")
        if isinstance(repository, dict):
            repository = repository.get("url", "npmjs.com")
        texts = readable_notices(directory)
        if not license_expression and not texts:
            raise RuntimeError(f"npm dependency {name} {version} has neither license metadata nor notice text")
        components[(name, version)] = Component(
            "JavaScript",
            name,
            version,
            license_expression or "see bundled license text",
            str(repository),
            texts,
        )
    return list(components.values())


def complete_missing_license_texts(components: list[Component]) -> list[Component]:
    apache = next(
        (
            body
            for component in components
            for _, body in component.texts
            if body.lstrip().startswith("Apache License") and "Version 2.0" in body[:200]
        ),
        None,
    )
    mpl = next(
        (
            body
            for component in components
            for _, body in component.texts
            if body.lstrip().startswith("Mozilla Public License Version 2.0")
        ),
        None,
    )
    if apache is None or mpl is None:
        raise RuntimeError("canonical Apache-2.0 or MPL-2.0 license text is unavailable")

    unic_packages = {
        "unic-char-property",
        "unic-char-range",
        "unic-common",
        "unic-ucd-ident",
        "unic-ucd-version",
    }
    completed: list[Component] = []
    for component in components:
        texts = component.texts
        if not texts and component.name == "alloc-stdlib" and component.version == "0.2.4":
            texts = (("UPSTREAM-LICENSE-BSD-3-Clause", ALLOC_STDLIB_BSD),)
        elif not texts and component.name == "selectors" and component.version == "0.36.1":
            texts = (("SPDX-MPL-2.0", mpl),)
        elif not texts and component.name in unic_packages and component.version == "0.9.0":
            texts = (("UPSTREAM-LICENSE-MIT", UNIC_MIT), ("SPDX-Apache-2.0", apache))
        elif not texts and component.name in {
            "webview2-com",
            "webview2-com-macros",
            "webview2-com-sys",
        }:
            texts = (("UPSTREAM-LICENSE-MIT", WEBVIEW2_MIT),)
        if not texts:
            raise RuntimeError(
                f"{component.ecosystem} dependency {component.name} {component.version} "
                "has no bundled license or notice text"
            )
        completed.append(
            Component(
                component.ecosystem,
                component.name,
                component.version,
                component.license_expression,
                component.source,
                texts,
            )
        )
    return completed


def render() -> str:
    cargo_lock = ROOT / "Cargo.lock"
    pnpm_lock = ROOT / "pnpm-lock.yaml"
    components = cargo_components() + npm_components()
    vendor = ROOT / "vendor" / "minisign-verify"
    components.append(
        Component(
            "Vendored Rust",
            "minisign-verify",
            "0.2.5",
            "MIT",
            "https://github.com/jedisct1/rust-minisign-verify",
            readable_notices(vendor),
        )
    )
    components = complete_missing_license_texts(components)
    components.sort(key=lambda item: (item.ecosystem, item.name.casefold(), item.version))

    text_ids: dict[str, str] = {}
    text_bodies: dict[str, str] = {}
    component_rows: list[str] = []
    for component in components:
        references: list[str] = []
        for filename, body in component.texts:
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            identifier = text_ids.setdefault(digest, f"L{len(text_ids) + 1:04d}")
            text_bodies.setdefault(identifier, body)
            references.append(f"{filename}:{identifier}")
        component_rows.append(
            " | ".join(
                [
                    component.ecosystem,
                    f"{component.name} {component.version}",
                    component.license_expression,
                    component.source,
                    ", ".join(references),
                ]
            )
        )

    lines = [
        "LAWYER ASSISTANCE THIRD-PARTY SOFTWARE NOTICES",
        "",
        "This file is generated from the exact Rust and JavaScript dependency installations.",
        f"Cargo.lock SHA-256: {canonical_text_sha256(cargo_lock)}",
        f"pnpm-lock.yaml SHA-256: {canonical_text_sha256(pnpm_lock)}",
        f"Components: {len(components)}; unique bundled notice texts: {len(text_bodies)}",
        "",
        "COMPONENT INDEX",
        "Ecosystem | Component | Declared license | Upstream | Bundled texts",
        *component_rows,
        "",
        "BUNDLED LICENSE AND NOTICE TEXTS",
    ]
    for identifier in sorted(text_bodies):
        lines.extend(["", f"===== {identifier} =====", text_bodies[identifier]])
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    expected = render()
    if arguments.check:
        actual = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if actual != expected:
            print("THIRD_PARTY_NOTICES.txt is stale; regenerate it", file=sys.stderr)
            return 1
        print(f"verified {OUTPUT}")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8", newline="\n")
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
