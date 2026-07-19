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
FONT_ASSET_DIR = ROOT / "crates" / "material-processing" / "assets" / "fonts"
SAFE_EXPORT_FONT_SHA256 = "c7763f454946833081cc90e73186615f8e1189de9c5e5a5a8752871fd79fddbc"
NOTICE_NAMES = re.compile(r"^(licen[cs]e|copying|copyright|notice)([._-].*)?$", re.IGNORECASE)
CARGO_RELEASE_TARGET_PRODUCTS: tuple[tuple[str, frozenset[str]], ...] = (
    ("x86_64-pc-windows-msvc", frozenset({"lawyer-assistance-desktop", "legal-mcp"})),
    ("x86_64-unknown-linux-gnu", frozenset({"legal-mcp"})),
    ("aarch64-apple-darwin", frozenset({"legal-mcp"})),
)

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

CC0_1_0 = """Creative Commons Legal Code

CC0 1.0 Universal

    CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
    LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
    ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
    INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
    REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
    PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
    THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
    HEREUNDER.

Statement of Purpose

The laws of most jurisdictions throughout the world automatically confer
exclusive Copyright and Related Rights (defined below) upon the creator
and subsequent owner(s) (each and all, an "owner") of an original work of
authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for
the purpose of contributing to a commons of creative, cultural and
scientific works ("Commons") that the public can reliably and without fear
of later claims of infringement build upon, modify, incorporate in other
works, reuse and redistribute as freely as possible in any form whatsoever
and for any purposes, including without limitation commercial purposes.
These owners may contribute to the Commons to promote the ideal of a free
culture and the further production of creative, cultural and scientific
works, or to gain reputation or greater distribution for their Work in
part through the use and efforts of others.

For these and/or other purposes and motivations, and without any
expectation of additional consideration or compensation, the person
associating CC0 with a Work (the "Affirmer"), to the extent that he or she
is an owner of Copyright and Related Rights in the Work, voluntarily
elects to apply CC0 to the Work and publicly distribute the Work under its
terms, with knowledge of his or her Copyright and Related Rights in the
Work and the meaning and intended legal effect of CC0 on those rights.

1. Copyright and Related Rights. A Work made available under CC0 may be
protected by copyright and related or neighboring rights ("Copyright and
Related Rights"). Copyright and Related Rights include, but are not
limited to, the following:

  i. the right to reproduce, adapt, distribute, perform, display,
     communicate, and translate a Work;
 ii. moral rights retained by the original author(s) and/or performer(s);
iii. publicity and privacy rights pertaining to a person's image or
     likeness depicted in a Work;
 iv. rights protecting against unfair competition in regards to a Work,
     subject to the limitations in paragraph 4(a), below;
  v. rights protecting the extraction, dissemination, use and reuse of data
     in a Work;
 vi. database rights (such as those arising under Directive 96/9/EC of
     the European Parliament and of the Council of 11 March 1996 on the
     legal protection of databases, and under any national implementation
     thereof, including any amended or successor version of such
     directive); and
vii. other similar, equivalent or corresponding rights throughout the
     world based on applicable law or treaty, and any national
     implementations thereof.

2. Waiver. To the greatest extent permitted by, but not in contravention
of, applicable law, Affirmer hereby overtly, fully, permanently,
irrevocably and unconditionally waives, abandons, and surrenders all of
Affirmer's Copyright and Related Rights and associated claims and causes
of action, whether now known or unknown (including existing as well as
future claims and causes of action), in the Work (i) in all territories
worldwide, (ii) for the maximum duration provided by applicable law or
treaty (including future time extensions), (iii) in any current or future
medium and for any number of copies, and (iv) for any purpose whatsoever,
including without limitation commercial, advertising or promotional
purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
member of the public at large and to the detriment of Affirmer's heirs and
successors, fully intending that such Waiver shall not be subject to
revocation, rescission, cancellation, termination, or any other legal or
equitable action to disrupt the quiet enjoyment of the Work by the public
as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback. Should any part of the Waiver for any reason be
judged legally invalid or ineffective under applicable law, then the
Waiver shall be preserved to the maximum extent permitted taking into
account Affirmer's express Statement of Purpose. In addition, to the
extent the Waiver is so judged Affirmer hereby grants to each affected
person a royalty-free, non transferable, non sublicensable, non exclusive,
irrevocable and unconditional license to exercise Affirmer's Copyright and
Related Rights in the Work (i) in all territories worldwide, (ii) for the
maximum duration provided by applicable law or treaty (including future
time extensions), (iii) in any current or future medium and for any number
of copies, and (iv) for any purpose whatsoever, including without
limitation commercial, advertising or promotional purposes (the
"License"). The License shall be deemed effective as of the date CC0 was
applied by Affirmer to the Work. Should any part of the License for any
reason be judged legally invalid or ineffective under applicable law, such
partial invalidity or ineffectiveness shall not invalidate the remainder
of the License, and in such case Affirmer hereby affirms that he or she
will not (i) exercise any of his or her remaining Copyright and Related
Rights in the Work or (ii) assert any associated claims and causes of
action with respect to the Work, in either case contrary to Affirmer's
express Statement of Purpose.

4. Limitations and Disclaimers.

 a. No trademark or patent rights held by Affirmer are waived, abandoned,
    surrendered, licensed or otherwise affected by this document.
 b. Affirmer offers the Work as-is and makes no representations or
    warranties of any kind concerning the Work, express, implied,
    statutory or otherwise, including without limitation warranties of
    title, merchantability, fitness for a particular purpose, non
    infringement, or the absence of latent or other defects, accuracy, or
    the present or absence of errors, whether or not discoverable, all to
    the greatest extent permissible under applicable law.
 c. Affirmer disclaims responsibility for clearing rights of other persons
    that may apply to the Work or any use thereof, including without
    limitation any person's Copyright and Related Rights in the Work.
    Further, Affirmer disclaims responsibility for obtaining any necessary
    consents, permissions or other rights required for any use of the Work.
 d. Affirmer understands and acknowledges that Creative Commons is not a
    party to this document and has no duty or obligation with respect to
    this CC0 or use of the Work."""


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


def bundled_asset_components() -> list[Component]:
    font_path = FONT_ASSET_DIR / "NotoSansSC-Regular.ttf"
    if not font_path.is_file():
        raise RuntimeError("bundled safe-export font is missing")
    digest = hashlib.sha256(font_path.read_bytes()).hexdigest()
    if digest != SAFE_EXPORT_FONT_SHA256:
        raise RuntimeError("bundled safe-export font SHA-256 does not match the reviewed binary")
    texts = readable_notices(FONT_ASSET_DIR)
    text_names = {name for name, _ in texts}
    required = {"LICENSE-OFL-1.1.txt", "NOTICE-NOTO-SANS-SC.txt"}
    if not required.issubset(text_names):
        raise RuntimeError("bundled safe-export font license or notice is missing")
    return [
        Component(
            "Bundled Font",
            "Noto Sans SC Regular",
            "2.004",
            "OFL-1.1",
            "https://github.com/notofonts/noto-cjk/tree/Sans2.004",
            texts,
        )
    ]

def cargo_metadata_for_target(target: str) -> dict:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--filter-platform",
        target,
        "--format-version",
        "1",
    ]
    return json.loads(
        subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
    )


def cargo_components() -> list[Component]:
    packages_by_id: dict[str, dict] = {}
    reachable: set[str] = set()
    for target, product_names in CARGO_RELEASE_TARGET_PRODUCTS:
        metadata = cargo_metadata_for_target(target)
        target_packages_by_id = {package["id"]: package for package in metadata["packages"]}
        nodes_by_id = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        roots = [
            package["id"]
            for package in metadata["packages"]
            if package["name"] in product_names
        ]
        resolved_names = {target_packages_by_id[package_id]["name"] for package_id in roots}
        if resolved_names != product_names:
            raise RuntimeError(f"cannot identify Cargo product packages for {target}")
        target_reachable: set[str] = set()
        pending = list(roots)
        while pending:
            package_id = pending.pop()
            if package_id in target_reachable:
                continue
            target_reachable.add(package_id)
            node = nodes_by_id[package_id]
            for dependency in node.get("deps", []):
                kinds = dependency.get("dep_kinds", [])
                if kinds and all(kind.get("kind") == "dev" for kind in kinds):
                    continue
                pending.append(dependency["pkg"])
        packages_by_id.update(target_packages_by_id)
        reachable.update(target_reachable)

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
        # A resolved pnpm package lives below
        # `.pnpm/<package>/node_modules/<package>`.  Its scoped transitive
        # dependencies are siblings below the *outer* node_modules directory,
        # not children of the resolved package directory.  Walk the bounded
        # ancestor chain so both ordinary npm layouts and pnpm's isolated
        # layout are resolved without assuming a particular store hash.
        search_paths = [owner.joinpath(*parts)]
        for ancestor in (owner, *owner.parents):
            search_paths.append(ancestor.joinpath("node_modules", *parts))
            search_paths.append(ancestor.joinpath(*parts))
            if ancestor == ROOT:
                break
        search_paths.append(desktop_modules.joinpath(*parts))
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
    encoding_index_packages = {
        "encoding-index-japanese",
        "encoding-index-korean",
        "encoding-index-simpchinese",
        "encoding-index-singlebyte",
        "encoding-index-tradchinese",
        "encoding_index_tests",
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
        elif (
            not texts
            and component.name in encoding_index_packages
            and component.license_expression == "CC0-1.0"
        ):
            texts = (("SPDX-CC0-1.0", CC0_1_0),)
        elif not texts and component.name == "genpdf" and component.version == "0.2.0":
            # genpdf offers Apache-2.0 OR MIT.  The package omits both license
            # files from its published crate, so distribute it under the
            # Apache-2.0 option using the canonical text already present in
            # another locked dependency.
            texts = (("SPDX-Apache-2.0", apache),)
        elif not texts and component.name == "tauri-plugin" and component.version == "2.6.3":
            # tauri-plugin offers Apache-2.0 OR MIT.  The published crate omits
            # both license files, so use the canonical Apache-2.0 text already
            # present in this exact locked dependency closure.
            texts = (("SPDX-Apache-2.0", apache),)
        elif not texts and component.license_expression in {
            "Apache-2.0",
            "Apache-2.0 OR MIT",
            "MIT OR Apache-2.0",
            "MIT/Apache-2.0",
        }:
            # Some crates (including rmcp-macros and sse-stream) declare an
            # Apache-2.0 option in their published manifest but omit the
            # duplicate license file. Reuse the canonical Apache text from
            # this exact locked closure and distribute under that option.
            texts = (("SPDX-Apache-2.0", apache),)
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
    components = cargo_components() + npm_components() + bundled_asset_components()
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
        "This file is generated from the exact Rust/JavaScript installations and reviewed bundled assets.",
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
