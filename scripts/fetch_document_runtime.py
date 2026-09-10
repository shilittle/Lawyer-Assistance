"""Fetch pinned, redistributable PDF export tools into the ignored build output."""
from pathlib import Path
import hashlib
import io
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1] / "output" / "runtime-tools"
TYPST_URL = "https://github.com/typst/typst/releases/download/v0.15.1/typst-x86_64-pc-windows-msvc.zip"
TYPST_SHA = "19ce3551153c2fe7ee9fa2f95208310c8f4d3209fedb699e0333faf8913f6736"
FONT_SHA = {"Regular": "78aa7a328fd974df2d688c8a9fd74a33d8334dfa84ab24d9d11efb2ffc464117", "Bold": "706b8c0de2deff6cbc0c87e2cdedfd33a78b7ffd76cebb4549012f197ba611fe"}

def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "LawyerAssistance-build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()

def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    records = []
    archive = ROOT / "typst-0.15.1.zip"
    data = archive.read_bytes() if archive.exists() else fetch(TYPST_URL)
    if hashlib.sha256(data).hexdigest() != TYPST_SHA:
        raise RuntimeError("Typst archive checksum mismatch")
    archive.write_bytes(data)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if name.endswith("/typst.exe"):
                (ROOT / "typst.exe").write_bytes(z.read(name))
    records.append({"component": "Typst", "path":"typst.exe", "sha256":hashlib.sha256((ROOT / "typst.exe").read_bytes()).hexdigest(), "version": "0.15.1", "url": TYPST_URL, "archive_sha256": TYPST_SHA})
    fonts = ROOT / "fonts"
    fonts.mkdir(exist_ok=True)
    for weight in ["Regular", "Bold"]:
        name = f"SourceHanSerifSC-{weight}.otf"
        url = f"https://raw.githubusercontent.com/adobe-fonts/source-han-serif/2.003R/OTF/SimplifiedChinese/{name}"
        dest = fonts / name
        if not dest.exists():
            dest.write_bytes(fetch(url))
        if hashlib.sha256(dest.read_bytes()).hexdigest() != FONT_SHA[weight]:
            raise RuntimeError("font checksum mismatch")
        records.append({"component": name, "path":f"fonts/{name}", "version": "2.003R", "url": url, "sha256": FONT_SHA[weight]})
    for name, url in [
        ("SourceHanSerif-LICENSE.txt", "https://raw.githubusercontent.com/adobe-fonts/source-han-serif/2.003R/LICENSE.txt"),
        ("Typst-LICENSE.txt", "https://raw.githubusercontent.com/typst/typst/v0.15.1/LICENSE"),
    ]:
        (ROOT / name).write_bytes(fetch(url))
    (ROOT / "document-runtime.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(json.dumps({"ready": True, "root": str(ROOT), "components": len(records)}))

if __name__ == "__main__":
    main()
