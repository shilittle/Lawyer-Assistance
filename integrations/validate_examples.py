from pathlib import Path
import json
import re
import sys
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = ROOT / "integrations"
PUBLIC_TOOLS = (
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
)
PRIVACY_TOOLS = PUBLIC_TOOLS + (
    "privacy_workspace.submit",
    "privacy_workspace.status",
    "privacy_workspace.read_result",
)
LEGACY_PROFILES = (
    "approved_case_workspace",
    "redacted_case",
    "diagram_authoring",
)
ERRORS: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        ERRORS.append(message)


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        ERRORS.append(f"{display_path(path)}: invalid JSON: {error}")
        return None


def load_toml(path: Path) -> Any:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        ERRORS.append(f"{display_path(path)}: invalid TOML: {error}")
        return None


def catalog_names(data: Any) -> tuple[str | None, ...]:
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        return ()
    return tuple(item.get("name") if isinstance(item, dict) else None for item in data["tools"])


def validate_catalog(path: Path, profile: str, tools: tuple[str, ...]) -> None:
    data = load_json(path)
    if not isinstance(data, dict):
        return
    check(data.get("privacy_profile") == profile, f"{path.name}: profile drift")
    check(catalog_names(data) == tools, f"{path.name}: exact tool contract drift")


def public_stdio_toml(path: Path) -> None:
    data = load_toml(path)
    if not isinstance(data, dict):
        return
    server = data.get("mcp_servers", {}).get("lawyer_assistance", {})
    check(server.get("args") == ["--privacy-profile", "public_law_only", "stdio"], f"{path.name}: public stdio args drift")
    check(server.get("env") == {"LEGAL_DB": "/absolute/path/to/legal_core.sqlite"}, f"{path.name}: public stdio environment drift")
    check(tuple(server.get("enabled_tools", ())) == PUBLIC_TOOLS, f"{path.name}: public tool list drift")


def privacy_stdio_toml(path: Path) -> None:
    data = load_toml(path)
    if not isinstance(data, dict):
        return
    server = data.get("mcp_servers", {}).get("lawyer_assistance_privacy_workspace", {})
    args = server.get("args", [])
    check("--privacy-profile" in args and "privacy_workspace" in args, f"{path.name}: privacy profile drift")
    check("--client-token-file" in args, f"{path.name}: privacy token must be a file argument")
    check(tuple(server.get("enabled_tools", ())) == PRIVACY_TOOLS, f"{path.name}: privacy tool list drift")


def validate_no_legacy_profile_assets(integrations_root: Path) -> None:
    for path in integrations_root.rglob("*"):
        if not path.is_file() or path.suffix not in {".md", ".json", ".toml", ".yaml", ".yml"}:
            continue
        text = path.read_text(encoding="utf-8")
        for profile in LEGACY_PROFILES:
            check(profile not in text, f"{display_path(path)}: removed legacy profile remains")


def validate_no_literal_secret(integrations_root: Path) -> None:
    marker = re.compile(r"(?i)bearer\s+(?!\$\{|\{env:)[A-Za-z0-9._~+/=-]{16,}")
    for path in integrations_root.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".json", ".toml", ".yaml", ".yml"}:
            check(marker.search(path.read_text(encoding="utf-8")) is None, f"{display_path(path)}: literal bearer token")


def validate_rust_registry() -> None:
    path = ROOT / "crates" / "legal-mcp" / "src" / "registry.rs"
    text = path.read_text(encoding="utf-8")
    public = re.search(r"pub const TOOL_NAMES:\s*\[&str;\s*5\]\s*=\s*\[(.*?)\];", text, re.DOTALL)
    privacy = re.search(r"pub const PRIVACY_WORKSPACE_TOOL_NAMES:\s*\[&str;\s*8\]\s*=\s*\[(.*?)\];", text, re.DOTALL)
    check(public is not None, "registry: public five declaration missing")
    check(privacy is not None, "registry: privacy eight declaration missing")
    if public:
        check(tuple(re.findall(r'"([^\"]+)"', public.group(1))) == PUBLIC_TOOLS, "registry: public tools drift")
    if privacy:
        check(tuple(re.findall(r'"([^\"]+)"', privacy.group(1))) == PRIVACY_TOOLS, "registry: privacy tools drift")


def validate_integrations_root(integrations_root: Path = INTEGRATIONS) -> None:
    validate_catalog(integrations_root / "tool-catalog.json", "public_law_only", PUBLIC_TOOLS)
    validate_catalog(integrations_root / "tool-catalog.privacy-workspace.json", "privacy_workspace", PRIVACY_TOOLS)
    public_stdio_toml(integrations_root / "codex" / "config.stdio.toml")
    privacy_stdio_toml(integrations_root / "codex" / "config.privacy-workspace.stdio.toml")
    for path in integrations_root.rglob("*.json"):
        load_json(path)
    for path in integrations_root.rglob("*.toml"):
        load_toml(path)
    validate_no_legacy_profile_assets(integrations_root)
    validate_no_literal_secret(integrations_root)


def main() -> int:
    ERRORS.clear()
    validate_integrations_root()
    validate_rust_registry()
    if ERRORS:
        print("\n".join(f"ERROR: {error}" for error in ERRORS), file=sys.stderr)
        return 1
    print("validated public five-tool and privacy eight-tool MCP examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
