#!/usr/bin/env python3
"""Validate qualification-gated approved-case-workspace host packages."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = ROOT / "integrations"
PROFILE = "approved_case_workspace"
PROFILE_STDIO_ARGS = ["--privacy-profile", PROFILE, "stdio"]
PUBLIC_TOOLS = (
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
)
CASE_TOOLS = (
    "case_list",
    "case_get_public_metadata",
    "case_list_approved_materials",
    "case_read_approved_material",
    "case_search_approved_materials",
    "case_list_work_products",
    "case_read_work_product",
    "case_write_work_product",
    "case_update_work_product",
    "case_export_work_product_manifest",
)
EXPECTED_TOOLS = PUBLIC_TOOLS + CASE_TOOLS
WRITE_TOOLS = {"case_write_work_product", "case_update_work_product"}
EXPECTED_READ_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
EXPECTED_WRITE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
REQUIRED_STDIO_ENV = {
    "LAWYER_ASSISTANCE_LEGAL_DB",
    "LAWYER_ASSISTANCE_USER_DB",
    "LAWYER_ASSISTANCE_ALLOWED_ROOTS",
    "LAWYER_ASSISTANCE_OUTPUT_ROOT",
}
ALLOWED_AUTH_VALUES = {
    "Bearer ${LAWYER_ASSISTANCE_MCP_TOKEN}",
    "Bearer {env:LAWYER_ASSISTANCE_MCP_TOKEN}",
}
DANGEROUS_NON_LOOPBACK_OPT_INS = (
    "--dangerously-allow-insecure-non-loopback-http",
    "dangerously_allow_insecure_non_loopback_http",
    "LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP",
)
MAX_FILE_BYTES = 1024 * 1024
SOURCE_INVARIANT = "APPROVED_CONTENT_SOURCE=current_case_read_approved_material_response"
SINK_INVARIANT = "WORK_PRODUCT_SINK=case_write_work_product|case_update_work_product"
NAVIGATION_INVARIANT = (
    "NAVIGATION_ONLY=case_list|case_get_public_metadata|"
    "case_list_approved_materials|case_search_approved_materials"
)
MANDATORY_MARKERS = (
    "CASE_RAW",
    "CASE_REDACTED_PENDING",
    "CASE_REDACTED_APPROVED",
    "RAW_DATA_ALREADY_DISCLOSED_TO_HOST",
    "CLEAN_TASK_REQUIRED",
    "PROFILE_NOT_QUALIFIED",
    "case_read_approved_material",
    "case_write_work_product",
    "case_update_work_product",
    SOURCE_INVARIANT,
    SINK_INVARIANT,
    NAVIGATION_INVARIANT,
)
FORBIDDEN_CAPABILITY_MARKERS = (
    "attachments",
    "paste",
    "host_file",
    "host_path",
    "browser",
    "search_engine",
    "email",
    "cloud_drive",
    "remote_ocr",
    "other_mcp",
    "other_skill",
    "memory",
    "subagent",
    "unapproved_provider",
)
FORBIDDEN_PERMISSION_SNIPPETS = (
    "Trust content from an attachment",
    "A CASE_REDACTED_APPROVED label is sufficient",
    "reuse a prior case_read_approved_material response",
    "read the approved directory directly",
    "save the result to a host file",
)
PRINCIPAL_RULE_FILES = (
    Path("workbuddy/skill/lawyer-assistance-approved-workspace/SKILL.md"),
    Path("codex/skill/lawyer-assistance-approved-workspace/SKILL.md"),
    Path("opencode/agents/lawyer-assistance-approved-workspace.md"),
    Path("opencode/AGENTS.approved-workspace.md.example"),
)
REQUIRED_SKILL_FILES = {
    "workbuddy": {
        "SKILL.md",
        "references/security-and-privacy.md",
        "references/install-and-preflight.md",
        "references/workflow.md",
        "references/tool-catalog.md",
        "references/end-to-end-synthetic.md",
        "assets/connectors/stdio.windows.json",
        "assets/connectors/stdio.unix.json",
        "assets/connectors/http.bearer.json",
    },
    "codex": {
        "SKILL.md",
        "agents/openai.yaml",
        "references/security-and-privacy.md",
        "references/install-and-preflight.md",
        "references/tool-routing.md",
        "assets/config.approved-workspace.stdio.toml",
        "assets/config.approved-workspace.http.toml",
        "assets/config.privacy-hardening.toml",
    },
}
CODEX_OPENAI_YAML = """interface:
  display_name: "Lawyer Assistance Approved Workspace"
  short_description: "Use verified approved case materials safely"
  default_prompt: "Use $lawyer-assistance-approved-workspace in a clean task to process an approved case by opaque IDs only."
dependencies:
  tools:
    - type: "mcp"
      value: "lawyer_assistance"
      description: "Qualification-gated Lawyer Assistance approved-case-workspace MCP server"
      transport: "streamable_http"
      url: "http://127.0.0.1:8787/mcp"
policy:
  allow_implicit_invocation: false
"""

ERRORS: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        ERRORS.append(message)


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        ERRORS.append(f"{display_path(path)}: invalid strict JSON: {error}")
        return None


def load_toml(path: Path) -> Any:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        ERRORS.append(f"{display_path(path)}: invalid TOML: {error}")
        return None


def iter_values(value: Any, keys: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_values(child, keys + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_values(child, keys + (str(index),))
    else:
        yield keys, value


def validate_generic_document(path: Path, data: Any) -> None:
    for keys, value in iter_values(data):
        key_path = ".".join(keys)
        if not isinstance(value, str):
            continue
        leaf = keys[-1].lower() if keys else ""
        if leaf == "authorization":
            check(
                value in ALLOWED_AUTH_VALUES,
                f"{display_path(path)}: Authorization must use the approved environment placeholder",
            )
        if re.search(r"(?i)bearer\s+\S+", value):
            check(
                value in ALLOWED_AUTH_VALUES,
                f"{display_path(path)}: possible hard-coded bearer credential at {key_path}",
            )
        if leaf in {"api_key", "apikey", "access_token", "bearer_token", "secret"}:
            check(False, f"{display_path(path)}: literal secret field {key_path} is forbidden")
        for opt_in in DANGEROUS_NON_LOOPBACK_OPT_INS:
            check(
                opt_in not in key_path and opt_in not in value,
                f"{display_path(path)}: dangerous transport opt-in is forbidden: {opt_in}",
            )


def validate_approved_roots(path: Path, environment: Any, input_root: str, output_root: str) -> None:
    if not isinstance(environment, dict):
        return
    allowed = str(environment.get("LAWYER_ASSISTANCE_ALLOWED_ROOTS", "")).replace("\\", "/")
    output = str(environment.get("LAWYER_ASSISTANCE_OUTPUT_ROOT", "")).replace("\\", "/")
    check(allowed == input_root, f"{display_path(path)}: approved input root must be dedicated empty-input")
    check(output == output_root, f"{display_path(path)}: work-product root drift")
    check(allowed != output and output not in allowed, f"{display_path(path)}: output root must not be readable input")
    for value in (allowed, output):
        check(
            re.search(r"(?i)(?:^|/)(?:vault|pending|approved|cases?)(?:/|$)", value) is None,
            f"{display_path(path)}: host config grants a sensitive workspace root",
        )


def validate_catalog(catalog: Any) -> None:
    check(isinstance(catalog, dict), "approved tool catalog must be an object")
    if not isinstance(catalog, dict):
        return
    check(
        set(catalog)
        == {"server_name", "binary", "http_endpoint", "privacy_profile", "qualification_required", "tools"},
        "approved tool catalog fields drift",
    )
    check(catalog.get("server_name") == "lawyer_assistance", "approved catalog server name drift")
    check(catalog.get("binary") == "lawyer-assistance-mcp", "approved catalog binary drift")
    check(catalog.get("http_endpoint") == "/mcp", "approved catalog endpoint drift")
    check(catalog.get("privacy_profile") == PROFILE, "approved catalog profile drift")
    check(catalog.get("qualification_required") is True, "approved catalog must require qualification")
    tools = catalog.get("tools")
    check(isinstance(tools, list), "approved catalog tools must be an array")
    if not isinstance(tools, list):
        return
    names = tuple(item.get("name") for item in tools if isinstance(item, dict))
    check(names == EXPECTED_TOOLS, "approved catalog must contain the exact ordered 15-tool surface")
    for item in tools:
        if not isinstance(item, dict) or item.get("name") not in EXPECTED_TOOLS:
            continue
        name = item["name"]
        check(set(item) == {"name", "annotations", "confirmation_required"}, f"{name}: catalog fields drift")
        expected_annotations = EXPECTED_WRITE_ANNOTATIONS if name in WRITE_TOOLS else EXPECTED_READ_ANNOTATIONS
        check(item.get("annotations") == expected_annotations, f"{name}: annotations drift")
        check(
            item.get("confirmation_required") is (name in WRITE_TOOLS),
            f"{name}: write confirmation classification drift",
        )


def _approved_json_documents(integrations_root: Path) -> dict[Path, Any]:
    paths = [integrations_root / "tool-catalog.approved-case-workspace.json"]
    paths.extend((integrations_root / "workbuddy" / "connectors" / "approved-case-workspace").glob("*.json"))
    paths.extend(
        (integrations_root / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "assets").rglob("*.json")
    )
    paths.extend((integrations_root / "opencode").glob("opencode.approved-workspace.*.json"))
    return {path: load_json(path) for path in sorted(set(paths))}


def _approved_toml_documents(integrations_root: Path) -> dict[Path, Any]:
    paths = list((integrations_root / "codex").glob("config.approved-workspace.*.toml"))
    paths.extend(
        (integrations_root / "codex" / "skill" / "lawyer-assistance-approved-workspace" / "assets").glob("*.toml")
    )
    return {path: load_toml(path) for path in sorted(set(paths))}


def validate_workbuddy(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "workbuddy" / "connectors" / "approved-case-workspace"
    assets = integrations_root / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "assets" / "connectors"
    for filename in ("stdio.windows.json", "stdio.unix.json", "http.bearer.json"):
        root_path = base / filename
        asset_path = assets / filename
        check(root_path.is_file() and asset_path.is_file(), f"WorkBuddy approved connector missing: {filename}")
        if root_path.is_file() and asset_path.is_file():
            check(root_path.read_bytes() == asset_path.read_bytes(), f"WorkBuddy approved asset differs: {filename}")
        data = documents.get(root_path)
        if not isinstance(data, dict):
            continue
        check(set(data.get("mcpServers", {})) == {"lawyer_assistance"}, f"{display_path(root_path)}: server drift")
        server = data.get("mcpServers", {}).get("lawyer_assistance", {})
        description = str(server.get("description", "")).lower()
        check("qualification-gated" in description, f"{display_path(root_path)}: qualification warning missing")
        if filename.startswith("stdio"):
            check(server.get("type") == "stdio", f"{display_path(root_path)}: expected stdio")
            check(server.get("args") == PROFILE_STDIO_ARGS, f"{display_path(root_path)}: approved profile args drift")
            environment = server.get("env", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(root_path)}: environment fields drift")
            windows = "windows" in filename
            validate_approved_roots(
                root_path,
                environment,
                "C:/LawyerAssistance/empty-input" if windows else "/srv/lawyer-assistance/empty-input",
                "C:/LawyerAssistance/work-products" if windows else "/srv/lawyer-assistance/work-products",
            )
        else:
            check(server.get("type") == "http", f"{display_path(root_path)}: expected HTTP")
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(root_path)}: loopback URL drift")
            check(
                server.get("headers", {}).get("Authorization") == "Bearer ${LAWYER_ASSISTANCE_MCP_TOKEN}",
                f"{display_path(root_path)}: bearer placeholder drift",
            )


def validate_codex(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "codex"
    assets = base / "skill" / "lawyer-assistance-approved-workspace" / "assets"
    pairs = (
        (base / "config.approved-workspace.stdio.toml", assets / "config.approved-workspace.stdio.toml"),
        (base / "config.approved-workspace.http.toml", assets / "config.approved-workspace.http.toml"),
        (base / "config.privacy-hardening.toml", assets / "config.privacy-hardening.toml"),
    )
    for root_path, asset_path in pairs:
        check(root_path.is_file() and asset_path.is_file(), f"Codex approved config copy missing: {root_path.name}")
        if root_path.is_file() and asset_path.is_file():
            check(root_path.read_bytes() == asset_path.read_bytes(), f"Codex approved asset differs: {root_path.name}")
    for filename, transport in (
        ("config.approved-workspace.stdio.toml", "stdio"),
        ("config.approved-workspace.http.toml", "http"),
    ):
        path = base / filename
        data = documents.get(path)
        if not isinstance(data, dict):
            continue
        server = data.get("mcp_servers", {}).get("lawyer_assistance", {})
        check(tuple(server.get("enabled_tools", ())) == EXPECTED_TOOLS, f"{display_path(path)}: exact 15 tools required")
        check(server.get("enabled") is False, f"{display_path(path)}: unqualified example must be disabled")
        check(server.get("required") is True, f"{display_path(path)}: server must fail closed when enabled")
        check(server.get("default_tools_approval_mode") == "writes", f"{display_path(path)}: write approval mode drift")
        check(not server.get("tools"), f"{display_path(path)}: ad hoc per-tool override is forbidden")
        if transport == "stdio":
            check(server.get("args") == PROFILE_STDIO_ARGS, f"{display_path(path)}: approved profile args drift")
            environment = server.get("env", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(path)}: environment fields drift")
            validate_approved_roots(
                path,
                environment,
                "/absolute/path/to/empty-input",
                "/absolute/path/to/work-products",
            )
        else:
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(path)}: loopback URL drift")
            check(
                server.get("bearer_token_env_var") == "LAWYER_ASSISTANCE_MCP_TOKEN",
                f"{display_path(path)}: bearer env drift",
            )
    metadata = base / "skill" / "lawyer-assistance-approved-workspace" / "agents" / "openai.yaml"
    check(metadata.is_file(), "Codex approved Skill metadata missing")
    if metadata.is_file():
        actual = metadata.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n")
        check(actual == CODEX_OPENAI_YAML.rstrip("\n"), "Codex approved openai.yaml drift")


def validate_opencode(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "opencode"
    expected_permissions = {"lawyer_assistance_*"} | {
        f"lawyer_assistance_{name}" for name in EXPECTED_TOOLS
    }
    for filename, transport in (
        ("opencode.approved-workspace.local.json", "local"),
        ("opencode.approved-workspace.remote.json", "remote"),
    ):
        path = base / filename
        data = documents.get(path)
        if not isinstance(data, dict):
            continue
        check(data.get("share") == "disabled", f"{display_path(path)}: sharing must be disabled")
        server = data.get("mcp", {}).get("lawyer_assistance", {})
        check(server.get("type") == transport, f"{display_path(path)}: transport drift")
        check(server.get("enabled") is False, f"{display_path(path)}: unqualified example must be disabled")
        permissions = data.get("permission", {})
        check(set(permissions) == expected_permissions, f"{display_path(path)}: exact wildcard plus 15 permissions required")
        check(permissions.get("lawyer_assistance_*") == "deny", f"{display_path(path)}: wildcard must deny")
        for name in EXPECTED_TOOLS:
            check(permissions.get(f"lawyer_assistance_{name}") == "allow", f"{display_path(path)}: {name} must be allowed")
        if transport == "local":
            command = server.get("command", [])
            check(isinstance(command, list) and command[1:] == PROFILE_STDIO_ARGS, f"{display_path(path)}: profile args drift")
            environment = server.get("environment", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(path)}: environment fields drift")
            validate_approved_roots(
                path,
                environment,
                "/absolute/path/to/empty-input",
                "/absolute/path/to/work-products",
            )
        else:
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(path)}: loopback URL drift")
            check(
                server.get("headers", {}).get("Authorization") == "Bearer {env:LAWYER_ASSISTANCE_MCP_TOKEN}",
                f"{display_path(path)}: bearer placeholder drift",
            )

    agent = base / "agents" / "lawyer-assistance-approved-workspace.md"
    check(agent.is_file(), f"{display_path(agent)}: OpenCode approved agent missing")
    if not agent.is_file():
        return
    text = agent.read_text(encoding="utf-8").replace("\r\n", "\n")
    check(text.startswith("---\n") and "\n---\n" in text[4:], f"{display_path(agent)}: invalid agent frontmatter")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return
    block = text.split("\n---\n", 1)[0][4:]
    metadata: dict[str, str] = {}
    agent_permissions: dict[str, str] = {}
    in_permissions = False
    for line in block.splitlines():
        if line == "permission:":
            check("permission" not in metadata, f"{display_path(agent)}: duplicate permission block")
            metadata["permission"] = ""
            in_permissions = True
            continue
        if line.startswith("  ") and in_permissions:
            key, separator, value = line.strip().partition(":")
            check(bool(separator) and bool(key) and bool(value.strip()), f"{display_path(agent)}: invalid permission line")
            check(key not in agent_permissions, f"{display_path(agent)}: duplicate agent permission {key}")
            agent_permissions[key] = value.strip()
            continue
        in_permissions = False
        key, separator, value = line.partition(":")
        check(bool(separator) and bool(key) and bool(value.strip()), f"{display_path(agent)}: invalid frontmatter line")
        check(key not in metadata, f"{display_path(agent)}: duplicate frontmatter field {key}")
        metadata[key] = value.strip()
    check(set(metadata) == {"description", "mode", "permission"}, f"{display_path(agent)}: frontmatter fields drift")
    check(metadata.get("mode") == "primary", f"{display_path(agent)}: mode drift")
    description = metadata.get("description", "")
    check(PROFILE in description, f"{display_path(agent)}: approved profile missing from description")
    check("CASE_REDACTED_APPROVED" in description, f"{display_path(agent)}: approved classification missing")
    expected_order = ("lawyer_assistance_*",) + tuple(
        f"lawyer_assistance_{name}" for name in EXPECTED_TOOLS
    )
    check(tuple(agent_permissions) == expected_order, f"{display_path(agent)}: exact ordered agent permission surface required")
    check(agent_permissions.get("lawyer_assistance_*") == "deny", f"{display_path(agent)}: agent wildcard must deny")
    for name in EXPECTED_TOOLS:
        check(agent_permissions.get(f"lawyer_assistance_{name}") == "allow", f"{display_path(agent)}: agent must allow {name}")


def _parse_skill_frontmatter(path: Path) -> dict[str, str] | None:
    try:
        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    except (OSError, UnicodeError) as error:
        ERRORS.append(f"{display_path(path)}: cannot read Skill: {error}")
        return None
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        ERRORS.append(f"{display_path(path)}: invalid Skill frontmatter")
        return None
    block = text.split("\n---\n", 1)[0][4:]
    metadata: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            ERRORS.append(f"{display_path(path)}: invalid frontmatter line")
            return None
        key, value = line.split(":", 1)
        if key in metadata:
            ERRORS.append(f"{display_path(path)}: duplicate frontmatter field {key}")
            return None
        metadata[key] = value.strip()
    return metadata


def _validate_links(skill_root: Path) -> None:
    for path in skill_root.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("#"):
                continue
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            try:
                resolved.relative_to(skill_root.resolve())
            except ValueError:
                ERRORS.append(f"{display_path(path)}: package link escapes Skill: {target}")
            check(resolved.is_file(), f"{display_path(path)}: package link target missing: {target}")


def validate_principal_rules(integrations_root: Path = INTEGRATIONS) -> None:
    for relative in PRINCIPAL_RULE_FILES:
        path = integrations_root / relative
        check(path.is_file(), f"{display_path(path)}: approved principal rule file missing")
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lower = text.lower()
        case_gate = text.find("CASE_RAW")
        source = text.find(SOURCE_INVARIANT)
        check(case_gate >= 0 and source >= 0 and case_gate < source, f"{display_path(path)}: CASE_RAW gate must precede approved source")
        for marker in MANDATORY_MARKERS:
            check(marker in text, f"{display_path(path)}: mandatory marker missing: {marker}")
        for marker in FORBIDDEN_CAPABILITY_MARKERS:
            check(marker in lower, f"{display_path(path)}: forbidden capability marker missing: {marker}")
        for snippet in FORBIDDEN_PERMISSION_SNIPPETS:
            check(snippet.lower() not in lower, f"{display_path(path)}: unsafe host permission present: {snippet}")
        check("opaque" in lower, f"{display_path(path)}: opaque-ID boundary missing")
        check("current" in lower and "direct" in lower, f"{display_path(path)}: current direct response requirement missing")
        check("new clean task" in lower, f"{display_path(path)}: clean replacement task requirement missing")


def validate_skill_packages(integrations_root: Path = INTEGRATIONS) -> None:
    for host, required in REQUIRED_SKILL_FILES.items():
        skill_root = integrations_root / host / "skill" / "lawyer-assistance-approved-workspace"
        present = {path.relative_to(skill_root).as_posix() for path in skill_root.rglob("*") if path.is_file()}
        check(present == required, f"{display_path(skill_root)}: approved Skill file set drift: {sorted(present ^ required)}")
        skill_path = skill_root / "SKILL.md"
        metadata = _parse_skill_frontmatter(skill_path)
        if metadata is not None:
            check(set(metadata) == {"name", "description"}, f"{display_path(skill_path)}: frontmatter fields drift")
            check(metadata.get("name") == "lawyer-assistance-approved-workspace", f"{display_path(skill_path)}: Skill name drift")
            description = metadata.get("description", "")
            check(PROFILE in description, f"{display_path(skill_path)}: profile missing from description")
            check("CASE_REDACTED_APPROVED" in description, f"{display_path(skill_path)}: approved classification missing")
            check("opaque" in description.lower(), f"{display_path(skill_path)}: opaque-ID trigger boundary missing")
        for path in skill_root.rglob("*"):
            if not path.is_file():
                continue
            check(not path.is_symlink(), f"{display_path(path)}: symlink is forbidden")
            check(path.stat().st_size <= MAX_FILE_BYTES, f"{display_path(path)}: file exceeds size limit")
        _validate_links(skill_root)
    check(
        not (integrations_root / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace" / "agents").exists(),
        "WorkBuddy approved Skill must not contain Codex metadata",
    )
    validate_principal_rules(integrations_root)


def validate_documentation(integrations_root: Path = INTEGRATIONS) -> None:
    docs = (
        integrations_root / "approved-case-workspace.md",
        integrations_root / "workbuddy" / "APPROVED_WORKSPACE.md",
        integrations_root / "codex" / "APPROVED_WORKSPACE.md",
        integrations_root / "opencode" / "APPROVED_WORKSPACE.md",
    )
    for path in docs:
        check(path.is_file(), f"{display_path(path)}: approved host documentation missing")
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for marker in (
            PROFILE,
            "PROFILE_NOT_QUALIFIED",
            "case_read_approved_material",
            "CASE_REDACTED_APPROVED",
            "case_write_work_product",
            "case_update_work_product",
            "opaque",
        ):
            check(marker in text, f"{display_path(path)}: documentation marker missing: {marker}")


def validate_text_hygiene(integrations_root: Path = INTEGRATIONS) -> None:
    roots = (
        integrations_root / "approved-case-workspace.md",
        integrations_root / "workbuddy" / "APPROVED_WORKSPACE.md",
        integrations_root / "workbuddy" / "skill" / "lawyer-assistance-approved-workspace",
        integrations_root / "codex" / "APPROVED_WORKSPACE.md",
        integrations_root / "codex" / "skill" / "lawyer-assistance-approved-workspace",
        integrations_root / "opencode" / "APPROVED_WORKSPACE.md",
        integrations_root / "opencode" / "agents" / "lawyer-assistance-approved-workspace.md",
        integrations_root / "opencode" / "AGENTS.approved-workspace.md.example",
    )
    marker = re.compile("|".join(("TO" + "DO", "T" + "BD", "FIX" + "ME")), re.IGNORECASE)
    for root in roots:
        paths = [root] if root.is_file() else list(root.rglob("*")) if root.exists() else []
        for path in paths:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            check(marker.search(text) is None, f"{display_path(path)}: unfinished marker is forbidden")
            check(
                re.search(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{16,}", text) is None,
                f"{display_path(path)}: possible literal bearer secret",
            )


def validate_rust_registry(root: Path = ROOT) -> None:
    approved = root / "crates" / "legal-mcp" / "src" / "approved_workspace.rs"
    registry = root / "crates" / "legal-mcp" / "src" / "registry.rs"
    check(approved.is_file(), f"{display_path(approved)}: approved tool source missing")
    check(registry.is_file(), f"{display_path(registry)}: registry source missing")
    if approved.is_file():
        text = approved.read_text(encoding="utf-8")
        match = re.search(
            r"pub const APPROVED_CASE_WORKSPACE_TOOL_NAMES:\s*\[&str;\s*10\]\s*=\s*\[(.*?)\];",
            text,
            re.DOTALL,
        )
        check(match is not None, "approved Rust source must declare exact ten case tools")
        if match:
            names = tuple(re.findall(r'"([a-z_]+)"', match.group(1)))
            check(names == CASE_TOOLS, "approved Rust case tools and host catalog differ")
    if registry.is_file():
        text = registry.read_text(encoding="utf-8")
        check("ApprovedCaseWorkspace" in text, "Rust registry missing ApprovedCaseWorkspace profile")
        check(PROFILE in text, "Rust registry missing approved_case_workspace parser name")
        match = re.search(
            r"pub const APPROVED_CASE_WORKSPACE_PROFILE_TOOL_NAMES:\s*\[&str;\s*15\]\s*=\s*\[(.*?)\];",
            text,
            re.DOTALL,
        )
        check(match is not None, "Rust registry must declare the exact approved 15-tool profile")
        if match:
            names = tuple(re.findall(r'"([a-z_]+)"', match.group(1)))
            check(names == EXPECTED_TOOLS, "Rust approved profile and host catalog differ")
        check(
            "candidates.extend(approved_workspace::build_tools())" in text,
            "Rust registry does not compose approved workspace schemas",
        )


def validate_integrations_root(integrations_root: Path = INTEGRATIONS, *, include_rust: bool = True) -> tuple[int, int]:
    json_documents = _approved_json_documents(integrations_root)
    toml_documents = _approved_toml_documents(integrations_root)
    for path, data in {**json_documents, **toml_documents}.items():
        if data is not None:
            validate_generic_document(path, data)
    validate_catalog(json_documents.get(integrations_root / "tool-catalog.approved-case-workspace.json"))
    validate_workbuddy(json_documents, integrations_root)
    validate_codex(toml_documents, integrations_root)
    validate_opencode(json_documents, integrations_root)
    validate_skill_packages(integrations_root)
    validate_documentation(integrations_root)
    validate_text_hygiene(integrations_root)
    if include_rust:
        validate_rust_registry()
    return len(json_documents), len(toml_documents)


def main() -> int:
    ERRORS.clear()
    json_count, toml_count = validate_integrations_root()
    if ERRORS:
        for error in ERRORS:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"approved workspace validation failed with {len(ERRORS)} error(s)", file=sys.stderr)
        return 1
    print(
        f"validated {json_count} approved JSON files, {toml_count} approved TOML files, "
        f"three host packages, and {len(EXPECTED_TOOLS)} exact tools"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
