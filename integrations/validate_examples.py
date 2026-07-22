#!/usr/bin/env python3
"""Validate the public-law-only MCP host examples with the standard library."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = ROOT / "integrations"
EXPECTED_TOOLS = (
    "system_status",
    "legal_search",
    "legal_get_article",
    "legal_get_versions",
    "legal_get_relations",
)
FORBIDDEN_SENSITIVE_TOOLS = (
    "citation_validate",
    "case_get_state",
    "case_propose_patch",
    "case_apply_patch",
    "case_analyze_gaps",
    "document_generate",
    "document_export",
)
PROFILE = "public_law_only"
PROFILE_STDIO_ARGS = ["--privacy-profile", PROFILE, "stdio"]
EXPECTED_ANNOTATIONS = {
    "readOnlyHint": True,
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
RAW_DATA_STOP_CODE = "RAW_DATA_ALREADY_DISCLOSED_TO_HOST"
MAX_SKILL_FILE_BYTES = 1024 * 1024
CODEX_OPENAI_YAML = """interface:
  display_name: "Lawyer Assistance"
  short_description: "Research Chinese public law safely"
  default_prompt: "Use $lawyer-assistance to research a public Chinese law question with no client or case data."
dependencies:
  tools:
    - type: "mcp"
      value: "lawyer_assistance"
      description: "Lawyer Assistance public-law-only MCP server"
      transport: "streamable_http"
      url: "http://127.0.0.1:8787/mcp"
"""
SKILL_REQUIRED_FILES = {
    "workbuddy": {
        "SKILL.md",
        "references/end-to-end-examples.md",
        "references/install-and-preflight.md",
        "references/security-and-privacy.md",
        "references/tool-catalog.md",
        "references/workflow.md",
        "assets/connectors/http.bearer.json",
        "assets/connectors/stdio.unix.json",
        "assets/connectors/stdio.windows.json",
    },
    "codex": {
        "SKILL.md",
        "agents/openai.yaml",
        "references/install-and-preflight.md",
        "references/security-and-privacy.md",
        "references/tool-routing.md",
        "assets/config.http.toml",
        "assets/config.privacy-hardening.toml",
        "assets/config.stdio.toml",
    },
}
DIAGRAM_SKILL_REQUIRED_FILES = {
    "SKILL.md",
    "references/examples.md",
    "references/security.md",
    "references/workflow.md",
}
DIAGRAM_SKILL_PRIVACY_MARKERS = (
    "不可覆盖",
    "CASE_RAW",
    "CASE_REDACTED_PENDING",
    "未经 Privacy",
    "附件",
    "粘贴",
    "Provider",
    "网络",
    "browser",
    "search",
    "远程 OCR",
    "其他 MCP",
    "其他 Skill",
    "memory",
    "subagent",
    "不调用任何工具",
)
PRINCIPAL_RULE_FILES = (
    Path("workbuddy/skill/lawyer-assistance/SKILL.md"),
    Path("codex/skill/lawyer-assistance/SKILL.md"),
    Path("opencode/agents/lawyer-assistance.md"),
    Path("opencode/AGENTS.md.example"),
)
FORBIDDEN_HOST_PERMISSION_SNIPPETS = (
    "Base facts only on text supplied by a host attachment",
    "Text used to form facts must come from a host attachment",
    "explicitly authorized host file read",
    "facts require host-supplied or explicitly authorized host-read text",
    "形成 facts 的正文只能来自宿主附件",
    "明确授权的宿主文件读取",
    "用户对宿主文件读取的单独明确授权",
)
FORBIDDEN_HOST_PERMISSION_PATTERNS = (
    re.compile(
        r"(?is)\bfacts?\b.{0,60}\b(?:require|come from|use|may use)\b.{0,60}"
        r"\bhost[- ](?:supplied|attachment|file[- ]read)\b"
    ),
    re.compile(r"(?i)\bexplicitly authorized host[- ](?:file )?read\b"),
    re.compile(
        r"(?:facts|事实|正文).{0,50}(?:只|可以|能够|必须|只能).{0,20}"
        r"(?:来自|使用).{0,30}(?:宿主附件|宿主文件读取|WorkBuddy 附件)"
    ),
)
LEGACY_WORKFLOW_MARKERS = FORBIDDEN_SENSITIVE_TOOLS + (
    "redacted_case",
    "material_imports",
    "project_bootstrap",
    "exactly 12 tools",
    "12 tools",
    "12 个工具",
    "propose→",
    "propose/approve/apply",
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


def iter_values(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_values(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_values(child, path + (str(index),))
    else:
        yield path, value


def validate_no_literal_secrets(path: Path, data: Any) -> None:
    for keys, value in iter_values(data):
        if not isinstance(value, str):
            continue
        leaf = keys[-1].lower() if keys else ""
        if leaf == "authorization":
            check(
                value in ALLOWED_AUTH_VALUES,
                f"{display_path(path)}: Authorization must use the environment placeholder",
            )
        if re.search(r"(?i)bearer\s+\S+", value):
            check(
                value in ALLOWED_AUTH_VALUES,
                f"{display_path(path)}: possible hard-coded bearer credential at {'.'.join(keys)}",
            )
        if leaf in {"api_key", "apikey", "access_token", "bearer_token", "secret"}:
            check(False, f"{display_path(path)}: literal secret field {'.'.join(keys)} is forbidden")


def validate_no_dangerous_transport_opt_in(path: Path, data: Any) -> None:
    for keys, value in iter_values(data):
        key_path = ".".join(keys)
        for opt_in in DANGEROUS_NON_LOOPBACK_OPT_INS:
            check(
                opt_in not in key_path and (not isinstance(value, str) or opt_in not in value),
                f"{display_path(path)}: packaged config must not carry dangerous opt-in {opt_in}",
            )


def validate_stdio_path_boundaries(
    path: Path,
    environment: Any,
    expected_input_root: str,
    expected_output_root: str,
) -> None:
    if not isinstance(environment, dict):
        return
    allowed = str(environment.get("LAWYER_ASSISTANCE_ALLOWED_ROOTS", "")).replace("\\", "/")
    output = str(environment.get("LAWYER_ASSISTANCE_OUTPUT_ROOT", "")).replace("\\", "/")
    check(allowed == expected_input_root, f"{display_path(path)}: default allowed root drift")
    check(output == expected_output_root, f"{display_path(path)}: output root drift")
    check(allowed != output and output not in allowed, f"{display_path(path)}: output root must not be an input root")


def validate_catalog(catalog: Any) -> None:
    check(isinstance(catalog, dict), "integrations/tool-catalog.json: expected an object")
    if not isinstance(catalog, dict):
        return
    check(
        set(catalog) == {"server_name", "binary", "http_endpoint", "privacy_profile", "tools"},
        "tool catalog fields drift",
    )
    check(catalog.get("server_name") == "lawyer_assistance", "tool catalog server_name drift")
    check(catalog.get("binary") == "lawyer-assistance-mcp", "tool catalog binary drift")
    check(catalog.get("http_endpoint") == "/mcp", "tool catalog endpoint drift")
    check(catalog.get("privacy_profile") == PROFILE, "tool catalog must pin public_law_only")
    tools = catalog.get("tools")
    check(isinstance(tools, list), "tool catalog tools must be an array")
    if not isinstance(tools, list):
        return
    names = tuple(item.get("name") for item in tools if isinstance(item, dict))
    check(names == EXPECTED_TOOLS, "tool catalog must contain exactly five public-law tools in order")
    for item in tools:
        if not isinstance(item, dict) or item.get("name") not in EXPECTED_TOOLS:
            continue
        name = item["name"]
        check(set(item) == {"name", "annotations", "confirmation_required"}, f"{name}: tool catalog fields drift")
        check(item.get("annotations") == EXPECTED_ANNOTATIONS, f"{name}: annotations drift")
        check(item.get("confirmation_required") is False, f"{name}: must not require write confirmation")


def _documents(integrations_root: Path) -> tuple[dict[Path, Any], dict[Path, Any]]:
    json_documents = {path: load_json(path) for path in sorted(integrations_root.rglob("*.json"))}
    toml_documents = {path: load_toml(path) for path in sorted(integrations_root.rglob("*.toml"))}
    return json_documents, toml_documents
def validate_workbuddy(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "workbuddy" / "connectors"
    packaged = integrations_root / "workbuddy" / "skill" / "lawyer-assistance" / "assets" / "connectors"
    for filename in ("stdio.windows.json", "stdio.unix.json", "http.bearer.json"):
        root_path = base / filename
        asset_path = packaged / filename
        check(root_path.is_file() and asset_path.is_file(), f"WorkBuddy connector missing: {filename}")
        if root_path.is_file() and asset_path.is_file():
            check(root_path.read_bytes() == asset_path.read_bytes(), f"WorkBuddy packaged connector differs: {filename}")
        data = documents.get(root_path)
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers", {})
        check(set(servers) == {"lawyer_assistance"}, f"{display_path(root_path)}: server name drift")
        server = servers.get("lawyer_assistance", {})
        check(
            PROFILE.replace("_", "-") in str(server.get("description", "")).lower(),
            f"{display_path(root_path)}: public-only description missing",
        )
        if filename.startswith("stdio"):
            check(server.get("type") == "stdio", f"{display_path(root_path)}: expected stdio")
            check(server.get("args") == PROFILE_STDIO_ARGS, f"{display_path(root_path)}: must pin public_law_only CLI profile")
            environment = server.get("env", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(root_path)}: environment keys drift")
            validate_stdio_path_boundaries(
                root_path,
                environment,
                "C:/LawyerAssistance/cases" if "windows" in filename else "/srv/lawyer-assistance/cases",
                "C:/LawyerAssistance/exports" if "windows" in filename else "/srv/lawyer-assistance/exports",
            )
        else:
            check(server.get("type") == "http", f"{display_path(root_path)}: expected HTTP")
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(root_path)}: URL drift")
            check(
                server.get("headers", {}).get("Authorization") == "Bearer ${LAWYER_ASSISTANCE_MCP_TOKEN}",
                f"{display_path(root_path)}: bearer placeholder drift",
            )


def validate_codex(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "codex"
    assets = base / "skill" / "lawyer-assistance" / "assets"
    for filename in ("config.stdio.toml", "config.http.toml", "config.privacy-hardening.toml"):
        root_path = base / filename
        asset_path = assets / filename
        check(root_path.is_file() and asset_path.is_file(), f"Codex config missing: {filename}")
        if root_path.is_file() and asset_path.is_file():
            check(root_path.read_bytes() == asset_path.read_bytes(), f"Codex packaged asset differs: {filename}")
    for filename, transport in (("config.stdio.toml", "stdio"), ("config.http.toml", "http")):
        path = base / filename
        data = documents.get(path)
        if not isinstance(data, dict):
            continue
        server = data.get("mcp_servers", {}).get("lawyer_assistance", {})
        check(tuple(server.get("enabled_tools", ())) == EXPECTED_TOOLS, f"{display_path(path)}: enabled_tools must be exact public five")
        check(not server.get("tools"), f"{display_path(path)}: sensitive per-tool rules must be absent")
        if transport == "stdio":
            check(server.get("args") == PROFILE_STDIO_ARGS, f"{display_path(path)}: must pin public_law_only CLI profile")
            environment = server.get("env", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(path)}: environment keys drift")
            validate_stdio_path_boundaries(path, environment, "/absolute/path/to/cases", "/absolute/path/to/exports")
        else:
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(path)}: URL drift")
            check(server.get("bearer_token_env_var") == "LAWYER_ASSISTANCE_MCP_TOKEN", f"{display_path(path)}: bearer env drift")
    privacy = documents.get(base / "config.privacy-hardening.toml")
    if isinstance(privacy, dict):
        check(privacy.get("history", {}).get("persistence") == "none", "Codex history hardening drift")
        check(privacy.get("memories", {}).get("disable_on_external_context") is True, "Codex memory hardening drift")
    metadata = base / "skill" / "lawyer-assistance" / "agents" / "openai.yaml"
    check(metadata.is_file(), "Codex Skill UI metadata missing")
    if metadata.is_file():
        check(
            metadata.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n")
            == CODEX_OPENAI_YAML.rstrip("\n"),
            "Codex openai.yaml must describe public-law-only use",
        )


def validate_opencode(documents: dict[Path, Any], integrations_root: Path = INTEGRATIONS) -> None:
    base = integrations_root / "opencode"
    expected_permissions = {"lawyer_assistance_*"} | {f"lawyer_assistance_{name}" for name in EXPECTED_TOOLS}
    for filename, transport in (("opencode.local.json", "local"), ("opencode.remote.json", "remote")):
        path = base / filename
        data = documents.get(path)
        if not isinstance(data, dict):
            continue
        check(data.get("share") == "disabled", f"{display_path(path)}: sharing must be disabled")
        server = data.get("mcp", {}).get("lawyer_assistance", {})
        check(server.get("type") == transport, f"{display_path(path)}: transport drift")
        permissions = data.get("permission", {})
        check(set(permissions) == expected_permissions, f"{display_path(path)}: permission set must be wildcard deny plus public five")
        check(permissions.get("lawyer_assistance_*") == "deny", f"{display_path(path)}: wildcard must deny")
        for name in EXPECTED_TOOLS:
            check(permissions.get(f"lawyer_assistance_{name}") == "allow", f"{display_path(path)}: {name} must be allowed")
        if transport == "local":
            command = server.get("command", [])
            check(isinstance(command, list) and command[1:] == PROFILE_STDIO_ARGS, f"{display_path(path)}: must pin public_law_only CLI profile")
            environment = server.get("environment", {})
            check(set(environment) == REQUIRED_STDIO_ENV, f"{display_path(path)}: environment keys drift")
            validate_stdio_path_boundaries(path, environment, "/absolute/path/to/cases", "/absolute/path/to/exports")
        else:
            check(server.get("url") == "http://127.0.0.1:8787/mcp", f"{display_path(path)}: URL drift")
            check(
                server.get("headers", {}).get("Authorization") == "Bearer {env:LAWYER_ASSISTANCE_MCP_TOKEN}",
                f"{display_path(path)}: bearer placeholder drift",
            )
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


def validate_skill_frontmatter(integrations_root: Path = INTEGRATIONS) -> None:
    for host in ("workbuddy", "codex"):
        path = integrations_root / host / "skill" / "lawyer-assistance" / "SKILL.md"
        metadata = _parse_skill_frontmatter(path)
        if metadata is None:
            continue
        check(set(metadata) == {"name", "description"}, f"{display_path(path)}: frontmatter must contain only name and description")
        check(metadata.get("name") == "lawyer-assistance", f"{display_path(path)}: Skill name drift")
        description = metadata.get("description", "")
        check(PROFILE in description, f"{display_path(path)}: description must name public_law_only")
        check("case" in description.lower() or "案件" in description, f"{display_path(path)}: description must state the case-data exclusion")


def _first_operational_heading(text: str) -> str:
    normalized = text.replace("\r\n", "\n")
    if normalized.startswith("---\n") and "\n---\n" in normalized[4:]:
        normalized = normalized.split("\n---\n", 1)[1]
    headings = re.findall(r"^#{1,6}\s+(.+?)\s*$", normalized, re.MULTILINE)
    if not headings:
        return ""
    if len(headings) > 1 and "CASE_RAW" not in headings[0]:
        return headings[1]
    return headings[0]


def _validate_principal_privacy_rules(integrations_root: Path) -> None:
    for relative in PRINCIPAL_RULE_FILES:
        path = integrations_root / relative
        check(path.is_file(), f"{display_path(path)}: principal rule file missing")
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        heading = _first_operational_heading(text)
        check(
            "CASE_RAW" in heading and ("不可覆盖" in heading or "non-overridable" in heading.lower()),
            f"{display_path(path)}: first operational section must be the non-overridable CASE_RAW gate",
        )
        for marker in ("CASE_RAW", "CASE_REDACTED_PENDING", "CASE_REDACTED_APPROVED", RAW_DATA_STOP_CODE):
            check(marker in text, f"{display_path(path)}: missing mandatory privacy marker {marker}")
        check("App→MCP" in text, f"{display_path(path)}: missing App-to-MCP boundary")
        check("正向链" in text or "positive path" in text, f"{display_path(path)}: missing unimplemented receipt-chain statement")
        check("Provider" in text, f"{display_path(path)}: Provider egress prohibition missing")
        check("MCP" in text, f"{display_path(path)}: MCP prohibition missing")
        check("文件" in text or "filesystem" in text, f"{display_path(path)}: file/filesystem prohibition missing")
        check("网络" in text or "network" in text, f"{display_path(path)}: network prohibition missing")

    workbuddy = (integrations_root / PRINCIPAL_RULE_FILES[0]).read_text(encoding="utf-8")
    check("无法阻止或撤回这次宿主前置披露" in workbuddy, "WorkBuddy Skill: host pre-Skill disclosure boundary missing")
    check("不得声称原件未上传、未发送、未记录、已删除或已撤回" in workbuddy, "WorkBuddy Skill: honest retention statement missing")
    codex = (integrations_root / PRINCIPAL_RULE_FILES[1]).read_text(encoding="utf-8")
    check(
        "The Skill cannot prevent or retract a first-message or attachment disclosure that Codex made before loading it." in codex,
        "Codex Skill: host pre-Skill disclosure boundary missing",
    )
    check(
        "Do not claim that the original was never uploaded, sent, logged, retained, deleted, or recalled." in codex,
        "Codex Skill: honest retention statement missing",
    )
    opencode = (integrations_root / PRINCIPAL_RULE_FILES[2]).read_text(encoding="utf-8")
    check("cannot prevent or retract" in opencode and "before loading" in opencode, "OpenCode agent: host pre-agent disclosure boundary missing")


def _validate_package_links(skill_root: Path) -> None:
    for path in skill_root.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("#"):
                continue
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            try:
                resolved.relative_to(skill_root.resolve())
            except ValueError:
                ERRORS.append(f"{display_path(path)}: package link escapes the Skill: {target}")


def _validate_diagram_skill_privacy_rule(integrations_root: Path) -> None:
    skill_root = integrations_root / "workbuddy" / "skill" / "lawyer-diagrams"
    skill = skill_root / "SKILL.md"
    check(skill.is_file(), f"{display_path(skill)}: diagram Skill missing")
    if not skill.is_file():
        return
    metadata = _parse_skill_frontmatter(skill)
    if metadata is not None:
        check(
            set(metadata) == {"name", "description"},
            f"{display_path(skill)}: diagram Skill frontmatter must contain only name and description",
        )
        check(
            metadata.get("name") == "lawyer-diagrams",
            f"{display_path(skill)}: diagram Skill name drift",
        )
        check(
            "Privacy" in metadata.get("description", ""),
            f"{display_path(skill)}: diagram Skill description must name the Privacy approval boundary",
        )
    text = skill.read_text(encoding="utf-8")
    heading = _first_operational_heading(text)
    check(
        "CASE_RAW" in heading and "不可覆盖" in heading,
        f"{display_path(skill)}: first operational section must be the non-overridable CASE_RAW gate",
    )
    for marker in DIAGRAM_SKILL_PRIVACY_MARKERS:
        check(marker in text, f"{display_path(skill)}: missing mandatory privacy marker {marker}")
    present = {
        path.relative_to(skill_root).as_posix()
        for path in skill_root.rglob("*")
        if path.is_file()
    }
    missing = sorted(DIAGRAM_SKILL_REQUIRED_FILES - present)
    check(not missing, f"{display_path(skill_root)}: required self-contained files missing: {missing}")
    for path in skill_root.rglob("*"):
        if not path.is_file():
            continue
        check(not path.is_symlink(), f"{display_path(path)}: symlinks are forbidden in Skill packages")
        check(path.stat().st_size <= MAX_SKILL_FILE_BYTES, f"{display_path(path)}: Skill file exceeds size limit")
    _validate_package_links(skill_root)


def validate_skill_packages(integrations_root: Path = INTEGRATIONS) -> None:
    validate_skill_frontmatter(integrations_root)
    _validate_principal_privacy_rules(integrations_root)
    _validate_diagram_skill_privacy_rule(integrations_root)
    for host, required in SKILL_REQUIRED_FILES.items():
        skill_root = integrations_root / host / "skill" / "lawyer-assistance"
        present = {path.relative_to(skill_root).as_posix() for path in skill_root.rglob("*") if path.is_file()}
        missing = sorted(required - present)
        check(not missing, f"{display_path(skill_root)}: required self-contained files missing: {missing}")
        for path in skill_root.rglob("*"):
            if not path.is_file():
                continue
            check(not path.is_symlink(), f"{display_path(path)}: symlinks are forbidden in Skill packages")
            check(path.stat().st_size <= MAX_SKILL_FILE_BYTES, f"{display_path(path)}: Skill file exceeds size limit")
        _validate_package_links(skill_root)
    check(
        not (integrations_root / "workbuddy" / "skill" / "lawyer-assistance" / "agents" / "openai.yaml").exists(),
        "WorkBuddy Skill must not contain Codex UI metadata",
    )


def validate_no_legacy_case_workflows(integrations_root: Path = INTEGRATIONS) -> None:
    extensions = {".md", ".json", ".toml", ".yaml", ".yml"}
    for path in integrations_root.rglob("*"):
        if not path.is_file() or (path.suffix.lower() not in extensions and not path.name.endswith(".md.example")):
            continue
        text = path.read_text(encoding="utf-8")
        for marker in LEGACY_WORKFLOW_MARKERS:
            check(marker.lower() not in text.lower(), f"{display_path(path)}: legacy case workflow marker is forbidden: {marker}")


def validate_repository_privacy_boundary(paths: Iterable[Path] | None = None) -> None:
    if paths is None:
        roots = (ROOT / "README.md", ROOT / "RELEASE_NOTES.md", ROOT / "docs" / "mcp", INTEGRATIONS)
        candidates: list[Path] = []
        for root in roots:
            if root.is_file():
                candidates.append(root)
            elif root.exists():
                candidates.extend(root.rglob("*.md"))
                candidates.extend(root.rglob("*.md.example"))
        paths = candidates
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in FORBIDDEN_HOST_PERMISSION_SNIPPETS:
            check(snippet not in text, f"{display_path(path)}: repository documentation permits CASE_RAW host content: {snippet}")
        for pattern in FORBIDDEN_HOST_PERMISSION_PATTERNS:
            check(pattern.search(text) is None, f"{display_path(path)}: repository documentation permits CASE_RAW host content")
def validate_rust_registry() -> None:
    path = ROOT / "crates" / "legal-mcp" / "src" / "registry.rs"
    check(path.is_file(), f"{display_path(path)}: Rust registry missing")
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    match = re.search(r"pub const TOOL_NAMES:\s*\[&str;\s*5\]\s*=\s*\[(.*?)\];", text, re.DOTALL)
    check(match is not None, "Rust registry must declare a five-item TOOL_NAMES public list")
    if match:
        names = tuple(re.findall(r'"([a-z_]+)"', match.group(1)))
        check(names == EXPECTED_TOOLS, "Rust public registry and integration catalog differ")
    check(
        re.search(r"#\[default\][\s\S]{0,160}PublicLawOnly", text) is not None,
        "Rust default privacy profile must remain PublicLawOnly",
    )


def validate_clean_markers(integrations_root: Path = INTEGRATIONS) -> None:
    marker = re.compile("|".join(("TO" + "DO", "T" + "BD", "FIX" + "ME")), re.IGNORECASE)
    extensions = {".md", ".json", ".toml", ".yaml", ".yml", ".py"}
    for path in integrations_root.rglob("*"):
        if not path.is_file() or (path.suffix.lower() not in extensions and not path.name.endswith(".md.example")):
            continue
        text = path.read_text(encoding="utf-8")
        check(marker.search(text) is None, f"{display_path(path)}: unfinished-work marker is forbidden")
        check(
            re.search(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{16,}", text) is None,
            f"{display_path(path)}: possible hard-coded bearer credential",
        )


def validate_integrations_root(integrations_root: Path = INTEGRATIONS) -> tuple[int, int]:
    json_documents, toml_documents = _documents(integrations_root)
    documents = {**json_documents, **toml_documents}
    for path, data in documents.items():
        if data is not None:
            validate_no_literal_secrets(path, data)
            validate_no_dangerous_transport_opt_in(path, data)
    validate_catalog(json_documents.get(integrations_root / "tool-catalog.json"))
    validate_workbuddy(json_documents, integrations_root)
    validate_codex(toml_documents, integrations_root)
    validate_opencode(json_documents, integrations_root)
    validate_skill_packages(integrations_root)
    validate_no_legacy_case_workflows(integrations_root)
    validate_clean_markers(integrations_root)
    return len(json_documents), len(toml_documents)


def main() -> int:
    ERRORS.clear()
    json_count, toml_count = validate_integrations_root()
    validate_repository_privacy_boundary()
    validate_rust_registry()
    if ERRORS:
        for error in ERRORS:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"validation failed with {len(ERRORS)} error(s)", file=sys.stderr)
        return 1
    print(
        f"validated {json_count} JSON files, {toml_count} TOML files, "
        f"and {len(EXPECTED_TOOLS)} canonical public-law tools"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
