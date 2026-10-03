#!/usr/bin/env python3
"""Scan OpenClaw/NemoClaw SKILL.md files.

The scanner is intentionally external to the agent. It does not patch or import
OpenClaw/NemoClaw code; it reads the agent's config/data filesystem and emits
SkillInput-compatible objects for rail-center registration payloads.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


DEFAULT_AGENT_ROOTS = (
    "/home/node/.openclaw",
    "/workdir/.openclaw",
    "/usr/local/lib/node_modules/openclaw/skills",
    "/usr/local/lib/node_modules/openclaw/dist/extensions",
)

DEFAULT_HOST_ROOTS = (
    "~/.openclaw",
    "~/.config/openclaw",
    ".openclaw",
)

ENDPOINT_KEYS = {
    "destination_endpoints",
    "destination_endpoint",
    "destinations",
    "endpoints",
    "service_urls",
    "service_url",
    "urls",
}

SECRET_QUERY_RE = re.compile(r"(token|key|secret|password|credential|auth)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>'\"`)\]}]+", re.IGNORECASE)


@dataclass(frozen=True)
class SkillDocument:
    source: str
    path: str
    text: str


class ScannerError(RuntimeError):
    """Raised for user-correctable scanner errors."""


def run_command(cmd: list[str], timeout: float = 10.0) -> str | None:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def truncate(value: str, max_len: int) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 3].rstrip() + "..."


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines:
        return {}, text

    if lines[0].strip() != "---":
        for idx, line in enumerate(lines[:40]):
            if line.strip() != "---":
                continue
            prefix = lines[:idx]
            has_metadata = any(re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:", item) for item in prefix)
            if has_metadata:
                return parse_simple_frontmatter(prefix), "\n".join(lines[idx + 1 :])
            return {}, text
        return {}, text

    end = None
    for idx, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = idx
            break
    if end is None:
        return {}, text

    frontmatter = parse_simple_frontmatter(lines[1:end])
    body = "\n".join(lines[end + 1 :])
    return frontmatter, body


def parse_simple_frontmatter(lines: list[str]) -> dict[str, Any]:
    """Parse a small YAML subset without adding a dependency.

    Supports scalar fields and list fields in the form:
      key: value
      key:
        - value
    """
    data: dict[str, Any] = {}
    current_key: str | None = None

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        stripped = raw.strip()
        if raw[:1].isspace() and current_key and stripped.startswith("- "):
            value = strip_quotes(stripped[2:])
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(value)
            continue

        current_key = None
        if ":" not in raw:
            continue

        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if not value:
            data[key] = []
            current_key = key
            continue

        if value.startswith("[") and value.endswith("]"):
            try:
                parsed = json.loads(value)
                data[key] = parsed
                continue
            except json.JSONDecodeError:
                pass

        data[key] = strip_quotes(value)
    return data


def first_heading(body: str) -> str | None:
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or None
    return None


def first_paragraph(body: str) -> str | None:
    paragraph: list[str] = []
    in_fence = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            if paragraph:
                break
            continue
        if stripped.startswith(("#", "-", "*", "|", ">", "<!--")):
            continue
        paragraph.append(stripped)
    if not paragraph:
        return None
    return " ".join(paragraph)


def sanitize_url(raw_url: str) -> str | None:
    candidate = raw_url.rstrip(".,;:")
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None

    hostname = parts.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = hostname
    try:
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
    except ValueError:
        return None

    path = parts.path or ""
    # Drop query/fragment entirely. SKILL.md often contains examples, and
    # query strings are the most common place for accidental secrets.
    if parts.query and not SECRET_QUERY_RE.search(parts.query):
        pass
    return urlunsplit((parts.scheme.lower(), netloc, path, "", ""))


def endpoint_values_from_frontmatter(frontmatter: dict[str, Any]) -> list[str]:
    endpoints: list[str] = []
    for key, value in frontmatter.items():
        if key.lower().replace("-", "_") not in ENDPOINT_KEYS:
            continue
        if isinstance(value, str):
            endpoints.append(value)
        elif isinstance(value, list):
            endpoints.extend(str(item) for item in value if item)
    return endpoints


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for raw in URL_RE.findall(text):
        sanitized = sanitize_url(raw)
        if sanitized:
            urls.append(sanitized)
    return dedupe(urls)


def parse_skill_document(document: SkillDocument) -> dict[str, Any]:
    frontmatter, body = split_frontmatter(document.text)

    name = (
        str(frontmatter.get("name") or "").strip()
        or first_heading(body)
        or Path(document.path).parent.name
        or "unknown-skill"
    )
    description = (
        str(frontmatter.get("description") or "").strip()
        or first_paragraph(body)
        or f"Skill loaded from {document.path}"
    )

    endpoint_candidates = endpoint_values_from_frontmatter(frontmatter)
    endpoint_candidates.extend(extract_urls(document.text))
    endpoints = dedupe(
        endpoint
        for endpoint in (sanitize_url(value) for value in endpoint_candidates)
        if endpoint is not None
    )

    return {
        "name": truncate(name, 255),
        "description": truncate(description, 1000),
        "destination_endpoints": endpoints,
        "source_type": "skills_config",
    }


def read_host_text(path: Path, max_bytes: int = 256_000) -> str | None:
    try:
        with path.open("rb") as f:
            return f.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return None


def find_host_skill_documents(root: Path) -> list[SkillDocument]:
    expanded = root.expanduser()
    if not expanded.exists():
        return []

    paths = [expanded] if expanded.is_file() and expanded.name == "SKILL.md" else sorted(expanded.rglob("SKILL.md"))
    documents: list[SkillDocument] = []
    for path in paths:
        if not path.is_file():
            continue
        text = read_host_text(path)
        if text is None:
            continue
        documents.append(SkillDocument(source="host", path=str(path), text=text))
    return documents


def docker_inspect(container: str) -> dict[str, Any] | None:
    output = run_command(["docker", "inspect", container], timeout=10.0)
    if not output:
        return None
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    return data[0]


def mounted_host_roots(container: str, destinations: list[str]) -> list[Path]:
    inspect = docker_inspect(container)
    if not inspect:
        return []

    roots: list[Path] = []
    destination_set = {dest.rstrip("/") for dest in destinations}
    for mount in inspect.get("Mounts") or []:
        destination = str(mount.get("Destination") or "").rstrip("/")
        source = mount.get("Source")
        if not destination or not source:
            continue
        if destination in destination_set or any(dest.startswith(destination + "/") for dest in destination_set):
            roots.append(Path(str(source)))
    return roots


def find_container_skill_paths(container: str, roots: list[str]) -> list[str]:
    quoted_roots = " ".join(shlex.quote(root) for root in roots)
    script = (
        f"for d in {quoted_roots}; do "
        '[ -d "$d" ] && find "$d" -type f -name SKILL.md 2>/dev/null; '
        "done"
    )
    output = run_command(["docker", "exec", container, "sh", "-lc", script], timeout=15.0)
    if not output:
        return []
    return dedupe([line.strip() for line in output.splitlines() if line.strip()])


def read_container_file(container: str, path: str) -> str | None:
    output = run_command(["docker", "exec", container, "sh", "-lc", f"cat {shlex.quote(path)}"], timeout=10.0)
    if output is None:
        return None
    return output


def find_container_skill_documents(container: str, roots: list[str]) -> list[SkillDocument]:
    documents: list[SkillDocument] = []
    for path in find_container_skill_paths(container, roots):
        text = read_container_file(container, path)
        if text is None:
            continue
        documents.append(SkillDocument(source=f"container:{container}", path=path, text=text))
    return documents


def env_host_roots() -> list[Path]:
    configured = os.environ.get("RAIL_SCAN_SKILL_ROOTS")
    roots: list[str] = []
    if configured:
        for chunk in re.split(r"[:,]", configured):
            if chunk.strip():
                roots.append(chunk.strip())
    roots.extend(DEFAULT_HOST_ROOTS)
    return [Path(root) for root in roots]


def collect_documents(args: argparse.Namespace) -> list[SkillDocument]:
    documents: list[SkillDocument] = []

    host_roots = [Path(root) for root in args.root] if args.root else []
    if not host_roots and not args.container:
        host_roots = env_host_roots()

    for root in host_roots:
        documents.extend(find_host_skill_documents(root))

    container_roots = args.container_root or list(DEFAULT_AGENT_ROOTS)
    for container in args.container:
        for mounted_root in mounted_host_roots(container, container_roots):
            documents.extend(find_host_skill_documents(mounted_root))
        documents.extend(find_container_skill_documents(container, container_roots))

    seen_paths: set[tuple[str, str]] = set()
    unique: list[SkillDocument] = []
    for doc in documents:
        key = (doc.source, doc.path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        unique.append(doc)
    return unique


def merge_skills(skills: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for skill in skills:
        key = (skill["source_type"], skill["name"])
        if key not in merged:
            merged[key] = skill
            continue
        merged[key]["destination_endpoints"] = dedupe(
            [*merged[key]["destination_endpoints"], *skill["destination_endpoints"]]
        )
        if len(skill["description"]) > len(merged[key]["description"]):
            merged[key]["description"] = skill["description"]
    return [merged[key] for key in sorted(merged)]


def scan_skills(args: argparse.Namespace) -> list[dict[str, Any]]:
    return merge_skills([parse_skill_document(document) for document in collect_documents(args)])


def infer_sandbox_type(args: argparse.Namespace) -> str:
    if args.sandbox_type:
        return args.sandbox_type
    agent = (args.agent or "").lower()
    if agent in {"nemoclaw", "nemo_claw", "nemo-claw"}:
        return "nemo_claw"
    if agent in {"openclaw", "open-claw"}:
        return "openclaw"

    markers: list[str] = []
    for container in args.container:
        inspect = docker_inspect(container) or {}
        config = inspect.get("Config") or {}
        markers.extend(
            [
                str(config.get("Image") or ""),
                str(inspect.get("Name") or ""),
                str(config.get("Cmd") or ""),
                str(config.get("Entrypoint") or ""),
            ]
        )
    joined = " ".join(markers).lower()
    if "nemoclaw" in joined or "nvidia/nemoclaw" in joined or "openshell" in joined:
        return "nemo_claw"
    if "openclaw" in joined:
        return "openclaw"
    return "unknown"


def current_owner(explicit: str | None) -> str:
    if explicit:
        return explicit
    for key in ("RAIL_OWNER", "USER", "LOGNAME"):
        value = os.environ.get(key)
        if value:
            return value
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def build_registration_payload(args: argparse.Namespace, skills: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "type": args.agent_type,
        "owner": current_owner(args.owner),
        "environment": {
            "sandbox_type": infer_sandbox_type(args),
            "llm_provider": args.llm_provider or os.environ.get("RAIL_LLM_PROVIDER") or "unknown",
            "llm_model": args.llm_model or os.environ.get("RAIL_LLM_MODEL") or "unknown",
            "system_info": {
                "hostname": socket.gethostname(),
                "scanner": "skills-scanner",
                "scanner_version": "0.1.0",
                "skill_roots": args.root,
                "container_roots": args.container_root or list(DEFAULT_AGENT_ROOTS),
                "containers": args.container,
            },
            "user_info": {
                "owner_source": "cli" if args.owner else "environment",
            },
        },
        "skills": skills,
    }


def output_object(args: argparse.Namespace) -> Any:
    skills = scan_skills(args)
    if args.payload or args.register:
        return build_registration_payload(args, skills)
    return skills


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def render_json(value: Any, compact: bool) -> str:
    if compact:
        return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write_output(args: argparse.Namespace, value: Any) -> None:
    text = render_json(value, args.compact)
    if args.output:
        Path(args.output).expanduser().write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def registration_url(center_url: str) -> str:
    cleaned = center_url.rstrip("/")
    if cleaned.endswith("/v1/agents/register"):
        return cleaned
    return f"{cleaned}/v1/agents/register"


def post_registration(center_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        registration_url(center_url),
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": json.loads(body) if body else None}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ScannerError(f"rail-center registration failed: HTTP {exc.code}: {body}") from exc
    except (URLError, OSError) as exc:
        raise ScannerError(f"rail-center registration failed: {exc}") from exc


def emit_once(args: argparse.Namespace) -> Any:
    value = output_object(args)
    if args.register:
        if not isinstance(value, dict):
            raise ScannerError("--register requires registration payload output")
        if not args.center_url:
            raise ScannerError("--center-url is required with --register")
        response = post_registration(args.center_url, value)
        if args.output_register_response:
            value = {"registration_payload": value, "registration_response": response}
        else:
            print(
                f"[skills-scanner] registered with rail-center: HTTP {response['status']}",
                file=sys.stderr,
            )
    write_output(args, value)
    return value


def run_loop(args: argparse.Namespace) -> int:
    last_hash: str | None = None
    next_time_scan = 0.0

    while True:
        now = time.time()
        value = output_object(args)
        digest = canonical_hash(value)
        changed = digest != last_hash
        due = args.interval_seconds > 0 and now >= next_time_scan

        if changed or due:
            if args.register:
                if not args.center_url:
                    raise ScannerError("--center-url is required with --register")
                response = post_registration(args.center_url, value)
                print(
                    f"[skills-scanner] registered with rail-center: HTTP {response['status']}",
                    file=sys.stderr,
                )
            write_output(args, value)
            last_hash = digest
            if args.interval_seconds > 0:
                next_time_scan = now + args.interval_seconds

        time.sleep(args.poll_interval)


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan real OpenClaw/NemoClaw SKILL.md files and emit rail-center SkillInput objects."
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Host file/directory to scan. Can be passed multiple times.",
    )
    parser.add_argument(
        "--container",
        action="append",
        default=[],
        help="Running Docker container name/id to scan without modifying the agent.",
    )
    parser.add_argument(
        "--container-root",
        action="append",
        default=[],
        help="Path inside each container to scan. Defaults to OpenClaw/NemoClaw data roots.",
    )
    parser.add_argument("--output", "-o", help="Write JSON output to this file instead of stdout.")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON.")
    parser.add_argument("--watch", action="store_true", help="Poll roots and emit when SKILL.md content changes.")
    parser.add_argument(
        "--poll-interval",
        type=positive_float,
        default=5.0,
        help="Seconds between trigger-based scans in --watch mode.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=positive_float,
        default=0.0,
        help="Also emit on this time interval. Use 86400 for daily scanning.",
    )
    parser.add_argument("--daily", action="store_true", help="Shortcut for --interval-seconds 86400.")
    parser.add_argument(
        "--payload",
        action="store_true",
        help="Emit a complete RegisterAgentRequest payload instead of only the skills list.",
    )
    parser.add_argument("--agent", choices=["auto", "openclaw", "nemoclaw"], default="auto")
    parser.add_argument("--agent-type", choices=["personal", "service"], default="personal")
    parser.add_argument("--owner", help="Owner value for --payload/--register.")
    parser.add_argument("--sandbox-type", help="Sandbox override, e.g. openclaw or nemo_claw.")
    parser.add_argument("--llm-provider", help="LLM provider for --payload/--register.")
    parser.add_argument("--llm-model", help="LLM model for --payload/--register.")
    parser.add_argument("--register", action="store_true", help="POST the generated payload to rail-center.")
    parser.add_argument("--center-url", help="rail-center base URL or /v1/agents/register URL.")
    parser.add_argument(
        "--output-register-response",
        action="store_true",
        help="Include rail-center response in stdout/output when --register is used.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.daily:
        args.interval_seconds = 86_400.0
    if args.register:
        args.payload = True

    try:
        if args.watch or args.interval_seconds > 0:
            return run_loop(args)
        emit_once(args)
    except ScannerError as exc:
        print(f"skills-scanner: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[skills-scanner] stopped", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
