#!/usr/bin/env python3
"""Agent registration environment scanner.

Builds a registration payload compatible with rail-center's
POST /v1/agents/register schema.
"""

from __future__ import annotations

import argparse
import base64
import copy
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlopen


LOCAL_BASE_HOSTS = (
    "127.0.0.1",
    "0.0.0.0",
    "localhost",
    "host.docker.internal",
    "ollama",
    "llama",
    "llama.cpp",
    "lmstudio",
)

SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "CREDS")

# `PWD` earns its place in SECRET_MARKERS through DB_PWD and friends, but it is
# also the shell's own working-directory variable, present in essentially every
# environment. Without this exception every scan would report two benign
# variables as plaintext passwords, which is noise the scorer would have to
# learn to ignore.
NON_SECRET_KEYS = frozenset({"PWD", "OLDPWD"})
MODEL_KEYS = {
    "model",
    "llm_model",
    "default_model",
    "defaultModel",
    "model_name",
    "modelName",
}
DEFAULT_REGISTRATION_OUTPUT = Path(".rail") / "railmon" / "registration.json"
DEFAULT_FEATURE_OUTPUT = Path(".rail") / "railmon" / "features.json"
# RailScan-era defaults, still written where that layout is in use; see
# evidence_bundle.default_output.
LEGACY_REGISTRATION_OUTPUT = Path(".datrail") / "rail-guardian" / "registration.json"
LEGACY_FEATURE_OUTPUT = Path(".rail") / "railscan" / "features.json"
# A format identifier, not a path: consumers match on it, so it keeps the name
# the format was published under.
FEATURE_SCHEMA_VERSION = "railscan.features/v1"
DEFAULT_CONTAINER_CONFIG_ROOTS = (
    "/home/node/.openclaw",
    "/home/node/.config/openclaw",
    "/root/.openclaw",
    "/root/.config/openclaw",
)

# rail-center bounds both identity fields to their storage width. Truncating here
# turns what would surface as a database error into a value the control plane
# accepts, and the feature file records that it was truncated.
HOST_ID_MAX = 64
SANDBOX_NAME_MAX = 255

# The label an operator sets to name a sandbox explicitly. Read from the
# container's own metadata, never from an environment variable injected into the
# agent: discovering agents nobody onboarded is the point, and those carry no
# Rail configuration at all.
SANDBOX_NAME_LABEL = "rail.sandbox_name"

# Client-side credential modes, matching rail-center's RAIL_AUTH_MODES_ACCEPTED.
# Note the deliberate near-miss in the names: the server takes a list
# (RAIL_AUTH_MODES_ACCEPTED), a component takes one (RAIL_AUTH_MODE).
AUTH_MODES = ("none", "bearer", "gcp")

CANONICAL_LLM_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.com",
    "bedrock-runtime.amazonaws.com",
)

SECRET_TYPE_MARKERS = (
    ("api_key", ("API_KEY", "APIKEY")),
    ("access_token", ("ACCESS_TOKEN",)),
    ("refresh_token", ("REFRESH_TOKEN",)),
    ("token", ("TOKEN",)),
    ("password", ("PASSWORD", "PASSWD", "PWD")),
    ("credential", ("CREDENTIAL", "CREDS")),
    ("secret", ("SECRET",)),
    ("key", ("KEY",)),
)

# Values that name a secret elsewhere rather than carrying it. Matching these is
# what separates "this agent holds a plaintext key" from "this agent holds a
# pointer", which is the whole point of the secrets-hygiene dimension.
SECRET_REFERENCE_PREFIXES = (
    "projects/",
    "sm://",
    "vault:",
    "gcpsecret://",
    "arn:aws:secretsmanager:",
    "azurekeyvault://",
    "${",
)

# Credentials in the shapes their vendors actually issue. Length alone cannot
# catch these — `sk-live-abc12` is thirteen characters and still opens the
# account — but a bare prefix cannot be used either: `asia`, `akia` and `aiza`
# are the leading letters of AWS and Google keys *and* of ordinary words, so
# prefix matching would silently delete a skill named `asian-markets` and a host
# called `aizawa-metrics.internal`. Each entry therefore carries the length and
# character shape that distinguishes the key from the word.
SECRET_TOKEN_RES = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),  # OpenAI, Anthropic, and lookalikes
    re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),  # Stripe
    re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}"),  # GitHub
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{6,}"),  # GitLab
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}"),
    re.compile(r"npm_[A-Za-z0-9]{30,}"),
    re.compile(r"shpat_[a-f0-9]{20,}"),  # Shopify
    re.compile(r"hf_[A-Za-z0-9]{30,}"),  # Hugging Face
    re.compile(r"dop_v1_[a-f0-9]{32,}"),  # DigitalOcean
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),  # Google API key
    re.compile(r"ya29\.[A-Za-z0-9_-]{20,}"),  # Google OAuth
    re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}"),  # AWS access key id
)


class ScannerError(RuntimeError):
    """Raised for user-correctable scanner errors."""


def run_command(cmd: list[str], timeout: float = 2.0) -> str | None:
    """Run a command and return stdout, tolerating missing commands/failures."""
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def read_text(path: Path, max_bytes: int = 64_000) -> str | None:
    try:
        with path.open("rb") as f:
            return f.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return None


def hash_identifier(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.strip().encode()).hexdigest()[:16]


def parse_env_lines(text: str | None) -> dict[str, str]:
    env: dict[str, str] = {}
    if not text:
        return env
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key] = value
    return env


def looks_secret(key: str) -> bool:
    upper = key.upper()
    if upper in NON_SECRET_KEYS:
        return False
    return any(marker in upper for marker in SECRET_MARKERS)


def safe_env_keys(env: dict[str, str]) -> list[str]:
    return sorted(key for key in env if not looks_secret(key))


def first_nonempty(*values: str | None) -> str | None:
    for value in values:
        if value:
            stripped = value.strip()
            if stripped:
                return stripped
    return None


def normalize_sandbox_type(value: str | None) -> str | None:
    if not value:
        return None
    compact = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    aliases = {
        "nemo": "nemo_claw",
        "nemoclaw": "nemo_claw",
        "nemo_claw": "nemo_claw",
        "open_shell": "nemo_claw",
        "openshell": "nemo_claw",
        "open_claw": "openclaw",
        "openclaw": "openclaw",
        "baremetal": "bare_metal",
        "bare_metal": "bare_metal",
        "docker": "docker_container",
        "container": "docker_container",
    }
    return aliases.get(compact, compact)


def normalize_provider(value: str | None) -> str | None:
    if not value:
        return None
    compact = value.lower().strip()
    if compact in {"anthropic", "claude"}:
        return "anthropic"
    if compact in {"openai", "chatgpt"}:
        return "openai"
    if compact in {"local", "ollama", "llama", "llama.cpp", "lmstudio"}:
        return "local"
    return compact


def is_local_base_url(url: str | None) -> bool:
    """Whether the URL points at something on this machine or the local network.

    Compares the parsed host, not a substring of the whole URL: `ollama` and
    `localhost` appear inside `ollama.attacker.net` and `notlocalhost.example`,
    and calling those local would silence the egress signal more thoroughly than
    calling them canonical would.
    """
    if not url:
        return False
    host = url_host(url)
    if not host:
        return False
    return any(host == local or host.endswith("." + local) for local in LOCAL_BASE_HOSTS)


def infer_provider_from_model(model: str | None) -> str | None:
    if not model:
        return None
    lowered = model.lower()
    if lowered.startswith("claude"):
        return "anthropic"
    if lowered.startswith(("gpt-", "o1", "o3", "o4", "o5")):
        return "openai"
    if any(name in lowered for name in ("llama", "mistral", "qwen", "gemma", "deepseek", "phi")):
        return "local"
    return None


def detect_provider(env: dict[str, str], model: str | None = None, explicit: str | None = None) -> str:
    provider = normalize_provider(first_nonempty(explicit, env.get("RAIL_LLM_PROVIDER"), env.get("LLM_PROVIDER")))
    if provider:
        return provider

    openai_base = first_nonempty(env.get("OPENAI_BASE_URL"), env.get("OPENAI_API_BASE"))
    if env.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if env.get("OPENAI_API_KEY"):
        return "local" if is_local_base_url(openai_base) else "openai"
    if openai_base and is_local_base_url(openai_base):
        return "local"
    if env.get("OLLAMA_HOST"):
        return "local"

    return infer_provider_from_model(model) or "unknown"


def collect_candidate_models(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in MODEL_KEYS and isinstance(item, str) and item.strip():
                found.append(item.strip())
            found.extend(collect_candidate_models(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_candidate_models(item))
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                found.extend(collect_candidate_models(json.loads(stripped)))
            except (json.JSONDecodeError, TypeError):
                pass
    return found


def load_json_file(path: Path) -> Any | None:
    text = read_text(path)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def find_models_in_capture(paths: list[Path]) -> list[str]:
    models: list[str] = []
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    models.extend(collect_candidate_models(event))
        except OSError:
            continue
    return dedupe(models)


def find_models_in_openclaw_config(paths: list[Path]) -> list[str]:
    models: list[str] = []
    for path in paths:
        if path.is_file():
            data = load_json_file(path)
            if data is not None:
                models.extend(collect_candidate_models(data))
        elif path.is_dir():
            for child in sorted(path.glob("*.json")):
                data = load_json_file(child)
                if data is not None:
                    models.extend(collect_candidate_models(data))
    return dedupe(models)


def find_container_config_files(container: str, roots: list[str]) -> list[str]:
    quoted_roots = " ".join(shlex.quote(root) for root in roots if root)
    if not quoted_roots:
        return []
    script = f"""
for root in {quoted_roots}; do
  if [ -d "$root" ]; then
    find "$root" -maxdepth 4 -type f \\( -name '*.json' -o -name '*.jsonl' \\) 2>/dev/null
  elif [ -f "$root" ]; then
    printf '%s\\n' "$root"
  fi
done
"""
    output = run_command(["docker", "exec", container, "sh", "-lc", script], timeout=10.0)
    if not output:
        return []
    return dedupe([line.strip() for line in output.splitlines() if line.strip()])


def read_container_file(container: str, path: str, max_bytes: int = 256_000) -> str | None:
    script = f"head -c {int(max_bytes)} {shlex.quote(path)}"
    return run_command(["docker", "exec", container, "sh", "-lc", script], timeout=5.0)


def find_models_in_container_openclaw_config(container: str, roots: list[str]) -> list[str]:
    models: list[str] = []
    for path in find_container_config_files(container, roots):
        text = read_container_file(container, path)
        if not text:
            continue
        for line in text.splitlines() if path.endswith(".jsonl") else [text]:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                models.extend(collect_candidate_models(json.loads(stripped)))
            except json.JSONDecodeError:
                continue
    return dedupe(models)


def detect_model(
    env: dict[str, str],
    capture_files: list[Path],
    config_paths: list[Path],
    explicit: str | None = None,
) -> tuple[str, str]:
    env_model = first_nonempty(
        explicit,
        env.get("RAIL_LLM_MODEL"),
        env.get("LLM_MODEL"),
        env.get("OPENAI_MODEL"),
        env.get("ANTHROPIC_MODEL"),
        env.get("OPENCLAW_MODEL"),
        env.get("MODEL"),
    )
    if env_model:
        return env_model, "env_or_cli"

    config_models = find_models_in_openclaw_config(config_paths)
    if config_models:
        return config_models[-1], "openclaw_config"

    capture_models = find_models_in_capture(capture_files)
    if capture_models:
        return capture_models[-1], "capture_file"

    return "unknown", "not_detected"


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def detect_container_id() -> str | None:
    cgroup = read_text(Path("/proc/self/cgroup"))
    if not cgroup:
        return None
    matches = re.findall(r"([0-9a-f]{64}|[0-9a-f]{12})(?:\.scope)?", cgroup)
    return matches[-1] if matches else None


def in_container() -> bool:
    return Path("/.dockerenv").exists() or detect_container_id() is not None


def collect_self_context() -> dict[str, Any]:
    env = dict(os.environ)
    cmdline = read_text(Path("/proc/1/cmdline"))
    proc1_cmdline = redact_cmdline(cmdline.replace("\x00", " ").strip()) if cmdline else None
    return {
        "mode": "self",
        "env": env,
        "hostname": socket.gethostname(),
        "image": None,
        "container_name": None,
        "container_id": detect_container_id(),
        "proc1_cmdline": proc1_cmdline,
        "docker_inspect": None,
    }


def docker_inspect(container: str) -> dict[str, Any]:
    output = run_command(["docker", "inspect", container], timeout=5.0)
    if not output:
        raise ScannerError(f"docker inspect failed for container: {container}")
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ScannerError("docker inspect returned invalid JSON") from exc
    if not data:
        raise ScannerError(f"container not found: {container}")
    return data[0]


def collect_docker_context(container: str) -> dict[str, Any]:
    inspect = docker_inspect(container)
    config = inspect.get("Config") or {}
    state = inspect.get("State") or {}
    name = str(inspect.get("Name") or "").lstrip("/") or container
    env = parse_env_lines("\n".join(config.get("Env") or []))

    exec_env = run_command(["docker", "exec", container, "env"], timeout=5.0)
    env.update(parse_env_lines(exec_env))
    hostname = first_nonempty(
        run_command(["docker", "exec", container, "hostname"], timeout=2.0),
        config.get("Hostname"),
        name,
    )
    cmd_parts = [str(config.get("Entrypoint") or ""), str(config.get("Cmd") or ""), str(inspect.get("Path") or "")]
    return {
        "mode": "docker",
        "env": env,
        "hostname": hostname,
        "image": config.get("Image"),
        "container_name": name,
        "container_id": inspect.get("Id"),
        "proc1_cmdline": redact_cmdline(" ".join(cmd_parts)),
        "docker_inspect": inspect,
        "docker_state_pid": state.get("Pid"),
    }


def detect_sandbox_type(context: dict[str, Any], explicit: str | None = None) -> str:
    env = context["env"]
    sandbox = normalize_sandbox_type(
        first_nonempty(
            explicit,
            env.get("RAIL_SANDBOX_TYPE"),
            env.get("SANDBOX_TYPE"),
        )
    )
    if sandbox:
        return sandbox

    markers = " ".join(
        str(value or "")
        for value in (
            context.get("image"),
            context.get("container_name"),
            context.get("hostname"),
            context.get("proc1_cmdline"),
            env.get("NEMOCLAW_HOME"),
            env.get("OPENCLAW_HOME"),
        )
    ).lower()

    if "nemoclaw" in markers or "nvidia/nemoclaw" in markers or "openshell" in markers:
        return "nemo_claw"
    if "openclaw" in markers or Path("/home/node/.openclaw").exists():
        return "openclaw"
    if context["mode"] == "docker" or in_container():
        return "docker_container"
    return "bare_metal"


def parse_os_release(text: str | None = None) -> dict[str, str]:
    if text is None:
        text = read_text(Path("/etc/os-release"))
    if not text:
        return {}
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.lower()] = value.strip().strip('"')
    return result


def runtime_versions(container: str | None = None) -> dict[str, str]:
    commands = {
        "python": ["python3", "--version"],
        "node": ["node", "--version"],
        "openclaw": ["openclaw", "--version"],
        "claude": ["claude", "--version"],
    }
    versions: dict[str, str] = {}
    for name, cmd in commands.items():
        full_cmd = ["docker", "exec", container, *cmd] if container else cmd
        output = run_command(full_cmd, timeout=3.0)
        if output:
            versions[name] = output.splitlines()[0]
    return versions


def primary_runtime(runtimes: dict[str, str]) -> str | None:
    for name in ("openclaw", "claude", "node", "python"):
        if name in runtimes:
            return runtimes[name]
    return None


def collect_system_info(context: dict[str, Any], model_source: str, capture_files: list[Path]) -> dict[str, Any]:
    container = context.get("container_name") if context["mode"] == "docker" else None
    uname = run_command(["docker", "exec", container, "uname", "-srm"], timeout=3.0) if container else None
    os_release_text = run_command(["docker", "exec", container, "cat", "/etc/os-release"], timeout=3.0) if container else None
    machine_id_text = run_command(["docker", "exec", container, "cat", "/etc/machine-id"], timeout=3.0) if container else None
    if not uname:
        uname = " ".join(platform.uname())

    machine_id_hash = hash_identifier(machine_id_text if container else read_text(Path("/etc/machine-id"), max_bytes=256))
    runtimes = runtime_versions(container)
    info: dict[str, Any] = {
        "os": platform.system(),
        "os_release": parse_os_release(os_release_text),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "uname": uname,
        "runtime": primary_runtime(runtimes),
        "runtimes": runtimes,
        "hostname": context.get("hostname"),
        "fqdn": socket.getfqdn(),
        "machine_id_sha256": machine_id_hash,
        "container": {
            "is_container": context["mode"] == "docker" or in_container(),
            "id": context.get("container_id"),
            "name": context.get("container_name"),
            "image": context.get("image"),
            "host_pid": context.get("docker_state_pid"),
        },
        "process": {
            "pid": os.getpid(),
            "proc1_cmdline": context.get("proc1_cmdline"),
            "cwd": str(Path.cwd()),
        },
        "model_source": model_source,
        "capture_files": [str(path) for path in capture_files],
        "environment_keys": safe_env_keys(context["env"]),
    }
    return drop_none(info)


def git_config_value(key: str) -> str | None:
    return run_command(["git", "config", "--global", "--get", key], timeout=1.0)


def collect_user_info(context: dict[str, Any], owner: str, owner_source: str) -> dict[str, Any]:
    env = context["env"]
    username = first_nonempty(env.get("USER"), env.get("LOGNAME"))
    if not username:
        try:
            username = getpass.getuser()
        except Exception:
            username = None

    user_info: dict[str, Any] = {
        "owner": owner,
        "owner_source": owner_source,
        "username": username,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "home": env.get("HOME"),
        "git_user_name": git_config_value("user.name"),
        "git_user_email": git_config_value("user.email"),
    }

    if context["mode"] == "docker" and context.get("container_name"):
        container = context["container_name"]
        user_info["container_username"] = run_command(["docker", "exec", container, "id", "-un"], timeout=2.0)
        user_info["container_uid"] = run_command(["docker", "exec", container, "id", "-u"], timeout=2.0)
        user_info["container_gid"] = run_command(["docker", "exec", container, "id", "-g"], timeout=2.0)

    return drop_none(user_info)


def detect_owner(env: dict[str, str], explicit: str | None = None) -> tuple[str, str]:
    candidates = [
        ("cli", explicit),
        ("RAIL_OWNER", env.get("RAIL_OWNER")),
        ("GIT_AUTHOR_EMAIL", env.get("GIT_AUTHOR_EMAIL")),
        ("git user.email", git_config_value("user.email")),
        ("USER", env.get("USER")),
        ("LOGNAME", env.get("LOGNAME")),
    ]
    for source, value in candidates:
        if value and value.strip():
            return value.strip(), source
    return "unknown", "fallback"


def default_config_paths(env: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    home = env.get("HOME")
    if home:
        paths.append(Path(home) / ".openclaw")
        paths.append(Path(home) / ".config" / "openclaw")
    paths.append(Path("/home/node/.openclaw"))
    paths.append(Path.cwd() / ".openclaw")
    return paths


def read_mcp_inventory(path: Path) -> list[dict[str, Any]]:
    """MCP servers as inventory: name, how it is reached, and the transport.

    The skills view of the same file describes what an agent can *do*; this one
    describes what it can *reach*, which is the dimension the scorer weighs.
    """
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []

    inventory: list[dict[str, Any]] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url")
        command = spec.get("command")
        inventory.append(
            {
                # An operator-chosen nickname, but this file is persisted and
                # shipped to a scorer the same as a skill's name/description —
                # same redact_text() treatment `normalize_skill` gives those.
                "name": redact_text(str(name)),
                # The executable, not its arguments: an MCP server is routinely
                # launched with `--token …` on the command line, and this file is
                # persisted and shipped to a scorer.
                "command": command_basename(command),
                "url": redact_url(url) if isinstance(url, str) else None,
                "transport": "http" if url else ("stdio" if command else "unknown"),
                "source": path.name,
            }
        )
    return inventory


# The per-server env convention confirmed by Kyle Liwanag for the GCP estate
# behind DR-123 (`compose.agent-zone.yml`): one MCP server per agent, named and
# located by a pair of env vars rather than a `.mcp.json` on disk.
ENV_MCP_NAME_KEY = "AGENT_MCP_NAME"
ENV_MCP_URL_KEY = "AGENT_MCP_URL"


def read_mcp_inventory_from_env(env: dict[str, str]) -> list[dict[str, Any]]:
    """The single env-declared MCP server as inventory, mirroring `read_mcp_inventory`.

    An estate with no `.mcp.json` at all still declares its one server this way
    (`AGENT_MCP_NAME`/`AGENT_MCP_URL`); without this the file-derived inventory is
    silently empty and a scan reports the agent as having no tools.
    """
    name = env.get(ENV_MCP_NAME_KEY)
    url = env.get(ENV_MCP_URL_KEY)
    if not name or not url:
        return []
    return [
        {
            "name": redact_text(name),
            "command": None,
            "url": redact_url(url),
            "transport": "http",
            "source": "environment",
        }
    ]


def collect_mcp_inventory(mcp_configs: list[Path], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Every declared MCP server, config-file and env sources combined.

    Deduped on (name, url) rather than name alone: DR-106 already fixed a
    silent-drop-on-name-collision bug one function over (`collect_skills`,
    where two independent servers commonly share a tool name) by merging
    instead of dropping. An inventory entry has no comparable merge — but
    keying on (name, url) means a real duplicate (same server, same URL,
    seen twice — e.g. an onboarded agent whose env vars and `.mcp.json` both
    describe it) still collapses to one entry, while two servers that only
    happen to share a name keep both, instead of one silently vanishing.
    """
    inventory: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for path in mcp_configs:
        if not path.exists():
            continue
        for entry in read_mcp_inventory(path):
            key = (entry["name"], entry["url"])
            if key in seen:
                continue
            seen.add(key)
            inventory.append(entry)
    for entry in read_mcp_inventory_from_env(env or {}):
        key = (entry["name"], entry["url"])
        if key in seen:
            continue
        seen.add(key)
        inventory.append(entry)
    return inventory


def read_mcp_config(path: Path) -> list[dict[str, Any]]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []

    skills: list[dict[str, Any]] = []
    for name, spec in servers.items():
        if isinstance(spec, dict):
            skills.extend(mcp_server_skills(str(name), spec, path.name))
    return skills


def read_mcp_config_from_env(env: dict[str, str]) -> list[dict[str, Any]]:
    """Skills for the single env-declared MCP server, mirroring `read_mcp_config`."""
    name = env.get(ENV_MCP_NAME_KEY)
    url = env.get(ENV_MCP_URL_KEY)
    if not name or not url:
        return []
    return mcp_server_skills(name, {"url": url}, "environment")


def mcp_server_skills(name: str, spec: dict[str, Any], source_label: str) -> list[dict[str, Any]]:
    """One skill per tool a reachable MCP server declares.

    The scanner never asked a server what it exposes before this; it
    synthesized one skill per *configured* server instead. That makes the
    comparison DSC.G2 exists for impossible later without re-scanning an
    estate that has already changed, so a server that declares three tools
    now arrives as three skills, each carrying the tool's own description —
    and a server this cannot reach or authenticate to is still recorded, as
    unreachable, rather than dropped from the inventory silently.
    """
    endpoints = dedupe(
        redact_url(value) or "[unparseable]" for value in collect_strings(spec) if value.startswith(("http://", "https://"))
    )
    url = spec.get("url")
    if isinstance(url, str) and url:
        headers = spec.get("headers")
        headers = {str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else None
        tools = probe_mcp_tools(url, headers)
        if tools is None:
            return [unreachable_mcp_skill(name, source_label, endpoints, "unreachable")]
        result: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = first_nonempty(str(tool.get("name") or ""))
            if not tool_name:
                continue
            description = first_nonempty(redact_text(str(tool.get("description") or "")))
            result.append(
                {
                    "name": tool_name,
                    "description": description or f"tool declared by {name} ({source_label})",
                    "destination_endpoints": endpoints,
                    "source_type": "mcp_config",
                }
            )
        return result or [unreachable_mcp_skill(name, source_label, endpoints, "reachable, declares no tools")]

    command = spec.get("command")
    reached = command_basename(command)
    if not reached:
        return [unreachable_mcp_skill(name, source_label, endpoints, "unreachable")]
    return [
        {
            "name": name,
            "description": f"MCP server configured via {source_label}: {reached}",
            "destination_endpoints": endpoints,
            "source_type": "mcp_config",
        }
    ]


def unreachable_mcp_skill(name: str, source_label: str, endpoints: list[str], reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"MCP server configured via {source_label}: {reason}",
        "destination_endpoints": endpoints,
        "source_type": "mcp_config",
    }


MCP_PROBE_TIMEOUT_SECONDS = 3.0
MCP_PROTOCOL_VERSION = "2025-06-18"


def probe_mcp_tools(
    url: str, headers: dict[str, str] | None, timeout: float = MCP_PROBE_TIMEOUT_SECONDS
) -> list[dict[str, Any]] | None:
    """Every tool a live MCP server declares, or `None` if it could not be asked.

    Speaks only the two Streamable HTTP messages this needs: `initialize` to
    open a session (some servers require the session id it returns on every
    later call; stateless ones ignore it either way), then `tools/list`. Never
    raises — an agent's configured MCP server is untrusted input the scan must
    survive, and a probe failure is recorded as unreachable, not fatal to the
    rest of the scan.

    Only ever `http(s)://`. `urllib` also has a handler for `file://`, and it
    does not care that this sends a POST body: a config entry of
    `"url": "file:///etc/shadow"` would otherwise make the scanner read it and
    try to parse it as a tools/list response, which is a local file read this
    function must never become.
    """
    if not url.startswith(("http://", "https://")):
        return None
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        **(headers or {}),
    }
    init_result, response_headers = mcp_rpc_call(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "datrail-railmon-scanner", "version": "1"},
            },
        },
        base_headers,
        timeout,
    )
    if init_result is None:
        return None

    call_headers = dict(base_headers)
    session_id = response_headers.get("Mcp-Session-Id")
    if session_id:
        call_headers["Mcp-Session-Id"] = session_id

    list_result, _ = mcp_rpc_call(
        url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, call_headers, timeout
    )
    if list_result is None:
        return None
    tools = list_result.get("tools")
    return tools if isinstance(tools, list) else None


def mcp_rpc_call(
    url: str, body: dict[str, Any], headers: dict[str, str], timeout: float
) -> tuple[dict[str, Any] | None, Any]:
    """One JSON-RPC round trip to an MCP endpoint.

    Returns the response's `result` object and its headers, or `(None, {})` on
    any failure: refused connection, timeout, a non-2xx status, a body that
    isn't JSON or SSE-framed JSON, or a response with no `result`.
    """
    req = Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8", errors="replace")
            response_headers = resp.headers
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return None, {}

    payload = parse_mcp_body(raw, content_type)
    if not isinstance(payload, dict) or not isinstance(payload.get("result"), dict):
        return None, {}
    return payload["result"], response_headers


def parse_mcp_body(raw: str, content_type: str) -> Any:
    if "text/event-stream" in content_type:
        for line in raw.splitlines():
            if line.startswith("data:"):
                raw = line[len("data:") :].strip()
                break
        else:
            return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(collect_strings(item))
        return result
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(collect_strings(item))
        return result
    return []


def collect_skills(mcp_configs: list[Path], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Every mcp_config skill across every config path, same-name collisions merged.

    Used to dedupe on name alone and drop the second match outright — safe
    while `name` was an operator-chosen server nickname, but this now reads
    one skill per *tool*, and two independent servers commonly expose a tool
    of the same name (`search`, `list_files`). Discarding the second would
    silently drop that server's reachability from the inventory. Reuses
    `merge_skill_lists`'s union of `destination_endpoints`, the same merge the
    final registration payload already relies on for the analogous collision
    between mcp- and skills-file-derived skills.
    """
    skills: list[dict[str, Any]] = []
    for path in mcp_configs:
        if path.exists():
            skills.extend(read_mcp_config(path))
    skills.extend(read_mcp_config_from_env(env or {}))
    return merge_skill_lists(skills)


def normalize_skill(value: Any, source_hint: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScannerError(f"invalid skill in {source_hint}: expected object")

    # Redacted alongside the endpoints below, and for the same reason: these are
    # operator-written free-text fields that reach the feature file and the POST,
    # and a pasted key is exactly what lands in a description.
    name = first_nonempty(redact_text(str(value.get("name") or "")))
    description = first_nonempty(redact_text(str(value.get("description") or "")))
    if not name:
        raise ScannerError(f"invalid skill in {source_hint}: missing name")
    if not description:
        raise ScannerError(f"invalid skill in {source_hint}: missing description")

    endpoints_value = value.get("destination_endpoints", [])
    if endpoints_value is None:
        endpoints: list[str] = []
    elif isinstance(endpoints_value, list):
        # Redacted here rather than only where MCP configs are read: a skills
        # file is operator-supplied and its endpoints reach both the feature file
        # and the registration POST, so a gateway URL carrying its key in the
        # path would otherwise be persisted and shipped verbatim.
        endpoints = [redact_endpoint(str(item)) for item in endpoints_value if item is not None]
    else:
        raise ScannerError(f"invalid skill {name!r} in {source_hint}: destination_endpoints must be a list")

    source_type = first_nonempty(str(value.get("source_type") or "")) or "skills_config"
    return {
        "name": name,
        "description": description,
        "destination_endpoints": dedupe(endpoints),
        "source_type": source_type,
    }


def read_skills_file(path: Path) -> list[dict[str, Any]]:
    data = load_json_file(path)
    if data is None:
        raise ScannerError(f"skills file is not readable JSON: {path}")
    if isinstance(data, dict) and isinstance(data.get("skills"), list):
        raw_skills = data["skills"]
    elif isinstance(data, list):
        raw_skills = data
    else:
        raise ScannerError(f"skills file must be a SkillInput list or payload object with skills: {path}")
    return [normalize_skill(skill, str(path)) for skill in raw_skills]


def collect_skills_from_files(paths: list[Path]) -> list[dict[str, Any]]:
    skills: list[dict[str, Any]] = []
    for path in paths:
        skills.extend(read_skills_file(path))
    return skills


def merge_skill_lists(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for group in groups:
        for raw_skill in group:
            skill = normalize_skill(raw_skill, "generated skills")
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


def default_mcp_paths(env: dict[str, str]) -> list[Path]:
    paths = [Path.cwd() / ".mcp.json", Path("/workdir/.mcp.json")]
    home = env.get("HOME")
    if home:
        paths.append(Path(home) / ".mcp.json")
    return paths


HOST_ID_KEYS = ("RAIL_HOST_ID",)


def detect_host_id(context: dict[str, Any], explicit: str | None = None) -> tuple[str | None, str]:
    """The host's shared identity, and where it came from.

    Deliberately does not derive a fallback. The value's whole purpose is that
    every Rail component on a host reports the *same* one, so a locally invented
    id would be worse than none: it would look like identity while quietly
    disagreeing with the proxy and the collector. rail-center treats the field
    as optional and falls back to the container hostname, so reporting nothing
    is the honest answer when nobody set it.

    The scanner's own environment is read before the scanned container's. In
    `--mode docker` the container's environment is the *subject* of the scan, not
    a source of truth about the host it runs on, so a container that sets
    `RAIL_HOST_ID` must not be able to relabel the host out from under the
    components that actually share it. It is still read — an onboarded agent
    legitimately carries the value — but last, and the source says so.
    """
    candidates: list[tuple[str, str | None]] = [("flag", explicit)]
    candidates += [("env", os.environ.get(key)) for key in HOST_ID_KEYS]
    candidates += [("container_env", context["env"].get(key)) for key in HOST_ID_KEYS]
    for source, candidate in candidates:
        value = first_nonempty(candidate)
        if value:
            return value[:HOST_ID_MAX], source
    return None, "unset"


def container_labels(context: dict[str, Any]) -> dict[str, str]:
    inspect = context.get("docker_inspect") or {}
    labels = (inspect.get("Config") or {}).get("Labels")
    return labels if isinstance(labels, dict) else {}


def detect_sandbox_name(context: dict[str, Any], explicit: str | None = None) -> tuple[str | None, str]:
    """What this sandbox is called, and how we learned it.

    Never read from an environment variable: an agent that was never onboarded
    carries no Rail configuration, and those are exactly the ones worth
    discovering, so the name has to come from metadata the operator or the
    runtime owns.
    """
    flag = first_nonempty(explicit)
    if flag:
        return flag[:SANDBOX_NAME_MAX], "flag"
    label = first_nonempty(container_labels(context).get(SANDBOX_NAME_LABEL))
    if label:
        return label[:SANDBOX_NAME_MAX], "label"
    name = first_nonempty(context.get("container_name"))
    if name:
        return name[:SANDBOX_NAME_MAX], "container_name"
    hostname = first_nonempty(context.get("hostname"))
    if hostname:
        return hostname[:SANDBOX_NAME_MAX], "hostname"
    return None, "unset"


def detect_host_class(context: dict[str, Any]) -> str:
    """What kind of machine this is: a cloud VM, bare metal, or a container."""
    vendor = (read_text(Path("/sys/class/dmi/id/sys_vendor"), 256) or "").strip().lower()
    product = (read_text(Path("/sys/class/dmi/id/product_name"), 256) or "").strip().lower()
    marker = f"{vendor} {product}"
    if "google" in marker:
        return "gce_vm"
    if "amazon" in marker or "ec2" in marker:
        return "ec2_vm"
    if "microsoft" in marker and "virtual" in marker:
        return "azure_vm"
    if any(hint in marker for hint in ("qemu", "kvm", "vmware", "virtualbox", "xen", "bochs")):
        return "virtual_machine"
    if context["mode"] == "docker":
        # We are inspecting a sibling container, so the DMI we just read is the
        # host's. Nothing matched, so say what we can stand behind.
        return "bare_metal" if marker.strip() else "unknown"
    if in_container():
        return "container"
    return "bare_metal" if marker.strip() else "unknown"


def classify_secret_type(key: str) -> str:
    upper = key.upper()
    for name, markers in SECRET_TYPE_MARKERS:
        if any(marker in upper for marker in markers):
            return name
    return "unknown"


# A directory and a file, not a blob that happens to start with a slash. Base64
# encodes plenty of keys to a leading `/`, and calling one of those a mount would
# report a plaintext key as a pointer — understating risk on the one dimension
# this classification exists to measure.
PATH_RE = re.compile(r"(?:/[A-Za-z0-9._@%~-]+){2,}/?")


def looks_like_path(value: str) -> bool:
    return bool(PATH_RE.fullmatch(value))


def local_path_exists(path: str) -> bool:
    # Secret material commonly sits in a directory the scanner cannot stat —
    # /etc/ssl/private is the usual one — and being unable to look is not a
    # reason to crash a scan. Treat it as present: something is mounted there.
    try:
        return Path(path).exists()
    except OSError:
        return True


def container_path_checker(container: str) -> Callable[[str], bool]:
    """Existence, asked of the filesystem the value actually refers to.

    A secret mounted into the scanned container is not present on the machine
    running the scanner, so checking locally would report every mount in a
    `--mode docker` scan as a dangling reference. Only the verdict is kept; the
    path is a pointer, and the secret it points at is never read.
    """
    cache: dict[str, bool] = {}

    def exists(path: str) -> bool:
        if path not in cache:
            cache[path] = run_command(["docker", "exec", container, "test", "-e", path], timeout=2.0) is not None
        return cache[path]

    return exists


def classify_secret_class(value: str, path_exists: Callable[[str], bool] | None = None) -> str:
    """Whether the value is the secret itself or a pointer to it.

    Only the shape of the value is examined, and only the verdict is reported —
    the value never leaves this function.
    """
    stripped = value.strip()
    if not stripped:
        return "empty"
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in SECRET_REFERENCE_PREFIXES):
        return "reference"
    if looks_like_path(stripped):
        # A path that exists is a mounted file; one that does not is still a
        # pointer, just a broken one, and either way it is not a plaintext key.
        return "mount" if (path_exists or local_path_exists)(stripped) else "reference"
    return "plaintext"


def collect_secret_hygiene(
    env: dict[str, str],
    path_exists: Callable[[str], bool] | None = None,
) -> list[dict[str, Any]]:
    """One entry per secret-looking variable: name, type, class. Never a value."""
    entries = []
    for key in sorted(env):
        if not looks_secret(key):
            continue
        entries.append(
            {
                "key": key,
                "secret_type": classify_secret_type(key),
                "secret_class": classify_secret_class(env[key], path_exists),
            }
        )
    return entries


def url_host(url: str) -> str:
    """The parsed host, for a URL with or without a scheme.

    A bare `127.0.0.1:11434` is how `OLLAMA_HOST` and friends are normally
    written, so the scheme-less form is parsed rather than compared whole —
    otherwise the port would be part of the "host" and no local address with one
    would ever match.
    """
    text = url.strip()
    if not text:
        return ""
    try:
        return (urlsplit(text if "://" in text else f"//{text}").hostname or "").lower()
    except ValueError:
        return ""


def redact_url(url: str | None) -> str | None:
    """A URL with everything that could be a credential removed.

    Gateways routinely carry the key in the URL — `https://host/mcp/sk-live-…/sse`
    or `?api_key=…` or `https://user:pass@host` or `#access_token=…` — so
    recording a base_url or an MCP endpoint verbatim would put a live secret in a
    file whose whole premise is that it holds none. Scheme, host and a path shape
    are what the scorer needs; userinfo, query and fragment are dropped whole
    rather than trusted to look harmless.

    Idempotent: re-redacting an already-redacted URL returns it unchanged, so a
    value can pass through more than one collector safely.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        # A netloc urlsplit refuses to parse — an unbracketed IPv6 literal is the
        # usual one. Nothing here can be reported as a host without guessing.
        return "[unparseable]"
    if not parts.scheme or not host:
        return "[unparseable]"
    # Re-bracketed, so the result parses back the same way. Emitting a bare
    # `::1:8080` would make this function crash on its own output.
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    segments = [segment for segment in parts.path.split("/") if segment]
    path = "/".join("[redacted]" if looks_like_secret_segment(segment) else segment for segment in segments)
    suffix = "?[redacted]" if parts.query else ""
    return f"{parts.scheme}://{netloc}" + (f"/{path}" if path else "") + suffix


# A host as an operator writes one: dotted with an alphabetic TLD, or a short
# single label like `ollama` or `localhost`. Long single labels are excluded on
# purpose — that is the shape a pasted key has.
BARE_HOST_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    r"|[a-z0-9](?:[a-z0-9-]{0,17}[a-z0-9])?",
    re.IGNORECASE,
)


def looks_like_bare_host(value: str) -> bool:
    host, _, port = value.partition(":")
    if port and not port.isdigit():
        return False
    return bool(BARE_HOST_RE.fullmatch(host))


def redact_endpoint(value: str) -> str:
    """An endpoint recorded for its reach, not for replay.

    Endpoints arrive as bare hosts as well as URLs, and running a bare host
    through `redact_url` would report every one of them as `[unparseable]`,
    throwing away the reach the field exists to record. So a host keeps its
    shape — but only if it actually has one. A skills file is operator-supplied,
    and nothing stops a key being pasted where a host belongs, so anything that
    is not host-shaped still faces the key-shape test.
    """
    text = value.strip()
    if "://" in text:
        return redact_url(text) or "[unparseable]"
    # The vendor shape is checked before the host shape, not after: `sk-live-abc12`
    # is a perfectly legal DNS label, so a host test that ran first would wave
    # through every short hyphenated key there is.
    if is_secret_token(text):
        return "[redacted]"
    if looks_like_bare_host(text):
        return text
    return "[redacted]" if looks_like_secret_segment(text) else text


# The same shapes, found inside free text. The lookbehind is what keeps
# `risk-management-dashboard` from being read as an `sk-` key; the cost is that a
# token glued directly to a preceding word is not matched, which is the right way
# round — a missed match on `xsk-live…` is rarer than a mangled ordinary word.
SECRET_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(pattern.pattern for pattern in SECRET_TOKEN_RES) + r")"
)

# `--api-key=…`, `--token …`, and the `api_key=…` an entrypoint sets inline.
CMDLINE_SECRET_RES = (
    re.compile(r"(--?[A-Za-z0-9_-]*(?:key|token|secret|password|passwd|credential|auth)[A-Za-z0-9_-]*[= ])\S+", re.I),
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDS)=)\S+", re.I),
)


def redact_text(value: str) -> str:
    """Free text with anything vendor-key-shaped removed.

    A skill's name and description are operator-written and reach both the
    feature file and the registration POST, so they get the same treatment as
    the endpoints beside them. Free text cannot be parsed into fields, so this
    is a shape match rather than a structural one: it catches a pasted key from
    a vendor whose format is recognised, not every conceivable secret.
    """
    return SECRET_TEXT_RE.sub("[redacted]", value)


def redact_cmdline(value: str | None) -> str | None:
    """A command line with its credential-naming arguments removed.

    A container's entrypoint routinely carries `--api-key=…`, and the command
    line is reported in `system_info` — which is POSTed to rail-center and
    printed to stdout. Recording it verbatim would ship the key with it.

    What is removed is the argument that *names* a credential, plus anything of
    a recognised vendor shape wherever it appears. A single-letter flag names
    nothing (`-k` is curl's insecure switch as often as it is a key), so those
    are left alone rather than swallowing the token after them.
    """
    if not value:
        return value
    redacted = value
    for pattern in CMDLINE_SECRET_RES:
        redacted = pattern.sub(r"\1[redacted]", redacted)
    return redact_text(redacted)


def is_secret_token(value: str) -> bool:
    """Whether the whole value is a credential in a shape some vendor issues."""
    return any(pattern.fullmatch(value) for pattern in SECRET_TOKEN_RES)


def looks_like_secret_segment(segment: str) -> bool:
    """A path segment that could be a key rather than a route.

    Deliberately over-inclusive. The earlier shape test — long, no character
    outside `[A-Za-z0-9._~-]`, at least one digit — let two whole families
    through: base64 keys, whose `+` and `/` and `=` fail the character class, and
    all-alphabetic keys, which carry no digit. Redacting a long route segment
    costs a scorer a path component; keeping one live key costs the file its
    entire premise, so length alone is now enough, and a recognised vendor shape
    redacts a short one.
    """
    return is_secret_token(segment) or len(segment) >= 20


def command_basename(command: Any) -> str | None:
    """The executable alone, with any arguments dropped.

    MCP configs split argv into `command` and `args`, but they also inline the
    whole invocation into `command`, and `Path(...).name` only cuts at the last
    slash — it would carry `--token sk-…` straight into a file that is persisted
    and POSTed.
    """
    if not isinstance(command, str) or not command.strip():
        return None
    try:
        # Non-POSIX so a backslash stays a path separator: an MCP config on
        # Windows spells the executable `C:\...\node.exe`, and POSIX splitting
        # would read those separators as escapes and hand back `C:Usersnode.exe`.
        parts = shlex.split(command, posix=False)
    except ValueError:
        parts = command.split()
    if not parts:
        return None
    return re.split(r"[\\/]", parts[0].strip("\"'"))[-1] or None


def classify_base_url(url: str | None) -> str:
    if not url:
        return "unset"
    if is_local_base_url(url):
        return "local"
    host = url_host(url)
    if not host:
        return "unknown_proxy"
    # Match on the host, not on a substring of the whole URL: `api.anthropic.com`
    # appears inside `evil-api.anthropic.com.attacker.net`, and calling that
    # canonical would silence the exact signal this field exists to raise.
    if any(host == canonical or host.endswith("." + canonical) for canonical in CANONICAL_LLM_HOSTS):
        return "canonical"
    return "unknown_proxy"


def collect_model_egress(env: dict[str, str]) -> dict[str, Any]:
    """The base URL the agent's model calls go to, and whether we recognise it.

    An unknown host is the signal worth surfacing: it means the agent's traffic
    is being routed somewhere the provider does not own.
    """
    base_url = first_nonempty(
        env.get("ANTHROPIC_BASE_URL"),
        env.get("OPENAI_BASE_URL"),
        env.get("OPENAI_API_BASE"),
        env.get("RAIL_LLM_BASE_URL"),
        env.get("LLM_BASE_URL"),
    )
    return {"base_url": redact_url(base_url), "base_url_class": classify_base_url(base_url)}


def summarize_observed(snapshot: dict[str, Any], declared_hosts: set[str]) -> dict[str, Any]:
    """Turn an AgentSight snapshot into the behaviour dimension.

    AgentSight has already done the parsing and the aggregation — `network_targets`
    arrives grouped by host with counts — so this only classifies, redacts and
    diffs. Deliberately takes names and counts and nothing else: `tool_calls`
    carries `input`/`output` and `process_nodes` carries full argv, which are
    conversation and command-line contents, not metadata, and must never reach a
    file that is persisted and handed to a scorer.

    Produce it with:  agentsight report export -o snapshot.json
    """
    destinations = []
    observed_hosts = set()
    for target in snapshot.get("network_targets") or []:
        host = str(target.get("host") or "").lower()
        if not host:
            continue
        observed_hosts.add(host)
        destinations.append(
            {
                "host": host,
                "class": classify_base_url(f"https://{host}"),
                "path": redact_url(f"https://{host}{target.get('path') or '/'}"),
                "count": target.get("count"),
                "error_count": target.get("error_count"),
            }
        )

    summary = snapshot.get("summary") or {}
    return {
        "source": "agentsight",
        "snapshot_schema_version": snapshot.get("schema_version"),
        "generated_at": snapshot.get("generated_at"),
        "sessions": summary.get("sessions"),
        "llm_calls": summary.get("llm_calls"),
        "destinations": sorted(destinations, key=lambda d: -(d["count"] or 0)),
        # The signal the configuration alone cannot give: reached, but never
        # declared. RC-159 computes the same drift centrally; this is the local
        # answer, so the feature file still means something without a control
        # plane.
        "undeclared_destinations": sorted(observed_hosts - declared_hosts),
        "tools_used": sorted({str(call.get("tool_name")) for call in (snapshot.get("tool_calls") or []) if call.get("tool_name")}),
        "models": sorted({str(row.get("group")) for row in (snapshot.get("token_summary") or []) if row.get("group")}),
    }


def declared_hosts(identity: dict[str, Any], env: dict[str, str]) -> set[str]:
    """Every host the configuration says this agent is meant to talk to."""
    hosts = {url_host(server["url"]) for server in identity["mcp_servers"] if server.get("url")}
    base_url = collect_model_egress(env)["base_url"]
    if base_url:
        hosts.add(url_host(base_url))
    return {host for host in hosts if host}


# Distinct listeners kept in the bundle. More are counted, not listed: the
# events come from every process in the sandbox, and a value this size is
# compared field by field on every scan.
LISTENER_CAP = 256
LISTEN_KINDS = {"listen", "bind", "autobind"}
# Distinct (listener, peer) pairs kept, for the same reason. A listener the
# whole internet can reach meets a new peer on every scan; past the cap the
# list says so (PARTIAL) rather than growing without bound.
PEER_CAP = 256
# A line of this many characters or more is not one listensnoop wrote (its
# lines are ~250); it is skipped without being read into memory whole.
MAX_LISTEN_LINE = 4096


def _printable(value: str, limit: int) -> str:
    return "".join(c if c.isprintable() else "?" for c in value[:limit])


# Named, not ipaddress's is_private: that also covers documentation,
# benchmarking and reserved space, which are not "inside the network".
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def peer_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Where a peer connected from, in the words of the ASP requirement's
    "internal only" threshold: loopback, link-local, private (RFC 1918, ULA),
    public (globally routable), or other (CGNAT, documentation, reserved...)."""
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if any(address in net for net in PRIVATE_NETWORKS if net.version == address.version):
        return "private"
    if address.is_global:
        return "public"
    return "other"


def _peer_address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    # listensnoop never writes a zone ("fe80::1%eth0"), and ipaddress keeps
    # one verbatim, control characters and all: refuse it.
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        return None
    # listensnoop already writes an IPv4 client of a dual-stack listener as
    # IPv4; normalise anyway, so one client is one peer whatever wrote it.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


# A heartbeat older than this many intervals means the probe stopped.
HEARTBEAT_GRACE = 3


def _probe_beat(event: dict[str, Any], kind: str) -> tuple[datetime, int] | None:
    """A `start` or `alive` record's time and interval, or None when it is
    malformed. listensnoop and filesnoop write them the same way."""
    try:
        seen = datetime.strptime(str(event.get("time")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    interval = event.get("every")
    if not isinstance(interval, int) or isinstance(interval, bool) or interval < (kind == "alive"):
        return None
    return seen, interval


class _ProbeHealth:
    """Whether a probe's event file can be trusted, from its start and alive
    records: no start record, a restart, or a stale heartbeat (see
    `summarize_listeners`). Shared by listensnoop's and filesnoop's files."""

    def __init__(self) -> None:
        self.starts = 0
        self.every = 0
        self.last_alive: datetime | None = None

    def beat(self, kind: str, seen: datetime, interval: int) -> None:
        self.starts += kind == "start"
        if self.last_alive is None or seen > self.last_alive:
            self.last_alive, self.every = seen, interval

    def summary(self, now: datetime | None) -> dict[str, Any]:
        last_alive, every = self.last_alive, self.every
        return {
            "starts": self.starts,
            "restarted": self.starts > 1,
            "last_alive": last_alive.strftime("%Y-%m-%dT%H:%M:%SZ") if last_alive else None,
            # None when there is no interval to judge by: no -H, or no record.
            "stale": (
                None if last_alive is None or not every
                else abs(((now or datetime.now(timezone.utc)) - last_alive).total_seconds())
                > HEARTBEAT_GRACE * every
            ),
        }


def summarize_listeners(lines: Iterable[str], now: datetime | None = None) -> dict[str, Any]:
    """Turn listensnoop's JSON lines into the listening half of observed reach.

    A socket the agent opened to accept inbound traffic is reach in the other
    direction: a service the agent offers that its configuration never
    declared, the shape a covert channel takes. Like `summarize_observed`,
    this keeps names and no counts or PIDs, so the value only changes when a
    new kind of listener appears:

    - a port the kernel chose (listensnoop's `ephemeral`: a bind to port 0, a
      listen() on an unbound socket, an autobind) is "ephemeral" rather than
      a number that differs on every run. A port the caller asked for stays a
      number whatever range it is in: it is the service's identity, and a
      covert listener on one must not pass as ephemeral;
    - an event with pid 0 came from outside the PID namespace listensnoop ran
      in, so it is not this sandbox's and is only counted;
    - `lost` sums listensnoop's own gap records: events it could not deliver,
      so the list may be missing a listener;
    - listensnoop prints a `start` record at each attach and, with -H, an
      `alive` one each interval. The agent shares the probe's PID namespace
      and can stop or kill it, so these decide whether the list can be
      trusted:
      * no start record: the probe never attached (or is older than them);
      * more than one: it `restarted`, and missed whatever opened while it
        was down (it does not report sockets already listening; `railmon
        listen`'s snapshot at each attach adds those still open, as records
        with `"snapshot": true`, but not one opened and closed meanwhile);
      * the newest start/alive more than HEARTBEAT_GRACE intervals from
        `now`, either way (a clock stepped back too): it is `stale`.

    `peer` events (DR-145) are who actually connected in: per listener, the
    distinct remote addresses a process accepted a connection from, each
    with its scope. Kept the same way (no counts, no PIDs, a chosen port as
    "ephemeral"), so the value changes only when a new peer appears. Only a
    listensnoop from DR-144 on reports them, and its start records say
    `"peers": true`; `peers_reported` says whether the newest one did, so
    an empty list from a probe that predates them is never read as "nobody
    connected". Peer events are kept whatever the start record says.

    Produce the file with listensnoop (ebpf-tls-tap) run in the agent's PID
    namespace; see the README's "Observed listeners".
    """
    listeners: set[tuple[str, str, Any, str]] = set()
    peers: set[tuple[str, str, Any, str, Any]] = set()
    lost = unlisted = peers_unlisted = malformed = outside = 0
    health = _ProbeHealth()
    last_start: datetime | None = None
    peers_reported = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(event, dict):
            malformed += 1
            continue
        kind = event.get("kind")
        if kind == "lost":
            count = event.get("count")
            lost += count if isinstance(count, int) and count > 0 else 0
            continue
        if kind in ("alive", "start"):
            beat = _probe_beat(event, kind)
            if beat is None:
                malformed += 1
                continue
            seen, interval = beat
            if kind == "start" and (last_start is None or seen >= last_start):
                last_start, peers_reported = seen, event.get("peers") is True
            health.beat(kind, seen, interval)
            continue
        port, protocol, addr = event.get("port"), event.get("protocol"), event.get("addr")
        comm, ephemeral = event.get("comm"), event.get("ephemeral")
        peer = _peer_address(event.get("peer")) if kind == "peer" else None
        if (
            (kind not in LISTEN_KINDS and not (kind == "peer" and peer is not None))
            or not isinstance(port, int) or not 0 <= port <= 65535
            or not isinstance(protocol, str) or not isinstance(addr, str)
            or not isinstance(comm, str) or not isinstance(event.get("pid"), int)
            or not isinstance(ephemeral, (bool, type(None)))
        ):
            malformed += 1
            continue
        if event["pid"] == 0:
            outside += 1
            continue
        # A listensnoop older than the flag (before DR-125) only marks an
        # autobind for sure. Its port-0 binds then show their real ports,
        # which differ per run: churn, but never a hidden listener.
        chosen = ephemeral if ephemeral is not None else kind == "autobind"
        key = (
            _printable(protocol, 16),
            _printable(addr, 64),
            "ephemeral" if chosen else port,
            _printable(comm, 16),
        )
        if peer is not None:
            pair = (*key, peer)
            if pair not in peers and len(peers) >= PEER_CAP:
                peers_unlisted += 1
            else:
                peers.add(pair)
            continue
        if key not in listeners and len(listeners) >= LISTENER_CAP:
            unlisted += 1
            continue
        listeners.add(key)
    return {
        "source": "listensnoop",
        "listeners": [
            {"protocol": protocol, "addr": addr, "port": port, "process": process}
            for protocol, addr, port, process in sorted(listeners, key=lambda k: (k[0], k[1], str(k[2]), k[3]))
        ],
        "peers": [
            {"protocol": protocol, "addr": addr, "port": port, "process": process,
             "peer": str(peer), "scope": peer_scope(peer)}
            for protocol, addr, port, process, peer in sorted(
                peers, key=lambda k: (k[0], k[1], str(k[2]), k[3], k[4].version, k[4]))
        ],
        "peers_reported": peers_reported,
        "lost": lost,
        "unlisted": unlisted,
        "peers_unlisted": peers_unlisted,
        "malformed": malformed,
        "outside_namespace": outside,
        **health.summary(now),
    }


# Distinct (path, layer) entries kept in the bundle. A process opens many
# files: a stdlib-only Python touches ~150 on start, and a real agent with its
# packages far more. So the cap is wider than the listeners', and when it is
# hit, what is dropped is reads: every write and exec is kept first, since a
# newly written path is the drift that matters most.
FILE_ACCESS_CAP = 512
# And a byte budget, because the agent names its files: a 1024-character
# path of non-ASCII characters renders as ~6 KB (the bundle is written with
# ensure_ascii), so 512 of them would push the bundle past RailDash's 1 MiB
# bound and every delivery would be refused. Each entry is measured as
# rendered compactly, plus FILE_ENTRY_OVERHEAD for the indentation of the
# pretty-printed form. An entry that does not fit is left out and counted,
# like one past the cap. Ordinary paths reach the 512 cap long before this.
FILE_ACCESS_BYTES = 256 * 1024
FILE_ENTRY_OVERHEAD = 128
# Distinct entries tracked while reading, before the cap picks; beyond this
# they are only counted. Read-only entries and written-or-run ones each get
# this many, so a flood of reads cannot use up the room a write needs.
# filesnoop's own dedup LRU is 65,536 entries.
FILE_ACCESS_TRACKED = 16384
# A longer path is counted, not listed: it would let one entry dominate the
# bundle. PATH_MAX is 4096, so an agent can make one; that is a gap (PARTIAL),
# never a silent omission.
FILE_PATH_MAX = 1024
# filesnoop's longest line: a 4096-byte path with every byte escaped as
# \u00XX, its path_hex, and the fixed fields, about 33,000 characters.
MAX_FILE_LINE = 65536


# Randomly named temp files (DR-166). A tempfile or mkstemp name differs on
# every run, so kept verbatim each one would be a newly written path on every
# scan: drift that means nothing. A file whose name matches one of these
# patterns, in a temp dir (or below one of FILE_TEMP_DIRS), is folded into one
# entry per (directory, pattern, layer) whose path puts `*` where the random
# part was: /tmp/tmpk3j_9xq2 and /tmp/tmp0a1b2c3d are both /tmp/tmp*. A name
# that matches none of them is never folded, so /tmp/exfil.tar stays its own
# entry, and a template itself is a new entry the first time it appears. An
# agent that knows the rule can still pick a matching name; once its template
# is in the baseline such a write is aligned. That is the price of not
# reporting drift on every scan, and the README says so.
FILE_TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
# The agent sets $TMPDIR, so it counts only when its last part names a temp
# dir (/scratch/tmp, /home/a/.tmp, /work/temp), never a home, a workdir or
# ~/.ssh; and even then not when it is, or is below, one of these system dirs.
FILE_TEMP_DIR_NAME = re.compile(r"\.?(?:tmp|temp)(?:dir)?", re.IGNORECASE)
FILE_TEMP_REFUSED = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libexec",
                     "/libx32", "/proc", "/sbin", "/sys", "/usr")
# An optional extension the caller asked for (mkstemp's suffix, mkstemps).
_TEMP_SUFFIX = r"(?P<suffix>\.[A-Za-z0-9]{1,8})?"
# (name pattern, what its `random` group must hold, whether it may fold below
# a temp dir as well as directly in it). The first that matches, and may
# apply where the file is, wins.
FILE_TEMP_PATTERNS = (
    # Vim's swap files, whose last letter moves on (.swp, .swo, ...) when one
    # is already taken. First, so a swap file of an edited file whose name
    # looks random (.Report2.swp) still folds by the edited file's name.
    (re.compile(r"(?P<prefix>\.[^/]+\.sw)[a-p]"), None, True),
    # The file Python's tempfile writes, and removes at once, the first time a
    # process uses it, to check it can write there: 8 of [a-z0-9_], no prefix,
    # directly in the temp dir. With no prefix it is the loosest pattern, so it
    # is never applied below one.
    (re.compile(r"(?P<prefix>)[a-z0-9_]{8}"), None, False),
    # Python's tempfile (mkstemp, NamedTemporaryFile, ...) with its default
    # prefix: "tmp" and 8 characters of [a-z0-9_].
    (re.compile(r"(?P<prefix>tmp)[a-z0-9_]{8}" + _TEMP_SUFFIX), None, True),
    # mkstemp(3)/mkstemps(3) (6 random [A-Za-z0-9] for the caller's XXXXXX),
    # mktemp(1) (tmp.XXXXXXXXXX) and Go's os.CreateTemp("", "run-*"): a
    # prefix that ends in . - or _ (or is "tmp"), then 6 to 12 random
    # letters and digits. The random part must hold a digit or a
    # capital, so an ordinary word after a dash (/tmp/build-output) is not
    # taken for one.
    (re.compile(r"(?P<prefix>[A-Za-z0-9_.-]*[._-]|tmp)(?P<random>[A-Za-z0-9]{6,12})" + _TEMP_SUFFIX),
     re.compile(r"[A-Z0-9]"), True),
)


def file_temp_dirs(env: dict[str, str] | None = None) -> tuple[str, ...]:
    """The temp dirs whose randomly named files are folded: FILE_TEMP_DIRS,
    plus the scanned environment's $TMPDIR (where that agent's tempfile and
    mktemp write) when it is a plain absolute directory: printable, at most
    256 characters, no empty, `.` or `..` part, a last part that names a temp
    dir (FILE_TEMP_DIR_NAME), not the environment's $HOME, and not in
    FILE_TEMP_REFUSED. The agent can set it, so anything else is ignored,
    and only files directly in it are folded (`ephemeral_file_template`)."""
    dirs = list(FILE_TEMP_DIRS)
    env = env or {}
    tmpdir, home = env.get("TMPDIR"), env.get("HOME")
    if isinstance(tmpdir, str):
        tmpdir = tmpdir.rstrip("/")
        if (
            tmpdir.startswith("/") and len(tmpdir) <= 256 and tmpdir.isprintable()
            and all(part not in ("", ".", "..") for part in tmpdir.split("/")[1:])
            and FILE_TEMP_DIR_NAME.fullmatch(tmpdir.rsplit("/", 1)[-1]) is not None
            and not any(tmpdir == root or tmpdir.startswith(root + "/") for root in FILE_TEMP_REFUSED)
            and tmpdir != (home.rstrip("/") if isinstance(home, str) else None)
            and tmpdir not in dirs
        ):
            dirs.append(tmpdir)
    return tuple(dirs)


# A procfs path named by a process or thread ID (/proc/1234/maps,
# /proc/1234/task/1240/attr/apparmor/exec). The ID is a new number for every
# process, so the same access by each new process would be a new path: every
# `docker exec` into the agent, the scanner's own included, has the
# container runtime's init read and write a few of these. They fold to
# /proc/*/..., which no real file is named, so a folded path never passes
# for a literal one (DR-185). The price, as for temp names: a process's own
# /proc/self/environ and another's are one entry, and the README says so.
_PROC_PID = re.compile(r"/proc/[0-9]+(?=/|$)(?:/task/[0-9]+(?=/|$))?")


def fold_proc_pid(path: str) -> str:
    """`path` with a leading /proc/<pid> and /task/<tid> made `*`."""
    match = _PROC_PID.match(path)
    if match is None:
        return path
    folded = "/proc/*" + ("/task/*" if "/task/" in match.group(0) else "")
    return folded + path[match.end():]


def ephemeral_file_template(path: str, temp_dirs: Iterable[str] = FILE_TEMP_DIRS) -> str | None:
    """The templated path a randomly named temp file folds into, or None when
    `path` is not one (see FILE_TEMP_PATTERNS). Only the file's own name is
    templated; its directory is kept as it is. That directory must be one of
    `temp_dirs`, or, for all but the prefix-less pattern, below one of
    FILE_TEMP_DIRS (never below a $TMPDIR)."""
    directory, _, name = path.rpartition("/")
    if not name or len(name) > 255:
        return None
    if any(part in ("", ".", "..") for part in directory.split("/")[1:]):
        return None
    directly = directory in temp_dirs
    below = any(directory.startswith(root + "/") for root in FILE_TEMP_DIRS if root in temp_dirs)
    if not (directly or below):
        return None
    for pattern, random_must, nested in FILE_TEMP_PATTERNS:
        match = pattern.fullmatch(name)
        if match and (random_must is None or random_must.search(match.group("random"))):
            if not (directly or nested):
                continue  # a later pattern may still fold it below one
            return f"{directory}/{match.group('prefix')}*{match.groupdict().get('suffix') or ''}"
    return None


def summarize_file_access(
    lines: Iterable[str], now: datetime | None = None, temp_dirs: Iterable[str] = FILE_TEMP_DIRS
) -> dict[str, Any]:
    """Turn filesnoop's JSON lines into the files the sandbox opened (DR-154).

    filesnoop (ebpf-tls-tap, DR-152) reports the first time each process
    opens each regular file for each kind of access. Like the listeners,
    this keeps what was touched and how, with no counts, PIDs or process
    names, so the value only changes when a file is opened in a new way:

    - one entry per (path, layer), with `read`, `write` and `exec` the union
      of every access seen. A file first read and later written is one entry
      whose `write` turns true: that change is the drift;
    - process names are left out: comm is per thread and agent-chosen
      (Python names its threads "Thread-8 (reader)"), so it would churn;
    - `layer` is filesnoop's flag for an open overlayfs made in a layer
      beneath, under the credentials of a user-namespace mounter; its path is
      the layer's, so it is its own entry;
    - an event with pid 0 came from outside filesnoop's PID namespace, so it
      is only counted;
    - a path filesnoop could not resolve (`path_error`) or longer than
      FILE_PATH_MAX is counted as `unnamed`: a file was opened that the list
      cannot show. `unnamed_write_exec` counts those that were written or
      run, and `unlisted_write_exec` the written or run entries left out,
      so a lost write reads differently from a lost read;
    - past FILE_ACCESS_CAP entries, or FILE_ACCESS_BYTES as rendered, reads
      are dropped first and counted in `unlisted`, so every write and exec
      is kept while there is room. While each class stays within
      FILE_ACCESS_TRACKED, the choice depends only on the set seen, not on
      the order of the lines;
    - a procfs path under a process or thread ID is folded to /proc/*/...
      (`fold_proc_pid`), so each new process's runtime init is not a new
      path;
    - a randomly named temp file (`ephemeral_file_template`) is folded into
      its template's entry, its access unioned in like any other open, and
      the distinct paths folded into entries that made the list are counted
      in `collapsed`. Past FILE_ACCESS_TRACKED folds it is a lower bound,
      though every listed templated entry still counts at least 1;
    - `lost` and the start/alive records mean what they do for listensnoop.

    Produce the file with filesnoop run in the agent's PID namespace (`-n`);
    the image's `railmon files` does that.
    """
    files: dict[tuple[str, bool], list[bool]] = {}
    lost = unlisted = unnamed = malformed = outside = 0
    temp_dirs = tuple(temp_dirs)
    # Hashes of the distinct (path, layer) folded, and how many went into each
    # templated entry, for the feature file's count; past FILE_ACCESS_TRACKED
    # of them it stops growing.
    collapsed: set[int] = set()
    folded_into: dict[tuple[str, bool], int] = {}
    # Every templated entry, uncapped, so the note is said whenever one is listed.
    templated: set[tuple[str, bool]] = set()
    # Written or run entries left out or unnamed, counted apart from reads so
    # the bundle's note can say a write was lost, not just "more files".
    unlisted_write_exec = unnamed_write_exec = 0
    tracked_reads = tracked_write_exec = 0
    health = _ProbeHealth()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(event, dict):
            malformed += 1
            continue
        kind = event.get("kind")
        if kind == "lost":
            count = event.get("count")
            lost += count if isinstance(count, int) and count > 0 else 0
            continue
        if kind in ("alive", "start"):
            beat = _probe_beat(event, kind)
            if beat is None:
                malformed += 1
                continue
            health.beat(kind, beat[0], beat[1])
            continue
        path, layer = event.get("path"), event.get("layer", False)
        access = [event.get(name) for name in ("read", "write", "exec")]
        if (
            kind != "open"
            or not isinstance(path, str)
            or not all(isinstance(flag, bool) for flag in access)
            or not isinstance(layer, bool)
            or not isinstance(event.get("pid"), int) or isinstance(event.get("pid"), bool)
        ):
            malformed += 1
            continue
        if event["pid"] == 0:
            outside += 1
            continue
        changes = access[1] or access[2]
        if not path or len(path) > FILE_PATH_MAX:
            unnamed += 1
            unnamed_write_exec += changes
            continue
        path = fold_proc_pid(_printable(path, FILE_PATH_MAX))
        template = ephemeral_file_template(path, temp_dirs)
        key = (template if template is not None else path, layer)
        seen = files.get(key)
        if seen is None:
            if (tracked_write_exec if changes else tracked_reads) >= FILE_ACCESS_TRACKED:
                unlisted += 1
                unlisted_write_exec += changes
                continue
            files[key] = list(access)
            if changes:
                tracked_write_exec += 1
            else:
                tracked_reads += 1
        else:
            files[key] = merged = [old or new for old, new in zip(seen, access)]
            if not (seen[1] or seen[2]) and (merged[1] or merged[2]):
                tracked_reads -= 1  # it moves classes; the total does not grow
                tracked_write_exec += 1
        if template is not None:
            templated.add(key)
        if template is not None and len(collapsed) < FILE_ACCESS_TRACKED:
            folded = hash((path, layer))
            if folded not in collapsed:
                collapsed.add(folded)
                folded_into[key] = folded_into.get(key, 0) + 1
    # Writes and execs first, then by path: the same set always yields the
    # same value, and a new read can only displace another read. Within the
    # byte budget, an entry too large to fit is skipped, not the rest.
    ranked = sorted(files.items(), key=lambda item: (not (item[1][1] or item[1][2]), item[0]))
    kept: list[dict[str, Any]] = []
    used = 0
    for (path, layer), (read, write, run) in ranked:
        if len(kept) >= FILE_ACCESS_CAP:
            break
        entry = {"path": path, "read": read, "write": write, "exec": run, "layer": layer}
        size = len(json.dumps(entry, separators=(",", ":"))) + FILE_ENTRY_OVERHEAD
        if used + size > FILE_ACCESS_BYTES:
            continue
        kept.append(entry)
        used += size
    kept.sort(key=lambda entry: (entry["path"], entry["layer"]))
    unlisted += len(ranked) - len(kept)
    unlisted_write_exec += sum(1 for _, (_, write, run) in ranked if write or run) \
        - sum(1 for entry in kept if entry["write"] or entry["exec"])
    return {
        "source": "filesnoop",
        "files": kept,
        "lost": lost,
        "unlisted": unlisted,
        "unnamed": unnamed,
        "unlisted_write_exec": unlisted_write_exec,
        "unnamed_write_exec": unnamed_write_exec,
        # Only the entries in the list count, so the note never claims a fold
        # whose entry the cap left out; and a listed templated entry always
        # counts, so the note is never lost once the count stopped growing.
        "collapsed": sum(max(folded_into.get(key, 0), 1) for key in
                         ((entry["path"], entry["layer"]) for entry in kept) if key in templated),
        "malformed": malformed,
        "outside_namespace": outside,
        **health.summary(now),
    }


def _bounded_lines(stream: Any, limit: int = MAX_LISTEN_LINE) -> Iterable[str]:
    """Lines of at most `limit` characters; a longer one is yielded as a
    single unparseable marker, never held whole."""
    while True:
        line = stream.readline(limit)
        if not line:
            return
        if len(line) == limit and not line.endswith("\n"):
            while True:  # discard the rest of it
                rest = stream.readline(limit)
                if not rest or rest.endswith("\n"):
                    break
            yield "\x00oversized"
            continue
        yield line


def load_listen_events(path: Path) -> dict[str, Any]:
    # Streamed, not read whole: listensnoop appends for as long as it runs.
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return summarize_listeners(_bounded_lines(stream))
    except OSError as exc:
        raise ScannerError(f"cannot read listensnoop events {path}: {exc}") from exc


def load_file_events(path: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    # Streamed, like listensnoop's: filesnoop appends for as long as it runs.
    # `env` is the scanned environment, for its $TMPDIR (`file_temp_dirs`).
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return summarize_file_access(_bounded_lines(stream, MAX_FILE_LINE), temp_dirs=file_temp_dirs(env))
    except OSError as exc:
        raise ScannerError(f"cannot read filesnoop events {path}: {exc}") from exc


def load_snapshot(path: Path) -> dict[str, Any]:
    # Read it whole. load_json_file() goes through read_text(), which caps at
    # 64 KB for config files; a snapshot of a real session is megabytes, and the
    # truncated read fails to parse with nothing to suggest the file was fine.
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        raise ScannerError(f"cannot read AgentSight snapshot {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScannerError(f"AgentSight snapshot is not valid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ScannerError(f"not an AgentSight snapshot: {path}")
    return data


def build_feature_file(
    args: argparse.Namespace,
    context: dict[str, Any],
    payload: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    """The artifact a scorer consumes. Metadata only, and no control plane needed."""
    env = context["env"]
    environment = payload.get("environment") or {}
    container = context.get("container_name") if context["mode"] == "docker" else None
    path_exists = container_path_checker(str(container)) if container else None
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "mode": context["mode"],
            "container": args.container,
            "registration_status": identity["registration_status"],
        },
        "host_and_identity": {
            "sandbox_type": environment.get("sandbox_type"),
            "host_class": identity["host_class"],
            "host_id": identity["host_id"],
            "host_id_source": identity["host_id_source"],
            "sandbox_name": identity["sandbox_name"],
            "sandbox_name_source": identity["sandbox_name_source"],
            "image": context.get("image"),
            "container_id": context.get("container_id"),
            "owner": payload.get("owner"),
        },
        "secrets_hygiene": {
            "env_key_names": safe_env_keys(env),
            "secrets": collect_secret_hygiene(env, path_exists),
        },
        "model_and_egress": {
            "llm_provider": environment.get("llm_provider"),
            "llm_model": environment.get("llm_model"),
            **collect_model_egress(env),
        },
        "tool_and_mcp_reach": {
            "mcp_servers": identity["mcp_servers"],
        },
        "skills": payload.get("skills") or [],
        **({"observed_reach": identity["observed_reach"]} if identity.get("observed_reach") else {}),
        **({"observed_listeners": identity["observed_listeners"]} if identity.get("observed_listeners") else {}),
        **({"observed_file_access": identity["observed_file_access"]} if identity.get("observed_file_access") else {}),
    }


def collect_identity(args: argparse.Namespace, context: dict[str, Any]) -> dict[str, Any]:
    host_id, host_id_source = detect_host_id(context, args.host_id)
    sandbox_name, sandbox_name_source = detect_sandbox_name(context, args.sandbox_name)
    return {
        "host_id": host_id,
        "host_id_source": host_id_source,
        "sandbox_name": sandbox_name,
        "sandbox_name_source": sandbox_name_source,
        "host_class": detect_host_class(context),
        # Overwritten with "registered" only once the POST has actually succeeded.
        "registration_status": "registration_failed" if args.register else "unregistered",
        "mcp_servers": [],
        "observed_reach": None,
        "observed_listeners": None,
        "observed_file_access": None,
    }


def drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [drop_none(item) for item in value if item is not None]
    return value


def scan(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Inspect the environment once and return (context, payload, identity)."""
    if args.mode == "docker":
        if not args.container:
            raise ScannerError("--container is required with --mode docker")
        context = collect_docker_context(args.container)
    else:
        context = collect_self_context()
    identity = collect_identity(args, context)
    payload = build_registration_payload(args, context, identity)
    identity["mcp_servers"] = collect_mcp_inventory(
        [Path(path).expanduser() for path in args.mcp_config] or default_mcp_paths(context["env"]),
        context["env"],
    )
    observed_file = resolve_observed_file(args)
    if observed_file:
        identity["observed_reach"] = summarize_observed(
            load_snapshot(Path(observed_file).expanduser()),
            declared_hosts(identity, context["env"]),
        )
    listen_file = resolve_listen_file(args)
    if listen_file:
        identity["observed_listeners"] = load_listen_events(Path(listen_file).expanduser())
    files_file = resolve_files_file(args)
    if files_file:
        identity["observed_file_access"] = load_file_events(Path(files_file).expanduser(), context["env"])
    return context, payload, identity


def build_registration_payload(
    args: argparse.Namespace,
    context: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:

    env = context["env"]
    capture_files = [Path(path).expanduser() for path in args.capture_file]
    config_paths = [Path(path).expanduser() for path in args.config_path] or default_config_paths(env)
    mcp_paths = [Path(path).expanduser() for path in args.mcp_config] or default_mcp_paths(env)
    skill_files = [Path(path).expanduser() for path in args.skills_file]

    llm_model, model_source = detect_model(env, capture_files, config_paths, args.llm_model)
    if llm_model == "unknown" and context["mode"] == "docker" and context.get("container_name"):
        container_config_roots = [str(path) for path in config_paths] or list(DEFAULT_CONTAINER_CONFIG_ROOTS)
        container_config_models = find_models_in_container_openclaw_config(
            str(context["container_name"]), container_config_roots
        )
        if container_config_models:
            llm_model = container_config_models[-1]
            model_source = "container_openclaw_config"
    owner, owner_source = detect_owner(env, args.owner)
    mcp_skills = collect_skills(mcp_paths, env)
    scanned_skills = collect_skills_from_files(skill_files)
    payload = {
        "type": args.agent_type,
        "owner": owner,
        # Asserted, never verified, and optional on rail-center's side: a
        # registration that omits them still succeeds against an identity derived
        # from the container hostname.
        "host_id": identity["host_id"],
        "sandbox_name": identity["sandbox_name"],
        # None (the unkeyed compatibility path) is dropped below by
        # drop_none, so an invocation that never names an agent key sends
        # exactly the payload it always has.
        "agent_key": configured_agent_key(args),
        "environment": {
            "sandbox_type": detect_sandbox_type(context, args.sandbox_type),
            "llm_provider": detect_provider(env, llm_model, args.llm_provider),
            "llm_model": llm_model,
            "system_info": collect_system_info(context, model_source, capture_files),
            "user_info": collect_user_info(context, owner, owner_source),
        },
        "skills": merge_skill_lists(mcp_skills, scanned_skills),
    }
    return drop_none(payload)


def render_json(value: Any, compact: bool) -> str:
    if compact:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return json.dumps(value, indent=2, sort_keys=True)


REGISTRATION_PATH = "/v1/agents/register"


def registration_url(center_url: str) -> str:
    """The register endpoint, whether the base URL already names it or not.

    Appended to the parsed path rather than to the string: a base URL carrying a
    query would otherwise get the endpoint glued on after it, producing
    `…/register?x=1/v1/agents/register`.
    """
    parts = urlsplit(center_url)
    path = parts.path.rstrip("/")
    if not path.endswith(REGISTRATION_PATH):
        path += REGISTRATION_PATH
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


DEFAULT_METADATA_HOST = "metadata.google.internal"
# Mint again once less than this much of an identity token's life is left.
GCP_REFRESH_MARGIN_SECONDS = 300
_HEADER_SAFE = frozenset(chr(c) for c in range(0x21, 0x7F))
# (metadata host, audience) -> (token, exp). In memory only: a scanner on an
# interval reuses a fresh token across passes and never writes one down.
_GCP_TOKENS: dict[tuple[str, str], tuple[str, int]] = {}


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to follow: urllib carries `Authorization` to wherever a 3xx
    points, any host or scheme. A redirect surfaces as an HTTPError instead."""

    def redirect_request(self, *args, **kwargs):
        return None


_REGISTRATION_OPENER = build_opener(_NoRedirect)
# The metadata server is link-local: never through an HTTP proxy, which would
# see the minted identity token in clear.
_METADATA_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


def _header_safe(raw: str, name: str) -> str:
    """`raw` trimmed, or a refusal naming `name` and the offset, never the value."""
    value = raw.strip()
    if not value:
        raise ScannerError(f"{name} is empty")
    for offset, ch in enumerate(value):
        if ch not in _HEADER_SAFE:
            raise ScannerError(f"{name} holds U+{ord(ch):04X} at offset {offset}, which cannot go in a header value")
    return value


def _jwt_expiry(token: str) -> int | None:
    """The `exp` claim of our own freshly minted JWT, unverified; None if unreadable."""
    try:
        payload = token.split(".")[1]
        exp = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("exp")
    except (IndexError, ValueError, AttributeError):
        return None
    return exp if isinstance(exp, int) and not isinstance(exp, bool) else None


def _gcp_identity_token(audience: str, timeout: float) -> str:
    host = first_nonempty(os.environ.get("GCE_METADATA_HOST")) or DEFAULT_METADATA_HOST
    cached = _GCP_TOKENS.get((host, audience))
    if cached and time.time() + GCP_REFRESH_MARGIN_SECONDS < cached[1]:
        return cached[0]
    request = Request(
        f"http://{host}/computeMetadata/v1/instance/service-accounts/default/identity?"
        + urlencode({"audience": audience}),
        headers={"Metadata-Flavor": "Google"},
    )
    try:
        with _METADATA_OPENER.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        raise ScannerError(
            f"RAIL_AUTH_MODE=gcp: the metadata server at {host} returned {exc.code} for an identity token"
        ) from None
    except (URLError, TimeoutError, OSError) as exc:
        raise ScannerError(f"RAIL_AUTH_MODE=gcp: minting an identity token from the metadata server at {host}: {exc}") from None
    token = _header_safe(body, "the metadata server's identity token")
    exp = _jwt_expiry(token)
    if exp is None:
        _GCP_TOKENS.pop((host, audience), None)
    else:
        _GCP_TOKENS[(host, audience)] = (token, exp)
    return token


def auth_headers(mode: str | None = None, timeout: float = 15.0) -> dict[str, str]:
    """The credential this component presents, chosen by RAIL_AUTH_MODE.

    Mirrors rail-center's RAIL_AUTH_MODES_ACCEPTED, and the collector's
    `--webhook` (RailMon `src/auth.rs`) reads the same variables the same way:

    - `none` (default) sends nothing. A token set beside it is refused: it is an
      operator who set the credential and not the mode.
    - `bearer` sends RAIL_AUTH_TOKEN, or the contents of RAIL_AUTH_TOKEN_FILE,
      read on every call so a rotated file takes effect on the next pass
      without a restart. Neither form wins when both are set; that is refused.
    - `gcp` mints an identity token for RAIL_AUTH_AUDIENCE from the workload's
      metadata server (GCE_METADATA_HOST overrides its address), held only in
      memory until shortly before it expires.

    Anything it cannot produce raises, never degrading to an anonymous call
    the operator believes is authenticated. No message quotes a token.
    """
    explicit = first_nonempty(mode)
    resolved = (explicit or first_nonempty(os.environ.get("RAIL_AUTH_MODE")) or "none").lower()
    token = first_nonempty(os.environ.get("RAIL_AUTH_TOKEN"))
    token_file = first_nonempty(os.environ.get("RAIL_AUTH_TOKEN_FILE"))
    token_set = "RAIL_AUTH_TOKEN" if token else "RAIL_AUTH_TOKEN_FILE" if token_file else None
    if resolved not in AUTH_MODES:
        raise ScannerError(f"RAIL_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {resolved}")
    if resolved == "none":
        if token_set:
            configured = "none" if explicit or first_nonempty(os.environ.get("RAIL_AUTH_MODE")) else "unset, which is none"
            raise ScannerError(
                f"RAIL_AUTH_MODE is {configured} and sends no credential, but {token_set} is set; "
                f"set RAIL_AUTH_MODE=bearer to use it, or unset {token_set} to mean none"
            )
        return {}
    if resolved == "bearer":
        if token and token_file:
            raise ScannerError(
                "RAIL_AUTH_MODE=bearer takes RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE, and both are set; unset one"
            )
        if token_file:
            try:
                raw = Path(token_file).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ScannerError(f"reading RAIL_AUTH_TOKEN_FILE {token_file}: {exc.__class__.__name__}") from None
            return {"Authorization": f"Bearer {_header_safe(raw, 'RAIL_AUTH_TOKEN_FILE')}"}
        if not token:
            raise ScannerError("RAIL_AUTH_MODE=bearer requires RAIL_AUTH_TOKEN or RAIL_AUTH_TOKEN_FILE")
        return {"Authorization": f"Bearer {_header_safe(token, 'RAIL_AUTH_TOKEN')}"}
    if token_set:
        raise ScannerError(
            f"RAIL_AUTH_MODE=gcp mints its own credential, but {token_set} is set; "
            "unset it, or set RAIL_AUTH_MODE=bearer to use it"
        )
    audience = first_nonempty(os.environ.get("RAIL_AUTH_AUDIENCE"))
    if not audience:
        raise ScannerError("RAIL_AUTH_MODE=gcp requires RAIL_AUTH_AUDIENCE")
    return {"Authorization": f"Bearer {_gcp_identity_token(audience, timeout)}"}


def post_registration(
    center_url: str,
    payload: dict[str, Any],
    timeout: float = 15.0,
    auth_mode: str | None = None,
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        registration_url(center_url),
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **auth_headers(auth_mode, timeout),
        },
        method="POST",
    )
    try:
        with _REGISTRATION_OPENER.open(req, timeout=timeout) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(body_text) if body_text else None
            except json.JSONDecodeError as exc:
                raise ScannerError(f"rail-center returned non-JSON response: {body_text[:200]}") from exc
            return {"status": resp.status, "body": body}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ScannerError(f"rail-center registration failed: HTTP {exc.code}: {body}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScannerError(f"rail-center registration failed: {exc}") from exc


def configured_center_url(args: argparse.Namespace) -> str:
    center_url = first_nonempty(
        args.center_url,
        os.environ.get("RAIL_CENTER_URL"),
    )
    if not center_url:
        raise ScannerError("--center-url or RAIL_CENTER_URL is required with --register")
    return center_url


EVIDENCE_BUNDLE_INGEST_PATH = "/v1/evidence-bundles"


def configured_raildash_url(args: argparse.Namespace) -> str | None:
    """The RailDash target, or None when this scan is not delivering there.

    Unlike `--register`/`--center-url`, there is no separate boolean flag:
    naming a URL (flag or env) is itself the request to deliver, so a single
    invocation can target RailDash, Rail Center, both or neither by simply
    setting or omitting each URL independently.
    """
    return first_nonempty(args.raildash_url, os.environ.get("RAIL_RAILDASH_URL"))


def configured_agent_key(args: argparse.Namespace) -> str | None:
    return first_nonempty(args.agent_key, os.environ.get("RAIL_AGENT_KEY"))


def resolve_listen_file(args: argparse.Namespace) -> str | None:
    return first_nonempty(getattr(args, "listen_file", None), os.environ.get("RAIL_LISTEN_FILE"))


def resolve_files_file(args: argparse.Namespace) -> str | None:
    return first_nonempty(getattr(args, "files_file", None), os.environ.get("RAIL_FILES_FILE"))


def resolve_observed_file(args: argparse.Namespace) -> str | None:
    return first_nonempty(getattr(args, "observed_file", None), os.environ.get("RAIL_OBSERVED_FILE"))


def configured_target_manifest(args: argparse.Namespace) -> str | None:
    return first_nonempty(args.target_manifest, os.environ.get("RAIL_TARGET_MANIFEST"))


def configured_railmon_bin() -> str:
    """The compiled collector binary, resolved the same way `entrypoint.sh`
    resolves it — same env var, same fallback path — since this and the
    collector are the two processes sharing one container image."""
    return first_nonempty(os.environ.get("RAILMON_BIN")) or "/usr/local/bin/railmon-collector"


def resolve_targets(manifest_path: Path) -> list[dict[str, Any]]:
    """Every `--target-manifest` agent's discovery outcome and scan-scoping
    fields, resolved by the compiled collector rather than reimplemented
    here: process liveness, ownership and cross-target collision checks
    (`identity.rs`) have exactly one implementation this way, instead of a
    second one in Python that could silently diverge from it.
    """
    railmon_bin = configured_railmon_bin()
    output = run_command(
        [railmon_bin, "--target-manifest", str(manifest_path), "--print-resolved-targets"],
        timeout=10.0,
    )
    if output is None:
        raise ScannerError(f"failed to resolve --target-manifest via {railmon_bin} --print-resolved-targets")
    try:
        targets = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"{railmon_bin} --print-resolved-targets returned invalid JSON") from exc
    if not isinstance(targets, list):
        raise ScannerError(f"{railmon_bin} --print-resolved-targets returned a non-list JSON value")
    return targets


def _keyed_path(path: Path, agent_key: str) -> str:
    """The same default path, suffixed with the agent key, so a per-key scan
    run in the same collection does not overwrite the sandbox-wide scan's
    (or another key's) local artifact at the one un-keyed default path."""
    return str(path.with_name(path.name + f".{agent_key}"))


def _v2_collection_requested(args: argparse.Namespace) -> bool:
    """Whether this collection needs evidence at all — the same test
    `run_one_scan` itself uses (`not args.no_evidence_bundle or a RailDash
    URL is configured`). When true, `run_one_collection` builds and
    delivers exactly one evidence-bundle-v2 collection instead of letting
    `run_one_scan` build its own (v1) bundle per scan (DR-109 M2)."""
    return not args.no_evidence_bundle or configured_raildash_url(args) is not None


def _v1_scope_from_scan_result(
    target_args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Build (but do not write, verify against v1, or deliver) the raw
    v1-shaped attribute data one scope of a v2 collection needs — either
    the sandbox-wide scan or one agent-scoped scan.

    Reads the `(context, payload, identity)` `run_one_scan` already stashed
    on `target_args._v2_scan_result` from its own `scan()` call, rather than
    calling `scan()` a second time. An earlier version of this function
    called `scan()` itself, so composing a v2 collection ran a full live
    environment read (docker inspect, MCP inventory, model detection) twice
    per scope — once for `run_one_scan`'s feature file/registration, once
    here — breaking `build_verified_bundle`'s own "built once and shared"
    contract (this same file, `run_one_scan`'s docstring comment): two
    independent scans of the same target can observe different live state
    and disagree, exactly what that contract exists to prevent.

    Returns `(bundle, context)`. `bundle` is `None` on any failure — either
    `run_one_scan`'s own `scan()` never having run at all (`_v2_scan_result`
    unset), or the stashed result failing v1's own contract
    (`try_build_verified_bundle`, reporting rather than raising). `context`
    is `run_one_scan`'s own environment/mode snapshot, returned even when
    `bundle` is `None` as long as `scan()` got far enough to produce one —
    the caller's sandbox-failure path needs it to still name a
    `host_id`/`sandbox_name` for a synthetic `FAILED` sandbox scope (design
    §5). `context` is `None` only when `scan()` failed before establishing
    even that (so `run_one_scan` never reached its `finally` stash).
    """
    import evidence_bundle  # lazy: breaks the import cycle

    result = getattr(target_args, "_v2_scan_result", None)
    if result is None:
        return None, None
    context, payload, identity = result
    bundle = evidence_bundle.try_build_verified_bundle(target_args, context, payload, identity)
    return bundle, context


def _deliver_v1_fallback(args: argparse.Namespace) -> int:
    """This scope's v1 evidence bundle, from the scan `run_one_scan` already
    ran — reused via `_v2_scan_result`, not a second `scan()` call — for the
    two cases where `run_one_collection` suppressed a `_v2_collection`
    target's own v1 write (betting on a v2 collection being produced) but
    that bet did not pay off: the target manifest itself failed to resolve,
    or no v2 collection could be built at all because `host_id`/
    `sandbox_name` were never determined. Without this fallback the scan
    that already ran leaves no artifact anywhere — worse than the
    unkeyed-manifest single-scan path this function's docstring promises
    never to regress. Mirrors `run_one_scan`'s own v1 evidence-bundle
    block exactly (file write, then an optional RailDash POST), minus the
    `scan()` call it already reused.
    """
    import evidence_bundle  # lazy: breaks the import cycle

    result = getattr(args, "_v2_scan_result", None)
    if result is None:
        return 0
    context, payload, identity = result
    bundle = evidence_bundle.try_build_verified_bundle(args, context, payload, identity)
    exit_code = 0
    if bundle is None:
        # Already reported: the bundle failed its own contract (DR-157).
        exit_code = 2
    else:
        bundle = evidence_bundle.reuse_unchanged_bundle(bundle, configured_agent_key(args))
    if not args.no_evidence_bundle and bundle is not None:
        bundle_path = evidence_bundle.evidence_bundle_output_path(args)
        try:
            store_json(bundle_path, bundle, args.compact)
            print(f"[agent-environment-scanner] evidence bundle: {bundle_path}", file=sys.stderr)
        except ScannerError as exc:
            print(f"agent-environment-scanner: {exc}", file=sys.stderr)
    raildash_url = configured_raildash_url(args)
    if raildash_url:
        if bundle is None:
            exit_code = 2
        else:
            try:
                data = evidence_bundle.render_bundle_bytes(bundle, args.compact)
                agent_key = configured_agent_key(args)
                raildash_token = configured_raildash_token(args)
                response = post_evidence_bundle(
                    raildash_url, data, raildash_token=raildash_token, agent_key=agent_key
                )
                body = response.get("body")
                body = body if isinstance(body, dict) else {}
                outcome = "duplicate" if body.get("duplicate") else "accepted"
                print(
                    f"[agent-environment-scanner] delivered evidence bundle to raildash: "
                    f"HTTP {response['status']} {outcome} id={body.get('asp_id')}",
                    file=sys.stderr,
                )
            except ScannerError as exc:
                print(f"agent-environment-scanner: {exc}", file=sys.stderr)
                exit_code = 2
    return exit_code


def _deliver_v2_collection(args: argparse.Namespace, sandbox_v1: dict[str, Any], agent_entries: list[dict[str, Any]]) -> int:
    """Compose, verify, and write/deliver exactly one evidence-bundle-v2
    collection — the shared `sandbox` scope from `sandbox_v1` plus every
    entry in `agent_entries` (already sorted-or-not; `compose_from_scopes`
    sorts and rejects a duplicate key). Built once as one dict and rendered
    to bytes exactly once (`evidence_bundle.render_bundle_bytes`), then
    that identical object/bytes are reused for both the on-disk artifact
    and the RailDash POST — the same exact-byte idempotency contract v1's
    own `build_verified_bundle`/`render_bundle_bytes` document. Returns 0 on
    success, 2 if any part of composing/writing/delivering failed.
    """
    import compose_evidence_bundle_v2 as composer  # lazy: breaks the import cycle
    import evidence_bundle  # lazy: breaks the import cycle

    try:
        collection = composer.compose_from_scopes(
            host_id=sandbox_v1["host_id"],
            sandbox_name=sandbox_v1["sandbox_name"],
            rule_pack_version=sandbox_v1["rule_pack_version"],
            sandbox_inputs=sandbox_v1["inputs_attempted"],
            sandbox_attributes={
                name: value
                for name, value in sandbox_v1["attributes"].items()
                if name in composer.SANDBOX_ATTRIBUTES
            },
            agent_entries=agent_entries,
            attestations=sandbox_v1.get("attestations"),
        )
        evidence_bundle.verify_bundle_v2(collection)
    except (ValueError, ScannerError) as exc:
        print(f"agent-environment-scanner: evidence bundle v2 composition failed: {exc}", file=sys.stderr)
        return 2
    # DR-157: an interval scan whose collection has not changed re-sends the
    # previous one, so RailDash records a duplicate rather than a new ASP.
    collection = evidence_bundle.reuse_unchanged_bundle(collection)

    exit_code = 0
    # Built once above; every consumer below shares this exact dict/bytes.
    data = evidence_bundle.render_bundle_bytes(collection, args.compact)
    if not args.no_evidence_bundle:
        bundle_path = evidence_bundle.evidence_bundle_output_path(args)
        try:
            store_json(bundle_path, collection, args.compact)
            print(f"[agent-environment-scanner] evidence bundle v2: {bundle_path}", file=sys.stderr)
        except ScannerError as exc:
            print(f"agent-environment-scanner: {exc}", file=sys.stderr)
            exit_code = 2

    raildash_url = configured_raildash_url(args)
    if raildash_url:
        try:
            raildash_token = configured_raildash_token(args)
            response = post_evidence_bundle(raildash_url, data, raildash_token=raildash_token)
            body = response.get("body")
            body = body if isinstance(body, dict) else {}
            outcome = "duplicate" if body.get("duplicate") else "accepted"
            print(
                f"[agent-environment-scanner] delivered evidence bundle v2 to raildash: "
                f"HTTP {response['status']} {outcome} id={body.get('asp_id')}",
                file=sys.stderr,
            )
        except ScannerError as exc:
            print(f"agent-environment-scanner: {exc}", file=sys.stderr)
            exit_code = 2
    return exit_code


def run_one_collection(args: argparse.Namespace) -> int:
    """DR-109 M2: sandbox scanning once per collection (the existing
    single-target scan, unchanged for the feature file and registration),
    plus agent-scoped scanning and registration once per resolved agent
    key — scoped to that key's `scan.config_roots` and carrying its
    `agent_key` into the registration payload. A declared agent that does
    not currently resolve is logged and skipped for registration/feature-file
    purposes, matching the collector's own `run_multi_target` (never drop a
    declared agent's siblings over one bad target) — but it still gets an
    `agents[]` entry in the evidence collection below, with its real
    `discovery_status`, instead of silently vanishing from what a scorer
    reads (design §4.3).

    Evidence: when this collection is configured to build or deliver
    evidence at all (`_v2_collection_requested`), exactly one
    evidence-bundle-v2 collection is produced — one shared `sandbox` scope
    from the sandbox-wide scan plus a sorted `agents[]` array — not the N
    separate v1 bundles an earlier version of this function wrote one per
    key. Every `run_one_scan` call this function drives is told to suppress
    its own v1 evidence-bundle handling (`_v2_collection`) so that is the
    only evidence artifact/delivery a manifest-scoped run produces.
    """
    build_v2 = _v2_collection_requested(args)

    sandbox_scan_args = args
    if build_v2:
        sandbox_scan_args = copy.copy(args)
        sandbox_scan_args._v2_collection = True
    exit_code = run_one_scan(sandbox_scan_args)

    manifest_path = Path(configured_target_manifest(args)).expanduser()
    try:
        targets = resolve_targets(manifest_path)
    except ScannerError as exc:
        print(f"agent-environment-scanner: {exc}", file=sys.stderr)
        if build_v2:
            # The sandbox scan above already ran and had its own v1 write
            # suppressed on the bet that a v2 collection would follow — a
            # bet a broken manifest just lost. Delivering the v1 fallback
            # here (reusing that same scan, not a second one) is the only
            # way this scope's evidence reaches an artifact at all.
            _deliver_v1_fallback(sandbox_scan_args)
        return 2

    sandbox_v1: dict[str, Any] | None = None
    if build_v2:
        import evidence_bundle  # lazy: breaks the import cycle

        sandbox_v1, sandbox_context = _v1_scope_from_scan_result(sandbox_scan_args)
        if sandbox_v1 is None:
            # Design §5, "Shared evidence collection fails": agent-scoped
            # scanning/registration below still runs (never drop a sibling
            # agent over this). A v2 collection still needs a non-empty
            # `host_id`/`sandbox_name` (schema `minLength: 1` on both) even
            # when nothing else about the sandbox could be collected — when
            # `scan()` got far enough to know those, synthesize a sandbox
            # scope whose every source is FAILED instead of omitting the
            # sandbox scope (and so the whole collection) outright.
            host_id = sandbox_name = None
            if sandbox_context is not None:
                host_id, _ = detect_host_id(sandbox_context, args.host_id)
                sandbox_name, _ = detect_sandbox_name(sandbox_context, args.sandbox_name)
            if host_id and sandbox_name:
                sandbox_v1 = {
                    "host_id": host_id,
                    "sandbox_name": sandbox_name,
                    "rule_pack_version": evidence_bundle.RULE_PACK_VERSION,
                    "inputs_attempted": evidence_bundle.failed_inputs("PARSE_FAILED"),
                    "attributes": {},
                    "attestations": [],
                }
                print(
                    "agent-environment-scanner: shared evidence collection failed; "
                    "sandbox scope marked FAILED, agent-scoped scanning still runs",
                    file=sys.stderr,
                )
            else:
                # `scan()` failed before even a host_id/sandbox_name could be
                # named — no schema-legal v2 collection can be built at all,
                # since both are required non-empty fields at the bundle's
                # top level, not just inside the sandbox scope. Deliver this
                # scope's v1 fallback (reusing the same scan) rather than
                # losing it outright, the same as the broken-manifest case.
                print(
                    "agent-environment-scanner: shared evidence collection failed before "
                    "host_id/sandbox_name could be determined; no evidence-bundle-v2 will "
                    "be produced for this run",
                    file=sys.stderr,
                )
                _deliver_v1_fallback(sandbox_scan_args)
            exit_code = 2

    agent_entries: list[dict[str, Any]] = []
    for target in targets:
        agent_key = target["agent_key"]
        status = target.get("status")
        self_asserted_agent_key = target.get("self_asserted_agent_key")
        if self_asserted_agent_key and self_asserted_agent_key != agent_key:
            # Design doc §4.1: self-asserted, diagnostic only -- this never
            # changes discovery_status, config_roots, or which key the scan
            # below runs under; it only tells an operator their manifest and
            # the process's own RAIL_AGENT_KEY have drifted apart.
            print(
                f"[agent-environment-scanner] '{agent_key}' resolved to a process whose own "
                f"RAIL_AGENT_KEY is '{self_asserted_agent_key}' (manifest and process disagree; "
                "the manifest's declared key is authoritative)",
                file=sys.stderr,
            )
        if status != "available":
            print(
                f"[agent-environment-scanner] skipping agent-scoped scan for '{agent_key}': "
                f"{status} ({target.get('reason')})",
                file=sys.stderr,
            )
            if build_v2 and sandbox_v1 is not None:
                import evidence_bundle  # lazy: breaks the import cycle

                agent_entries.append(
                    {
                        "agent_key": agent_key,
                        "discovery_status": status,
                        "inputs_attempted": evidence_bundle.unattempted_inputs("NO_SOURCE_ACCESS"),
                        "attributes": {},
                    }
                )
            continue
        config_roots = target.get("config_roots") or []
        if not config_roots:
            # No declared scan.config_roots means nothing agent-specific to
            # scope this scan to. Running it anyway would fall through to
            # build_registration_payload's own `or default_config_paths(env)`
            # fallback — the same paths the sandbox-wide scan above already
            # covers — and register that duplicate, un-scoped data under this
            # agent's key as if it had been observed specifically for it.
            print(
                f"[agent-environment-scanner] skipping agent-scoped scan for '{agent_key}': "
                "no scan.config_roots declared, nothing agent-specific to scope it to",
                file=sys.stderr,
            )
            if build_v2 and sandbox_v1 is not None:
                import compose_evidence_bundle_v2 as composer  # lazy: breaks the import cycle
                import evidence_bundle  # lazy: breaks the import cycle

                agent_entries.append(
                    {
                        "agent_key": agent_key,
                        # Discovery *did* resolve this agent to a live
                        # process; it is the scan-scoping the collector
                        # cannot isolate, so discovery_status stays
                        # "available" and each would-be agent-scoped
                        # attribute is individually BLIND instead (design
                        # §4.3's MULTI_AGENT_SCOPE_UNRESOLVED).
                        "discovery_status": "available",
                        "inputs_attempted": evidence_bundle.unattempted_inputs(
                            "MULTI_AGENT_SCOPE_UNRESOLVED"
                        ),
                        "attributes": evidence_bundle.scope_unresolved_attributes(
                            sandbox_v1["attributes"], composer.SANDBOX_ATTRIBUTES
                        ),
                    }
                )
            continue
        target_args = copy.copy(args)
        target_args.agent_key = agent_key
        target_args.config_path = config_roots
        target_args.feature_output = _keyed_path(feature_output_path(args), agent_key)
        target_args.registration_output = _keyed_path(registration_output_path(args), agent_key)
        # Only suppress this agent's own v1 write when a v2 collection can
        # actually receive its data (`sandbox_v1 is not None`) — otherwise
        # the earlier sandbox-scope failure already means no v2 collection
        # will ever be composed, and suppressing this agent's v1 bundle too
        # would drop a successfully-scanned agent's evidence entirely for
        # no gain. Falls through to the same keyed v1 path a non-v2 run uses.
        if build_v2 and sandbox_v1 is not None:
            target_args._v2_collection = True
        elif not target_args.no_evidence_bundle or configured_raildash_url(target_args):
            import evidence_bundle  # lazy: breaks the import cycle

            target_args.evidence_bundle_output = _keyed_path(
                evidence_bundle.evidence_bundle_output_path(args), agent_key
            )
        target_exit = run_one_scan(target_args)
        exit_code = target_exit if target_exit != 0 else exit_code

        if build_v2 and sandbox_v1 is not None:
            agent_v1, _ = _v1_scope_from_scan_result(target_args)
            import compose_evidence_bundle_v2 as composer  # lazy: breaks the import cycle
            import evidence_bundle  # lazy: breaks the import cycle

            if agent_v1 is None:
                # Design §5, "One agent collector fails": other keyed agents
                # still continue (the loop keeps going); this entry is still
                # present in `agents[]`, with every attribute the sandbox
                # scope's own template names marked FAILED, rather than
                # silently missing as if the agent had never been declared.
                exit_code = 2
                if sandbox_v1 is not None:
                    agent_entries.append(
                        {
                            "agent_key": agent_key,
                            "discovery_status": "available",
                            "inputs_attempted": evidence_bundle.failed_inputs("PARSE_FAILED"),
                            "attributes": evidence_bundle.failed_attributes(
                                sandbox_v1["attributes"], composer.SANDBOX_ATTRIBUTES
                            ),
                        }
                    )
                continue

            agent_entries.append(
                {
                    "agent_key": agent_key,
                    "discovery_status": "available",
                    "inputs_attempted": agent_v1["inputs_attempted"],
                    "attributes": composer.agent_scoped_attributes(agent_v1["attributes"]),
                }
            )

    if build_v2 and sandbox_v1 is not None:
        if not agent_entries:
            print(
                "agent-environment-scanner: no agent entries to compose into evidence bundle v2 "
                "(the v2 schema requires at least one)",
                file=sys.stderr,
            )
            exit_code = 2
        else:
            delivery_exit = _deliver_v2_collection(args, sandbox_v1, agent_entries)
            exit_code = delivery_exit if delivery_exit != 0 else exit_code

    return exit_code


def configured_raildash_token(args: argparse.Namespace) -> str | None:
    """`RAIL_RAILDASH_TOKEN` only, deliberately no `--raildash-token` flag —

    same reasoning as `RAIL_AUTH_TOKEN`: a CLI flag lands in `ps` output on a
    shared host, an env var does not.
    """
    del args  # kept for call-site symmetry with the other `configured_*` helpers
    return os.environ.get("RAIL_RAILDASH_TOKEN")


def evidence_bundle_ingest_url(raildash_url: str, agent_key: str | None = None) -> str:
    """RailDash's evidence-bundle ingest endpoint for this base URL.

    Mirrors `registration_url`'s query-safe joining: the endpoint is appended
    to the parsed path, never glued onto a raw string that might already
    carry a query. `agent_key`, when given, rides as a `?agent_key=` query
    parameter alongside (not replacing) whatever query the base URL already
    carried.

    DR-120 (RailDash's ingest route) had not landed a PR when this was
    written, so the query-string placement — the more conventional choice —
    is a best guess rather than a confirmed contract; if DR-120 lands with
    `agent_key` as a header instead, this is the one place to change.
    """
    parts = urlsplit(raildash_url)
    path = parts.path.rstrip("/")
    if not path.endswith(EVIDENCE_BUNDLE_INGEST_PATH):
        path += EVIDENCE_BUNDLE_INGEST_PATH
    query_pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "agent_key"]
    if agent_key:
        query_pairs.append(("agent_key", agent_key))
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query_pairs), ""))


def post_evidence_bundle(
    raildash_url: str,
    data: bytes,
    timeout: float = 15.0,
    raildash_token: str | None = None,
    agent_key: str | None = None,
) -> dict[str, Any]:
    """POST the evidence bundle's raw bytes to RailDash, unchanged.

    `data` must be exactly what would be written to `--evidence-bundle-output`
    for this scan — RailDash dedupes by the content digest of the bytes it
    receives, so re-serializing (different key order, whitespace, or a second
    build with a fresh `bundle_id`) here would defeat that.

    RailDash's own write-route guard (DR-120) rejects this endpoint without a
    valid `X-RailDash-Token`, regardless of loopback — this is not rail-center's
    `RAIL_AUTH_MODE`/bearer scheme (`auth_headers`), which RailDash does not
    understand at all. Delivery silently 403ing here was the actual, discovered
    failure mode DR-110's runtime acceptance ran into (see needs-yusheng history):
    the two features landed in the order that made this codepath dead on arrival.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if raildash_token:
        headers["X-RailDash-Token"] = raildash_token
    req = Request(
        evidence_bundle_ingest_url(raildash_url, agent_key),
        data=data,
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(body_text) if body_text else None
            except json.JSONDecodeError as exc:
                raise ScannerError(f"raildash returned non-JSON response: {body_text[:200]}") from exc
            return {"status": resp.status, "body": body}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ScannerError(f"raildash evidence-bundle delivery failed: HTTP {exc.code}: {body}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScannerError(f"raildash evidence-bundle delivery failed: {exc}") from exc


def registration_output_path(args: argparse.Namespace) -> Path:
    configured = first_nonempty(
        args.registration_output,
        os.environ.get("RAIL_REGISTRATION_OUTPUT"),
    )
    if configured:
        return Path(configured).expanduser()
    import evidence_bundle  # lazy: breaks the import cycle

    return evidence_bundle.default_output(DEFAULT_REGISTRATION_OUTPUT, LEGACY_REGISTRATION_OUTPUT)


def feature_output_path(args: argparse.Namespace) -> Path:
    configured = first_nonempty(args.feature_output, os.environ.get("RAIL_FEATURE_OUTPUT"))
    if configured:
        return Path(configured).expanduser()
    import evidence_bundle  # lazy: breaks the import cycle

    return evidence_bundle.default_output(DEFAULT_FEATURE_OUTPUT, LEGACY_FEATURE_OUTPUT)


def build_registration_state(center_url: str, payload: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """What we keep from a registration: the agent id, and nothing that is a ticket.

    The response carries a `token`, and the scanner drops it on the floor. It is a
    placeholder minted with a null posture — posture is scored asynchronously
    after the response returns — so anything that stored or forwarded it would
    pin the fleet to a posture that was never computed. The proxy fetches its own
    ticket; the scanner is the registrar, and a registrar holds no credentials.
    """
    body = response.get("body")
    if not isinstance(body, dict):
        raise ScannerError("rail-center registration response did not contain an object body")
    agent = body.get("agent")
    if not isinstance(agent, dict):
        raise ScannerError("rail-center registration response did not contain agent object")

    return {
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "center_url": center_url.rstrip("/"),
        "registration_url": registration_url(center_url),
        "status": response.get("status"),
        "agent_id": agent.get("id"),
        "sandbox_id": agent.get("sandbox_id"),
        "host_id": agent.get("host_id"),
        "sandbox_name": agent.get("sandbox_name"),
        "environment_fingerprint": agent.get("environment_fingerprint"),
        "request_summary": {
            "type": payload.get("type"),
            "owner": payload.get("owner"),
            "host_id": payload.get("host_id"),
            "sandbox_name": payload.get("sandbox_name"),
            "environment": payload.get("environment"),
            "skills_count": len(payload.get("skills") or []),
        },
        "response": strip_ticket(body),
    }


RESPONSE_KEYS_KEPT = ("agent",)
AGENT_KEYS_KEPT = ("id", "sandbox_id", "host_id", "sandbox_name", "environment_fingerprint")


def strip_ticket(body: dict[str, Any]) -> dict[str, Any]:
    """The response reduced to the keys we know are not credentials.

    An allowlist at both levels, not a denylist: dropping the two field names a
    ticket happens to use today would let a renamed or newly added credential
    field ride along the next time rail-center's response grows. `agent` grows
    the same way, so keeping it whole would reopen the identical hole one level
    down.
    """
    kept = {key: body[key] for key in RESPONSE_KEYS_KEPT if key in body}
    agent = kept.get("agent")
    if isinstance(agent, dict):
        kept["agent"] = {key: agent[key] for key in AGENT_KEYS_KEPT if key in agent}
    return kept


def store_json(path: Path, value: dict[str, Any], compact: bool) -> None:
    """Write owner-only, and owner-only from the moment the file exists.

    The inventory names an agent's tools, endpoints and which of its secrets sit
    in plaintext — a map worth reading for anyone who wants to attack the agent,
    so it should not be world-readable by default. The mode is settled before any
    content is written rather than by a chmod afterwards: creating the file under
    the umask and tightening it later leaves the map readable for the length of
    the write. O_CREAT only carries a mode for a file that does not exist yet, so
    a file an earlier, looser run left at 0644 is tightened through its own
    descriptor before the first byte goes in.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            try:
                os.fchmod(handle.fileno(), 0o600)
            except (AttributeError, OSError):
                # No fchmod (Windows) or a filesystem that refuses it. A file we
                # created is already 0600; one we inherited stays as it was.
                pass
            handle.write(render_json(value, compact) + "\n")
    except OSError as exc:
        raise ScannerError(f"could not write {path}: {exc}") from exc


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan the local agent environment and emit a rail-center registration payload."
    )
    parser.add_argument("--mode", choices=["self", "docker"], default="self")
    parser.add_argument("--container", help="Docker container name/id to scan when --mode docker is used")
    parser.add_argument("--output", "-o", help="Write JSON payload to this file instead of stdout")
    parser.add_argument("--agent-type", default="personal", choices=["personal", "service"])
    parser.add_argument("--owner", help="Owner identity override")
    parser.add_argument("--sandbox-type", help="Sandbox type override, e.g. nemo_claw or openclaw")
    parser.add_argument("--llm-provider", help="LLM provider override, e.g. anthropic, openai, local")
    parser.add_argument("--llm-model", help="LLM model override")
    parser.add_argument(
        "--capture-file",
        action="append",
        default=[],
        help="JSONL capture file to inspect for request body model fields. Can be passed multiple times.",
    )
    parser.add_argument(
        "--config-path",
        action="append",
        default=[],
        help="OpenClaw/NemoClaw config file or directory to scan for model fields.",
    )
    parser.add_argument(
        "--mcp-config",
        action="append",
        default=[],
        help="MCP config file to scan for skills. Defaults to .mcp.json, /workdir/.mcp.json, and ~/.mcp.json.",
    )
    parser.add_argument(
        "--skills-file",
        action="append",
        default=[],
        help="JSON skills list or RegisterAgentRequest payload to merge into the generated registration payload.",
    )
    parser.add_argument(
        "--observed-file",
        help="AgentSight snapshot (agentsight report export -o snapshot.json) to summarise "
        "into the observed-reach dimension. Names and counts only; no prompts, tool "
        "arguments or command lines are read from it. Defaults to RAIL_OBSERVED_FILE.",
    )
    parser.add_argument(
        "--listen-file",
        help="listensnoop JSON lines (from ebpf-tls-tap, run in the agent's PID namespace) to "
        "summarise into the observed listening sockets. Protocol, address, port and process "
        "name only. Defaults to RAIL_LISTEN_FILE.",
    )
    parser.add_argument(
        "--files-file",
        help="filesnoop JSON lines (from ebpf-tls-tap, run in the agent's PID namespace) to "
        "summarise into the observed file access. Path and read/write/exec only; no file "
        "content. Defaults to RAIL_FILES_FILE.",
    )
    parser.add_argument("--host-id", help="Host identity override. Defaults to RAIL_HOST_ID.")
    parser.add_argument(
        "--sandbox-name",
        help=f"Sandbox name override. Otherwise the {SANDBOX_NAME_LABEL} label, then the container name.",
    )
    parser.add_argument(
        "--feature-output",
        help=f"Write the feature file here. Defaults to {DEFAULT_FEATURE_OUTPUT}.",
    )
    parser.add_argument(
        "--no-feature-file",
        action="store_true",
        help="Skip writing the feature file (it is the scanner's primary output).",
    )
    parser.add_argument(
        "--evidence-bundle-output",
        help="Write the evidence bundle (the profile brain's input) here. "
        "Defaults to .rail/railmon/evidence-bundle.json; RAIL_EVIDENCE_BUNDLE_OUTPUT also works.",
    )
    parser.add_argument(
        "--no-evidence-bundle",
        action="store_true",
        help="Skip writing the evidence bundle.",
    )
    parser.add_argument("--register", action="store_true", help="POST the generated payload to rail-center.")
    parser.add_argument("--center-url", help="rail-center base URL or /v1/agents/register URL.")
    parser.add_argument(
        "--auth-mode",
        choices=list(AUTH_MODES),
        help="Credential to present when registering. Defaults to RAIL_AUTH_MODE, then none.",
    )
    parser.add_argument(
        "--registration-output",
        help=f"Store the rail-center agent id and identity here (never a ticket). "
        f"Defaults to {DEFAULT_REGISTRATION_OUTPUT}.",
    )
    parser.add_argument(
        "--output-register-response",
        action="store_true",
        help="Print rail-center registration response/state instead of only storing it when --register is used.",
    )
    parser.add_argument(
        "--raildash-url",
        help="RailDash base URL to POST the evidence bundle to, as raw bytes, at "
        f"<url>{EVIDENCE_BUNDLE_INGEST_PATH}. Also read from RAIL_RAILDASH_URL. Independent of "
        "--register/--center-url: use either, both, or neither in one scan.",
    )
    parser.add_argument(
        "--agent-key",
        help="Local agent key RailDash uses to resolve identity when the evidence bundle carries no "
        "deployment pair (mirrors `raildash asp load --agent-key`). Sent as the RailDash delivery's "
        "?agent_key= query parameter. Also read from RAIL_AGENT_KEY.",
    )
    parser.add_argument(
        "--target-manifest",
        help="DR-109 M2: the collector's multi-agent target manifest (same schema, same file). When "
        "given, each collection also runs one agent-scoped scan+registration per resolved agent "
        "key, scoped to that key's scan.config_roots, in addition to (not instead of) the existing "
        "sandbox-wide scan above. A declared agent that does not currently resolve is logged and "
        "skipped, not treated as a failure. Also read from RAIL_TARGET_MANIFEST.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="DR-83: seconds between scans. When set (or RAIL_SCAN_INTERVAL_IN_SECONDS is), the scanner "
        "stays running and scans again on this interval instead of exiting after one scan. Omit both for "
        "the existing single-scan-and-exit behavior.",
    )
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    return parser


DEFAULT_SCAN_INTERVAL_SECONDS = 3600.0


def configured_scan_interval(args: argparse.Namespace) -> float | None:
    """DR-83: `None` means the existing single-scan-and-exit behavior — an
    existing invocation that names neither `--interval` nor the env var is
    unaffected. Naming either (a bare `RAIL_SCAN_INTERVAL_IN_SECONDS=1`, say)
    opts in to interval mode; `--interval`'s own value, when given, wins over
    the env var's. `RAIL_SCAN_INTERVAL_IN_SECONDS` set to something that isn't
    a number falls back to the 3600s default rather than failing the scan —
    a malformed interval should not be worse than the default one.
    """
    if args.interval is not None:
        return args.interval
    raw = os.environ.get("RAIL_SCAN_INTERVAL_IN_SECONDS")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_SCAN_INTERVAL_SECONDS


def write_feature_file(
    args: argparse.Namespace,
    context: dict[str, Any],
    payload: dict[str, Any],
    identity: dict[str, Any],
) -> bool:
    """Write the feature file, reporting failure rather than raising.

    It runs from a `finally`, so raising here would replace whatever error is
    already on its way out — and a registration failure is the one the operator
    needs to read. The failure is still reported and still fails the run; it just
    does not overwrite the diagnosis, which is printed after it as the exception
    finishes unwinding.
    """
    feature_path = feature_output_path(args)
    try:
        store_json(feature_path, build_feature_file(args, context, payload, identity), args.compact)
    except ScannerError as exc:
        print(f"agent-environment-scanner: {exc}", file=sys.stderr)
        return False
    print(f"[agent-environment-scanner] feature file: {feature_path}", file=sys.stderr)
    return True


def run_one_scan(args: argparse.Namespace) -> int:
    """One scan, exactly as `main` always ran it before DR-83 — the loop in
    `main` below is the only new caller; every existing single-shot caller
    (including this module's own tests) goes through this unchanged."""
    feature_file_written = True
    delivery_failed = False
    bundle_failed = False
    raildash_url = configured_raildash_url(args)
    try:
        context, payload, identity = scan(args)

        try:
            if args.output:
                # Through store_json like every other artifact: this payload
                # carries the same tool, endpoint and user inventory the feature
                # file does. Inside the try, so a bad --output path still leaves
                # the feature file written.
                store_json(Path(args.output).expanduser(), payload, args.compact)
            elif not args.register:
                print(render_json(payload, args.compact))

            if args.register:
                # Caught here, not left to propagate: a --raildash-url target
                # below must still be attempted even when --register fails, and
                # vice versa — the two delivery targets are independent.
                try:
                    center_url = configured_center_url(args)
                    response = post_registration(center_url, payload, auth_mode=args.auth_mode)
                    state = build_registration_state(center_url, payload, response)
                    state_path = registration_output_path(args)
                    store_json(state_path, state, args.compact)
                    identity["registration_status"] = "registered"
                    if args.output_register_response:
                        print(render_json(state, args.compact))
                    else:
                        print(
                            f"[agent-environment-scanner] registered with rail-center: HTTP {response['status']} "
                            f"agent_id={state['agent_id']} state_file={state_path}",
                            file=sys.stderr,
                        )
                except ScannerError as exc:
                    print(f"agent-environment-scanner: {exc}", file=sys.stderr)
                    delivery_failed = True
        finally:
            # The feature file is the primary artifact and needs no control plane,
            # so it is written even when registration fails — but only after the
            # attempt, so registration_status reports what happened rather than
            # what was asked for. A scorer reading "registered" off an agent that
            # never reached the control plane would be reading a lie.
            if not args.no_feature_file:
                feature_file_written = write_feature_file(args, context, payload, identity)
            # The evidence bundle rides the same guarantee: the brain's input,
            # built even on a failed registration. Built once and shared by
            # both consumers below — the file write and a RailDash POST both
            # need the identical bytes, and building it twice would mint two
            # different bundle_ids for one scan's output. A write or delivery
            # failure is reported without changing the exit code for the file
            # write (the feature file owns that); a RailDash delivery failure
            # does change it, like a failed --register.
            #
            # DR-109 M2: `run_one_collection` sets `_v2_collection` on a
            # target's args when it will itself compose this scan's raw
            # attribute data into one shared evidence-bundle-v2 collection
            # and write/deliver *that* exactly once. Without this guard a
            # manifest-scoped run would additionally write (and, with a
            # RailDash URL configured, separately POST) N keyed v1 bundles
            # here — the exact "not N v1 bundles" gap this milestone closes.
            #
            # This scan's own `(context, payload, identity)` is stashed on
            # `args._v2_scan_result` rather than simply skipped, so
            # `_v1_scope_from_scan_result` (and the v1-fallback delivery for
            # the cases where a v2 collection ultimately can't be built) can
            # reuse this exact scan instead of calling `scan()` a second
            # time for the same target — two independent scans of one
            # target could observe different live state and disagree,
            # exactly what "built once and shared" above exists to prevent.
            if getattr(args, "_v2_collection", False):
                args._v2_scan_result = (context, payload, identity)
            elif not args.no_evidence_bundle or raildash_url:
                import evidence_bundle  # lazy: breaks the import cycle

                bundle = evidence_bundle.try_build_verified_bundle(args, context, payload, identity)
                if bundle is None:
                    # Already reported. A bundle that fails its own contract
                    # fails the scan (DR-157), whether or not it was going
                    # anywhere: exiting 0 here left a supervisor or CI job
                    # believing a scan produced evidence when none was written.
                    bundle_failed = True
                else:
                    # DR-157: unchanged content since this process's last
                    # scan reuses that scan's bundle (bundle_id and all), so
                    # an interval scan re-sends the same bytes and RailDash
                    # dedupes them instead of storing a new ASP per tick.
                    bundle = evidence_bundle.reuse_unchanged_bundle(bundle, configured_agent_key(args))

                if not args.no_evidence_bundle and bundle is not None:
                    bundle_path = evidence_bundle.evidence_bundle_output_path(args)
                    try:
                        store_json(bundle_path, bundle, args.compact)
                        print(f"[agent-environment-scanner] evidence bundle: {bundle_path}", file=sys.stderr)
                    except ScannerError as exc:
                        print(f"agent-environment-scanner: {exc}", file=sys.stderr)

                if raildash_url:
                    if bundle is None:
                        # Already reported above: the bundle failed to build
                        # or verify, so there is nothing to deliver.
                        delivery_failed = True
                    else:
                        try:
                            data = evidence_bundle.render_bundle_bytes(bundle, args.compact)
                            agent_key = configured_agent_key(args)
                            raildash_token = configured_raildash_token(args)
                            response = post_evidence_bundle(
                                raildash_url, data, raildash_token=raildash_token, agent_key=agent_key
                            )
                            body = response.get("body")
                            body = body if isinstance(body, dict) else {}
                            outcome = "duplicate" if body.get("duplicate") else "accepted"
                            print(
                                f"[agent-environment-scanner] delivered evidence bundle to raildash: "
                                f"HTTP {response['status']} {outcome} id={body.get('asp_id')}",
                                file=sys.stderr,
                            )
                        except ScannerError as exc:
                            print(f"agent-environment-scanner: {exc}", file=sys.stderr)
                            delivery_failed = True
    except ScannerError as exc:
        print(f"agent-environment-scanner: {exc}", file=sys.stderr)
        return 2
    return 0 if feature_file_written and not delivery_failed and not bundle_failed else 2


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    interval = configured_scan_interval(args)
    # DR-109 M2: a target manifest turns each collection from one scan into
    # the sandbox-wide scan plus one agent-scoped scan per resolved key.
    # `configured_target_manifest`'s absence preserves the exact legacy
    # single-target call below, for every existing caller that never names one.
    run_collection = run_one_collection if configured_target_manifest(args) else run_one_scan
    if interval is None:
        return run_collection(args)

    # DR-83: stays running, scanning again on the interval. An agent that
    # first appears after scan N reaches the control plane on scan N+1
    # without the scanner being re-run by hand; one that changes or
    # disappears between scans is reflected the same way, because every
    # iteration re-delivers (to rail-center and/or RailDash) rather than only
    # diffing locally. An unchanged evidence bundle is re-sent as the same
    # bytes (`evidence_bundle.reuse_unchanged_bundle`), so RailDash keeps one
    # ASP for it instead of one per tick (DR-157). The last exit code is what the process exits with, so
    # a deployment supervisor (systemd, a container restart policy) still
    # sees a failing scan as a failure rather than this loop swallowing it.
    exit_code = 0
    try:
        while True:
            exit_code = run_collection(args)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
