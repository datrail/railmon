#!/usr/bin/env python3
"""Agent registration environment scanner.

Builds a registration payload compatible with rail-center's
POST /v1/agents/register schema.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


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
DEFAULT_REGISTRATION_OUTPUT = Path(".datrail") / "rail-guardian" / "registration.json"
DEFAULT_FEATURE_OUTPUT = Path(".rail") / "railscan" / "features.json"
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
                "name": str(name),
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


def collect_mcp_inventory(mcp_configs: list[Path]) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in mcp_configs:
        if not path.exists():
            continue
        for entry in read_mcp_inventory(path):
            if entry["name"] in seen:
                continue
            seen.add(entry["name"])
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
        if not isinstance(spec, dict):
            continue
        endpoints = []
        for value in collect_strings(spec):
            if value.startswith(("http://", "https://")):
                # Redacted for the same reason the MCP inventory is: a hosted
                # endpoint carries its key in the URL, and unlike the feature
                # file these skills are also POSTed to the control plane.
                endpoints.append(redact_url(value) or "[unparseable]")
        command = spec.get("command")
        reached = command_basename(command) or redact_url(spec.get("url"))
        skills.append(
            {
                "name": str(name),
                "description": f"MCP server configured via {path.name}: {reached or 'unknown'}",
                "destination_endpoints": dedupe(endpoints),
                "source_type": "mcp_config",
            }
        )
    return skills


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


def collect_skills(mcp_configs: list[Path]) -> list[dict[str, Any]]:
    skills: list[dict[str, Any]] = []
    for path in mcp_configs:
        if path.exists():
            skills.extend(read_mcp_config(path))
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for skill in skills:
        key = skill["name"]
        if key in seen:
            continue
        seen.add(key)
        result.append(skill)
    return result


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
        [Path(path).expanduser() for path in args.mcp_config] or default_mcp_paths(context["env"])
    )
    if args.observed_file:
        identity["observed_reach"] = summarize_observed(
            load_snapshot(Path(args.observed_file).expanduser()),
            declared_hosts(identity, context["env"]),
        )
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
    mcp_skills = collect_skills(mcp_paths)
    scanned_skills = collect_skills_from_files(skill_files)
    payload = {
        "type": args.agent_type,
        "owner": owner,
        # Asserted, never verified, and optional on rail-center's side: a
        # registration that omits them still succeeds against an identity derived
        # from the container hostname.
        "host_id": identity["host_id"],
        "sandbox_name": identity["sandbox_name"],
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


def auth_headers(mode: str | None = None) -> dict[str, str]:
    """The credential this component presents, chosen by RAIL_AUTH_MODE.

    Mirrors rail-center's RAIL_AUTH_MODES_ACCEPTED: `none` sends nothing and is
    accepted only while the control plane still lists `none`; `bearer` sends the
    token from RAIL_AUTH_TOKEN. `gcp` belongs to DR-10's shared token client, so
    it fails loudly here rather than silently degrading to an anonymous call
    that the operator believes is authenticated.
    """
    resolved = (first_nonempty(mode, os.environ.get("RAIL_AUTH_MODE")) or "none").lower()
    if resolved not in AUTH_MODES:
        raise ScannerError(f"RAIL_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {resolved}")
    if resolved == "none":
        return {}
    if resolved == "bearer":
        token = first_nonempty(os.environ.get("RAIL_AUTH_TOKEN"))
        if not token:
            raise ScannerError("RAIL_AUTH_MODE=bearer requires RAIL_AUTH_TOKEN")
        return {"Authorization": f"Bearer {token}"}
    raise ScannerError("RAIL_AUTH_MODE=gcp is not implemented here; it lands with DR-10's token client")


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
            **auth_headers(auth_mode),
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
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


def registration_output_path(args: argparse.Namespace) -> Path:
    configured = first_nonempty(
        args.registration_output,
        os.environ.get("RAIL_REGISTRATION_OUTPUT"),
    )
    return Path(configured).expanduser() if configured else DEFAULT_REGISTRATION_OUTPUT


def feature_output_path(args: argparse.Namespace) -> Path:
    configured = first_nonempty(args.feature_output, os.environ.get("RAIL_FEATURE_OUTPUT"))
    return Path(configured).expanduser() if configured else DEFAULT_FEATURE_OUTPUT


def build_registration_state(center_url: str, payload: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """What we keep from a registration: the agent id, and nothing that is a ticket.

    The response carries a `token`, and RailScan drops it on the floor. It is a
    placeholder minted with a null posture — posture is scored asynchronously
    after the response returns — so anything that stored or forwarded it would
    pin the fleet to a posture that was never computed. The proxy fetches its own
    ticket; RailScan is the registrar, and a registrar holds no credentials.
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
        "arguments or command lines are read from it.",
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
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    return parser


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


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    feature_file_written = True
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
        finally:
            # The feature file is the primary artifact and needs no control plane,
            # so it is written even when registration fails — but only after the
            # attempt, so registration_status reports what happened rather than
            # what was asked for. A scorer reading "registered" off an agent that
            # never reached the control plane would be reading a lie.
            if not args.no_feature_file:
                feature_file_written = write_feature_file(args, context, payload, identity)
    except ScannerError as exc:
        print(f"agent-environment-scanner: {exc}", file=sys.stderr)
        return 2
    return 0 if feature_file_written else 2


if __name__ == "__main__":
    raise SystemExit(main())
