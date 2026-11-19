"""Pod mode's side of the shared harness reader (RC-510).

The reader (reader.py, beside this file) knows nothing of pods: it asks a
`Sources` object for the agent's files by the paths the agent sees. This
module is that object for a sidecar, and the agent the reader matches profiles
against:

* A path under a --config-path is read from the config volume, which the
  webhook mounts in the sidecar at the same path as in the agent. It is read
  with the volume as the root, so a link the agent planted there can't leave
  the volume or reach the sidecar's own files.
* Any other path is read through the agent's own root (/proc/<pid>/root),
  with agent_process.read_in_root's guards: links resolve in the agent's
  root, no step crosses into another filesystem, only regular files are
  opened, without blocking.
* The agent's command line and environment, for the profile markers and for
  `~` and `$VAR` in a profile's paths, come from the agent's process (RC-509).
  Environment values are used to find files only; none reaches the bundle.

Like the other gke modules, it imports nothing of railmon's: the reader and
agent_process are loaded by path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> Any:
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def reader() -> Any:
    """reader.py beside this file, the shared harness reader."""
    return _load("harness_reader", HERE / "reader.py")


def _agent_process() -> Any:
    return _load("gke_agent_process", HERE.parent / "agent_process.py")


class PodSources:
    """The agent's files as the sidecar can safely reach them."""

    def __init__(self, agent_root: str | None, config_paths: list[Path]):
        self.agent_root = Path(agent_root) if agent_root else None
        # A --config-path naming a file stands for the folder it's in.
        self.volumes = sorted({str(p if p.suffix != ".json" else p.parent).rstrip("/") or "/" for p in config_paths},
                              key=len, reverse=True)

    def _locate(self, path: str) -> tuple[Path, str] | None:
        """(root to read under, path inside it), or None when out of reach."""
        if not path.startswith("/"):
            return None
        for volume in self.volumes:
            if path == volume or path.startswith(volume + "/"):
                return Path(volume), "/" + path[len(volume):].lstrip("/")
        if self.agent_root is not None:
            return self.agent_root, path
        return None

    def read_text(self, path: str, max_bytes: int) -> str | None:
        located = self._locate(path)
        if located is None:
            return None
        return _agent_process().read_in_root(located[0], located[1], max_bytes)

    def read_bytes(self, path: str, max_bytes: int) -> bytes | None:
        located = self._locate(path)
        if located is None:
            return None
        return _agent_process().read_bytes_in_root(located[0], located[1], max_bytes)

    def list_dir(self, path: str) -> list[str] | None:
        located = self._locate(path)
        if located is None:
            return None
        return _agent_process().list_in_root(*located)

    def digest(self, path: str, max_bytes: int) -> tuple[str, int] | None:
        """The SHA-256 of a regular file's first `max_bytes` and how many
        bytes that was, read a chunk at a time with the same guards (the
        watcher, RC-523)."""
        located = self._locate(path)
        if located is None:
            return None
        return _agent_process().digest_in_root(located[0], located[1], max_bytes)


# What the MCP probe uses from a declared server's spec (RC-531): its
# address or command. Everything else (headers, env, OAuth settings) is
# dropped before the probe sees it.
PROBE_SPEC_KEYS = ("url", "command", "args", "type", "transport")


def read_declared_mcp_servers(context: dict[str, Any], config_paths: list[Path],
                              known_profiles: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    """The MCP servers the matched profile settles for mcp_servers_declared
    (RC-531), for the MCP probe: None when no profile matches, else the
    field's result (`status`, `value` as {name: spec}, `reason`, `note`, and
    `exclusive` when the harness loads these servers and no others) and the
    profile's `harness`.

    Only that one field is read, so a scan doesn't copy the transcript
    databases twice, and its value is not redacted: the reader's redaction
    is for the bundle, and it hides a server's whole config when the
    server's name looks like a credential's (secrets-manager, github-token),
    so its URL would reach the probe as `[redacted]`. Each spec keeps only
    PROBE_SPEC_KEYS instead, so headers and env never reach the probe, and
    the probe judges the URL itself (url_carries_credential), as it does a
    .mcp.json server's. This value never reaches the bundle: the bundle's
    mcp_servers_declared is read_agent_harness's, redacted."""
    subject = context.get("subject")
    if not subject:
        return None
    harness_reader = reader()
    agent = agent_view(subject)
    profile = harness_reader.harness_reader_for(profiles() if known_profiles is None else known_profiles, agent)
    spec = (profile or {}).get("fields", {}).get("mcp_servers_declared")
    if spec is None:
        return None
    # read_harness_fields' own steps for one config field, without its
    # redaction of the value.
    ctx = harness_reader.Context(profile, harness_reader.with_derived(profile, agent),
                                 PodSources(subject.get("root"), config_paths), harness_reader.loads_json, False)
    ctx.config_sources = harness_reader._read_sources(ctx)
    result = harness_reader._config_field(ctx, "mcp_servers_declared", spec, ctx.config_sources)
    value = result.get("value")
    if isinstance(value, dict):
        result = {**result, "value": {
            str(name): {key: server[key] for key in PROBE_SPEC_KEYS if key in server}
            for name, server in value.items() if isinstance(server, dict)
        }}
    return {**result, "harness": profile["harness"]}


def profiles() -> list[dict[str, Any]]:
    """The harness profiles shipped with the scanner (gke/sidecar/harness/profiles)."""
    return reader().load_profiles()


def agent_view(subject: dict[str, Any]) -> Any:
    return reader().Agent(cmdline=subject.get("cmdline") or "", env=subject.get("env") or {},
                          cwd=subject.get("cwd"))


def read_agent_harness(context: dict[str, Any], config_paths: list[Path],
                       known_profiles: list[dict[str, Any]] | None = None,
                       redact_url: Any = None) -> tuple[str | None, dict[str, Any]]:
    """The matched profile's name and the harness fields for the agent in
    `context`, read through PodSources. When no profile matches, the generic
    reader (generic.py, RC-520) reads them and the name is
    reader.GENERIC_HARNESS; with no agent process, (None, {}). `redact_url`
    is the scanner's, which also masks a secret in a URL's path (a gateway's
    /mcp/<key>/sse), so a URL a profile reads is redacted as the bundle's own
    are."""
    subject = context.get("subject")
    if not subject:
        return None, {}
    harness_reader = reader()
    agent = agent_view(subject)
    profile = harness_reader.harness_reader_for(profiles() if known_profiles is None else known_profiles, agent)
    results = harness_reader.read_harness_fields(profile, agent, PodSources(subject.get("root"), config_paths),
                                                 redact_url=redact_url, config_paths=[str(p) for p in config_paths])
    return (profile or {}).get("harness", harness_reader.GENERIC_HARNESS), results
