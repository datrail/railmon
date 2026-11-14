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

    def list_dir(self, path: str) -> list[str] | None:
        located = self._locate(path)
        if located is None:
            return None
        return _agent_process().list_in_root(*located)


def profiles() -> list[dict[str, Any]]:
    """The harness profiles shipped with the scanner (gke/harness/profiles)."""
    return reader().load_profiles()


def agent_view(subject: dict[str, Any]) -> Any:
    return reader().Agent(cmdline=subject.get("cmdline") or "", env=subject.get("env") or {})


def read_agent_harness(context: dict[str, Any], config_paths: list[Path],
                       known_profiles: list[dict[str, Any]] | None = None,
                       redact_url: Any = None) -> tuple[str | None, dict[str, Any]]:
    """The matched profile's name (None if none) and the harness fields for
    the agent in `context`, read through PodSources. `redact_url` is the
    scanner's, which also masks a secret in a URL's path (a gateway's
    /mcp/<key>/sse), so a URL a profile reads is redacted as the bundle's own
    are."""
    subject = context.get("subject")
    if not subject:
        return None, {}
    harness_reader = reader()
    agent = agent_view(subject)
    profile = harness_reader.harness_reader_for(profiles() if known_profiles is None else known_profiles, agent)
    results = harness_reader.read_harness_fields(profile, agent, PodSources(subject.get("root"), config_paths),
                                                 redact_url=redact_url)
    return (profile or {}).get("harness"), results
