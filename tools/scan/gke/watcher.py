"""Pod mode's watcher (RC-523): rescan when the agent's config changes, wait
for an agent that is still starting, shut down cleanly, and report health.

`railmon scan --mode pod --interval N` (or RAIL_SCAN_INTERVAL_IN_SECONDS)
runs this loop in place of the plain interval loop:

* **What it watches.** The sources the agent's harness profile names: its
  config `sources`, its workspace `prompt_files` and `skills`, and the
  profile's own `watch.content`, hashed by content; and `watch.list`
  (transcripts), hashed by file list only, since a transcript grows on every
  turn. Every harness also has `.mcp.json` in each `--config-path` and each
  `--mcp-config`, and an agent no profile matches has what the generic
  reader reads: `.mcp.json`, `AGENTS.md` and the top-level `*.json` under
  `--config-path`. The agent's process (command line, environment and
  working directory) is hashed too, so a restart with a new environment is a
  change. Paths are found as the scan finds them (harness_sources.PodSources),
  and logged as the profile writes them, never with an environment value.
* **When it scans.** Everything is hashed every 10 seconds (POLL_SECONDS),
  within one read budget for the whole poll (POLL_MAX_BYTES,
  POLL_MAX_ENTRIES), config first and the agent's skill folders last; the
  `watch.list` file lists, which read no bytes, have their own allowance
  (LIST_MAX_ENTRIES), so a full budget can't hide a new transcript. After
  a change it scans once nothing has changed for 5 seconds (SETTLE_SECONDS),
  so a config written in several steps is scanned once, but no later than
  MAX_DEFER_SECONDS after the change was first seen, so files that never
  stop changing can't put a scan off for good; the same content rewritten
  changes no hash. `--interval` still rescans, whether or not a change is
  pending. Scans run one at a time: what changes during a scan is seen on
  the next poll and gives one more scan, however much changed.
* **Waiting at start.** A profile's `watch.wait_for` names what must exist
  before the first scan (OpenClaw: openclaw.json and agents/main/), for up to
  `watch.wait_seconds`; then it scans anyway, and what is missing is reported
  BLIND. A profile with no `wait_for` (Claude Code), or an agent no profile
  matches, is scanned as soon as its process is found. With no agent process
  at all it waits up to NO_PROCESS_WAIT_SECONDS, then scans.
* **Shutdown.** SIGTERM abandons a scan in progress (nothing is written or
  sent for it) and gives a bundle being written or sent SHUTDOWN_GRACE_SECONDS
  to finish. The scanner marks that stretch with `delivering()`.
* **Health.** After each scan and delivery the time and interval are written
  to the health file (RAIL_HEALTH_FILE, default /tmp/railmon-health.json);
  `railmon scan --health-check`, the exec liveness probe, fails when the last
  scan is older than two intervals.

Like the other gke modules, it imports nothing of railmon's.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent

POLL_SECONDS = 10.0
SETTLE_SECONDS = 5.0
SHUTDOWN_GRACE_SECONDS = 5.0
# How long to wait for the agent's process when none is found at start: the
# longest wait a shipped profile asks for (OpenClaw's).
NO_PROCESS_WAIT_SECONDS = 300.0
# A change waits for SETTLE_SECONDS of quiet, but is scanned at most this long
# after it was first seen, however often the files keep changing.
MAX_DEFER_SECONDS = 60.0
# What one whole poll reads, at most, across every watched path: POLL_MAX_BYTES
# of file content and POLL_MAX_ENTRIES files and folders, TREE_MAX_DEPTH deep.
# The agent can write to watched folders (its skills), and links in them are
# followed inside its root, so the budget is the poll's, never a path's: a
# folder of links to one large file costs what one file does. What doesn't
# fit is hashed as OVER_BUDGET and left to the interval scan.
POLL_MAX_BYTES = 64 * 1024 * 1024
POLL_MAX_ENTRIES = 5000
# The `watch.list` file lists (transcripts) read names, never content, so they
# have their own allowance of files and folders: a skill folder or state
# database that spends the poll's budget can't hide a new agent or session,
# and a large transcript folder can't crowd out the config.
LIST_MAX_ENTRIES = 5000
TREE_MAX_DEPTH = 8
OVER_BUDGET = "over the poll's read budget"
BUDGET_KEY = "the poll's read budget"
# How many changed paths a change line names.
LOG_MAX_NAMES = 5

HEALTH_FILE_ENV = "RAIL_HEALTH_FILE"
DEFAULT_HEALTH_FILE = Path("/tmp/railmon-health.json")
LOG_PREFIX = "[agent-environment-scanner] watcher:"
AGENT_PROCESS = "the agent's process"


def log(message: str) -> None:
    """One line per event, on stderr."""
    print(f"{LOG_PREFIX} {message}", file=sys.stderr, flush=True)


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


def harness_sources() -> Any:
    """harness/harness_sources.py, under the name pod_mode loads it by."""
    return _load("gke_harness_sources", HERE / "harness" / "harness_sources.py")


def agent_process() -> Any:
    return _load("gke_agent_process", HERE / "agent_process.py")


# --- what to watch ---------------------------------------------------------

@dataclass
class WatchPlan:
    """What one poll hashes, for the agent as it is now. `harness` is the
    matched profile's name, "generic" for an agent no profile matches, or
    None when there is no agent process. Each path is (shown, read at):
    shown as the profile writes it, read where the agent's environment puts
    it."""

    harness: str | None
    sources: Any
    content: list[tuple[str, str]] = field(default_factory=list)
    listed: list[tuple[str, str]] = field(default_factory=list)
    wait_for: list[tuple[str, str]] = field(default_factory=list)
    wait_seconds: float = 0.0
    agent_digest: str | None = None

    def exists(self, path: str) -> bool:
        return self.sources.list_dir(path) is not None or self.sources.read_bytes(path, 1) is not None

    def missing(self) -> list[str]:
        """What `wait_for` names that isn't there yet; with no agent process,
        the process itself."""
        if self.harness is None:
            return [AGENT_PROCESS]
        return [shown for shown, path in self.wait_for if not self.exists(path)]


def _config_folders(config_paths: list[Path]) -> list[Path]:
    """Each --config-path's folder: one naming a file stands for the folder
    it's in, as harness_sources.PodSources takes it."""
    folders: list[Path] = []
    for path in config_paths:
        folder = path if path.suffix != ".json" else path.parent
        if folder not in folders:
            folders.append(folder)
    return folders


def _glob(sources: Any, shown: str, path: str) -> list[tuple[str, str]]:
    """A path whose last part is a pattern, as the matching names in its
    folder (as the reader reads a drop-in source); any other path as is."""
    folder, _, pattern = path.rpartition("/")
    shown_folder = shown.rpartition("/")[0]
    if not any(c in pattern for c in "*?["):
        return [(shown, path)]
    names = sources.list_dir(folder or "/") or []
    return [(f"{shown_folder}/{name}", f"{folder}/{name}")
            for name in sorted(names) if fnmatch.fnmatchcase(name, pattern) and name not in (".", "..")]


def _expand(agent: Any, sources: Any, templates: list[str]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for template in templates:
        expanded = agent.expand(template)
        if expanded:
            found.extend(_glob(sources, template, expanded))
    return found


def _unique(paths: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """First of each path read at, so a file two templates name is hashed once."""
    seen: set[str] = set()
    kept = []
    for shown, path in paths:
        if path not in seen:
            seen.add(path)
            kept.append((shown, path))
    return kept


def watch_spec(profile: dict[str, Any]) -> dict[str, Any]:
    """A profile's `watch` object, checked: `content` and `list` are lists of
    path templates, `wait_for` a list of templates or lists of alternatives
    (the first whose variables are set is used), `wait_seconds` a number of
    seconds. ValueError says what is wrong."""
    spec = profile.get("watch", {})
    name = profile.get("harness", "?")
    if not isinstance(spec, dict):
        raise ValueError(f"{name}: watch is an object")
    for key in ("content", "list"):
        if not all(isinstance(t, str) for t in spec.get(key, [])) or not isinstance(spec.get(key, []), list):
            raise ValueError(f"{name}: watch.{key} is a list of path templates")
    wait_for = spec.get("wait_for", [])
    if not isinstance(wait_for, list) or not all(
            isinstance(item, str) or (isinstance(item, list) and item and all(isinstance(t, str) for t in item))
            for item in wait_for):
        raise ValueError(f"{name}: watch.wait_for is a list of path templates or lists of alternatives")
    seconds = spec.get("wait_seconds", 0)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds < 0:
        raise ValueError(f"{name}: watch.wait_seconds is a number of seconds")
    if wait_for and not seconds:
        raise ValueError(f"{name}: watch.wait_for needs watch.wait_seconds")
    return spec


def agent_digest(subject: dict[str, Any]) -> str:
    """The agent's command line, environment and working directory, hashed:
    a restart with a new environment is a change. Never logged."""
    material = json.dumps([subject.get("cmdline") or "", sorted((subject.get("env") or {}).items()),
                           subject.get("cwd")], sort_keys=True)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def watch_plan(subject: dict[str, Any] | None, config_paths: list[Path], profiles: list[dict[str, Any]],
               mcp_configs: list[Path] = ()) -> WatchPlan:
    """What to hash for the agent `subject` (from its process; None when
    there is none) and the harness profile its markers match."""
    hs = harness_sources()
    sources = hs.PodSources(subject.get("root") if subject else None, config_paths)
    folders = _config_folders(config_paths)
    # What the scan reads whatever the harness: .mcp.json in each config
    # folder (its default --mcp-config in pod mode) and each --mcp-config.
    content = [(f"{folder}/.mcp.json", f"{folder}/.mcp.json") for folder in folders]
    content += [(str(path), str(path)) for path in mcp_configs]
    content += [(str(path), str(path)) for path in config_paths if path.suffix == ".json"]
    plan = WatchPlan(harness=None, sources=sources)
    profile = None
    if subject is not None:
        reader = hs.reader()
        agent = hs.agent_view(subject)
        profile = reader.harness_reader_for(profiles, agent)
        plan.harness = profile["harness"] if profile else reader.GENERIC_HARNESS
        plan.agent_digest = agent_digest(subject)
    if profile is not None:
        agent = hs.reader().with_derived(profile, hs.agent_view(subject))
        spec = watch_spec(profile)
        workspace = profile.get("workspace", {})
        # Config first and the agent's own skill folders last, so a folder
        # it stuffs can spend only what the poll's budget has left.
        content += _expand(agent, sources, [source["path"] for source in profile.get("sources", [])])
        content += _expand(agent, sources, list(workspace.get("prompt_files", [])))
        content += _expand(agent, sources, list(spec.get("content", [])))
        content += _expand(agent, sources, list(workspace.get("skills", [])))
        plan.listed = _unique(_expand(agent, sources, list(spec.get("list", []))))
        for item in spec.get("wait_for", []):
            for template in [item] if isinstance(item, str) else item:
                expanded = agent.expand(template)
                if expanded:
                    plan.wait_for.append((template, expanded))
                    break
        plan.wait_seconds = float(spec.get("wait_seconds", 0)) if plan.wait_for else 0.0
    else:
        # What the generic reader (harness/generic.py) reads under each
        # config folder; also all there is to watch with no agent process.
        for folder in folders:
            content.append((f"{folder}/AGENTS.md", f"{folder}/AGENTS.md"))
            content += _glob(sources, f"{folder}/*.json", f"{folder}/*.json")
    listed = {path for _, path in plan.listed}
    plan.content = [entry for entry in _unique(content) if entry[1] not in listed]
    return plan


class PollBudget:
    """What one poll may still read, shared by every watched path."""

    def __init__(self, max_bytes: int = POLL_MAX_BYTES, max_entries: int = POLL_MAX_ENTRIES):
        self.bytes, self.entries, self.exhausted = max_bytes, max_entries, False

    def entry(self) -> bool:
        """Spend one file or folder; False when none is left."""
        if self.entries <= 0:
            self.exhausted = True
            return False
        self.entries -= 1
        return True

    def file_digest(self, sources: Any, path: str) -> str:
        """A file's content hash, if it fits in what is left; OVER_BUDGET when
        it doesn't (never a hash of part of it, which would change with what
        earlier files spent)."""
        if self.exhausted or self.bytes <= 0:
            self.exhausted = True
            return OVER_BUDGET
        found = sources.digest(path, self.bytes + 1)
        if found is None:
            return "unreadable"
        digest, size = found
        if size > self.bytes:
            self.bytes, self.exhausted = 0, True
            return OVER_BUDGET
        self.bytes -= size
        return digest


def _walk(sources: Any, path: str, depth: int, budget: PollBudget,
          visit: Callable[[str, str | None], None]) -> None:
    """Visit `path` and, if it is a folder, what is under it, folders before
    their contents, in name order. A folder's entry is visited with "/"; what
    the budget can't cover, with OVER_BUDGET."""
    if not budget.entry():
        visit(path, OVER_BUDGET)
        return
    names = sources.list_dir(path)
    if names is None:
        visit(path, None)
        return
    visit(path, "/")
    if depth >= TREE_MAX_DEPTH:
        return
    for name in names:
        if name in (".", ".."):
            continue
        if budget.exhausted:
            visit(path, OVER_BUDGET)
            return
        _walk(sources, f"{path.rstrip('/')}/{name}", depth + 1, budget, visit)


def digest_content(sources: Any, path: str, budget: PollBudget | None = None) -> str:
    """A file's content hash, or a folder's over every file in it; "missing"
    when there is nothing to read."""
    budget = budget or PollBudget()
    if sources.list_dir(path) is None and sources.read_bytes(path, 0) is None:
        return "missing"
    digest = hashlib.sha256()

    def visit(item: str, kind: str | None) -> None:
        digest.update(item.encode("utf-8", errors="replace") + b"\0")
        digest.update((budget.file_digest(sources, item) if kind is None else kind).encode() + b"\0")

    _walk(sources, path, 0, budget, visit)
    return digest.hexdigest()


def digest_listing(sources: Any, path: str, budget: PollBudget | None = None) -> str:
    """A folder's file list, hashed by names only: no file is read, so a
    transcript that grows changes nothing and a new one does."""
    budget = budget or PollBudget()
    if sources.list_dir(path) is None:
        return "missing"
    digest = hashlib.sha256()
    _walk(sources, path, 0, budget,
          lambda item, kind: digest.update(item.encode("utf-8", errors="replace") + (kind or "").encode() + b"\0"))
    return digest.hexdigest()


def fingerprint(plan: WatchPlan, budget: PollBudget | None = None,
                list_budget: PollBudget | None = None) -> dict[str, str]:
    """Every watched path's hash, keyed by its shown name: content within one
    PollBudget for the whole poll, file lists within their own (no bytes,
    LIST_MAX_ENTRIES entries). When either ran out, BUDGET_KEY says so."""
    budget = budget or PollBudget()
    list_budget = list_budget or PollBudget(max_bytes=0, max_entries=LIST_MAX_ENTRIES)
    hashes: dict[str, str] = {}
    if plan.agent_digest:
        hashes[AGENT_PROCESS] = plan.agent_digest
    for shown, path in plan.content:
        hashes[shown] = digest_content(plan.sources, path, budget)
    for shown, path in plan.listed:
        hashes[f"{shown} (file list)"] = digest_listing(plan.sources, path, list_budget)
    if budget.exhausted or list_budget.exhausted:
        hashes[BUDGET_KEY] = "exhausted"
    return hashes


def changed(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:LOG_MAX_NAMES])
    return shown + (f" and {len(names) - LOG_MAX_NAMES} more" if len(names) > LOG_MAX_NAMES else "")


# --- the loop --------------------------------------------------------------

class Watcher:
    """The scan loop. `scan` runs one scan and delivery and returns its exit
    code; `plan` says what to watch now. The clock and sleep are injected,
    so the loop can be tested with a fake clock. It runs until an exception
    (Shutdown, KeyboardInterrupt) ends it."""

    def __init__(self, scan: Callable[[], int], plan: Callable[[], WatchPlan], *, interval: float,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 on_scanned: Callable[[], None] | None = None, poll: float = POLL_SECONDS,
                 settle: float = SETTLE_SECONDS, max_defer: float = MAX_DEFER_SECONDS,
                 no_process_wait: float = NO_PROCESS_WAIT_SECONDS,
                 before_first_scan: Callable[[], Any] | None = None):
        self.scan, self.plan, self.interval = scan, plan, interval
        self.before_first_scan = before_first_scan
        self.clock, self.sleep, self.on_scanned = clock, sleep, on_scanned
        self.poll, self.settle, self.max_defer = poll, settle, max_defer
        self.no_process_wait = no_process_wait
        self.exit_code = 0

    def wait_for_agent(self) -> WatchPlan:
        """The plan to scan first with: once what it waits for exists, or
        once its wait is over."""
        start = self.clock()
        announced: list[str] | None = None
        while True:
            plan = self.plan()
            missing = plan.missing()
            limit = self.no_process_wait if plan.harness is None else plan.wait_seconds
            if not missing:
                if announced:
                    log(f"{_names(announced)} found after {self.clock() - start:.0f}s; scanning")
                return plan
            waited = self.clock() - start
            if waited >= limit:
                if limit:
                    log(f"waited {waited:.0f}s; scanning without {_names(missing)}, reported BLIND")
                return plan
            if missing != announced:
                harness = f"{plan.harness}: " if plan.harness else ""
                log(f"{harness}waiting up to {limit:.0f}s for {_names(missing)}")
                announced = missing
            self.sleep(min(self.poll, limit - waited))

    def _scan(self, why: str) -> None:
        log(f"scan: {why}")
        started = self.clock()
        self.exit_code = self.scan()
        log(f"scan done in {self.clock() - started:.0f}s, exit {self.exit_code}")
        if self.on_scanned is not None:
            self.on_scanned()

    def run(self) -> None:
        plan = self.wait_for_agent()
        if self.before_first_scan is not None:
            self.before_first_scan()
            plan = self.plan()
        if plan.harness is not None:
            log(f"harness {plan.harness}; watching {len(plan.content)} paths by content "
                f"and {len(plan.listed)} by file list")
        seen = fingerprint(plan)
        if BUDGET_KEY in seen:
            log(f"a poll needs more than {POLL_MAX_BYTES >> 20} MiB or {POLL_MAX_ENTRIES} files; "
                "what doesn't fit is left to the interval scan")
        self._scan("first scan")
        next_interval = self.clock() + self.interval
        # The last change seen, and the first since the last scan: a change
        # waits for SETTLE_SECONDS of quiet, but never more than
        # MAX_DEFER_SECONDS in all, so files that never stop changing (a
        # busy agent, or one rewriting a watched file on purpose) can't put
        # a scan off for good, and changes cause at most about one scan a
        # minute.
        changed_at: float | None = None
        pending_since: float | None = None
        while True:
            now = self.clock()
            if changed_at is not None and pending_since is not None:
                wake = min(changed_at + self.settle, pending_since + self.max_defer)
            else:
                wake = now + self.poll
            self.sleep(max(0.0, min(wake, next_interval) - now))
            plan = self.plan()
            current = fingerprint(plan)
            now = self.clock()
            if (BUDGET_KEY in current) != (BUDGET_KEY in seen):
                log(f"a poll needs more than {POLL_MAX_BYTES >> 20} MiB or {POLL_MAX_ENTRIES} files; "
                    "what doesn't fit is left to the interval scan" if BUDGET_KEY in current
                    else "a poll fits its read budget again")
            if current != seen:
                if pending_since is None:
                    log(f"change in {_names(changed(seen, current))}")
                    pending_since = now
                seen, changed_at = current, now
            why = None
            if changed_at is not None and pending_since is not None:
                if now - changed_at >= self.settle:
                    why = f"nothing changed for {self.settle:.0f}s"
                elif now - pending_since >= self.max_defer:
                    why = f"still changing after {self.max_defer:.0f}s; scanning anyway"
            if why is None and now >= next_interval:
                why = "interval"
            if why is not None:
                # `seen` is this scan's baseline: what changes while it runs
                # is a change on the next poll, which queues one more scan.
                changed_at = pending_since = None
                self._scan(why)
                next_interval = self.clock() + self.interval


# --- shutdown --------------------------------------------------------------

class Shutdown(BaseException):
    """SIGTERM ended the watcher. A BaseException, so no `except Exception`
    in a scan holds it up."""


_STATE = {"delivering": False, "stopping": False}
# What ends the process when a delivery outlasts its grace; a test replaces it.
hard_exit: Callable[[int], None] = os._exit


def delivering(active: bool) -> None:
    """The scanner calls this when it starts writing or sending a bundle
    (True) and when it is done (False). While it is True, SIGTERM lets it
    finish for up to SHUTDOWN_GRACE_SECONDS; a SIGTERM that came meanwhile
    ends the watcher as soon as it is done."""
    _STATE["delivering"] = active
    if not active and _STATE["stopping"]:
        signal.setitimer(signal.ITIMER_REAL, 0)
        log("SIGTERM: the bundle in flight was delivered; exiting")
        raise Shutdown("delivered")


def _on_sigterm(signum: int, frame: Any) -> None:
    if _STATE["stopping"]:
        return
    _STATE["stopping"] = True
    if _STATE["delivering"]:
        log(f"SIGTERM: letting the bundle in flight finish, up to {SHUTDOWN_GRACE_SECONDS:.0f}s")
        signal.signal(signal.SIGALRM, _on_grace_over)
        signal.setitimer(signal.ITIMER_REAL, SHUTDOWN_GRACE_SECONDS)
        return
    log("SIGTERM: abandoning the scan in progress, if any; nothing is written or sent for it")
    raise Shutdown("SIGTERM")


def _on_grace_over(signum: int, frame: Any) -> None:
    log(f"SIGTERM: the bundle in flight didn't finish in {SHUTDOWN_GRACE_SECONDS:.0f}s; exiting")
    hard_exit(0)


def install_signal_handlers() -> Callable[[], None]:
    """SIGTERM's handler, and a function that restores what was there."""
    _STATE.update(delivering=False, stopping=False)
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGALRM)}
    signal.signal(signal.SIGTERM, _on_sigterm)

    def restore() -> None:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        _STATE.update(delivering=False, stopping=False)
    return restore


# --- health ----------------------------------------------------------------

def health_path() -> Path:
    return Path(os.environ.get(HEALTH_FILE_ENV) or DEFAULT_HEALTH_FILE)


def write_health(path: Path, interval: float, now: float | None = None,
                 starting_until: float | None = None) -> None:
    """The time of the last scan and the interval, for the liveness probe.
    At start, before any scan, `starting_until` is when the first scan is
    due at the latest: until then the sidecar is starting, not stuck. A
    failed write is logged, never raised: the scan already happened."""
    fields: dict[str, float] = {"last_scan": time.time() if now is None else now, "interval": interval}
    if starting_until is not None:
        fields["starting_until"] = starting_until
    record = json.dumps(fields)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(record + "\n", encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        log(f"health file {path} not written: {exc.strerror or exc}")


def check_health(path: Path, now: float | None = None) -> tuple[bool, str]:
    """Whether the last scan is at most two intervals old, or the sidecar is
    still starting within its startup allowance, and one line saying so."""
    now = time.time() if now is None else now
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        last, interval = float(record["last_scan"]), float(record["interval"])
        starting_until = float(record["starting_until"]) if "starting_until" in record else None
    except (OSError, ValueError, KeyError, TypeError):
        return False, f"unhealthy: no readable health file at {path}"
    if starting_until is not None:
        if now <= starting_until:
            return True, f"healthy: starting, the first scan due within {starting_until - now:.0f}s"
        return False, f"unhealthy: still no first scan {now - last:.0f}s after start"
    age, limit = now - last, 2 * interval
    if age > limit:
        return False, f"unhealthy: the last scan was {age:.0f}s ago, more than two intervals ({limit:.0f}s)"
    return True, f"healthy: the last scan was {age:.0f}s ago"


def health_check_main() -> int:
    ok, line = check_health(health_path())
    print(line, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


# --- entry -----------------------------------------------------------------

def subject_finder(config_paths: list[Path]) -> Callable[[], dict[str, Any] | None]:
    """The agent's process as the plan needs it (root, command line,
    environment, working directory), found again on every poll so a
    restarted agent is followed."""
    processes = agent_process()

    def find() -> dict[str, Any] | None:
        agent, _ = processes.find_agent_process(config_paths)
        if agent is None:
            return None
        root = agent["root"]
        return {"root": str(root), "cmdline": agent["cmdline"], "env": agent["env"],
                "cwd": processes._working_dir(root.parent)}
    return find


def startup_allowance(profiles: list[dict[str, Any]], interval: float, before_first_scan_seconds: float) -> float:
    """How long after start the first scan has landed at the latest: the
    longest wait for the agent (any shipped profile's, or for its process),
    then `before_first_scan_seconds`, then two intervals, as for any scan.
    The liveness probe passes until then."""
    longest = max([NO_PROCESS_WAIT_SECONDS] + [float(watch_spec(p).get("wait_seconds", 0)) for p in profiles])
    return longest + before_first_scan_seconds + 2 * interval


def run(args: Any, run_once: Callable[[Any], int], interval: float,
        before_first_scan: Callable[[], Any] | None = None, before_first_scan_seconds: float = 0.0) -> int:
    """The watcher for a pod-mode scanner with an interval. Returns the last
    scan's exit code when SIGTERM or Ctrl-C ends it. `before_first_scan`
    (the scanner's wait for RailDash, DR-316, which takes up to
    `before_first_scan_seconds`) runs once the agent is ready, with SIGTERM
    handled; the startup health record allows for it and for the wait for the
    agent (startup_allowance), so a slow start neither blocks shutdown nor
    fails the liveness probe."""
    config_paths = [Path(path).expanduser() for path in args.config_path]
    if not config_paths:
        return run_once(args)  # which says pod mode needs --config-path
    profiles = harness_sources().profiles()
    mcp_configs = [Path(path).expanduser() for path in args.mcp_config]
    find = subject_finder(config_paths)
    health = health_path()

    def scan() -> int:
        _STATE["delivering"] = False
        return run_once(args)

    watcher = Watcher(scan, lambda: watch_plan(find(), config_paths, profiles, mcp_configs),
                      interval=interval, on_scanned=lambda: write_health(health, interval),
                      before_first_scan=before_first_scan)
    restore = install_signal_handlers()
    started = time.time()
    write_health(health, interval, now=started,
                 starting_until=started + startup_allowance(profiles, interval, before_first_scan_seconds))
    try:
        watcher.run()
    except Shutdown:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        restore()
    return watcher.exit_code
