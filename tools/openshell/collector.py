#!/usr/bin/env python3
"""`railmon openshell`: read what an OpenShell sandbox's gateway knows and
post it to RailDash (DR-249, the OpenShell design's M3).

Opt-in. RailDash takes a sandbox's policy as a file the user imports by
default (DR-248); this collector is for a user who accepts holding the
OpenShell CLI's credential, a Platform Admin one on a local gateway, in
exchange for freshness and the supervisor's denials. Each interval it:

- runs `openshell policy get <sandbox> --full -o json`, the effective policy
  the supervisor has loaded, and posts it to RailDash when its revision or
  hash changed, and at least every `POLICY_REPOST_SECONDS` so RailDash can
  tell a current policy from a stopped collector, with only the fields
  RailDash reads (no credential field). One call answers what the design's
  `policy list` then `policy get` would: the loaded revision and its policy;
- runs `openshell logs <sandbox> --source sandbox -n 2000 --since <window>`
  and posts the `DENIED` `NET:OPEN` and `HTTP:<method>` lines it hasn't
  posted yet. The CLI has no resume cursor and the gateway keeps 2,000 lines
  a sandbox, so a batch says it is PARTIAL when it can't show it holds every
  denial since the last one: the first poll, a poll that no longer reaches
  the last line seen, a full buffer, or a failed poll.

It runs only the CLI subcommands in `ALLOWED_COMMANDS`, enforced in
`run_openshell`. It holds no Docker socket and listens on nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

# The only CLI calls this process makes (design §5): reads, never a write.
ALLOWED_COMMANDS = (("policy", "get"), ("logs",))
SANDBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
OPENSHELL_PREFIX = "openshell:"
# The gateway keeps this many log lines a sandbox (OpenShell 0.1.3); a poll
# that returns as many may have lost older ones.
LOG_BUFFER_LINES = 2000
# Each logs window reaches back this far before the last line seen, so a
# line stamped just before it is read again (and deduped) rather than missed.
OVERLAP_SECONDS = 30
# The first poll's window: what the log still holds of the last hour.
FIRST_WINDOW_SECONDS = 3600
DEFAULT_INTERVAL = 60
CLI_TIMEOUT = 30.0
POST_TIMEOUT = 15.0
# RailDash takes at most 2,000 denials and 2 MiB a post; a post is cut at
# whichever of these comes first.
MAX_DENIALS_PER_POST = 1000
MAX_POST_BYTES = 1024 * 1024
# Denials RailDash hasn't taken yet (it was down), kept to post again; past
# this many the oldest go and the span is marked PARTIAL.
MAX_PENDING_DENIALS = 10_000
# An unchanged policy is posted again this often: under RailDash's two-hour
# stale window, so a running collector's policy never reads as stale.
POLICY_REPOST_SECONDS = 1800

# `[1792867645.652] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED <rest>`
LOG_LINE = re.compile(
    r"^\[(?P<ts>\d+(?:\.\d+)?)\] \[(?P<source>[^\]]*)\] \[(?P<level>[^\]]*)\] \[(?P<target>[^\]]*)\] (?P<message>.*)$"
)
DENIED = re.compile(r"^(?P<event>NET:OPEN|HTTP:[A-Z]+) \[[A-Z]+\] DENIED (?P<rest>.*)$")
# NET:OPEN: `/usr/local/bin/python3.13(0) -> example.org:443 [reason:...]`
NET_OPEN = re.compile(r"^(?P<binary>\S+?)(?:\((?P<pid>\d+)\))? -> (?P<host>\S+?)(?::(?P<port>\d+))?(?P<tail>(?: \[.*)?)$")
# HTTP: `POST http://api.github.com:443/markdown [policy:github_api engine:l7] [reason:...]`
HTTP_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<url>\S+)(?P<tail>(?: \[.*)?)$")
BRACKET = re.compile(r"\[(?P<key>[a-z_]+):(?P<value>[^\]]*)\]")

# What RailDash reads of a policy (raildash `openshell_policy.py`): the
# fields kept here, everything else is dropped before the post, so a
# credential a policy carries (a middleware's config, signing settings, a
# rule's query values) never leaves this process.
ENDPOINT_FIELDS = ("host", "port", "ports", "path", "protocol", "tls", "enforcement", "access", "allowed_ips")
RULE_FIELDS = ("method", "path", "command", "operation_type", "tool")
WRAPPER_FIELDS = ("active_version", "current_policy_version", "version", "hash", "policy_source", "scope", "sandbox")


class CollectorError(Exception):
    """A setting or call that failed; the message says which. `refused` is
    True when RailDash answered that the post itself is wrong (a 4xx other
    than auth or rate limiting), so sending it again can't help."""

    def __init__(self, message: str, refused: bool = False) -> None:
        super().__init__(message)
        self.refused = refused


# --------------------------------------------------------------- the CLI


def run_openshell(cli: str, args: list[str], timeout: float = CLI_TIMEOUT) -> str:
    """Run one allowed `openshell` subcommand and return its stdout.
    Anything not in `ALLOWED_COMMANDS` is refused before a process starts."""
    if not any(tuple(args[: len(allowed)]) == allowed for allowed in ALLOWED_COMMANDS):
        raise CollectorError(f"openshell {' '.join(args[:2])}: not a command this collector runs")
    try:
        done = subprocess.run(
            [cli, *args], capture_output=True, text=True, timeout=timeout, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"openshell {args[0]}: {exc}") from exc
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()
        raise CollectorError(f"openshell {' '.join(args[:2])} exited {done.returncode}: {detail[0] if detail else ''}")
    return done.stdout


# ---------------------------------------------------------------- policy


def strip_policy(view: dict[str, Any]) -> dict[str, Any]:
    """`policy get --full -o json` with only what RailDash reads."""
    policy = view.get("policy")
    if not isinstance(policy, dict):
        raise CollectorError("openshell policy get printed no policy")
    network = policy.get("network_policies") or {}
    if not isinstance(network, dict):
        raise CollectorError("openshell policy get printed network_policies that aren't a mapping")
    rules = {}
    for key, rule in network.items():
        if not isinstance(rule, dict):
            continue
        endpoints = []
        for endpoint in rule.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            kept = {field: endpoint[field] for field in ENDPOINT_FIELDS if field in endpoint}
            kept["rules"] = [
                {"allow": {field: rule_["allow"][field] for field in RULE_FIELDS if field in rule_["allow"]}}
                for rule_ in endpoint.get("rules") or []
                if isinstance(rule_, dict) and isinstance(rule_.get("allow"), dict)
            ]
            # Only how many: a deny rule's matchers aren't shown.
            kept["deny_rules"] = [{} for _ in endpoint.get("deny_rules") or []]
            endpoints.append(kept)
        binaries = [
            {"path": binary["path"] if isinstance(binary, dict) else binary}
            for binary in rule.get("binaries") or []
            if (isinstance(binary, dict) and isinstance(binary.get("path"), str)) or isinstance(binary, str)
        ]
        rules[key] = {"name": rule.get("name") or key, "endpoints": endpoints, "binaries": binaries}
    out = {field: view[field] for field in WRAPPER_FIELDS if field in view}
    out["policy"] = {"version": policy.get("version", 1), "network_policies": rules}
    return out


def policy_revision(view: dict[str, Any]) -> tuple[Any, Any]:
    """What says the loaded policy changed: its version and its hash."""
    return (view.get("active_version", view.get("current_policy_version")), view.get("hash"))


# --------------------------------------------------------------- denials


def line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:32]


def _brackets(tail: str) -> dict[str, str]:
    """`[policy:github_api engine:l7] [reason:...]` -> {"policy": ..., "reason": ...}"""
    found = {}
    for match in BRACKET.finditer(tail):
        key, value = match["key"], match["value"]
        if key == "policy":
            value = value.split(" ", 1)[0]
        found.setdefault(key, value)
    return found


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_log(text: str) -> tuple[list[float], list[dict[str, Any]]]:
    """Every timestamped line's time, and the denials among them, as
    RailDash takes them (raildash `parse_denials`)."""
    stamps: list[float] = []
    denials: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = LOG_LINE.match(line)
        if match is None:
            continue
        ts = float(match["ts"])
        stamps.append(ts)
        denied = DENIED.match(match["message"])
        if denied is None:
            continue
        denial: dict[str, Any] = {"at": _iso(ts), "hash": line_hash(line), "host": None, "port": None,
                                  "method": None, "path": None, "binary": None, "policy": None, "reason": None}
        if denied["event"] == "NET:OPEN":
            net = NET_OPEN.match(denied["rest"])
            if net is None:
                continue
            port = int(net["port"]) if net["port"] else None
            denial.update(kind="net", host=net["host"], binary=net["binary"],
                          port=port if port is not None and 0 < port < 65536 else None,
                          **_brackets(net["tail"]))
        else:
            http = HTTP_REQUEST.match(denied["rest"])
            if http is None:
                continue
            url = urlsplit(http["url"])
            try:
                port = url.port
            except ValueError:
                port = None
            denial.update(kind="http", method=http["method"], host=url.hostname, port=port,
                          path=url.path or "/", **_brackets(http["tail"]))
        denial = {key: denial[key] for key in
                  ("at", "hash", "kind", "host", "port", "method", "path", "binary", "policy", "reason")}
        for key, limit in (("host", 253), ("method", 32), ("path", 2048), ("binary", 4096),
                           ("policy", 253), ("reason", 1024)):
            if isinstance(denial[key], str) and len(denial[key]) > limit:
                denial[key] = denial[key][:limit]
        denials.append(denial)
    return stamps, denials


class DenialCursor:
    """Where the last poll got to: the newest line's time and the hashes of
    the lines in the overlap, so a line read twice is posted once."""

    def __init__(self) -> None:
        self.started: float | None = None
        self.last_seen: float | None = None
        self.recent: dict[str, float] = {}

    def window(self, now: float) -> int:
        """`--since` in whole seconds: back to the last line seen (or this
        collector's first poll, while the log has held none), plus the
        overlap; the first poll reads the last hour."""
        anchor = self.last_seen if self.last_seen is not None else self.started
        if anchor is None:
            return FIRST_WINDOW_SECONDS
        return max(1, math.ceil(now - anchor + OVERLAP_SECONDS))

    def batch(self, text: str | None, now: float) -> dict[str, Any]:
        """The post for one poll's output (None: the poll failed)."""
        anchor = self.last_seen if self.last_seen is not None else self.started
        gap_from = None if anchor is None else _iso(anchor)
        if text is None:
            return {"denials": [], "partial": {"from": gap_from, "to": _iso(now), "reasons": ["poll_failed"]}}
        stamps, denials = parse_log(text)
        oldest = min(stamps) if stamps else None
        reasons = []
        if self.started is None:
            # Whatever the log held before the hour read is unknown.
            reasons.append("first_poll")
        elif self.last_seen is not None and (oldest is None or oldest > self.last_seen):
            # The window reaches back past the last line seen, so a log that
            # still held it would have returned it.
            reasons.append("gap")
        if len(stamps) >= LOG_BUFFER_LINES and (self.last_seen is None or oldest > self.last_seen):
            # The newest 2,000 lines start after where this poll had to
            # begin: older ones in the window were cut.
            reasons.append("full_buffer")
        self.started = now if self.started is None else self.started
        fresh = [d for d in denials if d["hash"] not in self.recent]
        if stamps:
            self.last_seen = max(stamps) if self.last_seen is None else max(self.last_seen, max(stamps))
        for denial in fresh:
            self.recent[denial["hash"]] = datetime.fromisoformat(denial["at"].replace("Z", "+00:00")).timestamp()
        floor = (self.last_seen or now) - 2 * OVERLAP_SECONDS
        self.recent = {h: ts for h, ts in self.recent.items() if ts >= floor}
        partial = None
        if reasons:
            partial = {"from": gap_from, "to": _iso(oldest if oldest is not None else now), "reasons": reasons}
        return {"denials": fresh, "partial": partial}


def merge_partial(first: dict[str, Any] | None, second: dict[str, Any] | None) -> dict[str, Any] | None:
    """One span covering both (a batch held back, then the next one)."""
    if first is None or second is None:
        return first or second
    return {
        "from": None if first["from"] is None or second["from"] is None else min(first["from"], second["from"]),
        "to": max(first["to"], second["to"]),
        "reasons": sorted(set(first["reasons"]) | set(second["reasons"])),
    }


# ------------------------------------------------------------------ post


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to follow: the token would go wherever a 3xx points."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D102
        return None


_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def raildash_token() -> str:
    """`RAIL_RAILDASH_TOKEN`, or the file `RAIL_RAILDASH_TOKEN_FILE` names,
    read again on every post (RailDash may rotate it on a restart)."""
    value, path = os.environ.get("RAIL_RAILDASH_TOKEN"), os.environ.get("RAIL_RAILDASH_TOKEN_FILE")
    if value and path:
        raise CollectorError("set RAIL_RAILDASH_TOKEN or RAIL_RAILDASH_TOKEN_FILE, not both")
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as exc:
            raise CollectorError(f"RAIL_RAILDASH_TOKEN_FILE: {exc.strerror}") from exc
    if not value:
        raise CollectorError("no RailDash token: set RAIL_RAILDASH_TOKEN or RAIL_RAILDASH_TOKEN_FILE")
    return value


def encode(body: dict[str, Any]) -> bytes:
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chunks(denials: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Posts of at most MAX_DENIALS_PER_POST denials and MAX_POST_BYTES."""
    out: list[list[dict[str, Any]]] = [[]]
    size = 0
    for denial in denials:
        length = len(encode(denial)) + 1
        if out[-1] and (len(out[-1]) >= MAX_DENIALS_PER_POST or size + length > MAX_POST_BYTES):
            out.append([])
            size = 0
        out[-1].append(denial)
        size += length
    return out


def post(raildash_url: str, sandbox: str, what: str, body: dict[str, Any]) -> dict[str, Any]:
    parts = urlsplit(raildash_url)
    path = f"{parts.path.rstrip('/')}/v1/openshell/sandboxes/{quote(sandbox, safe='')}/{what}"
    request = Request(
        urlunsplit((parts.scheme, parts.netloc, path, "", "")),
        data=encode(body),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "X-RailDash-Token": raildash_token()},
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=POST_TIMEOUT) as response:
            return json.loads(response.read() or b"null")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        refused = 400 <= exc.code < 500 and exc.code not in (401, 403, 408, 429)
        raise CollectorError(f"RailDash refused the {what} post: HTTP {exc.code}: {detail}", refused) from exc
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        raise CollectorError(f"RailDash {what} post failed: {exc}") from exc


# ------------------------------------------------------------------ loop


class Collector:
    def __init__(self, sandbox: str, raildash_url: str, cli: str = "openshell",
                 log: Callable[[str], None] = lambda message: print(message, file=sys.stderr, flush=True),
                 clock: Callable[[], float] = time.time) -> None:
        self.sandbox, self.raildash_url, self.cli, self.log, self.clock = sandbox, raildash_url, cli, log, clock
        self.revision: tuple[Any, Any] | None = None
        self.posted_at: float | None = None
        self.cursor = DenialCursor()
        # What RailDash hasn't taken yet: posted again with the next batch.
        self.pending: dict[str, Any] = {"denials": [], "partial": None}
        self._last_problem: dict[str, str | None] = {}

    def _say(self, what: str, problem: str | None) -> None:
        """Log a problem when it starts or changes, and once when it clears."""
        if problem != self._last_problem.get(what):
            self.log(f"railmon openshell: {what}: {problem}" if problem else f"railmon openshell: {what}: ok again")
            self._last_problem[what] = problem

    def poll_policy(self) -> None:
        try:
            view = json.loads(run_openshell(self.cli, ["policy", "get", self.sandbox, "--full", "-o", "json"]))
            if not isinstance(view, dict):
                raise CollectorError("openshell policy get printed no JSON object")
            revision = policy_revision(view)
            now = self.clock()
            if (revision != self.revision or self.posted_at is None
                    or now - self.posted_at >= POLICY_REPOST_SECONDS):
                post(self.raildash_url, self.sandbox, "policy", strip_policy(view))
                if revision != self.revision:
                    self.log(f"railmon openshell: posted {self.sandbox}'s policy revision {revision[0]}")
                self.revision, self.posted_at = revision, now
            self._say("policy", None)
        except (CollectorError, ValueError) as exc:
            self._say("policy", str(exc))

    def poll_denials(self) -> None:
        now = self.clock()
        args = ["logs", self.sandbox, "--source", "sandbox", "-n", str(LOG_BUFFER_LINES),
                "--since", f"{self.cursor.window(now)}s"]
        try:
            text: str | None = run_openshell(self.cli, args)
            self._say("logs", None)
        except CollectorError as exc:
            text = None
            self._say("logs", str(exc))
        batch = self.cursor.batch(text, now)
        # Anything RailDash didn't take last time goes first.
        denials = self.pending["denials"] + batch["denials"]
        partial = merge_partial(self.pending["partial"], batch["partial"])
        if len(denials) > MAX_PENDING_DENIALS:
            dropped = denials[: len(denials) - MAX_PENDING_DENIALS]
            denials = denials[len(dropped):]
            partial = merge_partial(partial, {"from": dropped[0]["at"], "to": denials[0]["at"], "reasons": ["gap"]})
        self.pending = {"denials": [], "partial": None}
        if not denials and partial is None:
            return
        posted = 0
        for chunk in chunks(denials):
            try:
                post(self.raildash_url, self.sandbox, "denials", {"denials": chunk, "partial": partial})
            except CollectorError as exc:
                if exc.refused:
                    # RailDash says this post is wrong: sending it again
                    # would block every later one. Its span is marked.
                    self.log(f"railmon openshell: RailDash refused {len(chunk)} denials, dropped: {exc}")
                    if chunk:
                        partial = merge_partial(partial, {"from": chunk[0]["at"], "to": chunk[-1]["at"],
                                                          "reasons": ["gap"]})
                    posted += len(chunk)
                    continue
                # Kept, not dropped: the cursor has moved past these lines,
                # so the next poll won't read them again.
                self.pending = {"denials": denials[posted:], "partial": partial}
                self._say("denials post", str(exc))
                return
            posted += len(chunk)
            partial = None
        if partial is not None:
            # The last chunk was refused: its span still has to arrive.
            self.pending = {"denials": [], "partial": partial}
        self._say("denials post", None)

    def once(self) -> None:
        self.poll_policy()
        self.poll_denials()


def sandbox_from(value: str | None) -> str:
    """`--sandbox`, `RAIL_OPENSHELL_SANDBOX`, or the sandbox named by
    `AGENT_CONTAINER=openshell:<sandbox>` (DR-247)."""
    if not value:
        value = os.environ.get("RAIL_OPENSHELL_SANDBOX")
    if not value:
        ref = os.environ.get("AGENT_CONTAINER", "")
        value = ref[len(OPENSHELL_PREFIX):] if ref.startswith(OPENSHELL_PREFIX) else None
    if not value or not SANDBOX_NAME.match(value):
        raise CollectorError("name the sandbox: --sandbox, RAIL_OPENSHELL_SANDBOX or AGENT_CONTAINER=openshell:<name>")
    return value


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="railmon openshell",
        description="Post an OpenShell sandbox's policy and the denials its supervisor logged to RailDash.",
    )
    parser.add_argument("--sandbox", help="the sandbox's name (or RAIL_OPENSHELL_SANDBOX, or AGENT_CONTAINER=openshell:<name>)")
    parser.add_argument("--raildash-url", default=os.environ.get("RAIL_RAILDASH_URL") or None,
                        help="RailDash's base URL (or RAIL_RAILDASH_URL)")
    parser.add_argument("--interval", type=float, default=None,
                        help=f"seconds between polls (or RAIL_OPENSHELL_INTERVAL; default {DEFAULT_INTERVAL})")
    parser.add_argument("--openshell", default=os.environ.get("OPENSHELL_CLI") or "openshell",
                        help="the OpenShell CLI to run (or OPENSHELL_CLI)")
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.interval is None:
            raw = os.environ.get("RAIL_OPENSHELL_INTERVAL") or str(DEFAULT_INTERVAL)
            try:
                args.interval = float(raw)
            except ValueError:
                raise CollectorError(f"RAIL_OPENSHELL_INTERVAL is not a number: {raw!r}") from None
        sandbox = sandbox_from(args.sandbox)
        if not args.raildash_url:
            raise CollectorError("name RailDash: --raildash-url or RAIL_RAILDASH_URL")
        if not 5 <= args.interval <= 3600:
            raise CollectorError("--interval must be between 5 and 3600 seconds")
        raildash_token()
    except CollectorError as exc:
        print(f"railmon openshell: {exc}", file=sys.stderr)
        return 64
    collector = Collector(sandbox, args.raildash_url, args.openshell)
    collector.log(f"railmon openshell: following sandbox {sandbox} every {args.interval:g}s")
    while True:
        collector.once()
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
