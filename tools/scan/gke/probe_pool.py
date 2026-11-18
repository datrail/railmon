"""The probe pool and the scan deadline (RC-512, with the former RC-517).

Pod mode's probe stage: after the harness reader has settled the agent's MCP
servers, every MCP probe and every API spec probe (gke/spec_probe.py) runs in
one ProbePool, four at a time, and the whole scan gets SCAN_DEADLINE_SECONDS
from its start. A probe still out at the deadline is BLIND for its server
alone, and the rest of the bundle is built and sent as usual.

Self and docker scans still probe their MCP servers one after another, with
no deadline, so this lives with the rest of the sidecar. Like the other
modules in tools/scan/gke/, it imports nothing of railmon's: the scanner
hands itself over with `register`, and the MCP probe itself (and its memory
bounds) stays in the scanner, which every mode shares.
"""

from __future__ import annotations

import concurrent.futures
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

_s: Any = None  # the scanner module (scan_agent_environment), set by register
_spec: Any = None  # gke/spec_probe.py, as the scanner loads it


def register(scanner: Any) -> None:
    """Hand over the scanner, whose MCP probe and spec prober this uses."""
    global _s, _spec
    _s = scanner
    _spec = scanner._spec_probe()

# Pod mode runs the scan's MCP and spec probes PROBE_POOL_WORKERS at a time,
# each call bounded on its own (MCP_PROBE_TIMEOUT_SECONDS an MCP call,
# OPENAPI_PATH_TIMEOUT_SECONDS a spec path), and gives the whole scan
# SCAN_DEADLINE_SECONDS from its start. A probe that hasn't answered by then
# is reported BLIND for its server or destination, and the rest of the bundle
# is built and sent as usual. Self and docker scans still probe one after
# another, with no deadline.
PROBE_POOL_WORKERS = 4
SCAN_DEADLINE_SECONDS = 60.0


class ProbePool:
    """At most `workers` probes at a time, on daemon threads, each submitted
    once by key, and each result waited for only until `deadline` (a
    time.monotonic() value, or None for no deadline).

    The threads are daemons and nothing joins them: a probe still running at
    the deadline is left to end on its own per-call timeout, so neither the
    scan nor the process's exit waits for it. Probes not yet started when the
    pool closes are cancelled."""

    def __init__(self, workers: int = PROBE_POOL_WORKERS, deadline: float | None = None) -> None:
        self.deadline = deadline
        self._queue: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._futures: dict[Any, concurrent.futures.Future[Any]] = {}
        self._lock = threading.Lock()
        self._workers = [threading.Thread(target=self._work, name=f"railmon-probe-{index}", daemon=True)
                         for index in range(max(1, workers))]
        for worker in self._workers:
            worker.start()

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            future, function, args = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(function(*args))
            except BaseException as exc:  # a probe "never raises"; if one does, it is that probe's failure alone
                future.set_exception(exc)

    def submit(self, key: Any, function: Callable[..., Any], *args: Any) -> concurrent.futures.Future[Any]:
        with self._lock:
            future = self._futures.get(key)
            if future is None:
                future = self._futures[key] = concurrent.futures.Future()
                self._queue.put((future, function, args))
            return future

    def wait(self, key: Any, on_deadline: Any, on_error: Any = None) -> Any:
        """The probe's result; `on_deadline` if it isn't in by the deadline
        (or was never submitted); `on_error` (else `on_deadline`) if it
        raised."""
        future = self._futures.get(key)
        if future is None:
            return on_deadline
        remaining = None if self.deadline is None else max(0.0, self.deadline - time.monotonic())
        try:
            return future.result(timeout=remaining)
        except (concurrent.futures.TimeoutError, concurrent.futures.CancelledError):
            return on_deadline
        except Exception:
            return on_error if on_error is not None else on_deadline

    def unanswered(self) -> int:
        return sum(1 for future in self._futures.values() if not future.done())

    def close(self) -> None:
        for future in self._futures.values():
            future.cancel()  # only one not yet started; a running probe ends on its own timeout
        for _ in self._workers:
            self._queue.put(None)

    def __enter__(self) -> "ProbePool":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def deadline_spec_entry(destination: str) -> dict[str, Any]:
    return {"destination": _s.redact_text(destination), "status": "BLIND", "reason": "NO_SOURCE_ACCESS",
            "deadline_exceeded": True,
            "note": f"no answer within the scan's {SCAN_DEADLINE_SECONDS:g}-second deadline"}


def run_pod_probes(
    mcp_configs: list[Path],
    env: dict[str, str],
    declared: dict[str, Any] | None,
    schemas: list[dict[str, Any]],
    deadline: float | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Pod mode's probe stage, after the harness reader has settled the MCP
    servers (`declared`): every planned MCP server (without the agent's
    headers) and every HTTP destination's spec paths, in one ProbePool with
    the scan's deadline. Returns the MCP skills, as collect_skills does
    (`schemas` gets tool_schemas' entries), http_operations' destinations,
    and how many MCP servers were planned: with no destination, that tells
    "servers, none with an origin to ask" (command servers, or URLs carrying
    a credential) from "no server found"."""
    plan = _s.mcp_probe_plan(mcp_configs, env, declared)
    destinations = _spec.spec_destinations(plan)
    mounts = _spec.spec_mount_paths(plan)
    mcp_deadline = (None, "unreachable", False, True)
    # Every server's tools are kept until the bundle is built, so their JSON
    # elements share one budget for the scan.
    scan_budget = _s.JsonElementBudget(_s.MCP_SCAN_MAX_ELEMENTS)

    def ask(url: str) -> tuple[Any, ...]:
        return _s.probe_mcp_server(url, None, scan_budget=scan_budget)

    with ProbePool(PROBE_POOL_WORKERS, deadline) as pool:
        for _, spec, *_ in plan:
            request = _s.mcp_probe_request(spec, send_headers=False)
            if request is not None:
                pool.submit(("mcp", request[0]), ask, request[0])
        for origin in destinations:
            pool.submit(("spec", origin), _spec.probe_openapi, origin, _spec.OPENAPI_PATH_TIMEOUT_SECONDS,
                        tuple(mounts.get(origin, ())))

        def probe(url: str, headers: dict[str, str] | None) -> tuple[Any, ...]:
            pool.submit(("mcp", url), ask, url)  # already submitted above; never a header
            return pool.wait(("mcp", url), mcp_deadline, (None, "unreachable", False))

        skills = _s.collect_skills(mcp_configs, env, send_headers=False, schemas=schemas, declared=declared,
                                probe=probe)
        operations = [
            pool.wait(("spec", origin), deadline_spec_entry(origin),
                      {"destination": _s.redact_text(origin), "status": "BLIND", "reason": "NO_SOURCE_ACCESS",
                       "note": "the spec probe failed"})
            for origin in destinations
        ]
        late = pool.unanswered()
    if late:
        print(f"agent-environment-scanner: pod mode: {late} probe(s) had not answered by the scan's "
              f"{SCAN_DEADLINE_SECONDS:g}-second deadline; their servers are reported BLIND", file=sys.stderr)
    for entry in operations:
        print(f"agent-environment-scanner: pod mode: API spec at {entry['destination']}: {entry['status']}"
              + (f" ({entry['reason']})" if entry.get("reason") else "")
              + (f", {len(entry['operations'])} operations" if "operations" in entry else ""), file=sys.stderr)
    return skills, _spec.cap_http_operations(operations), len(plan)
