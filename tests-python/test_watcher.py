"""RC-523: pod mode's watcher rescans when the agent's config changes, waits
for an agent still starting, shuts down cleanly and reports its health.

The loop tests run gke/watcher.py's Watcher against a temporary folder that
stands for the agent's root, with a fake clock: the clock only moves when the
watcher sleeps (or a fake scan takes time), and files change at set times.
The SIGTERM tests send the process a real SIGTERM.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "tools" / "scan"
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))  # the scanner's lazy `import evidence_bundle`


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scanner = sys.modules.get("scan_agent_environment") or _load("scan_agent_environment",
                                                              SCANNER_DIR / "scan_agent_environment.py")
sys.modules.setdefault("scan_agent_environment", scanner)
watcher = scanner._gke("watcher")
harness_sources = watcher.harness_sources()
PROFILES = harness_sources.profiles()

OPENCLAW_CMD = "openclaw-gateway"  # how OpenClaw 2026.9.2's gateway names its process
CLAUDE_CMD = "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"
OPENCLAW_JSON = {"agents": {"defaults": {"model": {"primary": "external/gemini-flash-latest"}}}}


class Stop(Exception):
    """Ends a fake-clock run."""


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.events: list[tuple[float, int, object]] = []

    def at(self, when: float, action) -> None:
        self.events.append((when, len(self.events), action))
        self.events.sort(key=lambda event: event[:2])

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        target = self.now + max(0.0, seconds)
        while self.events and self.events[0][0] <= target:
            when, _, action = self.events.pop(0)
            self.now = max(self.now, when)
            action()
        self.now = target


class Agent:
    """A temporary folder standing for the agent's root, and its process."""

    def __init__(self, cmdline: str, env: dict[str, str], cwd: str = "/") -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.volume = self.root / "volume"   # the --config-path volume, empty unless a test fills it
        self.volume.mkdir()
        self.subject: dict | None = {"root": str(self.root), "cmdline": cmdline, "env": env, "cwd": cwd}

    def path(self, inside: str) -> Path:
        return self.root / inside.lstrip("/")

    def write(self, inside: str, text: str) -> None:
        path = self.path(inside)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def append(self, inside: str, text: str) -> None:
        with self.path(inside).open("a", encoding="utf-8") as handle:
            handle.write(text)

    def plan(self):
        return watcher.watch_plan(self.subject, [self.volume], PROFILES)

    def close(self) -> None:
        self.dir.cleanup()


def openclaw_agent(with_agents_main: bool = True) -> Agent:
    agent = Agent(OPENCLAW_CMD, {"HOME": "/root"})
    agent.write("/root/.openclaw/openclaw.json", json.dumps(OPENCLAW_JSON))
    if with_agents_main:
        agent.path("/root/.openclaw/agents/main/agent").mkdir(parents=True)
    return agent


class LoopRun:
    """One Watcher run on a fake clock, recording when it scanned."""

    def __init__(self, agent: Agent, interval: float = 3600.0, scan_seconds: float = 0.0, stop_at: float = 1000.0):
        self.clock = FakeClock()
        self.scans: list[float] = []
        self.scan_seconds = scan_seconds
        self.during_scan: dict[int, list] = {}
        self.clock.at(stop_at, self._stop)
        self.watcher = watcher.Watcher(self._scan, agent.plan, interval=interval, clock=self.clock.time,
                                       sleep=self.clock.sleep)

    @staticmethod
    def _stop() -> None:
        raise Stop

    def _scan(self) -> int:
        self.scans.append(self.clock.now)
        for action in self.during_scan.get(len(self.scans), []):
            action()
        self.clock.sleep(self.scan_seconds)
        return 0

    def run(self) -> str:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaisesStop():
            self.watcher.run()
        return stderr.getvalue()

    @contextlib.contextmanager
    def assertRaisesStop(self):
        try:
            yield
        except Stop:
            return
        raise AssertionError("the watcher stopped before the test's end")


class WatcherLoopTest(unittest.TestCase):
    def agent(self, factory=openclaw_agent, **kwargs) -> Agent:
        agent = factory(**kwargs)
        self.addCleanup(agent.close)
        return agent

    def test_the_same_content_rewritten_triggers_nothing(self):
        agent = self.agent()
        run = LoopRun(agent, stop_at=200)
        for when in (12, 33, 71):
            run.clock.at(when, lambda: agent.write("/root/.openclaw/openclaw.json", json.dumps(OPENCLAW_JSON)))
        run.run()
        self.assertEqual(run.scans, [0])

    def test_a_burst_of_writes_triggers_one_scan(self):
        agent = self.agent()
        run = LoopRun(agent, stop_at=200)
        for when, model in ((5, "a"), (12, "b"), (17, "c")):
            config = {"agents": {"defaults": {"model": {"primary": f"external/{model}"}}}}
            run.clock.at(when, lambda config=config: agent.write("/root/.openclaw/openclaw.json", json.dumps(config)))
        log = run.run()
        # Seen at the 10-second poll, still changing at 15 and 20, quiet at 25.
        self.assertEqual(run.scans, [0, 25])
        self.assertIn("change in $OPENCLAW_DIR/openclaw.json", log)

    def test_a_change_during_a_scan_queues_exactly_one_more(self):
        agent = self.agent()
        run = LoopRun(agent, scan_seconds=30, stop_at=400)
        # The second scan (after a skill is added) takes 30 seconds, and
        # the config changes three times while it runs.
        run.clock.at(3, lambda: agent.write("/root/.openclaw/skills/new/SKILL.md", "---\nname: new\n---\n"))
        for offset, model in ((5, "a"), (11, "b"), (20, "c")):
            config = {"agents": {"defaults": {"model": {"primary": f"external/{model}"}}}}
            run.during_scan.setdefault(2, []).append(
                lambda offset=offset, config=config: run.clock.at(
                    run.clock.now + offset,
                    lambda: agent.write("/root/.openclaw/openclaw.json", json.dumps(config))))
        run.run()
        self.assertEqual(len(run.scans), 3, run.scans)
        self.assertGreaterEqual(run.scans[2], run.scans[1] + 30)

    def test_the_interval_still_rescans_when_nothing_changes(self):
        agent = self.agent()
        run = LoopRun(agent, interval=60, stop_at=200)
        run.run()
        self.assertEqual(run.scans, [0, 60, 120, 180])

    def test_openclaw_waits_for_agents_main(self):
        agent = self.agent(with_agents_main=False)
        run = LoopRun(agent, stop_at=200)
        run.clock.at(80, lambda: agent.path("/root/.openclaw/agents/main").mkdir(parents=True))
        log = run.run()
        self.assertEqual(run.scans, [80])
        self.assertIn("openclaw: waiting up to 300s for $OPENCLAW_DIR/agents/main", log)

    def test_openclaw_waits_for_openclaw_json_too(self):
        agent = Agent(OPENCLAW_CMD, {"HOME": "/root"})
        self.addCleanup(agent.close)
        run = LoopRun(agent, stop_at=200)
        run.clock.at(40, lambda: agent.write("/root/.openclaw/openclaw.json", json.dumps(OPENCLAW_JSON)))
        run.clock.at(90, lambda: agent.path("/root/.openclaw/agents/main").mkdir(parents=True))
        run.run()
        self.assertEqual(run.scans, [90])

    def test_openclaw_config_path_moves_what_it_waits_for(self):
        agent = Agent(OPENCLAW_CMD, {"HOME": "/root", "OPENCLAW_CONFIG_PATH": "/etc/openclaw/config.json"})
        self.addCleanup(agent.close)
        agent.path("/root/.openclaw/agents/main").mkdir(parents=True)
        run = LoopRun(agent, stop_at=200)
        run.clock.at(30, lambda: agent.write("/etc/openclaw/config.json", json.dumps(OPENCLAW_JSON)))
        run.run()
        self.assertEqual(run.scans, [30])

    def test_the_300_second_cap_scans_with_the_missing_parts_blind(self):
        agent = self.agent(with_agents_main=False)
        run = LoopRun(agent, stop_at=400)
        log = run.run()
        self.assertEqual(run.scans, [300])
        self.assertIn("waited 300s; scanning without $OPENCLAW_DIR/agents/main, reported BLIND", log)
        # What that scan reads: the config, and no transcripts.
        harness, fields = harness_sources.read_agent_harness({"subject": agent.subject}, [agent.volume])
        self.assertEqual(harness, "openclaw")
        self.assertEqual(fields["model_name"]["status"], "ANSWERED")
        self.assertEqual((fields["tool_names"]["status"], fields["tool_names"]["reason"]),
                         ("BLIND", "NO_SOURCE_ACCESS"))

    def test_a_harness_without_a_profile_scans_at_once(self):
        agent = Agent("hermes serve", {"HOME": "/home/agent"})
        self.addCleanup(agent.close)
        (agent.volume / ".mcp.json").write_text("{}", encoding="utf-8")
        run = LoopRun(agent, stop_at=100)
        run.clock.at(23, lambda: (agent.volume / ".mcp.json").write_text(
            '{"mcpServers": {"x": {"url": "http://x:1/mcp"}}}', encoding="utf-8"))
        run.run()
        self.assertEqual(run.scans, [0, 35])

    def test_claude_code_scans_at_once_and_a_new_transcript_rescans(self):
        agent = Agent(CLAUDE_CMD, {"HOME": "/home/agent"}, cwd="/work")
        self.addCleanup(agent.close)
        agent.write("/home/agent/.claude/settings.json", '{"model": "sonnet"}')
        agent.write("/home/agent/.claude/projects/-work/one.jsonl", '{"type": "user"}\n')
        run = LoopRun(agent, stop_at=100)
        # The open session grows: no scan. A new session: one.
        run.clock.at(12, lambda: agent.append("/home/agent/.claude/projects/-work/one.jsonl", '{"type": "x"}\n'))
        run.clock.at(42, lambda: agent.write("/home/agent/.claude/projects/-work/two.jsonl", '{"type": "user"}\n'))
        log = run.run()
        self.assertEqual(run.scans, [0, 55])
        self.assertIn("$CLAUDE_DIR/projects (file list)", log)

    def test_a_claude_code_settings_change_rescans(self):
        agent = Agent(CLAUDE_CMD, {"HOME": "/home/agent"}, cwd="/work")
        self.addCleanup(agent.close)
        run = LoopRun(agent, stop_at=100)
        run.clock.at(31, lambda: agent.write("/work/.claude/settings.json", '{"permissions": {"deny": ["Bash"]}}'))
        run.run()
        self.assertEqual(run.scans, [0, 45])

    def test_with_no_agent_process_it_waits_for_one(self):
        agent = self.agent(Agent, cmdline=CLAUDE_CMD, env={"HOME": "/home/agent"})
        found = agent.subject
        agent.subject = None
        run = LoopRun(agent, stop_at=200)
        run.clock.at(40, lambda: setattr(agent, "subject", found))
        log = run.run()
        self.assertEqual(run.scans, [40])
        self.assertIn("waiting up to 300s for the agent's process", log)

    def test_with_no_agent_process_at_all_it_scans_after_the_cap(self):
        agent = self.agent(Agent, cmdline=CLAUDE_CMD, env={"HOME": "/home/agent"})
        agent.subject = None
        run = LoopRun(agent, stop_at=400)
        log = run.run()
        self.assertEqual(run.scans, [300])
        self.assertIn("waited 300s; scanning without the agent's process", log)

    def test_a_restarted_agent_with_a_new_environment_is_a_change(self):
        agent = self.agent()
        run = LoopRun(agent, stop_at=100)
        run.clock.at(14, lambda: agent.subject["env"].update(ANTHROPIC_MODEL="claude-fable-5-2"))
        log = run.run()
        self.assertEqual(run.scans, [0, 25])
        self.assertIn("change in the agent's process", log)


class RailDashWaitTest(unittest.TestCase):
    """DR-316's wait for RailDash still runs in pod mode, once the agent is
    ready and before the first scan."""

    def test_the_raildash_wait_runs_after_the_agent_wait_and_before_the_first_scan(self):
        agent = openclaw_agent(with_agents_main=False)
        self.addCleanup(agent.close)
        run = LoopRun(agent, stop_at=200)
        order: list[tuple[str, float]] = []
        run.clock.at(80, lambda: agent.path("/root/.openclaw/agents/main").mkdir(parents=True))
        run.watcher.before_first_scan = lambda: (order.append(("raildash", run.clock.now)), run.clock.sleep(30))
        scan = run.watcher.scan
        run.watcher.scan = lambda: (order.append(("scan", run.clock.now)), scan())[1]
        run.run()
        self.assertEqual(order[:2], [("raildash", 80), ("scan", 110)])

    def test_pod_mode_passes_the_raildash_wait_only_with_a_raildash_url(self):
        calls = []
        budgets = []
        with mock.patch.object(watcher, "run", lambda args, run_once, interval, before_first_scan=None,
                               before_first_scan_seconds=0.0:
                               calls.append(before_first_scan) or budgets.append(before_first_scan_seconds) or 0), \
                mock.patch.object(scanner, "wait_for_raildash", lambda url: calls.append(url)):
            base = ["--mode", "pod", "--config-path", "/x", "--interval", "60"]
            scanner.main(base)
            scanner.main([*base, "--raildash-url", "http://raildash:8080"])
            self.assertIsNone(calls[0])
            calls[1]()
        self.assertEqual(calls[2], "http://raildash:8080")
        # The health record's startup allowance covers the RailDash wait only when there is one.
        self.assertEqual(budgets[0], 0.0)
        self.assertGreaterEqual(budgets[1], scanner.RAILDASH_START_WAIT_SECONDS)


class WatchPlanTest(unittest.TestCase):
    def test_the_shipped_profiles_watch_specs_are_valid(self):
        for profile in PROFILES:
            watcher.watch_spec(profile)

    def test_a_bad_watch_spec_is_refused(self):
        for watch in ({"content": "x"}, {"wait_for": ["x"]}, {"wait_for": [[]], "wait_seconds": 1},
                      {"wait_seconds": -1}, []):
            with self.assertRaises(ValueError, msg=watch):
                watcher.watch_spec({"harness": "toy", "watch": watch})

    def test_transcripts_are_listed_not_read(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        plan = agent.plan()
        self.assertIn(("$OPENCLAW_DIR/agents", "/root/.openclaw/agents"), plan.listed)
        self.assertNotIn("/root/.openclaw/agents", [path for _, path in plan.content])

    def test_openclaws_backups_are_not_watched(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        for name in ("openclaw.json.bak", "openclaw.json.bak.1", "openclaw.json.last-good"):
            agent.write(f"/root/.openclaw/{name}", "{}")
        agent.write("/root/.openclaw/extra.json", "{}")
        shown = [name for name, _ in agent.plan().content]
        self.assertIn("$OPENCLAW_DIR/extra.json", shown)
        self.assertFalse([name for name in shown if ".bak" in name or "last-good" in name], shown)

    def test_a_large_file_is_hashed_without_reading_it_whole(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        data = os.urandom(3 * (1 << 20) + 17)
        agent.path("/root/.openclaw/state").mkdir()
        agent.path("/root/.openclaw/state/openclaw.sqlite").write_bytes(data)
        import hashlib
        digest = watcher.agent_process().digest_in_root(agent.root, "/root/.openclaw/state/openclaw.sqlite", 1 << 30)
        self.assertEqual(digest, (hashlib.sha256(data).hexdigest(), len(data)))


class CountingSources:
    """PodSources, counting what a poll reads."""

    def __init__(self, sources):
        self.sources, self.bytes, self.opened = sources, 0, 0

    def __getattr__(self, name):
        return getattr(self.sources, name)

    def list_dir(self, path):
        self.opened += 1
        return self.sources.list_dir(path)

    def digest(self, path, max_bytes):
        self.opened += 1
        found = self.sources.digest(path, max_bytes)
        self.bytes += found[1] if found else 0
        return found


class PollBudgetTest(unittest.TestCase):
    """Rail review: a folder the agent can write to must not make one poll
    read without bound."""

    def setUp(self):
        self.agent = openclaw_agent()
        self.addCleanup(self.agent.close)

    def counted_plan(self):
        plan = self.agent.plan()
        plan.sources = CountingSources(plan.sources)
        return plan

    def test_links_to_one_large_file_cost_one_budget(self):
        big = self.agent.path("/root/big.bin")
        big.write_bytes(b"x" * (1 << 20))
        skill = self.agent.path("/root/.openclaw/skills/stuffed")
        skill.mkdir(parents=True)
        for index in range(300):  # 300 MiB if each link were hashed
            (skill / f"link{index:03}").symlink_to("/root/big.bin")
        plan = self.counted_plan()
        hashes = watcher.fingerprint(plan, watcher.PollBudget(max_bytes=8 << 20))
        self.assertLessEqual(plan.sources.bytes, (8 << 20) + 1)
        self.assertEqual(hashes[watcher.BUDGET_KEY], "exhausted")
        # Config comes first, so it is still hashed.
        self.assertNotIn(hashes["$OPENCLAW_DIR/openclaw.json"], (watcher.OVER_BUDGET, "missing"))

    def test_the_entry_budget_is_the_polls_not_each_paths(self):
        for folder in ("/root/.openclaw/skills", "/root/.openclaw/workspace/skills"):
            path = self.agent.path(folder)
            path.mkdir(parents=True)
            for index in range(400):
                (path / f"s{index:03}").write_text("x", encoding="utf-8")
        plan = self.counted_plan()
        hashes = watcher.fingerprint(plan, watcher.PollBudget(max_entries=500))
        self.assertIn(watcher.BUDGET_KEY, hashes)
        # Each entry is listed once and, if a file, hashed once.
        self.assertLessEqual(plan.sources.opened, 2 * 500 + 2 * len(plan.content) + 2 * len(plan.listed))

    def test_a_spent_budget_still_sees_a_new_agent(self):
        # Rail review on 23db14c: the file lists came after the skill
        # folders, so a skill folder over the entry budget hid agents/work/.
        skill = self.agent.path("/root/.openclaw/skills/stuffed")
        skill.mkdir(parents=True)
        for index in range(600):
            (skill / f"f{index:03}").write_text("x", encoding="utf-8")
        plan = self.agent.plan()
        before = watcher.fingerprint(plan, watcher.PollBudget(max_entries=500))
        self.assertIn(watcher.BUDGET_KEY, before)
        self.agent.path("/root/.openclaw/agents/work").mkdir(parents=True)
        after = watcher.fingerprint(self.agent.plan(), watcher.PollBudget(max_entries=500))
        self.assertIn("agents (file list)", [name.split("/")[-1] for name in watcher.changed(before, after)])

    def test_an_over_budget_poll_hashes_the_same_each_time(self):
        skill = self.agent.path("/root/.openclaw/skills/big")
        skill.mkdir(parents=True)
        for index in range(5):
            (skill / f"part{index}").write_bytes(os.urandom(1 << 20))
        plan = self.agent.plan()
        first = watcher.fingerprint(plan, watcher.PollBudget(max_bytes=2 << 20))
        again = watcher.fingerprint(plan, watcher.PollBudget(max_bytes=2 << 20))
        self.assertIn(watcher.BUDGET_KEY, first)
        self.assertEqual(first, again)


class DeferralTest(unittest.TestCase):
    """Rail review: files that never stop changing must not put scans off for
    good, and the interval must still run while a change is pending."""

    def churn(self, agent: Agent, run: LoopRun, until: float) -> None:
        def rewrite(when: float) -> None:
            agent.write("/root/.openclaw/state/openclaw.sqlite-wal", f"write at {when}")
            if when + 3 < until:
                run.clock.at(when + 3, lambda: rewrite(when + 3))
        run.clock.at(5, lambda: rewrite(5))

    def test_files_that_never_stop_changing_are_scanned_at_most_a_minute_late(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        run = LoopRun(agent, stop_at=300)
        self.churn(agent, run, until=300)
        log = run.run()
        # Seen at 10, scanned 60s later; seen again at the next poll, and so on.
        self.assertEqual(run.scans, [0, 70, 140, 210, 280])
        self.assertIn("still changing after 60s; scanning anyway", log)
        # One change line per pending change (10, 80, 150, 220 and 290), not one per poll.
        self.assertEqual(log.count("change in"), 5)

    def test_the_interval_scan_runs_while_a_change_is_pending(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        run = LoopRun(agent, interval=30, stop_at=60)
        self.churn(agent, run, until=60)
        log = run.run()
        self.assertEqual(run.scans[:2], [0, 30])
        self.assertIn("scan: interval", log)

    def test_the_health_file_keeps_being_written_while_files_churn(self):
        agent = openclaw_agent()
        self.addCleanup(agent.close)
        run = LoopRun(agent, interval=3600, stop_at=600)
        writes: list[float] = []
        run.watcher.on_scanned = lambda: writes.append(run.clock.now)
        self.churn(agent, run, until=600)
        run.run()
        # Never more than two minutes without a scan, so a liveness probe
        # with any interval of a few minutes or more stays healthy.
        gaps = [later - earlier for earlier, later in zip([0.0, *writes], writes)]
        self.assertLessEqual(max(gaps), 120)


class LogTest(unittest.TestCase):
    def test_a_full_run_logs_no_token_or_secret_value(self):
        """The real scanner, in pod mode, scanning three times through the
        watcher: no secret from the agent's config or environment, and no
        environment value, reaches the log."""
        # Made-up marker strings shaped like credentials (no real key or token):
        # planted in the agent's config and environment, then looked for in the log.
        markers = ["sk-ant-api03-WATCHERMARKERvalue000000000000000", "gw-token-6f1c2e9a8b7d4c3e",
                   "hunter2-db-password"]
        agent = Agent(OPENCLAW_CMD, {"HOME": "/home/marked-home-dir", "OPENCLAW_GATEWAY_TOKEN": markers[1],
                                     "DATABASE_URL": f"postgres://app:{markers[2]}@db/app"})
        self.addCleanup(agent.close)
        agent.write("/home/marked-home-dir/.openclaw/openclaw.json", json.dumps({
            **OPENCLAW_JSON, "models": {"providers": {"external": {"baseUrl": "http://llm:1", "apiKey": markers[0]}}}}))
        agent.path("/home/marked-home-dir/.openclaw/agents/main").mkdir(parents=True)
        (agent.volume / ".mcp.json").write_text("{}", encoding="utf-8")
        out = Path(agent.dir.name) / "out"
        out.mkdir()
        pod_info = out / "podinfo"
        pod_info.mkdir()
        (pod_info / "labels").write_text('app="agent"\npod-template-hash="58cd78b55d"\n', encoding="utf-8")
        args = scanner.make_parser().parse_args([
            "--mode", "pod", "--config-path", str(agent.volume), "--host-id", "gke-test", "--no-feature-file",
            "--evidence-bundle-output", str(out / "bundle.json"), "--output", str(out / "payload.json")])
        env = {"POD_NAME": "agent-58cd78b55d-48jcw", "POD_NAMESPACE": "ns", "POD_UID": "u", "NODE_NAME": "n",
               "RAIL_POD_INFO_DIR": str(pod_info), "RAIL_SCAN_INTERVAL_IN_SECONDS": "60",
               "OPENCLAW_GATEWAY_TOKEN": markers[1]}
        run = LoopRun(agent, interval=60, stop_at=130)
        run.watcher.scan = lambda: (run.scans.append(run.clock.now), scanner.run_one_scan(args))[1]
        run.clock.at(23, lambda: agent.write("/home/marked-home-dir/.openclaw/openclaw.json", json.dumps({
            **OPENCLAW_JSON, "models": {"providers": {"external": {"baseUrl": "http://llm:2", "apiKey": markers[0]}}}})))
        process = {"pid": 4242, "root": agent.root, "cmdline": OPENCLAW_CMD, "env": agent.subject["env"],
                   "holds_config": True, "containers": 1}
        bundles: list[bytes] = []
        scan_once = run.watcher.scan
        run.watcher.scan = lambda: (scan_once(), bundles.append((out / "bundle.json").read_bytes()))[0]
        with mock.patch.dict(os.environ, env), mock.patch.object(
                watcher.agent_process(), "find_agent_process", lambda *a, **k: (dict(process), "found")):
            log = run.run()
        self.assertEqual(run.scans, [0, 35, 95])
        # The scanner read the agent: its harness and its changed endpoint are in the bundle.
        self.assertIn(b"openclaw", bundles[0])
        self.assertNotEqual(bundles[0], bundles[1])
        self.assertIn(b"llm:2", bundles[1])
        self.assertIn("watcher: change in $OPENCLAW_DIR/openclaw.json", log)
        for marker in [*markers, "marked-home-dir"]:
            self.assertNotIn(marker, log)


@unittest.skipUnless(hasattr(signal, "setitimer"), "needs SIGALRM timers")
class ShutdownTest(unittest.TestCase):
    """A real SIGTERM, sent to this process while watcher.run() scans."""

    def setUp(self):
        self.agent = Agent("hermes serve", {"HOME": "/home/agent"})
        self.addCleanup(self.agent.close)
        self.out = Path(self.agent.dir.name) / "bundle.json"
        health = Path(self.agent.dir.name) / "health.json"
        patches = [
            mock.patch.dict(os.environ, {"RAIL_HEALTH_FILE": str(health)}),
            mock.patch.object(watcher, "subject_finder", lambda paths: (lambda: self.agent.subject)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.args = SimpleNamespace(config_path=[str(self.agent.volume)], mcp_config=[])
        self.events: list[str] = []

    def sigterm_in(self, seconds: float) -> None:
        timer = threading.Timer(seconds, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.cancel)

    def deliver(self, seconds: float) -> None:
        """What _deliver_v1 does around writing and sending a bundle."""
        watcher.delivering(True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(0.02)
        self.out.write_text("{}", encoding="utf-8")
        self.events.append("sent")
        watcher.delivering(False)

    def run_watcher(self, run_once) -> tuple[float, str]:
        started = time.monotonic()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            watcher.run(self.args, run_once, 3600)
        return time.monotonic() - started, stderr.getvalue()

    def test_sigterm_during_a_scan_exits_within_5_seconds_and_writes_and_sends_no_bundle(self):
        def run_once(args):
            self.events.append("scanning")
            self.sigterm_in(0.2)
            time.sleep(30)  # building the bundle
            self.deliver(0)
            return 0

        elapsed, log = self.run_watcher(run_once)
        self.assertLess(elapsed, 5)
        self.assertEqual(self.events, ["scanning"])
        self.assertFalse(self.out.exists())
        self.assertIn("SIGTERM: abandoning the scan in progress", log)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_sigterm_while_waiting_between_scans_exits_at_once(self):
        def run_once(args):
            self.events.append("scan")
            self.sigterm_in(0.2)
            return 0

        elapsed, _ = self.run_watcher(run_once)
        self.assertLess(elapsed, 5)
        self.assertEqual(self.events, ["scan"])

    def test_a_bundle_in_flight_gets_to_finish(self):
        def run_once(args):
            self.sigterm_in(0.2)
            self.deliver(1.0)
            self.events.append("after delivery")  # never reached: SIGTERM ends it
            return 0

        elapsed, log = self.run_watcher(run_once)
        self.assertEqual(self.events, ["sent"])
        self.assertTrue(self.out.exists())
        self.assertLess(elapsed, 5)
        self.assertIn("letting the bundle in flight finish, up to 5s", log)
        self.assertIn("the bundle in flight was delivered; exiting", log)

    def test_a_bundle_in_flight_gets_5_seconds_at_most(self):
        class HardExit(BaseException):
            pass

        def hard_exit(code):
            raise HardExit(code)

        def run_once(args):
            self.sigterm_in(0.2)
            self.deliver(30)
            return 0

        started = time.monotonic()
        with mock.patch.object(watcher, "hard_exit", hard_exit), self.assertRaises(HardExit), \
                contextlib.redirect_stderr(io.StringIO()):
            watcher.run(self.args, run_once, 3600)
        self.assertLess(time.monotonic() - started, 6)
        self.assertGreaterEqual(time.monotonic() - started, 5)
        self.assertEqual(self.events, [])
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)


class HealthTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "health.json"

    def test_a_fresh_scan_is_healthy(self):
        watcher.write_health(self.path, 3600, now=1000)
        self.assertEqual(watcher.check_health(self.path, now=1000 + 7200)[0], True)

    def test_the_health_check_fails_on_a_stale_file(self):
        watcher.write_health(self.path, 3600, now=1000)
        ok, line = watcher.check_health(self.path, now=1000 + 7201)
        self.assertFalse(ok)
        self.assertIn("more than two intervals", line)

    def test_no_health_file_is_unhealthy(self):
        self.assertFalse(watcher.check_health(self.path)[0])
        self.path.write_text("not json", encoding="utf-8")
        self.assertFalse(watcher.check_health(self.path)[0])

    def test_the_cli_health_check_is_the_liveness_probe(self):
        with mock.patch.dict(os.environ, {"RAIL_HEALTH_FILE": str(self.path)}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(["--health-check"]), 1)
            watcher.write_health(self.path, 60)
            self.assertEqual(scanner.main(["--health-check"]), 0)
            watcher.write_health(self.path, 60, now=time.time() - 121)
            self.assertEqual(scanner.main(["--health-check"]), 1)

    def test_a_slow_start_stays_healthy_until_its_allowance_runs_out(self):
        """Rail review: the startup waits (300s for OpenClaw, then 120s for
        RailDash) must not fail the liveness probe, even with a short
        interval; a start stuck past them still does."""
        agent = Agent("hermes serve", {"HOME": "/home/agent"})
        self.addCleanup(agent.close)
        args = SimpleNamespace(config_path=[str(agent.volume)], mcp_config=[])
        seen = {}

        def startup_probe(_watcher):
            started = json.loads(self.path.read_text(encoding="utf-8"))["last_scan"]
            for offset in (30, 300, 300 + 127, 300 + 127 + 2 * 30):
                seen[offset] = watcher.check_health(self.path, now=started + offset)[0]
            seen["stuck"] = watcher.check_health(self.path, now=started + 300 + 127 + 2 * 30 + 1)

        with mock.patch.dict(os.environ, {"RAIL_HEALTH_FILE": str(self.path)}), \
                mock.patch.object(watcher, "subject_finder", lambda paths: (lambda: agent.subject)), \
                mock.patch.object(watcher.Watcher, "run", startup_probe):
            watcher.run(args, lambda a: 0, 30, before_first_scan=lambda: None, before_first_scan_seconds=127)
        self.assertEqual({k: v for k, v in seen.items() if k != "stuck"},
                         {30: True, 300: True, 427: True, 487: True})
        self.assertFalse(seen["stuck"][0])
        self.assertIn("still no first scan", seen["stuck"][1])

    def test_the_first_scan_ends_the_startup_allowance(self):
        watcher.write_health(self.path, 30, now=1000, starting_until=1600)
        watcher.write_health(self.path, 30, now=1050)  # what on_scanned writes
        self.assertFalse(watcher.check_health(self.path, now=1050 + 61)[0])

    def test_the_watcher_writes_the_health_file_after_each_scan(self):
        agent = Agent("hermes serve", {"HOME": "/home/agent"})
        self.addCleanup(agent.close)
        clock = FakeClock()
        writes: list[float] = []
        clock.at(130, lambda: (_ for _ in ()).throw(Stop()))
        loop = watcher.Watcher(lambda: 0, agent.plan, interval=60, clock=clock.time, sleep=clock.sleep,
                               on_scanned=lambda: writes.append(clock.now))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(Stop):
            loop.run()
        self.assertEqual(writes, [0, 60, 120])


if __name__ == "__main__":
    unittest.main()
