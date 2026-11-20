"""RC-530: tool_names reads every transcript it should.

OpenClaw 2026.10.8 stores a transcript event of 1 KB or more compressed in
event_zstd, with event_json NULL. The OpenClaw profile's hook decompresses it
(the standard library's compression.zstd, Python 3.14+) within caps, and
counts what it can't read as unparsed. The decompressor is swapped for a
stand-in in most tests, so the hook's logic is tested on any Python; the
tests that need real zstd frames run where compression.zstd exists (CI and
the images run 3.15).

The transcript file cap (TRANSCRIPT_MAX_FILES): the shared reader and Claude
Code's profile read the newest transcripts first, when Sources can give
modification times, and report tool_names PARTIAL with SIZE_CAP_EXCEEDED,
saying how many were read, when the cap leaves some unread.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "scan"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str, path: Path):
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


reader = load("harness_reader", SCAN / "gke" / "sidecar" / "harness" / "reader.py")
agent_process = load("gke_agent_process", SCAN / "gke" / "sidecar" / "agent_process.py")
PROFILES = reader.load_profiles()
OPENCLAW = next(p for p in PROFILES if p["harness"] == "openclaw")
CLAUDE = next(p for p in PROFILES if p["harness"] == "claude-code")
hooks = sys.modules["harness_profile_openclaw"]
OPENCLAW_AGENT = reader.Agent("node /usr/local/bin/openclaw gateway --allow-unconfigured", {"HOME": "/root"})
CLAUDE_AGENT = reader.Agent("/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe -p hi",
                            {"HOME": "/root"}, "/work")

try:
    from compression import zstd as real_zstd  # type: ignore[import-not-found]
except ImportError:
    real_zstd = None

ARGUMENT = "argument-placeholder-do-not-report"


def call(name: str, pad: int = 0) -> str:
    """An assistant event calling `name`, with an argument that must never
    reach the bundle, padded to `pad` bytes (OpenClaw compresses from 1 KB)."""
    return json.dumps({"type": "message", "message": {"role": "assistant", "content": [
        {"type": "toolCall", "name": name, "arguments": {"query": ARGUMENT, "pad": "x" * pad}}]}})


def fake_compress(text: str) -> bytes:
    return b"FAKEZSTD" + text.encode()


def fake_decompress(data: bytes, limit: int) -> bytes:
    """The stand-in for zstd_decompress: the same contract (LookupError,
    EventTooLarge, ValueError), for frames made by fake_compress."""
    if data == b"FAKEBOMB":  # a few bytes that would decompress past any cap
        out = b"x" * (limit + 1)
    elif data.startswith(b"FAKEZSTD"):
        out = data[len(b"FAKEZSTD"):]
    else:
        raise ValueError("not a frame")
    if len(out) > limit:
        raise hooks.EventTooLarge(limit)
    return out


class OpenClawInstall(unittest.TestCase):
    """An OpenClaw agent's root with a transcript database as 2026.10.8 lays it out."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        state = self.root / "root" / ".openclaw"
        state.mkdir(parents=True)
        shutil.copy(FIXTURES / "openclaw" / "openclaw.json", state / "openclaw.json")
        path = state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        path.parent.mkdir(parents=True)
        self.db = sqlite3.connect(path)
        self.addCleanup(self.db.close)
        self.db.execute("pragma journal_mode=wal")
        self.db.execute("pragma wal_autocheckpoint=0")

    def table(self, with_zstd: bool = True) -> None:
        if with_zstd:
            self.db.execute("create table transcript_events (session_id text, seq integer, event_json text, "
                            "event_zstd blob, created_at text)")
        else:  # 2026.9.2
            self.db.execute("create table transcript_events (session_id text, seq integer, event_json text, created_at text)")

    def add(self, seq: int, event_json: str | None = None, event_zstd: bytes | None = None) -> None:
        self.db.execute("insert into transcript_events (session_id, seq, event_json, event_zstd, created_at) "
                        "values ('s1', ?, ?, ?, '')", (seq, event_json, event_zstd))
        self.db.commit()

    def tool_names(self):
        return reader.read_harness_fields(OPENCLAW, OPENCLAW_AGENT, reader.LocalSources(self.root))["tool_names"]


class OpenClawZstdTest(OpenClawInstall):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hooks, "zstd_decompress", side_effect=fake_decompress)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_compressed_events_give_their_tool_names(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, fake_compress(call("getStatement", pad=2000)))
        self.add(3, None, fake_compress(call("buyStock", pad=5000)))
        result = self.tool_names()
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["buyStock", "getStatement", "getStockPrice"]))
        self.assertNotIn(ARGUMENT, json.dumps(result))

    def test_a_2026_9_table_reads_as_before(self):
        self.table(with_zstd=False)
        self.db.execute("insert into transcript_events values ('s1', 1, ?, '')", (call("getStockPrice"),))
        self.db.commit()
        result = self.tool_names()
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["getStockPrice"]))

    def test_a_frame_that_does_not_decompress_is_unparsed_and_the_rest_count(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, b"\x28\xb5\x2f\xfd garbage")
        self.add(3, None, "a text value, not a blob")
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "PARSE_FAILED", ["getStockPrice"]))
        self.assertIn("2 compressed event(s) could not be decompressed", result["note"])

    def test_a_frame_past_the_decompressed_cap_is_unparsed(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, b"FAKEBOMB")
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "PARSE_FAILED", ["getStockPrice"]))
        self.assertIn(f"larger than {hooks.EVENT_MAX_DECOMPRESSED} bytes decompressed", result["note"])

    def test_decompressed_bytes_have_a_budget(self):
        self.table()
        for seq in range(1, 6):
            self.add(seq, None, fake_compress(call(f"tool{seq}", pad=3000)))
        with mock.patch.object(hooks, "DB_MAX_DECOMPRESSED", 5000):
            result = self.tool_names()
        # Two decompress before the budget is spent; the rest are left unread.
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertEqual(result["value"], ["tool1", "tool2"])
        self.assertIn("3 compressed event(s) not read", result["note"])

    def test_decompression_has_a_deadline(self):
        self.table()
        self.add(1, None, fake_compress(call("first")))
        self.add(2, None, fake_compress(call("second")))
        clock = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0, 1000.0])
        with mock.patch.object(hooks.time, "monotonic", side_effect=lambda: next(clock, 1000.0)):
            decoder = hooks._Decoder()
            first = decoder.text(None, fake_compress(call("first")))
            second = decoder.text(None, fake_compress(call("second")))
        self.assertIn("first", first)
        self.assertIs(second, hooks.SKIPPED)
        self.assertEqual(decoder.over_budget, 1)

    def test_a_row_with_neither_column_is_still_unparsed(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, None)
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "PARSE_FAILED"))


class NoZstdTest(OpenClawInstall):
    def test_without_compression_zstd_compressed_events_are_unparsed(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, b"\x28\xb5\x2f\xfd frame")
        with mock.patch.object(hooks, "_zstd_module", return_value=None):
            result = self.tool_names()
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "PARSE_FAILED", ["getStockPrice"]))
        self.assertIn("1 compressed event(s) not read: this Python has no compression.zstd (3.14+)", result["note"])


@unittest.skipUnless(real_zstd, "needs compression.zstd (Python 3.14+), as CI and the images have")
class RealZstdTest(OpenClawInstall):
    def test_real_frames_give_their_tool_names(self):
        self.table()
        self.add(1, call("getStockPrice"))
        self.add(2, None, real_zstd.compress(call("getStatement", pad=2000).encode()))
        result = self.tool_names()
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["getStatement", "getStockPrice"]))
        self.assertNotIn(ARGUMENT, json.dumps(result))

    def test_decompression_never_produces_more_than_the_cap(self):
        bomb = real_zstd.compress(b"\0" * 50_000_000)  # tiny compressed, 50 MB decompressed
        self.assertLess(len(bomb), 100_000)
        with self.assertRaises(hooks.EventTooLarge):
            hooks.zstd_decompress(bomb, 1000)

    def test_truncated_and_trailing_frames_are_refused(self):
        frame = real_zstd.compress(call("x", pad=3000).encode())
        for data in (frame[:-10], frame + b"trailing", b"not zstd at all"):
            with self.assertRaises(ValueError):
                hooks.zstd_decompress(data, hooks.EVENT_MAX_DECOMPRESSED)
        self.assertIn(b"toolCall", hooks.zstd_decompress(frame, hooks.EVENT_MAX_DECOMPRESSED))


class NoMtimes:
    """LocalSources without modification times, as a Sources may be."""

    def __init__(self, inner):
        self.inner = inner

    def read_text(self, path, max_bytes):
        return self.inner.read_text(path, max_bytes)

    def read_bytes(self, path, max_bytes):
        return self.inner.read_bytes(path, max_bytes)

    def list_dir(self, path):
        return self.inner.list_dir(path)


TOY = {
    "harness": "toy",
    "markers": {"commands": ["toyagent"]},
    "sources": [],
    "fields": {},
    "workspace": {"transcripts": {"folders": ["~/.toy/sessions"], "files": "*.jsonl", "tool_name": "call.name"}},
}


class Transcripts(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "agent-root"
        self.now = time.time()

    def write(self, path: str, text: str, age: float) -> None:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        os.utime(target, (self.now - age, self.now - age))


class SharedReaderFileCapTest(Transcripts):
    def toy(self, count: int, newest_tool: str = "recent", old_tool: str = "old") -> None:
        # Names in reverse of age, so name order and newest-first disagree:
        # a.jsonl is the oldest, and the newest have names late in order.
        for i in range(count):
            tool = newest_tool if i >= count - reader.TRANSCRIPT_MAX_FILES else old_tool
            self.write(f"/home/toy/.toy/sessions/{i:04d}.jsonl", json.dumps({"call": {"name": tool}}) + "\n",
                       age=count - i)

    def tool_names(self, sources=None):
        agent = reader.Agent("toyagent serve", {"HOME": "/home/toy"})
        return reader.read_harness_fields(TOY, agent, sources or reader.LocalSources(self.root))["tool_names"]

    def test_past_the_cap_the_newest_are_read_and_it_says_so(self):
        self.toy(60)
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "SIZE_CAP_EXCEEDED", ["recent"]))
        self.assertIn(f"read the {reader.TRANSCRIPT_MAX_FILES} newest of 60 transcripts", result["note"])
        self.assertEqual(len(result["source"]), reader.TRANSCRIPT_MAX_FILES)
        self.assertNotIn("~/.toy/sessions/0000.jsonl", result["source"])

    def test_without_modification_times_name_order_is_kept_and_said(self):
        self.toy(60)
        result = self.tool_names(NoMtimes(reader.LocalSources(self.root)))
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("old", result["value"])
        self.assertIn("in name order", result["note"])

    def test_under_the_cap_nothing_changes(self):
        self.toy(reader.TRANSCRIPT_MAX_FILES)
        result = self.tool_names()
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["recent"]))
        self.assertNotIn("newest", result["note"])

    def test_none_found_with_some_unread_is_an_empty_floor_not_absent(self):
        for i in range(55):
            self.write(f"/home/toy/.toy/sessions/{i:04d}.jsonl", '{"other": 1}\n', age=i)
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"], result["value"]), ("PARTIAL", "SIZE_CAP_EXCEEDED", []))

    def test_newest_first_puts_unreadable_times_last(self):
        times = {"a": 10.0, "b": None, "c": 30.0}
        sources = mock.Mock()
        sources.mtime.side_effect = lambda path: times[path]
        with mock.patch.object(reader, "TRANSCRIPT_MAX_FILES", 2):
            chosen, note = reader.newest_first(sources, ["a", "b", "c"], lambda p: p)
        self.assertEqual((chosen, note), (["c", "a"], "read the 2 newest of 3 transcripts (TRANSCRIPT_MAX_FILES)"))
        with mock.patch.object(reader, "TRANSCRIPT_MAX_FILES", 2):
            chosen, note = reader.newest_first(sources, ["a", "b"], lambda p: p, more=True)
        self.assertIn("of more than 2 transcripts", note)


class ClaudeCodeFileCapTest(Transcripts):
    def entry(self, tool: str) -> str:
        return json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": tool,
                                                                          "input": {"q": ARGUMENT}}]}}) + "\n"

    def tool_names(self):
        return reader.read_harness_fields(CLAUDE, CLAUDE_AGENT, reader.LocalSources(self.root))["tool_names"]

    def test_subagent_transcripts_count_toward_the_cap_and_the_newest_are_read(self):
        # The agent's own project: one old session with many old subagents.
        session = "0cf9746c-7773-486a-9058-fb795c31ab97"
        self.write(f"/root/.claude/projects/-work/{session}.jsonl", self.entry("Read"), age=1000)
        for i in range(60):
            self.write(f"/root/.claude/projects/-work/{session}/subagents/agent-{i:02d}.jsonl", self.entry("OldGrep"),
                       age=900 - i)
        # Another project's session, the newest of all.
        self.write("/root/.claude/projects/-srv-other/a1b2.jsonl", self.entry("NewBash"), age=1)
        result = self.tool_names()
        self.assertEqual((result["status"], result["reason"]), ("PARTIAL", "SIZE_CAP_EXCEEDED"))
        self.assertIn("NewBash", result["value"])
        self.assertNotIn("Read", result["value"])  # the oldest transcript, past the cap
        self.assertIn(f"read the {reader.TRANSCRIPT_MAX_FILES} newest of 62 transcripts", result["note"])
        self.assertNotIn(ARGUMENT, json.dumps(result))
        self.assertNotIn("srv-other", json.dumps(result))  # a project's folder name is never reported

    def test_under_the_cap_is_unchanged(self):
        self.write("/root/.claude/projects/-work/s.jsonl", self.entry("Read"), age=1)
        result = self.tool_names()
        self.assertEqual((result["status"], result["value"]), ("ANSWERED", ["Read"]))


class MtimeInRootTest(unittest.TestCase):
    def test_a_regular_file_inside_the_root_only(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = tmp / "root"
        (root / "data").mkdir(parents=True)
        (root / "data" / "t.jsonl").write_text("{}\n")
        os.utime(root / "data" / "t.jsonl", (1_700_000_000, 1_700_000_000))
        outside = tmp / "outside.jsonl"
        outside.write_text("{}\n")
        os.utime(outside, (1_800_000_000, 1_800_000_000))
        # An absolute link resolves inside the agent's root, never the reader's.
        (root / "data" / "escape.jsonl").symlink_to(outside)
        self.assertEqual(agent_process.mtime_in_root(root, "/data/t.jsonl"), 1_700_000_000)
        self.assertIsNone(agent_process.mtime_in_root(root, "/data"))
        self.assertIsNone(agent_process.mtime_in_root(root, "/data/missing.jsonl"))
        self.assertNotEqual(agent_process.mtime_in_root(root, "/data/escape.jsonl"), 1_800_000_000)


if __name__ == "__main__":
    unittest.main()
