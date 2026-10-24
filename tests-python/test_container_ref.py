"""`openshell:<sandbox>` (DR-247): the agent named by its OpenShell sandbox.
The lookup itself, the listen/files supervisor following a recreated sandbox,
and the scan, whose bundle is the one a scan of that container's name gives."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: str):
    """A private copy, never put in sys.modules (see test_egress_containment)."""
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


container_ref = _load("container_ref", "tools/scan/container_ref.py")
follow = _load("follow_container", "tools/listen/follow_container.py")
SUPERVISOR = ROOT / "tools/listen/follow_container.py"
SCANNER = ROOT / "tools/scan/scan_agent_environment.py"

# A stand-in for Docker. `ps` prints $FAKE_PS's lines (the containers its
# label filters match, which the test sets) and records its arguments;
# `inspect -f` prints the PID $FAKE_PIDS maps the container to; a plain
# `inspect` prints one workload container's inspect output; anything else
# (exec, network inspect) fails, as on a container with nothing to run.
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
if a[0] == "ps":
    with open(os.environ["FAKE_ARGS"], "a") as f:
        f.write(" ".join(a) + "\n")
    if os.environ.get("FAKE_PS_FAIL"):
        print("Cannot connect to the Docker daemon", file=sys.stderr)
        sys.exit(1)
    print(open(os.environ["FAKE_PS"]).read(), end="")
    sys.exit(0)
pids = json.load(open(os.environ["FAKE_PIDS"]))
if a[0] == "inspect" and a[1] == "-f":
    if a[3] not in pids:
        sys.exit(1)
    print(pids[a[3]])
    sys.exit(0)
if a[0] == "inspect" and a[1] in pids:
    print(json.dumps([{"Id": "id-" + a[1], "Name": "/" + a[1], "Config": {
        "Image": "agent:1", "Hostname": "agent", "Env": ["PATH=/usr/bin", "OPENAI_API_KEY=sk-x"],
        "Labels": {"openshell.ai/sandbox-name": "my-agent", "openshell.ai/isolation-role": "sandbox"}},
        "State": {"Pid": pids[a[1]], "Running": True}, "HostConfig": {"NetworkMode": "none"},
        "NetworkSettings": {"Networks": {}}}]))
    sys.exit(0)
sys.exit(1)
'''

# A stand-in for AgentSight's process probe: records its arguments, starts, waits.
FAKE_AGENTSIGHT = """#!/bin/sh
echo "$*" >> "$FAKE_PROBE_ARGS"
printf '%s\\n' '{"event":"PROBE_LIVENESS","kind":"start","pid":0,"comm":"process","timestamp":1,"wall_time_ns":1791453600000000000,"every":5,"trace_net":true}'
exec sleep 30
"""


class FakeDocker:
    def __init__(self, base: Path):
        self.base = base
        self.path = base / "docker"
        self.path.write_text(FAKE_DOCKER)
        self.path.chmod(0o755)
        self.args = base / "docker-args"
        self.ps = base / "ps"
        self.pids = base / "pids"
        self.running({})

    def running(self, containers: dict[str, int]) -> None:
        """The sandbox's running containers now, each with its init PID."""
        self.pids.write_text(json.dumps(containers))
        self.ps.write_text("".join(f"{name}\n" for name in containers))

    @property
    def env(self) -> dict[str, str]:
        return {"FAKE_ARGS": str(self.args), "FAKE_PS": str(self.ps), "FAKE_PIDS": str(self.pids)}


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.docker = FakeDocker(Path(self.tmp.name))
        patch = mock.patch.dict(os.environ, self.docker.env)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def resolve(self, ref):
        return container_ref.resolve(ref, str(self.docker.path))

    def test_a_container_name_is_used_as_it_is_without_asking_docker(self):
        self.assertEqual(self.resolve("my-agent"), ("my-agent", None))
        self.assertFalse(self.docker.args.exists())

    def test_a_sandbox_is_its_one_running_workload_container(self):
        self.docker.running({"openshell-7f3a": 4242})
        self.assertEqual(self.resolve("openshell:my-agent"), ("openshell-7f3a", None))
        # By both labels: the sandbox's name, and the workload's role, so
        # the supervisor's own container never matches.
        self.assertEqual(self.docker.args.read_text().split(), [
            "ps", "--format", "{{.Names}}", "--filter", "label=openshell.ai/sandbox-name=my-agent",
            "--filter", "label=openshell.ai/isolation-role=sandbox"])

    def test_none_running_is_not_a_problem_and_several_are(self):
        self.assertEqual(self.resolve("openshell:my-agent"), (None, None))
        self.docker.running({"openshell-b": 2, "openshell-a": 1})
        self.assertEqual(self.resolve("openshell:my-agent"), (
            None, "OpenShell sandbox my-agent has 2 running containers (openshell-a, openshell-b); "
                  "none is watched until exactly one runs"))

    def test_a_name_openshell_would_not_give_never_reaches_docker(self):
        for ref in ("openshell:", "openshell:a,label=x", "openshell:-a", "openshell:a b"):
            container, problem = self.resolve(ref)
            self.assertIsNone(container)
            self.assertIn("does not name an OpenShell sandbox", problem)
        self.assertFalse(self.docker.args.exists())

    def test_docker_not_answering_is_a_problem(self):
        with mock.patch.dict(os.environ, {"FAKE_PS_FAIL": "1"}):
            container, problem = self.resolve("openshell:my-agent")
        self.assertIsNone(container)
        self.assertIn("Cannot connect to the Docker daemon", problem)

    def test_the_supervisors_log_a_problem_once_until_it_changes(self):
        self.docker.running({"openshell-a": 1, "openshell-b": 2})
        logged: list[str] = []
        with mock.patch.dict(follow._reported, clear=True):
            for _ in range(3):
                self.assertEqual(follow.container_pid(str(self.docker.path), "openshell:my-agent",
                                                      logged.append), 0)
            self.docker.running({"openshell-b": 2})
            self.assertEqual(follow.container_pid(str(self.docker.path), "openshell:my-agent",
                                                  logged.append), 2)
        self.assertEqual(logged, ["OpenShell sandbox my-agent has 2 running containers "
                                  "(openshell-a, openshell-b); none is watched until exactly one runs"])


class SupervisorTest(unittest.TestCase):
    """`railmon listen`/`files` with RAIL_*_CONTAINER=openshell:<sandbox>."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.docker = FakeDocker(self.dir)
        probe = self.dir / "agentsight"
        probe.write_text(FAKE_AGENTSIGHT)
        probe.chmod(0o755)
        self.probe_args = self.dir / "probe-args"
        self.env = {**os.environ, **self.docker.env, "RAIL_DOCKER": str(self.docker.path),
                    "RAIL_AGENTSIGHT_PROCESS": str(probe), "FAKE_PROBE_ARGS": str(self.probe_args)}

    def wait_for(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not predicate():
            time.sleep(0.05)
        return predicate()

    def test_a_recreated_sandbox_is_followed_without_a_restart(self):
        output = self.dir / "files.jsonl"
        supervisor = subprocess.Popen(
            [sys.executable, str(SUPERVISOR), "--source", "agentsight", "--command", "files",
             "--output", str(output), "--heartbeat", "5", "openshell:my-agent"],
            env=self.env, stderr=subprocess.PIPE, text=True)
        try:
            # The stack can start before the sandbox exists.
            self.assertTrue(self.wait_for(lambda: self.docker.args.exists()))
            self.docker.running({"openshell-7f3a": 4242})
            self.assertTrue(self.wait_for(lambda: output.exists() and '"kind":"start"' in output.read_text()))
            # `openshell sandbox delete` then `create`: a new container, a new name.
            self.docker.running({})
            self.docker.running({"openshell-91c0": 4343})
            self.assertTrue(self.wait_for(lambda: output.read_text().count('"kind":"start"') >= 2))
        finally:
            supervisor.send_signal(signal.SIGTERM)
            _, stderr = supervisor.communicate(timeout=20)
        self.assertEqual(self.probe_args.read_text().splitlines(),
                         ["-m 0 --pidns-of 4242 --heartbeat 5", "-m 0 --pidns-of 4343 --heartbeat 5"])
        self.assertIn("waiting for container openshell:my-agent to run", stderr)
        self.assertIn("attaching to openshell:my-agent (pid 4343)", stderr)
        self.assertEqual(supervisor.returncode, 0)

    def test_a_reference_that_can_never_resolve_exits_at_once(self):
        for script in (SUPERVISOR, ROOT / "tools/collect/follow_container_tls.py"):
            run = subprocess.run([sys.executable, str(script), "openshell:my agent"],
                                 env=self.env, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 2, script)
            self.assertIn("'openshell:my agent' does not name an OpenShell sandbox", run.stderr)
        self.assertFalse(self.docker.args.exists())


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.docker = FakeDocker(self.dir)
        self.docker.running({"openshell-7f3a": 4242})

    def scan(self, *args: str, name: str) -> tuple[subprocess.CompletedProcess, Path]:
        bundle = self.dir / f"bundle-{name}.json"
        env = {**os.environ, **self.docker.env, "PATH": f"{self.dir}{os.pathsep}{os.environ['PATH']}",
               "RAIL_EVIDENCE_BUNDLE_OUTPUT": str(bundle)}
        env.pop("RAIL_AGENT_KEY", None)
        run = subprocess.run(
            [sys.executable, str(SCANNER), "--mode", "docker", "--host-id", "h1",
             "--output", str(self.dir / f"payload-{name}.json"),
             "--feature-output", str(self.dir / f"features-{name}.json"), *args],
            env=env, capture_output=True, text=True, timeout=120)
        return run, bundle

    @staticmethod
    def stable(path: Path) -> dict:
        """The bundle without what differs between any two runs: its id,
        collection time and the scanner's own PID."""
        bundle = json.loads(path.read_text())
        del bundle["bundle_id"], bundle["collected_at"]
        del bundle["attributes"]["agent_instance"]["value"]["process"]["pid"]
        return bundle

    def test_the_bundle_is_the_one_a_scan_of_the_containers_name_gives(self):
        by_sandbox, sandbox_bundle = self.scan("--container", "openshell:my-agent", name="sandbox")
        self.assertEqual(by_sandbox.returncode, 0, by_sandbox.stderr)
        by_name, name_bundle = self.scan("--container", "openshell-7f3a", "--agent-key", "my-agent",
                                         "--sandbox-name", "my-agent", name="name")
        self.assertEqual(by_name.returncode, 0, by_name.stderr)
        sandbox, name = self.stable(sandbox_bundle), self.stable(name_bundle)
        # The sandbox's name, which a recreate keeps, not the container's.
        identity = sandbox["attributes"]["container_identity"]
        self.assertEqual(identity["value"], {"host_id": "h1", "sandbox_name": "my-agent"})
        self.assertEqual(sandbox["sandbox_name"], "my-agent")
        # Apart from saying where that name came from, the same bundle.
        self.assertEqual(identity["method"], "host_id: flag; sandbox_name: openshell_sandbox")
        self.assertEqual(name["attributes"]["container_identity"]["method"],
                         "host_id: flag; sandbox_name: flag")
        identity["method"] = name["attributes"]["container_identity"]["method"]
        self.assertEqual(sandbox, name)
        self.assertEqual(sandbox["attributes"]["agent_instance"]["value"]["container"],
                         {"host_pid": 4242, "id": "id-openshell-7f3a"})

    def test_no_running_sandbox_container_fails_that_scan(self):
        self.docker.running({})
        run, bundle = self.scan("--container", "openshell:my-agent", name="none")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("no running container for OpenShell sandbox my-agent yet", run.stderr)
        self.assertFalse(bundle.exists())


class AgentKeyTest(unittest.TestCase):
    def setUp(self):
        self.scanner = _load("scan_agent_environment", "tools/scan/scan_agent_environment.py")

    def key(self, **args):
        defaults = {"mode": "docker", "container": None, "agent_key": None}
        with mock.patch.dict(os.environ, {"RAIL_AGENT_KEY": ""}):
            return self.scanner.configured_agent_key(argparse.Namespace(**{**defaults, **args}))

    def test_the_agent_key_defaults_to_the_sandbox_name(self):
        self.assertEqual(self.key(container="openshell:my-agent"), "my-agent")
        self.assertEqual(self.key(container="openshell:my-agent", agent_key="other"), "other")
        self.assertIsNone(self.key(container="my-agent"))
        self.assertIsNone(self.key(mode="self", container="openshell:my-agent"))
        # Not a valid agent key: no default, rather than one every delivery refuses.
        self.assertIsNone(self.key(container="openshell:My-Agent"))
        self.assertIsNone(self.key(container="openshell:" + "a" * 65))

    def test_the_key_rule_is_the_multi_agent_one(self):
        composer = _load("compose_evidence_bundle_v2", "tools/scan/compose_evidence_bundle_v2.py")
        self.assertEqual(container_ref.AGENT_KEY.pattern, composer.KEY.pattern)


if __name__ == "__main__":
    unittest.main()
