#!/usr/bin/env python3
"""The scan-sidecar image runs a pod-mode scan the way the webhook runs it (RC-518).

Two containers from the built image, set up as a pod would be, three times:

- an "agent": a process named `openclaw-gateway`, with an API key in its
  environment and the OpenClaw fixture as its config;
- the sidecar: `railmon scan --mode pod` with a read-only root filesystem,
  no-new-privileges, the capabilities the webhook gives it (none for a
  non-root agent; a root agent's own set), the agent's UID and GID, the
  agent's PID and network namespaces (shareProcessNamespace and the pod's
  network), the config volume read-only, a downward API labels file and
  variables, and a writable folder at /tmp only (the pod's emptyDir).

Run as UID 1000 with no capabilities, then as root with the agent's default
set, then as root with none. Checked, the first two times:

1. the scan exits 0 and writes its bundle to /tmp, and nothing else is
   writable (the root filesystem is read-only, so a write anywhere else would
   have failed the scan);
2. the bundle's key is the cluster and the workload (`ci/agent-finretail`),
   with the pod in `agent_instance` and `sandbox_type` kubernetes;
3. the agent's own process was read: OpenClaw recognized from its command
   line, its config's model and MCP server, its environment variable's name,
   and never the variable's value or the config's apiKey;
4. the third time, the agent's process is BLIND: the kernel won't let a
   process with fewer capabilities read it, which is why the webhook mirrors
   a root agent's (tools/scan/gke/webhook/patch.py);
5. the image is slim: no pip, Docker CLI, curl, openssl or collector, and its
   entrypoint offers only the scan-sidecar image's commands.

Needs Docker, as CI's runner has.

  python3 tests/scan_sidecar_acceptance.py --image scan-sidecar:ci
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests-python" / "fixtures" / "openclaw" / "openclaw.json"
AGENT_UID = 1000
CONFIG_HOME = "/home/agent/.openclaw"
SECRET_VALUE = "ci-not-a-real-key-0123456789abcdef"
FIXTURE_KEY = "fixture-placeholder-not-a-key"
POD_UID = "f3fe5e58-b328-40cb-9b03-1acf558d773d"


def docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], check=check, text=True,
                          stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)


def fail(message: str, *logs: str) -> None:
    for log in logs:
        if log:
            print(log, file=sys.stderr)
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def attribute(bundle: dict, name: str) -> dict:
    attrs = bundle.get("attributes") or {}
    found = attrs.get(name) if isinstance(attrs, dict) else next((a for a in attrs if a.get("name") == name), None)
    if not isinstance(found, dict):
        fail(f"the bundle has no {name} attribute")
    return found  # type: ignore[return-value]


def check_slim(image: str) -> None:
    probe = docker("run", "--rm", "--read-only", "--entrypoint", "sh", image, "-c",
                   "for b in pip pip3 docker curl wget openssl railmon-collector agentsight openshell; do "
                   "command -v $b && exit 1; done; exit 0", check=False)
    if probe.returncode != 0:
        fail(f"the image carries {probe.stdout.strip()}, which the scan sidecar doesn't need")
    for command in (["help"], ["scan", "--help"], ["gke-scan", "--help"], ["scan-webhook", "--help"]):
        run = docker("run", "--rm", "--read-only", image, *command, check=False)
        if run.returncode != 0:
            fail(f"`railmon {' '.join(command)}` exits {run.returncode}", run.stderr)
    run = docker("run", "--rm", "--read-only", image, "collect", check=False)
    if run.returncode != 64:
        fail("`railmon collect` should be refused in the scan-sidecar image", run.stderr)


def scan(image: str, work: Path, uid: int, cap_args: list[str]) -> tuple[subprocess.CompletedProcess[str], str]:
    """One agent and one sidecar beside it, both as `uid`. The sidecar gets
    `cap_args` (the webhook's choice for that agent); the rest is as the
    webhook sets it. Returns the scan and the bundle's text ("" if none)."""
    agent = f"scan-sidecar-agent-{uuid.uuid4().hex[:8]}"
    config, podinfo, tmp = work / "config", work / "podinfo", work / f"tmp-{uid}-{len(cap_args)}"
    tmp.mkdir()
    # The emptyDir: the pod's UID's. CI's runner isn't root, so there it is
    # world-writable instead.
    if os.geteuid() == 0:
        os.chown(tmp, uid, uid)
    else:
        os.chmod(tmp, 0o777)
    home = "/root" if uid == 0 else "/home/agent"
    try:
        # The agent: what the sidecar should find through the shared process
        # namespace. Named openclaw-gateway, as OpenClaw's gateway runs. A
        # root agent keeps the runtime's default capabilities, as one does in
        # a pod that doesn't drop them.
        agent_caps = [] if uid == 0 else ["--cap-drop", "ALL"]
        docker("run", "-d", "--name", agent, "--network", "none", "--read-only",
               "--user", f"{uid}:{uid}", *agent_caps,
               "-e", f"HOME={home}", "-e", f"AGENT_LLM_API_KEY={SECRET_VALUE}",
               "-v", f"{config}:{home}/.openclaw:ro",
               "--entrypoint", "python3", image,
               "-c", "import os; os.execvp('sleep', ['openclaw-gateway', '600'])")
        env = {
            "POD_NAME": "agent-finretail-58cd78b55d-48jcw",
            "POD_NAMESPACE": "ci",
            "POD_UID": POD_UID,
            "NODE_NAME": "ci-node",
            "RAIL_POD_INFO_DIR": "/etc/podinfo",
            "RAIL_OWNER": "support-platform",
            "RAIL_HOST_ID": "ci",
            "RAIL_SANDBOX_TYPE": "kubernetes",
        }
        env_args = [item for key, value in env.items() for item in ("-e", f"{key}={value}")]
        run = docker(
            "run", "--rm", "--read-only", *cap_args, "--security-opt", "no-new-privileges",
            "--user", f"{uid}:{uid}",
            "--pid", f"container:{agent}", "--network", f"container:{agent}",
            "-v", f"{config}:{home}/.openclaw:ro",
            "-v", f"{podinfo}:/etc/podinfo:ro",
            "-v", f"{tmp}:/tmp",
            *env_args,
            image, "scan", "--mode", "pod", "--config-path", f"{home}/.openclaw", "--no-feature-file", "--compact",
            check=False,
        )
        # The scanner writes the bundle owner-only (0600, store_bytes), as the
        # sidecar's UID. On a Linux runner the test's own user can't read that,
        # so it is read back the way the pod would: as the same UID.
        read = docker("run", "--rm", "--read-only", "--user", f"{uid}:{uid}", "-v", f"{tmp}:/tmp:ro",
                      "--entrypoint", "cat", image, "/tmp/evidence-bundle.json", check=False)
        return run, read.stdout if read.returncode == 0 else ""
    finally:
        docker("rm", "-f", agent, check=False)


def check_bundle(label: str, run: subprocess.CompletedProcess[str], text: str) -> None:
    if run.returncode != 0:
        fail(f"{label}: the pod-mode scan exited {run.returncode}", run.stderr)
    if not text:
        fail(f"{label}: no bundle at /tmp/evidence-bundle.json", run.stderr)
    bundle = json.loads(text)
    if (bundle.get("host_id"), bundle.get("sandbox_name")) != ("ci", "ci/agent-finretail"):
        fail(f"{label}: agent key {bundle.get('host_id')!r}, {bundle.get('sandbox_name')!r}", run.stderr)
    instance = attribute(bundle, "agent_instance")
    if instance.get("status") != "ANSWERED" or (instance.get("value") or {}).get("pod", {}).get("uid") != POD_UID:
        fail(f"{label}: agent_instance: {instance}")
    if attribute(bundle, "sandbox_type").get("value") != "kubernetes":
        fail(f"{label}: sandbox_type: {attribute(bundle, 'sandbox_type')}")
    harness = attribute(bundle, "harness_identity")
    if harness.get("status") != "ANSWERED" or "2026.9.2" not in json.dumps(harness.get("value")):
        fail(f"{label}: harness_identity: the agent's process wasn't read as OpenClaw's: {harness}", run.stderr)
    if "gemini-flash-latest" not in json.dumps(attribute(bundle, "model_name").get("value")):
        fail(f"{label}: model_name: {attribute(bundle, 'model_name')}")
    if "finretail" not in json.dumps(attribute(bundle, "mcp_servers_declared").get("value")):
        fail(f"{label}: mcp_servers_declared: {attribute(bundle, 'mcp_servers_declared')}")
    credentials = attribute(bundle, "credential_inventory")
    if credentials.get("status") != "ANSWERED" or "AGENT_LLM_API_KEY" not in json.dumps(credentials.get("value")):
        fail(f"{label}: credential_inventory: the agent's environment wasn't read: {credentials}", run.stderr)
    # The message names which secret leaked, never any of its value.
    def leaked(secret: str) -> bool:
        return secret in text or secret in run.stdout or secret in run.stderr

    if leaked(SECRET_VALUE):
        fail(f"{label}: the agent's environment value reached the bundle or the logs")
    if leaked(FIXTURE_KEY):
        fail(f"{label}: the config's apiKey reached the bundle or the logs")
    print(f"ok: {label}: {len(bundle.get('attributes') or {})} attributes, harness and agent process read")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    check_slim(args.image)

    work = Path(tempfile.mkdtemp(prefix="scan-sidecar-"))
    try:
        config, podinfo = work / "config", work / "podinfo"
        config.mkdir()
        podinfo.mkdir()
        shutil.copy(FIXTURE, config / "openclaw.json")
        (podinfo / "labels").write_text(
            'app="agent-finretail"\npod-template-hash="58cd78b55d"\nrail.datrail.io/scan="true"\n'
            'rail.datrail.io/owner="support-platform"\n'
        )
        for path, mode in ((config, 0o755), (config / "openclaw.json", 0o644), (podinfo, 0o755), (podinfo / "labels", 0o644)):
            os.chmod(path, mode)

        # A non-root agent: the sidecar at its UID, with no capabilities.
        run, text = scan(args.image, work, AGENT_UID, ["--cap-drop", "ALL"])
        check_bundle(f"non-root agent (UID {AGENT_UID}), sidecar with no capabilities", run, text)

        # A root agent with the runtime's default capabilities: the sidecar
        # gets the same set (the webhook mirrors the agent's), and reads it.
        run, text = scan(args.image, work, 0, [])
        check_bundle("root agent, sidecar with the agent's capabilities", run, text)

        # Why it must: with none, the kernel refuses to let it read the
        # agent's process, and those fields are BLIND, never the sidecar's own.
        run, text = scan(args.image, work, 0, ["--cap-drop", "ALL"])
        if run.returncode != 0 or not text:
            fail("root agent, sidecar with no capabilities: the scan should still run", run.stderr)
        credentials = attribute(json.loads(text), "credential_inventory")
        if (credentials.get("status"), credentials.get("reason")) != ("BLIND", "NO_SOURCE_ACCESS"):
            fail(f"root agent read by a sidecar with no capabilities: {credentials}; "
                 "if the kernel now allows it, the webhook needn't mirror capabilities")
        print("ok: root agent, sidecar with no capabilities: the agent's process is BLIND, as expected")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
