"""Start-up checks for RailMon's sensors: name what is missing (DR-301).

When a sensor lacks a permission, the kernel's tracing folder or Docker, the
messages it gave pointed at the wrong cause: `collect` said no process in the
agent's container loads libssl, libbpf said the kernel may not support BPF,
and a supervisor waited forever for a running container it could not ask
Docker about (DR-288, fix 3). These checks name the missing piece and how to
grant it.

They report and never block: each problem is one stderr line, and the sensor
then starts as it always did. A check that is wrong about some environment
must not stop a capture that would have worked.

    python3 preflight.py collect|listen|files [--container NAME]

checks what that sensor needs at start. The supervisors also call
`container_problem`, `pid_problem` and `maps_problem` while they wait, so a
wait that cannot end says why.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

PROC = "/proc"
TRACEFS = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")
DOCKER_SOCKET = "/var/run/docker.sock"

CAP_SYS_ADMIN = 21
CAP_PERFMON = 38
CAP_BPF = 39
CAP_NAMES = {CAP_SYS_ADMIN: "SYS_ADMIN", CAP_PERFMON: "PERFMON", CAP_BPF: "BPF"}

# The fix the compose file needs, written once.
GRANT_CAPS = "add them with cap_add (or run the container privileged)"
GRANT_PID = "run this container in the host's PID namespace (pid: host)"


def effective_caps(proc: str = PROC) -> int | None:
    """This process's effective capability set, or None if unreadable."""
    try:
        with open(f"{proc}/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return None


def last_cap(proc: str = PROC) -> int:
    """The highest capability the kernel knows. CAP_BPF and CAP_PERFMON came
    in Linux 5.8; before that CAP_SYS_ADMIN covers what they do."""
    try:
        with open(f"{proc}/sys/kernel/cap_last_cap") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return CAP_BPF


def capability_problem(caps: int | None, last: int) -> str | None:
    """Every eBPF sensor loads programs and attaches probes (BPF, PERFMON),
    and `collect` reads the agent's memory maps (/proc/<pid>/map_files,
    SYS_ADMIN). SYS_ADMIN is also what mounts tracefs."""
    if caps is None:
        return None
    need = [CAP_SYS_ADMIN] + ([CAP_PERFMON, CAP_BPF] if last >= CAP_BPF else [])
    missing = [CAP_NAMES[c] for c in need if not caps >> c & 1]
    if not missing:
        return None
    return (f"missing capabilit{'y' if len(missing) == 1 else 'ies'} "
            f"{', '.join(missing)}: the eBPF probes can't load without "
            f"{'it' if len(missing) == 1 else 'them'}; {GRANT_CAPS}")


def tracefs_problem(roots=TRACEFS, caps: int | None = None) -> str | None:
    """`listen` and `files` attach AgentSight's process probe to tracepoints,
    whose ids are under tracefs. It is mounted at start when it can be
    (agentsight_adapter.ensure_tracefs), which needs SYS_ADMIN."""
    if any(os.path.isdir(os.path.join(root, "events")) for root in roots):
        return None
    if caps is not None and caps >> CAP_SYS_ADMIN & 1:
        return None  # ensure_tracefs mounts it, and says so if it can't
    return (f"the kernel's tracing folder isn't visible ({roots[0]} has no events/) "
            f"and can't be mounted without SYS_ADMIN: mount {roots[0]} into this "
            f"container read-only (volumes: - {roots[0]}:{roots[0]}:ro)")


def docker_problem(docker: str = "docker", env=None, socket: str = DOCKER_SOCKET) -> str | None:
    """None when the Docker daemon answers; otherwise which of: no CLI, no
    socket or DOCKER_HOST, no permission, a daemon that doesn't answer."""
    env = os.environ if env is None else env
    try:
        done = subprocess.run([docker, "version", "--format", "{{.Server.APIVersion}}"],
                              capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return f"no Docker client ({docker}) in this image, so it can't find the agent's container"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Docker didn't answer: {exc}"
    if done.returncode == 0:
        return None
    err = (done.stderr or "").strip()
    host = env.get("DOCKER_HOST", "")
    if "permission denied" in err.lower():
        return (f"no permission on the Docker socket ({host or socket}); "
                "it is how this sensor finds the agent's container")
    if host:
        return (f"Docker at DOCKER_HOST={host} doesn't answer "
                f"({err.splitlines()[-1] if err else done.returncode})")
    if not os.path.exists(socket):
        return (f"no Docker access: {socket} isn't mounted and DOCKER_HOST isn't set; "
                f"mount {socket} (or set DOCKER_HOST to a Docker API proxy) so this "
                "sensor can find the agent's container")
    return f"the Docker daemon at {socket} doesn't answer ({err.splitlines()[-1] if err else done.returncode})"


def container_problem(docker: str, container: str, env=None,
                      socket: str = DOCKER_SOCKET) -> str | None:
    """Why waiting for `container` to run may never end: Docker unreachable,
    or no container by that name. None when it exists (running or not) or is
    an `openshell:` sandbox, whose lookup reports its own problems."""
    if container.startswith("openshell:"):
        return None
    problem = docker_problem(docker, env, socket)
    if problem:
        return problem
    try:
        done = subprocess.run([docker, "inspect", "-f", "{{.State.Status}}", container],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 and "no such" in (done.stderr or "").lower():
        return (f"no container named {container}: check AGENT_CONTAINER "
                "(`docker ps` lists the running ones)")
    return None


def pid_problem(pid: int, proc: str = PROC) -> str | None:
    """Docker names the agent's host PID; outside the host's PID namespace
    there is no such process here to follow."""
    if pid and not os.path.isdir(f"{proc}/{pid}"):
        return f"the agent's process (host pid {pid}) isn't visible here: {GRANT_PID}"
    return None


def maps_problem(pid: int, proc: str = PROC) -> str | None:
    """`collect` finds a loaded libssl through /proc/<pid>/map_files, whose
    links the kernel resolves only for SYS_ADMIN. Without it every lookup
    fails and the agent looked as though it used no TLS."""
    base = f"{proc}/{pid}/map_files"
    try:
        names = os.listdir(base)
    except PermissionError:
        return (f"can't read the agent's memory maps ({base}): reading them needs "
                "SYS_ADMIN; add it with cap_add (or run the container privileged)")
    except OSError:
        return None
    for name in names[:1]:
        try:
            os.stat(os.path.join(base, name))
        except PermissionError:
            return (f"can't read the agent's memory maps ({base}): reading them needs "
                    "SYS_ADMIN; add it with cap_add (or run the container privileged)")
        except OSError:
            return None
    return None


class Waiting:
    """Says why a supervisor is waiting: once per reason, asking `explain`
    again at most every `every` seconds, since a reason may cost a Docker
    call and the supervisors poll every second or two. A new `kind` of wait
    (the container, then a TLS user) asks at once."""

    def __init__(self, log, every: float = 30.0, clock=time.monotonic):
        self.log, self.every, self.clock = log, every, clock
        self.kind: str | None = None
        self.logged: str | None = None
        self.next = 0.0

    def wait(self, kind: str, explain) -> None:
        now = self.clock()
        if kind == self.kind and now < self.next:
            return
        self.kind, self.next = kind, now + self.every
        reason = explain()
        if reason != self.logged:
            self.log(reason)
            self.logged = reason

    def clear(self) -> None:
        self.kind, self.logged, self.next = None, None, 0.0


def startup_problems(command: str, container: str | None = None, *, proc: str = PROC,
                     tracefs=TRACEFS, docker: str = "docker", env=None,
                     socket: str = DOCKER_SOCKET) -> list[str]:
    """What `command` (collect, listen or files) is missing before it starts."""
    problems = []
    caps = effective_caps(proc)
    problem = capability_problem(caps, last_cap(proc))
    if problem:
        problems.append(problem)
    if command in ("listen", "files"):
        problem = tracefs_problem(tracefs, caps)
        if problem:
            problems.append(problem)
    if container:
        problem = container_problem(docker, container, env, socket)
        if problem:
            problems.append(problem)
        else:
            problem = pid_problem(_running_pid(docker, container), proc)
            if problem:
                problems.append(problem)
    return problems


def _running_pid(docker: str, container: str) -> int:
    """The container's host PID while it runs, else 0 (an `openshell:`
    sandbox is left to the supervisor's own lookup)."""
    if container.startswith("openshell:"):
        return 0
    try:
        done = subprocess.run([docker, "inspect", "-f", "{{.State.Pid}}", container],
                              capture_output=True, text=True, timeout=15)
        return int(done.stdout.strip()) if done.returncode == 0 else 0
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("collect", "listen", "files"))
    parser.add_argument("--container", help="the agent's container, when the sensor follows one")
    args = parser.parse_args(argv)
    docker = os.environ.get("RAIL_DOCKER", "docker")
    for problem in startup_problems(args.command, args.container, docker=docker):
        print(f"[railmon {args.command}] start-up check: {problem}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
