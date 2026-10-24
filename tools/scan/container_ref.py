"""`openshell:<sandbox>`: the agent named by its OpenShell sandbox, not its container (DR-247).

OpenShell's Docker driver runs a sandbox's agent in a workload container
named after an id it generates, so the name changes each time the sandbox is
recreated. Anywhere RailMon takes the agent's container (RAIL_COLLECT_CONTAINER,
RAIL_LISTEN_CONTAINER, RAIL_FILES_CONTAINER, `scan --container`) it also takes
`openshell:<sandbox>`, and finds the container again on each attach and each
scan by the two labels OpenShell puts on it. A Docker name can't contain a
colon, so the prefix is never a container's own name.

Shared by the scanner and the listen/files/collect supervisors, so the one
lookup decides which container all four watch.
"""

from __future__ import annotations

import re
import subprocess

PREFIX = "openshell:"
SANDBOX_LABEL = "openshell.ai/sandbox-name"
ROLE_LABEL = "openshell.ai/isolation-role=sandbox"
# A name OpenShell accepts is a DNS-style label; anything else can't match a
# label value we could safely pass to `docker ps --filter`.
SANDBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def sandbox_name(ref: str | None) -> str | None:
    """The sandbox `ref` names, or None when it names a container."""
    if ref and ref.startswith(PREFIX):
        return ref[len(PREFIX):]
    return None


def resolve(ref: str, docker: str = "docker", timeout: float = 10.0) -> tuple[str | None, str | None]:
    """(container, problem) for `ref`.

    A container name or id comes back as it is. For `openshell:<sandbox>` it
    is the name of the one running container labelled as that sandbox's
    workload. None with no problem means none is running yet (not started, or
    between a delete and a create); None with a problem means the name is not
    one OpenShell gives, Docker didn't answer, or several containers match, so
    which one is the agent can't be told and none is watched."""
    name = sandbox_name(ref)
    if name is None:
        return ref, None
    if not SANDBOX_NAME.fullmatch(name):
        return None, f"{ref!r} does not name an OpenShell sandbox"
    try:
        out = subprocess.run(
            [docker, "ps", "--format", "{{.Names}}",
             "--filter", f"label={SANDBOX_LABEL}={name}", "--filter", f"label={ROLE_LABEL}"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"cannot ask Docker for OpenShell sandbox {name}'s container: {exc}"
    if out.returncode != 0:
        return None, f"cannot ask Docker for OpenShell sandbox {name}'s container: {out.stderr.strip()}"
    names = sorted(line.strip() for line in out.stdout.splitlines() if line.strip())
    if len(names) > 1:
        return None, f"OpenShell sandbox {name} has {len(names)} running containers ({', '.join(names)})"
    return (names[0], None) if names else (None, None)
