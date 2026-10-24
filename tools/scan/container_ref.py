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
# What a sandbox name may be here: letters, digits, `.`, `_` and `-`, so it
# is one `docker ps --filter label=…` value and can't add a filter or a flag.
SANDBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
# The multi-agent key rule (compose_evidence_bundle_v2.KEY, RailDash's
# _V2_AGENT_KEY): a sandbox name is the default agent key only if it is one.
AGENT_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def sandbox_name(ref: str | None) -> str | None:
    """The sandbox `ref` names, or None when it names a container."""
    if ref and ref.startswith(PREFIX):
        return ref[len(PREFIX):]
    return None


def invalid(ref: str | None) -> str | None:
    """Why `ref` can never resolve, or None. A supervisor given such a ref
    exits instead of waiting for a container that can't exist."""
    name = sandbox_name(ref)
    if name is not None and not SANDBOX_NAME.fullmatch(name):
        return f"{ref!r} does not name an OpenShell sandbox"
    return None


def default_agent_key(ref: str | None) -> str | None:
    """The sandbox's name as the agent key, which stays the same across a
    recreate while its container's name doesn't; None for a container name,
    or a sandbox name that isn't a valid key (then pass --agent-key)."""
    name = sandbox_name(ref)
    return name if name is not None and AGENT_KEY.fullmatch(name) else None


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
    problem = invalid(ref)
    if problem:
        return None, problem
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
        return None, (f"OpenShell sandbox {name} has {len(names)} running containers "
                      f"({', '.join(names)}); none is watched until exactly one runs")
    return (names[0], None) if names else (None, None)
