"""Pod mode (RC-509): read the agent's own process, not the sidecar's.

With spec.shareProcessNamespace the sidecar sees every process in the pod
under /proc. It picks the agent's main process and reads it there: its
environment (names reach the bundle, never values), its user, its command
line, its runtimes and its /etc/os-release, all through the process's own
root (/proc/<pid>/root). Nothing is executed in the agent's container.

Reading another process's environ and root needs the same user and no more
capabilities than the sidecar has, which a sidecar given the agent's
securityContext meets. When no such process can be read (no shared process
namespace, different UIDs, the agent restarting mid-scan), the caller
reports the fields that come from it BLIND rather than falling back to the
sidecar's own values.

Like pod_mode.py, this module imports nothing of railmon's.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

PROC_DIR = Path("/proc")
ENVIRON_MAX_BYTES = 256_000
SMALL_FILE_MAX_BYTES = 64_000
# Where an OpenClaw install keeps its build stamp, under the agent's root.
OPENCLAW_PACKAGE_DIRS = (
    "/usr/local/lib/node_modules/openclaw",
    "/usr/lib/node_modules/openclaw",
    "/opt/openclaw",
    "/app",
)


def _read(path: Path, max_bytes: int = SMALL_FILE_MAX_BYTES) -> str | None:
    """A kernel file under /proc/<pid> (environ, cmdline, status). Files in
    the agent's own filesystem go through read_in_root instead."""
    try:
        with path.open("rb") as handle:
            return handle.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return None


def _json(root: Path, path: str) -> Any | None:
    text = read_in_root(root, path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        # A deeply nested document raises RecursionError, not ValueError.
        # Only top-level keys are read from it, so depth short of that is safe.
        return None


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _parse_environ(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in text.split("\x00"):
        key, sep, value = item.partition("=")
        if sep and key:
            env[key] = value
    return env


def _ids(status: str | None) -> tuple[int | None, int | None]:
    """The real uid and gid from /proc/<pid>/status."""
    uid = gid = None
    for line in (status or "").splitlines():
        name, _, rest = line.partition(":")
        fields = rest.split()
        if name == "Uid" and fields and fields[0].isdigit():
            uid = int(fields[0])
        elif name == "Gid" and fields and fields[0].isdigit():
            gid = int(fields[0])
    return uid, gid


def _passwd_name(root: Path, uid: int | None) -> str | None:
    """The user name for `uid` in the agent's own /etc/passwd."""
    if uid is None:
        return None
    for line in (read_in_root(root, "/etc/passwd") or "").splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2] == str(uid):
            return fields[0] or None
    return None


# Directories are opened only to walk through them: O_PATH (Linux) needs
# search permission alone, and O_NOFOLLOW refuses a link swapped in after it
# was checked.
_DIR_FLAGS = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
              | getattr(os, "O_PATH", 0))
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


def _walk_in_root(root: Path, path: str, open_file: bool, same_device: bool = True,
                  hops: int = 32) -> tuple[list[str], int | None] | None:
    """Resolve `path` inside the container whose root is `root`, one
    component at a time from a handle on that root.

    The kernel resolves an absolute link found under /proc/<pid>/root
    against the *reader's* root, so a plain open of <root>/etc/os-release
    that the agent pointed at /proc/self/environ reads the sidecar's own
    environment. Here every link is read and followed by hand, an absolute
    target restarts at the agent's root, and `..` never climbs above it.
    With `same_device`, no component may leave the root's filesystem: the
    agent's own /proc is the sidecar's too (one process namespace), so a
    relative link into it would reach the sidecar the same way.

    Returns the resolved components and, with `open_file`, a descriptor of
    the regular file (opened without blocking, so a FIFO can't hang the
    scan), or None when there is no such path or it is refused."""
    try:
        root_fd = os.open(root, _DIR_FLAGS & ~os.O_NOFOLLOW)  # /proc/<pid>/root is a link to follow
    except OSError:
        return None
    stack, names = [root_fd], []
    pending = [part for part in path.split("/") if part]
    try:
        root_dev = os.fstat(root_fd).st_dev
        while pending:
            part = pending.pop(0)
            if part == ".":
                continue
            if part == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                    names.pop()
                continue
            info = os.stat(part, dir_fd=stack[-1], follow_symlinks=False)
            if same_device and info.st_dev != root_dev:
                return None
            if stat.S_ISLNK(info.st_mode):
                hops -= 1
                if hops < 0:
                    return None
                target = os.readlink(part, dir_fd=stack[-1])
                if target.startswith("/"):
                    while len(stack) > 1:
                        os.close(stack.pop())
                    names = []
                pending = [t for t in target.split("/") if t] + pending
                continue
            if pending:
                if not stat.S_ISDIR(info.st_mode):
                    return None
                stack.append(os.open(part, _DIR_FLAGS, dir_fd=stack[-1]))
                names.append(part)
                continue
            names.append(part)
            if not open_file:
                return names, None
            if not stat.S_ISREG(info.st_mode):
                return None
            fd = os.open(part, _FILE_FLAGS, dir_fd=stack[-1])
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                    or (same_device and opened.st_dev != root_dev)):
                os.close(fd)
                return None
            return names, fd
        return (names, None) if not open_file else None
    except OSError:
        return None
    finally:
        for fd in stack:
            os.close(fd)


def read_in_root(root: Path, path: str, max_bytes: int = SMALL_FILE_MAX_BYTES) -> str | None:
    """A regular file's text inside the agent's root, read as `_walk_in_root`
    resolves it: never the sidecar's own file, never a FIFO or device."""
    walked = _walk_in_root(root, path, open_file=True)
    if walked is None or walked[1] is None:
        return None
    fd = walked[1]
    try:
        chunks, size = [], 0
        while size < max_bytes:
            chunk = os.read(fd, max_bytes - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def resolve_under_root(root: Path, path: str, same_device: bool = True) -> str | None:
    """`path` as the agent's container resolves it, as an absolute path
    inside that container, or None when it doesn't exist or is refused."""
    walked = _walk_in_root(root, path, open_file=False, same_device=same_device)
    return None if walked is None else "/" + "/".join(walked[0])


def runtime_versions(root: Path, env: dict[str, str]) -> dict[str, str]:
    """The agent's runtimes, read rather than run: OpenClaw's build stamp
    (dist/build-info.json, else package.json) for the openclaw on the agent's
    PATH or in a usual install folder, and the base image's NODE_VERSION and
    PYTHON_VERSION. The same strings `openclaw --version`, `node --version`
    and `python3 --version` print."""
    versions: dict[str, str] = {}
    package_dirs: list[str] = []
    for directory in (env.get("PATH") or "").split(":"):
        relative = resolve_under_root(root, f"{directory.rstrip('/')}/openclaw") if directory else None
        if relative is None:
            continue
        # A link into the package, or npm's node_modules/.bin wrapper beside it.
        for marker in ("/node_modules/openclaw/", "/node_modules/.bin/"):
            if marker in relative:
                package_dirs.append(relative.split(marker, 1)[0] + "/node_modules/openclaw")
                break
        break
    for directory in dict.fromkeys(package_dirs + list(OPENCLAW_PACKAGE_DIRS)):
        package_dir = resolve_under_root(root, directory)
        if package_dir is None:
            continue
        info = _json(root, f"{package_dir}/dist/build-info.json")
        package = _json(root, f"{package_dir}/package.json")
        if isinstance(package, dict) and package.get("name") not in (None, "openclaw"):
            continue
        info = info if isinstance(info, dict) else {}
        package = package if isinstance(package, dict) else {}
        version = info.get("version") or package.get("version")
        if version:
            commit = str(info.get("commit") or "")[:7]
            versions["openclaw"] = f"OpenClaw {version}" + (f" ({commit})" if commit else "")
            break
    if env.get("NODE_VERSION"):
        versions["node"] = "v" + env["NODE_VERSION"].lstrip("v")
    if env.get("PYTHON_VERSION"):
        versions["python"] = "Python " + env["PYTHON_VERSION"]
    return versions


def _is_pause(cmdline: str) -> bool:
    return cmdline.split()[0].rsplit("/", 1)[-1] == "pause"


def find_agent_process(config_paths: list[Path], proc: Path | None = None,
                       own_pid: int | None = None) -> tuple[dict[str, Any] | None, str]:
    """The agent's main process, and why none was found when it wasn't.

    Candidates are processes whose root isn't the sidecar's own (so not the
    sidecar's processes), leaving out the pod's pause process. Of those whose
    environment can be read, one whose root holds the agent's config wins,
    then the lowest-numbered. Called on every scan, so a restarted agent,
    which comes back under a new pid, is found again.
    """
    proc = proc or PROC_DIR
    own_pid = os.getpid() if own_pid is None else own_pid
    try:
        own_root = os.stat(proc / "self" / "root")
        entries = list(proc.iterdir())
    except OSError:
        return None, "no /proc to read"
    seen_other = False
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    # Each container has its own root; an agent's own children share its root.
    containers: set[tuple[int, int]] = set()
    for entry in entries:
        if not entry.name.isdigit() or int(entry.name) == own_pid:
            continue
        cmdline = (_read(entry / "cmdline") or "").replace("\x00", " ").strip()
        try:
            root_stat = os.stat(entry / "root")
        except PermissionError:
            # Another user's process, so another container's: the pod does
            # share its process namespace, and this one can't be read.
            # (cmdline stays world-readable, which leaves out the pause process.)
            if cmdline and not _is_pause(cmdline):
                seen_other = True
            continue
        except OSError:
            continue  # gone since the listing
        if _same_file(root_stat, own_root):
            continue
        if not cmdline or _is_pause(cmdline):
            continue
        seen_other = True
        environ = _read(entry / "environ", ENVIRON_MAX_BYTES)
        if environ is None:
            continue
        root = entry / "root"
        # The config is on its own volume, so this check may cross devices;
        # it only ranks the agent's own processes and reads nothing.
        holds_config = any(resolve_under_root(root, str(path), same_device=False) is not None
                           for path in config_paths)
        containers.add((root_stat.st_dev, root_stat.st_ino))
        candidates.append((0 if holds_config else 1, int(entry.name),
                           {"pid": int(entry.name), "root": root, "cmdline": cmdline,
                            "env": _parse_environ(environ)}))
    if candidates:
        rank, _, agent = min(candidates, key=lambda c: c[:2])
        # How sure the choice is, for the caller to say: an agent that can run
        # code in its container can also start a decoy beside itself.
        agent["holds_config"] = rank == 0
        agent["containers"] = len(containers)
        return agent, "found"
    if seen_other:
        return None, "the agent's process can't be read (a different user, or it is restarting)"
    return None, "no other container's process is visible (the pod doesn't share its process namespace)"


def read_subject(config_paths: list[Path], proc: Path | None = None,
                 own_pid: int | None = None) -> tuple[dict[str, Any] | None, str]:
    """What the scan describes in place of the sidecar: the agent process's
    environment, command line, user, runtimes and system files, read through
    /proc/<pid>. None, with the reason, when there is no readable agent."""
    agent, reason = find_agent_process(config_paths, proc, own_pid)
    if agent is None:
        return None, reason
    root: Path = agent["root"]
    env: dict[str, str] = agent["env"]
    uid, gid = _ids(_read(root.parent / "status"))
    cgroup = _read(root.parent / "cgroup")
    return {
        "pid": agent["pid"],
        "root": str(root),
        "env": env,
        "cmdline": agent["cmdline"],
        "cgroup": cgroup,
        "holds_config": agent.get("holds_config", False),
        "containers": agent.get("containers", 1),
        "uid": uid,
        "gid": gid,
        "username": _passwd_name(root, uid) or env.get("USER") or env.get("LOGNAME"),
        "home": env.get("HOME"),
        "runtimes": runtime_versions(root, env),
        "os_release": read_in_root(root, "/etc/os-release"),
        "machine_id": read_in_root(root, "/etc/machine-id", 256),
    }, "found"
