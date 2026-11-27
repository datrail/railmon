"""in_layer_deleted_secrets, from an image's layers (RC-553, from the RC-406
prototype).

A secret a Dockerfile adds in one layer and deletes in a later one is gone
from the running filesystem but still in the image, for anyone who pulls it.
This walks an image's layers in order and reports each file whose name looks
like a secret that an earlier layer added and a later layer deleted, by a
whiteout (.wh.<name>) of the file or a directory above it, or an opaque
whiteout (.wh..wh..opq) of a directory above it. Names, layer indexes and
sizes only: no file content is read.

`layer_entries` reads one uncompressed layer tar as a stream, for a caller
that fetches layers itself (gke-scan's registry reader,
gke/central_service/registry.py), and `deleted_across` puts the layers
together in order. Only a layer's secret-looking files and its whiteouts are
kept, so memory doesn't grow with the layer, and what a hostile layer can make
it keep is capped (LayerCapExceeded): a tar header gets 1 MiB past where it
starts, global pax headers 1 MiB in all, and the kept names 8 MiB. `deleted_secret_files` does the
same for a `docker save` archive, whose uncompressed layer tars are named or
identified by their diff IDs, so a layer's place is found by hashing it
against the image's RootFS.Layers; a layer that does not hash to one keeps
its archive order.

Like the rest of the scanner, it uses only the standard library.
"""

from __future__ import annotations

import bisect
import hashlib
import posixpath
import re
import tarfile
from typing import IO, Any

# Judged on the file's own name. A key or env file by its extension; any other
# name by the words in it, unless it is code or documentation (a package
# removal deletes files like CPAN/HTTP/Credentials.pm and PullParserToken.pm,
# which are modules, not secrets).
SECRET_FILE = re.compile(r"(^\.env(\..+)?$|\.env$|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|\.jks$|\.keystore$|^id_(rsa|ecdsa|ed25519|dsa)$)", re.I)
SECRET_WORD = re.compile(r"(secret|token|passw|credential|api[-_]?key|private[-_]?key)", re.I)
CODE_OR_DOCS = re.compile(
    r"\.(pm|pl|pod|py|pyc|pyi|js|mjs|cjs|ts|map|rb|go|java|class|c|h|cc|hpp|so|a|o|html?|css|md|rst|[0-9](\.gz)?|gz|mo|po)$",
    re.I,
)


def secretish(path: str) -> bool:
    name = path.rpartition("/")[2]
    if SECRET_FILE.search(name):
        return True
    return bool(SECRET_WORD.search(name)) and not CODE_OR_DOCS.search(name)


class _Hashing:
    """A read-only stream that hashes what passes through it."""

    def __init__(self, raw: IO[bytes]):
        self.raw, self.digest = raw, hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.raw.read(size)
        self.digest.update(data)
        return data

    def drain(self) -> str:
        while self.read(1 << 20):
            pass
        return "sha256:" + self.digest.hexdigest()


class LayerCapExceeded(Exception):
    """A layer whose tar headers, or whose kept names, pass the caps below."""


# A layer can be built by whoever controls the image, so what one layer can
# make this hold is capped. A tar header with its GNU long name or pax records
# gets MAX_HEADER_BYTES (tarfile reads one whole into memory), counted from
# where tarfile will read the next header, not from a member's declared size,
# which a symlink or a sparse file can set to anything; global pax headers,
# which tarfile keeps for the rest of the layer, get MAX_HEADER_BYTES in all;
# a name longer than PATH_MAX is no path a container can have, so it isn't
# kept; and the names kept get MAX_KEPT_BYTES, counted with what a kept entry
# costs.
MAX_HEADER_BYTES = 1 << 20
MAX_PATH = 4096
MAX_KEPT_BYTES = 8 << 20
ENTRY_OVERHEAD = 128


def _tar_path(name: str) -> str:
    """A member's absolute path, normalized as an extractor would place it
    (`./`, `//`, `/./` and `..` resolved, never a name's own leading dot), so
    that a file and the whiteout that deletes it compare equal however the
    layer spells them."""
    return posixpath.normpath("/" + name.lstrip("/"))


class _HeaderBound:
    """The uncompressed layer as tarfile reads it, refusing to read further
    than MAX_HEADER_BYTES past where the next header starts."""

    def __init__(self, raw: IO[bytes]):
        self.raw, self.position, self.end = raw, 0, MAX_HEADER_BYTES

    def read(self, size: int = -1) -> bytes:
        data = self.raw.read(size)
        self.position += len(data)
        if self.position > self.end:
            raise LayerCapExceeded(f"a tar header is over {MAX_HEADER_BYTES} bytes")
        return data

    def member(self, layer: tarfile.TarFile) -> None:
        """After a member: tarfile's own offset is where the next header
        starts, past exactly the data it skips."""
        self.end = layer.offset + MAX_HEADER_BYTES


class _GlobalHeaders(dict):
    """tarfile's global pax headers, which it keeps for the rest of the
    layer, refused past MAX_HEADER_BYTES in all."""

    def __init__(self, headers: dict[str, str]):
        super().__init__(headers)
        self.size = sum(len(k) + len(v) for k, v in headers.items())

    def __setitem__(self, key: str, value: str) -> None:
        self.size += len(key) + len(value)
        if self.size > MAX_HEADER_BYTES:
            raise LayerCapExceeded(f"the layer's global pax headers are over {MAX_HEADER_BYTES} bytes")
        super().__setitem__(key, value)


def kept_bytes(entries: tuple[dict[str, int], set[str], set[str]]) -> int:
    """What one layer's kept entries count against MAX_KEPT_BYTES."""
    added, whiteouts, opaque = entries
    return sum(len(path) + ENTRY_OVERHEAD for group in (added, whiteouts, opaque) for path in group)


def _layer_entries(stream: IO[bytes], max_kept_bytes: int = MAX_KEPT_BYTES) -> tuple[dict[str, int], set[str], set[str]] | None:
    """(secret-ish files added {path: size}, whiteout targets, opaque dirs) of
    one layer tar, or None if not a tar. LayerCapExceeded past a header or
    kept-names cap."""
    added: dict[str, int] = {}
    whiteouts: set[str] = set()
    opaque: set[str] = set()
    kept = 0
    bounded = _HeaderBound(stream)
    try:
        with tarfile.open(fileobj=bounded, mode="r|") as layer:
            layer.pax_headers = _GlobalHeaders(layer.pax_headers)
            while (member := layer.next()) is not None:
                layer.members.clear()  # a streamed tar still keeps every member it has read
                bounded.member(layer)
                path = _tar_path(member.name)
                if len(path) > MAX_PATH:
                    continue
                directory, _, base = path.rpartition("/")
                if base == ".wh..wh..opq":
                    opaque.add(directory or "/")
                elif base.startswith(".wh."):
                    if base[4:] in ("", ".", ".."):
                        continue  # names no file
                    whiteouts.add(f"{directory}/{base[4:]}")
                elif member.isfile() and secretish(path):
                    added[path] = member.size
                else:
                    continue
                kept += len(path) + ENTRY_OVERHEAD
                if kept > max_kept_bytes:
                    raise LayerCapExceeded(f"the layer's secret-looking names and whiteouts are over "
                                           f"{max_kept_bytes} bytes")
    except tarfile.ReadError:
        # An empty layer is an empty tar to containerd (Go's archive/tar reads
        # no bytes as no entries), so it is one here too, not "not a tar".
        return (added, whiteouts, opaque) if bounded.position == 0 else None
    return added, whiteouts, opaque


def deleted_secret_files(archive: IO[bytes], diff_ids: list[str]) -> dict[str, Any]:
    """Walk a `docker save` stream; the secret-ish files a later layer deletes."""
    blobs: dict[str, tuple[dict[str, int], set[str], set[str]]] = {}
    with tarfile.open(fileobj=archive, mode="r|") as outer:
        for member in outer:
            if not member.isfile() or member.name.endswith(".json") or member.size < 1024:
                continue
            stream = _Hashing(outer.extractfile(member))
            entries = _layer_entries(stream)
            digest = stream.drain()
            if entries is not None:
                blobs[digest] = entries
    # The image's own layer order; a layer the image repeats (two identical
    # empty layers, say) is one blob in the archive but two places here.
    layers = [blobs[d] for d in diff_ids if d in blobs] + [e for d, e in blobs.items() if d not in diff_ids]
    return deleted_across(layers)


def layer_entries(stream: IO[bytes], max_kept_bytes: int = MAX_KEPT_BYTES) -> tuple[dict[str, int], set[str], set[str]] | None:
    """One uncompressed layer tar's entries, for a caller that reads layers
    itself (from a registry, say), keeping at most `max_kept_bytes` of names
    (what is left of the image's MAX_KEPT_BYTES, for a caller that reads
    several layers)."""
    return _layer_entries(stream, max_kept_bytes)


def deleted_across(layers: list[tuple[dict[str, int], set[str], set[str]]]) -> dict[str, Any]:
    """The secret-ish files a later layer deletes, given each layer's entries in order.

    The paths still present are kept sorted, so the ones a whiteout or an
    opaque directory deletes are a range found by bisection: the work grows
    with the entries kept, not with the files present times the whiteouts,
    which a hostile image could make take minutes."""
    present: dict[str, tuple[int, int]] = {}  # secret-ish path -> (layer index, size)
    ordered: list[str] = []  # the same paths, sorted
    deleted = []
    for index, (added, whiteouts, opaque) in enumerate(layers):
        gone: list[str] = []
        # A whiteout deletes its target and everything under it; an opaque
        # directory, everything under it. "/" sorts just before "0", so the
        # paths under d are those from d + "/" up to d + "0".
        for target, itself in [(t, True) for t in whiteouts] + [(d.rstrip("/"), False) for d in opaque]:
            if itself:
                at = bisect.bisect_left(ordered, target)
                if at < len(ordered) and ordered[at] == target:
                    gone.append(ordered.pop(at))
            start = bisect.bisect_left(ordered, target + "/")
            end = bisect.bisect_left(ordered, target + "0", start)
            if end > start:
                gone.extend(ordered[start:end])
                del ordered[start:end]
        for path in sorted(gone):
            first, size = present.pop(path)
            deleted.append({"path": path, "added_in_layer": first, "deleted_in_layer": index, "size": size})
        for path, size in added.items():
            if path not in present:
                bisect.insort(ordered, path)
            present[path] = (index, size)
    return {"layers": len(layers), "deleted": deleted}
