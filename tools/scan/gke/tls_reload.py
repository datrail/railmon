"""A server certificate that follows its files (RC-518).

gke-scan and the scan-sidecar webhook serve the certificates the chart puts in
their TLS Secrets. The chart signs new ones on every render, and the kubelet
swaps a mounted Secret's files in place (a new folder and one atomic rename),
so a pod that loaded its certificate once at start would keep serving the old
one: until it expires, or, when the chart makes a new CA, until the API server
or the sidecars stop trusting it. Each new connection here checks the files
and loads them again when they have changed, so a running pod serves the
certificate its Secret holds, with no restart.

Standard library only, like the two servers that load it.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
from typing import Callable


def _new_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return context


class ReloadingContext:
    """The server SSLContext for a certificate and key file, loaded again
    whenever either file changes.

    The files are first loaded here, so a certificate that won't load at
    start raises, as a plain SSLContext would. After that, one that won't
    load (a half-written file, say) is logged once and the last good one
    keeps serving until good files arrive.
    """

    def __init__(self, cert_file: str, key_file: str, log: Callable[[str], None] | None = None):
        self.cert_file, self.key_file = cert_file, key_file
        self._log = log or (lambda line: None)
        self._lock = threading.Lock()
        self._stamp = self._read_stamp()
        self._context = _new_context(cert_file, key_file)
        self._failed_stamp: tuple | None = None

    def _read_stamp(self) -> tuple:
        # stat follows the Secret volume's links, so the kubelet's swap
        # changes the inode even when the size and time happen to match.
        stamps = []
        for path in (self.cert_file, self.key_file):
            info = os.stat(path)
            stamps.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns))
        return tuple(stamps)

    def current(self) -> ssl.SSLContext:
        """The context for the next connection."""
        with self._lock:
            try:
                stamp = self._read_stamp()
            except OSError:
                return self._context  # mid-swap: try again on the next connection
            if stamp == self._stamp or stamp == self._failed_stamp:
                return self._context
            try:
                context = _new_context(self.cert_file, self.key_file)
            except (OSError, ssl.SSLError, ValueError) as error:
                self._failed_stamp = stamp
                self._log(f"the new certificate in {self.cert_file} wouldn't load "
                          f"({type(error).__name__}); kept the last one")
                return self._context
            self._context, self._stamp, self._failed_stamp = context, stamp, None
            self._log(f"reloaded the certificate in {self.cert_file}")
            return self._context


def wrap_accepted(conn: socket.socket, tls: ReloadingContext) -> ssl.SSLSocket:
    """An accepted connection, wrapped with the current certificate. The
    handshake runs on the first read, in the request's own thread under its
    read timeout, so a client that stalls in it can't hold up the accept loop."""
    return tls.current().wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
