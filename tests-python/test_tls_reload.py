"""tools/scan/gke/tls_reload.py: the webhook's and gke-scan's certificate
follows its files, so a certificate the chart renews reaches a running pod
without a restart (RC-518)."""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gke_tls_reload", ROOT / "tools" / "scan" / "gke" / "tls_reload.py")
assert spec is not None and spec.loader is not None
tls_reload = importlib.util.module_from_spec(spec)
sys.modules["gke_tls_reload"] = tls_reload
spec.loader.exec_module(tls_reload)


def make_cert(folder: Path, name: str) -> tuple[Path, Path]:
    """A self-signed certificate for 127.0.0.1, written under `name`."""
    cert, key = folder / f"{name}.crt", folder / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", f"/CN={name}",
         "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    return cert, key


def swap_in(folder: Path, name: str, cert_link: Path, key_link: Path) -> None:
    """Point the served files at another certificate the way the kubelet
    updates a Secret volume: a new folder, then one atomic rename."""
    data = folder / f"..data-{name}"
    data.mkdir()
    shutil.copy(folder / f"{name}.crt", data / "tls.crt")
    shutil.copy(folder / f"{name}.key", data / "tls.key")
    tmp = folder / "..data.tmp"
    os.symlink(data.name, tmp)
    os.replace(tmp, folder / "..data")
    for link, target in ((cert_link, "..data/tls.crt"), (key_link, "..data/tls.key")):
        if not link.is_symlink():
            os.symlink(target, link)


def served_subject(port: int, cafile: Path) -> str:
    context = ssl.create_default_context(cafile=str(cafile))
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # as the servers require
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            subject = dict(item[0] for item in tls.getpeercert()["subject"])
            return subject["commonName"]


@unittest.skipUnless(shutil.which("openssl"), "needs openssl for test certificates")
class ReloadingContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)
        make_cert(self.folder, "first")
        make_cert(self.folder, "second")
        self.cert, self.key = self.folder / "tls.crt", self.folder / "tls.key"
        swap_in(self.folder, "first", self.cert, self.key)
        self.logged: list[str] = []
        self.tls = tls_reload.ReloadingContext(str(self.cert), str(self.key), log=self.logged.append)

    def test_unchanged_files_keep_the_same_context(self) -> None:
        self.assertIs(self.tls.current(), self.tls.current())
        self.assertEqual(self.logged, [])

    def test_a_renewed_certificate_is_loaded_without_a_restart(self) -> None:
        before = self.tls.current()
        swap_in(self.folder, "second", self.cert, self.key)
        after = self.tls.current()
        self.assertIsNot(before, after)
        self.assertTrue(any("reloaded" in line for line in self.logged))

    def test_a_certificate_that_wont_load_keeps_the_last_one(self) -> None:
        before = self.tls.current()
        data = self.folder / "..data-broken"
        data.mkdir()
        (data / "tls.crt").write_text("not a certificate\n")
        shutil.copy(self.folder / "first.key", data / "tls.key")
        os.symlink(data.name, self.folder / "..data.tmp")
        os.replace(self.folder / "..data.tmp", self.folder / "..data")
        self.assertIs(self.tls.current(), before)
        self.assertEqual(len([line for line in self.logged if "kept" in line]), 1)
        # Logged once, not on every connection while the files stay broken.
        self.tls.current()
        self.assertEqual(len([line for line in self.logged if "kept" in line]), 1)
        # And picked up once a good certificate arrives.
        swap_in(self.folder, "second", self.cert, self.key)
        self.assertIsNot(self.tls.current(), before)

    def test_files_that_wont_load_at_start_raise(self) -> None:
        with self.assertRaises((OSError, ssl.SSLError)):
            tls_reload.ReloadingContext(str(self.folder / "missing.crt"), str(self.key))

    def test_a_server_serves_the_renewed_certificate_on_new_connections(self) -> None:
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]

        def serve(count: int) -> None:
            for _ in range(count):
                conn, _ = listener.accept()
                tls = tls_reload.wrap_accepted(conn, self.tls)
                try:
                    tls.do_handshake()
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    tls.close()

        thread = threading.Thread(target=serve, args=(2,), daemon=True)
        thread.start()
        self.assertEqual(served_subject(port, self.folder / "first.crt"), "first")
        swap_in(self.folder, "second", self.cert, self.key)
        self.assertEqual(served_subject(port, self.folder / "second.crt"), "second")
        thread.join(5)


if __name__ == "__main__":
    unittest.main()
