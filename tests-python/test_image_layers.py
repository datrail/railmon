"""RC-553: in_layer_deleted_secrets from an image's layers
(tools/scan/image_layers.py), ported with the RC-406 prototype's tests, plus
the streamed reads gke-scan's registry reader makes (layer_entries,
deleted_across)."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tracemalloc
import unittest
from pathlib import Path

SCAN = Path(__file__).resolve().parents[1] / "tools" / "scan"


def _module(name: str):
    # Loaded on its own, without the scanner.
    spec = importlib.util.spec_from_file_location(f"_rc553_{name}", SCAN / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


layers = _module("image_layers")


def _tar(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class ImageLayersTest(unittest.TestCase):
    def save(self, *layer_entries: dict[str, bytes]) -> tuple[io.BytesIO, list[str]]:
        """A docker save archive with these layers, and their diff IDs in order."""
        blobs = [_tar(entries) for entries in layer_entries]
        diff_ids = ["sha256:" + hashlib.sha256(blob).hexdigest() for blob in blobs]
        # Out of order in the archive, as an OCI layout can be: order comes from the diff IDs.
        # docker save stores a repeated layer once.
        archive = {f"blobs/sha256/{d[7:]}": b for d, b in reversed(list(zip(diff_ids, blobs)))}
        archive["manifest.json"] = json.dumps([{"Layers": list(archive)}]).encode()
        return io.BytesIO(_tar(archive)), diff_ids

    def test_a_secret_added_then_whited_out_is_found(self):
        filler = {"usr/lib/x": b"x" * 2048}
        archive, diff_ids = self.save(
            filler,
            {"opt/railtest/deleted-secret.env": b"RAILTEST=not-a-real-secret", "opt/railtest/readme": b"hi", **filler},
            {"opt/railtest/.wh.deleted-secret.env": b"", "opt/railtest/.wh.readme": b""},
        )
        result = layers.deleted_secret_files(archive, diff_ids)
        self.assertEqual(result["layers"], 3)
        self.assertEqual(result["deleted"], [{"path": "/opt/railtest/deleted-secret.env",
                                              "added_in_layer": 1, "deleted_in_layer": 2, "size": 26}])

    def test_an_opaque_directory_deletes_what_is_under_it(self):
        archive, diff_ids = self.save({"etc/app/api_key.txt": b"k" * 2000}, {"etc/app/.wh..wh..opq": b"", "z": b"z" * 2000})
        self.assertEqual([d["path"] for d in layers.deleted_secret_files(archive, diff_ids)["deleted"]],
                         ["/etc/app/api_key.txt"])

    def test_a_deleted_module_is_not_a_secret(self):
        archive, diff_ids = self.save({"usr/share/perl/CPAN/HTTP/Credentials.pm": b"p" * 2000,
                                       "usr/share/perl/Pod/PullParserToken.pm": b"p" * 2000},
                                      {"usr/share/perl/.wh.CPAN": b"", "usr/share/perl/Pod/.wh.PullParserToken.pm": b"", "z": b"z" * 2000})
        self.assertEqual(layers.deleted_secret_files(archive, diff_ids)["deleted"], [])

    def test_a_repeated_layer_counts_in_each_place(self):
        empty = {"z": b"z" * 2000}
        archive, diff_ids = self.save(empty, {"opt/a/secret.env": b"s" * 10, **{"y": b"y" * 2000}}, empty,
                                      {"opt/a/.wh.secret.env": b"", "x": b"x" * 2000})
        self.assertEqual(layers.deleted_secret_files(archive, diff_ids)["deleted"][0]["deleted_in_layer"], 3)

    def test_a_secret_still_present_is_not_deleted(self):
        archive, diff_ids = self.save({"app/.env": b"A=1" * 700})
        self.assertEqual(layers.deleted_secret_files(archive, diff_ids)["deleted"], [])


class StreamedLayersTest(unittest.TestCase):
    """layer_entries and deleted_across, as the registry reader calls them."""

    def entries(self, entries: dict[str, bytes]):
        return layers.layer_entries(io.BytesIO(_tar(entries)))

    def test_layers_read_one_by_one_give_the_same_answer(self):
        result = layers.deleted_across([
            self.entries({"usr/lib/x": b"x"}),
            self.entries({"opt/railtest/deleted-secret.env": b"RAILTEST=not-a-real-secret"}),
            self.entries({"opt/railtest/.wh.deleted-secret.env": b""}),
        ])
        self.assertEqual(result, {"layers": 3, "deleted": [{"path": "/opt/railtest/deleted-secret.env",
                                                            "added_in_layer": 1, "deleted_in_layer": 2, "size": 26}]})

    def test_a_directory_whiteout_deletes_what_is_under_it(self):
        result = layers.deleted_across([self.entries({"root/.ssh/id_ed25519": b"k"}),
                                        self.entries({"root/.wh..ssh": b""})])
        self.assertEqual([d["path"] for d in result["deleted"]], ["/root/.ssh/id_ed25519"])

    def test_only_secret_looking_names_are_kept(self):
        added, whiteouts, opaque = self.entries({"app/main.py": b"x", "app/server.key": b"k", "app/.env.prod": b"e",
                                                 "app/token_utils.js": b"t", "app/.wh.old": b""})
        self.assertEqual(sorted(added), ["/app/.env.prod", "/app/server.key"])
        self.assertEqual(whiteouts, {"/app/old"})

    def test_not_a_tar_is_none(self):
        self.assertIsNone(layers.layer_entries(io.BytesIO(b"not a tar at all" * 64)))

    def test_an_empty_layer_is_an_empty_tar(self):
        self.assertEqual(layers.layer_entries(io.BytesIO(b"")), ({}, set(), set()))

    def test_names_at_the_layers_root_keep_their_leading_dot(self):
        # Layers written with and without a "./" prefix, as different builders write them.
        for prefix in ("", "./"):
            with self.subTest(prefix=prefix):
                added, whiteouts, opaque = self.entries({f"{prefix}.env": b"A=1", f"{prefix}.wh..netrc": b"",
                                                         f"{prefix}.ssh/id_rsa": b"k", f"{prefix}.wh..wh..opq": b""})
                self.assertEqual(sorted(added), ["/.env", "/.ssh/id_rsa"])
                self.assertEqual(whiteouts, {"/.netrc"})
                self.assertEqual(opaque, {"/"})

    def test_a_secret_at_the_root_deleted_later_is_found(self):
        result = layers.deleted_across([self.entries({"./.env": b"A=1", "./.aws/credentials": b"c"}),
                                        self.entries({"./.wh..env": b"", "./.wh..aws": b""})])
        self.assertEqual(sorted(d["path"] for d in result["deleted"]), ["/.aws/credentials", "/.env"])

    def test_a_file_and_its_whiteout_match_however_the_layer_spells_them(self):
        # A hostile image can spell the added file and its whiteout differently,
        # so the deletion would be missed if the paths weren't normalized.
        cases = [("etc//.env", "etc/.wh..env"), ("etc/./.env", "etc/.wh..env"), ("etc/.env", "etc//.wh..env"),
                 ("opt/x/../.env", "opt/.wh..env"), ("app//secrets/token", "app/./.wh.secrets")]
        for added, whiteout in cases:
            with self.subTest(added=added, whiteout=whiteout):
                result = layers.deleted_across([self.entries({added: b"s"}), self.entries({whiteout: b""})])
                self.assertEqual(len(result["deleted"]), 1, result)
        result = layers.deleted_across([self.entries({"srv//conf/.env": b"s"}), self.entries({"srv/./conf/.wh..wh..opq": b""})])
        self.assertEqual([d["path"] for d in result["deleted"]], ["/srv/conf/.env"])

    def test_deleted_across_matches_the_plain_definition(self):
        # The bisection gives what checking every path against every whiteout gives.
        import random

        def plain(entries):
            present, deleted = {}, []
            for index, (added, whiteouts, opaque) in enumerate(entries):
                for path in sorted(present):
                    if any(path == t or path.startswith(t + "/") for t in whiteouts) or \
                            any(path.startswith(d.rstrip("/") + "/") for d in opaque):
                        first, size = present.pop(path)
                        deleted.append({"path": path, "added_in_layer": first, "deleted_in_layer": index, "size": size})
                for path, size in added.items():
                    present[path] = (index, size)
            return {"layers": len(entries), "deleted": deleted}

        rng = random.Random(553)
        names = ["a", "b", "a.b", "a-b", "a0", ".env", "key.pem", "c"]
        for _ in range(400):
            def path(depth=None):
                return "/" + "/".join(rng.choice(names) for _ in range(depth or rng.randint(1, 3)))
            entries = []
            for _layer in range(rng.randint(1, 5)):
                added = {path(): rng.randint(0, 99) for _ in range(rng.randint(0, 6))}
                whiteouts = {path() for _ in range(rng.randint(0, 3))}
                opaque = {rng.choice(["/", path()]) for _ in range(rng.randint(0, 2))}
                entries.append((added, whiteouts, opaque))
            self.assertEqual(layers.deleted_across(entries), plain(entries), entries)

    def test_deleted_across_stays_fast_on_a_hostile_image(self):
        # 25,000 secret-looking files and 25,000 whiteouts that match none of
        # them took the plain loop over 40 seconds; and 20,000 layers that
        # each add a file and white one out.
        import time
        added = {f"/srv/{i:05d}/.env": 1 for i in range(25000)}
        whiteouts = {f"/srv/{i:05d}/other" for i in range(25000)}
        started = time.monotonic()
        result = layers.deleted_across([(added, set(), set()), ({}, whiteouts, set())])
        self.assertEqual(result["deleted"], [])
        many = [({f"/a/{i:05d}.env": 1}, {f"/a/{i - 1:05d}.env"} if i else set(), set()) for i in range(20000)]
        self.assertEqual(len(layers.deleted_across(many)["deleted"]), 19999)
        self.assertLess(time.monotonic() - started, 5)

    def test_a_whiteout_that_names_no_file_is_not_kept(self):
        added, whiteouts, opaque = self.entries({"app/.wh.": b"", "app/.wh..": b"", "app/.wh...": b""})
        self.assertEqual(whiteouts, set())

    def test_a_layer_of_many_entries_keeps_memory_flat(self):
        # tarfile keeps every member a streamed tar has read, unless told not to.
        blob = _tar({f"usr/share/f{i}": b"" for i in range(30_000)})
        tracemalloc.start()
        try:
            self.assertIsNotNone(layers.layer_entries(io.BytesIO(blob)))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 * 1024 * 1024, f"peak {peak} bytes over 30,000 entries")

    def test_a_tar_header_past_its_cap_is_refused(self):
        name = "opt/" + "a" * (layers.MAX_HEADER_BYTES + 1)
        for fmt in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            with self.subTest(fmt=fmt):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w", format=fmt) as tar:
                    tar.addfile(tarfile.TarInfo(name))
                with self.assertRaises(layers.LayerCapExceeded):
                    layers.layer_entries(io.BytesIO(buffer.getvalue()))

    def test_a_member_with_no_data_doesnt_widen_the_header_cap(self):
        # A symlink or directory declaring gigabytes has no data to skip, so
        # the long name after it is still a header, capped from where it starts.
        for kind in (tarfile.SYMTYPE, tarfile.DIRTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("opt/link")
                info.type, info.linkname, info.size = kind, "target", 64 * layers.MAX_HEADER_BYTES
                lead = info.tobuf(tarfile.GNU_FORMAT)
                self.assertEqual(tarfile.TarInfo.frombuf(lead[:512], "utf-8", "strict").size, info.size)
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
                    tar.addfile(tarfile.TarInfo("opt/" + "a" * (2 * layers.MAX_HEADER_BYTES)))
                with self.assertRaises(layers.LayerCapExceeded):
                    layers.layer_entries(io.BytesIO(lead + buffer.getvalue()))

    def test_global_pax_headers_are_capped_in_all(self):
        # Each global header is small, but tarfile keeps them all for the rest of the layer.
        blob = b""
        for i in range(20):
            blob += tarfile.TarInfo._create_pax_generic_header({f"k{i}": "v" * 100_000}, tarfile.XGLTYPE, "utf-8")
            blob += tarfile.TarInfo(f"opt/f{i}").tobuf(tarfile.USTAR_FORMAT)
        with self.assertRaises(layers.LayerCapExceeded):
            layers.layer_entries(io.BytesIO(blob + bytes(2 * tarfile.RECORDSIZE)))

    def test_a_layer_with_a_global_header_is_still_read(self):
        # git archive writes one, with the commit as its comment.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT,
                          pax_headers={"comment": "0123456789abcdef" * 2}) as tar:
            info = tarfile.TarInfo("opt/a.key")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"k"))
        added, _, _ = layers.layer_entries(io.BytesIO(buffer.getvalue()))
        self.assertEqual(sorted(added), ["/opt/a.key"])

    def test_a_large_file_isnt_mistaken_for_a_large_header(self):
        added, _, _ = self.entries({"opt/big.bin": b"x" * (3 * layers.MAX_HEADER_BYTES), "opt/after.key": b"k"})
        self.assertEqual(sorted(added), ["/opt/after.key"])

    def test_kept_names_past_their_cap_are_refused(self):
        stream = io.BytesIO(_tar({f"opt/s{i}.key": b"" for i in range(200)}))
        with self.assertRaises(layers.LayerCapExceeded):
            layers.layer_entries(stream, max_kept_bytes=10_000)

    def test_a_name_longer_than_path_max_isnt_kept(self):
        long = "opt/" + "d" * layers.MAX_PATH + "/x.key"
        added, whiteouts, _ = self.entries({long: b"k", "opt/" + "d" * layers.MAX_PATH + "/.wh.y": b""})
        self.assertEqual((added, whiteouts), ({}, set()))


if __name__ == "__main__":
    unittest.main()
