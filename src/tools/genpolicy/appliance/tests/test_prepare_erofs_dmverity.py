#
# Copyright (c) 2026 Kata Containers
#
# SPDX-License-Identifier: Apache-2.0
#

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "prepare_erofs_dmverity.py"
SPEC = importlib.util.spec_from_file_location("prepare_erofs_dmverity", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _spec(reference: str) -> str:
    return json.dumps({"annotations": {"io.kubernetes.cri.image-name": reference}})


class FakeContainerd:
    """Stub exposing the single `ctr` method `_snapshot_chain` relies on."""

    def __init__(self, snapshot_listing: str):
        self._listing = snapshot_listing

    def ctr(self, *args, namespaced: bool = False):
        return type("R", (), {"stdout": self._listing})()


class DiscoverImagesTests(unittest.TestCase):
    def test_only_digest_pinned_unique_and_sorted(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp)
            (raw / f"0002-b{MODULE.CONFIG_SUFFIX}").write_text(_spec(f"reg/b@{DIGEST_B}"))
            (raw / f"0001-a{MODULE.CONFIG_SUFFIX}").write_text(_spec(f"reg/a@{DIGEST_A}"))
            # Duplicate reference and a mutable tag (no digest) are excluded.
            (raw / f"0003-a{MODULE.CONFIG_SUFFIX}").write_text(_spec(f"reg/a@{DIGEST_A}"))
            (raw / f"0004-tag{MODULE.CONFIG_SUFFIX}").write_text(_spec("reg/c:latest"))
            images = MODULE.discover_images(raw)
        self.assertEqual(
            images, [(f"reg/a@{DIGEST_A}", DIGEST_A), (f"reg/b@{DIGEST_B}", DIGEST_B)]
        )


class AssembleMountsTests(unittest.TestCase):
    def test_single_layer_is_block_rootfs_shape(self):
        mounts = MODULE.assemble_mounts([("/blobs/000-layer.erofs", "/blobs/000-layer.erofs.dmverity")])
        self.assertEqual(len(mounts), 1)
        mount = mounts[0]
        self.assertEqual(mount["type"], "erofs")
        self.assertEqual(mount["source"], "/blobs/000-layer.erofs")
        self.assertEqual(mount["target"], "/")
        self.assertIn("loop", mount["options"])
        self.assertIn("ro", mount["options"])
        self.assertIn("X-containerd.dmverity=/blobs/000-layer.erofs.dmverity", mount["options"])

    def test_multi_layer_erofs_plus_overlay_with_dmverity(self):
        layers = [
            ("/b/000-layer.erofs", "/b/000-layer.erofs.dmverity"),
            ("/b/001-layer.erofs", "/b/001-layer.erofs.dmverity"),
            ("/b/002-layer.erofs", "/b/002-layer.erofs.dmverity"),
        ]
        mounts = MODULE.assemble_mounts(layers)
        self.assertEqual([m["type"] for m in mounts], ["erofs", "erofs", "erofs", "overlay"])
        for mount, (blob, dmverity) in zip(mounts[:3], layers):
            self.assertEqual(mount["source"], blob)
            self.assertIn("ro", mount["options"])
            self.assertNotIn("loop", mount["options"])
            self.assertIn(f"X-containerd.dmverity={dmverity}", mount["options"])
        # Overlay lowerdir is ordered top-most first (base last), like overlayfs.
        lowerdir = [o for o in mounts[3]["options"] if o.startswith("lowerdir=")][0]
        self.assertEqual(
            lowerdir,
            "lowerdir=/b/002-layer.erofs:/b/001-layer.erofs:/b/000-layer.erofs",
        )

    def test_missing_dmverity_omits_annotation(self):
        mounts = MODULE.assemble_mounts([("/b/000-layer.erofs", None)])
        self.assertFalse(any(o.startswith("X-containerd.dmverity=") for o in mounts[0]["options"]))


class SnapshotChainTests(unittest.TestCase):
    def test_chain_orders_base_to_top_including_base_row(self):
        # The base layer prints only KEY + KIND (empty PARENT column).
        listing = (
            "KEY PARENT KIND\n"
            "sha256:top child2 Committed\n"
            "child2 child1 Committed\n"
            "child1 Committed\n"
        )
        chain = MODULE._snapshot_chain(FakeContainerd(listing))
        self.assertEqual(chain, ["child1", "child2", "sha256:top"])

    def test_single_layer_chain(self):
        listing = "KEY PARENT KIND\nsha256:only Committed\n"
        self.assertEqual(MODULE._snapshot_chain(FakeContainerd(listing)), ["sha256:only"])

    def test_multiple_leaves_rejected(self):
        listing = (
            "KEY PARENT KIND\n"
            "leafA base Committed\n"
            "leafB base Committed\n"
            "base Committed\n"
        )
        with self.assertRaises(RuntimeError):
            MODULE._snapshot_chain(FakeContainerd(listing))


class PersistLayersTests(unittest.TestCase):
    def test_copies_blobs_and_returns_stable_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            blob = src / "layer.erofs"
            blob.write_bytes(b"erofs-blob")
            dmverity = src / "layer.erofs.dmverity"
            dmverity.write_text('{"roothash":"ab","hashoffset":1}')
            dest = Path(tmp) / "out" / "blobs" / "slug"
            persisted = MODULE.persist_layers([(blob, dmverity)], dest)

            new_blob, new_dmverity = persisted[0]
            self.assertTrue(new_blob.exists() and new_dmverity.exists())
            self.assertTrue(str(new_blob).startswith(str(dest)))
            self.assertEqual(new_blob.read_bytes(), b"erofs-blob")
            self.assertEqual(new_blob.name, "000-layer.erofs")
            self.assertEqual(new_dmverity.name, "000-layer.erofs.dmverity")


if __name__ == "__main__":
    unittest.main()
