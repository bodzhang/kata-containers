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


SCRIPT = Path(__file__).parents[1] / "scripts" / "capture_rootfs_mounts.py"
SPEC = importlib.util.spec_from_file_location("capture_rootfs_mounts", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DIGEST = "sha256:" + "a" * 64

# Representative multi-layer erofs mount-handler mounts (the block mounts the
# Kata shim receives): an ext4 rw upper, an erofs ro lower with extra device=
# layers, and an overlay. This is NOT `ctr snapshots mounts` output (host overlay).
CTR_MOUNTS = f"""mount -t ext4 -o rw,loop /var/lib/containerd/erofs/1/rw.img /target
mount -t erofs -o ro,loop,device=/var/lib/containerd/erofs/2/extra.erofs /var/lib/containerd/erofs/2/layer.erofs /target
mount -t overlay -o lowerdir=/l,upperdir=/u,workdir=/w,X-containerd.mkdir.path=/data:0755 overlay /target
"""


class CaptureRootfsMountsTests(unittest.TestCase):
    def test_image_reference_from_annotation(self):
        spec = {"annotations": {"io.kubernetes.cri.image-name": f"reg/app@{DIGEST}"}}
        self.assertEqual(MODULE.image_reference(spec), f"reg/app@{DIGEST}")

    def test_image_reference_missing_is_empty(self):
        self.assertEqual(MODULE.image_reference({"annotations": {}}), "")

    def test_image_digest_extracted(self):
        self.assertEqual(MODULE.image_digest(f"reg/app:tag@{DIGEST}"), DIGEST)
        self.assertEqual(MODULE.image_digest("reg/app:tag"), "")

    def test_parse_ctr_mounts_multi_layer(self):
        mounts = MODULE.parse_ctr_mounts(CTR_MOUNTS)
        self.assertEqual([m["type"] for m in mounts], ["ext4", "erofs", "overlay"])
        self.assertEqual(mounts[0]["source"], "/var/lib/containerd/erofs/1/rw.img")
        self.assertIn("rw", mounts[0]["options"])
        self.assertIn(
            "device=/var/lib/containerd/erofs/2/extra.erofs", mounts[1]["options"]
        )

    def test_to_kata_mounts_shape_and_readonly(self):
        kata = MODULE.to_kata_mounts(MODULE.parse_ctr_mounts(CTR_MOUNTS))
        self.assertEqual(kata[0]["fs_type"], "ext4")
        self.assertFalse(kata[0]["read_only"])
        self.assertIsNone(kata[0]["device_id"])
        self.assertIsNone(kata[0]["host_shared_fs_path"])
        self.assertEqual(kata[1]["fs_type"], "erofs")
        self.assertTrue(kata[1]["read_only"])
        # device= options are preserved for the predictor's erofs handler.
        self.assertIn(
            "device=/var/lib/containerd/erofs/2/extra.erofs", kata[1]["options"]
        )

    def test_capture_writes_rootfs_mounts_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / "raw"
            mounts_dir = Path(temporary) / "mounts"
            raw.mkdir()
            mounts_dir.mkdir()
            (raw / "0001-c.config.json").write_text(
                json.dumps(
                    {"annotations": {"io.kubernetes.cri.image-name": f"reg/app@{DIGEST}"}}
                ),
                encoding="utf-8",
            )
            (mounts_dir / f"{DIGEST.replace(':', '_')}.mounts").write_text(
                CTR_MOUNTS, encoding="utf-8"
            )

            report = MODULE.capture(raw, mounts_dir)

            artifact = raw / "0001-c.rootfs-mounts.json"
            self.assertTrue(artifact.exists())
            mounts = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual([m["fs_type"] for m in mounts], ["ext4", "erofs", "overlay"])
            self.assertEqual(report["captures"][0]["layers"], 3)

    def test_capture_skips_when_no_mounts_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / "raw"
            mounts_dir = Path(temporary) / "mounts"
            raw.mkdir()
            mounts_dir.mkdir()
            (raw / "0001-c.config.json").write_text(
                json.dumps(
                    {"annotations": {"io.kubernetes.cri.image-name": f"reg/app@{DIGEST}"}}
                ),
                encoding="utf-8",
            )

            report = MODULE.capture(raw, mounts_dir)

            self.assertFalse((raw / "0001-c.rootfs-mounts.json").exists())
            self.assertIn("skipped", report["captures"][0])

    def test_capture_skips_when_no_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / "raw"
            mounts_dir = Path(temporary) / "mounts"
            raw.mkdir()
            mounts_dir.mkdir()
            (raw / "0001-c.config.json").write_text(
                json.dumps(
                    {"annotations": {"io.kubernetes.cri.image-name": "reg/app:tag"}}
                ),
                encoding="utf-8",
            )

            report = MODULE.capture(raw, mounts_dir)

            self.assertFalse((raw / "0001-c.rootfs-mounts.json").exists())
            self.assertIn("skipped", report["captures"][0])


if __name__ == "__main__":
    unittest.main()
