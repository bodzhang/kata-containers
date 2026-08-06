#!/usr/bin/env python3

import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_oci_image.py"


class MakeOciImageTests(unittest.TestCase):
    def test_writes_requested_oci_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs"
            rootfs.mkdir()
            (rootfs / "pause").write_bytes(b"pause")
            archive = root / "pause.tar"

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--rootfs",
                    str(rootfs),
                    "--reference",
                    "example.invalid/pause:3.10",
                    "--entrypoint",
                    '["/pause"]',
                    "--user",
                    "65535:65535",
                    "--output",
                    str(archive),
                ],
                check=True,
            )

            with tarfile.open(archive) as layout:
                index = json.load(layout.extractfile("index.json"))
                manifest_digest = index["manifests"][0]["digest"].split(":", 1)[1]
                manifest = json.load(
                    layout.extractfile(f"blobs/sha256/{manifest_digest}")
                )
                config_digest = manifest["config"]["digest"].split(":", 1)[1]
                config = json.load(layout.extractfile(f"blobs/sha256/{config_digest}"))

            self.assertEqual(config["config"]["User"], "65535:65535")


if __name__ == "__main__":
    unittest.main()
