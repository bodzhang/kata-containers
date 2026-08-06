#!/usr/bin/env python3

import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class ReferenceOciImageTests(unittest.TestCase):
    def test_rewrites_reference_without_changing_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs"
            rootfs.mkdir()
            (rootfs / "payload").write_bytes(b"payload")
            source = root / "source.tar"
            output = root / "referenced.tar"

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "make_oci_image.py"),
                    "--rootfs",
                    str(rootfs),
                    "--reference",
                    "registry.example/app:latest",
                    "--entrypoint",
                    '["/payload"]',
                    "--output",
                    str(source),
                ],
                check=True,
            )
            with tarfile.open(source) as layout:
                source_index = json.load(layout.extractfile("index.json"))
            manifest_digest = source_index["manifests"][0]["digest"]
            requested = f"mirror.example/app@{manifest_digest}"

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "reference_oci_image.py"),
                    "--reference",
                    requested,
                    "--output",
                    str(output),
                    str(source),
                ],
                check=True,
            )

            with tarfile.open(output) as layout:
                index = json.load(layout.extractfile("index.json"))
                names = set(layout.getnames())
            descriptor = index["manifests"][0]
            self.assertEqual(descriptor["digest"], manifest_digest)
            self.assertEqual(
                descriptor["annotations"]["org.opencontainers.image.ref.name"],
                requested,
            )
            self.assertIn(f"blobs/sha256/{manifest_digest.split(':', 1)[1]}", names)


if __name__ == "__main__":
    unittest.main()
