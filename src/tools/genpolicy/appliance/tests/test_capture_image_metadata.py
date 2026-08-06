import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "capture_image_metadata.py"
SPEC = importlib.util.spec_from_file_location("capture_image_metadata", SCRIPT)
metadata = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(metadata)


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


class CaptureImageMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name) / "images"
        self.config = encoded(
            {
                "architecture": "amd64",
                "config": {"Env": ["FROM_IMAGE=value"], "User": "1000"},
                "os": "linux",
            }
        )
        self.config_digest = digest(self.config)
        self.manifest = encoded(
            {
                "config": {
                    "digest": self.config_digest,
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": len(self.config),
                },
                "layers": [],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2,
            }
        )
        self.manifest_digest = digest(self.manifest)
        self.content = {
            self.config_digest: self.config,
            self.manifest_digest: self.manifest,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def read_content(self, content_digest):
        return self.content[content_digest]

    def test_exports_manifest_and_config_by_digest(self):
        reference = f"registry/image@{self.manifest_digest}"
        result = metadata.export_image_metadata(
            [reference], self.output, self.read_content, "linux", "amd64"
        )

        self.assertEqual(result[reference]["manifest_digest"], self.manifest_digest)
        self.assertEqual(result[reference]["config_digest"], self.config_digest)
        self.assertEqual(
            (self.output / result[reference]["config_path"]).read_bytes(), self.config
        )
        index = json.loads((self.output / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["images"], result)

    def test_exports_manifest_without_top_level_media_type(self):
        manifest = json.loads(self.manifest)
        del manifest["mediaType"]
        raw_manifest = encoded(manifest)
        manifest_digest = digest(raw_manifest)
        self.content[manifest_digest] = raw_manifest
        reference = f"registry/image@{manifest_digest}"

        result = metadata.export_image_metadata(
            [reference], self.output, self.read_content, "linux", "amd64"
        )

        self.assertEqual(result[reference]["manifest_digest"], manifest_digest)

    def test_resolves_platform_manifest_from_index(self):
        index = encoded(
            {
                "manifests": [
                    {
                        "digest": self.manifest_digest,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"architecture": "amd64", "os": "linux"},
                        "size": len(self.manifest),
                    }
                ],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        )
        index_digest = digest(index)
        self.content[index_digest] = index
        reference = f"registry/image@{index_digest}"

        result = metadata.export_image_metadata(
            [reference], self.output, self.read_content, "linux", "amd64"
        )

        self.assertEqual(result[reference]["requested_digest"], index_digest)
        self.assertEqual(result[reference]["manifest_digest"], self.manifest_digest)

    def test_rejects_content_digest_mismatch(self):
        reference = f"registry/image@{self.manifest_digest}"

        with self.assertRaisesRegex(metadata.ImageMetadataError, "digest mismatch"):
            metadata.export_image_metadata(
                [reference], self.output, lambda _: b"{}", "linux", "amd64"
            )


if __name__ == "__main__":
    unittest.main()