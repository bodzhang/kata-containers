import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "capture_bundle.py"
SPEC = importlib.util.spec_from_file_location("capture_bundle", SCRIPT)
capture_bundle = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(capture_bundle)


class CaptureBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "output"
        self.source.mkdir()
        self.bundle = self.source / "capture"
        self.workload = self.root / "workload.yaml"
        self.workload.write_text("kind: Pod\n", encoding="utf-8")
        self.profile = self.root / "profile.env"
        self.profile.write_text(
            "PROFILE_NAME=test\n"
            "REQUEST_AUTHORITY=recording-agent\n"
            "KUBERNETES_VERSION=v1.33.13\n"
            "CONTAINERD_VERSION=v2.3.3\n",
            encoding="utf-8",
        )
        self.config = self.root / "containerd.toml"
        self.config.write_text("version = 3\n", encoding="utf-8")
        self.binary = self.root / "capture-shim"
        self.binary.write_bytes(b"capture binary")
        self.image = self.root / "image.tar"
        self.image.write_bytes(b"image archive")

        for name in capture_bundle.REQUIRED_FILES:
            (self.source / name).write_text("{}\n", encoding="utf-8")
        image_config = b'{"config":{"Env":["FROM_IMAGE=value"]}}'
        image_config_digest = hashlib.sha256(image_config).hexdigest()
        image_manifest = (
            '{"config":{"digest":"sha256:'
            + image_config_digest
            + '"},"mediaType":"application/vnd.oci.image.manifest.v1+json"}'
        ).encode()
        image_manifest_digest = hashlib.sha256(image_manifest).hexdigest()
        self.image_reference = f"registry/image@sha256:{image_manifest_digest}"
        (self.source / "requested-images.txt").write_text(
            f"{self.image_reference}\n", encoding="utf-8"
        )
        images_dir = self.source / "images"
        (images_dir / "configs").mkdir(parents=True)
        (images_dir / "manifests").mkdir()
        (images_dir / "configs" / f"{image_config_digest}.json").write_bytes(
            image_config
        )
        (images_dir / "manifests" / f"{image_manifest_digest}.json").write_bytes(
            image_manifest
        )
        (images_dir / "index.json").write_text(
            json.dumps(
                {
                    "images": {
                        self.image_reference: {
                            "config_digest": f"sha256:{image_config_digest}",
                            "config_path": f"configs/{image_config_digest}.json",
                            "manifest_digest": f"sha256:{image_manifest_digest}",
                            "manifest_path": f"manifests/{image_manifest_digest}.json",
                            "requested_digest": f"sha256:{image_manifest_digest}",
                        }
                    },
                    "schema_version": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        pods = [
            {
                "spec": {
                    "initContainers": [{"name": "setup"}],
                    "containers": [{"name": "workload"}],
                }
            }
        ]
        (self.source / "pods.json").write_text(
            json.dumps(pods) + "\n", encoding="utf-8"
        )
        for directory in (
            "raw",
            "createcontainer-requests",
            "execprocess-requests",
            "logs",
        ):
            (self.source / directory).mkdir()
        for number in range(3):
            (self.source / "raw" / f"{number}.config.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (self.source / "createcontainer-requests" / f"{number}.json").write_text(
                "{}\n", encoding="utf-8"
            )
        (self.source / "execprocess-requests" / "probe.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.source / "logs" / "containerd.log").write_text(
            "started\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, require_complete=True):
        return capture_bundle.build_bundle(
            source=self.source,
            bundle=self.bundle,
            workload=self.workload,
            profile_path=self.profile,
            capture_backend="runtime-rs",
            rootfs_mode="native",
            outbound_sealed=True,
            configurations={"containerd.toml": self.config},
            capture_binaries={"capture-shim": self.binary},
            input_images={"workload.tar": self.image},
            require_complete=require_complete,
        )

    def test_builds_and_validates_complete_bundle(self):
        manifest = self.build()

        self.assertTrue(manifest["capture"]["complete"])
        self.assertEqual(
            manifest["capture"]["counts"],
            {
                "createcontainer": 3,
                "execprocess": 1,
                "expected_createcontainer": 3,
                "raw_oci": 3,
            },
        )
        self.assertEqual(manifest["components"]["containerd"], "v2.3.3")
        self.assertEqual(manifest["capture"]["request_authority"], "recording-agent")
        self.assertIn("raw-oci/0.config.json", manifest["artifacts"])
        self.assertIn("config/containerd.toml", manifest["artifacts"])
        self.assertIn("images/index.json", manifest["artifacts"])
        self.assertEqual(
            json.loads((self.bundle / "profile.json").read_text(encoding="utf-8"))[
                "capture_backend"
            ],
            "runtime-rs",
        )
        capture_bundle.validate_bundle(self.bundle, require_complete=True)

    def test_detects_tampered_artifact(self):
        self.build()
        (self.bundle / "workload.yaml").write_text("kind: Job\n", encoding="utf-8")

        with self.assertRaisesRegex(capture_bundle.BundleError, "integrity"):
            capture_bundle.validate_bundle(self.bundle)

    def test_rejects_missing_requested_image_metadata(self):
        index_path = self.source / "images" / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["images"] = {}
        index_path.write_text(json.dumps(index) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(capture_bundle.BundleError, "references differ"):
            self.build()

    def test_records_and_rejects_incomplete_bundle(self):
        (self.source / "createcontainer-requests" / "2.json").unlink()
        manifest = self.build(require_complete=False)

        self.assertFalse(manifest["capture"]["complete"])
        with self.assertRaisesRegex(capture_bundle.BundleError, "incomplete"):
            capture_bundle.validate_bundle(self.bundle, require_complete=True)

    def test_rejects_authority_inconsistent_with_backend(self):
        self.profile.write_text(
            "PROFILE_NAME=test\n"
            "REQUEST_AUTHORITY=raw-oci\n"
            "KUBERNETES_VERSION=v1.33.13\n"
            "CONTAINERD_VERSION=v2.3.3\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(capture_bundle.BundleError, "request authority"):
            self.build()


if __name__ == "__main__":
    unittest.main()