import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "analyze_storage_mounts.py"
SPEC = importlib.util.spec_from_file_location("analyze_storage_mounts", SCRIPT)
analysis = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(analysis)


class StorageMountAnalysisTests(unittest.TestCase):
    def make_capture(self, root: Path, authority: str = "recording-agent") -> Path:
        capture = root / "capture"
        requests = capture / "createcontainer-requests"
        requests.mkdir(parents=True)
        manifest = {
            "capture": {
                "backend": "runtime-rs" if authority == "recording-agent" else "runc",
                "request_authority": authority,
                "rootfs_mode": "guest-pull",
            }
        }
        (capture / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        config = capture / "config"
        config.mkdir()
        (config / "kata-configuration.toml").write_text(
            '[hypervisor.qemu]\nshared_fs = "none"\n\n'
            '[runtime]\nhypervisor_name = "qemu"\n',
            encoding="utf-8",
        )
        (capture / "workload.yaml").write_text(
            """apiVersion: v1
kind: Pod
spec:
  volumes:
  - name: config
    configMap:
      name: app-config
  containers:
  - name: app
    image: registry/app@sha256:abc
    envFrom:
    - secretRef:
        name: env-secret
    volumeMounts:
    - name: config
      mountPath: /etc/config
""",
            encoding="utf-8",
        )
        request = {
            "container_id": "cid",
            "oci": {
                "annotations": {"io.kubernetes.cri.container-name": "app"},
                "root": {"path": "/run/kata-containers/cid/rootfs"},
                "mounts": [
                    {
                        "destination": "/dev/shm",
                        "source": "/run/kata-containers/sandbox/shm",
                        "type": "bind",
                    },
                    {
                        "destination": "/etc/config",
                        "source": "/run/kata-containers/shared/containers/cid-0123456789abcdef-config",
                        "type": "bind",
                    },
                ],
            },
            "storages": [
                {
                    "driver": "image_guest_pull",
                    "fs_type": "overlay",
                    "mount_point": "/run/kata-containers/cid/rootfs",
                    "source": "registry/app@sha256:abc",
                }
            ],
            "devices": [],
        }
        (requests / "0001-cid.json").write_text(json.dumps(request), encoding="utf-8")
        return capture

    def test_confirms_only_observed_authoritative_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = analysis.analyze(self.make_capture(Path(temporary)))

        claims = {entry["id"]: entry for entry in report["claims"]}
        self.assertEqual(claims["guest-pull-rootfs"]["status"], "confirmed")
        self.assertEqual(claims["uvm-dev-shm"]["status"], "confirmed")
        self.assertEqual(claims["shared-fs-none-volume-copy"]["status"], "confirmed")
        self.assertEqual(claims["virtiofs-watchable-volume"]["status"], "not-exercised")
        self.assertEqual(claims["emptydir-local-storage"]["status"], "not-exercised")
        self.assertEqual(report["observations"]["workload"]["env_from"], {"secret": 1})
        self.assertEqual(report["observations"]["workload"]["volume_types"], {"configMap": 1})
    def test_classifies_agent_devices_without_claiming_physical_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary))
            request_path = next((capture / "createcontainer-requests").glob("*.json"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["devices"] = [
                {"field_type": "blk", "container_path": "/dev/data"},
                {"field_type": "vfio-pci-gk", "container_path": "/dev/vfio0"},
            ]
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)

        claims = {entry["id"]: entry for entry in report["claims"]}
        self.assertEqual(claims["agent-devices"]["status"], "confirmed")
        self.assertEqual(claims["block-agent-devices"]["status"], "confirmed")
        self.assertEqual(claims["vfio-agent-devices"]["status"], "confirmed")

    def test_reconstructed_requests_are_not_authoritative(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary), authority="raw-oci")
            report = analysis.analyze(capture)

        self.assertTrue(
            all(entry["status"] == "not-authoritative" for entry in report["claims"])
        )

    def test_erofs_claim_requires_read_only_lower_with_roothash(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary))
            request_path = next((capture / "createcontainer-requests").glob("*.json"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            root = request["oci"]["root"]["path"]
            request["storages"] = [
                {
                    "driver": "blk",
                    "fs_type": "ext4",
                    "mount_point": root,
                    "options": ["rw", "X-kata.overlay-upper", "X-kata.multi-layer=true"],
                },
                {
                    "driver": "blk",
                    "fs_type": "erofs",
                    "mount_point": root,
                    "options": [
                        "ro",
                        "X-kata.dmverity-enabled=true",
                        "X-kata.dmverity.roothash=abc",
                        "X-kata.overlay-lower",
                        "X-kata.multi-layer=true",
                    ],
                },
            ]
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(claims["erofs-overlay-rootfs"]["status"], "confirmed")

            request["storages"][1]["options"].remove(
                "X-kata.dmverity.roothash=abc"
            )
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(claims["erofs-overlay-rootfs"]["status"], "not-exercised")

    def test_single_layer_dmverity_requires_enabled_root_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary))
            request_path = next((capture / "createcontainer-requests").glob("*.json"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["storages"] = [
                {
                    "driver": "blk",
                    "fs_type": "ext4",
                    "mount_point": request["oci"]["root"]["path"],
                    "options": [
                        "ro",
                        "X-kata.dmverity-enabled=true",
                        "X-kata.dmverity.roothash=abc",
                    ],
                }
            ]
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(
                claims["single-layer-dmverity-rootfs"]["status"], "confirmed"
            )

            request["storages"][0]["options"].remove(
                "X-kata.dmverity.roothash=abc"
            )
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(
                claims["single-layer-dmverity-rootfs"]["status"], "not-exercised"
            )

    def test_encrypted_emptydir_requires_cdh_trigger_and_filesystem_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary))
            request_path = next((capture / "createcontainer-requests").glob("*.json"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["storages"].append(
                {
                    "driver": "blk",
                    "driver_options": [
                        "encryption_key=ephemeral",
                        "create_filesystem",
                    ],
                    "fs_type": "ext4",
                    "mount_point": "/run/kata-containers/sandbox/storage/MDE=",
                    "shared": True,
                    "source": "01",
                }
            )
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(
                claims["emptydir-block-encrypted-storage"]["status"], "confirmed"
            )
            self.assertEqual(claims["emptydir-block-storage"]["status"], "confirmed")

            request["storages"][1]["driver_options"] = ["create_filesystem"]
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)
            claims = {entry["id"]: entry for entry in report["claims"]}
            self.assertEqual(
                claims["emptydir-block-encrypted-storage"]["status"],
                "not-exercised",
            )
            self.assertEqual(claims["emptydir-block-storage"]["status"], "confirmed")

    def test_names_generic_block_shared_fs_and_unsupported_rootfs(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.make_capture(Path(temporary))
            request_path = next((capture / "createcontainer-requests").glob("*.json"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["oci"]["mounts"].append(
                {
                    "destination": "/data",
                    "source": "/run/kata-containers/shared/containers/sandbox-0123abcd-data",
                    "type": "bind",
                }
            )
            request["storages"].extend(
                [
                    {
                        "driver": "scsi",
                        "driver_options": [],
                        "fs_type": "ext4",
                        "mount_point": "/run/kata-containers/shared/containers/volume",
                        "source": "0:1",
                    },
                    {
                        "driver": "overlayfs",
                        "fs_type": "overlay",
                        "mount_point": request["oci"]["root"]["path"],
                        "source": "overlay",
                    },
                ]
            )
            request_path.write_text(json.dumps(request), encoding="utf-8")
            report = analysis.analyze(capture)

        claims = {entry["id"]: entry for entry in report["claims"]}
        self.assertEqual(claims["generic-block-volume-storage"]["status"], "confirmed")
        self.assertEqual(claims["unsupported-rootfs-storage"]["status"], "confirmed")
        self.assertEqual(claims["virtiofs-shared-volume"]["status"], "confirmed")
        self.assertEqual(
            report["observations"]["storage_classes"]["rootfs-nydus-overlay"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
