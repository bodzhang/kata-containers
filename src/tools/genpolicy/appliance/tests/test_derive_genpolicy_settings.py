import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "derive_genpolicy_settings.py"
SPEC = importlib.util.spec_from_file_location("derive_genpolicy_settings", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DeriveGenpolicySettingsTests(unittest.TestCase):
    def configuration(self, shared_fs: str, emptydir_mode: str = "shared-fs") -> dict:
        return {
            "runtime": {
                "hypervisor_name": "qemu",
                "emptydir_mode": emptydir_mode,
            },
            "hypervisor": {"qemu": {"shared_fs": shared_fs}},
        }

    def test_shared_fs_none_selects_guest_local_storage(self) -> None:
        patch = MODULE.derive_settings(self.configuration("none"))
        values = {entry["path"]: entry["value"] for entry in patch}
        self.assertEqual(values["/cluster_config/emptydir_type"], "shared-fs")
        self.assertFalse(values["/cluster_config/fs_sharing_supported"])

    def test_virtio_fs_preserves_host_shared_storage(self) -> None:
        patch = MODULE.derive_settings(self.configuration("virtio-fs"))
        values = {entry["path"]: entry["value"] for entry in patch}
        self.assertTrue(values["/cluster_config/fs_sharing_supported"])

    def test_block_encrypted_mode_is_derived(self) -> None:
        patch = MODULE.derive_settings(self.configuration("none", "block-encrypted"))
        values = {entry["path"]: entry["value"] for entry in patch}
        self.assertEqual(values["/cluster_config/emptydir_type"], "block-encrypted")

    def test_missing_shared_fs_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "shared_fs is required"):
            MODULE.derive_settings(self.configuration(""))

    def test_unknown_emptydir_mode_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported or missing"):
            MODULE.derive_settings(self.configuration("none", "unknown"))


if __name__ == "__main__":
    unittest.main()