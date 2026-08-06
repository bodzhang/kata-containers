import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "watch_device_mapper_nodes.py"
SPEC = importlib.util.spec_from_file_location("watch_device_mapper_nodes", SCRIPT)
monitor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(monitor)


class DeviceMapperNodeTests(unittest.TestCase):
    def test_creates_only_containerd_erofs_nodes_and_removes_stale_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block = root / "sys"
            dev_mapper = root / "dev"
            for device, name, number in (
                ("dm-0", "containerd-erofs-1", "254:0"),
                ("dm-1", "unrelated", "254:1"),
            ):
                (sys_block / device / "dm").mkdir(parents=True)
                (sys_block / device / "dm" / "name").write_text(name)
                (sys_block / device / "dev").write_text(number)
            dev_mapper.mkdir()
            (dev_mapper / "containerd-erofs-stale").touch()

            with mock.patch.object(monitor, "SYS_BLOCK", sys_block), mock.patch.object(
                monitor, "DEV_ROOT", root
            ), mock.patch.object(monitor, "DEV_MAPPER", dev_mapper), mock.patch.object(
                os, "mknod"
            ) as mknod:
                monitor.reconcile()

            self.assertEqual(
                mknod.call_args_list,
                [
                    mock.call(root / "dm-0", stat.S_IFBLK | 0o600, os.makedev(254, 0)),
                    mock.call(
                        dev_mapper / "containerd-erofs-1",
                        stat.S_IFBLK | 0o600,
                        os.makedev(254, 0),
                    ),
                ],
            )
            self.assertFalse((dev_mapper / "containerd-erofs-stale").exists())

    def test_accepts_udev_mapper_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block = root / "sys"
            dev_mapper = root / "dev" / "mapper"
            (sys_block / "dm-0" / "dm").mkdir(parents=True)
            (sys_block / "dm-0" / "dm" / "name").write_text("containerd-erofs-1")
            (sys_block / "dm-0" / "dev").write_text("254:0")
            dev_mapper.mkdir(parents=True)
            (dev_mapper / "containerd-erofs-1").symlink_to("../dm-0")

            with mock.patch.object(monitor, "SYS_BLOCK", sys_block), mock.patch.object(
                monitor, "DEV_ROOT", root / "dev"
            ), mock.patch.object(monitor, "DEV_MAPPER", dev_mapper), mock.patch.object(
                os, "mknod"
            ) as mknod:
                monitor.reconcile()

            mknod.assert_called_once_with(
                root / "dev" / "dm-0", stat.S_IFBLK | 0o600, os.makedev(254, 0)
            )


if __name__ == "__main__":
    unittest.main()