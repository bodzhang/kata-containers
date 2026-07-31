import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "predict_storages.py"
SPEC = importlib.util.spec_from_file_location("predict_storages", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PredictStoragesTests(unittest.TestCase):
    def test_sandbox_id_from_annotation(self):
        spec = {"annotations": {"io.kubernetes.cri.sandbox-id": "sb-1"}}
        self.assertEqual(MODULE.sandbox_id(spec), "sb-1")

    def test_sandbox_id_missing_defaults_empty(self):
        self.assertEqual(MODULE.sandbox_id({}), "")

    def test_collect_uses_meta_cid_and_annotation_sid(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary)
            (raw / "0001-abc.config.json").write_text(
                json.dumps(
                    {"annotations": {"io.kubernetes.cri.sandbox-id": "sb-xyz"}}
                ),
                encoding="utf-8",
            )
            (raw / "0001-abc.meta.json").write_text(
                json.dumps({"container_id": "abc"}), encoding="utf-8"
            )

            captured = {}

            def fake_predict_one(predictor, config, cid, sid, emptydir_mode, block_driver):
                captured["cid"] = cid
                captured["sid"] = sid
                captured["emptydir_mode"] = emptydir_mode
                captured["block_driver"] = block_driver
                return {"container_id": cid, "sandbox_id": sid, "volumes": []}

            with mock.patch.object(MODULE, "predict_one", fake_predict_one):
                report = MODULE.collect(
                    raw, "/usr/local/bin/storage-predictor", "shared-fs", "virtio-blk-pci"
                )

            self.assertEqual(captured["cid"], "abc")
            self.assertEqual(captured["sid"], "sb-xyz")
            self.assertEqual(captured["emptydir_mode"], "shared-fs")
            self.assertEqual(captured["block_driver"], "virtio-blk-pci")
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(len(report["predictions"]), 1)

    def test_collect_records_predictor_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary)
            (raw / "0001-c.config.json").write_text("{}", encoding="utf-8")
            (raw / "0001-c.meta.json").write_text(
                json.dumps({"container_id": "c"}), encoding="utf-8"
            )

            def failing(predictor, config, cid, sid, emptydir_mode, block_driver):
                return {"container_id": cid, "sandbox_id": sid, "error": "boom"}

            with mock.patch.object(MODULE, "predict_one", failing):
                report = MODULE.collect(raw, "predictor", "shared-fs", "virtio-blk-pci")

            self.assertEqual(report["predictions"][0]["error"], "boom")


if __name__ == "__main__":
    unittest.main()
