import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_profile_requests.py"
SPEC = importlib.util.spec_from_file_location("compare_profile_requests", SCRIPT)
comparison = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(comparison)


class ProfileRequestComparisonTests(unittest.TestCase):
    def make_capture(self, root: Path, identity: str, rootfs_mode: str, container_id: str, pod_name: str):
        (root / "createcontainer-requests").mkdir(parents=True)
        (root / "execprocess-requests").mkdir()
        workload = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: service
  namespace: test
spec:
  template:
    spec:
      containers:
      - name: workload
        image: registry/image@sha256:manifest
"""
        (root / "workload.yaml").write_text(workload, encoding="utf-8")
        profile = {
            "capture_backend": "runtime-rs",
            "configuration_hashes": {},
            "identity": identity,
            "rootfs_mode": rootfs_mode,
            "values": {"CONTAINERD_VERSION": "v2.3.3"},
        }
        (root / "profile.json").write_text(json.dumps(profile), encoding="utf-8")
        artifacts = {
            path: {"sha256": "same", "size": 1}
            for path in ("workload.yaml", "requested-images.txt", "images/index.json")
        }
        (root / "manifest.json").write_text(json.dumps({"artifacts": artifacts}), encoding="utf-8")
        annotations = {
            "io.kubernetes.cri.container-name": "workload",
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.sandbox-name": pod_name,
            "io.kubernetes.cri.sandbox-namespace": "test",
            "io.kubernetes.cri.sandbox-uid": f"uid-{identity}",
        }
        request = {
            "container_id": container_id,
            "oci": {
                "annotations": annotations,
                "process": {"args": ["/bin/app"], "env": ["B=2", "A=1"]},
            },
            "storages": [{"driver": rootfs_mode}],
        }
        (root / "createcontainer-requests" / f"0001-{container_id}.json").write_text(
            json.dumps(request), encoding="utf-8"
        )

    def test_pairs_by_workload_and_separates_generated_identity_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            candidate = root / "candidate"
            self.make_capture(baseline, "base", "native", "base-id", "service-old")
            self.make_capture(candidate, "next", "erofs-dmverity", "next-id", "service-new")
            candidate_path = next((candidate / "createcontainer-requests").glob("*.json"))
            request = json.loads(candidate_path.read_text(encoding="utf-8"))
            request["oci"]["process"]["env"] = ["A=1", "B=2"]
            candidate_path.write_text(json.dumps(request), encoding="utf-8")

            report = comparison.compare(baseline, candidate)

            self.assertEqual(report["profile_delta"]["attributed_cause"]["path"], "/rootfs_mode")
            entry = report["requests"][0]
            self.assertEqual(entry["status"], "paired")
            self.assertIn("/container_id", {change["path"] for change in entry["raw_changes"]})
            self.assertNotIn("/container_id", {change["path"] for change in entry["normalized_changes"]})
            normalized = {change["path"]: change for change in entry["normalized_changes"]}
            self.assertEqual(normalized["/oci/process/env"]["change"], "reordered")
            self.assertEqual(normalized["/storages"]["section"], "agent-storages")


if __name__ == "__main__":
    unittest.main()