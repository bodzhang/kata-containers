import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "analyze_request_provenance.py"
SPEC = importlib.util.spec_from_file_location("analyze_request_provenance", SCRIPT)
analysis = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(analysis)


class RequestProvenanceTests(unittest.TestCase):
    def test_reports_oci_mutations_runtime_storage_and_environment_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            (capture / "raw-oci").mkdir()
            (capture / "createcontainer-requests").mkdir()
            (capture / "images" / "configs").mkdir(parents=True)
            (capture / "workload.yaml").write_text(
                """apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: workload
    image: registry/image@sha256:manifest
    env:
    - name: YAML_VALUE
      value: from-yaml
    - name: IMAGE_OVERRIDE
      value: from-yaml
    - name: POD_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
""",
                encoding="utf-8",
            )
            config = {
                "config": {
                    "Cmd": ["--serve"],
                    "Entrypoint": ["/bin/image"],
                    "Env": ["IMAGE_VALUE=from-image", "IMAGE_OVERRIDE=from-image"],
                }
            }
            (capture / "images" / "configs" / "config.json").write_text(
                json.dumps(config), encoding="utf-8"
            )
            (capture / "images" / "index.json").write_text(
                json.dumps(
                    {
                        "images": {
                            "registry/image@sha256:manifest": {
                                "config_path": "configs/config.json"
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            raw = {
                "process": {
                    "args": ["/bin/image", "--serve"],
                    "cwd": "/",
                    "env": [
                        "IMAGE_VALUE=from-image",
                        "YAML_VALUE=from-yaml",
                        "IMAGE_OVERRIDE=from-yaml",
                        "POD_NAME=test",
                    ],
                },
                "mounts": [],
            }
            request = {
                "container_id": "container",
                "oci": {
                    **raw,
                    "annotations": {
                        "io.kubernetes.cri.container-name": "workload",
                        "io.kubernetes.cri.image-name": "registry/image@sha256:manifest",
                    },
                },
                "storages": [{"driver": "blk", "options": ["hash"]}],
                "devices": [],
                "shared_mounts": [],
            }
            (capture / "raw-oci" / "0001-container.config.json").write_text(
                json.dumps(raw), encoding="utf-8"
            )
            (capture / "createcontainer-requests" / "0001-container.json").write_text(
                json.dumps(request), encoding="utf-8"
            )

            transformations, provenance = analysis.analyze(capture)

            changes = transformations["requests"][0]["changes"]
            self.assertIn("oci-annotations", {change["section"] for change in changes})
            self.assertIn("agent-storages", {change["section"] for change in changes})
            sources = {
                entry.get("value") if isinstance(entry.get("value"), str) else "storage": entry[
                    "source"
                ]
                for entry in provenance["entries"]
            }
            self.assertEqual(sources["IMAGE_VALUE=from-image"], "image-config")
            self.assertEqual(sources["YAML_VALUE=from-yaml"], "yaml-declared")
            self.assertEqual(sources["POD_NAME=test"], "kubernetes-resolved")
            paths = {entry.get("path"): entry for entry in provenance["entries"]}
            self.assertEqual(paths["/storages/0"]["source"], "profile-runtime")
            self.assertEqual(paths["/oci/process/args"]["source"], "image-config")
            self.assertEqual(paths["/oci/process/cwd"]["source"], "cri-generated")
            self.assertEqual(paths["/oci/process/user"]["source"], "cri-generated")
            self.assertTrue(all("stage" in entry for entry in provenance["entries"]))
            overridden = [
                entry
                for entry in provenance["entries"]
                if entry.get("disposition") == "overridden"
            ]
            self.assertEqual(overridden[0]["value"], "IMAGE_OVERRIDE=from-image")


if __name__ == "__main__":
    unittest.main()