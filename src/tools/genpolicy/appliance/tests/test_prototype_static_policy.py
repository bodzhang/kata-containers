import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "prototype_static_policy.py"
SPEC = importlib.util.spec_from_file_location("prototype_static_policy", SCRIPT)
prototype = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(prototype)


class StaticPolicyPrototypeTests(unittest.TestCase):
    def make_capture(self, root: Path):
        (root / "images" / "configs").mkdir(parents=True)
        (root / "raw-oci").mkdir()
        (root / "createcontainer-requests").mkdir()
        workload = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  FROM_CONFIG: trusted
---
apiVersion: v1
kind: Secret
metadata:
  name: secret
data:
  TOKEN: {base64.b64encode(b'secret-value').decode()}
---
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: registry/image@sha256:manifest
    command: [/bin/yaml]
    args: [serve]
    workingDir: /work
    envFrom:
    - configMapRef:
        name: config
    - secretRef:
        name: secret
    env:
    - name: IMAGE_VALUE
      value: overridden
    - name: POD_UID
      valueFrom:
        fieldRef:
          fieldPath: metadata.uid
    readinessProbe:
      exec:
        command: [/bin/check]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
"""
        (root / "workload.yaml").write_text(workload, encoding="utf-8")
        config = {
            "config": {
                "Cmd": ["image-arg"],
                "Entrypoint": ["/bin/image"],
                "Env": ["IMAGE_VALUE=image", "ONLY_IMAGE=yes"],
                "WorkingDir": "/image-work",
            }
        }
        (root / "images" / "configs" / "config.json").write_text(
            json.dumps(config), encoding="utf-8"
        )
        (root / "images" / "index.json").write_text(
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

    def test_generates_static_constraints_without_profile_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)

            result = prototype.generate_static_ir(capture)

            subject = result["subjects"][0]
            constraints = subject["constraints"]
            self.assertEqual(subject["subject"], "container/app")
            self.assertEqual(
                constraints["/OCI/Annotations/io.kubernetes.cri.container-name"],
                "app",
            )
            self.assertEqual(constraints["/OCI/Process/Args"], ["/bin/yaml", "serve"])
            self.assertEqual(constraints["/OCI/Process/Cwd"], "/work")
            self.assertEqual(
                constraints["/OCI/Process/Env"],
                {
                    "FROM_CONFIG": "trusted",
                    "IMAGE_VALUE": "overridden",
                    "ONLY_IMAGE": "yes",
                    "TOKEN": "secret-value",
                },
            )
            self.assertTrue(constraints["/OCI/Process/NoNewPrivileges"])
            self.assertTrue(constraints["/OCI/Root/Readonly"])
            self.assertEqual(constraints["/exec_commands"], [["/bin/check"]])
            self.assertEqual(subject["unresolved"][0]["name"], "POD_UID")
            serialized = json.dumps(result)
            self.assertNotIn("root_path", serialized)
            self.assertNotIn("sandbox-id", serialized)
            self.assertNotIn("ociVersion", serialized)

    def test_rejects_non_digest_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            workload = (capture / "workload.yaml").read_text(encoding="utf-8")
            (capture / "workload.yaml").write_text(
                workload.replace("registry/image@sha256:manifest", "registry/image:latest"),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "not digest-bound"):
                prototype.generate_static_ir(capture)

    def test_rejects_duplicate_static_subject_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            workload = (capture / "workload.yaml").read_text(encoding="utf-8")
            pod = workload[workload.index("apiVersion: v1\nkind: Pod") :]
            (capture / "workload.yaml").write_text(
                workload + "---\n" + pod.replace("name: test", "name: second", 1),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "static subject identity is ambiguous"):
                prototype.generate_static_ir(capture)

    def test_generates_uvm_static_pause_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            baseline = capture / "uvm-static.json"
            constraints = {
                "/OCI/Process/Args": ["/pause"],
                "/OCI/Process/Cwd": "/",
                "/OCI/Process/Env": ["PATH=/usr/bin"],
                "/OCI/Process/NoNewPrivileges": True,
                "/OCI/Process/User": {
                    "AdditionalGids": [65535],
                    "GID": 65535,
                    "UID": 65535,
                    "Username": "",
                },
                "/OCI/Root/Path": "$(root_path)",
                "/OCI/Root/Readonly": True,
            }
            baseline.write_text(
                json.dumps(
                    {
                        "artifact_digest": f"sha256:{'a' * 64}",
                        "pause_constraints": constraints,
                        "schema_version": 1,
                    }
                ),
                encoding="utf-8",
            )

            result = prototype.generate_static_ir(capture, baseline)

            sandbox = result["subjects"][1]
            self.assertEqual(sandbox["subject"], "sandbox/default/test")
            self.assertEqual(sandbox["constraints"], constraints)
            self.assertEqual(sandbox["static_artifact"], f"sha256:{'a' * 64}")

    def test_rejects_profile_owned_uvm_static_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline = Path(temporary) / "uvm-static.json"
            baseline.write_text(
                json.dumps(
                    {
                        "artifact_digest": f"sha256:{'a' * 64}",
                        "pause_constraints": {
                            path: [] for path in prototype.UVM_STATIC_PATHS
                        }
                        | {"/OCI/Linux/Namespaces": []},
                        "schema_version": 1,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "profile-owned or unknown"):
                prototype.uvm_static_baseline(baseline)

    def test_compares_uvm_static_pause_subject(self):
        constraints = {
            "/OCI/Process/Args": ["/pause"],
            "/OCI/Process/Env": ["PATH=/usr/bin"],
            "/OCI/Root/Readonly": True,
        }
        static_ir = {
            "subjects": [
                {
                    "constraints": constraints,
                    "namespace": "default",
                    "subject": "sandbox/default/test",
                }
            ]
        }
        policy = {
            "containers": [
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "sandbox",
                            "io.kubernetes.cri.sandbox-namespace": "default",
                        },
                        "Process": {"Args": ["/pause"], "Env": ["PATH=/usr/bin"]},
                        "Root": {"Readonly": True},
                    }
                }
            ]
        }

        comparison = prototype.compare_static(static_ir, policy)

        self.assertEqual(comparison["result"], "pass")
        self.assertEqual(comparison["matched"], 3)

    def test_does_not_guess_ambiguous_sandbox_subject(self):
        static_ir = {
            "subjects": [
                {
                    "constraints": {"/OCI/Process/Args": ["/pause"]},
                    "namespace": "default",
                    "subject": "sandbox/default/first",
                },
                {
                    "constraints": {"/OCI/Process/Args": ["/pause"]},
                    "namespace": "default",
                    "subject": "sandbox/default/second",
                },
            ]
        }
        policy = {
            "containers": [
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "sandbox",
                            "io.kubernetes.cri.sandbox-namespace": "default",
                        }
                    }
                },
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "sandbox",
                            "io.kubernetes.cri.sandbox-namespace": "default",
                        }
                    }
                },
            ]
        }

        comparison = prototype.compare_static(static_ir, policy)

        self.assertEqual(comparison["result"], "fail")
        self.assertEqual(comparison["matched"], 0)

    def test_rejects_duplicate_final_policy_subject_identity(self):
        container = {
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-name": "app",
                    "io.kubernetes.cri.container-type": "container",
                }
            }
        }

        with self.assertRaisesRegex(ValueError, "policy subject identity is ambiguous"):
            prototype.policy_subjects({"containers": [container, container]})

    def test_merges_legacy_settings_patches_in_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "settings.json"
            first = root / "10-first.json"
            second = root / "20-second.json"
            base.write_text(
                json.dumps({"kata_config": {"oci_version": "1.1.0"}, "values": []}),
                encoding="utf-8",
            )
            first.write_text(
                json.dumps(
                    [
                        {
                            "op": "replace",
                            "path": "/kata_config/oci_version",
                            "value": "1.2.0",
                        },
                        {"op": "add", "path": "/values/-", "value": "first"},
                    ]
                ),
                encoding="utf-8",
            )
            second.write_text(
                json.dumps(
                    [
                        {
                            "op": "test",
                            "path": "/kata_config/oci_version",
                            "value": "1.2.0",
                        },
                        {
                            "op": "replace",
                            "path": "/kata_config/oci_version",
                            "value": "1.3.0",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            settings = prototype.merged_settings(base, [first, second])

            self.assertEqual(settings["kata_config"]["oci_version"], "1.3.0")
            self.assertEqual(settings["values"], ["first"])

    def test_settings_patch_decodes_json_pointer_tokens(self):
        settings = {"escaped/key": {"tilde~key": "old"}}

        prototype.apply_settings_patch(
            settings,
            [
                {
                    "op": "replace",
                    "path": "/escaped~1key/tilde~0key",
                    "value": "new",
                }
            ],
        )

        self.assertEqual(settings["escaped/key"]["tilde~key"], "new")
        self.assertEqual(
            prototype.pointer_value(settings, "/escaped~1key/tilde~0key"), "new"
        )

    def test_settings_patch_rejects_root_replacement(self):
        with self.assertRaisesRegex(ValueError, "settings root"):
            prototype.apply_settings_patch({}, [{"op": "replace", "path": "", "value": {}}])

    def test_reports_settings_leaf_coverage(self):
        settings = {
            "common": {"exact": "value", "compiler_only": "input"},
            "sandbox": {},
            "request_defaults": {},
            "devices": {},
            "cluster_config": {"mode": "expected"},
        }
        policy = {
            "common": {"exact": "value"},
            "sandbox": {},
            "request_defaults": {},
            "devices": {},
            "cluster_config": {"mode": "different"},
        }

        coverage = prototype.settings_leaf_coverage(settings, policy)

        self.assertEqual(coverage["matched"], 1)
        self.assertEqual(coverage["changed"], 1)
        self.assertEqual(coverage["not_serialized"], 1)


if __name__ == "__main__":
    unittest.main()
