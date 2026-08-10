import base64
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml


SCRIPT = Path(__file__).parents[1] / "scripts" / "prototype_static_policy.py"
SPEC = importlib.util.spec_from_file_location("prototype_static_policy", SCRIPT)
prototype = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(prototype)


class StaticPolicyPrototypeTests(unittest.TestCase):
    def test_normalizes_kubernetes_capability_intent(self):
        self.assertEqual(
            prototype.normalized_capabilities(
                {
                    "capabilities": {
                        "add": ["net_admin", "CAP_SYS_TIME", "net_admin"],
                        "drop": ["all", "CAP_CHOWN"],
                    }
                }
            ),
            {
                "add": ["CAP_NET_ADMIN", "CAP_SYS_TIME"],
                "drop": ["ALL", "CAP_CHOWN"],
            },
        )

    def write_profile(self, root: Path, mode: str):
        profile = {
            "rootfs_mode": mode,
            "schema_version": 1,
        }
        profile["identity"] = hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        (root / "profile.json").write_text(json.dumps(profile), encoding="utf-8")
        return profile

    def read_workload(self, root: Path):
        return list(yaml.safe_load_all((root / "workload.yaml").read_text(encoding="utf-8")))

    def write_workload(self, root: Path, documents: list[dict]):
        (root / "workload.yaml").write_text(
            yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8"
        )

    def document(self, documents: list[dict], kind: str):
        return next(document for document in documents if document.get("kind") == kind)

    def make_capture(self, root: Path):
        (root / "images" / "configs").mkdir(parents=True)
        (root / "raw-oci").mkdir()
        (root / "createcontainer-requests").mkdir()
        manifest_digest = f"sha256:{'a' * 64}"
        image_reference = f"registry/image@{manifest_digest}"
        documents = [
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "backend"},
                "spec": {
                    "ports": [
                        {"name": "https", "port": 8443, "protocol": "TCP"}
                    ]
                },
            },
            {
                "apiVersion": "v1",
                "data": {"FROM_CONFIG": "trusted"},
                "kind": "ConfigMap",
                "metadata": {"name": "config"},
            },
            {
                "apiVersion": "v1",
                "data": {"TOKEN": base64.b64encode(b"secret-value").decode()},
                "kind": "Secret",
                "metadata": {"name": "secret"},
            },
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "args": ["serve"],
                            "command": ["/bin/yaml"],
                            "env": [
                                {"name": "IMAGE_VALUE", "value": "overridden"},
                                {
                                    "name": "POD_UID",
                                    "valueFrom": {
                                        "fieldRef": {"fieldPath": "metadata.uid"}
                                    },
                                },
                            ],
                            "envFrom": [
                                {
                                    "configMapRef": {"name": "config"},
                                    "prefix": "CFG_",
                                },
                                {"secretRef": {"name": "secret"}},
                            ],
                            "image": image_reference,
                            "name": "app",
                            "readinessProbe": {
                                "exec": {"command": ["/bin/check"]}
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                            },
                            "volumeMounts": [
                                {"mountPath": "/scratch", "name": "scratch"},
                                {
                                    "mountPath": "/etc/configuration",
                                    "name": "configuration",
                                    "readOnly": True,
                                },
                            ],
                            "workingDir": "/work",
                        }
                    ],
                    "volumes": [
                        {
                            "emptyDir": {
                                "medium": "Memory",
                                "sizeLimit": "64Mi",
                            },
                            "name": "scratch",
                        },
                        {
                            "configMap": {"name": "config"},
                            "name": "configuration",
                        },
                    ],
                },
            },
        ]
        workload = yaml.safe_dump_all(documents, sort_keys=False)
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
                        image_reference: {
                            "config_path": "configs/config.json"
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        self.write_profile(root, "guest-pull")

    def test_generates_static_constraints_without_profile_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)

            result = prototype.generate_static_ir(capture)

            subject = result["subjects"][0]
            profile = json.loads((capture / "profile.json").read_text(encoding="utf-8"))
            self.assertEqual(result["profile_identity"], profile["identity"])
            self.assertEqual(
                result["services"],
                [
                    {
                        "name": "backend",
                        "namespace": "default",
                        "ports": [
                            {"name": "https", "port": 8443, "protocol": "TCP"}
                        ],
                    }
                ],
            )
            self.assertEqual(
                result["workloads"],
                [{"kind": "Pod", "name": "test", "namespace": "default"}],
            )
            constraints = subject["constraints"]
            self.assertEqual(subject["subject"], "container/app")
            self.assertEqual(
                subject["rootfs"],
                {
                    "image_manifest_digest": f"sha256:{'a' * 64}",
                    "mode": "guest-pull",
                    "profile_identity": profile["identity"],
                },
            )
            self.assertEqual(
                constraints["/OCI/Annotations/io.kubernetes.cri.container-name"],
                "app",
            )
            self.assertEqual(constraints["/OCI/Process/Args"], ["/bin/yaml", "serve"])
            self.assertEqual(constraints["/OCI/Process/Cwd"], "/work")
            self.assertEqual(
                constraints["/OCI/Process/Env"],
                {
                    "CFG_FROM_CONFIG": "trusted",
                    "IMAGE_VALUE": "overridden",
                    "ONLY_IMAGE": "yes",
                    "TOKEN": "secret-value",
                },
            )
            self.assertEqual(
                subject["env_from"],
                [
                    {
                        "content_digest": prototype.content_digest(
                            {"FROM_CONFIG": "trusted"}
                        ),
                        "keys": ["FROM_CONFIG"],
                        "name": "config",
                        "namespace": "default",
                        "optional": False,
                        "prefix": "CFG_",
                        "role": "config-map",
                        "status": "resolved",
                    },
                    {
                        "content_digest": prototype.content_digest(
                            {"TOKEN": "secret-value"}
                        ),
                        "keys": ["TOKEN"],
                        "name": "secret",
                        "namespace": "default",
                        "optional": False,
                        "prefix": "",
                        "role": "secret",
                        "status": "resolved",
                    },
                ],
            )
            self.assertTrue(constraints["/OCI/Process/NoNewPrivileges"])
            self.assertTrue(constraints["/OCI/Root/Readonly"])
            self.assertEqual(constraints["/exec_commands"], [["/bin/check"]])
            self.assertEqual(subject["unresolved"][0]["name"], "POD_UID")
            self.assertEqual(
                subject["volumes"],
                [
                    {
                        "destination": "/scratch",
                        "destination_basename": "scratch",
                        "medium": "memory",
                        "name": "scratch",
                        "read_only": False,
                        "role": "empty-dir",
                        "size_limit": "64Mi",
                    },
                    {
                        "destination": "/etc/configuration",
                        "destination_basename": "configuration",
                        "name": "configuration",
                        "read_only": True,
                        "role": "config-map",
                        "source": {
                            "content_digest": prototype.content_digest(
                                {"FROM_CONFIG": "trusted"}
                            ),
                            "keys": ["FROM_CONFIG"],
                            "name": "config",
                            "namespace": "default",
                            "status": "resolved",
                        },
                    },
                ],
            )
            serialized = json.dumps(result)
            self.assertNotIn("root_path", serialized)
            self.assertNotIn("sandbox-id", serialized)
            self.assertNotIn("ociVersion", serialized)

            rego = prototype.render_static_rego_ir(result)
            self.assertTrue(rego.startswith("package static_policy_ir\n\nir := {"))
            self.assertIn('"subject": "container/app"', rego)

    def test_rejects_non_digest_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            workload = (capture / "workload.yaml").read_text(encoding="utf-8")
            (capture / "workload.yaml").write_text(
                workload.replace(
                    f"registry/image@sha256:{'a' * 64}", "registry/image:latest"
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "not digest-bound"):
                prototype.generate_static_ir(capture)

    def test_required_env_from_object_must_be_supplied(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            self.write_workload(
                capture,
                [
                    document
                    for document in documents
                    if document.get("kind") != "ConfigMap"
                ],
            )

            with self.assertRaisesRegex(
                ValueError, "required envFrom config-map is missing"
            ):
                prototype.generate_static_ir(capture)

    def test_optional_missing_env_from_is_typed_and_adds_no_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            reference = self.document(documents, "Pod")["spec"]["containers"][0]["envFrom"][0][
                "configMapRef"
            ]
            reference["name"] = "not-present"
            reference["optional"] = True
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            subject = result["subjects"][0]
            self.assertEqual(
                subject["env_from"][0],
                {
                    "name": "not-present",
                    "namespace": "default",
                    "optional": True,
                    "prefix": "CFG_",
                    "role": "config-map",
                    "status": "absent",
                },
            )
            self.assertNotIn("CFG_FROM_CONFIG", subject["constraints"]["/OCI/Process/Env"])

    def test_duplicate_trusted_env_from_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            config_map = self.document(documents, "ConfigMap")
            self.write_workload(capture, [config_map, *documents])

            with self.assertRaisesRegex(ValueError, "duplicate trusted ConfigMap"):
                prototype.generate_static_ir(capture)

    def test_rejects_unsupported_volume_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            volume = self.document(documents, "Pod")["spec"]["volumes"][1]
            volume["hostPath"] = {"path": "/host/config"}
            del volume["configMap"]
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "supported source"):
                prototype.generate_static_ir(capture)

    def test_rejects_undeclared_volume_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            self.document(documents, "Pod")["spec"]["containers"][0]["volumeMounts"][0]["name"] = "missing"
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "undeclared volume"):
                prototype.generate_static_ir(capture)

    def test_rejects_dynamic_volume_subpath(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            self.document(documents, "Pod")["spec"]["containers"][0]["volumeMounts"][0][
                "subPathExpr"
            ] = "$(POD_NAME)"
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "subPathExpr"):
                prototype.generate_static_ir(capture)

    def test_rejects_volume_devices_until_device_intent_is_modeled(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            self.document(documents, "Pod")["spec"]["containers"][0]["volumeDevices"] = [
                {"devicePath": "/dev/data", "name": "scratch"}
            ]
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "volumeDevices intent"):
                prototype.generate_static_ir(capture)

    def test_optional_missing_resource_volume_is_typed_as_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
                {
                    "name": "optional-config",
                    "configMap": {"name": "missing", "optional": True},
                }
            )
            pod["spec"]["containers"][0]["volumeMounts"].append(
                {
                    "mountPath": "/optional-config",
                    "name": "optional-config",
                    "readOnly": True,
                }
            )
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)
            volume = next(
                volume
                for volume in result["subjects"][0]["volumes"]
                if volume["name"] == "optional-config"
            )

            self.assertEqual(
                volume["source"],
                {
                    "name": "missing",
                    "namespace": "default",
                    "optional": True,
                    "status": "absent",
                },
            )

    def test_generates_secret_downward_api_and_projected_volume_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].extend(
                [
                    {
                        "name": "credentials",
                        "secret": {"optional": False, "secretName": "secret"},
                    },
                    {
                        "downwardAPI": {
                            "items": [
                                {
                                    "fieldRef": {"fieldPath": "metadata.name"},
                                    "path": "name",
                                }
                            ]
                        },
                        "name": "podinfo",
                    },
                    {
                        "name": "combined",
                        "projected": {
                            "sources": [
                                {"configMap": {"name": "config"}},
                                {"secret": {"name": "secret"}},
                                {
                                    "serviceAccountToken": {
                                        "audience": "api",
                                        "path": "token",
                                    }
                                },
                            ]
                        },
                    },
                ]
            )
            pod["spec"]["containers"][0]["volumeMounts"].extend(
                [
                    {"mountPath": "/credentials", "name": "credentials", "readOnly": True},
                    {"mountPath": "/podinfo", "name": "podinfo", "readOnly": True},
                    {"mountPath": "/combined", "name": "combined", "readOnly": True},
                ]
            )
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            volumes = {volume["name"]: volume for volume in result["subjects"][0]["volumes"]}
            self.assertEqual(volumes["credentials"]["role"], "secret")
            self.assertEqual(
                volumes["credentials"]["source"],
                {
                    "content_digest": prototype.content_digest(
                        {"TOKEN": "secret-value"}
                    ),
                    "keys": ["TOKEN"],
                    "name": "secret",
                    "namespace": "default",
                    "optional": False,
                    "status": "resolved",
                },
            )
            self.assertEqual(volumes["podinfo"]["role"], "downward-api")
            self.assertEqual(volumes["combined"]["role"], "projected")
            self.assertEqual(
                [source["role"] for source in volumes["combined"]["sources"]],
                ["config-map", "secret", "service-account-token"],
            )

    def test_generates_dmverity_rootfs_from_trusted_artifact_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            self.write_profile(capture, "erofs-dmverity")
            artifacts = capture / "rootfs-artifacts.json"
            artifacts.write_text(
                json.dumps(
                    {
                        "images": {
                            f"sha256:{'a' * 64}": {
                                "root_hash": f"sha256:{'c' * 64}"
                            }
                        },
                        "schema_version": 1,
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            result = prototype.generate_static_ir(
                capture, rootfs_artifacts_path=artifacts
            )

            rootfs = result["subjects"][0]["rootfs"]
            self.assertEqual(rootfs["mode"], "erofs-dmverity")
            self.assertEqual(rootfs["image_manifest_digest"], f"sha256:{'a' * 64}")
            self.assertEqual(rootfs["dm_verity_root_hash"], f"sha256:{'c' * 64}")
            self.assertRegex(rootfs["artifact_manifest_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_dmverity_rootfs_requires_trusted_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            self.write_profile(capture, "erofs-dmverity")

            with self.assertRaisesRegex(ValueError, "rootfs artifact is missing"):
                prototype.generate_static_ir(capture)

    def test_static_rootfs_requires_capture_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            (capture / "profile.json").unlink()

            with self.assertRaisesRegex(ValueError, "capture profile is missing"):
                prototype.generate_static_ir(capture)

    def test_static_rootfs_rejects_unbound_profile_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            profile = json.loads((capture / "profile.json").read_text(encoding="utf-8"))
            profile["rootfs_mode"] = "erofs-dmverity"
            (capture / "profile.json").write_text(json.dumps(profile), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "profile identity mismatch"):
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
