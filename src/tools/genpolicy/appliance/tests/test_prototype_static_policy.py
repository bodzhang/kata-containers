import base64
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


SCRIPT = Path(__file__).parents[1] / "scripts" / "prototype_static_policy.py"
FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE_FIXTURE = (
    Path(__file__).parents[1]
    / "fragment-policy-composer"
    / "fixtures"
    / "run-complex-capture"
)
SPEC = importlib.util.spec_from_file_location("prototype_static_policy", SCRIPT)
prototype = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(prototype)


class StaticPolicyPrototypeTests(unittest.TestCase):
    def test_generates_device_direct_volume_fixture_ir(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture"
            shutil.copytree(CAPTURE_FIXTURE, capture)
            shutil.copyfile(
                FIXTURES / "device-direct-volume-workload.yaml",
                capture / "workload.yaml",
            )

            result = prototype.generate_static_ir(capture, rootfs_mode="guest-pull")
            subject = next(
                subject
                for subject in result["subjects"]
                if subject["subject"] == "container/workload"
            )

            self.assertEqual(
                subject["device_requests"]["extended_resources"],
                [
                    {
                        "count": 2,
                        "resource": "nvidia.com/gpu",
                        "resolution": "device-profile",
                    }
                ],
            )
            self.assertEqual(
                subject["device_requests"]["volume_devices"][0]["device_path"],
                "/dev/workload-data",
            )
            self.assertEqual(
                [volume["role"] for volume in subject["volumes"]],
                ["direct-volume"],
            )
            self.assertNotIn("/var/lib/genpolicy/device-test", json.dumps(subject))
            self.assertNotIn("device-test-data", json.dumps(subject))

    def test_rejects_image_content_tampered_after_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            images = Path(temporary)
            config = json.dumps({"config": {"Env": ["A=B"]}}).encode()
            config_digest = f"sha256:{hashlib.sha256(config).hexdigest()}"
            config_path = images / "config.json"
            config_path.write_bytes(config)

            document = prototype.verified_image_document(
                images, config_path.name, config_digest
            )
            self.assertEqual(document["config"]["Env"], ["A=B"])

            config_path.write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "content digest mismatch"):
                prototype.verified_image_document(
                    images, config_path.name, config_digest
                )

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
                    "automountServiceAccountToken": False,
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
                            "config_path": "configs/config.json",
                            "user_database": {
                                "group": "root:x:0:\nwheel:x:10:root\n",
                                "passwd": "root:x:0:0:root:/root:/bin/sh\n",
                            },
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
                },
            )
            self.assertEqual(
                subject["rootfs_identity_storage"],
                {
                    "driver": "guest-pull-images",
                    "driver_options": [],
                    "source": "",
                    "fstype": "",
                    "options": [f"sha256:{'a' * 64}"],
                    "mount_point": "",
                    "fs_group": None,
                    "shared": False,
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
            self.assertEqual(
                subject["environment_resolutions"],
                [
                    {
                        "owner": "kubelet-resolution",
                        "source": {
                            "api_version": "v1",
                            "field_path": "metadata.uid",
                            "kind": "field-ref",
                        },
                        "target": {
                            "collection": "environment",
                            "name": "POD_UID",
                            "path": "/OCI/Process/Env/POD_UID",
                        },
                        "value": "$(pod-uid)",
                        "value_type": "string",
                    }
                ],
            )
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
                            "content_trust": "untrusted-runtime",
                            "name": "config",
                            "namespace": "default",
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

    def test_config_map_key_ref_resolves_to_exact_static_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            container = self.document(documents, "Pod")["spec"]["containers"][0]
            container["env"].append(
                {
                    "name": "DIRECT_CONFIG",
                    "valueFrom": {
                        "configMapKeyRef": {
                            "key": "FROM_CONFIG",
                            "name": "config",
                        }
                    },
                }
            )
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            subject = result["subjects"][0]
            self.assertEqual(
                subject["constraints"]["/OCI/Process/Env"]["DIRECT_CONFIG"],
                "trusted",
            )
            self.assertFalse(
                any(
                    resolution["target"]["name"] == "DIRECT_CONFIG"
                    for resolution in subject["environment_resolutions"]
                )
            )

    def test_rejects_unsupported_resource_field_ref(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            container = self.document(documents, "Pod")["spec"]["containers"][0]
            container["env"].append(
                {
                    "name": "CPU_LIMIT",
                    "valueFrom": {
                        "resourceFieldRef": {
                            "resource": "limits.cpu",
                        }
                    },
                }
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "unsupported valueFrom source"):
                prototype.generate_static_ir(capture)

    def test_rejects_unsupported_field_ref_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            container = self.document(documents, "Pod")["spec"]["containers"][0]
            container["env"].append(
                {
                    "name": "POD_LABEL",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.labels['app']",
                        }
                    },
                }
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "unsupported fieldRef path"):
                prototype.generate_static_ir(capture)

    def test_duplicate_trusted_env_from_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            config_map = self.document(documents, "ConfigMap")
            self.write_workload(capture, [config_map, *documents])

            with self.assertRaisesRegex(ValueError, "duplicate trusted ConfigMap"):
                prototype.generate_static_ir(capture)

    def test_generates_host_path_volume_intent_as_untrusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            volume = self.document(documents, "Pod")["spec"]["volumes"][1]
            volume["hostPath"] = {"path": "/host/config"}
            del volume["configMap"]
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)
            volume = next(
                volume
                for volume in result["subjects"][0]["volumes"]
                if volume["name"] == "configuration"
            )
            self.assertEqual(volume["role"], "direct-volume")
            self.assertEqual(
                volume["uvm"],
                {
                    "content_trust": "untrusted-runtime",
                    "transport": "shared-fs",
                },
            )
            self.assertNotIn("/host/config", json.dumps(result))

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

    def test_generates_pvc_volume_device_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
                {
                    "name": "data",
                    "persistentVolumeClaim": {
                        "claimName": "workload-data",
                        "readOnly": True,
                    },
                }
            )
            pod["spec"]["containers"][0]["volumeDevices"] = [
                {"devicePath": "/dev/data", "name": "data"}
            ]
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            self.assertEqual(
                result["subjects"][0]["device_requests"]["volume_devices"],
                [
                    {
                        "device_path": "/dev/data",
                        "name": "data",
                        "resolution": "uvm-device",
                    }
                ],
            )
            self.assertNotIn("workload-data", json.dumps(result))

    def test_generates_extended_gpu_resource_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            container = self.document(documents, "Pod")["spec"]["containers"][0]
            container["resources"] = {
                "limits": {"cpu": "2", "nvidia.com/gpu": "2"}
            }
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            self.assertEqual(
                result["subjects"][0]["device_requests"]["extended_resources"],
                [
                    {
                        "count": 2,
                        "resource": "nvidia.com/gpu",
                        "resolution": "device-profile",
                    }
                ],
            )

    def test_rejects_malformed_extended_resource_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            container = self.document(documents, "Pod")["spec"]["containers"][0]
            container["resources"] = {"limits": {"nvidia.com/gpu": "1.5"}}
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "non-negative integer"):
                prototype.generate_static_ir(capture)

    def test_rejects_duplicate_volume_device_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].extend(
                [
                    {
                        "name": "first-data",
                        "persistentVolumeClaim": {"claimName": "first"},
                    },
                    {
                        "name": "second-data",
                        "persistentVolumeClaim": {"claimName": "second"},
                    },
                ]
            )
            pod["spec"]["containers"][0]["volumeDevices"] = [
                {"devicePath": "/dev/data", "name": "first-data"},
                {"devicePath": "/dev/data", "name": "second-data"},
            ]
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "duplicate volumeDevice"):
                prototype.generate_static_ir(capture)

    def test_rejects_inline_csi_mount_without_uvm_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
                {
                    "name": "plugin-data",
                    "csi": {
                        "driver": "example.csi.invalid",
                        "readOnly": True,
                        "volumeAttributes": {"profile": "safe"},
                    },
                }
            )
            pod["spec"]["containers"][0]["volumeMounts"].append(
                {
                    "mountPath": "/plugin-data",
                    "name": "plugin-data",
                    "readOnly": True,
                }
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(ValueError, "no reviewed UVM volume profile"):
                prototype.generate_static_ir(capture)

    def test_optional_resource_volume_remains_watchable_when_initially_absent(self):
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
                    "content_trust": "untrusted-runtime",
                    "name": "missing",
                    "namespace": "default",
                    "optional": True,
                },
            )

    def test_generates_secret_and_projected_volume_intent(self):
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
                        "name": "combined",
                        "projected": {
                            "sources": [
                                {"configMap": {"name": "config"}},
                                {"secret": {"name": "secret"}},
                            ]
                        },
                    },
                ]
            )
            pod["spec"]["containers"][0]["volumeMounts"].extend(
                [
                    {"mountPath": "/credentials", "name": "credentials", "readOnly": True},
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
                    "content_trust": "untrusted-runtime",
                    "name": "secret",
                    "namespace": "default",
                    "optional": False,
                },
            )
            self.assertEqual(volumes["combined"]["role"], "projected")
            self.assertEqual(
                [source["role"] for source in volumes["combined"]["sources"]],
                ["config-map", "secret"],
            )

    def test_accepts_yaml_service_account_when_automount_is_disabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            fixture = Path(__file__).parent / "fixtures" / "service-account-workload.yaml"
            fixture_pod = yaml.safe_load(fixture.read_text(encoding="utf-8"))
            documents = self.read_workload(capture)
            source_pod = self.document(documents, "Pod")
            fixture_pod["spec"]["containers"][0]["image"] = source_pod["spec"][
                "containers"
            ][0]["image"]
            documents = [
                fixture_pod if document.get("kind") == "Pod" else document
                for document in documents
            ]
            self.write_workload(capture, documents)

            result = prototype.generate_static_ir(capture)

            self.assertEqual(
                result["subjects"][0]["service_account"],
                {"automount_token": False, "name": "workload-identity"},
            )
            self.assertEqual(
                result["subjects"][0]["constraints"]["/OCI/Process/Env"][
                    "SERVICE_ACCOUNT_NAME"
                ],
                "workload-identity",
            )

    def test_rejects_implicit_service_account_token_automount(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            del self.document(documents, "Pod")["spec"]["automountServiceAccountToken"]
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(
                ValueError, "automountServiceAccountToken must be explicitly false"
            ):
                prototype.generate_static_ir(capture)

    def test_rejects_explicit_service_account_token_automount(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            self.document(documents, "Pod")["spec"]["automountServiceAccountToken"] = True
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(
                ValueError, "automountServiceAccountToken must be explicitly false"
            ):
                prototype.generate_static_ir(capture)

    def test_rejects_explicit_service_account_token_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
                {
                    "name": "identity",
                    "projected": {
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "audience": "api",
                                    "expirationSeconds": 3600,
                                    "path": "token",
                                }
                            }
                        ]
                    },
                }
            )
            pod["spec"]["containers"][0]["volumeMounts"].append(
                {"mountPath": "/identity", "name": "identity", "readOnly": True}
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(
                ValueError, "unsupported without trusted in-guest token verification"
            ):
                prototype.generate_static_ir(capture)

    def test_rejects_downward_api_volume(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
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
                }
            )
            pod["spec"]["containers"][0]["volumeMounts"].append(
                {"mountPath": "/podinfo", "name": "podinfo", "readOnly": True}
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(
                ValueError, "incompatible with the Kata-CC threat model"
            ):
                prototype.generate_static_ir(capture)

    def test_rejects_projected_downward_api_volume(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            documents = self.read_workload(capture)
            pod = self.document(documents, "Pod")
            pod["spec"]["volumes"].append(
                {
                    "name": "projected-podinfo",
                    "projected": {
                        "sources": [
                            {
                                "downwardAPI": {
                                    "items": [
                                        {
                                            "fieldRef": {
                                                "fieldPath": "metadata.name"
                                            },
                                            "path": "name",
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                }
            )
            pod["spec"]["containers"][0]["volumeMounts"].append(
                {
                    "mountPath": "/projected-podinfo",
                    "name": "projected-podinfo",
                    "readOnly": True,
                }
            )
            self.write_workload(capture, documents)

            with self.assertRaisesRegex(
                ValueError, "incompatible with the Kata-CC threat model"
            ):
                prototype.generate_static_ir(capture)

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
                capture,
                rootfs_mode="erofs-dmverity",
                rootfs_artifacts_path=artifacts,
            )

            rootfs = result["subjects"][0]["rootfs"]
            self.assertEqual(rootfs["mode"], "erofs-dmverity")
            self.assertEqual(rootfs["image_manifest_digest"], f"sha256:{'a' * 64}")
            self.assertEqual(rootfs["dm_verity_root_hash"], f"sha256:{'c' * 64}")
            self.assertRegex(rootfs["artifact_manifest_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("profile_identity", rootfs)
            marker = result["subjects"][0]["rootfs_identity_storage"]
            self.assertEqual(marker["driver"], "dmverity-roothashes")
            self.assertEqual(marker["options"], [f"sha256:{'c' * 64}"])

    def test_configured_rootfs_mode_does_not_depend_on_capture_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)
            self.write_profile(capture, "erofs-dmverity")

            result = prototype.generate_static_ir(capture)

            self.assertEqual(
                result["subjects"][0]["rootfs"],
                {
                    "image_manifest_digest": f"sha256:{'a' * 64}",
                    "mode": "guest-pull",
                },
            )

    def test_dmverity_rootfs_requires_trusted_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            self.make_capture(capture)

            with self.assertRaisesRegex(ValueError, "rootfs artifact is missing"):
                prototype.generate_static_ir(
                    capture,
                    rootfs_mode="erofs-dmverity",
                )

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

            result = prototype.generate_static_ir(
                capture,
                uvm_baseline_path=baseline,
            )

            sandbox = result["subjects"][1]
            self.assertEqual(sandbox["subject"], "sandbox/default/test")
            # The pause container is never placed in the shared PID namespace,
            # so the sandbox subject pins it on top of the measured baseline.
            self.assertEqual(
                sandbox["constraints"], {**constraints, "/sandbox_pidns": False}
            )
            self.assertEqual(sandbox["static_artifact"], f"sha256:{'a' * 64}")
            rendered = prototype.render_static_rego_ir(result)
            rendered_ir = json.loads(rendered.split("ir := ", 1)[1])
            self.assertEqual(
                rendered_ir["subjects"][1]["policy"]["OCI"]["Process"]["Env"],
                ["PATH=/usr/bin"],
            )

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

    def test_resolves_image_user_and_group_memberships(self):
        database = {
            "group": "root:x:0:\nwheel:x:10:root\napp:x:2000:app\n",
            "passwd": "root:x:0:0:root:/root:/bin/sh\napp:x:2000:2000:app:/home/app:/bin/sh\n",
        }

        self.assertEqual(
            prototype.container_user_intent({}, {}, {}, database),
            {
                "/OCI/Process/User/AdditionalGids": [0, 10],
                "/OCI/Process/User/GID": 0,
                "/OCI/Process/User/UID": 0,
                "/OCI/Process/User/Username": "",
            },
        )
        self.assertEqual(
            prototype.container_user_intent({}, {}, {"User": "app"}, database),
            {
                "/OCI/Process/User/AdditionalGids": [2000],
                "/OCI/Process/User/GID": 2000,
                "/OCI/Process/User/UID": 2000,
                "/OCI/Process/User/Username": "",
            },
        )

    def test_run_as_user_overrides_image_user_and_memberships(self):
        database = {
            "group": "root:x:0:\nwheel:x:10:root\n",
            "passwd": "root:x:0:0:root:/root:/bin/sh\n",
        }
        container = {"securityContext": {"runAsUser": 1000, "runAsGroup": 3000}}

        self.assertEqual(
            prototype.container_user_intent({}, container, {}, database),
            {
                "/OCI/Process/User/AdditionalGids": [3000],
                "/OCI/Process/User/GID": 3000,
                "/OCI/Process/User/UID": 1000,
                "/OCI/Process/User/Username": "",
            },
        )

    def test_appends_pod_supplemental_groups(self):
        database = {
            "group": "root:x:0:\nwheel:x:10:root\n",
            "passwd": "root:x:0:0:root:/root:/bin/sh\n",
        }
        spec = {"securityContext": {"supplementalGroups": [10, 4000]}}

        self.assertEqual(
            prototype.container_user_intent(spec, {}, {}, database)[
                "/OCI/Process/User/AdditionalGids"
            ],
            [0, 10, 4000],
        )

    def test_rejects_image_without_a_digest_bound_user_database(self):
        with self.assertRaisesRegex(ValueError, "digest-bound image user"):
            prototype.container_user_intent({}, {}, {}, {})

    def test_rejects_image_user_missing_from_the_database(self):
        database = {"group": "root:x:0:\n", "passwd": "root:x:0:0:root:/root:/bin/sh\n"}
        with self.assertRaisesRegex(ValueError, "no /etc/passwd entry"):
            prototype.container_user_intent({}, {}, {"User": "nobody"}, database)


if __name__ == "__main__":
    unittest.main()
