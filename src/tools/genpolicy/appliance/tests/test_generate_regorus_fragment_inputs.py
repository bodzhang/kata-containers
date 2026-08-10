import importlib.util
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "scripts"
    / "generate_regorus_fragment_inputs.py"
)
SPEC = importlib.util.spec_from_file_location("generate_regorus_fragment_inputs", SCRIPT)
renderer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(renderer)


class RegorusFragmentInputTests(unittest.TestCase):
    def test_empty_object_owns_no_policy_leaf(self):
        self.assertEqual(renderer.leaf_paths({}), [])

    def test_sparse_patch_decodes_json_pointer_tokens(self):
        self.assertEqual(
            renderer.sparse_patch("/OCI/Process/Env/A~1B", "value"),
            {"OCI": {"Process": {"Env": {"A/B": "value"}}}},
        )

    def test_static_rego_ir_targets_embedded_agent_framework(self):
        report = {
            "binding": {
                "profile_identity": "a" * 64,
                "static_base_digest": "b" * 64,
            },
            "fragments": [{"category": "runtime-rs"}, {"category": "containerd-oci"}],
            "static_policy": {"policy_data": {}, "subjects": []},
        }

        result = renderer.regorus_static_ir(report)

        self.assertEqual(
            result["agent_framework_version"], renderer.AGENT_FRAMEWORK_VERSION
        )

    def test_static_rego_ir_replaces_profile_identity_with_applicability_inputs(self):
        report = {
            "binding": {
                "profile_identity": "a" * 64,
                "static_base_digest": "b" * 64,
            },
            "fragments": [{"category": "runtime-rs"}, {"category": "containerd-oci"}],
            "static_policy": {"policy_data": {}, "subjects": []},
        }
        profile = {
            "rootfs_mode": "erofs-dmverity",
            "values": {"CONTAINERD_VERSION": "v2.3.3", "KUBERNETES_VERSION": "v1.33.13"},
        }
        static_ir = {"rootfs_mode": "guest-pull", "subjects": []}

        result = renderer.regorus_static_ir(report, static_ir, profile)

        self.assertNotIn("profile_identity", result)
        self.assertEqual(result["capture_provenance"], "a" * 64)
        self.assertEqual(
            result["requires"], {"categories": ["containerd-oci", "runtime-rs"]}
        )
        self.assertEqual(
            result["environment"],
            {
                "containerd": "v2.3.3",
                "kubernetes": "v1.33.13",
                "rootfs_mode": "guest-pull",
            },
        )

    def test_static_rego_ir_preserves_rootfs_authority(self):
        report = {
            "binding": {
                "profile_identity": "a" * 64,
                "static_base_digest": "b" * 64,
            },
            "fragments": [],
            "static_policy": {
                "policy_data": {},
                "subjects": [
                    {
                        "id": "container/app",
                        "ordinal": 0,
                        "policy": {},
                    }
                ],
            },
        }
        rootfs = {
            "artifact_manifest_digest": f"sha256:{'c' * 64}",
            "dm_verity_root_hash": f"sha256:{'d' * 64}",
            "image_manifest_digest": f"sha256:{'e' * 64}",
        }
        static_ir = {
            "rootfs_mode": "erofs-dmverity",
            "subjects": [
                {
                    "rootfs": rootfs,
                    "rootfs_identity_storage": {
                        "driver": "dmverity-roothashes",
                        "options": [f"sha256:{'d' * 64}"],
                    },
                    "subject": "container/app",
                }
            ]
        }

        result = renderer.regorus_static_ir(report, static_ir)

        self.assertEqual(result["subjects"][0]["rootfs"], rootfs)
        self.assertEqual(
            result["subjects"][0]["rootfs_identity_storage"]["driver"],
            "dmverity-roothashes",
        )

    def test_copy_file_patterns_are_sorted_deduplicated_and_watchable(self):
        static_ir = {
            "subjects": [
                {
                    "volumes": [
                        {
                            "role": "secret",
                            "destination_basename": "credentials",
                            "source": {"content_trust": "untrusted-runtime"},
                        },
                        {
                            "role": "config-map",
                            "destination_basename": "configuration",
                            "source": {"content_trust": "untrusted-runtime"},
                        },
                        {
                            "role": "config-map",
                            "destination_basename": "configuration",
                            "source": {"content_trust": "untrusted-runtime"},
                        },
                        {
                            "role": "secret",
                            "destination_basename": "missing",
                            "source": {"content_trust": "pinned-static"},
                        },
                    ]
                }
            ]
        }

        self.assertEqual(
            renderer.copy_file_patterns(static_ir),
            [
                "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-configuration",
                "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-credentials",
            ],
        )

    def test_service_environment_is_regex_scoped_to_application_container(self):
        policy = {
            "containers": [
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "sandbox"
                        },
                        "Process": {"Env": ["BACKEND_SERVICE_HOST=10.0.0.1"]},
                    }
                },
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "container"
                        },
                        "Process": {
                            "Env": ["STATIC=value", "BACKEND_SERVICE_HOST=10.0.0.1"]
                        },
                    }
                },
            ],
            "request_defaults": {
                "CreateContainerRequest": {"allow_env_regex": ["inherited"]}
            },
        }
        manifest = {
            "tags": [
                {
                    "tag": "service-env.BACKEND_SERVICE_HOST",
                    "suggested_regex": "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
                }
            ]
        }
        tagged_requests = [
            {
                "annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.container-name": "",
                },
                "process": {
                    "env": [
                        "BACKEND_SERVICE_HOST={{GENPOLICY_DYNAMIC:service-env.BACKEND_SERVICE_HOST}}"
                    ]
                },
            }
        ]

        result = renderer.production_safe_policy(policy, manifest, tagged_requests)

        self.assertEqual(
            result["request_defaults"]["CreateContainerRequest"]["allow_env_regex"],
            [],
        )
        self.assertEqual(
            result["containers"][0]["OCI"]["Process"]["Env"],
            ["BACKEND_SERVICE_HOST=10.0.0.1"],
        )
        process = result["containers"][1]["OCI"]["Process"]
        self.assertEqual(process["Env"], ["STATIC=value"])
        self.assertEqual(
            process["EnvRegex"],
            ["^BACKEND_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"],
        )

    def test_service_environment_marker_requires_manifest_regex(self):
        policy = {
            "containers": [
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "container",
                            "io.kubernetes.cri.container-name": "workload",
                        },
                        "Process": {"Env": []},
                    }
                }
            ],
            "request_defaults": {
                "CreateContainerRequest": {"allow_env_regex": []}
            },
        }
        tagged_requests = [
            {
                "annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.container-name": "workload",
                },
                "process": {
                    "env": [
                        "BACKEND_SERVICE_HOST={{GENPOLICY_DYNAMIC:service-env.BACKEND_SERVICE_HOST}}"
                    ]
                },
            }
        ]

        with self.assertRaisesRegex(
            ValueError, "Service environment marker has no regex"
        ):
            renderer.production_safe_policy(policy, {"tags": []}, tagged_requests)

    def test_reviewed_fragment_requires_applies_to(self):
        reviewed = [
            {
                "category": "kubelet-resolution",
                "claims": [],
                "scope": "profile",
            }
        ]

        with self.assertRaisesRegex(ValueError, "must declare applies_to"):
            renderer.validate_reviewed_profile_fragments([], [], reviewed)

    def test_applies_to_dimension_must_be_non_empty_string_list(self):
        reviewed = [
            {
                "applies_to": {"containerd": []},
                "category": "kubelet-resolution",
                "claims": [],
                "scope": "profile",
            }
        ]

        with self.assertRaisesRegex(ValueError, "non-empty list of strings"):
            renderer.validate_reviewed_profile_fragments([], [], reviewed)

    def test_materialization_contract_regex_must_be_anchored(self):
        reviewed = [
            {
                "applies_to": {"kubernetes": ["v1.33.13"]},
                "category": "kubelet-resolution",
                "claims": [],
                "materialization_contracts": [
                    {
                        "operations": ["resolve"],
                        "path_regex": "/OCI/Process/Env/.*",
                    }
                ],
                "scope": "profile",
            }
        ]

        with self.assertRaisesRegex(ValueError, "regex must be anchored"):
            renderer.validate_reviewed_profile_fragments([], [], reviewed)

    def test_every_materialization_requires_reviewed_contract(self):
        materializations = [
            {
                "category": "kubelet-resolution",
                "claims": [
                    {
                        "operation": "resolve",
                        "target": {"path": "/OCI/Process/Env/POD_UID"},
                    }
                ],
            }
        ]
        reviewed = [
            {
                "applies_to": {"kubernetes": ["v1.33.13"]},
                "category": "kubelet-resolution",
                "claims": [],
                "materialization_contracts": [
                    {
                        "operations": ["resolve"],
                        "path_regex": "^/OCI/Root/.*$",
                    }
                ],
                "scope": "profile",
            }
        ]

        with self.assertRaisesRegex(ValueError, "no reviewed materialization contract"):
            renderer.validate_reviewed_profile_fragments(
                [], materializations, reviewed
            )

    def test_service_link_paths_use_literal_environment_names(self):
        static_ir = {
            "services": [
                {
                    "name": "backend-api",
                    "namespace": "default",
                    "ports": [
                        {"name": "https-admin", "port": 8443, "protocol": "TCP"}
                    ],
                }
            ]
        }

        paths = renderer.service_link_materialization_paths(static_ir)

        self.assertEqual(
            paths,
            {
                "/OCI/Process/EnvRegex",
                "/OCI/Process/Env/BACKEND_API_SERVICE_PORT_HTTPS_ADMIN",
                "/OCI/Process/Env/KUBERNETES_SERVICE_PORT_HTTPS",
            },
        )

    def test_service_link_filter_preserves_runtime_env_regex(self):
        materializations = [
            {
                "category": "kubelet-or-containerd",
                "claims": [
                    {"target": {"path": "/OCI/Process/EnvRegex"}},
                    {
                        "target": {
                            "path": "/OCI/Process/Env/BACKEND_SERVICE_PORT_HTTPS"
                        }
                    },
                    {"target": {"path": "/OCI/Process/Env/HOSTNAME"}},
                ],
            },
            {
                "category": "runtime-rs",
                "claims": [{"target": {"path": "/OCI/Process/EnvRegex"}}],
            },
        ]
        static_ir = {
            "services": [
                {
                    "name": "backend",
                    "namespace": "default",
                    "ports": [
                        {"name": "https", "port": 8443, "protocol": "TCP"}
                    ],
                }
            ]
        }

        result = renderer.remove_profile_generated_materializations(
            materializations, static_ir
        )

        self.assertEqual(
            result[0]["claims"],
            [{"target": {"path": "/OCI/Process/Env/HOSTNAME"}}],
        )
        self.assertEqual(result[1], materializations[1])

    def test_filter_removes_only_declared_environment_resolutions(self):
        materializations = [
            {
                "category": "kubelet-resolution",
                "claims": [
                    {"target": {"path": "/OCI/Process/Env/POD_UID"}},
                    {"target": {"path": "/OCI/Process/Env/HOSTNAME"}},
                ],
            }
        ]
        static_ir = {
            "subjects": [
                {
                    "environment_resolutions": [
                        {
                            "target": {
                                "name": "POD_UID",
                                "path": "/OCI/Process/Env/POD_UID",
                            }
                        }
                    ],
                    "subject": "container/app",
                }
            ]
        }

        result = renderer.remove_profile_generated_materializations(
            materializations, static_ir
        )

        self.assertEqual(
            result[0]["claims"],
            [{"target": {"path": "/OCI/Process/Env/HOSTNAME"}}],
        )

    def test_filter_removes_only_profile_generated_oci_defaults(self):
        generated_path = "/OCI/Linux/MaskedPaths"
        unresolved_path = "/OCI/Mounts"
        materializations = [
            {
                "category": "kubelet-or-containerd",
                "claims": [
                    {"target": {"path": generated_path}},
                    {"target": {"path": unresolved_path}},
                ],
            },
            {
                "category": "runtime-rs",
                "claims": [{"target": {"path": generated_path}}],
            },
        ]

        result = renderer.remove_profile_generated_materializations(
            materializations, {"services": []}
        )

        self.assertEqual(
            result[0]["claims"], [{"target": {"path": unresolved_path}}]
        )
        self.assertEqual(result[1], materializations[1])

    def test_filter_removes_compiler_copy_file_materialization(self):
        materializations = [
            {
                "category": "runtime-rs-envelope",
                "claims": [
                    {
                        "target": {
                            "path": "/request_defaults/CopyFileRequest",
                            "subject": "policy",
                        }
                    },
                    {
                        "target": {
                            "path": "/devices",
                            "subject": "container/app",
                        }
                    },
                ],
            }
        ]

        result = renderer.remove_profile_generated_materializations(
            materializations, {"subjects": []}
        )

        self.assertEqual(
            result[0]["claims"],
            [
                {
                    "target": {
                        "path": "/devices",
                        "subject": "container/app",
                    }
                }
            ],
        )

    def test_filter_removes_mounts_and_storage_only_for_supported_volume_subjects(self):
        subjects = [
            "container/empty-dir",
            "container/config-map",
            "container/projected",
            "container/missing",
        ]
        materializations = [
            {
                "category": "runtime-rs-envelope",
                "claims": [
                    {"target": {"path": "/storages", "subject": subject}}
                    for subject in subjects
                ],
            },
            {
                "category": "kubelet-or-containerd",
                "claims": [
                    {"target": {"path": "/OCI/Mounts", "subject": subject}}
                    for subject in subjects
                ],
            },
        ]
        static_ir = {
            "services": [],
            "subjects": [
                {
                    "subject": "container/empty-dir",
                    "volumes": [
                        {
                            "medium": "memory",
                            "name": "cache",
                            "role": "empty-dir",
                        }
                    ],
                },
                {
                    "subject": "container/config-map",
                    "volumes": [
                        {
                            "destination_basename": "configuration",
                            "name": "config",
                            "role": "config-map",
                            "source": {"content_trust": "untrusted-runtime"},
                        },
                        {
                            "destination_basename": "credentials",
                            "name": "secret",
                            "role": "secret",
                            "source": {"content_trust": "untrusted-runtime"},
                        },
                    ],
                },
                {
                    "subject": "container/projected",
                    "volumes": [{"name": "identity", "role": "projected"}],
                },
            ],
        }

        result = renderer.remove_profile_generated_materializations(
            materializations, static_ir
        )

        self.assertEqual(
            [claim["target"]["subject"] for claim in result[0]["claims"]],
            ["container/projected", "container/missing"],
        )
        self.assertEqual(
            [claim["target"]["subject"] for claim in result[1]["claims"]],
            ["container/projected", "container/missing"],
        )

    def test_reusable_fragments_do_not_embed_subject_ids(self):
        report = {
            "fragments": [
                {
                    "category": "containerd-oci",
                    "claims": [
                        {
                            "operation": "default",
                            "scope": "profile",
                            "target": {
                                "cardinality": "all",
                                "path": "/OCI/Version",
                                "role": "all",
                                "scope": "container",
                            },
                            "value": "1.3.0",
                        }
                    ],
                    "profile_identity": "a" * 64,
                    "schema_version": 1,
                    "scope": "profile",
                }
            ],
            "materialization_sets": [],
            "static_policy": {"subjects": []},
        }

        fragments = renderer.regorus_fragments(report, {})

        self.assertNotIn("subject", fragments[0]["claims"][0]["target"])
        self.assertEqual(
            fragments[0]["claims"][0]["addition"],
            {"OCI": {"Version": "1.3.0"}},
        )


if __name__ == "__main__":
    unittest.main()
