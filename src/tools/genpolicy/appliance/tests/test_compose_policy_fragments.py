import copy
import importlib.util
import json
import unittest
from pathlib import Path


APPLIANCE = Path(__file__).parents[1]
SCRIPT = APPLIANCE / "scripts" / "compose_policy_fragments.py"
SPEC = importlib.util.spec_from_file_location("compose_policy_fragments", SCRIPT)
composition = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(composition)


class PolicyFragmentCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_path = APPLIANCE / "demo-compare" / "run-complex" / "output" / "policy.rego"
        policy = policy_path.read_text(encoding="utf-8")
        cls.compiler_policy = json.loads(policy.rsplit("\npolicy_data := ", 1)[1])
        fragment_path = Path(__file__).parent / "fixtures" / "fragments" / "run-complex.json"
        cls.fragments = json.loads(fragment_path.read_text(encoding="utf-8"))

    def static_baseline(self):
        policy_data = copy.deepcopy(self.compiler_policy)
        containers = policy_data.pop("containers")
        baseline = {
            "policy_data": policy_data,
            "subjects": [
                {"id": "container/sidecar", "ordinal": 0, "policy": containers[0]},
                {"id": "container/workload", "ordinal": 1, "policy": containers[1]},
                {"id": "sandbox/default/balanced-mode", "ordinal": 2, "policy": containers[2]},
            ],
        }
        for fragment in self.fragments:
            for claim in fragment["claims"]:
                selected, pointer = composition.resolve_target(baseline, claim["target"])
                parent, token = composition.pointer_parent(selected, pointer)
                del parent[token]
        return baseline

    def test_fragments_reconstruct_policy_compiler_output(self):
        composed = composition.materialize(
            self.static_baseline(), self.fragments, self.compiler_policy
        )

        self.assertEqual(composed, self.compiler_policy)

    def test_missing_claim_fails_expected_policy_coverage(self):
        fragments = copy.deepcopy(self.fragments)
        omitted = fragments[0]["claims"].pop()

        with self.assertRaisesRegex(
            composition.CompositionError,
            rf"does not match expected policy at /containers/2{omitted['target']['path']}",
        ):
            composition.materialize(
                self.static_baseline(), fragments, self.compiler_policy
            )

    def test_unexpected_static_leaf_fails_expected_policy_coverage(self):
        baseline = self.static_baseline()
        baseline["policy_data"]["unexpected"] = True

        with self.assertRaisesRegex(
            composition.CompositionError,
            "does not match expected policy at /unexpected",
        ):
            composition.materialize(baseline, self.fragments, self.compiler_policy)

    def test_selectors_survive_container_reordering(self):
        baseline = self.static_baseline()
        baseline["subjects"].reverse()

        composed = composition.materialize(baseline, self.fragments)
        by_type_and_name = {
            (
                container["OCI"]["Annotations"].get("io.kubernetes.cri.container-type"),
                container["OCI"]["Annotations"].get("io.kubernetes.cri.container-name", ""),
            ): container
            for container in composed["containers"]
        }
        expected = {
            (
                container["OCI"]["Annotations"].get("io.kubernetes.cri.container-type"),
                container["OCI"]["Annotations"].get("io.kubernetes.cri.container-name", ""),
            ): container
            for container in self.compiler_policy["containers"]
        }
        self.assertEqual(by_type_and_name, expected)

    def test_fragment_order_does_not_change_output(self):
        baseline = self.static_baseline()

        forward = composition.materialize(baseline, self.fragments)
        reverse = composition.materialize(baseline, list(reversed(self.fragments)))

        self.assertEqual(forward, reverse)

    def test_profile_targets_policy_or_container_role_explicitly(self):
        baseline = {
            "policy_data": {},
            "subjects": [
                {"id": "container/api", "ordinal": 0, "policy": {}},
                {"id": "container/worker", "ordinal": 1, "policy": {}},
                {"id": "sandbox/default/demo", "ordinal": 2, "policy": {}},
            ],
        }
        fragments = [
            {
                "category": "policy-framework-settings",
                "claims": [
                    {
                        "operation": "default",
                        "target": {"scope": "policy", "path": "/common"},
                        "value": {"cpath": "/run/kata"},
                    }
                ],
                "schema_version": 1,
                "scope": "profile",
            },
            {
                "category": "containerd",
                "claims": [
                    {
                        "operation": "default",
                        "target": {
                            "scope": "container",
                            "role": "application",
                            "cardinality": "all",
                            "path": "/OCI/Version",
                        },
                        "value": "1.3.0",
                    }
                ],
                "schema_version": 1,
                "scope": "profile",
            },
        ]

        composed = composition.compose(baseline, fragments)

        self.assertEqual(composed["policy_data"]["common"]["cpath"], "/run/kata")
        self.assertEqual(
            [subject["policy"].get("OCI", {}).get("Version") for subject in composed["subjects"]],
            ["1.3.0", "1.3.0", None],
        )

    def test_container_role_one_enforces_cardinality(self):
        baseline = {
            "policy_data": {},
            "subjects": [
                {"id": "container/api", "ordinal": 0, "policy": {}},
                {"id": "container/worker", "ordinal": 1, "policy": {}},
            ],
        }
        fragment = {
            "category": "containerd",
            "claims": [
                {
                    "operation": "default",
                    "target": {
                        "scope": "container",
                        "role": "application",
                        "cardinality": "one",
                        "path": "/OCI/Version",
                    },
                    "value": "1.3.0",
                }
            ],
            "schema_version": 1,
            "scope": "profile",
        }

        with self.assertRaisesRegex(
            composition.CompositionError, "requires one subject but matched 2"
        ):
            composition.compose(baseline, [fragment])

    def test_profile_fragment_rejects_exact_workload_subject(self):
        fragment = copy.deepcopy(self.fragments[0])
        fragment["scope"] = "profile"

        with self.assertRaisesRegex(
            composition.CompositionError, "requires explicit policy or container scope"
        ):
            composition.compose(self.static_baseline(), [fragment])

    def test_composition_does_not_mutate_inputs(self):
        baseline = self.static_baseline()
        fragments = copy.deepcopy(self.fragments)
        expected_baseline = copy.deepcopy(baseline)
        expected_fragments = copy.deepcopy(fragments)

        composition.materialize(baseline, fragments)

        self.assertEqual(baseline, expected_baseline)
        self.assertEqual(fragments, expected_fragments)

    def test_duplicate_claims_fail_composition(self):
        fragments = copy.deepcopy(self.fragments)
        fragments[1]["claims"].append(copy.deepcopy(fragments[0]["claims"][0]))

        with self.assertRaisesRegex(composition.CompositionError, "overlapping claim"):
            composition.compose(self.static_baseline(), fragments)

    def test_fragment_cannot_overwrite_static_data(self):
        baseline = self.static_baseline()
        selected, pointer = composition.resolve_target(
            baseline, self.fragments[0]["claims"][0]["target"]
        )
        parent, token = composition.pointer_parent(selected, pointer)
        parent[token] = "static-value"

        with self.assertRaisesRegex(composition.CompositionError, "overwrite static data"):
            composition.compose(baseline, self.fragments)

    def test_unknown_subject_fails_composition(self):
        fragments = copy.deepcopy(self.fragments)
        fragments[0]["claims"][0]["target"]["subject"] = "container/missing"

        with self.assertRaisesRegex(composition.CompositionError, "subject matched 0 items"):
            composition.compose(self.static_baseline(), fragments)

    def test_absence_assertion_does_not_materialize_a_value(self):
        fragments = copy.deepcopy(self.fragments)
        fragments.append(
            {
                "category": "runtime-rs",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "remove",
                        "target": {
                            "subject": "container/workload",
                            "path": "/OCI/Process/ApparmorProfile",
                        },
                    }
                ],
            }
        )

        composed = composition.materialize(
            self.static_baseline(), fragments, self.compiler_policy
        )

        self.assertEqual(composed, self.compiler_policy)

    def test_absence_assertion_rejects_static_value(self):
        fragments = copy.deepcopy(self.fragments)
        fragments.append(
            {
                "category": "runtime-rs",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "remove",
                        "target": {
                            "subject": "container/workload",
                            "path": "/OCI/Process/Cwd",
                        },
                    }
                ],
            }
        )

        with self.assertRaisesRegex(composition.CompositionError, "required absence is present"):
            composition.compose(self.static_baseline(), fragments)

    def test_absence_assertion_conflicts_with_additive_claim(self):
        fragments = copy.deepcopy(self.fragments)
        claim = copy.deepcopy(fragments[0]["claims"][0])
        claim.pop("value")
        claim["operation"] = "remove"
        fragments.append(
            {"category": "runtime-rs", "claims": [claim], "schema_version": 1}
        )

        with self.assertRaisesRegex(composition.CompositionError, "overlapping claim"):
            composition.compose(self.static_baseline(), fragments)

    def test_absence_assertion_rejects_value(self):
        fragments = copy.deepcopy(self.fragments)
        claim = copy.deepcopy(fragments[0]["claims"][0])
        claim["operation"] = "remove"
        fragments.append(
            {"category": "runtime-rs", "claims": [claim], "schema_version": 1}
        )

        with self.assertRaisesRegex(
            composition.CompositionError, "absence assertion cannot contain a value"
        ):
            composition.compose(self.static_baseline(), fragments)

    def test_environment_entries_compose_by_name(self):
        baseline = {
            "policy_data": {},
            "subjects": [
                {
                    "collection_encodings": {"/OCI/Process/Env": "env-map"},
                    "id": "container/app",
                    "ordinal": 0,
                    "policy": {
                        "OCI": {"Process": {"Env": {"STATIC": "image"}}}
                    },
                }
            ],
        }
        fragments = [
            {
                "category": "kubelet-resolution",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "resolve",
                        "target": {
                            "subject": "container/app",
                            "path": "/OCI/Process/Env/POD_UID",
                        },
                        "value": "$(pod-uid)",
                    }
                ],
            }
        ]
        expected = {
            "containers": [
                {
                    "OCI": {
                        "Process": {
                            "Env": ["STATIC=image", "POD_UID=$(pod-uid)"]
                        }
                    }
                }
            ]
        }

        composed = composition.materialize(baseline, fragments, expected)

        self.assertEqual(
            composed["containers"][0]["OCI"]["Process"]["Env"],
            ["POD_UID=$(pod-uid)", "STATIC=image"],
        )

    def test_expected_policy_rejects_duplicate_environment_name(self):
        policy = {
            "containers": [
                {"OCI": {"Process": {"Env": ["NAME=first", "NAME=second"]}}}
            ]
        }

        with self.assertRaisesRegex(
            composition.CompositionError, "invalid or duplicate process environment"
        ):
            composition.verify_expected_policy(policy, policy)

    def test_expected_policy_normalizes_typed_sets(self):
        actual = {
            "containers": [
                {
                    "OCI": {
                        "Process": {
                            "Capabilities": {"Bounding": ["CAP_CHOWN", "CAP_AUDIT_WRITE"]}
                        }
                    }
                }
            ],
            "request_defaults": {
                "CreateContainerRequest": {"allow_env_regex": ["second", "first"]}
            },
        }
        expected = {
            "containers": [
                {
                    "OCI": {
                        "Process": {
                            "Capabilities": {"Bounding": ["CAP_AUDIT_WRITE", "CAP_CHOWN"]}
                        }
                    }
                }
            ],
            "request_defaults": {
                "CreateContainerRequest": {"allow_env_regex": ["first", "second"]}
            },
        }

        composition.verify_expected_policy(actual, expected)

    def test_environment_map_rejects_invalid_name(self):
        baseline = {
            "policy_data": {},
            "subjects": [
                {
                    "collection_encodings": {"/OCI/Process/Env": "env-map"},
                    "id": "container/app",
                    "ordinal": 0,
                    "policy": {"OCI": {"Process": {"Env": {"BAD=NAME": "value"}}}},
                }
            ],
        }

        with self.assertRaisesRegex(composition.CompositionError, "invalid variable name"):
            composition.materialize(baseline, [])

    def test_leaf_claim_creates_missing_object_parents(self):
        baseline = {
            "policy_data": {},
            "subjects": [
                {"id": "container/app", "ordinal": 0, "policy": {}}
            ],
        }
        fragments = [
            {
                "category": "containerd-oci",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "default",
                        "target": {
                            "subject": "container/app",
                            "path": "/OCI/Linux/Namespaces",
                        },
                        "value": [{"Type": "pid"}],
                    }
                ],
            }
        ]
        expected = {
            "containers": [
                {"OCI": {"Linux": {"Namespaces": [{"Type": "pid"}]}}}
            ]
        }

        composed = composition.materialize(baseline, fragments, expected)

        self.assertEqual(composed, expected)

    def test_parent_and_child_claims_overlap(self):
        fragments = [
            {
                "category": "containerd-oci",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "default",
                        "target": {
                            "subject": "container/app",
                            "path": "/OCI/Linux",
                        },
                        "value": {},
                    }
                ],
            },
            {
                "category": "runtime-rs",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "rewrite",
                        "target": {
                            "subject": "container/app",
                            "path": "/OCI/Linux/Namespaces",
                        },
                        "value": [],
                    }
                ],
            },
        ]

        with self.assertRaisesRegex(composition.CompositionError, "overlapping claim"):
            composition.validate_fragments(fragments)

    def test_global_policy_leaf_claim(self):
        baseline = {"policy_data": {}, "subjects": []}
        fragments = [
            {
                "category": "policy-framework-settings",
                "schema_version": 1,
                "claims": [
                    {
                        "operation": "default",
                        "target": {"subject": "policy", "path": "/common/cpath"},
                        "value": "/run/kata-containers/shared/containers/",
                    }
                ],
            }
        ]
        expected = {
            "common": {"cpath": "/run/kata-containers/shared/containers/"},
            "containers": [],
        }

        composed = composition.materialize(baseline, fragments, expected)

        self.assertEqual(composed, expected)

    def test_rejects_unknown_fragment_schema(self):
        fragments = copy.deepcopy(self.fragments)
        fragments[0]["schema_version"] = 2

        with self.assertRaisesRegex(composition.CompositionError, "schema_version 1"):
            composition.validate_fragments(fragments)

    def test_rejects_non_array_claims(self):
        fragment = {"category": "containerd-oci", "claims": {}, "schema_version": 1}

        with self.assertRaisesRegex(composition.CompositionError, "non-empty array"):
            composition.validate_fragments([fragment])

    def test_rejects_root_claim_target(self):
        fragments = copy.deepcopy(self.fragments)
        fragments[0]["claims"][0]["target"]["path"] = ""

        with self.assertRaisesRegex(composition.CompositionError, "non-root JSON pointer"):
            composition.validate_fragments(fragments)

    def test_rejects_invalid_claim_pointer(self):
        fragments = copy.deepcopy(self.fragments)
        fragments[0]["claims"][0]["target"]["path"] = "OCI/Version"

        with self.assertRaisesRegex(composition.CompositionError, "invalid JSON pointer"):
            composition.validate_fragments(fragments)

    def test_rejects_mismatched_profile_binding(self):
        baseline = self.static_baseline()
        baseline["profile_identity"] = "profile-a"
        baseline["static_base_digest"] = "sha256:static"
        fragments = copy.deepcopy(self.fragments)
        for fragment in fragments:
            fragment["profile_identity"] = "profile-b"
            fragment["static_base_digest"] = "sha256:static"

        with self.assertRaisesRegex(composition.CompositionError, "profile_identity"):
            composition.compose(baseline, fragments)

    def test_rejects_unbound_fragment_in_bound_composition(self):
        baseline = self.static_baseline()
        baseline["profile_identity"] = "profile-a"
        baseline["static_base_digest"] = "sha256:static"

        with self.assertRaisesRegex(composition.CompositionError, "profile_identity"):
            composition.compose(baseline, self.fragments)

    def test_rejects_partial_static_binding(self):
        baseline = self.static_baseline()
        baseline["profile_identity"] = "profile-a"

        with self.assertRaisesRegex(composition.CompositionError, "complete fragment bindings"):
            composition.compose(baseline, self.fragments)

    def test_accepts_matching_fragment_bindings(self):
        baseline = self.static_baseline()
        baseline["profile_identity"] = "profile-a"
        baseline["static_base_digest"] = "sha256:static"
        fragments = copy.deepcopy(self.fragments)
        for fragment in fragments:
            fragment["profile_identity"] = "profile-a"
            fragment["static_base_digest"] = "sha256:static"

        composed = composition.materialize(baseline, fragments, self.compiler_policy)

        self.assertEqual(composed, self.compiler_policy)

    def test_profile_fragment_does_not_bind_static_base(self):
        baseline = self.static_baseline()
        baseline["profile_identity"] = "profile-a"
        baseline["static_base_digest"] = "sha256:static"
        fragments = copy.deepcopy(self.fragments)
        for fragment in fragments:
            fragment["scope"] = "profile"
            fragment["profile_identity"] = "profile-a"

        composition.validate_fragment_bindings(baseline, fragments)

        fragments[0]["static_base_digest"] = "sha256:static"
        with self.assertRaisesRegex(
            composition.CompositionError, "must not bind static_base_digest"
        ):
            composition.validate_fragment_bindings(baseline, fragments)


if __name__ == "__main__":
    unittest.main()
