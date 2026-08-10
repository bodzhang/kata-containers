import importlib.util
import json
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "prototype_fragment_coverage.py"
SPEC = importlib.util.spec_from_file_location("prototype_fragment_coverage", SCRIPT)
coverage = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(coverage)


class FragmentCoveragePrototypeTests(unittest.TestCase):
    def static_ir(self):
        return {
            "schema_version": 1,
            "subjects": [
                {
                    "constraints": {
                        "/OCI/Annotations/io.kubernetes.cri.container-name": "app",
                        "/OCI/Process/Args": ["/bin/app"],
                        "/OCI/Process/Env": {"STATIC": "image"},
                    },
                    "environment_resolutions": [
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
                    "namespace": "default",
                    "subject": "container/app",
                },
                {
                    "constraints": {
                        "/OCI/Process/Args": ["/pause"],
                        "/OCI/Process/Env": ["PATH=/usr/bin"],
                        "/OCI/Root/Path": "$(root_path)",
                    },
                    "environment_resolutions": [],
                    "namespace": "default",
                    "subject": "sandbox/default/demo",
                },
            ],
        }

    def expected_policy(self):
        return {
            "common": {"cpath": "/run/kata/"},
            "request_defaults": {
                "CreateContainerRequest": {"allow_env_regex": []}
            },
            "containers": [
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-name": "app",
                            "io.kubernetes.cri.container-type": "container",
                        },
                        "Process": {
                            "Args": ["/bin/app"],
                            "Env": ["POD_UID=$(pod-uid)", "STATIC=image"],
                        },
                        "Root": {"Path": "$(root_path)", "Readonly": False},
                        "Version": "1.1.0",
                    },
                    "storages": [],
                },
                {
                    "OCI": {
                        "Annotations": {
                            "io.kubernetes.cri.container-type": "sandbox",
                            "io.kubernetes.cri.sandbox-namespace": "default",
                        },
                        "Process": {
                            "Args": ["/pause"],
                            "Env": ["PATH=/usr/bin"],
                        },
                        "Root": {"Path": "$(root_path)"},
                        "Version": "1.1.0",
                    },
                    "storages": [],
                },
            ],
        }

    def source_report(self):
        return {
            "containers": [
                {
                    "fields": {
                        "/OCI/Annotations": {"source": "captured-oci"},
                        "/OCI/Process": {"source": "captured-oci"},
                        "/OCI/Root/Path": {"source": "settings-kata-normalization"},
                        "/OCI/Root/Readonly": {"source": "captured-oci"},
                    },
                    "identity": {
                        "container_name": "app",
                        "container_type": "container",
                    },
                },
                {
                    "fields": {
                        "/OCI/Annotations": {"source": "captured-oci"},
                        "/OCI/Process": {"source": "settings-kata-sandbox-normalization"},
                        "/OCI/Root/Path": {"source": "settings-kata-normalization"},
                    },
                    "identity": {"container_name": "", "container_type": "sandbox"},
                },
            ]
        }

    def test_reconstructs_final_policy_from_independent_static_ir(self):
        report = coverage.derive_candidate_coverage(
            self.static_ir(), self.expected_policy(), self.source_report()
        )

        self.assertEqual(report["coverage"]["reconstruction"], "pass")
        self.assertEqual(report["coverage"]["status"], "materialization-only")
        self.assertGreater(report["coverage"]["static_claims"], 0)
        self.assertGreater(report["coverage"]["workload_bound_materialization_claims"], 0)
        self.assertEqual(report["coverage"]["required_absence_claims"], 0)
        static_serialized = str(report["static_policy"])
        self.assertIn("STATIC", static_serialized)
        self.assertNotIn("POD_UID", static_serialized)
        fragment_claims = [
            claim for fragment in report["fragments"] for claim in fragment["claims"]
        ]
        materialization_claims = [
            claim
            for candidate in report["materialization_sets"]
            for claim in candidate["claims"]
        ]
        claims = fragment_claims + materialization_claims
        self.assertTrue(fragment_claims)
        self.assertTrue(
            all(claim["target"]["scope"] in {"policy", "container"} for claim in fragment_claims)
        )
        self.assertTrue(
            all("subject" not in claim["target"] for claim in fragment_claims)
        )
        self.assertFalse(
            any(
                claim["target"]["path"]
                == "/OCI/Annotations/io.kubernetes.cri.container-name"
                for claim in claims
            )
        )
        container_name = next(
            entry
            for entry in report["ledger"]
            if entry["path"]
            == "/OCI/Annotations/io.kubernetes.cri.container-name"
        )
        self.assertEqual(container_name["owner"], "static")
        self.assertEqual(container_name["evidence"], "trusted-workload-yaml")
        pod_uid = next(
            claim
            for claim in claims
            if claim["target"]["path"] == "/OCI/Process/Env/POD_UID"
        )
        self.assertEqual(pod_uid["operation"], "resolve")
        self.assertEqual(pod_uid["target"]["subject"], "container/app")
        self.assertEqual(pod_uid["value"], "$(pod-uid)")
        self.assertEqual(
            [fragment["category"] for fragment in report["fragments"]],
            ["containerd-oci", "policy-framework-settings"],
        )
        global_env = next(
            claim
            for claim in fragment_claims
            if claim["target"]["path"]
            == "/request_defaults/CreateContainerRequest/allow_env_regex"
        )
        self.assertEqual(global_env["value"], [])
        self.assertEqual(global_env["evidence"], "compiler-security-default")
        global_env_ledger = next(
            entry
            for entry in report["ledger"]
            if entry["path"]
            == "/request_defaults/CreateContainerRequest/allow_env_regex"
        )
        self.assertEqual(global_env_ledger["owner"], "fragment")
        self.assertEqual(
            global_env_ledger["evidence"], "compiler-security-default"
        )
        version = next(
            claim
            for claim in fragment_claims
            if claim["target"]["path"] == "/OCI/Version"
        )
        self.assertEqual(
            version["target"],
            {
                "cardinality": "all",
                "path": "/OCI/Version",
                "role": "all",
                "scope": "container",
            },
        )
        container_types = {
            (claim["target"]["role"], claim["value"])
            for claim in fragment_claims
            if claim["target"]["path"] == coverage.CONTAINER_TYPE_PATH
        }
        self.assertEqual(
            container_types,
            {("application", "container"), ("sandbox", "sandbox")},
        )
        materialization_scopes = {
            candidate["category"]: candidate["scope"]
            for candidate in report["materialization_sets"]
        }
        self.assertEqual(
            materialization_scopes["kubelet-resolution"],
            "static-base-materialization",
        )
        self.assertFalse(
            any(
                entry["path"] == "/OCI/Version"
                for entry in report["coverage"]["subject_fanout"]
            )
        )

    def test_service_environment_regex_is_workload_derived_global_policy(self):
        path = "/request_defaults/CreateContainerRequest/allow_env_regex"

        self.assertEqual(
            coverage.materialization_scope("policy", path),
            "static-base-materialization",
        )
        self.assertEqual(coverage.materialization_scope("policy", path, []), "profile")
        self.assertEqual(
            coverage.materialization_scope("policy", "/common/cpath"), "profile"
        )
        self.assertEqual(
            coverage.claim_classification("policy", path, set(), {}),
            (
                "policy-framework-settings",
                "default",
                "workload-service-objects+cluster-state",
            ),
        )

    def test_workload_bound_candidates_block_reusable_fragment_result(self):
        report = {
            "coverage": {
                "ambiguous_boundary_claims": 0,
                "workload_bound_materialization_claims": 2,
            }
        }
        absences = {"inventory": "loaded", "uncovered": 0}

        validators = {"inventory": "loaded", "uncovered": 0}

        result = coverage.finalize_report(
            report, absences, validators, {"uvm_bound": True}
        )

        self.assertEqual(result["result"], "incomplete")
        self.assertEqual(
            result["blockers"],
            [
                "2 claims depend on workload subjects or values and are not reusable fragments"
            ],
        )

    def test_static_value_conflict_fails_coverage(self):
        expected = self.expected_policy()
        expected["containers"][0]["OCI"]["Process"]["Args"] = ["/bin/other"]

        with self.assertRaisesRegex(coverage.CoverageError, "static value conflicts"):
            coverage.derive_candidate_coverage(
                self.static_ir(), expected, self.source_report()
            )

    def test_environment_map_rejects_empty_name(self):
        with self.assertRaisesRegex(coverage.CoverageError, "invalid or duplicate"):
            coverage.environment_map(["=value"])

    def test_container_environment_regex_is_order_insensitive(self):
        self.assertEqual(
            coverage.canonical_claim_value(
                "/OCI/Process/EnvRegex", ["^B=.*$", "^A=.*$"]
            ),
            ["^A=.*$", "^B=.*$"],
        )

    def test_identical_service_regexes_coalesce_to_application_role(self):
        claims = {
            "kubelet-or-containerd": [
                {
                    "evidence": "captured-oci",
                    "operation": "default",
                    "scope": "static-base-materialization",
                    "target": {"path": "/OCI/Process/EnvRegex", "subject": subject},
                    "value": ["^BACKEND_SERVICE_HOST=(?:IPv4|IPv6)$"],
                }
                for subject in ("container/api", "container/sidecar")
            ]
        }
        ledger = [
            {
                "category": "kubelet-or-containerd",
                "evidence": "captured-oci",
                "operation": "default",
                "owner": "materialization",
                "path": "/OCI/Process/EnvRegex",
                "scope": "static-base-materialization",
                "subject": subject,
            }
            for subject in ("container/api", "container/sidecar")
        ]
        static_ir = {
            "subjects": [
                {"subject": "container/api"},
                {"subject": "container/sidecar"},
                {"subject": "sandbox/default/demo"},
            ]
        }

        coverage.coalesce_workload_application_roles(claims, ledger, static_ir)

        self.assertEqual(len(claims["kubelet-or-containerd"]), 1)
        self.assertEqual(
            claims["kubelet-or-containerd"][0]["target"],
            {
                "cardinality": "all",
                "path": "/OCI/Process/EnvRegex",
                "role": "application",
                "scope": "container",
            },
        )
        self.assertEqual(ledger[0]["subject"], "role:container/application")

    def test_different_service_regexes_remain_per_container(self):
        claims = {
            "kubelet-or-containerd": [
                {
                    "evidence": "captured-oci",
                    "operation": "default",
                    "scope": "static-base-materialization",
                    "target": {"path": "/OCI/Process/EnvRegex", "subject": subject},
                    "value": [value],
                }
                for subject, value in (
                    ("container/api", "^BACKEND_SERVICE_HOST=(?:IPv4|IPv6)$"),
                    ("container/sidecar", "^METRICS_SERVICE_HOST=(?:IPv4|IPv6)$"),
                )
            ]
        }
        ledger = []
        static_ir = {
            "subjects": [
                {"subject": "container/api"},
                {"subject": "container/sidecar"},
            ]
        }

        coverage.coalesce_workload_application_roles(claims, ledger, static_ir)

        self.assertEqual(len(claims["kubelet-or-containerd"]), 2)
        self.assertTrue(
            all("subject" in claim["target"] for claim in claims["kubelet-or-containerd"])
        )

    def test_container_type_promotes_only_complete_reviewed_roles(self):
        claims = {
            "containerd-oci": [
                {
                    "evidence": "cri-container-role",
                    "operation": "default",
                    "scope": "static-base-materialization",
                    "target": {
                        "path": coverage.CONTAINER_TYPE_PATH,
                        "subject": subject,
                    },
                    "value": value,
                }
                for subject, value in (
                    ("container/api", "container"),
                    ("container/sidecar", "container"),
                    ("sandbox/default/demo", "sandbox"),
                )
            ]
        }
        ledger = [
            {
                "category": "containerd-oci",
                "evidence": "cri-container-role",
                "operation": "default",
                "owner": "materialization",
                "path": coverage.CONTAINER_TYPE_PATH,
                "scope": "static-base-materialization",
                "subject": subject,
            }
            for subject in (
                "container/api",
                "container/sidecar",
                "sandbox/default/demo",
            )
        ]
        static_ir = {
            "subjects": [
                {"subject": "container/api"},
                {"subject": "container/sidecar"},
                {"subject": "sandbox/default/demo"},
            ]
        }

        coverage.promote_profile_container_roles(claims, ledger, static_ir)

        promoted = {
            (claim["target"]["role"], claim["value"])
            for claim in claims["containerd-oci"]
        }
        self.assertEqual(
            promoted,
            {("application", "container"), ("sandbox", "sandbox")},
        )
        self.assertEqual(
            {entry["subject"] for entry in ledger},
            {"role:container/application", "role:container/sandbox"},
        )

    def test_container_type_does_not_promote_partial_application_role(self):
        claim = {
            "evidence": "cri-container-role",
            "operation": "default",
            "scope": "static-base-materialization",
            "target": {
                "path": coverage.CONTAINER_TYPE_PATH,
                "subject": "container/api",
            },
            "value": "container",
        }
        claims = {"containerd-oci": [claim]}
        ledger = []
        static_ir = {
            "subjects": [
                {"subject": "container/api"},
                {"subject": "container/sidecar"},
            ]
        }

        coverage.promote_profile_container_roles(claims, ledger, static_ir)

        self.assertEqual(claims, {"containerd-oci": [claim]})

    def test_unmapped_final_subject_fails_coverage(self):
        expected = self.expected_policy()
        expected["containers"][0]["OCI"]["Annotations"][
            "io.kubernetes.cri.container-name"
        ] = "other"

        with self.assertRaisesRegex(coverage.CoverageError, "no stable static subject"):
            coverage.derive_candidate_coverage(
                self.static_ir(), expected, self.source_report()
            )

    def test_runtime_absence_inventory_exposes_uncovered_removal(self):
        observed = [
            {
                "evidence": "sandbox.json",
                "path": "/OCI/Linux/Resources/Devices",
                "subject": "sandbox/default/demo",
            },
            {
                "evidence": "sandbox.json",
                "path": "/OCI/Linux/Seccomp",
                "subject": "sandbox/default/demo",
            },
        ]
        inventory = {
            "rules": [
                {
                    "all_subjects": True,
                    "category": "runtime-rs",
                    "evidence": "rules.rego: allow_create_container_input",
                    "path": "/OCI/Linux/Resources/Devices",
                }
            ],
            "schema_version": 1,
        }

        result = coverage.request_absence_coverage(observed, inventory)

        self.assertEqual(result["observed"], 2)
        self.assertEqual(result["covered"], 1)
        self.assertEqual(result["uncovered"], 1)
        self.assertEqual(result["entries"][1]["status"], "uncovered")

    def test_runtime_absence_inventory_rejects_duplicate_rules(self):
        observed = [
            {
                "evidence": "sandbox.json",
                "path": "/OCI/Linux/Seccomp",
                "subject": "sandbox/default/demo",
            }
        ]
        rule = {
            "all_subjects": True,
            "category": "runtime-rs",
            "evidence": "rules.rego",
            "path": "/OCI/Linux/Seccomp",
        }

        with self.assertRaisesRegex(coverage.CoverageError, "multiple runtime absence"):
            coverage.request_absence_coverage(
                observed, {"rules": [rule, rule], "schema_version": 1}
            )

    def test_runtime_absence_rule_requires_explicit_scope(self):
        rule = {
            "category": "runtime-rs",
            "evidence": "rules.rego",
            "path": "/OCI/Linux/Seccomp",
        }

        with self.assertRaisesRegex(coverage.CoverageError, "exactly one subject scope"):
            coverage.request_absence_coverage(
                [], {"rules": [rule], "schema_version": 1}
            )

    def test_runtime_absence_rule_rejects_multiple_scopes(self):
        rule = {
            "all_subjects": True,
            "category": "runtime-rs",
            "evidence": "rules.rego",
            "path": "/OCI/Linux/Seccomp",
            "subject": "sandbox/default/demo",
        }

        with self.assertRaisesRegex(coverage.CoverageError, "exactly one subject scope"):
            coverage.request_absence_coverage(
                [], {"rules": [rule], "schema_version": 1}
            )

    def test_final_report_fails_closed_on_coverage_gaps(self):
        report = {"coverage": {"ambiguous_boundary_claims": 2}}
        absences = {
            "inventory": "loaded",
            "uncovered": 1,
        }
        validators = {
            "inventory": "loaded",
            "uncovered": 1,
        }

        result = coverage.finalize_report(
            report, absences, validators, {"uvm_bound": False}
        )

        self.assertEqual(result["result"], "incomplete")
        self.assertEqual(len(result["blockers"]), 4)

    def test_final_report_passes_complete_evidence(self):
        report = {"coverage": {"ambiguous_boundary_claims": 0}}
        absences = {
            "inventory": "loaded",
            "uncovered": 0,
        }
        validators = {
            "inventory": "loaded",
            "uncovered": 0,
        }

        result = coverage.finalize_report(
            report, absences, validators, {"uvm_bound": True}
        )

        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["blockers"], [])

    def test_runtime_validator_inventory_exposes_uncovered_claim(self):
        report = {
            "fragments": [
                {
                    "category": "containerd-oci",
                    "claims": [
                        {
                            "operation": "default",
                            "target": {
                                "cardinality": "all",
                                "path": "/OCI/Version",
                                "role": "all",
                                "scope": "container",
                            },
                            "value": "1.1.0",
                        },
                        {
                            "operation": "default",
                            "target": {
                                "cardinality": "all",
                                "path": coverage.CONTAINER_TYPE_PATH,
                                "role": "application",
                                "scope": "container",
                            },
                            "value": "container",
                        },
                    ],
                }
            ]
        }
        inventory = {
            "schema_version": 1,
            "validators": [
                {
                    "category": "containerd-oci",
                    "evidence": "src/tools/genpolicy/rules.rego: allow_oci_version",
                    "path": "/OCI/Version",
                    "test": "src/tools/genpolicy/appliance/tests/fragment_runtime_validators_test.rego: test_fragment_oci_version_mismatch_denied",
                }
            ],
        }

        result = coverage.runtime_validator_coverage(report, inventory)

        self.assertEqual(result["required"], 2)
        self.assertEqual(result["covered"], 1)
        self.assertEqual(result["uncovered"], 1)
        self.assertEqual(result["entries"][1]["status"], "uncovered")

    def test_runtime_validator_inventory_rejects_duplicate_ownership(self):
        report = {
            "fragments": [
                {
                    "category": "containerd-oci",
                    "claims": [
                        {
                            "operation": "default",
                            "target": {"path": "/OCI/Version", "scope": "policy"},
                            "value": "1.1.0",
                        }
                    ],
                }
            ]
        }
        validator = {
            "category": "containerd-oci",
            "evidence": "src/tools/genpolicy/rules.rego: allow_oci_version",
            "path": "/OCI/Version",
            "test": "src/tools/genpolicy/appliance/tests/fragment_runtime_validators_test.rego: test_fragment_oci_version_mismatch_denied",
        }

        with self.assertRaisesRegex(coverage.CoverageError, "multiple runtime validators"):
            coverage.runtime_validator_coverage(
                report,
                {"schema_version": 1, "validators": [validator, validator]},
            )

    def test_runtime_validator_inventory_rejects_stale_evidence(self):
        report = {
            "fragments": [
                {
                    "category": "containerd-oci",
                    "claims": [
                        {
                            "operation": "default",
                            "target": {"path": "/OCI/Version", "scope": "policy"},
                            "value": "1.1.0",
                        }
                    ],
                }
            ]
        }
        inventory = {
            "schema_version": 1,
            "validators": [
                {
                    "category": "containerd-oci",
                    "evidence": "src/tools/genpolicy/rules.rego: missing_validator",
                    "path": "/OCI/Version",
                    "test": "src/tools/genpolicy/appliance/tests/fragment_runtime_validators_test.rego: test_fragment_oci_version_mismatch_denied",
                }
            ],
        }

        with self.assertRaisesRegex(
            coverage.CoverageError, "runtime validator evidence symbol does not exist"
        ):
            coverage.runtime_validator_coverage(report, inventory)

    def test_runtime_validator_inventory_can_scope_a_role(self):
        report = {
            "fragments": [
                {
                    "category": "containerd-oci",
                    "claims": [
                        {
                            "operation": "default",
                            "target": {
                                "cardinality": "all",
                                "path": coverage.CONTAINER_TYPE_PATH,
                                "role": "application",
                                "scope": "container",
                            },
                            "value": "container",
                        }
                    ],
                }
            ]
        }
        inventory = {
            "schema_version": 1,
            "validators": [
                {
                    "category": "containerd-oci",
                    "evidence": "src/tools/genpolicy/rules.rego: allow_container_role",
                    "path": coverage.CONTAINER_TYPE_PATH,
                    "role": "sandbox",
                    "test": "src/tools/genpolicy/appliance/tests/fragment_runtime_validators_test.rego: test_fragment_container_role_mismatch_denied",
                }
            ],
        }

        result = coverage.runtime_validator_coverage(report, inventory)

        self.assertEqual(result["covered"], 0)
        self.assertEqual(result["uncovered"], 1)

    def test_current_profile_claims_have_runtime_validator_evidence(self):
        report = coverage.derive_candidate_coverage(
            self.static_ir(), self.expected_policy(), self.source_report()
        )
        inventory_path = (
            Path(__file__).parent
            / "fixtures"
            / "fragments"
            / "runtime-validator-inventory.json"
        )
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

        result = coverage.runtime_validator_coverage(report, inventory)

        self.assertEqual(result["inventory"], "loaded")
        self.assertEqual(result["required"], 5)
        self.assertEqual(result["covered"], 5)
        self.assertEqual(result["uncovered"], 0)

    def test_binds_fragments_to_profile_and_static_base(self):
        static_ir = self.static_ir()
        static_ir["subjects"][1]["static_artifact"] = f"sha256:{'a' * 64}"
        report = coverage.derive_candidate_coverage(
            static_ir, self.expected_policy(), self.source_report()
        )
        profile = {
            "identity": "b" * 64,
            "values": {"UVM_IMAGE_DIGEST": "a" * 64},
        }

        result = coverage.bind_profile(report, static_ir, profile)

        self.assertTrue(result["binding"]["uvm_bound"])
        self.assertRegex(result["binding"]["static_base_digest"], r"^sha256:[0-9a-f]{64}$")
        for candidate in result["materialization_sets"]:
            self.assertEqual(candidate["profile_identity"], "b" * 64)
            self.assertEqual(
                candidate["static_base_digest"],
                result["binding"]["static_base_digest"],
            )
        for fragment in result["fragments"]:
            self.assertEqual(fragment["profile_identity"], "b" * 64)
            self.assertNotIn("static_base_digest", fragment)

    def test_rejects_invalid_profile_identity(self):
        report = {"fragments": []}

        with self.assertRaisesRegex(coverage.CoverageError, "sha256 identity"):
            coverage.bind_profile(report, self.static_ir(), {"identity": "profile-name"})


if __name__ == "__main__":
    unittest.main()