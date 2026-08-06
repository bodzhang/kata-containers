import importlib.util
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
                        "/OCI/Process/Args": ["/bin/app"],
                        "/OCI/Process/Env": {"STATIC": "image"},
                    },
                    "namespace": "default",
                    "subject": "container/app",
                    "unresolved": [{"name": "POD_UID"}],
                },
                {
                    "constraints": {
                        "/OCI/Process/Args": ["/pause"],
                        "/OCI/Process/Env": ["PATH=/usr/bin"],
                        "/OCI/Root/Path": "$(root_path)",
                    },
                    "namespace": "default",
                    "subject": "sandbox/default/demo",
                    "unresolved": [],
                },
            ],
        }

    def expected_policy(self):
        return {
            "common": {"cpath": "/run/kata/"},
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
        self.assertEqual(report["coverage"]["status"], "experimental")
        self.assertGreater(report["coverage"]["static_claims"], 0)
        self.assertEqual(report["coverage"]["required_absence_claims"], 0)
        static_serialized = str(report["static_policy"])
        self.assertIn("STATIC", static_serialized)
        self.assertNotIn("POD_UID", static_serialized)
        claims = [claim for fragment in report["fragments"] for claim in fragment["claims"]]
        pod_uid = next(
            claim
            for claim in claims
            if claim["target"]["path"] == "/OCI/Process/Env/POD_UID"
        )
        self.assertEqual(pod_uid["operation"], "resolve")
        self.assertEqual(pod_uid["target"]["subject"], "container/app")
        self.assertEqual(pod_uid["value"], "$(pod-uid)")

    def test_static_value_conflict_fails_coverage(self):
        expected = self.expected_policy()
        expected["containers"][0]["OCI"]["Process"]["Args"] = ["/bin/other"]

        with self.assertRaisesRegex(coverage.CoverageError, "static value conflicts"):
            coverage.derive_candidate_coverage(
                self.static_ir(), expected, self.source_report()
            )

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
            "category": "runtime-rs",
            "evidence": "rules.rego",
            "path": "/OCI/Linux/Seccomp",
        }

        with self.assertRaisesRegex(coverage.CoverageError, "multiple runtime absence"):
            coverage.request_absence_coverage(
                observed, {"rules": [rule, rule], "schema_version": 1}
            )

    def test_final_report_fails_closed_on_coverage_gaps(self):
        report = {"coverage": {"ambiguous_boundary_claims": 2}}
        absences = {
            "inventory": "loaded",
            "uncovered": 1,
        }

        result = coverage.finalize_report(report, absences)

        self.assertEqual(result["result"], "incomplete")
        self.assertEqual(len(result["blockers"]), 2)

    def test_final_report_passes_complete_evidence(self):
        report = {"coverage": {"ambiguous_boundary_claims": 0}}
        absences = {
            "inventory": "loaded",
            "uncovered": 0,
        }

        result = coverage.finalize_report(report, absences)

        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["blockers"], [])


if __name__ == "__main__":
    unittest.main()