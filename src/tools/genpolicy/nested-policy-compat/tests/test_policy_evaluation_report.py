#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


MODULE_PATH = (
    Path(__file__).parents[1] / "scripts" / "policy_evaluation_report.py"
)
SPEC = importlib.util.spec_from_file_location("policy_evaluation_report", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PolicyEvaluationReportTest(unittest.TestCase):
    def write_json(self, path: Path, value: dict) -> Path:
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def write_result(
        self, path: Path, result: str, denial: str | None = None
    ) -> Path:
        value = {"result": result, "denial": None}
        if denial is not None:
            value["denial"] = {"file": "agent.log", "text": denial}
        return self.write_json(path, value)

    def arguments(self, root: Path, candidate: bool = True) -> Namespace:
        generation = root / "generation.yaml"
        generation.write_text("kind: Pod\n", encoding="utf-8")
        runtime = root / "runtime.yaml"
        runtime.write_text("kind: Pod\n", encoding="utf-8")
        baseline_policy = root / "baseline.rego"
        baseline_policy.write_text("package agent_policy\n", encoding="utf-8")
        baseline_inputs = root / "baseline-inputs.sha256"
        baseline_inputs.write_text("a" * 64 + "  genpolicy\n", encoding="utf-8")

        candidate_policy = None
        candidate_inputs = None
        candidate_generator = None
        candidate_control_result = None
        candidate_control_status = None
        if candidate:
            candidate_policy = root / "candidate.rego"
            candidate_policy.write_text(
                "package agent_policy\n# candidate\n", encoding="utf-8"
            )
            candidate_inputs = root / "candidate-inputs.sha256"
            candidate_inputs.write_text(
                "b" * 64 + "  compiler\n", encoding="utf-8"
            )
            candidate_generator = root / "candidate-generator"
            candidate_generator.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate_control_result = self.write_result(
                root / "candidate-control.json", "compatible"
            )
            candidate_control_status = 0

        return Namespace(
            name="pod",
            generation_workload=generation,
            runtime_workload=runtime,
            baseline_policy=baseline_policy,
            baseline_generation_inputs=baseline_inputs,
            baseline_control_result=self.write_result(
                root / "baseline-control.json", "compatible"
            ),
            baseline_control_status=0,
            baseline_probe_result=None,
            baseline_probe_status=None,
            candidate_policy=candidate_policy,
            candidate_generation_inputs=candidate_inputs,
            candidate_generator=candidate_generator,
            candidate_control_result=candidate_control_result,
            candidate_control_status=candidate_control_status,
            candidate_probe_result=None,
            candidate_probe_status=None,
            expectations=None,
        )

    def make_probe(self, root: Path, args: Namespace) -> None:
        args.runtime_workload.write_text(
            "kind: Pod\nmetadata:\n  name: mutated\n", encoding="utf-8"
        )
        args.expectations = self.write_json(
            root / "expect.json",
            {
                "baseline": {
                    "result": "policy-incompatible",
                    "denial_contains": ["CreateContainerRequest", "annotation"],
                },
                "candidate": {
                    "result": "policy-incompatible",
                    "denial_contains": ["CreateContainerRequest", "annotation"],
                },
            },
        )
        denial = "CreateContainerRequest blocked by policy: annotation mismatch"
        args.baseline_probe_result = self.write_result(
            root / "baseline-probe.json", "policy-incompatible", denial
        )
        args.baseline_probe_status = 1
        args.candidate_probe_result = self.write_result(
            root / "candidate-probe.json", "policy-incompatible", denial
        )
        args.candidate_probe_status = 1

    def test_identical_workload_is_compatibility_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = MODULE.build_case_report(self.arguments(Path(temporary)))
            self.assertEqual(report["evaluation_type"], "compatibility")
            self.assertTrue(report["passed"])
            self.assertEqual(set(report["variants"]), {"baseline", "candidate"})

    def test_distinct_runtime_workload_runs_control_and_attributed_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            self.make_probe(root, args)

            report = MODULE.build_case_report(args)

            self.assertEqual(report["evaluation_type"], "security-probe")
            self.assertTrue(report["passed"])
            self.assertTrue(
                report["variants"]["candidate"]["control"]["passed"]
            )
            self.assertTrue(report["variants"]["candidate"]["probe"]["passed"])

    def test_unrelated_denial_does_not_satisfy_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root)
            self.make_probe(root, args)
            args.baseline_probe_result = self.write_result(
                root / "baseline-probe.json",
                "policy-incompatible",
                "ExecProcessRequest blocked by policy",
            )

            report = MODULE.build_case_report(args)

            self.assertFalse(report["passed"])
            self.assertFalse(
                report["variants"]["baseline"]["probe"]["passed"]
            )

    def test_infrastructure_failure_never_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root, candidate=False)
            args.baseline_control_result = root / "missing.json"
            args.baseline_control_status = 1

            report = MODULE.build_case_report(args)

            self.assertFalse(report["passed"])
            self.assertEqual(
                report["variants"]["baseline"]["control"]["actual"],
                "infrastructure-failure",
            )

    def test_exit_status_must_match_compatibility_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root, candidate=False)
            args.baseline_control_status = 1

            report = MODULE.build_case_report(args)

            self.assertFalse(report["passed"])
            self.assertFalse(
                report["variants"]["baseline"]["control"]["status_consistent"]
            )

    def test_invalid_generation_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.arguments(root, candidate=False)
            args.baseline_generation_inputs.write_text(
                "not a digest\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "invalid sha256 manifest"):
                MODULE.build_case_report(args)

    def test_matrix_requires_complete_nonempty_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = self.write_json(
                root / "a.json",
                {
                    "case": "a",
                    "evaluation_type": "compatibility",
                    "passed": True,
                },
            )

            report = MODULE.build_matrix_report([case], ["a", "b"])

            self.assertFalse(report["passed"])
            self.assertEqual(report["case_inventory"]["missing"], ["b"])
            self.assertEqual(report["summary"]["failed_cases"], 1)
            self.assertFalse(MODULE.build_matrix_report([], [])["passed"])


if __name__ == "__main__":
    unittest.main()
