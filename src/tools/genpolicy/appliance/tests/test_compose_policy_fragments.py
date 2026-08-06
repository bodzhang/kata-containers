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

        with self.assertRaisesRegex(composition.CompositionError, "duplicate claim"):
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


if __name__ == "__main__":
    unittest.main()
