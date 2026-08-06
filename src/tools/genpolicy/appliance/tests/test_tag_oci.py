import importlib.util
import json
import re
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "tag_oci.py"
SPEC = importlib.util.spec_from_file_location("tag_oci", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TagOciTests(unittest.TestCase):
    def test_exact_and_service_values_are_tagged(self):
        occurrences = {}
        occurrences = defaultdict(list)
        definitions = {}
        value = (
            "NODE=genpolicy-node;"
            "KUBERNETES_SERVICE_HOST=10.96.0.1"
        )
        transformed = MODULE.replace_string(
            value,
            ["oci", "process", "env", "0"],
            "tagged/test.json",
            [
                {
                    "source": "profile",
                    "suggested_regex": "[a-z0-9-]+",
                    "tag": "node.name",
                    "value": "genpolicy-node",
                }
            ],
            occurrences,
            definitions,
        )

        self.assertIn("{{GENPOLICY_DYNAMIC:node.name}}", transformed)

        service = MODULE.replace_string(
            "KUBERNETES_SERVICE_HOST=10.96.0.1",
            ["oci", "process", "env", "1"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )
        self.assertEqual(
            service,
            "KUBERNETES_SERVICE_HOST="
            "{{GENPOLICY_DYNAMIC:service-env.KUBERNETES_SERVICE_HOST}}",
        )
        self.assertIn("service-env.KUBERNETES_SERVICE_HOST", definitions)
        host_regex = (
            "^KUBERNETES_SERVICE_HOST="
            + definitions[
                "service-env.KUBERNETES_SERVICE_HOST"
            ]["suggested_regex"]
            + "$"
        )
        self.assertIsNotNone(
            re.search(host_regex, "KUBERNETES_SERVICE_HOST=10.96.0.1")
        )
        self.assertIsNotNone(
            re.search(host_regex, "KUBERNETES_SERVICE_HOST=::1")
        )
        self.assertIsNone(re.search(host_regex, "LD_PRELOAD=::1"))
        self.assertIsNone(
            re.search(
                host_regex,
                "KUBERNETES_SERVICE_HOST=10.96.0.1-attacker",
            )
        )

        MODULE.replace_string(
            "KUBERNETES_PORT=tcp://10.96.0.1:443",
            ["oci", "process", "env", "2"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )
        self.assertIn(
            "tcp|udp|sctp",
            definitions["service-env.KUBERNETES_PORT"]["suggested_regex"],
        )

    def test_service_environment_is_name_bound_and_portable(self):
        occurrences = defaultdict(list)
        definitions = {}
        transformed = MODULE.replace_string(
            "BACKEND_SERVICE_HOST=10.96.0.42",
            ["oci", "process", "env", "0"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )

        tag = "service-env.BACKEND_SERVICE_HOST"
        self.assertEqual(
            transformed,
            f"BACKEND_SERVICE_HOST={MODULE.marker(tag)}",
        )
        policy_regex = (
            "^BACKEND_SERVICE_HOST="
            + definitions[tag]["suggested_regex"]
            + "$"
        )
        self.assertIsNotNone(
            re.search(policy_regex, "BACKEND_SERVICE_HOST=10.244.7.19")
        )
        self.assertIsNone(
            re.search(policy_regex, "OTHER_SERVICE_HOST=10.244.7.19")
        )
        self.assertIsNone(
            re.search(policy_regex, "BACKEND_SERVICE_HOST=not-an-ip")
        )

        named_port = MODULE.replace_string(
            "BACKEND_SERVICE_PORT_HTTPS=8443",
            ["oci", "process", "env", "1"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )
        port_tag = "service-env.BACKEND_SERVICE_PORT_HTTPS"
        self.assertEqual(
            named_port,
            f"BACKEND_SERVICE_PORT_HTTPS={MODULE.marker(port_tag)}",
        )
        self.assertEqual(definitions[port_tag]["suggested_regex"], "[0-9]{1,5}")

    def test_main_writes_tagged_request_and_request_rooted_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw"
            tagged = root / "tagged"
            raw.mkdir()
            (raw / "0001-id.json").write_text(
                json.dumps(
                    {
                        "container_id": "a" * 64,
                        "storages": [{"source": "a" * 64}],
                        "oci": {
                            "annotations": {
                                "io.kubernetes.cri.sandbox-uid": (
                                    "11111111-1111-4111-8111-111111111111"
                                )
                            },
                            "process": {
                                "env": ["KUBERNETES_SERVICE_PORT=443"]
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            dynamic = root / "dynamic.json"
            dynamic.write_text("[]", encoding="utf-8")
            manifest = root / "manifest.json"

            original_argv = sys.argv
            try:
                sys.argv = [
                    "tag_oci.py",
                    "--raw-requests-dir",
                    str(raw),
                    "--dynamic-values",
                    str(dynamic),
                    "--output-dir",
                    str(tagged),
                    "--manifest",
                    str(manifest),
                ]
                MODULE.main()
            finally:
                sys.argv = original_argv

            output_path = tagged / "0001-id.tagged.json"
            output = output_path.read_text(encoding="utf-8")
            tagged_request = json.loads(output)
            self.assertIn("oci", tagged_request)
            self.assertIn("storages", tagged_request)
            self.assertIn("{{GENPOLICY_DYNAMIC:pod.uid}}", output)
            self.assertIn(
                "{{GENPOLICY_DYNAMIC:service-env.KUBERNETES_SERVICE_PORT}}",
                output,
            )
            tags = json.loads(manifest.read_text(encoding="utf-8"))["tags"]
            self.assertTrue(any(item["tag"] == "pod.uid" for item in tags))
            service_tag = next(
                item
                for item in tags
                if item["tag"] == "service-env.KUBERNETES_SERVICE_PORT"
            )
            self.assertEqual(
                service_tag["occurrences"][0]["json_pointer"],
                "/oci/process/env/0",
            )

    def test_termination_log_id_is_left_for_compiler_validation(self):
        from collections import defaultdict

        occurrences = defaultdict(list)
        definitions = {}
        transformed = MODULE.replace_string(
            "/var/lib/kubelet/pods/uid/containers/workload/7f627291",
            ["oci", "mounts", "7", "source"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )

        self.assertEqual(
            transformed,
            "/var/lib/kubelet/pods/uid/containers/workload/7f627291",
        )
        self.assertNotIn("termination-log.id", definitions)

    def test_network_namespace_is_tagged(self):
        from collections import defaultdict

        occurrences = defaultdict(list)
        definitions = {}
        transformed = MODULE.replace_string(
            "/var/run/netns/cni-11111111-2222-3333-4444-555555555555",
            ["oci", "annotations", "nerdctl/network-namespace"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )

        self.assertEqual(
            transformed, "{{GENPOLICY_DYNAMIC:network.namespace}}"
        )
        self.assertIn("network.namespace", definitions)

    def test_service_is_typed_and_cni_path_is_generalized(self):
        occurrences = defaultdict(list)
        definitions = {}
        service = MODULE.replace_string(
            "BACKEND_SERVICE_HOST=10.96.0.12",
            ["oci", "process", "env", "0"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )
        network_namespace = MODULE.replace_string(
            "/var/run/netns/cni-11111111-2222-3333-4444-555555555555",
            ["oci", "annotations", "nerdctl/network-namespace"],
            "tagged/test.json",
            [],
            occurrences,
            definitions,
        )

        self.assertEqual(
            service,
            "BACKEND_SERVICE_HOST="
            "{{GENPOLICY_DYNAMIC:service-env.BACKEND_SERVICE_HOST}}",
        )
        self.assertIn("service-env.BACKEND_SERVICE_HOST", definitions)
        self.assertEqual(
            network_namespace,
            "{{GENPOLICY_DYNAMIC:network.namespace}}",
        )
        self.assertIn("network.namespace", definitions)

    def test_kata_runtime_annotation_follows_oci_network_namespace(self):
        spec = {
            "annotations": {
                "io.kubernetes.cri.container-type": "sandbox",
            },
            "linux": {
                "namespaces": [
                    {
                        "type": "network",
                        "path": (
                            "/var/run/netns/"
                            "cni-11111111-2222-3333-4444-555555555555"
                        ),
                    }
                ]
            },
        }

        MODULE.apply_kata_runtime_behavior(spec)

        self.assertEqual(
            spec["annotations"]["nerdctl/network-namespace"],
            "/var/run/netns/cni-11111111-2222-3333-4444-555555555555",
        )

    def test_kata_runtime_rejects_mismatched_network_annotation(self):
        spec = {
            "annotations": {
                "io.kubernetes.cri.container-type": "sandbox",
                "nerdctl/network-namespace": "/var/run/netns/cni-existing",
            },
            "linux": {
                "namespaces": [
                    {
                        "type": "network",
                        "path": "/var/run/netns/cni-from-oci",
                    }
                ]
            },
        }

        with self.assertRaisesRegex(ValueError, "does not match"):
            MODULE.apply_kata_runtime_behavior(spec)

if __name__ == "__main__":
    unittest.main()
