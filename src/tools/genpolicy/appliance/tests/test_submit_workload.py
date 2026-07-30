import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "submit_workload.py"
SPEC = importlib.util.spec_from_file_location("submit_workload", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SubmitWorkloadTests(unittest.TestCase):
    def test_deployment_becomes_bound_pod(self):
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "test"},
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "containers": [
                            {"name": "web", "image": "example.invalid/web:1"}
                        ]
                    },
                }
            },
        }

        pod, generated = MODULE.pod_from_workload(deployment, "genpolicy-node")

        self.assertTrue(generated)
        self.assertEqual(pod["metadata"]["namespace"], "test")
        self.assertEqual(pod["metadata"]["labels"], {"app": "web"})
        self.assertTrue(pod["metadata"]["generateName"].startswith("gp-deployment-web-"))
        self.assertEqual(pod["spec"]["nodeName"], "genpolicy-node")

    def test_cronjob_template_path(self):
        cronjob = {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "nightly"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [
                                    {"name": "job", "image": "example.invalid/job:1"}
                                ],
                            }
                        }
                    }
                }
            },
        }

        pod, _ = MODULE.pod_from_workload(cronjob, "genpolicy-node")

        self.assertEqual(pod["spec"]["restartPolicy"], "Never")


if __name__ == "__main__":
    unittest.main()
