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

    def test_image_references_must_be_digest_pinned(self):
        import tempfile
        import yaml

        with tempfile.TemporaryDirectory() as temporary:
            workload = Path(temporary) / "workload.yaml"
            workload.write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "web"},
                        "spec": {
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "example.invalid/web:latest",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError, "image is not digest-pinned"
            ):
                MODULE.validate_image_references(workload)

    def test_digest_pinned_image_is_accepted(self):
        import tempfile
        import yaml

        with tempfile.TemporaryDirectory() as temporary:
            workload = Path(temporary) / "workload.yaml"
            workload.write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "web"},
                        "spec": {
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "genpolicy.local:5000/web@sha256:"
                                    + "a" * 64,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                MODULE.validate_image_references(workload),
                {"genpolicy.local:5000/web@sha256:" + "a" * 64},
            )

    def test_external_digest_pinned_image_is_accepted(self):
        import tempfile
        import yaml

        image = "registry.example.com/team/web:release@sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as temporary:
            workload = Path(temporary) / "workload.yaml"
            workload.write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "web"},
                        "spec": {
                            "containers": [
                                {"name": "web", "image": image}
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                MODULE.validate_image_references(workload), {image}
            )

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

    def test_podtemplate_template_path(self):
        pod_template = {
            "apiVersion": "v1",
            "kind": "PodTemplate",
            "metadata": {"name": "worker"},
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "worker",
                            "image": "example.invalid/worker@sha256:" + "c" * 64,
                        }
                    ]
                }
            },
        }

        pod, generated = MODULE.pod_from_workload(
            pod_template, "genpolicy-node"
        )

        self.assertTrue(generated)
        self.assertEqual(pod["spec"]["nodeName"], "genpolicy-node")

    def test_podtemplate_image_is_validated(self):
        import tempfile
        import yaml

        with tempfile.TemporaryDirectory() as temporary:
            workload = Path(temporary) / "workload.yaml"
            workload.write_text(
                yaml.safe_dump(
                    {
                        "apiVersion": "v1",
                        "kind": "PodTemplate",
                        "metadata": {"name": "worker"},
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "worker",
                                        "image": "example.invalid/worker:latest",
                                    }
                                ]
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError, "image is not digest-pinned"
            ):
                MODULE.validate_image_references(workload)


if __name__ == "__main__":
    unittest.main()
