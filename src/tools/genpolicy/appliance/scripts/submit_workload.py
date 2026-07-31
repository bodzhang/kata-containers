#!/usr/bin/env python3

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml


TEMPLATE_PATHS = {
    "CronJob": ("spec", "jobTemplate", "spec", "template"),
    "DaemonSet": ("spec", "template"),
    "Deployment": ("spec", "template"),
    "Job": ("spec", "template"),
    "PodTemplate": ("template",),
    "ReplicaSet": ("spec", "template"),
    "ReplicationController": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
}
IMAGE_DIGEST = re.compile(
    r"^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?"
    r"@sha256:[0-9a-f]{64}$"
)


def kubectl_create(value: dict) -> dict:
    result = subprocess.run(
        ["kubectl", "create", "-f", "-", "-o", "json"],
        input=json.dumps(value),
        text=True,
        check=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def ensure_namespace(namespace: str) -> None:
    subprocess.run(
        ["kubectl", "create", "namespace", namespace],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def nested(value: dict, path: tuple[str, ...]) -> dict:
    current = value
    for element in path:
        current = current[element]
    return current


def safe_prefix(kind: str, name: str) -> str:
    raw = f"gp-{kind.lower()}-{name.lower()}-"
    value = re.sub(r"[^a-z0-9-]+", "-", raw)
    value = re.sub(r"-+", "-", value).strip("-") + "-"
    return value[-58:]


def pod_from_workload(resource: dict, node_name: str) -> tuple[dict, bool]:
    kind = resource["kind"]
    if kind == "Pod":
        pod = copy.deepcopy(resource)
        pod.setdefault("spec", {})["nodeName"] = node_name
        return pod, bool(pod.get("metadata", {}).get("generateName"))

    template = copy.deepcopy(nested(resource, TEMPLATE_PATHS[kind]))
    resource_metadata = resource.get("metadata", {})
    template_metadata = template.get("metadata") or {}
    source_name = resource_metadata.get("name", kind.lower())
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "annotations": template_metadata.get("annotations", {}),
            "generateName": safe_prefix(kind, source_name),
            "labels": template_metadata.get("labels", {}),
            "namespace": resource_metadata.get("namespace", "default"),
        },
        "spec": template["spec"],
    }
    pod["spec"]["nodeName"] = node_name
    return pod, True


def iter_documents(path: Path):
    with path.open(encoding="utf-8") as source:
        for document in yaml.safe_load_all(source):
            if not document:
                continue
            if document.get("kind") == "List":
                yield from document.get("items", [])
            else:
                yield document


def validate_image_references(path: Path) -> set[str]:
    errors = []
    images = set()
    for document in iter_documents(path):
        kind = document.get("kind")
        if kind == "Pod":
            pod_spec = document.get("spec") or {}
        elif kind in TEMPLATE_PATHS:
            pod_spec = (nested(document, TEMPLATE_PATHS[kind]).get("spec") or {})
        else:
            continue
        for field in ("initContainers", "containers", "ephemeralContainers"):
            for container in pod_spec.get(field, []):
                image = container.get("image", "")
                if not IMAGE_DIGEST.fullmatch(image):
                    errors.append(
                        f"{kind} container {container.get('name', '<unnamed>')} "
                        f"image is not digest-pinned: {image or '<missing>'}"
                    )
                else:
                    images.add(image)
    if errors:
        raise ValueError("\n".join(errors))
    return images


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--images-output", type=Path)
    parser.add_argument("--node-name")
    parser.add_argument("--objects-output", type=Path)
    parser.add_argument("--pods-output", type=Path)
    parser.add_argument("--dynamic-output", type=Path)
    args = parser.parse_args()

    try:
        images = validate_image_references(args.input)
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    if args.images_output:
        args.images_output.write_text(
            "".join(f"{image}\n" for image in sorted(images)),
            encoding="utf-8",
        )
    if args.validate_only:
        return
    for name in (
        "node_name",
        "objects_output",
        "pods_output",
        "dynamic_output",
    ):
        if getattr(args, name) is None:
            parser.error(f"--{name.replace('_', '-')} is required")

    defaulted_objects = []
    pods = []
    dynamic_values = [
        {
            "source": "profile",
            "suggested_regex": "[a-z0-9](?:[-a-z0-9]*[a-z0-9])?",
            "tag": "node.name",
            "value": args.node_name,
        }
    ]

    for document in iter_documents(args.input):
        metadata = document.setdefault("metadata", {})
        namespace = metadata.get("namespace", "default")
        ensure_namespace(namespace)

        kind = document.get("kind")
        if kind == "Pod":
            document.setdefault("spec", {})["nodeName"] = args.node_name

        created = kubectl_create(document)
        defaulted_objects.append(created)

        if kind != "Pod" and kind not in TEMPLATE_PATHS:
            continue

        if kind == "Pod":
            pod = created
            generated_name = bool(document.get("metadata", {}).get("generateName"))
        else:
            pod_input, generated_name = pod_from_workload(created, args.node_name)
            pod = kubectl_create(pod_input)

        pods.append(pod)
        metadata = pod["metadata"]
        dynamic_values.append(
            {
                "source": "api-server",
                "suggested_regex": (
                    "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                    "[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                ),
                "tag": "pod.uid",
                "value": metadata["uid"],
            }
        )
        if generated_name:
            dynamic_values.append(
                {
                    "source": "api-server",
                    "suggested_regex": (
                        "[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
                    ),
                    "tag": "pod.name",
                    "value": metadata["name"],
                }
            )

    if not pods:
        print("input did not contain a supported workload", file=sys.stderr)
        raise SystemExit(1)

    args.objects_output.write_text(
        json.dumps(defaulted_objects, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.pods_output.write_text(
        json.dumps(pods, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    args.dynamic_output.write_text(
        json.dumps(dynamic_values, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
