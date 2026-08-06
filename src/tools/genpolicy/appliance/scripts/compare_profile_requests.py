#!/usr/bin/env python3

import argparse
import copy
import json
from collections import defaultdict
from pathlib import Path

import yaml


GENERATED_ANNOTATIONS = {
    "io.kubernetes.cri.container-id",
    "io.kubernetes.cri.sandbox-id",
    "io.kubernetes.cri.sandbox-log-directory",
    "io.kubernetes.cri.sandbox-name",
    "io.kubernetes.cri.sandbox-uid",
}


def pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def differences(baseline, candidate, path="") -> list[dict]:
    if isinstance(baseline, dict) and isinstance(candidate, dict):
        result = []
        for key in sorted(baseline.keys() | candidate.keys()):
            child = f"{path}/{pointer_escape(str(key))}"
            if key not in baseline:
                result.append({"candidate": candidate[key], "change": "added", "path": child})
            elif key not in candidate:
                result.append({"baseline": baseline[key], "change": "removed", "path": child})
            else:
                result.extend(differences(baseline[key], candidate[key], child))
        return result
    if isinstance(baseline, list) and isinstance(candidate, list):
        if baseline == candidate:
            return []
        if len(baseline) == len(candidate) and sorted(
            json.dumps(value, sort_keys=True) for value in baseline
        ) == sorted(json.dumps(value, sort_keys=True) for value in candidate):
            return [{"baseline": baseline, "candidate": candidate, "change": "reordered", "path": path or "/"}]
    if baseline != candidate:
        return [{"baseline": baseline, "candidate": candidate, "change": "changed", "path": path or "/"}]
    return []


def section(path: str) -> str:
    sections = (
        ("/oci/process", "oci-process"),
        ("/oci/root", "oci-root"),
        ("/oci/mounts", "oci-mounts"),
        ("/oci/linux/resources", "oci-resources"),
        ("/oci/linux/devices", "oci-devices"),
        ("/oci/linux/namespaces", "oci-namespaces"),
        ("/oci/linux", "oci-linux"),
        ("/oci/annotations", "oci-annotations"),
        ("/storages", "agent-storages"),
        ("/devices", "agent-devices"),
        ("/shared_mounts", "agent-shared-mounts"),
        ("/process", "exec-process"),
    )
    return next((name for prefix, name in sections if path.startswith(prefix)), "request")


def pod_spec(document: dict) -> dict | None:
    paths = {
        "Pod": ("spec",),
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
        "DaemonSet": ("spec", "template", "spec"),
        "Deployment": ("spec", "template", "spec"),
        "Job": ("spec", "template", "spec"),
        "ReplicaSet": ("spec", "template", "spec"),
        "ReplicationController": ("spec", "template", "spec"),
        "StatefulSet": ("spec", "template", "spec"),
    }
    if document.get("kind") not in paths:
        return None
    value = document
    for element in paths[document["kind"]]:
        value = value.get(element, {})
    return value


def workload_owners(capture: Path) -> list[dict]:
    owners = []
    with (capture / "workload.yaml").open(encoding="utf-8") as source:
        for document in yaml.safe_load_all(source):
            if not isinstance(document, dict) or pod_spec(document) is None:
                continue
            spec = pod_spec(document) or {}
            owners.append(
                {
                    "containers": {
                        container.get("name", "")
                        for field in ("initContainers", "containers", "ephemeralContainers")
                        for container in spec.get(field, [])
                    },
                    "kind": document.get("kind", ""),
                    "name": (document.get("metadata") or {}).get("name", ""),
                    "namespace": (document.get("metadata") or {}).get("namespace", "default"),
                }
            )
    return owners


def create_identity(request: dict, owners: list[dict]) -> tuple:
    annotations = ((request.get("oci") or {}).get("annotations") or {})
    namespace = annotations.get("io.kubernetes.cri.sandbox-namespace", "default")
    container_type = annotations.get("io.kubernetes.cri.container-type", "container")
    container_name = annotations.get("io.kubernetes.cri.container-name", "")
    matches = [
        owner
        for owner in owners
        if owner["namespace"] == namespace
        and (container_type == "sandbox" or container_name in owner["containers"])
    ]
    owner = matches[0] if len(matches) == 1 else {"kind": "", "name": ""}
    return (
        namespace,
        owner["kind"],
        owner["name"],
        container_type,
        container_name,
    )


def load_requests(capture: Path) -> dict[tuple, list[dict]]:
    owners = workload_owners(capture)
    grouped = defaultdict(list)
    containers = {}
    for path in sorted((capture / "createcontainer-requests").glob("*.json")):
        request = json.loads(path.read_text(encoding="utf-8"))
        key = ("CreateContainerRequest", *create_identity(request, owners))
        grouped[key].append({"file": path.name, "request": request})
        containers[request.get("container_id", "")] = key
    exec_counts = defaultdict(int)
    for path in sorted((capture / "execprocess-requests").glob("*.json")):
        request = json.loads(path.read_text(encoding="utf-8"))
        owner = containers.get(request.get("container_id", ""))
        if owner is None:
            key = ("ExecProcessRequest", "unresolved-container", request.get("container_id", ""))
        else:
            owner_identity = owner[1:]
            occurrence = exec_counts[owner_identity]
            exec_counts[owner_identity] += 1
            key = ("ExecProcessRequest", *owner_identity, occurrence)
        grouped[key].append({"file": path.name, "request": request})
    return grouped


def normalize(request: dict) -> dict:
    result = copy.deepcopy(request)
    for field in ("container_id", "exec_id"):
        if field in result:
            result[field] = f"{{{{generated:{field}}}}}"
    annotations = ((result.get("oci") or {}).get("annotations") or {})
    for name in GENERATED_ANNOTATIONS & annotations.keys():
        annotations[name] = f"{{{{generated:{name}}}}}"
    return result


def profile_delta(baseline: Path, candidate: Path) -> dict:
    baseline_profile = json.loads((baseline / "profile.json").read_text(encoding="utf-8"))
    candidate_profile = json.loads((candidate / "profile.json").read_text(encoding="utf-8"))
    dimensions = differences(
        {
            "capture_backend": baseline_profile.get("capture_backend"),
            "configuration_hashes": baseline_profile.get("configuration_hashes", {}),
            "rootfs_mode": baseline_profile.get("rootfs_mode"),
            "values": baseline_profile.get("values", {}),
        },
        {
            "capture_backend": candidate_profile.get("capture_backend"),
            "configuration_hashes": candidate_profile.get("configuration_hashes", {}),
            "rootfs_mode": candidate_profile.get("rootfs_mode"),
            "values": candidate_profile.get("values", {}),
        },
    )
    baseline_manifest = json.loads((baseline / "manifest.json").read_text(encoding="utf-8"))
    candidate_manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
    static_paths = ["workload.yaml", "requested-images.txt", "images/index.json"]
    inputs_equal = all(
        baseline_manifest["artifacts"].get(path) == candidate_manifest["artifacts"].get(path)
        for path in static_paths
    )
    result = {"dimensions": dimensions, "static_inputs_equal": inputs_equal}
    causal_dimensions = [
        dimension
        for dimension in dimensions
        if dimension["path"] != "/values/PROFILE_NAME"
    ]
    if inputs_equal and len(causal_dimensions) == 1:
        result["attributed_cause"] = causal_dimensions[0]
    elif causal_dimensions:
        result["candidate_causes"] = causal_dimensions
    return result


def compare(baseline: Path, candidate: Path) -> dict:
    baseline_requests = load_requests(baseline)
    candidate_requests = load_requests(candidate)
    entries = []
    for key in sorted(baseline_requests.keys() | candidate_requests.keys()):
        baseline_group = baseline_requests.get(key, [])
        candidate_group = candidate_requests.get(key, [])
        identity = {"kind": key[0], "workload": list(key[1:])}
        if len(baseline_group) != 1 or len(candidate_group) != 1:
            status = "ambiguous" if len(baseline_group) > 1 or len(candidate_group) > 1 else "unmatched"
            entries.append(
                {
                    "baseline_files": [item["file"] for item in baseline_group],
                    "candidate_files": [item["file"] for item in candidate_group],
                    "identity": identity,
                    "status": status,
                }
            )
            continue
        baseline_item = baseline_group[0]
        candidate_item = candidate_group[0]
        raw = differences(baseline_item["request"], candidate_item["request"])
        normalized = differences(
            normalize(baseline_item["request"]), normalize(candidate_item["request"])
        )
        for change in raw:
            change["section"] = section(change["path"])
        for change in normalized:
            change["section"] = section(change["path"])
        entries.append(
            {
                "baseline_file": baseline_item["file"],
                "candidate_file": candidate_item["file"],
                "identity": identity,
                "normalized_changes": normalized,
                "raw_changes": raw,
                "status": "paired",
            }
        )
    return {
        "baseline_profile": json.loads((baseline / "profile.json").read_text(encoding="utf-8"))["identity"],
        "candidate_profile": json.loads((candidate / "profile.json").read_text(encoding="utf-8"))["identity"],
        "profile_delta": profile_delta(baseline, candidate),
        "requests": entries,
        "schema_version": 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = compare(args.baseline, args.candidate)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()