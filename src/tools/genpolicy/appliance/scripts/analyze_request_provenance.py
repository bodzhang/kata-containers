#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import yaml


def pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def differences(reference, candidate, path="") -> list[dict]:
    if isinstance(reference, dict) and isinstance(candidate, dict):
        result = []
        for key in sorted(reference.keys() | candidate.keys()):
            child = f"{path}/{pointer_escape(str(key))}"
            if key not in reference:
                result.append(
                    {"candidate": candidate[key], "change": "added", "path": child}
                )
            elif key not in candidate:
                result.append(
                    {"baseline": reference[key], "change": "removed", "path": child}
                )
            else:
                result.extend(differences(reference[key], candidate[key], child))
        return result
    if isinstance(reference, list) and isinstance(candidate, list):
        if reference == candidate:
            return []
        if len(reference) == len(candidate) and sorted(
            json.dumps(value, sort_keys=True) for value in reference
        ) == sorted(json.dumps(value, sort_keys=True) for value in candidate):
            return [
                {
                    "baseline": reference,
                    "candidate": candidate,
                    "change": "reordered",
                    "path": path or "/",
                }
            ]
    if reference != candidate:
        return [
            {
                "baseline": reference,
                "candidate": candidate,
                "change": "changed",
                "path": path or "/",
            }
        ]
    return []


def request_section(path: str) -> str:
    if path.startswith("/process"):
        return "oci-process"
    if path.startswith("/root"):
        return "oci-root"
    if path.startswith("/mounts"):
        return "oci-mounts"
    if path.startswith("/linux/resources"):
        return "oci-resources"
    if path.startswith("/linux/devices"):
        return "oci-devices"
    if path.startswith("/linux/namespaces"):
        return "oci-namespaces"
    if path.startswith("/linux"):
        return "oci-linux"
    if path.startswith("/annotations"):
        return "oci-annotations"
    return "oci-other"


def key_values(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        key, separator, content = value.partition("=")
        if separator:
            result[key] = content
    return result


def pod_specs(document: dict):
    kind = document.get("kind")
    if kind == "Pod":
        yield document.get("spec", {})
        return
    paths = {
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
        "DaemonSet": ("spec", "template", "spec"),
        "Deployment": ("spec", "template", "spec"),
        "Job": ("spec", "template", "spec"),
        "ReplicaSet": ("spec", "template", "spec"),
        "ReplicationController": ("spec", "template", "spec"),
        "StatefulSet": ("spec", "template", "spec"),
    }
    if kind not in paths:
        return
    value = document
    for element in paths[kind]:
        value = value.get(element, {})
    yield value


def workload_containers(path: Path) -> dict[str, dict]:
    result = {}
    with path.open(encoding="utf-8") as source:
        for document in yaml.safe_load_all(source):
            if not isinstance(document, dict):
                continue
            for spec in pod_specs(document):
                for field in ("initContainers", "containers", "ephemeralContainers"):
                    for container in spec.get(field, []):
                        result[container.get("name", "")] = container
    return result


def image_configs(capture: Path) -> dict[str, dict]:
    index = json.loads((capture / "images" / "index.json").read_text(encoding="utf-8"))
    result = {}
    for reference, descriptor in index["images"].items():
        config = json.loads(
            (capture / "images" / descriptor["config_path"]).read_text(encoding="utf-8")
        )
        result[reference] = config.get("config") or {}
    return result


def environment_provenance(
    request: dict, workload: dict[str, dict], images: dict[str, dict]
) -> list[dict]:
    oci = request.get("oci") or {}
    annotations = oci.get("annotations") or {}
    container_name = annotations.get("io.kubernetes.cri.container-name", "")
    image_reference = annotations.get("io.kubernetes.cri.image-name", "")
    final = key_values((oci.get("process") or {}).get("env") or [])
    image = key_values(images.get(image_reference, {}).get("Env") or [])
    yaml_container = workload.get(container_name, {})
    yaml_env = {entry.get("name"): entry for entry in yaml_container.get("env", [])}
    entries = []
    for index, (name, value) in enumerate(final.items()):
        yaml_entry = yaml_env.get(name)
        image_matches = image.get(name) == value
        if yaml_entry and yaml_entry.get("value") == value:
            source = "yaml-declared"
            confidence = "direct"
            evidence = [{"artifact": "workload.yaml", "container": container_name, "field": f"env/{name}"}]
        elif yaml_entry and "valueFrom" in yaml_entry:
            source = "kubernetes-resolved"
            confidence = "derived"
            evidence = [{"artifact": "workload.yaml", "container": container_name, "field": f"env/{name}/valueFrom"}]
        elif image_matches and not yaml_entry:
            source = "image-config"
            confidence = "direct"
            evidence = [{"artifact": "images/index.json", "image": image_reference, "field": f"config.Env/{name}"}]
        elif image_matches and yaml_entry:
            source = "mixed"
            confidence = "ambiguous"
            evidence = [
                {"artifact": "workload.yaml", "container": container_name, "field": f"env/{name}"},
                {"artifact": "images/index.json", "image": image_reference, "field": f"config.Env/{name}"},
            ]
        else:
            source = "kubernetes-resolved"
            confidence = "derived"
            evidence = [{"artifact": "raw-oci", "container": container_name}]
        entries.append(
            {
                "confidence": confidence,
                "disposition": "effective",
                "evidence": evidence,
                "path": f"/oci/process/env/{index}",
                "source": source,
                "stage": "kubernetes-resolution" if source == "kubernetes-resolved" else source,
                "value": f"{name}={value}",
            }
        )
    for name, value in image.items():
        if name in yaml_env and final.get(name) != value:
            entries.append(
                {
                    "confidence": "direct",
                    "disposition": "overridden",
                    "evidence": [{"artifact": "images/index.json", "image": image_reference}],
                    "source": "image-config",
                    "stage": "image-config",
                    "value": f"{name}={value}",
                }
            )
    return entries


def process_provenance(
    request: dict, workload: dict[str, dict], images: dict[str, dict]
) -> list[dict]:
    oci = request.get("oci") or {}
    process = oci.get("process") or {}
    annotations = oci.get("annotations") or {}
    container_name = annotations.get("io.kubernetes.cri.container-name", "")
    image_reference = annotations.get("io.kubernetes.cri.image-name", "")
    container = workload.get(container_name, {})
    image = images.get(image_reference, {})
    entries = []

    command = container.get("command")
    arguments = container.get("args")
    image_entrypoint = image.get("Entrypoint") or []
    image_command = image.get("Cmd") or []
    expected_args = (command if command is not None else image_entrypoint) + (
        arguments if arguments is not None else image_command
    )
    if process.get("args") == expected_args:
        contributors = []
        if command is not None or arguments is not None:
            contributors.append({"artifact": "workload.yaml", "container": container_name, "field": "command/args"})
        if command is None or arguments is None:
            contributors.append({"artifact": "images/index.json", "image": image_reference, "field": "config.Entrypoint/Cmd"})
        source = "mixed" if len(contributors) > 1 else ("yaml-declared" if command is not None or arguments is not None else "image-config")
        entries.append(
            {
                "confidence": "derived" if source == "mixed" else "direct",
                "disposition": "effective",
                "evidence": contributors,
                "path": "/oci/process/args",
                "source": source,
                "stage": "cri-generation",
                "value": process.get("args"),
            }
        )

    working_directory = image.get("WorkingDir") or "/"
    entries.append(
        {
            "confidence": "direct" if image.get("WorkingDir") else "derived",
            "disposition": "effective",
            "evidence": [{"artifact": "images/index.json", "image": image_reference, "field": "config.WorkingDir"}],
            "path": "/oci/process/cwd",
            "source": "image-config" if process.get("cwd") == working_directory and image.get("WorkingDir") else "cri-generated",
            "stage": "image-config" if image.get("WorkingDir") else "cri-generation",
            "value": process.get("cwd"),
        }
    )

    security_context = container.get("securityContext") or {}
    user = process.get("user") or {}
    yaml_user = {
        "gid": security_context.get("runAsGroup"),
        "uid": security_context.get("runAsUser"),
    }
    if any(value is not None for value in yaml_user.values()):
        source = "yaml-declared"
        confidence = "direct"
        evidence = [{"artifact": "workload.yaml", "container": container_name, "field": "securityContext"}]
    else:
        image_user = str(image.get("User") or "")
        numeric = image_user.split(":", 1)
        matches = image_user and numeric[0].isdigit() and int(numeric[0]) == user.get("uid")
        source = "image-config" if matches else "cri-generated"
        confidence = "direct" if matches else "derived"
        evidence = [{"artifact": "images/index.json", "image": image_reference, "field": "config.User"}]
    entries.append(
        {
            "confidence": confidence,
            "disposition": "effective",
            "evidence": evidence,
            "path": "/oci/process/user",
            "source": source,
            "stage": "cri-generation",
            "value": user,
        }
    )
    return entries


def mount_provenance(request: dict, workload: dict[str, dict]) -> list[dict]:
    oci = request.get("oci") or {}
    annotations = oci.get("annotations") or {}
    container_name = annotations.get("io.kubernetes.cri.container-name", "")
    container = workload.get(container_name, {})
    declared = {
        mount.get("mountPath"): mount
        for mount in container.get("volumeMounts", [])
        if mount.get("mountPath")
    }
    entries = []
    for index, mount in enumerate(oci.get("mounts") or []):
        destination = mount.get("destination")
        if destination in declared:
            source = "yaml-declared"
            confidence = "derived"
            evidence = [{"artifact": "workload.yaml", "container": container_name, "field": f"volumeMounts/{destination}"}]
        else:
            source = "kubernetes-resolved"
            confidence = "derived"
            evidence = [{"artifact": "raw-oci", "container": container_name, "field": f"mounts/{index}"}]
        entries.append(
            {
                "confidence": confidence,
                "disposition": "effective",
                "evidence": evidence,
                "path": f"/oci/mounts/{index}",
                "source": source,
                "stage": "kubernetes-resolution",
                "value": mount,
            }
        )
    return entries


def analyze(capture: Path) -> tuple[dict, dict]:
    workload = workload_containers(capture / "workload.yaml")
    images = image_configs(capture)
    transformations = []
    provenance = []
    for request_path in sorted((capture / "createcontainer-requests").glob("*.json")):
        basename = request_path.stem
        raw_path = capture / "raw-oci" / f"{basename}.config.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        identity = {
            "container_id": request.get("container_id", ""),
            "file": request_path.name,
        }
        if not raw_path.is_file() or request.get("oci") is None:
            transformations.append(
                {"identity": identity, "status": "unmatched", "changes": []}
            )
            continue
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        changes = differences(raw, request["oci"])
        for change in changes:
            change["section"] = request_section(change["path"])
            if "candidate" in change:
                provenance.append(
                    {
                        "confidence": "direct",
                        "disposition": "effective",
                        "evidence": [
                            {"artifact": raw_path.relative_to(capture).as_posix()},
                            {"artifact": request_path.relative_to(capture).as_posix()},
                        ],
                        "path": f"/oci{change['path']}",
                        "request": identity,
                        "source": "profile-runtime",
                        "stage": "post-raw-oci",
                        "value": change["candidate"],
                    }
                )
        for field, section in (
            ("storages", "agent-storages"),
            ("devices", "agent-devices"),
            ("shared_mounts", "agent-shared-mounts"),
        ):
            if request.get(field):
                changes.append(
                    {
                        "candidate": request[field],
                        "change": "added",
                        "path": f"/{field}",
                        "section": section,
                    }
                )
                for index, value in enumerate(request[field]):
                    provenance.append(
                        {
                            "confidence": "direct",
                            "evidence": [{"artifact": request_path.name}],
                            "path": f"/{field}/{index}",
                            "request": identity,
                            "source": "profile-runtime",
                            "stage": "post-raw-oci",
                            "value": value,
                        }
                    )
        provenance.extend(
            {**entry, "request": identity}
            for entry in environment_provenance(request, workload, images)
        )
        provenance.extend(
            {**entry, "request": identity}
            for entry in process_provenance(request, workload, images)
        )
        provenance.extend(
            {**entry, "request": identity}
            for entry in mount_provenance(request, workload)
        )
        transformations.append(
            {"changes": changes, "identity": identity, "status": "paired"}
        )
    return (
        {"requests": transformations, "schema_version": 1},
        {"entries": provenance, "schema_version": 1},
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--transformations", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    args = parser.parse_args()
    transformations, provenance = analyze(args.capture)
    for path, value in (
        (args.transformations, transformations),
        (args.provenance, provenance),
    ):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()