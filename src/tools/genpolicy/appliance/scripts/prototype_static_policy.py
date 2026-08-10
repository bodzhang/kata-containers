#!/usr/bin/env python3

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import yaml


UVM_STATIC_PATHS = {
    "/OCI/Process/Args",
    "/OCI/Process/Cwd",
    "/OCI/Process/Env",
    "/OCI/Process/NoNewPrivileges",
    "/OCI/Process/User",
    "/OCI/Root/Path",
    "/OCI/Root/Readonly",
}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SCRIPT_DIR = Path(__file__).parent
request_provenance = load_module(
    "analyze_request_provenance",
    SCRIPT_DIR / "analyze_request_provenance.py",
)
profile_comparison = load_module(
    "compare_profile_requests",
    SCRIPT_DIR / "compare_profile_requests.py",
)
settings_derivation = load_module(
    "derive_genpolicy_settings",
    SCRIPT_DIR / "derive_genpolicy_settings.py",
)


def pod_spec(document: dict) -> tuple[dict, str, str] | None:
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
    kind = document.get("kind")
    if kind not in paths:
        return None
    value = document
    for element in paths[kind]:
        value = value.get(element, {})
    metadata = document.get("metadata") or {}
    return value, metadata.get("namespace", "default"), metadata.get("name", "")


def workload_documents(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as source:
        return [document for document in yaml.safe_load_all(source) if isinstance(document, dict)]


def trusted_objects(documents: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    config_maps = {}
    secrets = {}
    for document in documents:
        metadata = document.get("metadata") or {}
        key = (metadata.get("namespace", "default"), metadata.get("name", ""))
        if document.get("kind") == "ConfigMap":
            if key in config_maps:
                raise ValueError(f"duplicate trusted ConfigMap: {key[0]}/{key[1]}")
            config_maps[key] = document.get("data") or {}
        elif document.get("kind") == "Secret":
            if key in secrets:
                raise ValueError(f"duplicate trusted Secret: {key[0]}/{key[1]}")
            decoded = {}
            for name, value in (document.get("data") or {}).items():
                decoded[name] = base64.b64decode(value, validate=True).decode("utf-8")
            decoded.update(document.get("stringData") or {})
            secrets[key] = decoded
    return config_maps, secrets


def trusted_services(documents: list[dict]) -> list[dict]:
    services = []
    identities = set()
    for document in documents:
        if document.get("kind") != "Service":
            continue
        metadata = document.get("metadata") or {}
        namespace = metadata.get("namespace", "default")
        name = metadata.get("name", "")
        identity = (namespace, name)
        if not name or identity in identities:
            raise ValueError(f"invalid or duplicate trusted Service: {namespace}/{name}")
        ports = []
        for port in (document.get("spec") or {}).get("ports", []):
            number = port.get("port")
            protocol = port.get("protocol", "TCP").upper()
            if not isinstance(number, int) or not 1 <= number <= 65535:
                raise ValueError(f"invalid Service port: {namespace}/{name}")
            ports.append(
                {
                    "name": port.get("name", ""),
                    "port": number,
                    "protocol": protocol,
                }
            )
        services.append({"name": name, "namespace": namespace, "ports": ports})
        identities.add(identity)
    return services


def image_configs(capture: Path) -> dict[str, dict]:
    index = json.loads((capture / "images" / "index.json").read_text(encoding="utf-8"))
    result = {}
    for reference, descriptor in index["images"].items():
        document = json.loads(
            (capture / "images" / descriptor["config_path"]).read_text(encoding="utf-8")
        )
        result[reference] = document.get("config") or {}
    return result


def image_manifest_digest(reference: str) -> str:
    _, separator, digest = reference.rpartition("@")
    if not separator or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ValueError(f"static image is not digest-bound to a sha256 manifest: {reference}")
    return digest


def normalized_capabilities(security_context: dict) -> dict[str, list[str]]:
    capabilities = security_context.get("capabilities") or {}
    if not isinstance(capabilities, dict):
        raise ValueError("securityContext capabilities must be an object")
    unknown = set(capabilities) - {"add", "drop"}
    if unknown:
        raise ValueError(f"unsupported securityContext capability fields: {sorted(unknown)}")
    result = {}
    for operation in ("add", "drop"):
        values = capabilities.get(operation) or []
        if not isinstance(values, list) or any(
            not isinstance(value, str)
            or re.fullmatch(r"(?:CAP_)?[A-Za-z0-9_]+", value) is None
            for value in values
        ):
            raise ValueError(f"securityContext capabilities {operation} must be names")
        normalized = []
        for value in values:
            name = value.upper()
            if name != "ALL" and not name.startswith("CAP_"):
                name = f"CAP_{name}"
            if name not in normalized:
                normalized.append(name)
        result[operation] = normalized
    return result


def capture_profile(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("capture profile is missing")
    profile = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict) or profile.get("schema_version") != 1:
        raise ValueError("invalid capture profile")
    identity = profile.get("identity")
    unsigned = {key: value for key, value in profile.items() if key != "identity"}
    expected = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if identity != expected:
        raise ValueError("capture profile identity mismatch")
    return profile


def rootfs_artifacts(path: Path | None) -> tuple[dict[str, dict], str | None]:
    if path is None:
        return {}, None
    raw = path.read_bytes()
    manifest = json.loads(raw)
    if manifest.get("schema_version") != 1 or not isinstance(
        manifest.get("images"), dict
    ):
        raise ValueError("invalid rootfs artifact manifest")
    images = manifest["images"]
    for manifest_digest, artifact in images.items():
        if re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is None:
            raise ValueError(f"invalid rootfs artifact manifest digest: {manifest_digest}")
        if not isinstance(artifact, dict):
            raise ValueError(f"invalid rootfs artifact for {manifest_digest}")
        root_hash = artifact.get("root_hash")
        if not isinstance(root_hash, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", root_hash
        ) is None:
            raise ValueError(
                f"rootfs artifact requires a sha256 root hash: {manifest_digest}"
            )
    return images, "sha256:" + hashlib.sha256(raw).hexdigest()


def rootfs_plan(
    image_reference: str,
    profile: dict,
    artifacts: dict[str, dict],
    artifact_manifest_digest: str | None,
) -> dict | None:
    mode = profile.get("rootfs_mode")
    profile_identity = profile.get("identity")
    if not isinstance(profile_identity, str) or re.fullmatch(
        r"[0-9a-f]{64}", profile_identity
    ) is None:
        raise ValueError("capture profile requires a sha256 identity")
    manifest_digest = image_manifest_digest(image_reference)
    plan = {
        "image_manifest_digest": manifest_digest,
        "mode": mode,
        "profile_identity": profile_identity,
    }
    if mode == "guest-pull":
        return plan
    if mode == "erofs-dmverity":
        artifact = artifacts.get(manifest_digest)
        if artifact is None:
            raise ValueError(f"dm-verity rootfs artifact is missing: {manifest_digest}")
        plan["artifact_manifest_digest"] = artifact_manifest_digest
        plan["dm_verity_root_hash"] = artifact["root_hash"]
        return plan
    if mode == "native":
        return None
    raise ValueError(f"unsupported rootfs mode: {mode}")


def key_values(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        name, separator, content = value.partition("=")
        if separator:
            result[name] = content
    return result


def content_digest(values: dict[str, str]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def static_environment(
    container: dict,
    image: dict,
    namespace: str,
    config_maps: dict,
    secrets: dict,
) -> tuple[dict[str, str], list[dict], list[dict]]:
    environment = key_values(image.get("Env") or [])
    evidence = [
        {"field": f"config.Env/{name}", "source": "digest-bound-image"}
        for name in environment
    ]
    env_from = []
    for source in container.get("envFrom") or []:
        if not isinstance(source, dict):
            raise ValueError("envFrom source must be an object")
        prefix = source.get("prefix", "")
        if not isinstance(prefix, str):
            raise ValueError("envFrom prefix must be a string")
        reference_kinds = [kind for kind in ("configMapRef", "secretRef") if kind in source]
        if len(reference_kinds) != 1 or set(source) - {"prefix"} != {reference_kinds[0]}:
            raise ValueError("envFrom requires exactly one ConfigMap or Secret reference")
        kind = reference_kinds[0]
        reference = source[kind]
        if not isinstance(reference, dict):
            raise ValueError(f"envFrom {kind} must be an object")
        name = reference.get("name")
        optional = reference.get("optional", False)
        if not isinstance(name, str) or not name:
            raise ValueError(f"envFrom {kind} requires a name")
        if not isinstance(optional, bool):
            raise ValueError(f"envFrom {kind} optional must be boolean")
        if kind == "configMapRef":
            values = config_maps.get((namespace, name))
            source_name = "trusted-config-map"
            role = "config-map"
        else:
            values = secrets.get((namespace, name))
            source_name = "trusted-secret"
            role = "secret"
        if values is None and not optional:
            raise ValueError(f"required envFrom {role} is missing: {namespace}/{name}")
        if values is None:
            env_from.append(
                {
                    "name": name,
                    "namespace": namespace,
                    "optional": True,
                    "prefix": prefix,
                    "role": role,
                    "status": "absent",
                }
            )
            continue
        env_from.append(
            {
                "content_digest": content_digest(values),
                "keys": sorted(values),
                "name": name,
                "namespace": namespace,
                "optional": optional,
                "prefix": prefix,
                "role": role,
                "status": "resolved",
            }
        )
        for key, value in values.items():
            environment[prefix + key] = value
            evidence.append({"field": f"envFrom/{name}/{key}", "source": source_name})
    unresolved = []
    for entry in container.get("env") or []:
        name = entry.get("name", "")
        if "value" in entry:
            environment[name] = str(entry["value"])
            evidence.append({"field": f"env/{name}", "source": "workload-yaml"})
        elif "valueFrom" in entry:
            unresolved.append(
                {
                    "anchor": entry["valueFrom"],
                    "name": name,
                    "operation": "resolve",
                    "source": "workload-yaml",
                }
            )
    return environment, unresolved, env_from


def process_args(container: dict, image: dict) -> list[str]:
    command = container.get("command")
    arguments = container.get("args")
    return list(command if command is not None else image.get("Entrypoint") or []) + list(
        arguments if arguments is not None else image.get("Cmd") or []
    )


def exec_commands(container: dict) -> list[list[str]]:
    commands = []
    for field in ("livenessProbe", "readinessProbe", "startupProbe"):
        command = ((container.get(field) or {}).get("exec") or {}).get("command")
        if command:
            commands.append(command)
    lifecycle = container.get("lifecycle") or {}
    for field in ("postStart", "preStop"):
        command = ((lifecycle.get(field) or {}).get("exec") or {}).get("command")
        if command:
            commands.append(command)
    return commands


def projected_source(source: dict, namespace: str) -> dict:
    if not isinstance(source, dict):
        raise ValueError("projected volume source must be an object")
    kinds = [
        kind
        for kind in ("configMap", "secret", "downwardAPI", "serviceAccountToken")
        if kind in source
    ]
    if len(kinds) != 1 or len(source) != 1:
        raise ValueError("projected volume source requires exactly one supported type")
    kind = kinds[0]
    value = copy.deepcopy(source[kind])
    if not isinstance(value, dict):
        raise ValueError(f"invalid projected volume source: {kind}")
    if kind in {"configMap", "secret"}:
        name = value.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"projected {kind} source requires a name")
        value["namespace"] = namespace
    roles = {
        "configMap": "config-map",
        "downwardAPI": "downward-api",
        "secret": "secret",
        "serviceAccountToken": "service-account-token",
    }
    return {"role": roles[kind], "source": value}


def volume_source(
    volume: dict,
    namespace: str,
    config_maps: dict,
    secrets: dict,
) -> dict:
    if not isinstance(volume, dict):
        raise ValueError("volume declaration must be an object")
    kinds = [
        kind
        for kind in ("emptyDir", "configMap", "secret", "downwardAPI", "projected")
        if kind in volume
    ]
    source_keys = set(volume) - {"name"}
    if len(kinds) != 1 or source_keys != {kinds[0]}:
        name = volume.get("name", "")
        raise ValueError(f"volume {name} requires exactly one supported source")
    kind = kinds[0]
    source = copy.deepcopy(volume[kind])
    if not isinstance(source, dict):
        raise ValueError(f"invalid {kind} volume source")
    if kind == "emptyDir":
        medium = source.get("medium", "")
        if medium not in {"", "Memory"}:
            raise ValueError(f"unsupported emptyDir medium: {medium}")
        result = {
            "medium": "memory" if medium == "Memory" else "node-default",
            "role": "empty-dir",
        }
        if "sizeLimit" in source:
            result["size_limit"] = str(source["sizeLimit"])
        return result
    if kind in {"configMap", "secret"}:
        name_field = "name" if kind == "configMap" else "secretName"
        name = source.get(name_field)
        if not isinstance(name, str) or not name:
            raise ValueError(f"{kind} volume source requires {name_field}")
        optional = source.get("optional", False)
        if not isinstance(optional, bool):
            raise ValueError(f"{kind} volume source optional must be boolean")
        values = (config_maps if kind == "configMap" else secrets).get(
            (namespace, name)
        )
        role = "config-map" if kind == "configMap" else "secret"
        if values is None and not optional:
            raise ValueError(
                f"required {role} volume is missing: {namespace}/{name}"
            )
        source["name"] = source.pop(name_field)
        source["namespace"] = namespace
        source["status"] = "absent" if values is None else "resolved"
        if values is not None:
            source["content_digest"] = content_digest(values)
            source["keys"] = sorted(values)
        return {"role": role, "source": source}
    if kind == "downwardAPI":
        return {"role": "downward-api", "source": source}
    sources = source.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("projected volume requires sources")
    result = {
        "role": "projected",
        "sources": [projected_source(item, namespace) for item in sources],
    }
    if "defaultMode" in source:
        result["default_mode"] = source["defaultMode"]
    return result


def container_volume_intents(
    spec: dict,
    container: dict,
    namespace: str,
    config_maps: dict,
    secrets: dict,
) -> list[dict]:
    volumes = {}
    for volume in spec.get("volumes") or []:
        name = volume.get("name")
        if not isinstance(name, str) or not name or name in volumes:
            raise ValueError(f"invalid or duplicate volume name: {name}")
        volumes[name] = volume_source(
            volume, namespace, config_maps, secrets
        )
    if container.get("volumeDevices"):
        raise ValueError("static volumeDevices intent is not yet supported")
    intents = []
    destinations = set()
    for mount in container.get("volumeMounts") or []:
        if not isinstance(mount, dict):
            raise ValueError("container volume mount must be an object")
        name = mount.get("name")
        destination = mount.get("mountPath")
        if name not in volumes:
            raise ValueError(f"container volume mount references undeclared volume: {name}")
        if not isinstance(destination, str) or not destination.startswith("/"):
            raise ValueError(f"container volume mount requires an absolute destination: {name}")
        destination_basename = destination.rsplit("/", 1)[-1]
        if not destination_basename:
            raise ValueError(
                f"container volume mount requires a destination basename: {name}"
            )
        if destination in destinations:
            raise ValueError(f"duplicate container volume destination: {destination}")
        if mount.get("subPathExpr") is not None:
            raise ValueError(f"dynamic volume subPathExpr is not yet supported: {name}")
        read_only = mount.get("readOnly", False)
        if not isinstance(read_only, bool):
            raise ValueError(f"container volume mount readOnly must be boolean: {name}")
        intent = {
            "destination": destination,
            "destination_basename": destination_basename,
            "name": name,
            "read_only": read_only,
            **copy.deepcopy(volumes[name]),
        }
        for source_key, target_key in (
            ("mountPropagation", "mount_propagation"),
            ("recursiveReadOnly", "recursive_read_only"),
            ("subPath", "sub_path"),
        ):
            if source_key in mount:
                intent[target_key] = mount[source_key]
        intents.append(intent)
        destinations.add(destination)
    return intents


def uvm_static_baseline(path: Path) -> dict:
    baseline = json.loads(path.read_text(encoding="utf-8"))
    if baseline.get("schema_version") != 1:
        raise ValueError("unsupported UVM static baseline schema")
    artifact_digest = baseline.get("artifact_digest")
    if not isinstance(artifact_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", artifact_digest
    ) is None:
        raise ValueError("UVM static baseline requires a sha256 artifact digest")
    constraints = baseline.get("pause_constraints")
    if not isinstance(constraints, dict):
        raise ValueError("UVM static baseline requires pause_constraints")
    unknown = set(constraints) - UVM_STATIC_PATHS
    if unknown:
        raise ValueError(f"profile-owned or unknown UVM static paths: {sorted(unknown)}")
    missing = UVM_STATIC_PATHS - set(constraints)
    if missing:
        raise ValueError(f"missing UVM static paths: {sorted(missing)}")
    return {
        "artifact_digest": artifact_digest,
        "constraints": constraints,
    }


def generate_static_ir(
    capture: Path,
    uvm_baseline_path: Path | None = None,
    rootfs_artifacts_path: Path | None = None,
) -> dict:
    documents = workload_documents(capture / "workload.yaml")
    config_maps, secrets = trusted_objects(documents)
    services = trusted_services(documents)
    images = image_configs(capture)
    profile = capture_profile(capture / "profile.json")
    artifacts, artifact_manifest_digest = rootfs_artifacts(rootfs_artifacts_path)
    uvm_baseline = (
        uvm_static_baseline(uvm_baseline_path) if uvm_baseline_path is not None else None
    )
    subjects = []
    for document in documents:
        resolved = pod_spec(document)
        if resolved is None:
            continue
        spec, namespace, workload_name = resolved
        containers = [
            container
            for field in ("initContainers", "containers", "ephemeralContainers")
            for container in spec.get(field, [])
        ]
        for container in containers:
            image_reference = container.get("image", "")
            image_manifest_digest(image_reference)
            if image_reference not in images:
                raise ValueError(f"capture has no image config for {image_reference}")
            image = images[image_reference]
            environment, unresolved, env_from = static_environment(
                container, image, namespace, config_maps, secrets
            )
            constraints = {
                "/OCI/Annotations/io.kubernetes.cri.container-name": container["name"],
                "/OCI/Process/Args": process_args(container, image),
                "/OCI/Process/Env": environment,
                "/exec_commands": exec_commands(container),
            }
            working_directory = container.get("workingDir") or image.get("WorkingDir")
            if working_directory:
                constraints["/OCI/Process/Cwd"] = working_directory
            security_context = container.get("securityContext") or {}
            if "readOnlyRootFilesystem" in security_context:
                constraints["/OCI/Root/Readonly"] = security_context["readOnlyRootFilesystem"]
            if "allowPrivilegeEscalation" in security_context:
                constraints["/OCI/Process/NoNewPrivileges"] = not security_context[
                    "allowPrivilegeEscalation"
                ]
            subject = {
                "capabilities": normalized_capabilities(security_context),
                "constraints": constraints,
                "env_from": env_from,
                "image": image_reference,
                "namespace": namespace,
                "service_links_enabled": spec.get("enableServiceLinks", True),
                "subject": f"container/{container['name']}",
                "unresolved": unresolved,
                "volumes": container_volume_intents(
                    spec, container, namespace, config_maps, secrets
                ),
                "workload": {"kind": document["kind"], "name": workload_name},
            }
            rootfs = rootfs_plan(
                image_reference,
                profile,
                artifacts,
                artifact_manifest_digest,
            )
            if rootfs is not None:
                subject["rootfs"] = rootfs
            subjects.append(subject)
        if uvm_baseline is not None:
            subjects.append(
                {
                    "constraints": uvm_baseline["constraints"],
                    "namespace": namespace,
                    "static_artifact": uvm_baseline["artifact_digest"],
                    "subject": f"sandbox/{namespace}/{workload_name}",
                    "unresolved": [],
                    "workload": {"kind": document["kind"], "name": workload_name},
                }
            )
    subject_ids = [subject["subject"] for subject in subjects]
    duplicates = sorted(
        subject_id for subject_id in set(subject_ids) if subject_ids.count(subject_id) > 1
    )
    if duplicates:
        raise ValueError(f"static subject identity is ambiguous: {duplicates}")
    workloads = []
    workload_keys = set()
    for subject in subjects:
        workload = {
            **subject["workload"],
            "namespace": subject["namespace"],
        }
        key = (workload["kind"], workload["name"], workload["namespace"])
        if key not in workload_keys:
            workloads.append(workload)
            workload_keys.add(key)
    return {
        "profile_identity": profile["identity"],
        "schema_version": 1,
        "services": services,
        "subjects": subjects,
        "workloads": workloads,
    }


def render_static_rego_ir(ir: dict) -> str:
    subjects = []
    for ordinal, subject in enumerate(ir["subjects"]):
        constraints = subject["constraints"]
        annotations = {
            pointer.removeprefix("/OCI/Annotations/"): value
            for pointer, value in constraints.items()
            if pointer.startswith("/OCI/Annotations/")
        }
        annotations.setdefault("io.kubernetes.cri.sandbox-namespace", subject["namespace"])
        if subject["subject"].startswith("container/"):
            annotations.setdefault("io.kubernetes.cri.container-type", "container")
        process = {}
        for pointer, field in (
            ("/OCI/Process/Args", "Args"),
            ("/OCI/Process/Cwd", "Cwd"),
        ):
            if pointer in constraints:
                process[field] = constraints[pointer]
        if "/OCI/Process/Env" in constraints:
            process["Env"] = [
                f"{name}={value}"
                for name, value in sorted(constraints["/OCI/Process/Env"].items())
            ]
        subjects.append(
            {
                "id": subject["subject"],
                "ordinal": ordinal,
                "policy": {
                    "OCI": {
                        "Annotations": annotations,
                        "Process": process,
                    }
                },
                "static": subject,
                "workload": {
                    **subject["workload"],
                    "namespace": subject["namespace"],
                },
            }
        )
    regorus_ir = {
        "policy_data": {
            "cluster_config": {},
            "common": {},
            "devices": {},
            "dmverity": {},
            "guest_pull": {},
            "request_defaults": {},
            "sandbox": {},
        },
        "profile_identity": ir["profile_identity"],
        "schema_version": ir["schema_version"],
        "subjects": subjects,
        "workloads": ir["workloads"],
    }
    return (
        "package static_policy_ir\n\n"
        "ir := "
        + json.dumps(regorus_ir, indent=2, sort_keys=True)
        + "\n"
    )


def policy_data(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    marker = "\npolicy_data := "
    if marker not in text:
        raise ValueError(f"policy has no policy_data assignment: {path}")
    return json.loads(text.rsplit(marker, 1)[1])


def policy_subjects(data: dict, static_ir: dict | None = None) -> dict[str, dict]:
    result = {}
    sandboxes_by_namespace = {}
    for container in data.get("containers", []):
        annotations = container.get("OCI", {}).get("Annotations", {})
        container_type = annotations.get("io.kubernetes.cri.container-type")
        if container_type == "container":
            name = annotations.get("io.kubernetes.cri.container-name")
            if name:
                subject = f"container/{name}"
                if subject in result:
                    raise ValueError(f"policy subject identity is ambiguous: {subject}")
                result[subject] = container
        elif container_type == "sandbox":
            namespace = annotations.get("io.kubernetes.cri.sandbox-namespace")
            sandboxes_by_namespace.setdefault(namespace, []).append(container)
    if static_ir is not None:
        static_sandboxes = {}
        for subject in static_ir["subjects"]:
            if subject["subject"].startswith("sandbox/"):
                static_sandboxes.setdefault(subject["namespace"], []).append(subject)
        for namespace, subjects in static_sandboxes.items():
            candidates = sandboxes_by_namespace.get(namespace, [])
            if len(subjects) == 1 and len(candidates) == 1:
                result[subjects[0]["subject"]] = candidates[0]
    return result


def pointer_tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {pointer}")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def pointer_value(document: dict, pointer: str):
    value = document
    for token in pointer_tokens(pointer):
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def pointer_parent(document: dict, pointer: str):
    tokens = pointer_tokens(pointer)
    if not tokens:
        raise ValueError("JSON patch cannot replace the settings root")
    parent = document
    for token in tokens[:-1]:
        parent = parent[int(token)] if isinstance(parent, list) else parent[token]
    return parent, tokens[-1]


def apply_settings_patch(settings: dict, operations: list[dict]) -> None:
    for operation in operations:
        name = operation.get("op")
        parent, token = pointer_parent(settings, operation["path"])
        if name == "replace":
            if isinstance(parent, list):
                parent[int(token)] = operation["value"]
            elif token in parent:
                parent[token] = operation["value"]
            else:
                raise ValueError(f"settings replace target does not exist: {operation['path']}")
        elif name == "add":
            if isinstance(parent, list):
                if token == "-":
                    parent.append(operation["value"])
                else:
                    parent.insert(int(token), operation["value"])
            else:
                parent[token] = operation["value"]
        elif name == "remove":
            if isinstance(parent, list):
                del parent[int(token)]
            else:
                del parent[token]
        elif name == "test":
            actual = parent[int(token)] if isinstance(parent, list) else parent[token]
            if actual != operation["value"]:
                raise ValueError(f"settings test failed: {operation['path']}")
        else:
            raise ValueError(f"unsupported settings patch operation: {name}")


def merged_settings(base: Path, patches: list[Path]) -> dict:
    settings = json.loads(base.read_text(encoding="utf-8"))
    for patch in patches:
        operations = json.loads(patch.read_text(encoding="utf-8"))
        if not isinstance(operations, list):
            raise ValueError(f"settings patch is not an array: {patch}")
        apply_settings_patch(settings, operations)
    return settings


def compare_static(ir: dict, policy: dict) -> dict:
    subjects = policy_subjects(policy, ir)
    checks = []
    for static_subject in ir["subjects"]:
        subject = static_subject["subject"]
        candidate = subjects.get(subject)
        for path, expected in static_subject["constraints"].items():
            if candidate is None:
                actual = None
                matched = False
            else:
                try:
                    actual = pointer_value(candidate, path)
                    if path == "/OCI/Process/Env" and isinstance(expected, dict):
                        actual = key_values(actual)
                        matched = all(
                            actual.get(name) == value for name, value in expected.items()
                        )
                    else:
                        matched = actual == expected
                except (IndexError, KeyError, TypeError, ValueError):
                    actual = None
                    matched = False
            checks.append(
                {
                    "actual": actual,
                    "expected": expected,
                    "matched": matched,
                    "path": path,
                    "subject": subject,
                }
            )
    return {
        "checks": checks,
        "matched": sum(check["matched"] for check in checks),
        "result": "pass" if all(check["matched"] for check in checks) else "fail",
        "total": len(checks),
    }


def settings_comparison(settings: dict, *policies: dict) -> dict:
    fields = ("common", "sandbox", "request_defaults", "devices", "cluster_config")
    checks = []
    for field in fields:
        if field not in settings:
            continue
        checks.append(
            {
                "field": field,
                "matches": [policy.get(field) == settings[field] for policy in policies],
            }
        )
    return {
        "checks": checks,
        "direct_settings_fields": len(checks),
        "leaf_coverage": [settings_leaf_coverage(settings, policy) for policy in policies],
    }


def leaf_values(value, path=""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaf_values(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaf_values(child, f"{path}/{index}")
    else:
        yield path or "/", value


def settings_leaf_coverage(settings: dict, policy: dict) -> dict:
    fields = ("common", "sandbox", "request_defaults", "devices", "cluster_config")
    results = []
    for field in fields:
        for relative_path, expected in leaf_values(settings.get(field, {})):
            path = f"/{field}{relative_path}"
            try:
                actual = pointer_value(policy, path)
                status = "matched" if actual == expected else "changed"
            except (KeyError, IndexError, TypeError, ValueError):
                actual = None
                status = "not-serialized"
            results.append(
                {"actual": actual, "expected": expected, "path": path, "status": status}
            )
    return {
        "changed": sum(result["status"] == "changed" for result in results),
        "matched": sum(result["status"] == "matched" for result in results),
        "not_serialized": sum(
            result["status"] == "not-serialized" for result in results
        ),
        "results": results,
        "total": len(results),
    }


def mutation_layers(provenance: dict, transformations: dict) -> dict:
    layer_for_stage = {
        "image-config": "static",
        "yaml-declared": "static",
        "kubernetes-resolution": "kubelet-or-containerd",
        "cri-generation": "kubelet-or-containerd",
        "post-raw-oci": "runtime-rs",
    }
    layers = {}
    for entry in provenance["entries"]:
        stage = entry.get("stage", "unknown")
        layer = layer_for_stage.get(stage, "unclassified")
        layers.setdefault(layer, {"entries": 0, "stages": {}})
        layers[layer]["entries"] += 1
        layers[layer]["stages"][stage] = layers[layer]["stages"].get(stage, 0) + 1
    runtime_changes = [
        change
        for request in transformations["requests"]
        for change in request["changes"]
    ]
    layers.setdefault("runtime-rs", {"entries": 0, "stages": {}})[
        "observed_transformations"
    ] = len(runtime_changes)
    return layers


def profile_layer(baseline: Path, candidate: Path) -> dict:
    comparison = profile_comparison.compare(baseline, candidate)
    dimensions = comparison["profile_delta"]["dimensions"]
    paths = {dimension["path"] for dimension in dimensions}
    containerd_dimensions = {
        "/configuration_hashes/containerd.toml",
        "/values/CONTAINERD_CONFIG",
        "/values/CONTAINERD_VERSION",
        "/values/PROFILE_NAME",
    }
    residual = [
        change
        for request in comparison["requests"]
        for change in request.get("normalized_changes", [])
    ]
    controlled = bool(paths) and paths <= containerd_dimensions
    return {
        "attributed_category": "containerd-oci" if controlled else None,
        "attribution_status": "component-family" if controlled else "confounded",
        "dimensions": dimensions,
        "residual_changes_by_section": {
            section: sum(change["section"] == section for change in residual)
            for section in sorted({change["section"] for change in residual})
        },
        "static_inputs_equal": comparison["profile_delta"]["static_inputs_equal"],
        "warning": (
            "Residual changes still include generated identities and require typed correlation "
            "before becoming fragment claims."
        ),
    }


def analyze(
    capture: Path,
    legacy_policy_path: Path,
    compiler_policy_path: Path,
    settings_path: Path | None = None,
    settings_patches: list[Path] | None = None,
    baseline_capture: Path | None = None,
    kata_config: Path | None = None,
    uvm_baseline: Path | None = None,
    rootfs_artifacts_path: Path | None = None,
) -> dict:
    static_ir = generate_static_ir(capture, uvm_baseline, rootfs_artifacts_path)
    legacy = policy_data(legacy_policy_path)
    compiler = policy_data(compiler_policy_path)
    transformations, provenance = request_provenance.analyze(capture)
    stages = {}
    for entry in provenance["entries"]:
        stage = entry.get("stage", "unknown")
        stages[stage] = stages.get(stage, 0) + 1
    report = {
        "capture_profile": json.loads((capture / "profile.json").read_text(encoding="utf-8"))[
            "identity"
        ],
        "compiler": compare_static(static_ir, compiler),
        "legacy": compare_static(static_ir, legacy),
        "capture_evidence": {
            "layers": mutation_layers(provenance, transformations),
            "paired_requests": sum(
                request["status"] == "paired" for request in transformations["requests"]
            ),
            "provenance_entries_by_stage": dict(sorted(stages.items())),
            "transformation_count": sum(
                len(request["changes"]) for request in transformations["requests"]
            ),
        },
        "schema_version": 1,
        "static_ir": static_ir,
    }
    if settings_path is not None:
        settings = merged_settings(settings_path, settings_patches or [])
        if kata_config is not None:
            import tomllib

            with kata_config.open("rb") as source:
                derived = settings_derivation.derive_settings(tomllib.load(source))
                apply_settings_patch(settings, derived)
        report["legacy_settings"] = settings_comparison(settings, legacy, compiler)
    if baseline_capture is not None:
        report["profile_layer"] = profile_layer(baseline_capture, capture)
    report["result"] = (
        "pass"
        if report["legacy"]["result"] == "pass" and report["compiler"]["result"] == "pass"
        else "fail"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--legacy-policy", required=True, type=Path)
    parser.add_argument("--compiler-policy", required=True, type=Path)
    parser.add_argument("--settings", type=Path)
    parser.add_argument("--settings-patch", action="append", default=[], type=Path)
    parser.add_argument("--baseline-capture", type=Path)
    parser.add_argument("--kata-config", type=Path)
    parser.add_argument("--uvm-baseline", type=Path)
    parser.add_argument("--rootfs-artifacts", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = analyze(
        args.capture,
        args.legacy_policy,
        args.compiler_policy,
        args.settings,
        args.settings_patch,
        args.baseline_capture,
        args.kata_config,
        args.uvm_baseline,
        args.rootfs_artifacts,
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if report["result"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
