#!/usr/bin/env python3

import argparse
import gzip
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


def service_account_intent(spec: dict) -> dict:
    automount = spec.get("automountServiceAccountToken")
    if automount is not False:
        raise ValueError(
            "automountServiceAccountToken must be explicitly false for Kata-CC policy generation"
        )
    name = spec.get("serviceAccountName", "default")
    if not isinstance(name, str) or not name:
        raise ValueError("serviceAccountName must be a non-empty string")
    return {"automount_token": False, "name": name}


def share_process_namespace_intent(spec: dict) -> bool:
    shared = spec.get("shareProcessNamespace", False)
    if not isinstance(shared, bool):
        raise ValueError("shareProcessNamespace must be a boolean")
    return shared


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


def verified_image_document(images_dir: Path, path: str, digest: str) -> dict:
    raw = (images_dir / path).read_bytes()
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != digest:
        raise ValueError(f"image content digest mismatch: expected {digest}, got {actual}")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"image content is not an object: {digest}")
    return value


def verified_layer_diff_id(raw: bytes, media_type: str) -> str:
    if media_type.endswith("+gzip") or media_type.endswith(".gzip"):
        raw = gzip.decompress(raw)
    elif not media_type.endswith(".tar"):
        raise ValueError(f"unsupported verified layer media type: {media_type}")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def verify_image_descriptor(images_dir: Path, reference: str, descriptor: dict) -> dict:
    requested_digest = image_manifest_digest(reference)
    if descriptor.get("requested_digest") != requested_digest:
        raise ValueError(f"verified image request digest mismatch: {reference}")
    requested = verified_image_document(
        images_dir, descriptor["requested_path"], requested_digest
    )
    manifest_digest = descriptor["manifest_digest"]
    manifest = verified_image_document(
        images_dir, descriptor["manifest_path"], manifest_digest
    )
    if requested_digest != manifest_digest and not any(
        item.get("digest") == manifest_digest for item in requested.get("manifests", [])
    ):
        raise ValueError(f"selected manifest is not bound to image index: {reference}")
    config_digest = descriptor["config_digest"]
    config = verified_image_document(
        images_dir, descriptor["config_path"], config_digest
    )
    if (manifest.get("config") or {}).get("digest") != config_digest:
        raise ValueError(f"image config is not bound to manifest: {reference}")
    manifest_layers = manifest.get("layers", [])
    layers = descriptor.get("layers", [])
    diff_ids = (config.get("rootfs") or {}).get("diff_ids", [])
    if len(manifest_layers) != len(layers) or len(layers) != len(diff_ids):
        raise ValueError(f"verified image layer chain is incomplete: {reference}")
    for manifest_layer, layer, diff_id in zip(
        manifest_layers, layers, diff_ids, strict=True
    ):
        if manifest_layer.get("digest") != layer.get("digest"):
            raise ValueError(f"image layer is not bound to manifest: {reference}")
        raw = (images_dir / layer["path"]).read_bytes()
        actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual_digest != layer["digest"]:
            raise ValueError(
                f"image layer digest mismatch: expected {layer['digest']}, got {actual_digest}"
            )
        actual_diff_id = verified_layer_diff_id(raw, layer["media_type"])
        if actual_diff_id != diff_id or layer.get("diff_id") != diff_id:
            raise ValueError(f"image layer diff-id mismatch: {reference}")
    return config.get("config") or {}


def image_configs(capture: Path) -> dict[str, dict]:
    images_dir = capture / "images"
    index = json.loads((images_dir / "index.json").read_text(encoding="utf-8"))
    result = {}
    for reference, descriptor in index["images"].items():
        if index.get("schema_version") == 1:
            result[reference] = verify_image_descriptor(
                images_dir, reference, descriptor
            )
            continue
        document = json.loads(
            (images_dir / descriptor["config_path"]).read_text(encoding="utf-8")
        )
        result[reference] = document.get("config") or {}
    return result


def image_manifest_digest(reference: str) -> str:
    _, separator, digest = reference.rpartition("@")
    if not separator or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ValueError(f"static image is not digest-bound to a sha256 manifest: {reference}")
    return digest


def image_user_databases(capture: Path) -> dict[str, dict[str, str]]:
    """Return the per-image user and group database recorded by the capture.

    The database is bound to the same manifest digest that pins the rootfs, so
    the UID a container runs as is decided by the measured image rather than by
    whatever the host resolved at admission time.
    """
    images_dir = capture / "images"
    index = json.loads((images_dir / "index.json").read_text(encoding="utf-8"))
    return {
        reference: descriptor.get("user_database") or {}
        for reference, descriptor in index["images"].items()
    }


def parse_passwd_database(content: str) -> list[dict]:
    accounts = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            raise ValueError("image /etc/passwd entry has too few fields")
        accounts.append(
            {"name": fields[0], "uid": int(fields[2]), "gid": int(fields[3])}
        )
    return accounts


def parse_group_database(content: str) -> list[dict]:
    groups = []
    for line in content.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 3:
            raise ValueError("image /etc/group entry has too few fields")
        members = fields[3] if len(fields) > 3 else ""
        groups.append(
            {
                "name": fields[0],
                "gid": int(fields[2]),
                "members": [member for member in members.split(",") if member],
            }
        )
    return groups


def image_user_identity(image_user: str, accounts: list[dict], groups: list[dict]):
    """Resolve the image config User field to a UID, GID, and account name.

    Mirrors containerd's oci.WithUser: an empty field means uid 0, a numeric
    field selects by UID, and anything else selects by account name. The
    optional group half overrides the account's primary GID.
    """
    user_part, separator, group_part = image_user.partition(":")
    if user_part == "":
        selected = [account for account in accounts if account["uid"] == 0]
    elif user_part.isdigit():
        selected = [account for account in accounts if account["uid"] == int(user_part)]
    else:
        selected = [account for account in accounts if account["name"] == user_part]
    if len(selected) > 1:
        raise ValueError(f"image user is ambiguous in /etc/passwd: {image_user!r}")
    if not selected:
        if user_part.isdigit():
            # An unmatched numeric user carries no account name, so it inherits
            # no group memberships.
            return int(user_part), 0, ""
        raise ValueError(f"image user has no /etc/passwd entry: {image_user!r}")
    account = selected[0]
    gid = account["gid"]
    if separator:
        if group_part.isdigit():
            gid = int(group_part)
        else:
            matches = [group for group in groups if group["name"] == group_part]
            if len(matches) != 1:
                raise ValueError(f"image group has no /etc/group entry: {image_user!r}")
            gid = matches[0]["gid"]
    return account["uid"], gid, account["name"]


def container_user_intent(spec: dict, container: dict, image: dict, database: dict) -> dict:
    """Derive the OCI process user from the image database and typed intent."""
    if not isinstance(database, dict) or "passwd" not in database or "group" not in database:
        raise ValueError(
            "capture has no digest-bound image user and group database for this image"
        )
    accounts = parse_passwd_database(database["passwd"])
    groups = parse_group_database(database["group"])

    image_user = image.get("User") or ""
    if not isinstance(image_user, str):
        raise ValueError("image config User must be a string")
    uid, gid, account_name = image_user_identity(image_user, accounts, groups)

    pod_security = spec.get("securityContext") or {}
    container_security = container.get("securityContext") or {}
    run_as_user = container_security.get("runAsUser", pod_security.get("runAsUser"))
    if run_as_user is not None:
        if not isinstance(run_as_user, int) or isinstance(run_as_user, bool):
            raise ValueError("runAsUser must be an integer")
        uid = run_as_user
        # Group membership follows the account the numeric UID resolves to.
        matches = [account for account in accounts if account["uid"] == uid]
        if len(matches) > 1:
            raise ValueError(f"runAsUser {uid} is ambiguous in /etc/passwd")
        account_name = matches[0]["name"] if matches else ""
        gid = matches[0]["gid"] if matches else 0
    run_as_group = container_security.get("runAsGroup", pod_security.get("runAsGroup"))
    if run_as_group is not None:
        if not isinstance(run_as_group, int) or isinstance(run_as_group, bool):
            raise ValueError("runAsGroup must be an integer")
        gid = run_as_group

    # containerd lists the primary GID first, then the memberships it finds in
    # /etc/group in file order, and the kubelet appends supplementalGroups.
    additional_gids = [gid]
    for group in groups:
        if account_name and account_name in group["members"]:
            additional_gids.append(group["gid"])
    for supplemental in pod_security.get("supplementalGroups") or []:
        if not isinstance(supplemental, int) or isinstance(supplemental, bool):
            raise ValueError("supplementalGroups entries must be integers")
        additional_gids.append(supplemental)
    deduplicated = list(dict.fromkeys(additional_gids))

    return {
        "/OCI/Process/User/AdditionalGids": deduplicated,
        "/OCI/Process/User/GID": gid,
        "/OCI/Process/User/UID": uid,
        # Username is a Windows-only field of the OCI process user.
        "/OCI/Process/User/Username": "",
    }


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
    mode: str,
    artifacts: dict[str, dict],
    artifact_manifest_digest: str | None,
) -> dict:
    manifest_digest = image_manifest_digest(image_reference)
    plan = {
        "image_manifest_digest": manifest_digest,
        "mode": mode,
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
    raise ValueError(f"unsupported rootfs mode: {mode}")


def rootfs_identity_storage(rootfs: dict) -> dict:
    if rootfs["mode"] == "guest-pull":
        driver = "guest-pull-images"
        identity = rootfs["image_manifest_digest"]
    else:
        driver = "dmverity-roothashes"
        identity = rootfs["dm_verity_root_hash"]
    return {
        "driver": driver,
        "driver_options": [],
        "source": "",
        "fstype": "",
        "options": [identity],
        "mount_point": "",
        "fs_group": None,
        "shared": False,
    }


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


FIELD_REF_VALUES = {
    "metadata.name": "$(sandbox-name)",
    "metadata.uid": "$(pod-uid)",
    "spec.nodeName": "$(node-name)",
}


def environment_value_from(
    name: str,
    value_from: dict,
    namespace: str,
    service_account_name: str,
    config_maps: dict,
    secrets: dict,
) -> tuple[str | None, dict | None]:
    if not isinstance(value_from, dict) or len(value_from) != 1:
        raise ValueError(f"environment {name} valueFrom requires exactly one source")
    kind, reference = next(iter(value_from.items()))
    if not isinstance(reference, dict):
        raise ValueError(f"environment {name} {kind} must be an object")
    if kind == "fieldRef":
        unknown = set(reference) - {"apiVersion", "fieldPath"}
        api_version = reference.get("apiVersion", "v1")
        field_path = reference.get("fieldPath")
        if unknown or api_version != "v1" or not isinstance(field_path, str):
            raise ValueError(f"environment {name} has invalid fieldRef")
        if field_path == "metadata.namespace":
            value = namespace
        elif field_path == "spec.serviceAccountName":
            return service_account_name, None
        else:
            value = FIELD_REF_VALUES.get(field_path)
        if value is None:
            raise ValueError(
                f"environment {name} has unsupported fieldRef path: {field_path}"
            )
        return None, {
            "owner": "kubelet-resolution",
            "source": {
                "api_version": api_version,
                "field_path": field_path,
                "kind": "field-ref",
            },
            "target": {
                "collection": "environment",
                "name": name,
                "path": f"/OCI/Process/Env/{name}",
            },
            "value": value,
            "value_type": "string",
        }
    if kind not in {"configMapKeyRef", "secretKeyRef"}:
        raise ValueError(f"environment {name} has unsupported valueFrom source: {kind}")
    unknown = set(reference) - {"key", "name", "optional"}
    object_name = reference.get("name")
    key = reference.get("key")
    optional = reference.get("optional", False)
    if (
        unknown
        or not isinstance(object_name, str)
        or not object_name
        or not isinstance(key, str)
        or not key
        or not isinstance(optional, bool)
    ):
        raise ValueError(f"environment {name} has invalid {kind}")
    objects = config_maps if kind == "configMapKeyRef" else secrets
    values = objects.get((namespace, object_name))
    if values is None or key not in values:
        if optional:
            return None, None
        raise ValueError(
            f"required environment {kind} is missing: {namespace}/{object_name}/{key}"
        )
    return values[key], None


def static_environment(
    container: dict,
    image: dict,
    namespace: str,
    service_account_name: str,
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
    resolutions = []
    for entry in container.get("env") or []:
        if not isinstance(entry, dict):
            raise ValueError("environment entry must be an object")
        name = entry.get("name", "")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise ValueError(f"invalid environment name: {name}")
        if ("value" in entry) == ("valueFrom" in entry):
            raise ValueError(f"environment {name} requires exactly one value or valueFrom")
        if "value" in entry:
            environment[name] = str(entry["value"])
            evidence.append({"field": f"env/{name}", "source": "workload-yaml"})
        else:
            value, resolution = environment_value_from(
                name,
                entry["valueFrom"],
                namespace,
                service_account_name,
                config_maps,
                secrets,
            )
            if value is not None:
                environment[name] = value
                evidence.append(
                    {"field": f"env/{name}", "source": "trusted-workload-object"}
                )
            if resolution is not None:
                resolutions.append(resolution)
    return environment, resolutions, env_from


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


def extended_resource_requests(container: dict) -> list[dict]:
    limits = ((container.get("resources") or {}).get("limits") or {})
    if not isinstance(limits, dict):
        raise ValueError("container resource limits must be an object")
    requests = []
    for resource, quantity in sorted(limits.items()):
        if "/" not in resource:
            continue
        if resource not in {"nvidia.com/gpu", "nvidia.com/pgpu"}:
            raise ValueError(
                f"extended resource has no reviewed UVM device profile: {resource}"
            )
        value = str(quantity)
        if re.fullmatch(r"[0-9]+", value) is None:
            raise ValueError(
                f"extended resource limit must be a non-negative integer: {resource}={value}"
            )
        requests.append(
            {
                "count": int(value),
                "resource": resource,
                "resolution": "device-profile",
            }
        )
    return requests


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
    if kind == "downwardAPI":
        raise ValueError(
            "Downward API projected volume content is incompatible with the Kata-CC threat model"
        )
    if kind == "serviceAccountToken":
        raise ValueError(
            "serviceAccountToken projected volume is unsupported without trusted in-guest token verification"
        )
    value = copy.deepcopy(source[kind])
    if not isinstance(value, dict):
        raise ValueError(f"invalid projected volume source: {kind}")
    if kind in {"configMap", "secret"}:
        name = value.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"projected {kind} source requires a name")
        value["namespace"] = namespace
        value["content_trust"] = "untrusted-runtime"
    roles = {
        "configMap": "config-map",
        "downwardAPI": "downward-api",
        "secret": "secret",
    }
    return {"role": roles[kind], "source": value}


def volume_source(
    volume: dict,
    namespace: str,
) -> dict:
    if not isinstance(volume, dict):
        raise ValueError("volume declaration must be an object")
    kinds = [
        kind
        for kind in (
            "emptyDir",
            "configMap",
            "secret",
            "downwardAPI",
            "projected",
            "hostPath",
            "persistentVolumeClaim",
            "csi",
        )
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
        role = "config-map" if kind == "configMap" else "secret"
        source["name"] = source.pop(name_field)
        source["namespace"] = namespace
        source["content_trust"] = "untrusted-runtime"
        return {"role": role, "source": source}
    if kind == "downwardAPI":
        raise ValueError(
            "Downward API volume content is incompatible with the Kata-CC threat model"
        )
    if kind == "hostPath":
        path = source.get("path")
        source_type = source.get("type", "")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("hostPath volume requires an absolute path")
        if source_type not in {"", "Directory", "DirectoryOrCreate"}:
            raise ValueError(
                f"hostPath type {source_type or '<unset>'} has no reviewed UVM volume profile"
            )
        return {
            "role": "direct-volume",
            "uvm": {
                "content_trust": "untrusted-runtime",
                "transport": "shared-fs",
            },
        }
    if kind == "persistentVolumeClaim":
        raise ValueError(
            "mounted persistentVolumeClaim has no reviewed UVM volume profile"
        )
    if kind == "csi":
        raise ValueError("mounted CSI volume has no reviewed UVM volume profile")
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
) -> list[dict]:
    volumes = {}
    for volume in spec.get("volumes") or []:
        name = volume.get("name")
        if not isinstance(name, str) or not name or name in volumes:
            raise ValueError(f"invalid or duplicate volume name: {name}")
        volumes[name] = volume
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
            **volume_source(volumes[name], namespace),
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


def container_volume_device_intents(spec: dict, container: dict, namespace: str) -> list[dict]:
    volumes = {}
    for volume in spec.get("volumes") or []:
        name = volume.get("name")
        if not isinstance(name, str) or not name or name in volumes:
            raise ValueError(f"invalid or duplicate volume name: {name}")
        volumes[name] = volume
    intents = []
    names = set()
    paths = set()
    for device in container.get("volumeDevices") or []:
        if not isinstance(device, dict) or set(device) != {"devicePath", "name"}:
            raise ValueError("volumeDevice requires exactly name and devicePath")
        name = device["name"]
        device_path = device["devicePath"]
        if name not in volumes:
            raise ValueError(f"volumeDevice references undeclared volume: {name}")
        if not isinstance(device_path, str) or not device_path.startswith("/"):
            raise ValueError(f"volumeDevice requires an absolute devicePath: {name}")
        if name in names or device_path in paths:
            raise ValueError(f"duplicate volumeDevice name or path: {name}")
        volume = volumes[name]
        if "persistentVolumeClaim" not in volume:
            raise ValueError(
                f"volumeDevice {name} has no reviewed UVM block-device profile"
            )
        intents.append(
            {
                "device_path": device_path,
                "name": name,
                "resolution": "uvm-device",
            }
        )
        names.add(name)
        paths.add(device_path)
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
    *,
    rootfs_mode: str = "guest-pull",
    uvm_baseline_path: Path | None = None,
    rootfs_artifacts_path: Path | None = None,
) -> dict:
    documents = workload_documents(capture / "workload.yaml")
    config_maps, secrets = trusted_objects(documents)
    services = trusted_services(documents)
    images = image_configs(capture)
    user_databases = image_user_databases(capture)
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
        service_account = service_account_intent(spec)
        share_process_namespace = share_process_namespace_intent(spec)
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
            environment, environment_resolutions, env_from = static_environment(
                container,
                image,
                namespace,
                service_account["name"],
                config_maps,
                secrets,
            )
            constraints = {
                "/OCI/Annotations/io.kubernetes.cri.container-name": container["name"],
                "/OCI/Process/Args": process_args(container, image),
                "/OCI/Process/Env": environment,
                "/exec_commands": exec_commands(container),
                "/sandbox_pidns": share_process_namespace,
                **container_user_intent(
                    spec, container, image, user_databases.get(image_reference, {})
                ),
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
                "environment_resolutions": environment_resolutions,
                "env_from": env_from,
                "device_requests": {
                    "extended_resources": extended_resource_requests(container),
                    "volume_devices": container_volume_device_intents(
                        spec, container, namespace
                    ),
                },
                "image": image_reference,
                "namespace": namespace,
                "service_account": copy.deepcopy(service_account),
                "service_links_enabled": spec.get("enableServiceLinks", True),
                "subject": f"container/{container['name']}",
                "volumes": container_volume_intents(
                    spec, container, namespace
                ),
                "workload": {"kind": document["kind"], "name": workload_name},
            }
            rootfs = rootfs_plan(
                image_reference,
                rootfs_mode,
                artifacts,
                artifact_manifest_digest,
            )
            subject["rootfs"] = rootfs
            subject["rootfs_identity_storage"] = rootfs_identity_storage(rootfs)
            subjects.append(subject)
        if uvm_baseline is not None:
            subjects.append(
                {
                    # The pause container is never placed in the shared PID
                    # namespace, whatever the Pod declares.
                    "constraints": {
                        **copy.deepcopy(uvm_baseline["constraints"]),
                        "/sandbox_pidns": False,
                    },
                    "namespace": namespace,
                    "static_artifact": uvm_baseline["artifact_digest"],
                    "subject": f"sandbox/{namespace}/{workload_name}",
                    "environment_resolutions": [],
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
        "rootfs_mode": rootfs_mode,
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
            environment = constraints["/OCI/Process/Env"]
            process["Env"] = (
                [f"{name}={value}" for name, value in sorted(environment.items())]
                if isinstance(environment, dict)
                else list(environment)
            )
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
        "rootfs_mode": ir["rootfs_mode"],
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
    rootfs_mode: str,
    legacy_policy_path: Path,
    compiler_policy_path: Path,
    settings_path: Path | None = None,
    settings_patches: list[Path] | None = None,
    baseline_capture: Path | None = None,
    kata_config: Path | None = None,
    uvm_baseline: Path | None = None,
    rootfs_artifacts_path: Path | None = None,
) -> dict:
    static_ir = generate_static_ir(
        capture,
        rootfs_mode=rootfs_mode,
        uvm_baseline_path=uvm_baseline,
        rootfs_artifacts_path=rootfs_artifacts_path,
    )
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
    parser.add_argument(
        "--rootfs-mode",
        required=True,
        choices=("guest-pull", "erofs-dmverity"),
    )
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
        args.rootfs_mode,
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
