#!/usr/bin/env python3

import argparse
import json
import re
import tomllib
from collections import Counter
from pathlib import Path

import yaml


COPIED_FILE = re.compile(
    r"^/run/kata-containers/shared/containers/[^/]+-[0-9a-f]{16}-[^/]+$"
)
WATCHABLE = re.compile(
    r"^/run/kata-containers/shared/containers/(?:passthrough/)?watchable/"
    r"sandbox-[0-9a-f]{8}-.+$"
)
SHARED_VOLUME = re.compile(
    r"^/run/kata-containers/shared/containers/(?:passthrough/)?"
    r"sandbox-[0-9a-f]{8}-.+$"
)
BLOCK_DRIVERS = {"blk", "blk-ccw", "mmioblk", "nvdimm", "scsi"}


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


def workload_facts(path: Path) -> dict:
    containers = {}
    volume_types = Counter()
    env_from = Counter()
    with path.open(encoding="utf-8") as source:
        for document in yaml.safe_load_all(source):
            if not isinstance(document, dict):
                continue
            for spec in pod_specs(document):
                volumes = {}
                for volume in spec.get("volumes", []):
                    volume_type = next(
                        (key for key in volume if key not in {"name"}), "unknown"
                    )
                    volumes[volume.get("name", "")] = volume_type
                    volume_types[volume_type] += 1
                for field in ("initContainers", "containers", "ephemeralContainers"):
                    for container in spec.get(field, []):
                        name = container.get("name", "")
                        mounts = {
                            mount.get("mountPath", ""): {
                                "name": mount.get("name", ""),
                                "type": volumes.get(mount.get("name", ""), "unknown"),
                            }
                            for mount in container.get("volumeMounts", [])
                        }
                        devices = {
                            device.get("devicePath", ""): device.get("name", "")
                            for device in container.get("volumeDevices", [])
                        }
                        containers[name] = {"devices": devices, "mounts": mounts}
                        for entry in container.get("envFrom", []):
                            if "configMapRef" in entry:
                                env_from["configMap"] += 1
                            if "secretRef" in entry:
                                env_from["secret"] += 1
    return {
        "containers": containers,
        "env_from": dict(sorted(env_from.items())),
        "volume_types": dict(sorted(volume_types.items())),
    }


def runtime_facts(capture: Path) -> dict:
    path = capture / "config" / "kata-configuration.toml"
    if not path.is_file():
        return {"kata_configuration": None, "shared_fs": None}
    with path.open("rb") as source:
        configuration = tomllib.load(source)
    runtime = configuration.get("runtime", {})
    hypervisor_name = runtime.get("hypervisor_name")
    hypervisor = configuration.get("hypervisor", {}).get(hypervisor_name, {})
    return {
        "hypervisor_name": hypervisor_name,
        "kata_configuration": path.relative_to(capture).as_posix(),
        "shared_fs": hypervisor.get("shared_fs"),
    }


def evidence(artifact: str, pointer: str, container: str = "") -> dict:
    result = {"artifact": artifact, "pointer": pointer}
    if container:
        result["container"] = container
    return result


def rootfs_storage(storage: dict, root_path: str) -> bool:
    if storage.get("mount_point") == root_path:
        return True
    options = storage.get("options") or []
    return any(
        option.startswith("X-kata.dmverity.")
        or option.startswith("X-kata.multi-layer=")
        or option in {"X-kata.overlay-lower", "X-kata.overlay-upper"}
        for option in options
    )


def storage_class(storage: dict, is_rootfs: bool) -> str:
    options = storage.get("options") or []
    driver_options = storage.get("driver_options") or []
    driver = storage.get("driver") or "unknown"
    fs_type = storage.get("fs_type") or storage.get("fstype") or "unknown"
    if is_rootfs and storage.get("driver") == "image_guest_pull":
        return "rootfs-guest-pull"
    if is_rootfs and "X-kata.overlay-lower" in options:
        valid = (
            "ro" in options
            and "X-kata.dmverity-enabled=true" in options
            and any(o.startswith("X-kata.dmverity.roothash=") for o in options)
        )
        return "rootfs-erofs-lower" if valid else "rootfs-erofs-lower-invalid"
    if is_rootfs and "X-kata.overlay-upper" in options:
        return "rootfs-overlay-upper" if "rw" in options else "rootfs-overlay-upper-invalid"
    if is_rootfs and any(o.startswith("X-kata.dmverity.") for o in options):
        valid = (
            "ro" in options
            and "X-kata.dmverity-enabled=true" in options
            and any(o.startswith("X-kata.dmverity.roothash=") for o in options)
        )
        return "rootfs-dmverity-block" if valid else "rootfs-dmverity-block-invalid"
    if is_rootfs and driver == "overlayfs" and fs_type == "overlay":
        return "rootfs-nydus-overlay"
    if is_rootfs and driver in BLOCK_DRIVERS:
        return "rootfs-unprotected-block"
    if is_rootfs:
        return "rootfs-unsupported"
    if storage.get("driver") == "watchable-bind":
        return "volume-watchable-bind"
    if {
        "encryption_key=ephemeral",
        "create_filesystem",
    }.issubset(driver_options):
        return "volume-block-encrypted-emptydir"
    if "create_filesystem" in driver_options:
        return "volume-block-emptydir"
    if fs_type in {"tmpfs", "local", "hugetlbfs"}:
        return f"volume-{fs_type}"
    if driver in BLOCK_DRIVERS:
        return "volume-block-device"
    return "volume-unsupported"


def mount_class(mount: dict, declaration: dict | None) -> str:
    destination = mount.get("destination", "")
    source = mount.get("source", "")
    if destination == "/dev/shm":
        return (
            "uvm-dev-shm"
            if source == "/run/kata-containers/sandbox/shm"
            else "uvm-dev-shm-unexpected"
        )
    if WATCHABLE.fullmatch(source):
        return "volume-watchable"
    if declaration and SHARED_VOLUME.fullmatch(source):
        return f"volume-shared-{declaration['type']}"
    if SHARED_VOLUME.fullmatch(source):
        return "volume-shared-undeclared"
    if declaration and COPIED_FILE.fullmatch(source):
        return f"volume-copy-{declaration['type']}"
    if COPIED_FILE.fullmatch(source):
        return "kubernetes-generated-file"
    return "other"


def device_class(device: dict) -> str:
    device_type = (
        device.get("field_type") or device.get("type") or device.get("type_") or ""
    )
    if device_type.startswith("vfio"):
        return "agent-device-vfio"
    if device_type in BLOCK_DRIVERS or device_type == "block":
        return "agent-device-block"
    return "agent-device-other"


def claim(identifier: str, text: str, status: str, proof: list[dict]) -> dict:
    return {"claim": text, "evidence": proof, "id": identifier, "status": status}


def analyze(capture: Path) -> dict:
    manifest = json.loads((capture / "manifest.json").read_text(encoding="utf-8"))
    capture_metadata = manifest.get("capture", {})
    authority = capture_metadata.get("request_authority", "unknown")
    authoritative = authority == "recording-agent"
    workload = workload_facts(capture / "workload.yaml")
    runtime = runtime_facts(capture)
    storage_counts = Counter()
    mount_counts = Counter()
    device_count = 0
    observed = {}

    def record(kind: str, proof: dict):
        observed.setdefault(kind, []).append(proof)

    request_files = sorted((capture / "createcontainer-requests").glob("*.json"))
    for request_path in request_files:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        oci = request.get("oci") or {}
        annotations = oci.get("annotations") or {}
        container = annotations.get("io.kubernetes.cri.container-name", "sandbox")
        root_path = (oci.get("root") or {}).get("path", "")
        relative = request_path.relative_to(capture).as_posix()
        declarations = workload["containers"].get(container, {}).get("mounts", {})
        for index, storage in enumerate(request.get("storages") or []):
            kind = storage_class(storage, rootfs_storage(storage, root_path))
            storage_counts[kind] += 1
            record(kind, evidence(relative, f"/storages/{index}", container))
        for index, mount in enumerate(oci.get("mounts") or []):
            kind = mount_class(mount, declarations.get(mount.get("destination", "")))
            mount_counts[kind] += 1
            if kind != "other":
                record(kind, evidence(relative, f"/oci/mounts/{index}", container))
        devices = request.get("devices") or []
        device_count += len(devices)
        for index, device in enumerate(devices):
            kind = device_class(device)
            record(kind, evidence(relative, f"/devices/{index}", container))

    def status(kind: str) -> str:
        if not authoritative:
            return "not-authoritative"
        return "confirmed" if kind in observed else "not-exercised"

    def status_any(kinds: tuple[str, ...]) -> str:
        if not authoritative:
            return "not-authoritative"
        return "confirmed" if any(kind in observed for kind in kinds) else "not-exercised"

    claims = [
        claim(
            "guest-pull-rootfs",
            "Guest-pull rootfs is represented by image_guest_pull storage at the OCI root path.",
            status("rootfs-guest-pull"),
            observed.get("rootfs-guest-pull", []),
        ),
        claim(
            "erofs-overlay-rootfs",
            "EROFS multi-layer rootfs has a writable overlay upper and a read-only dm-verity lower.",
            "not-authoritative"
            if not authoritative
            else (
                "confirmed"
                if "rootfs-erofs-lower" in observed and "rootfs-overlay-upper" in observed
                else "not-exercised"
            ),
            observed.get("rootfs-erofs-lower", [])
            + observed.get("rootfs-overlay-upper", []),
        ),
        claim(
            "single-layer-dmverity-rootfs",
            "A single-layer block rootfs carries an enabled dm-verity root hash.",
            status("rootfs-dmverity-block"),
            observed.get("rootfs-dmverity-block", []),
        ),
        claim(
            "unsupported-rootfs-storage",
            "The final request contains a Nydus, unprotected block, or otherwise unsupported rootfs storage.",
            status_any(
                (
                    "rootfs-nydus-overlay",
                    "rootfs-unprotected-block",
                    "rootfs-unsupported",
                )
            ),
            [
                proof
                for kind in (
                    "rootfs-nydus-overlay",
                    "rootfs-unprotected-block",
                    "rootfs-unsupported",
                )
                for proof in observed.get(kind, [])
            ],
        ),
        claim(
            "kubernetes-generated-files",
            "Kubernetes-generated files are rewritten below the Kata shared container directory.",
            status("kubernetes-generated-file"),
            observed.get("kubernetes-generated-file", []),
        ),
        claim(
            "uvm-dev-shm",
            "/dev/shm is a UVM-local bind mount from /run/kata-containers/sandbox/shm.",
            status("uvm-dev-shm"),
            observed.get("uvm-dev-shm", []),
        ),
        claim(
            "shared-fs-none-volume-copy",
            "With shared_fs=none, a declared projected volume mount is copied to a generated guest path without Agent storage.",
            (
                "not-authoritative"
                if not authoritative
                else "not-exercised"
                if not any(
                    f"volume-copy-{kind}" in observed
                    for kind in ("configMap", "secret", "projected", "downwardAPI")
                )
                else "confirmed"
                if runtime["shared_fs"] == "none"
                else "configuration-unverified"
                if runtime["shared_fs"] is None
                else "contradicted"
            ),
            [
                proof
                for kind in ("configMap", "secret", "projected", "downwardAPI")
                for proof in observed.get(f"volume-copy-{kind}", [])
            ],
        ),
        claim(
            "shared-fs-none-hostpath-copy",
            "With shared_fs=none, a declared hostPath directory may be copied to a generated guest path instead of becoming Agent storage.",
            status("volume-copy-hostPath"),
            observed.get("volume-copy-hostPath", []),
        ),
        claim(
            "virtiofs-watchable-volume",
            "A watchable virtio-fs volume has a watchable-bind storage and watchable guest mount source.",
            "not-authoritative"
            if not authoritative
            else (
                "confirmed"
                if "volume-watchable-bind" in observed and "volume-watchable" in observed
                else "not-exercised"
            ),
            observed.get("volume-watchable-bind", [])
            + observed.get("volume-watchable", []),
        ),
        claim(
            "virtiofs-shared-volume",
            "A non-watchable virtio-fs volume is represented by a rewritten shared-filesystem OCI bind mount.",
            status_any(
                tuple(
                    f"volume-shared-{kind}"
                    for kind in (
                        "configMap",
                        "secret",
                        "projected",
                        "downwardAPI",
                        "hostPath",
                        "persistentVolumeClaim",
                    )
                )
                + ("volume-shared-undeclared",)
            ),
            [
                proof
                for kind, proofs in observed.items()
                if kind.startswith("volume-shared-")
                for proof in proofs
            ],
        ),
        claim(
            "emptydir-local-storage",
            "A disk emptyDir in shared-fs mode produces local Agent storage.",
            status("volume-local"),
            observed.get("volume-local", []),
        ),
        claim(
            "emptydir-tmpfs-storage",
            "A guest ephemeral emptyDir produces tmpfs Agent storage.",
            status("volume-tmpfs"),
            observed.get("volume-tmpfs", []),
        ),
        claim(
            "emptydir-hugepage-storage",
            "A hugepage emptyDir produces hugetlbfs Agent storage.",
            status("volume-hugetlbfs"),
            observed.get("volume-hugetlbfs", []),
        ),
        claim(
            "emptydir-block-storage",
            "A block-backed emptyDir produces storage marked create_filesystem.",
            "not-authoritative"
            if not authoritative
            else (
                "confirmed"
                if "volume-block-emptydir" in observed
                or "volume-block-encrypted-emptydir" in observed
                else "not-exercised"
            ),
            observed.get("volume-block-emptydir", [])
            + observed.get("volume-block-encrypted-emptydir", []),
        ),
        claim(
            "emptydir-block-encrypted-storage",
            "A CDH-managed encrypted emptyDir requests ephemeral encryption and filesystem creation.",
            status("volume-block-encrypted-emptydir"),
            observed.get("volume-block-encrypted-emptydir", []),
        ),
        claim(
            "generic-block-volume-storage",
            "A filesystem-mode block PVC or direct block volume produces block-device Agent storage without the emptyDir create_filesystem marker.",
            status("volume-block-device"),
            observed.get("volume-block-device", []),
        ),
        claim(
            "unsupported-volume-storage",
            "The final request contains a non-rootfs Agent storage class not supported by the policy compiler.",
            status("volume-unsupported"),
            observed.get("volume-unsupported", []),
        ),
        claim(
            "agent-devices",
            "The final request contains Agent devices produced for the workload.",
            status_any(
                ("agent-device-block", "agent-device-vfio", "agent-device-other")
            ),
            [
                proof
                for kind in (
                    "agent-device-block",
                    "agent-device-vfio",
                    "agent-device-other",
                )
                for proof in observed.get(kind, [])
            ],
        ),
        claim(
            "block-agent-devices",
            "The final request contains block Agent devices associated with workload volumeDevices or block storage.",
            status("agent-device-block"),
            observed.get("agent-device-block", []),
        ),
        claim(
            "vfio-agent-devices",
            "The final request contains VFIO Agent devices associated with declared passthrough resources.",
            status("agent-device-vfio"),
            observed.get("agent-device-vfio", []),
        ),
    ]

    return {
        "capture": {
            "backend": capture_metadata.get("backend"),
            "request_authority": authority,
            "rootfs_mode": capture_metadata.get("rootfs_mode"),
        },
        "claims": claims,
        "observations": {
            "agent_device_count": device_count,
            "mount_classes": dict(sorted(mount_counts.items())),
            "request_count": len(request_files),
            "storage_classes": dict(sorted(storage_counts.items())),
            "workload": workload,
            "runtime": runtime,
        },
        "schema_version": 2,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(analyze(args.capture), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
