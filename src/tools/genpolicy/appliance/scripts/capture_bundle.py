#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


SCHEMA_VERSION = 1
REQUIRED_FILES = (
    "submitted-objects.json",
    "pods.json",
    "dynamic-values.json",
    "requested-images.txt",
)
CAPTURE_DIRECTORIES = {
    "raw": "raw-oci",
    "createcontainer-requests": "createcontainer-requests",
    "execprocess-requests": "execprocess-requests",
    "images": "images",
    "logs": "logs",
}
LABEL = re.compile(r"^[A-Za-z0-9_.-]+$")


class BundleError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_profile(path: Path) -> dict[str, str]:
    profile = {}
    for number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise BundleError(f"invalid profile line {number}: {raw_line}")
        key, value = line.split("=", 1)
        if not LABEL.fullmatch(key):
            raise BundleError(f"invalid profile key on line {number}: {key}")
        profile[key] = value
    return profile


def parse_named_paths(values: list[str]) -> dict[str, Path]:
    result = {}
    for value in values:
        if "=" not in value:
            raise BundleError(f"expected NAME=PATH, got {value}")
        name, raw_path = value.split("=", 1)
        if not LABEL.fullmatch(name):
            raise BundleError(f"invalid artifact name: {name}")
        path = Path(raw_path)
        if not path.is_file():
            raise BundleError(f"artifact does not exist: {path}")
        if name in result:
            raise BundleError(f"duplicate artifact name: {name}")
        result[name] = path
    return result


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        return
    shutil.copytree(source, destination)


def artifact_index(bundle: Path) -> dict[str, dict[str, object]]:
    artifacts = {}
    for path in sorted(bundle.rglob("*")):
        if not path.is_file() or path == bundle / "manifest.json":
            continue
        relative = path.relative_to(bundle).as_posix()
        artifacts[relative] = {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
    return artifacts


def expected_request_count(pods_path: Path) -> int:
    pods = json.loads(pods_path.read_text(encoding="utf-8"))
    if not isinstance(pods, list):
        raise BundleError("pods.json must contain a list")
    count = 0
    for pod in pods:
        spec = pod.get("spec", {})
        count += 1
        count += len(spec.get("initContainers", []))
        count += len(spec.get("containers", []))
    return count


def count_files(path: Path, pattern: str) -> int:
    return sum(1 for candidate in path.glob(pattern) if candidate.is_file())


def validate_image_metadata(bundle: Path) -> None:
    requested = {
        line.strip()
        for line in (bundle / "requested-images.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    }
    index_path = bundle / "images" / "index.json"
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid image metadata index: {error}") from error
    if index.get("schema_version") != 1 or not isinstance(index.get("images"), dict):
        raise BundleError("invalid image metadata index schema")
    images = index["images"]
    if set(images) != requested:
        missing = sorted(requested - set(images))
        unexpected = sorted(set(images) - requested)
        raise BundleError(
            f"image metadata references differ: missing={missing}, unexpected={unexpected}"
        )
    for reference, descriptor in images.items():
        requested_digest = reference.rpartition("@")[2]
        if descriptor.get("requested_digest") != requested_digest:
            raise BundleError(
                f"image {reference} requested digest does not match its index entry"
            )
        decoded = {}
        for kind in ("manifest", "config"):
            digest = descriptor.get(f"{kind}_digest", "")
            relative_path = descriptor.get(f"{kind}_path", "")
            path = bundle / "images" / relative_path
            try:
                relative = path.resolve().relative_to((bundle / "images").resolve())
            except ValueError as error:
                raise BundleError(
                    f"image {reference} has invalid {kind} path: {relative_path}"
                ) from error
            if relative.as_posix() != relative_path or not path.is_file():
                raise BundleError(
                    f"image {reference} {kind} is missing: {relative_path}"
                )
            if f"sha256:{sha256(path)}" != digest:
                raise BundleError(
                    f"image {reference} {kind} digest does not match: {relative_path}"
                )
            try:
                decoded[kind] = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise BundleError(
                    f"image {reference} {kind} is not valid JSON: {relative_path}"
                ) from error
        manifest_config_digest = decoded["manifest"].get("config", {}).get("digest")
        if manifest_config_digest != descriptor.get("config_digest"):
            raise BundleError(
                f"image {reference} manifest config digest does not match its index entry"
            )


def build_bundle(
    source: Path,
    bundle: Path,
    workload: Path,
    profile_path: Path,
    capture_backend: str,
    rootfs_mode: str,
    outbound_sealed: bool,
    configurations: dict[str, Path] | None = None,
    capture_binaries: dict[str, Path] | None = None,
    input_images: dict[str, Path] | None = None,
    require_complete: bool = True,
) -> dict:
    configurations = configurations or {}
    capture_binaries = capture_binaries or {}
    input_images = input_images or {}

    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)

    if not workload.is_file():
        raise BundleError(f"workload does not exist: {workload}")
    shutil.copy2(workload, bundle / "workload.yaml")
    for name in REQUIRED_FILES:
        path = source / name
        if not path.is_file():
            raise BundleError(f"required capture artifact is missing: {path}")
        shutil.copy2(path, bundle / name)
    for source_name, bundle_name in CAPTURE_DIRECTORIES.items():
        copy_tree(source / source_name, bundle / bundle_name)
    validate_image_metadata(bundle)

    config_hashes = {}
    if configurations:
        config_dir = bundle / "config"
        config_dir.mkdir()
        for name, path in sorted(configurations.items()):
            destination = config_dir / name
            shutil.copy2(path, destination)
            config_hashes[name] = sha256(destination)

    profile = {
        "capture_backend": capture_backend,
        "configuration_hashes": config_hashes,
        "rootfs_mode": rootfs_mode,
        "schema_version": SCHEMA_VERSION,
        "values": parse_profile(profile_path),
    }
    identity_input = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    profile["identity"] = hashlib.sha256(identity_input.encode()).hexdigest()
    write_json(bundle / "profile.json", profile)

    expected = expected_request_count(bundle / "pods.json")
    counts = {
        "createcontainer": count_files(bundle / "createcontainer-requests", "*.json"),
        "execprocess": count_files(bundle / "execprocess-requests", "*.json"),
        "expected_createcontainer": expected,
        "raw_oci": count_files(bundle / "raw-oci", "*.config.json"),
    }
    complete = (
        outbound_sealed
        and counts["createcontainer"] == expected
        and counts["raw_oci"] == expected
    )
    image_inputs = {
        name: {"sha256": sha256(path), "size": path.stat().st_size}
        for name, path in sorted(input_images.items())
    }
    binary_inputs = {
        name: {"sha256": sha256(path), "size": path.stat().st_size}
        for name, path in sorted(capture_binaries.items())
    }
    artifacts = artifact_index(bundle)
    profile_values = profile["values"]
    request_authority = profile_values.get("REQUEST_AUTHORITY")
    expected_authority = "recording-agent" if capture_backend == "runtime-rs" else "raw-oci"
    if request_authority != expected_authority:
        raise BundleError(
            f"profile request authority must be {expected_authority} for {capture_backend}"
        )
    manifest = {
        "artifacts": artifacts,
        "bundle_type": "genpolicy-request-capture",
        "capture": {
            "backend": capture_backend,
            "complete": complete,
            "counts": counts,
            "outbound_sealed": outbound_sealed,
            "request_authority": request_authority,
            "rootfs_mode": rootfs_mode,
        },
        "capture_binaries": binary_inputs,
        "components": {
            "cni_plugins": profile_values.get("CNI_PLUGINS_VERSION"),
            "containerd": profile_values.get("CONTAINERD_VERSION"),
            "etcd": profile_values.get("ETCD_VERSION"),
            "kubernetes": profile_values.get("KUBERNETES_VERSION"),
            "runc": profile_values.get("RUNC_VERSION"),
        },
        "input_images": image_inputs,
        "profile": {
            "identity": profile["identity"],
            "path": "profile.json",
            "sha256": artifacts["profile.json"]["sha256"],
        },
        "schema_version": SCHEMA_VERSION,
    }
    write_json(bundle / "manifest.json", manifest)
    validate_bundle(bundle, require_complete=require_complete)
    return manifest


def validate_bundle(bundle: Path, require_complete: bool = False) -> dict:
    manifest_path = bundle / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise BundleError(f"invalid capture manifest: {error}") from error

    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("unsupported capture manifest schema version")
    if manifest.get("bundle_type") != "genpolicy-request-capture":
        raise BundleError("invalid capture bundle type")

    validate_image_metadata(bundle)

    recorded = manifest.get("artifacts")
    if not isinstance(recorded, dict):
        raise BundleError("manifest artifacts must be an object")
    actual = artifact_index(bundle)
    if set(recorded) != set(actual):
        missing = sorted(set(recorded) - set(actual))
        unexpected = sorted(set(actual) - set(recorded))
        raise BundleError(
            f"capture artifact set changed: missing={missing}, unexpected={unexpected}"
        )
    for name, descriptor in recorded.items():
        if descriptor != actual[name]:
            raise BundleError(f"capture artifact integrity check failed: {name}")

    capture = manifest.get("capture", {})
    profile = json.loads((bundle / "profile.json").read_text(encoding="utf-8"))
    request_authority = profile.get("values", {}).get("REQUEST_AUTHORITY")
    if capture.get("request_authority") != request_authority:
        raise BundleError("capture request authority does not match profile")
    counts = capture.get("counts", {})
    expected_counts = {
        "createcontainer": count_files(bundle / "createcontainer-requests", "*.json"),
        "execprocess": count_files(bundle / "execprocess-requests", "*.json"),
        "expected_createcontainer": expected_request_count(bundle / "pods.json"),
        "raw_oci": count_files(bundle / "raw-oci", "*.config.json"),
    }
    if counts != expected_counts:
        raise BundleError("capture request counts do not match bundle contents")
    calculated_complete = (
        capture.get("outbound_sealed") is True
        and counts["createcontainer"] == counts["expected_createcontainer"]
        and counts["raw_oci"] == counts["expected_createcontainer"]
    )
    if capture.get("complete") is not calculated_complete:
        raise BundleError("capture completeness flag is inconsistent")
    if require_complete and not calculated_complete:
        raise BundleError("capture bundle is incomplete")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--source", required=True, type=Path)
    build.add_argument("--bundle", required=True, type=Path)
    build.add_argument("--workload", required=True, type=Path)
    build.add_argument("--profile", required=True, type=Path)
    build.add_argument("--capture-backend", required=True)
    build.add_argument("--rootfs-mode", required=True)
    build.add_argument("--outbound-sealed", action="store_true")
    build.add_argument("--allow-incomplete", action="store_true")
    build.add_argument("--configuration", action="append", default=[])
    build.add_argument("--capture-binary", action="append", default=[])
    build.add_argument("--input-image", action="append", default=[])

    validate = subparsers.add_parser("validate")
    validate.add_argument("--bundle", required=True, type=Path)
    validate.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "build":
            build_bundle(
                source=args.source,
                bundle=args.bundle,
                workload=args.workload,
                profile_path=args.profile,
                capture_backend=args.capture_backend,
                rootfs_mode=args.rootfs_mode,
                outbound_sealed=args.outbound_sealed,
                configurations=parse_named_paths(args.configuration),
                capture_binaries=parse_named_paths(args.capture_binary),
                input_images=parse_named_paths(args.input_image),
                require_complete=not args.allow_incomplete,
            )
        else:
            validate_bundle(args.bundle, require_complete=args.require_complete)
    except BundleError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()