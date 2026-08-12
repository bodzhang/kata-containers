#!/usr/bin/env python3

import argparse
import gzip
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Callable


INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}


class ImageMetadataError(ValueError):
    pass


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def digest_path(directory: Path, digest: str, suffix: str = ".json") -> Path:
    algorithm, separator, value = digest.partition(":")
    if separator != ":" or algorithm != "sha256" or len(value) != 64:
        raise ImageMetadataError(f"unsupported content digest: {digest}")
    return directory / f"{value}{suffix}"


def verify_content(raw: bytes, expected_digest: str, expected_size: int | None = None) -> None:
    actual_digest = digest_bytes(raw)
    if actual_digest != expected_digest:
        raise ImageMetadataError(
            f"content digest mismatch: expected {expected_digest}, got {actual_digest}"
        )
    if expected_size is not None and len(raw) != expected_size:
        raise ImageMetadataError(
            f"content size mismatch for {expected_digest}: expected {expected_size}, got {len(raw)}"
        )


def decode_content(
    raw: bytes, expected_digest: str, expected_size: int | None = None
) -> dict:
    verify_content(raw, expected_digest, expected_size)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ImageMetadataError(f"content {expected_digest} is not JSON") from error
    if not isinstance(value, dict):
        raise ImageMetadataError(f"content {expected_digest} is not an object")
    return value


def uncompressed_layer(raw: bytes, media_type: str) -> bytes:
    if media_type.endswith("+gzip") or media_type.endswith(".gzip"):
        try:
            return gzip.decompress(raw)
        except gzip.BadGzipFile as error:
            raise ImageMetadataError("layer is not valid gzip content") from error
    if media_type.endswith("+zstd"):
        raise ImageMetadataError(
            "zstd layer diff-id verification is not supported by this prototype"
        )
    if media_type.endswith(".tar"):
        return raw
    raise ImageMetadataError(f"unsupported layer media type: {media_type}")


def select_platform_manifest(index: dict, os_name: str, architecture: str) -> dict:
    matches = []
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform", {})
        if platform.get("os") == os_name and platform.get("architecture") == architecture:
            matches.append(descriptor)
    if len(matches) != 1:
        raise ImageMetadataError(
            f"expected one {os_name}/{architecture} manifest, found {len(matches)}"
        )
    return matches[0]


def content_kind(value: dict) -> str | None:
    media_type = value.get("mediaType")
    if media_type in INDEX_MEDIA_TYPES:
        return "index"
    if media_type in MANIFEST_MEDIA_TYPES:
        return "manifest"
    if media_type is not None:
        return None
    if isinstance(value.get("manifests"), list):
        return "index"
    if isinstance(value.get("config"), dict) and isinstance(value.get("layers"), list):
        return "manifest"
    return None


def export_image_metadata(
    references: list[str],
    output: Path,
    read_content: Callable[[str], bytes],
    os_name: str,
    architecture: str,
) -> dict:
    manifests_dir = output / "manifests"
    configs_dir = output / "configs"
    layers_dir = output / "layers"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    configs_dir.mkdir(parents=True, exist_ok=True)
    layers_dir.mkdir(parents=True, exist_ok=True)
    result = {}

    for reference in sorted(set(references)):
        separator = reference.rfind("@")
        if separator < 0:
            raise ImageMetadataError(f"image reference is not digest-pinned: {reference}")
        requested_digest = reference[separator + 1 :]
        top_raw = read_content(requested_digest)
        top = decode_content(top_raw, requested_digest)
        top_media_type = top.get("mediaType")
        top_kind = content_kind(top)

        if top_kind == "index":
            descriptor = select_platform_manifest(top, os_name, architecture)
            manifest_digest = descriptor.get("digest", "")
            manifest_raw = read_content(manifest_digest)
            manifest = decode_content(
                manifest_raw, manifest_digest, descriptor.get("size")
            )
        elif top_kind == "manifest":
            manifest_digest = requested_digest
            manifest_raw = top_raw
            manifest = top
        else:
            raise ImageMetadataError(
                f"unsupported image media type for {reference}: {top_media_type}"
            )

        if content_kind(manifest) != "manifest":
            raise ImageMetadataError(
                f"selected content is not an image manifest: {manifest_digest}"
            )
        config_descriptor = manifest.get("config", {})
        config_digest = config_descriptor.get("digest", "")
        config_raw = read_content(config_digest)
        config = decode_content(
            config_raw, config_digest, config_descriptor.get("size")
        )

        layer_descriptors = manifest.get("layers", [])
        diff_ids = (config.get("rootfs") or {}).get("diff_ids", [])
        if len(layer_descriptors) != len(diff_ids):
            raise ImageMetadataError(
                f"manifest layer count does not match config diff_ids for {reference}"
            )
        layers = []
        for descriptor, diff_id in zip(layer_descriptors, diff_ids, strict=True):
            layer_digest = descriptor.get("digest", "")
            media_type = descriptor.get("mediaType", "")
            layer_raw = read_content(layer_digest)
            verify_content(layer_raw, layer_digest, descriptor.get("size"))
            actual_diff_id = digest_bytes(uncompressed_layer(layer_raw, media_type))
            if actual_diff_id != diff_id:
                raise ImageMetadataError(
                    f"layer diff-id mismatch: expected {diff_id}, got {actual_diff_id}"
                )
            layer_path = digest_path(layers_dir, layer_digest, ".blob")
            layer_path.write_bytes(layer_raw)
            layers.append(
                {
                    "digest": layer_digest,
                    "diff_id": diff_id,
                    "media_type": media_type,
                    "path": layer_path.relative_to(output).as_posix(),
                    "size": len(layer_raw),
                }
            )

        manifest_path = digest_path(manifests_dir, manifest_digest)
        requested_path = digest_path(manifests_dir, requested_digest)
        config_path = digest_path(configs_dir, config_digest)
        manifest_path.write_bytes(manifest_raw)
        requested_path.write_bytes(top_raw)
        config_path.write_bytes(config_raw)
        result[reference] = {
            "config_digest": config_digest,
            "config_path": config_path.relative_to(output).as_posix(),
            "manifest_digest": manifest_digest,
            "manifest_path": manifest_path.relative_to(output).as_posix(),
            "layers": layers,
            "platform": {"architecture": architecture, "os": os_name},
            "requested_digest": requested_digest,
            "requested_media_type": top_media_type,
            "requested_path": requested_path.relative_to(output).as_posix(),
        }

    (output / "index.json").write_text(
        json.dumps(
            {"images": result, "schema_version": 1}, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requested-images", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ctr", default="ctr")
    parser.add_argument("--address", default="/run/containerd/containerd.sock")
    parser.add_argument("--namespace", default="k8s.io")
    parser.add_argument("--os", default="linux")
    parser.add_argument("--architecture", required=True)
    args = parser.parse_args()

    references = [
        line.strip()
        for line in args.requested_images.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    def read_content(digest: str) -> bytes:
        result = subprocess.run(
            [
                args.ctr,
                "--address",
                args.address,
                "--namespace",
                args.namespace,
                "content",
                "get",
                digest,
            ],
            check=True,
            capture_output=True,
        )
        return result.stdout

    try:
        export_image_metadata(
            references,
            args.output,
            read_content,
            args.os,
            args.architecture,
        )
    except (ImageMetadataError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()