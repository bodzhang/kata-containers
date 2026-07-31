#!/usr/bin/env python3
#
# Copyright (c) 2026 Kata Containers
#
# SPDX-License-Identifier: Apache-2.0
#
# Audit-only capture of the Kata container rootfs_mounts that a snapshotter
# (e.g. the containerd-native multi-layer erofs snapshotter) would hand to the
# Kata shim. The appliance itself runs the workload under runc/overlayfs, so the
# erofs rootfs is prepared out-of-band and its mounts are captured here.
#
# IMPORTANT (verified against containerd 2.3.3 + native erofs snapshotter):
# `ctr snapshots mounts` returns the HOST view, a single `overlay` mount whose
# lowerdir is the mount-manager-mounted erofs blob:
#
#     mount -t overlay overlay <target> -o upperdir=.../snapshots/2/fs,\
#         lowerdir=.../mount-manager.v1.bolt/t/1/1,workdir=.../snapshots/2/work
#
# That is NOT what the guest mounts. The block-device rootfs (ext4 rw upper +
# erofs ro lower(s) with `device=`) that `ErofsMultiLayerRootfs` consumes is
# produced by the containerd erofs MOUNT-HANDLER when containerd hands the rootfs
# to the Kata shim. So the input to this converter must be the mount-handler
# block mounts (the mounts the Kata shim actually receives) — captured from a
# Kata-runtime run on the prep host, not from `ctr snapshots mounts`. The erofs
# layer blobs themselves live on disk at `<snapshotter>/snapshots/<N>/layer.erofs`.
#
# For each captured OCI bundle (raw/<name>.config.json) this maps the container's
# digest-pinned image to its per-image mount-handler mounts file and converts it
# into the rootfs_mounts artifact the storage-predictor consumes via
# --rootfs-mounts:
#
#     raw/<name>.rootfs-mounts.json  (JSON array of kata_types::mount::Mount)
#
# The conversion is authoritative and unit-tested; obtaining the mount-handler
# mounts requires containerd >= 2.2 with the erofs snapshotter and the erofs
# kernel module, so it runs on an equipped prep host / e2e environment.

import argparse
import json
import re
import shlex
from pathlib import Path

CONFIG_SUFFIX = ".config.json"

# OCI annotations that carry the container image reference (mirrors the shim's
# guest-pull `get_image_reference`).
_IMAGE_NAME_KEYS = (
    "io.kubernetes.cri.image-name",
    "io.kubernetes.cri-o.ImageName",
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def image_reference(spec: dict) -> str:
    annotations = spec.get("annotations", {})
    for key in _IMAGE_NAME_KEYS:
        value = annotations.get(key)
        if value:
            return value
    return ""


def image_digest(reference: str) -> str:
    match = _DIGEST_RE.search(reference or "")
    return match.group(0) if match else ""


def _parse_mount_line(line: str) -> dict:
    """Parse one `mount -t TYPE -o OPTS SRC TARGET` line (mount-handler output).

    Tolerant of flag order; unknown flags are ignored. Returns None for lines
    that are not mount commands.
    """
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if not tokens or tokens[0] != "mount":
        return None

    fs_type = ""
    options: list = []
    positionals: list = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in ("-t", "--types") and index + 1 < len(tokens):
            fs_type = tokens[index + 1]
            index += 2
        elif token in ("-o", "--options") and index + 1 < len(tokens):
            options = [option for option in tokens[index + 1].split(",") if option]
            index += 2
        elif token.startswith("-"):
            index += 1
        else:
            positionals.append(token)
            index += 1

    if not positionals:
        return None
    source = positionals[0]
    target = positionals[-1] if len(positionals) > 1 else ""
    return {"type": fs_type, "source": source, "target": target, "options": options}


def parse_ctr_mounts(text: str) -> list:
    mounts = []
    for line in text.splitlines():
        mount = _parse_mount_line(line)
        if mount:
            mounts.append(mount)
    return mounts


def load_mounts(path: Path) -> list:
    """Load mount-handler mounts from a `.mounts` (mount-command text) or `.json` file.

    JSON files hold containerd mount dicts ({type, source, options[, target]}).
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return parse_ctr_mounts(text)


def to_kata_mount(mount: dict) -> dict:
    """Convert a containerd mount dict into a kata_types::mount::Mount dict."""
    options = list(mount.get("options", []))
    return {
        "source": mount.get("source", ""),
        # Block layers ignore the destination (the guest path is cid-derived);
        # keep the snapshotter target when present, else a placeholder root.
        "destination": mount.get("target") or mount.get("destination") or "/",
        "fs_type": mount.get("type") or mount.get("fs_type", ""),
        "options": options,
        "device_id": None,
        "host_shared_fs_path": None,
        "read_only": "ro" in options,
    }


def to_kata_mounts(mounts: list) -> list:
    return [to_kata_mount(mount) for mount in mounts]


def _find_mounts_file(mounts_dir: Path, digest: str):
    slug = digest.replace(":", "_")
    for name in (slug, digest):
        for extension in (".mounts", ".json"):
            candidate = mounts_dir / f"{name}{extension}"
            if candidate.exists():
                return candidate
    return None


def capture(raw_dir: Path, mounts_dir: Path) -> dict:
    captures = []
    for config in sorted(raw_dir.glob(f"*{CONFIG_SUFFIX}")):
        base = config.name[: -len(CONFIG_SUFFIX)]
        spec = json.loads(config.read_text(encoding="utf-8"))
        reference = image_reference(spec)
        digest = image_digest(reference)
        status = {"config": config.name, "image": reference}

        if not digest:
            status["skipped"] = "no digest-pinned image reference"
            captures.append(status)
            continue

        source = _find_mounts_file(mounts_dir, digest)
        if source is None:
            status["skipped"] = f"no captured snapshotter mounts for {digest}"
            captures.append(status)
            continue

        mounts = to_kata_mounts(load_mounts(source))
        artifact = raw_dir / f"{base}.rootfs-mounts.json"
        artifact.write_text(json.dumps(mounts, indent=2) + "\n", encoding="utf-8")
        status["rootfs_mounts"] = artifact.name
        status["layers"] = len(mounts)
        captures.append(status)

    return {"schema_version": 1, "captures": captures}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument(
        "--mounts-dir",
        required=True,
        type=Path,
        help="directory of per-image snapshotter mounts (<digest>.mounts/.json)",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = capture(args.raw_dir, args.mounts_dir)
    if args.report:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
