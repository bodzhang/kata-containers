#!/usr/bin/env python3
#
# Copyright (c) 2026 Kata Containers
#
# SPDX-License-Identifier: Apache-2.0
#
# Audit-only driver: for each captured OCI config.json, run the storage-predictor
# binary (real runtime-rs volume handlers, no VM) and assemble a combined report.
# Per-container failures are recorded rather than aborting the run.

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

CONFIG_SUFFIX = ".config.json"


def sandbox_id(spec: dict) -> str:
    return spec.get("annotations", {}).get("io.kubernetes.cri.sandbox-id", "")


def predict_one(
    predictor: str,
    config: Path,
    cid: str,
    sid: str,
    emptydir_mode: str,
    block_driver: str,
    kata_config: str,
    rootfs_mounts: str = "",
    guest_pull: bool = False,
) -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "predicted.json"
        command = [
            predictor,
            "--config",
            str(config),
            "--output",
            str(output),
            "--sid",
            sid,
            "--cid",
            cid,
            "--emptydir-mode",
            emptydir_mode,
            "--block-driver",
            block_driver,
        ]
        if kata_config:
            command += ["--kata-config", kata_config]
        if rootfs_mounts:
            command += ["--rootfs-mounts", rootfs_mounts]
        elif guest_pull:
            # No snapshotter rootfs artifact: model the container rootfs as a
            # guest-pull image (mainstream CoCo). Mutually exclusive with erofs.
            command += ["--guest-pull-rootfs"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return {
                "container_id": cid,
                "sandbox_id": sid,
                "error": result.stderr.strip(),
            }
        return json.loads(output.read_text(encoding="utf-8"))


def collect(
    raw_dir: Path,
    predictor: str,
    emptydir_mode: str,
    block_driver: str,
    kata_config: str,
    guest_pull: bool = False,
) -> dict:
    predictions = []
    for config in sorted(raw_dir.glob(f"*{CONFIG_SUFFIX}")):
        meta_path = config.with_name(config.name[: -len(CONFIG_SUFFIX)] + ".meta.json")
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            meta = {}
        cid = meta.get("container_id", config.name[: -len(CONFIG_SUFFIX)])
        spec = json.loads(config.read_text(encoding="utf-8"))
        sid = sandbox_id(spec) or cid
        # Optional snapshotter-captured rootfs_mounts artifact (e.g. multi-layer
        # erofs) produced alongside the OCI bundle capture.
        rootfs_path = config.with_name(
            config.name[: -len(CONFIG_SUFFIX)] + ".rootfs-mounts.json"
        )
        rootfs_mounts = str(rootfs_path) if rootfs_path.exists() else ""
        predictions.append(
            predict_one(
                predictor,
                config,
                cid,
                sid,
                emptydir_mode,
                block_driver,
                kata_config,
                rootfs_mounts,
                guest_pull,
            )
        )
    return {"schema_version": 1, "predictions": predictions}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--predictor", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--emptydir-mode", default="shared-fs")
    parser.add_argument("--block-driver", default="virtio-blk-pci")
    parser.add_argument("--kata-config", default="")
    parser.add_argument(
        "--guest-pull",
        action="store_true",
        help="model each container rootfs as a guest-pull image when no "
        "snapshotter rootfs-mounts artifact is present",
    )
    args = parser.parse_args()

    report = collect(
        args.raw_dir,
        args.predictor,
        args.emptydir_mode,
        args.block_driver,
        args.kata_config,
        args.guest_pull,
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
