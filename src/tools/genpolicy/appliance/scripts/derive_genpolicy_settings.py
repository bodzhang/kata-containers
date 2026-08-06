#!/usr/bin/env python3

import argparse
import json
import tomllib
from pathlib import Path


EMPTYDIR_MODES = {"shared-fs", "block-encrypted", "block-plain"}
SHARED_FS_NONE = "none"


def derive_settings(configuration: dict) -> list[dict]:
    runtime = configuration.get("runtime", {})
    hypervisor_name = runtime.get("hypervisor_name")
    emptydir_mode = runtime.get("emptydir_mode")
    if emptydir_mode not in EMPTYDIR_MODES:
        raise ValueError(f"unsupported or missing runtime.emptydir_mode: {emptydir_mode!r}")
    if not hypervisor_name:
        raise ValueError("runtime.hypervisor_name is required")

    hypervisor = configuration.get("hypervisor", {}).get(hypervisor_name, {})
    shared_fs = hypervisor.get("shared_fs")
    if not isinstance(shared_fs, str) or not shared_fs:
        raise ValueError(f"hypervisor.{hypervisor_name}.shared_fs is required")

    return [
        {
            "op": "replace",
            "path": "/cluster_config/emptydir_type",
            "value": emptydir_mode,
        },
        {
            "op": "replace",
            "path": "/cluster_config/fs_sharing_supported",
            "value": shared_fs != SHARED_FS_NONE,
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kata-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    with args.kata_config.open("rb") as source:
        patch = derive_settings(tomllib.load(source))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(patch, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()