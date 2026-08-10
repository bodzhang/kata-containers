#!/usr/bin/env python3

import argparse
from pathlib import Path

import prototype_static_policy as static_policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument(
        "--rootfs-mode",
        required=True,
        choices=("guest-pull", "erofs-dmverity"),
    )
    parser.add_argument("--uvm-baseline", type=Path)
    parser.add_argument("--rootfs-artifacts", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    static_ir = static_policy.generate_static_ir(
        args.capture,
        rootfs_mode=args.rootfs_mode,
        uvm_baseline_path=args.uvm_baseline,
        rootfs_artifacts_path=args.rootfs_artifacts,
    )
    args.output.write_text(
        static_policy.render_static_rego_ir(static_ir),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
