#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def parse_profile(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--tag-manifest", required=True, type=Path)
    parser.add_argument("--tagged-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--generated", action="append", default=[])
    args = parser.parse_args()

    artifacts = {}
    for artifact in args.artifact:
        name, raw_path = artifact.split("=", 1)
        path = Path(raw_path)
        artifacts[name] = {"sha256": sha256(path)}

    generated = {}
    for output in args.generated:
        name, raw_path = output.split("=", 1)
        path = Path(raw_path)
        generated[name] = {"sha256": sha256(path)}

    tagged = {
        path.name: sha256(path) for path in sorted(args.tagged_dir.glob("*.json"))
    }
    result = {
        "artifacts": artifacts,
        "input": {"path": "workload.yaml", "sha256": sha256(args.input)},
        "outputs": {
            "dynamic-tags.json": sha256(args.tag_manifest),
            "generated": generated,
            "tagged": tagged,
        },
        "profile": parse_profile(args.profile),
        "schema_version": 1,
    }
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
