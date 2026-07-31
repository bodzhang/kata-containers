#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path


SERVICE_ENV = re.compile(
    r"^(?P<name>[A-Z][A-Z0-9_]*(?:_SERVICE_HOST|_SERVICE_PORT"
    r"|_PORT(?:_[0-9]+_[A-Z]+(?:_(?:ADDR|PORT|PROTO))?)?))=(?P<value>.*)$"
)
TERMINATION_LOG_SOURCE = re.compile(
    r"^(?P<prefix>.*/containers/[^/]+/)(?P<id>[0-9a-f]{8})$"
)
NETWORK_NAMESPACE = re.compile(
    r"^/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
IP_REGEX = (
    "(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}|"
    "(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})"
)


def marker(tag: str) -> str:
    return "{{GENPOLICY_DYNAMIC:" + tag + "}}"


def pointer(parts: list[str]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def value_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def apply_kata_runtime_behavior(spec: dict) -> None:
    annotations = spec.setdefault("annotations", {})
    if annotations.get("io.kubernetes.cri.container-type") != "sandbox":
        return

    network_paths = {
        namespace.get("path")
        for namespace in (spec.get("linux") or {}).get("namespaces", [])
        if namespace.get("type") == "network" and namespace.get("path")
    }
    if len(network_paths) > 1:
        raise ValueError(
            "sandbox OCI contains multiple network namespace paths"
        )
    if not network_paths:
        return

    network_path = network_paths.pop()
    annotation = annotations.get("nerdctl/network-namespace")
    if annotation is not None and annotation != network_path:
        raise ValueError(
            "Kata network namespace annotation does not match "
            f"OCI Linux namespace: {annotation} != {network_path}"
        )
    annotations["nerdctl/network-namespace"] = network_path


def add_derived_values(
    spec: dict, metadata: dict, values: list[dict]
) -> list[dict]:
    result = list(values)
    annotations = spec.get("annotations") or {}
    known = {(item["tag"], item["value"]) for item in result}

    for key, tag, regex in (
        (
            "io.kubernetes.cri.sandbox-id",
            "sandbox.id",
            "[0-9a-f]{64}",
        ),
        (
            "io.kubernetes.cri.sandbox-uid",
            "pod.uid",
            (
                "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
                "[89ab][0-9a-f]{3}-[0-9a-f]{12}"
            ),
        ),
    ):
        value = annotations.get(key)
        if value and (tag, value) not in known:
            result.append(
                {
                    "source": "containerd-annotation",
                    "suggested_regex": regex,
                    "tag": tag,
                    "value": value,
                }
            )
            known.add((tag, value))

    container_id = metadata.get("container_id")
    if container_id and ("container.id", container_id) not in known:
        result.append(
            {
                "source": "runc",
                "suggested_regex": "[0-9a-f]{64}",
                "tag": "container.id",
                "value": container_id,
            }
        )
    return result


def replace_string(
    value: str,
    parts: list[str],
    source_file: str,
    exact_values: list[dict],
    occurrences: dict[str, list[dict]],
    definitions: dict[str, dict],
    regex_policy_mode: str = "legacy",
) -> str:
    updated = value
    for item in sorted(exact_values, key=lambda entry: len(entry["value"]), reverse=True):
        original = item["value"]
        if not original or original not in updated:
            continue
        updated = updated.replace(original, marker(item["tag"]))
        definitions[item["tag"]] = {
            "marker": marker(item["tag"]),
            "source": item["source"],
            "suggested_regex": item["suggested_regex"],
            "tag": item["tag"],
        }
        occurrences[item["tag"]].append(
            {
                "file": source_file,
                "json_pointer": pointer(parts),
                "original_sha256": value_digest(original),
            }
        )

    match = SERVICE_ENV.match(updated)
    if match and "GENPOLICY_DYNAMIC" not in match.group("value"):
        if regex_policy_mode != "legacy":
            return updated
        variable = match.group("name")
        tag = f"service-env.{variable}"
        service_value = match.group("value")
        if variable.endswith("_HOST") or variable.endswith("_ADDR"):
            suggested_regex = IP_REGEX
        elif (
            variable.endswith("_SERVICE_PORT")
            or "_SERVICE_PORT_" in variable
            or re.search(r"_PORT_[0-9]+_[A-Z]+_PORT$", variable)
        ):
            suggested_regex = "[0-9]{1,5}"
        elif variable.endswith("_PROTO"):
            suggested_regex = "(?:tcp|udp|sctp)"
        elif variable.endswith("_PORT") or re.search(
            r"_PORT_[0-9]+_[A-Z]+$", variable
        ):
            suggested_regex = (
                f"(?:tcp|udp|sctp)://(?:{IP_REGEX}):[0-9]{{1,5}}"
            )
        else:
            suggested_regex = ".+"
        updated = f"{variable}={marker(tag)}"
        definitions[tag] = {
            "marker": marker(tag),
            "source": "kubernetes-service-env",
            "suggested_regex": suggested_regex,
            "tag": tag,
        }
        occurrences[tag].append(
            {
                "file": source_file,
                "json_pointer": pointer(parts),
                "original_sha256": value_digest(service_value),
            }
        )

    match = TERMINATION_LOG_SOURCE.match(updated)
    if parts[-1:] == ["source"] and match:
        if regex_policy_mode != "legacy":
            return updated
        tag = "termination-log.id"
        original = match.group("id")
        updated = match.group("prefix") + marker(tag)
        definitions[tag] = {
            "marker": marker(tag),
            "source": "kubelet",
            "suggested_regex": "[0-9a-f]{8}",
            "tag": tag,
        }
        occurrences[tag].append(
            {
                "file": source_file,
                "json_pointer": pointer(parts),
                "original_sha256": value_digest(original),
            }
        )

    if (
        parts == ["annotations", "nerdctl/network-namespace"]
        and NETWORK_NAMESPACE.match(updated)
    ):
        tag = "network.namespace"
        original = updated
        updated = marker(tag)
        definitions[tag] = {
            "marker": marker(tag),
            "source": "cni",
            "suggested_regex": (
                "/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-"
                "[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            ),
            "tag": tag,
        }
        occurrences[tag].append(
            {
                "file": source_file,
                "json_pointer": pointer(parts),
                "original_sha256": value_digest(original),
            }
        )
    return updated


def transform(
    value,
    parts: list[str],
    source_file: str,
    exact_values: list[dict],
    occurrences: dict[str, list[dict]],
    definitions: dict[str, dict],
    regex_policy_mode: str = "legacy",
):
    if isinstance(value, dict):
        return {
            key: transform(
                child,
                parts + [key],
                source_file,
                exact_values,
                occurrences,
                definitions,
                regex_policy_mode,
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            transform(
                child,
                parts + [str(index)],
                source_file,
                exact_values,
                occurrences,
                definitions,
                regex_policy_mode,
            )
            for index, child in enumerate(value)
        ]
    if isinstance(value, str):
        return replace_string(
            value,
            parts,
            source_file,
            exact_values,
            occurrences,
            definitions,
            regex_policy_mode,
        )
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--dynamic-values", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--regex-policy-mode",
        choices=("legacy", "balanced"),
        default="legacy",
    )
    args = parser.parse_args()

    base_values = json.loads(args.dynamic_values.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    occurrences = defaultdict(list)
    definitions: dict[str, dict] = {}

    captures = sorted(args.raw_dir.glob("*.config.json"))
    if not captures:
        raise SystemExit("no OCI config captures found")

    for capture in captures:
        metadata_path = capture.with_name(
            capture.name.removesuffix(".config.json") + ".meta.json"
        )
        metadata = (
            json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata_path.exists()
            else {}
        )
        spec = json.loads(capture.read_text(encoding="utf-8"))
        try:
            apply_kata_runtime_behavior(spec)
        except ValueError as error:
            raise SystemExit(f"{capture.name}: {error}") from error
        exact_values = add_derived_values(spec, metadata, base_values)
        output_name = capture.name.replace(".config.json", ".tagged.json")
        tagged = transform(
            spec,
            [],
            f"tagged/{output_name}",
            exact_values,
            occurrences,
            definitions,
            args.regex_policy_mode,
        )
        (args.output_dir / output_name).write_text(
            json.dumps(tagged, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    tags = []
    for tag in sorted(definitions):
        definition = definitions[tag]
        definition["occurrences"] = occurrences[tag]
        tags.append(definition)
    manifest = {"schema_version": 1, "tags": tags}
    if args.regex_policy_mode != "legacy":
        manifest["regex_policy_mode"] = args.regex_policy_mode
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
