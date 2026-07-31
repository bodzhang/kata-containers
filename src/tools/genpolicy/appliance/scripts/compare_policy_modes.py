#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path


def policy_document(path: Path) -> tuple[str, dict]:
    text = path.read_text(encoding="utf-8")
    rules, data = text.rsplit("\npolicy_data := ", 1)
    return rules, json.loads(data)


def policy_data(path: Path) -> dict:
    return policy_document(path)[1]


def manifest_summary(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    tags = manifest["tags"]
    return {
        "mode": manifest.get("regex_policy_mode", "legacy"),
        "tag_count": len(tags),
        "service_endpoint_tags": sum(
            tag.get("source") == "kubernetes-service-env" for tag in tags
        ),
        "path_identity_tags": sum(
            tag.get("tag") in {"termination-log.id", "network.namespace"}
            for tag in tags
        ),
    }


def policy_summary(path: Path) -> dict:
    rules, data = policy_document(path)
    regexes = data["request_defaults"]["CreateContainerRequest"][
        "allow_env_regex"
    ]
    service_regexes = [
        value
        for value in regexes
        if "_SERVICE_" in value or "_PORT" in value
    ]
    identity_regexes = [
        value
        for value in regexes
        if "AZURE_CLIENT_ID" in value
        or "AZURE_TENANT_ID" in value
        or "JOB_COMPLETION_INDEX" in value
    ]
    exact_service_env = sorted(
        {
            value
            for container in data["containers"]
            for value in container["OCI"]["Process"]["Env"]
            if "_SERVICE_" in value or "_PORT=" in value
        }
    )
    annotation_patterns = sum(
        len(container["runtime_anno_patterns"])
        for container in data["containers"]
    )
    network_namespace_patterns = sorted(
        {
            value
            for container in data["containers"]
            for key, value in container["OCI"]["Annotations"].items()
            if key == "nerdctl/network-namespace"
        }
    )
    termination_path_patterns = sorted(
        {
            value
            for container in data["containers"]
            for key, value in container["runtime_anno_patterns"].items()
            if "terminationMessagePath" in key
        }
    )
    return {
        "rules_sha256": hashlib.sha256(rules.rstrip().encode()).hexdigest(),
        "allow_env_regex_count": len(regexes),
        "network_namespace_patterns": network_namespace_patterns,
        "termination_path_patterns": termination_path_patterns,
        "service_endpoint_regex_count": len(service_regexes),
        "identity_or_partition_regex_count": len(identity_regexes),
        "exact_service_env_count": len(exact_service_env),
        "runtime_annotation_pattern_count": annotation_patterns,
    }


def container_identity(container: dict) -> str:
    annotations = container["OCI"]["Annotations"]
    container_type = annotations["io.kubernetes.cri.container-type"]
    container_name = annotations.get(
        "io.kubernetes.cri.container-name", "<sandbox>"
    )
    return f"{container_type}/{container_name}"


def policy_comparison(reference_path: Path, candidate_path: Path) -> dict:
    reference_rules, reference = policy_document(reference_path)
    candidate_rules, candidate = policy_document(candidate_path)
    reference_containers = {
        container_identity(container): container
        for container in reference["containers"]
    }
    candidate_containers = {
        container_identity(container): container
        for container in candidate["containers"]
    }
    containers = {}
    for identity in sorted(reference_containers.keys() | candidate_containers.keys()):
        reference_container = reference_containers.get(identity)
        candidate_container = candidate_containers.get(identity)
        if reference_container is None or candidate_container is None:
            containers[identity] = {
                "reference_present": reference_container is not None,
                "candidate_present": candidate_container is not None,
            }
            continue

        reference_oci = reference_container["OCI"]
        candidate_oci = candidate_container["OCI"]
        reference_process = reference_oci["Process"]
        candidate_process = candidate_oci["Process"]
        reference_env = set(reference_process["Env"])
        candidate_env = set(candidate_process["Env"])
        reference_mounts = {
            mount["destination"] for mount in reference_oci["Mounts"]
        }
        candidate_mounts = {
            mount["destination"] for mount in candidate_oci["Mounts"]
        }
        containers[identity] = {
            "cwd": {
                "reference": reference_process["Cwd"],
                "candidate": candidate_process["Cwd"],
            },
            "exec_commands": {
                "reference": reference_container["exec_commands"],
                "candidate": candidate_container["exec_commands"],
            },
            "environment_only_in_reference": sorted(
                reference_env - candidate_env
            ),
            "environment_only_in_candidate": sorted(
                candidate_env - reference_env
            ),
            "mount_destinations_only_in_reference": sorted(
                reference_mounts - candidate_mounts
            ),
            "mount_destinations_only_in_candidate": sorted(
                candidate_mounts - reference_mounts
            ),
            "masked_paths_equal": (
                reference_oci["Linux"]["MaskedPaths"]
                == candidate_oci["Linux"]["MaskedPaths"]
            ),
            "readonly_paths_equal": (
                reference_oci["Linux"]["ReadonlyPaths"]
                == candidate_oci["Linux"]["ReadonlyPaths"]
            ),
        }

    return {
        "rules_equal_ignoring_trailing_whitespace": (
            reference_rules.rstrip() == candidate_rules.rstrip()
        ),
        "containers": containers,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    modes = {}
    for mode, suffix in (
        ("legacy", ""),
        ("balanced", "-balanced"),
    ):
        modes[mode] = {
            "manifest": manifest_summary(
                args.output_dir / f"dynamic-tags{suffix}.json"
            ),
            "policy": policy_summary(args.output_dir / f"policy{suffix}.rego"),
        }

    legacy_reference_path = args.output_dir / "legacy-reference-policy.rego"
    if legacy_reference_path.exists():
        modes["legacy-reference"] = {
            "policy": policy_summary(legacy_reference_path)
        }

    legacy = modes["legacy"]["policy"]
    balanced = modes["balanced"]["policy"]
    result = {
        "schema_version": 1,
        "known_limitations": [
            (
                "The OCI capture does not yet preserve per-environment-variable "
                "provenance, so balanced mode cannot distinguish explicit image/YAML "
                "variables from unknown runtime injections."
            ),
            (
                "The policy model does not yet express required-exactly-once "
                "environment keys, so missing or duplicate variables are not "
                "measured by the mode report."
            ),
            (
                "A portable external-untrusted endpoint mode requires structured "
                "UVM-local address and control-endpoint exclusion; generic IP "
                "regex cannot enforce that boundary safely."
            ),
            (
                "The appliance emulates Kata's network-namespace annotation "
                "injection from the sandbox OCI namespace. Balanced mode "
                "generalizes that generated CNI path because its deployment "
                "UUID cannot be predicted safely from the capture."
            ),
        ],
        "modes": modes,
        "tradeoffs": {
            "balanced": {
                "security": (
                    "Removes inherited identity/partition regexes and service "
                    "endpoint regexes. It retains existing regex-backed "
                    "relation markers for Kubernetes-generated names and IDs, "
                    "which remain a residual risk until agent-authoritative "
                    "correlation is implemented."
                ),
                "operation": (
                    "Pins resolved service endpoints exactly, so the policy "
                    "must be regenerated when ClusterIP or service ports change."
                ),
                "removed_env_regexes": (
                    legacy["allow_env_regex_count"]
                    - balanced["allow_env_regex_count"]
                ),
                "remaining_dynamic_tags": modes["balanced"]["manifest"][
                    "tag_count"
                ],
            },
        },
    }
    if legacy_reference_path.exists():
        result["comparisons"] = {
            "legacy-reference-vs-oci-legacy": policy_comparison(
                legacy_reference_path, args.output_dir / "policy.rego"
            )
        }
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
