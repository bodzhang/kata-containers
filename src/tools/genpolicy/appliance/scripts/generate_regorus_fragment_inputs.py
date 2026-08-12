#!/usr/bin/env python3

import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SCRIPT_DIR = Path(__file__).parent
COMPOSITION_SCHEMA_VERSION = 1
PLATFORM_SERVICES = [
    {
        "name": "kubernetes",
        "namespace": "default",
        "ports": [{"name": "https", "port": 443, "protocol": "TCP"}],
    }
]
coverage = load_module(
    "prototype_fragment_coverage",
    SCRIPT_DIR / "prototype_fragment_coverage.py",
)
static_policy = load_module(
    "prototype_static_policy",
    SCRIPT_DIR / "prototype_static_policy.py",
)


def leaf_paths(value, path="") -> list[str]:
    if isinstance(value, dict):
        result = []
        for key, child in value.items():
            result.extend(leaf_paths(child, coverage.child_path(path, key)))
        return result
    return [path]


def sparse_patch(pointer: str, value):
    result = copy.deepcopy(value)
    for token in reversed(coverage.composition.pointer_tokens(pointer)):
        result = {token: result}
    return result


def render_module(package: str, name: str, value) -> str:
    return (
        f"package {package}\n\n{name} := "
        + json.dumps(value, indent=2, sort_keys=True)
        + "\n"
    )


def service_env_patterns(tag_manifest: dict) -> dict[str, str]:
    prefix = "service-env."
    patterns = {}
    for tag in tag_manifest.get("tags", []):
        name = tag.get("tag", "")
        if not name.startswith(prefix):
            continue
        variable = name.removeprefix(prefix)
        pattern = tag.get("suggested_regex")
        if not variable or not pattern:
            raise ValueError(f"invalid Service environment tag: {name}")
        patterns[variable] = f"^{variable}={pattern}$"
    return patterns


def tagged_service_env(tagged_requests: list[dict]) -> dict[tuple[str, str], set[str]]:
    prefix = "{{GENPOLICY_DYNAMIC:service-env."
    result = {}
    for request in tagged_requests:
        oci = request.get("oci", request)
        annotations = oci.get("annotations", {})
        identity = (
            annotations.get("io.kubernetes.cri.container-type", ""),
            annotations.get("io.kubernetes.cri.container-name", ""),
        )
        variables = result.setdefault(identity, set())
        for entry in oci.get("process", {}).get("env", []):
            marker = entry.partition("=")[2]
            if marker.startswith(prefix) and marker.endswith("}}"):
                variables.add(marker[len(prefix) : -2])
    return result


def copy_file_patterns(static_ir: dict) -> list[str]:
    return sorted(
        {
            f"^$(cpath)/$(bundle-id)-[0-9a-f]{{16}}-{volume['destination_basename']}"
            for subject in static_ir.get("subjects", [])
            for volume in subject.get("volumes", [])
            if volume.get("role") in {"config-map", "secret"}
            and (volume.get("source") or {}).get("content_trust")
            == "untrusted-runtime"
            and re.fullmatch(
                r"[A-Za-z0-9_-]+", volume.get("destination_basename", "")
            )
        }
    )


def production_safe_policy(
    expected: dict,
    tag_manifest: dict,
    tagged_requests: list[dict],
    static_ir: dict | None = None,
) -> dict:
    result = copy.deepcopy(expected)
    patterns = service_env_patterns(tag_manifest)
    scoped_variables = tagged_service_env(tagged_requests)
    request = result["request_defaults"]["CreateContainerRequest"]
    request["allow_env_regex"] = []
    result["request_defaults"]["CopyFileRequest"] = copy_file_patterns(
        static_ir or {}
    )
    static_subjects = {
        subject["subject"]: subject for subject in (static_ir or {}).get("subjects", [])
    }
    for container in result["containers"]:
        annotations = container["OCI"].get("Annotations", {})
        identity = (
            annotations.get("io.kubernetes.cri.container-type", ""),
            annotations.get("io.kubernetes.cri.container-name", ""),
        )
        process = container["OCI"]["Process"]
        container_name = annotations.get("io.kubernetes.cri.container-name")
        static_subject = static_subjects.get(f"container/{container_name}", {})
        rootfs_identity = static_subject.get("rootfs_identity_storage")
        if rootfs_identity is not None:
            runtime_storages = [
                storage
                for storage in container.get("storages", [])
                if storage.get("driver")
                not in {"dmverity-roothashes", "guest-pull-images"}
            ]
            container["storages"] = [copy.deepcopy(rootfs_identity), *runtime_storages]
        dynamic_variables = scoped_variables.get(identity, set())
        exact = []
        scoped = list(process.get("EnvRegex", []))
        for entry in process.get("Env", []):
            variable = entry.partition("=")[0]
            if variable in dynamic_variables:
                scoped.append(patterns[variable])
            else:
                exact.append(entry)
        process["Env"] = exact
        for variable in sorted(dynamic_variables):
            if variable not in patterns:
                raise ValueError(f"Service environment marker has no regex: {variable}")
            scoped.append(patterns[variable])
        process["EnvRegex"] = list(dict.fromkeys(scoped))
    return result


ENVIRONMENT_DIMENSIONS = {
    "cni_plugins": "CNI_PLUGINS_VERSION",
    "containerd": "CONTAINERD_VERSION",
    "kubernetes": "KUBERNETES_VERSION",
    "runc": "RUNC_VERSION",
}


def capture_environment(profile: dict) -> dict:
    values = profile.get("values") or {}
    environment = {
        dimension: values[key]
        for dimension, key in ENVIRONMENT_DIMENSIONS.items()
        if values.get(key)
    }
    if profile.get("rootfs_mode"):
        environment["rootfs_mode"] = profile["rootfs_mode"]
    return environment


def regorus_static_ir(
    report: dict, static_ir: dict | None = None, profile: dict | None = None
) -> dict:
    result = copy.deepcopy(report["static_policy"])
    static_subjects = {
        subject["subject"]: subject for subject in (static_ir or {}).get("subjects", [])
    }
    required_categories = sorted(
        {fragment["category"] for fragment in report["fragments"]}
    )
    result.update(
        {
            "composition_schema_version": COMPOSITION_SCHEMA_VERSION,
            "capture_provenance": report["binding"]["profile_identity"],
            "environment": capture_environment(profile or {}),
            "policy_owned_paths": leaf_paths(result["policy_data"]),
            "requires": {"categories": required_categories},
            "schema_version": 1,
            "static_base_digest": report["binding"]["static_base_digest"],
        }
    )
    if static_ir is not None:
        result["environment"]["rootfs_mode"] = static_ir["rootfs_mode"]
    # The composer accepts fragments by declared applicability, not by capture hash.
    result.pop("profile_identity", None)
    result["services"] = copy.deepcopy((static_ir or {}).get("services", []))
    for subject in result["subjects"]:
        static_subject = static_subjects.get(subject["id"], {})
        subject["namespace"] = static_subject.get("namespace", "")
        subject["service_links_enabled"] = static_subject.get(
            "service_links_enabled", False
        )
        capabilities = static_subject.get("capabilities", {})
        subject["capability_adds"] = capabilities.get("add", [])
        subject["capability_drops"] = capabilities.get("drop", [])
        subject["environment_resolutions"] = copy.deepcopy(
            static_subject.get("environment_resolutions", [])
        )
        subject["device_requests"] = copy.deepcopy(
            static_subject.get("device_requests", {})
        )
        subject["rootfs"] = copy.deepcopy(static_subject.get("rootfs", {}))
        subject["rootfs_identity_storage"] = copy.deepcopy(
            static_subject.get("rootfs_identity_storage", {})
        )
        subject["volumes"] = copy.deepcopy(static_subject.get("volumes", []))
        subject["owned_paths"] = leaf_paths(subject["policy"])
        subject["role"] = (
            "application" if subject["id"].startswith("container/") else "sandbox"
        )
    return result


def serialized_claim_value(claim: dict, report: dict, expected: dict):
    path = claim["target"]["path"]
    set_like = path.startswith("/OCI/Process/Capabilities/") or path in {
        "/OCI/Process/EnvRegex",
        "/request_defaults/CreateContainerRequest/allow_env_regex",
    }
    if not set_like:
        return claim.get("value")
    target = claim["target"]
    if target.get("scope") == "policy" or target.get("subject") == "policy":
        return coverage.composition.get_pointer(expected, path)
    subjects = report["static_policy"]["subjects"]
    if "subject" in target:
        selected = [subject for subject in subjects if subject["id"] == target["subject"]]
    else:
        selected = [
            subject
            for subject in subjects
            if target["role"] == "all"
            or subject["id"].startswith(
                "container/" if target["role"] == "application" else "sandbox/"
            )
        ]
    values = [
        coverage.composition.get_pointer(expected["containers"][subject["ordinal"]], path)
        for subject in selected
    ]
    if not values or any(value != values[0] for value in values[1:]):
        raise ValueError(f"set-like role claim has non-identical serialized values: {path}")
    return values[0]


def regorus_fragments(report: dict, expected: dict) -> list[dict]:
    fragments = copy.deepcopy(report["fragments"] + report["materialization_sets"])
    for fragment in fragments:
        for claim in fragment["claims"]:
            if claim["operation"] != "remove":
                claim["value"] = serialized_claim_value(claim, report, expected)
                claim["addition"] = sparse_patch(claim["target"]["path"], claim["value"])
    return fragments


def reviewed_profile_fragments(directory: Path) -> list[dict]:
    fragments = []
    for path in sorted(directory.glob("*.rego")):
        source = path.read_text(encoding="utf-8")
        marker = "fragment := "
        if marker not in source:
            continue
        fragments.append(json.loads(source.split(marker, 1)[1]))
    if not fragments:
        raise ValueError(f"no reviewed profile fragments in {directory}")
    return fragments


def validate_reviewed_profile_fragments(
    candidates: list[dict],
    materializations: list[dict],
    reviewed: list[dict],
    expected: dict | None = None,
) -> None:
    for fragment in reviewed:
        if fragment.get("scope") != "profile":
            raise ValueError("reviewed fragment must have profile scope")
        applies_to = fragment.get("applies_to")
        if not isinstance(applies_to, dict):
            raise ValueError("reviewed fragment must declare applies_to")
        for dimension, allowed in applies_to.items():
            if (
                not isinstance(allowed, list)
                or not allowed
                or any(not isinstance(value, str) for value in allowed)
            ):
                raise ValueError(
                    f"applies_to {dimension} must be a non-empty list of strings"
                )
        for contract in fragment.get("materialization_contracts", []):
            if "paths" in contract:
                paths = contract["paths"]
                if not paths or any(
                    not isinstance(path, str) or not path.startswith("/")
                    for path in paths
                ):
                    raise ValueError("materialization contract paths must be exact pointers")
            else:
                pattern = contract.get("path_regex", "")
                if not pattern.startswith("^") or not pattern.endswith("$"):
                    raise ValueError("materialization contract regex must be anchored")
        for claim in fragment.get("claims", []):
            if claim.get("evidence") == "profile-compatibility-contract" and (
                fragment["category"] != "policy-framework-settings"
                or claim.get("operation") != "default"
                or claim.get("target", {}).get("scope") != "policy"
                or not claim.get("target", {}).get("path", "").startswith("/")
                or claim.get("addition")
                != sparse_patch(claim["target"]["path"], claim.get("value"))
            ):
                raise ValueError(
                    "profile compatibility claims must be exact policy defaults"
                )
    for candidate in candidates:
        compatibility_paths = [
            claim["target"]["path"]
            for fragment in reviewed
            if fragment["category"] == candidate["category"]
            for claim in fragment.get("claims", [])
            if claim.get("evidence") == "profile-compatibility-contract"
        ]
        reviewed_claims = [
            claim
            for fragment in reviewed
            if fragment["category"] == candidate["category"]
            for claim in fragment.get("claims", [])
            if claim.get("evidence") != "profile-compatibility-contract"
        ]
        uncovered_candidate_claims = [
            claim
            for claim in candidate["claims"]
            if not any(
                claim["target"]["path"] == path
                or claim["target"]["path"].startswith(path + "/")
                for path in compatibility_paths
            )
        ]
        candidate_paths = {claim["target"]["path"] for claim in uncovered_candidate_claims}
        claims = [
            claim for claim in reviewed_claims if claim["target"]["path"] in candidate_paths
        ]
        producer_claims = [
            claim for claim in reviewed_claims if claim["target"]["path"] not in candidate_paths
        ]
        if expected is None and producer_claims:
            raise ValueError("canonical policy is required to verify producer claims")
        for claim in producer_claims:
            try:
                produced = coverage.composition.get_pointer(expected, claim["target"]["path"])
            except (KeyError, IndexError, TypeError, coverage.composition.CompositionError):
                raise ValueError(
                    f"compiler omitted reviewed claim {claim['target']['path']}"
                ) from None
            if produced != claim["value"]:
                raise ValueError(
                    f"compiler value differs from reviewed claim {claim['target']['path']}"
                )
        if claims != uncovered_candidate_claims:
            raise ValueError(
                f"reviewed {candidate['category']} claims do not cover candidate mutations: "
                f"reviewed={[claim['target']['path'] for claim in claims]}, "
                f"candidate={[claim['target']['path'] for claim in uncovered_candidate_claims]}"
            )
    for materialization in materializations:
        contracts = [
            contract
            for fragment in reviewed
            if fragment["category"] == materialization["category"]
            for contract in fragment.get("materialization_contracts", [])
        ]
        for claim in materialization["claims"]:
            if not any(
                claim["operation"] in contract["operations"]
                and (
                    claim["target"]["path"] in contract.get("paths", [])
                    or re.fullmatch(
                        contract.get("path_regex", "^$"),
                        claim["target"]["path"],
                    )
                )
                for contract in contracts
            ):
                raise ValueError(
                    f"no reviewed materialization contract for "
                    f"{materialization['category']} {claim['operation']} "
                    f"{claim['target']['path']}"
                )


def apply_profile_policy_defaults(policy: dict, reviewed: list[dict]) -> None:
    for fragment in reviewed:
        for claim in fragment.get("claims", []):
            if (
                claim.get("operation") == "default"
                and claim.get("target", {}).get("scope") == "policy"
            ):
                tokens = coverage.composition.pointer_tokens(claim["target"]["path"])
                parent = policy
                for token in tokens[:-1]:
                    child = parent.setdefault(token, {})
                    if not isinstance(child, dict):
                        raise ValueError("profile compatibility path crosses a non-object")
                    parent = child
                leaf = tokens[-1]
                value = claim["value"]
                if leaf in parent and parent[leaf] != value:
                    raise ValueError(
                        f"profile policy default conflicts at {claim['target']['path']}"
                    )
                parent[leaf] = copy.deepcopy(value)


def service_link_materialization_paths(static_ir: dict) -> set[str]:
    paths = {"/OCI/Process/EnvRegex"}
    for service in static_ir.get("services", []) + PLATFORM_SERVICES:
        prefix = service["name"].replace("-", "_").upper()
        for port in service["ports"]:
            if port.get("name"):
                name = port["name"].replace("-", "_").upper()
                paths.add(f"/OCI/Process/Env/{prefix}_SERVICE_PORT_{name}")
    return paths


def environment_resolution_paths(static_ir: dict) -> set[str]:
    return {
        resolution["target"]["path"]
        for subject in static_ir.get("subjects", [])
        for resolution in subject.get("environment_resolutions", [])
    }


PROFILE_GENERATED_KUBELET_CONTAINERD_PATHS = {
    "/OCI/Annotations/io.katacontainers.pkg.oci.bundle_path",
    "/OCI/Annotations/io.katacontainers.pkg.oci.container_type",
    "/OCI/Annotations/io.kubernetes.cri.sandbox-id",
    "/OCI/Annotations/io.kubernetes.cri.sandbox-log-directory",
    "/OCI/Annotations/io.kubernetes.cri.sandbox-namespace",
    "/OCI/Annotations/nerdctl~1network-namespace",
    "/OCI/Linux/Devices",
    "/OCI/Linux/MaskedPaths",
    "/OCI/Linux/ReadonlyPaths",
    "/OCI/Linux/Sysctl/net.ipv4.ip_unprivileged_port_start",
    "/OCI/Linux/Sysctl/net.ipv4.ping_group_range",
    "/OCI/Process/Capabilities/Ambient",
    "/OCI/Process/Capabilities/Bounding",
    "/OCI/Process/Capabilities/Effective",
    "/OCI/Process/Capabilities/Inheritable",
    "/OCI/Process/Capabilities/Permitted",
    "/OCI/Process/NoNewPrivileges",
    "/OCI/Process/Terminal",
    "/OCI/Root/Readonly",
}


def remove_profile_generated_materializations(
    materializations: list[dict], static_ir: dict
) -> list[dict]:
    generated_paths = service_link_materialization_paths(static_ir)
    resolution_paths = environment_resolution_paths(static_ir)
    static_subjects = {
        subject["subject"]: subject for subject in static_ir.get("subjects", [])
    }
    result = copy.deepcopy(materializations)
    for fragment in result:
        if fragment["category"] == "kubelet-resolution":
            fragment["claims"] = [
                claim
                for claim in fragment["claims"]
                if claim["target"]["path"] not in resolution_paths
            ]
            continue
        if fragment["category"] != "kubelet-or-containerd":
            if fragment["category"] == "runtime-rs-envelope":
                fragment["claims"] = [
                    claim
                    for claim in fragment["claims"]
                    if not (
                        claim["target"]["path"]
                        in {
                            "/devices",
                            "/request_defaults/CopyFileRequest",
                            "/runtime_anno_patterns",
                        }
                        or claim["target"]["path"].startswith(
                            "/runtime_anno_patterns/"
                        )
                        or (
                            claim["target"]["path"] == "/storages"
                            and volume_policy_supported(
                                static_subjects.get(
                                    claim["target"].get("subject")
                                )
                            )
                        )
                    )
                ]
            continue
        fragment["claims"] = [
            claim
            for claim in fragment["claims"]
            if not (
                claim["target"]["path"]
                in generated_paths | PROFILE_GENERATED_KUBELET_CONTAINERD_PATHS
                or (
                    claim["target"]["path"] == "/OCI/Mounts"
                    and volume_policy_supported(
                        static_subjects.get(claim["target"].get("subject"))
                    )
                )
            )
        ]
    return [fragment for fragment in result if fragment["claims"]]


def volume_policy_supported(subject: dict | None) -> bool:
    if subject is None:
        return False
    for volume in subject.get("volumes", []):
        if volume.get("mount_propagation") not in {None, ""}:
            return False
        if volume.get("recursive_read_only") not in {None, False}:
            return False
        if volume.get("sub_path") not in {None, ""}:
            return False
        if volume.get("role") == "empty-dir":
            if volume.get("medium") not in {"memory", "node-default"}:
                return False
            if "size_limit" in volume:
                return False
        elif volume.get("role") in {"config-map", "secret"}:
            if (volume.get("source") or {}).get("content_trust") != "untrusted-runtime":
                return False
            if re.fullmatch(
                r"[A-Za-z0-9_-]+", volume.get("destination_basename", "")
            ) is None:
                return False
        elif volume.get("role") == "direct-volume":
            uvm = volume.get("uvm") or {}
            if uvm != {
                "content_trust": "untrusted-runtime",
                "transport": "shared-fs",
            }:
                return False
            if re.fullmatch(
                r"[A-Za-z0-9_-]+", volume.get("destination_basename", "")
            ) is None:
                return False
        else:
            return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument(
        "--rootfs-mode",
        required=True,
        choices=("guest-pull", "erofs-dmverity"),
    )
    parser.add_argument("--uvm-baseline", required=True, type=Path)
    parser.add_argument("--rootfs-artifacts", type=Path)
    parser.add_argument("--compiler-policy", required=True, type=Path)
    parser.add_argument("--tag-manifest", required=True, type=Path)
    parser.add_argument("--tagged-requests-dir", required=True, type=Path)
    parser.add_argument("--source-report", required=True, type=Path)
    parser.add_argument("--profile-fragments-dir", required=True, type=Path)
    parser.add_argument("--static-output", required=True, type=Path)
    parser.add_argument("--materializations-output", required=True, type=Path)
    parser.add_argument("--expected-output", required=True, type=Path)
    args = parser.parse_args()

    static_ir = static_policy.generate_static_ir(
        args.capture,
        rootfs_mode=args.rootfs_mode,
        uvm_baseline_path=args.uvm_baseline,
        rootfs_artifacts_path=args.rootfs_artifacts,
    )
    expected = production_safe_policy(
        static_policy.policy_data(args.compiler_policy),
        json.loads(args.tag_manifest.read_text(encoding="utf-8")),
        [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(args.tagged_requests_dir.glob("*.tagged.json"))
        ],
        static_ir,
    )
    source_report = json.loads(args.source_report.read_text(encoding="utf-8"))
    report = coverage.derive_candidate_coverage(static_ir, expected, source_report)
    profile = json.loads((args.capture / "profile.json").read_text(encoding="utf-8"))
    report = coverage.bind_profile(report, static_ir, profile)
    candidate_sets = regorus_fragments(report, expected)
    candidate_profiles = [item for item in candidate_sets if item["scope"] == "profile"]
    materializations = [
        item for item in candidate_sets if item["scope"] == "static-base-materialization"
    ]
    materializations = remove_profile_generated_materializations(
        materializations, static_ir
    )
    reviewed_profiles = reviewed_profile_fragments(args.profile_fragments_dir)
    apply_profile_policy_defaults(expected, reviewed_profiles)
    validate_reviewed_profile_fragments(
        candidate_profiles, materializations, reviewed_profiles, expected
    )

    args.static_output.write_text(
        render_module(
            "static_policy_ir", "ir", regorus_static_ir(report, static_ir, profile)
        ),
        encoding="utf-8",
    )
    args.materializations_output.write_text(
        render_module(
            "selected_materializations", "materializations", materializations
        ),
        encoding="utf-8",
    )
    args.expected_output.write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()