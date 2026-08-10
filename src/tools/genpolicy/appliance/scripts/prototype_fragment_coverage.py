#!/usr/bin/env python3

import argparse
import copy
import hashlib
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
composition = load_module(
    "compose_policy_fragments",
    SCRIPT_DIR / "compose_policy_fragments.py",
)
static_policy = load_module(
    "prototype_static_policy",
    SCRIPT_DIR / "prototype_static_policy.py",
)


class CoverageError(ValueError):
    pass


REPO_ROOT = Path(__file__).resolve().parents[5]


def validate_source_reference(reference: str, kind: str) -> None:
    try:
        relative_path, symbol = reference.split(": ", 1)
    except ValueError as error:
        raise CoverageError(f"runtime validator {kind} must use 'path: symbol'") from error
    path = (REPO_ROOT / relative_path).resolve()
    try:
        path.relative_to(REPO_ROOT)
    except ValueError as error:
        raise CoverageError(f"runtime validator {kind} escapes the repository") from error
    if not path.is_file():
        raise CoverageError(f"runtime validator {kind} file does not exist: {relative_path}")
    if re.search(rf"\b{re.escape(symbol)}\b", path.read_text(encoding="utf-8")) is None:
        raise CoverageError(
            f"runtime validator {kind} symbol does not exist: {reference}"
        )


WORKLOAD_DERIVED_POLICY_PATHS = {
    "/request_defaults/CopyFileRequest",
    "/request_defaults/CreateContainerRequest/allow_env_regex",
}
CONTAINER_TYPE_PATH = "/OCI/Annotations/io.kubernetes.cri.container-type"
PROFILE_CONTAINER_ROLE_CLAIMS = (
    {"path": "/OCI/Version", "role": "all"},
    {"path": CONTAINER_TYPE_PATH, "role": "application", "value": "container"},
    {"path": CONTAINER_TYPE_PATH, "role": "sandbox", "value": "sandbox"},
)
WORKLOAD_APPLICATION_ROLE_PATHS = {"/OCI/Process/EnvRegex"}


def materialization_scope(subject: str, path: str, value=None) -> str:
    if subject == "policy" and path == "/request_defaults/CopyFileRequest":
        return "static-base-materialization"
    if subject != "policy" or (
        path in WORKLOAD_DERIVED_POLICY_PATHS and value != []
    ):
        return "static-base-materialization"
    return "profile"


def escaped_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def child_path(path: str, token: str) -> str:
    return f"{path}/{escaped_token(token)}"


def set_pointer(document: dict, pointer: str, value) -> None:
    tokens = composition.pointer_tokens(pointer)
    if not tokens:
        raise CoverageError("static constraint cannot replace a subject root")
    parent = document
    for token in tokens[:-1]:
        child = parent.setdefault(token, {})
        if not isinstance(child, dict):
            raise CoverageError(f"static constraint parent is not an object: {pointer}")
        parent = child
    if tokens[-1] in parent:
        raise CoverageError(f"duplicate static constraint: {pointer}")
    parent[tokens[-1]] = copy.deepcopy(value)


def environment_map(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        name, separator, content = value.partition("=")
        if not separator or not name or name in result:
            raise CoverageError(f"invalid or duplicate environment entry: {value}")
        result[name] = content
    return result


def expected_subject_policy(container: dict, encodings: dict[str, str]) -> dict:
    result = copy.deepcopy(container)
    for pointer, encoding in encodings.items():
        if encoding != "env-map":
            raise CoverageError(f"unsupported collection encoding: {encoding}")
        parent, token = composition.pointer_parent(result, pointer)
        parent[token] = environment_map(parent[token])
    return result


def sparse_static_policy(static_ir: dict, expected: dict) -> tuple[dict, dict[str, dict]]:
    mapped = static_policy.policy_subjects(expected, static_ir)
    static_subjects = {subject["subject"]: subject for subject in static_ir["subjects"]}
    by_object = {id(policy): subject for subject, policy in mapped.items()}
    subjects = []
    normalized_expected = {}
    for ordinal, container in enumerate(expected.get("containers", [])):
        subject_id = by_object.get(id(container))
        if subject_id is None or subject_id not in static_subjects:
            raise CoverageError(f"final policy container {ordinal} has no stable static subject")
        source = static_subjects[subject_id]
        policy = {}
        encodings = {}
        for pointer, value in source["constraints"].items():
            if pointer == "/OCI/Process/Env" and isinstance(value, dict):
                encodings[pointer] = "env-map"
            set_pointer(policy, pointer, value)
        subjects.append(
            {
                "collection_encodings": encodings,
                "id": subject_id,
                "ordinal": ordinal,
                "policy": policy,
            }
        )
        normalized_expected[subject_id] = expected_subject_policy(container, encodings)
    missing = set(static_subjects) - {subject["id"] for subject in subjects}
    if missing:
        raise CoverageError(f"static subjects absent from final policy: {sorted(missing)}")
    return {"policy_data": {}, "subjects": subjects}, normalized_expected


def missing_leaves(actual, expected, path=""):
    if isinstance(actual, dict):
        if not isinstance(expected, dict):
            raise CoverageError(f"static type conflicts with final policy at {path or '/'}")
        extra = set(actual) - set(expected)
        if extra:
            raise CoverageError(
                f"static fields absent from final policy at {path or '/'}: {sorted(extra)}"
            )
        for key, expected_value in expected.items():
            pointer = child_path(path, key)
            if key in actual:
                yield from missing_leaves(actual[key], expected_value, pointer)
            else:
                yield from all_leaves(expected_value, pointer)
        return
    if actual != expected:
        raise CoverageError(f"static value conflicts with final policy at {path or '/'}")


def all_leaves(value, path: str):
    if isinstance(value, dict) and value:
        for key, child in value.items():
            yield from all_leaves(child, child_path(path, key))
    else:
        yield path, copy.deepcopy(value)


def canonical_claim_value(path: str, value):
    capability_prefix = "/OCI/Process/Capabilities/"
    if path.startswith(capability_prefix) and isinstance(value, list):
        return sorted(value)
    if path in {
        "/OCI/Process/EnvRegex",
        "/request_defaults/CreateContainerRequest/allow_env_regex",
    } and isinstance(value, list):
        return sorted(value)
    return value


def request_policy_path(path: str) -> str:
    names = {
        "devices": "Devices",
        "linux": "Linux",
        "resources": "Resources",
        "seccomp": "Seccomp",
    }
    tokens = composition.pointer_tokens(path)
    return "/OCI/" + "/".join(names.get(token, token) for token in tokens)


def request_subjects(capture: Path, static_ir: dict) -> dict[str, str]:
    sandboxes = [
        subject["subject"]
        for subject in static_ir["subjects"]
        if subject["subject"].startswith("sandbox/")
    ]
    result = {}
    for path in (capture / "createcontainer-requests").glob("*.json"):
        request = json.loads(path.read_text(encoding="utf-8"))
        annotations = (request.get("oci") or {}).get("annotations") or {}
        if annotations.get("io.kubernetes.cri.container-type") == "container":
            subject = f"container/{annotations.get('io.kubernetes.cri.container-name', '')}"
        elif len(sandboxes) == 1:
            subject = sandboxes[0]
        else:
            continue
        result[path.name] = subject
    return result


def observed_request_absences(capture: Path, static_ir: dict) -> list[dict]:
    transformations, _ = static_policy.request_provenance.analyze(capture)
    subjects = request_subjects(capture, static_ir)
    result = []
    for request in transformations["requests"]:
        subject = subjects.get(request["identity"]["file"])
        if subject is None:
            continue
        for change in request["changes"]:
            if change["change"] == "removed" and change["path"].startswith("/linux/"):
                result.append(
                    {
                        "evidence": request["identity"]["file"],
                        "path": request_policy_path(change["path"]),
                        "subject": subject,
                    }
                )
    return result


def request_absence_coverage(observed: list[dict], inventory: dict | None) -> dict:
    if inventory is None:
        rules = []
        inventory_status = "missing"
    else:
        if inventory.get("schema_version") != 1 or not isinstance(
            inventory.get("rules"), list
        ):
            raise CoverageError("invalid runtime absence inventory")
        rules = inventory["rules"]
        for rule in rules:
            if not isinstance(rule, dict):
                raise CoverageError("runtime absence rule must be an object")
            if not all(
                isinstance(rule.get(field), str) and rule[field]
                for field in ("category", "evidence", "path")
            ):
                raise CoverageError("runtime absence rule requires category, evidence, and path")
            composition.pointer_tokens(rule["path"])
            scopes = [
                rule.get("all_subjects") is True,
                isinstance(rule.get("subject"), str) and bool(rule["subject"]),
                isinstance(rule.get("subject_prefix"), str)
                and bool(rule["subject_prefix"]),
            ]
            if sum(scopes) != 1:
                raise CoverageError("runtime absence rule requires exactly one subject scope")
        inventory_status = "loaded"
    entries = []
    for absence in observed:
        matches = [
            rule
            for rule in rules
            if rule.get("path") == absence["path"]
            and (
                rule.get("all_subjects") is True
                or rule.get("subject") == absence["subject"]
                or absence["subject"].startswith(rule.get("subject_prefix", "\0"))
            )
        ]
        if len(matches) > 1:
            raise CoverageError(
                f"multiple runtime absence rules cover {absence['subject']} {absence['path']}"
            )
        entry = {**absence, "status": "covered" if matches else "uncovered"}
        if matches:
            entry["category"] = matches[0]["category"]
            entry["rule_evidence"] = matches[0]["evidence"]
        entries.append(entry)
    return {
        "covered": sum(entry["status"] == "covered" for entry in entries),
        "entries": entries,
        "inventory": inventory_status,
        "observed": len(entries),
        "uncovered": sum(entry["status"] == "uncovered" for entry in entries),
    }


def runtime_validator_coverage(report: dict, inventory: dict | None) -> dict:
    if inventory is None:
        validators = []
        inventory_status = "missing"
    else:
        if inventory.get("schema_version") != 1 or not isinstance(
            inventory.get("validators"), list
        ):
            raise CoverageError("invalid runtime validator inventory")
        validators = inventory["validators"]
        for validator in validators:
            if not isinstance(validator, dict):
                raise CoverageError("runtime validator must be an object")
            if not all(
                isinstance(validator.get(field), str) and validator[field]
                for field in ("category", "evidence", "path", "test")
            ):
                raise CoverageError(
                    "runtime validator requires category, evidence, path, and test"
                )
            composition.pointer_tokens(validator["path"])
            validate_source_reference(validator["evidence"], "evidence")
            validate_source_reference(validator["test"], "test")
            if validator.get("role") is not None and (
                not isinstance(validator["role"], str) or not validator["role"]
            ):
                raise CoverageError("runtime validator role must be a non-empty string")
        inventory_status = "loaded"

    claims = [
        {"category": fragment["category"], **claim}
        for fragment in report.get("fragments", [])
        for claim in fragment.get("claims", [])
    ]
    entries = []
    for claim in claims:
        target = claim["target"]
        matches = [
            validator
            for validator in validators
            if validator["category"] == claim["category"]
            and validator["path"] == target["path"]
            and (
                validator.get("role") is None
                or validator["role"] == target.get("role")
            )
        ]
        if len(matches) > 1:
            raise CoverageError(
                "multiple runtime validators cover "
                f"{claim['category']} {target.get('role', 'policy')} {target['path']}"
            )
        entry = {
            "category": claim["category"],
            "operation": claim["operation"],
            "path": target["path"],
            "role": target.get("role"),
            "status": "covered" if matches else "uncovered",
        }
        if matches:
            entry["rule_evidence"] = matches[0]["evidence"]
            entry["negative_test"] = matches[0]["test"]
        entries.append(entry)
    return {
        "covered": sum(entry["status"] == "covered" for entry in entries),
        "entries": entries,
        "inventory": inventory_status,
        "required": len(entries),
        "uncovered": sum(entry["status"] == "uncovered" for entry in entries),
    }


def bind_profile(report: dict, static_ir: dict, profile: dict) -> dict:
    identity = profile.get("identity")
    if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise CoverageError("capture profile requires a sha256 identity")
    static_base_digest = "sha256:" + hashlib.sha256(
        json.dumps(static_ir, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    uvm_artifacts = sorted(
        {
            subject["static_artifact"]
            for subject in static_ir["subjects"]
            if "static_artifact" in subject
        }
    )
    profile_uvm_digest = (profile.get("values") or {}).get("UVM_IMAGE_DIGEST")
    if profile_uvm_digest and not str(profile_uvm_digest).startswith("sha256:"):
        profile_uvm_digest = f"sha256:{profile_uvm_digest}"
    binding = {
        "profile_identity": identity,
        "profile_uvm_digest": profile_uvm_digest,
        "static_base_digest": static_base_digest,
        "uvm_artifacts": uvm_artifacts,
        "uvm_bound": bool(uvm_artifacts) and profile_uvm_digest in uvm_artifacts,
    }
    report["binding"] = binding
    report["static_policy"]["profile_identity"] = identity
    report["static_policy"]["static_base_digest"] = static_base_digest
    for fragment in report["fragments"]:
        fragment["profile_identity"] = identity
        fragment.pop("static_base_digest", None)
    for candidate in report.get("materialization_sets", []):
        candidate["profile_identity"] = identity
        candidate["static_base_digest"] = static_base_digest
    candidate_sets = report["fragments"] + report.get("materialization_sets", [])
    composition.validate_fragment_bindings(
        report["static_policy"], candidate_sets
    )
    return report


def finalize_report(
    report: dict,
    absence_coverage: dict,
    validator_coverage: dict,
    binding: dict | None = None,
) -> dict:
    report["request_absence_coverage"] = absence_coverage
    report["runtime_validator_coverage"] = validator_coverage
    blockers = []
    ambiguous = report["coverage"]["ambiguous_boundary_claims"]
    if ambiguous:
        blockers.append(f"{ambiguous} claims have ambiguous component ownership")
    if absence_coverage["inventory"] != "loaded":
        blockers.append("runtime absence inventory is missing")
    if absence_coverage["uncovered"]:
        blockers.append(
            f"{absence_coverage['uncovered']} observed runtime absences are uncovered"
        )
    if validator_coverage["inventory"] != "loaded":
        blockers.append("runtime validator inventory is missing")
    if validator_coverage["uncovered"]:
        blockers.append(
            f"{validator_coverage['uncovered']} fragment claims have no runtime validator"
        )
    if binding is None or not binding.get("uvm_bound"):
        blockers.append("capture profile does not bind the measured UVM artifact")
    workload_bound = report["coverage"].get("workload_bound_materialization_claims", 0)
    if workload_bound:
        blockers.append(
            f"{workload_bound} claims depend on workload subjects or values and are not reusable fragments"
        )
    report["blockers"] = blockers
    report["result"] = "pass" if not blockers else "incomplete"
    return report


def report_sources(source_report: dict, static_ir: dict) -> dict[str, dict[str, str]]:
    static_sandboxes = [
        subject["subject"]
        for subject in static_ir["subjects"]
        if subject["subject"].startswith("sandbox/")
    ]
    result = {}
    for container in source_report.get("containers", []):
        identity = container.get("identity", {})
        if identity.get("container_type") == "container":
            subject = f"container/{identity.get('container_name', '')}"
        elif len(static_sandboxes) == 1:
            subject = static_sandboxes[0]
        else:
            continue
        result[subject] = {
            path: evidence.get("source", "unclassified")
            for path, evidence in container.get("fields", {}).items()
        }
    return result


def nearest_source(sources: dict[str, str], path: str) -> str | None:
    matches = [source for prefix, source in sources.items() if path == prefix or path.startswith(prefix + "/")]
    return matches[0] if len(set(matches)) == 1 else None


def claim_classification(
    subject: str,
    path: str,
    unresolved: set[str],
    sources: dict[str, str],
) -> tuple[str, str, str]:
    if subject == "policy":
        if path == "/request_defaults/CopyFileRequest":
            return (
                "runtime-rs-envelope",
                "envelope",
                "trusted-resource-volume-intent",
            )
        if path in WORKLOAD_DERIVED_POLICY_PATHS:
            return (
                "policy-framework-settings",
                "default",
                "workload-service-objects+cluster-state",
            )
        return "policy-framework-settings", "default", "compiler-settings"
    if path == "/OCI/Version":
        return "containerd-oci", "default", "captured-oci"
    if path == CONTAINER_TYPE_PATH:
        return "containerd-oci", "default", "cri-container-role"
    env_prefix = "/OCI/Process/Env/"
    if path.startswith(env_prefix):
        name = composition.pointer_tokens(path)[-1]
        if name in unresolved:
            return "kubelet-resolution", "resolve", "workload-valueFrom"
        if name == "HOSTNAME":
            return "kubelet-resolution", "resolve", "kubelet-hostname"
        return "kubelet-or-containerd", "resolve", "missing-kubelet-CRI-boundary"
    source = nearest_source(sources, path)
    if path == "/OCI/Root/Path" or (source and source.startswith("settings-kata")):
        return "runtime-rs", "rewrite", source or "runtime-rootfs-rewrite"
    if not path.startswith("/OCI/"):
        return "runtime-rs-envelope", "envelope", source or "agent-request-envelope"
    return "kubelet-or-containerd", "default", source or "missing-kubelet-CRI-boundary"


def subject_fanout(fragments: list[dict], static_ir: dict) -> list[dict]:
    all_subjects = {subject["subject"] for subject in static_ir["subjects"]}
    application_subjects = {
        subject for subject in all_subjects if subject.startswith("container/")
    }
    sandbox_subjects = all_subjects - application_subjects
    grouped = {}
    for fragment in fragments:
        for claim in fragment["claims"]:
            subject = claim["target"].get("subject")
            if subject is None:
                continue
            if subject == "policy":
                continue
            grouped.setdefault(claim["target"]["path"], []).append(
                (fragment["category"], subject, claim)
            )

    analysis = []
    for path, entries in sorted(grouped.items()):
        subjects = {entry[1] for entry in entries}
        if subjects == all_subjects:
            target_population = "all-subjects"
        elif subjects == application_subjects:
            target_population = "all-application-containers"
        elif subjects == sandbox_subjects:
            target_population = "all-sandboxes"
        elif len(subjects) == 1:
            target_population = "single-subject"
        else:
            target_population = "subject-subset"
        values = {
            json.dumps(entry[2].get("value"), sort_keys=True, separators=(",", ":"))
            for entry in entries
        }
        analysis.append(
            {
                "categories": sorted({entry[0] for entry in entries}),
                "claim_count": len(entries),
                "distinct_values": len(values),
                "evidence": sorted({entry[2]["evidence"] for entry in entries}),
                "path": path,
                "subjects": sorted(subjects),
                "target_population": target_population,
                "value_shape": "identical" if len(values) == 1 else "subject-specific",
            }
        )
    return analysis


def promote_profile_container_roles(
    claims_by_category: dict[str, list[dict]], ledger: list[dict], static_ir: dict
) -> None:
    all_subjects = {subject["subject"] for subject in static_ir["subjects"]}
    subjects_by_role = {
        "all": all_subjects,
        "application": {
            subject for subject in all_subjects if subject.startswith("container/")
        },
        "sandbox": {
            subject for subject in all_subjects if subject.startswith("sandbox/")
        },
    }
    for category, claims in claims_by_category.items():
        for role_claim in PROFILE_CONTAINER_ROLE_CLAIMS:
            path = role_claim["path"]
            role = role_claim["role"]
            selected_subjects = subjects_by_role[role]
            candidates = [
                claim
                for claim in claims
                if claim["scope"] == "static-base-materialization"
                and claim["target"]["path"] == path
                and claim["target"]["subject"] in selected_subjects
            ]
            subjects = {claim["target"]["subject"] for claim in candidates}
            values = {
                json.dumps(claim["value"], sort_keys=True, separators=(",", ":"))
                for claim in candidates
            }
            operations = {claim["operation"] for claim in candidates}
            evidence = {claim["evidence"] for claim in candidates}
            if (
                not selected_subjects
                or subjects != selected_subjects
                or len(values) != 1
                or len(operations) != 1
                or len(evidence) != 1
            ):
                continue
            if "value" in role_claim and values != {
                json.dumps(
                    role_claim["value"], sort_keys=True, separators=(",", ":")
                )
            }:
                continue
            for claim in candidates:
                claims.remove(claim)
            role_claim = copy.deepcopy(candidates[0])
            role_claim["scope"] = "profile"
            role_claim["target"] = {
                "cardinality": "all",
                "path": path,
                "role": role,
                "scope": "container",
            }
            claims.append(role_claim)
            ledger[:] = [
                entry
                for entry in ledger
                if not (
                    entry["owner"] == "materialization"
                    and entry["category"] == category
                    and entry["path"] == path
                    and entry["subject"] in subjects
                )
            ]
            ledger.append(
                {
                    "category": category,
                    "evidence": role_claim["evidence"],
                    "operation": role_claim["operation"],
                    "owner": "fragment",
                    "path": path,
                    "scope": "profile",
                    "subject": f"role:container/{role}",
                }
            )


def coalesce_workload_application_roles(
    claims_by_category: dict[str, list[dict]], ledger: list[dict], static_ir: dict
) -> None:
    application_subjects = {
        subject["subject"]
        for subject in static_ir["subjects"]
        if subject["subject"].startswith("container/")
    }
    for category, claims in claims_by_category.items():
        for path in WORKLOAD_APPLICATION_ROLE_PATHS:
            candidates = [
                claim
                for claim in claims
                if claim["scope"] == "static-base-materialization"
                and claim["target"].get("path") == path
                and claim["target"].get("subject") in application_subjects
            ]
            subjects = {claim["target"]["subject"] for claim in candidates}
            values = {
                json.dumps(claim["value"], sort_keys=True, separators=(",", ":"))
                for claim in candidates
            }
            operations = {claim["operation"] for claim in candidates}
            evidence = {claim["evidence"] for claim in candidates}
            if (
                not application_subjects
                or subjects != application_subjects
                or len(values) != 1
                or len(operations) != 1
                or len(evidence) != 1
            ):
                continue
            for claim in candidates:
                claims.remove(claim)
            role_claim = copy.deepcopy(candidates[0])
            role_claim["target"] = {
                "cardinality": "all",
                "path": path,
                "role": "application",
                "scope": "container",
            }
            claims.append(role_claim)
            ledger[:] = [
                entry
                for entry in ledger
                if not (
                    entry["owner"] == "materialization"
                    and entry["category"] == category
                    and entry["path"] == path
                    and entry["subject"] in subjects
                )
            ]
            ledger.append(
                {
                    "category": category,
                    "evidence": role_claim["evidence"],
                    "operation": role_claim["operation"],
                    "owner": "materialization",
                    "path": path,
                    "scope": "static-base-materialization",
                    "subject": "role:container/application",
                }
            )


def derive_candidate_coverage(
    static_ir: dict,
    expected: dict,
    source_report: dict,
) -> dict:
    baseline, normalized_expected = sparse_static_policy(static_ir, expected)
    sources = report_sources(source_report, static_ir)
    unresolved = {
        subject["subject"]: {
            entry["target"]["name"]
            for entry in subject.get("environment_resolutions", [])
        }
        for subject in static_ir["subjects"]
    }
    claims_by_category = {}
    ledger = []
    for subject in static_ir["subjects"]:
        category = "uvm-static" if "static_artifact" in subject else "workload-static"
        for path, value in subject["constraints"].items():
            if path == "/OCI/Process/Env" and isinstance(value, dict):
                paths = [child_path(path, name) for name in value]
            else:
                paths = [path]
            ledger.extend(
                {
                    "category": category,
                    "evidence": (
                        "trusted-workload-yaml"
                        if owned_path
                        == "/OCI/Annotations/io.kubernetes.cri.container-name"
                        else subject.get("static_artifact", subject.get("image"))
                    ),
                    "operation": "derive",
                    "owner": "static",
                    "path": owned_path,
                    "subject": subject["subject"],
                }
                for owned_path in paths
            )
    expected_globals = {key: value for key, value in expected.items() if key != "containers"}
    differences = [("policy", path, value) for path, value in missing_leaves({}, expected_globals)]
    for subject in baseline["subjects"]:
        subject_id = subject["id"]
        differences.extend(
            (subject_id, path, value)
            for path, value in missing_leaves(
                subject["policy"], normalized_expected[subject_id]
            )
        )
    for subject, path, value in differences:
        value = canonical_claim_value(path, value)
        category, operation, evidence = claim_classification(
            subject,
            path,
            unresolved.get(subject, set()),
            sources.get(subject, {}),
        )
        claim = {
            "evidence": evidence,
            "operation": operation,
            "scope": materialization_scope(subject, path, value),
            "value": value,
        }
        claim["target"] = (
            {"path": path, "scope": "policy"}
            if claim["scope"] == "profile"
            else {"path": path, "subject": subject}
        )
        if path in WORKLOAD_DERIVED_POLICY_PATHS and value == []:
            claim["evidence"] = "compiler-security-default"
        owner = (
            "fragment"
            if claim["scope"] == "profile"
            else "materialization"
        )
        claims_by_category.setdefault(category, []).append(claim)
        ledger.append(
            {
                "category": category,
                "evidence": claim["evidence"],
                "operation": operation,
                "owner": owner,
                "path": path,
                "scope": claim["scope"],
                "subject": subject,
            }
        )
    promote_profile_container_roles(claims_by_category, ledger, static_ir)
    coalesce_workload_application_roles(claims_by_category, ledger, static_ir)
    fragments = []
    materialization_sets = []
    for category, claims in sorted(claims_by_category.items()):
        profile_claims = [claim for claim in claims if claim["scope"] == "profile"]
        workload_claims = [
            claim for claim in claims if claim["scope"] == "static-base-materialization"
        ]
        if profile_claims:
            fragments.append(
                {
                    "category": category,
                    "claims": profile_claims,
                    "schema_version": 1,
                    "scope": "profile",
                }
            )
        if workload_claims:
            materialization_sets.append(
                {
                    "category": category,
                    "claims": workload_claims,
                    "schema_version": 1,
                    "scope": "static-base-materialization",
                }
            )
    candidate_sets = fragments + materialization_sets
    composition.materialize(baseline, candidate_sets, expected)
    candidate_ledger = [entry for entry in ledger if entry["owner"] != "static"]
    fragment_ledger = [entry for entry in ledger if entry["owner"] == "fragment"]
    materialization_ledger = [
        entry for entry in ledger if entry["owner"] == "materialization"
    ]
    static_ledger = [entry for entry in ledger if entry["owner"] == "static"]
    workload_bound = len(materialization_ledger)
    workload_derived_globals = sum(
        entry["subject"] == "policy"
        for entry in materialization_ledger
    )
    ambiguous = sum(
        entry["category"] == "kubelet-or-containerd" for entry in candidate_ledger
    )
    return {
        "coverage": {
            "ambiguous_boundary_claims": ambiguous,
            "candidate_fragment_claims": len(fragment_ledger),
            "candidate_claims": len(candidate_ledger),
            "categories": {
                category: len(claims) for category, claims in sorted(claims_by_category.items())
            },
            "limitations": [
                "required absence inventory is not implemented",
                "kubelet and containerd ownership is ambiguous without a CRI capture boundary",
                "the measured UVM digest is not present in current capture profile manifests",
                "additional role classification and workload-parameter lowering are not implemented",
            ],
            "reconstruction": "pass",
            "materialization_claims": len(materialization_ledger),
            "reusable_profile_claims": len(fragment_ledger),
            "required_absence_claims": 0,
            "static_claims": len(static_ledger),
            "status": "materialization-only" if workload_bound else "experimental",
            "subject_fanout": subject_fanout(materialization_sets, static_ir),
            "workload_derived_global_claims": workload_derived_globals,
            "workload_bound_materialization_claims": workload_bound,
        },
        "fragments": fragments,
        "ledger": ledger,
        "materialization_sets": materialization_sets,
        "schema_version": 1,
        "static_policy": baseline,
    }


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
    parser.add_argument("--source-report", required=True, type=Path)
    parser.add_argument("--absence-inventory", type=Path)
    parser.add_argument("--validator-inventory", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    static_ir = static_policy.generate_static_ir(
        args.capture,
        rootfs_mode=args.rootfs_mode,
        uvm_baseline_path=args.uvm_baseline,
        rootfs_artifacts_path=args.rootfs_artifacts,
    )
    expected = static_policy.policy_data(args.compiler_policy)
    source_report = json.loads(args.source_report.read_text(encoding="utf-8"))
    report = derive_candidate_coverage(static_ir, expected, source_report)
    profile = json.loads((args.capture / "profile.json").read_text(encoding="utf-8"))
    report = bind_profile(report, static_ir, profile)
    inventory = (
        json.loads(args.absence_inventory.read_text(encoding="utf-8"))
        if args.absence_inventory is not None
        else None
    )
    validator_inventory = (
        json.loads(args.validator_inventory.read_text(encoding="utf-8"))
        if args.validator_inventory is not None
        else None
    )
    report = finalize_report(
        report,
        request_absence_coverage(
            observed_request_absences(args.capture, static_ir), inventory
        ),
        runtime_validator_coverage(report, validator_inventory),
        report["binding"],
    )
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["result"] != "pass" and not args.allow_incomplete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()