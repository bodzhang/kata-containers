#!/usr/bin/env python3

import argparse
import copy
import importlib.util
import json
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
    if path == "/request_defaults/CreateContainerRequest/allow_env_regex" and isinstance(
        value, list
    ):
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
        inventory_status = "loaded"
    entries = []
    for absence in observed:
        matches = [
            rule
            for rule in rules
            if rule.get("path") == absence["path"]
            and (
                rule.get("subject") in (None, absence["subject"])
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
        return "policy-framework-settings", "default", "compiler-settings"
    env_prefix = "/OCI/Process/Env/"
    if path.startswith(env_prefix):
        name = composition.pointer_tokens(path)[-1]
        if name in unresolved:
            return "kubelet-resolution", "resolve", "workload-valueFrom"
        return "kubelet-or-containerd", "resolve", "missing-kubelet-CRI-boundary"
    source = nearest_source(sources, path)
    if path == "/OCI/Root/Path" or (source and source.startswith("settings-kata")):
        return "runtime-rs", "rewrite", source or "runtime-rootfs-rewrite"
    if not path.startswith("/OCI/"):
        return "runtime-rs-envelope", "envelope", source or "agent-request-envelope"
    return "kubelet-or-containerd", "default", source or "missing-kubelet-CRI-boundary"


def derive_candidate_coverage(
    static_ir: dict,
    expected: dict,
    source_report: dict,
) -> dict:
    baseline, normalized_expected = sparse_static_policy(static_ir, expected)
    sources = report_sources(source_report, static_ir)
    unresolved = {
        subject["subject"]: {entry["name"] for entry in subject.get("unresolved", [])}
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
                    "evidence": subject.get("static_artifact", subject.get("image")),
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
            "target": {"path": path, "subject": subject},
            "value": value,
        }
        claims_by_category.setdefault(category, []).append(claim)
        ledger.append(
            {
                "category": category,
                "evidence": evidence,
                "operation": operation,
                "owner": "fragment",
                "path": path,
                "subject": subject,
            }
        )
    fragments = [
        {"category": category, "claims": claims, "schema_version": 1}
        for category, claims in sorted(claims_by_category.items())
    ]
    composition.materialize(baseline, fragments, expected)
    fragment_ledger = [entry for entry in ledger if entry["owner"] == "fragment"]
    static_ledger = [entry for entry in ledger if entry["owner"] == "static"]
    ambiguous = sum(
        entry["category"] == "kubelet-or-containerd" for entry in fragment_ledger
    )
    return {
        "coverage": {
            "ambiguous_boundary_claims": ambiguous,
            "candidate_fragment_claims": len(fragment_ledger),
            "categories": {
                category: len(claims) for category, claims in sorted(claims_by_category.items())
            },
            "limitations": [
                "required absence inventory is not implemented",
                "kubelet and containerd ownership is ambiguous without a CRI capture boundary",
                "the measured UVM digest is not present in current capture profile manifests",
            ],
            "reconstruction": "pass",
            "required_absence_claims": 0,
            "static_claims": len(static_ledger),
            "status": "experimental",
        },
        "fragments": fragments,
        "ledger": ledger,
        "schema_version": 1,
        "static_policy": baseline,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--uvm-baseline", required=True, type=Path)
    parser.add_argument("--compiler-policy", required=True, type=Path)
    parser.add_argument("--source-report", required=True, type=Path)
    parser.add_argument("--absence-inventory", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    static_ir = static_policy.generate_static_ir(args.capture, args.uvm_baseline)
    expected = static_policy.policy_data(args.compiler_policy)
    source_report = json.loads(args.source_report.read_text(encoding="utf-8"))
    report = derive_candidate_coverage(static_ir, expected, source_report)
    inventory = (
        json.loads(args.absence_inventory.read_text(encoding="utf-8"))
        if args.absence_inventory is not None
        else None
    )
    report["request_absence_coverage"] = request_absence_coverage(
        observed_request_absences(args.capture, static_ir), inventory
    )
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()