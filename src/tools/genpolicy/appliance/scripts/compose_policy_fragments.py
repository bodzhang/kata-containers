#!/usr/bin/env python3

import argparse
import copy
import json
from pathlib import Path


SEMANTIC_OPERATIONS = {
    "default",
    "derive",
    "envelope",
    "generate",
    "normalize",
    "remove",
    "resolve",
    "rewrite",
}
class CompositionError(ValueError):
    pass


def pointer_tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise CompositionError(f"invalid JSON pointer: {pointer}")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def get_pointer(document, pointer: str):
    value = document
    for token in pointer_tokens(pointer):
        if isinstance(value, list):
            try:
                value = value[int(token)]
            except (ValueError, IndexError) as error:
                raise CompositionError(f"pointer does not exist: {pointer}") from error
        elif isinstance(value, dict) and token in value:
            value = value[token]
        else:
            raise CompositionError(f"pointer does not exist: {pointer}")
    return value


def target_identity(target: dict) -> str:
    return json.dumps(target, sort_keys=True, separators=(",", ":"))


def resolve_target(document: dict, target: dict):
    subject = target.get("subject")
    if not isinstance(subject, str) or not subject:
        raise CompositionError("target subject must be a non-empty string")
    relative_pointer = target.get("path")
    if not isinstance(relative_pointer, str):
        raise CompositionError("target requires a string path")
    subjects = document.get("subjects", [])
    selected = [item for item in subjects if item.get("id") == subject]
    if len(selected) != 1:
        raise CompositionError(f"target subject matched {len(selected)} items: {subject}")
    return selected[0]["policy"], relative_pointer


def pointer_parent(document, pointer: str):
    tokens = pointer_tokens(pointer)
    if not tokens:
        raise CompositionError("a fragment cannot patch the selected object root")
    parent = document
    for token in tokens[:-1]:
        if isinstance(parent, list):
            try:
                parent = parent[int(token)]
            except (ValueError, IndexError) as error:
                raise CompositionError(f"pointer parent does not exist: {pointer}") from error
        elif isinstance(parent, dict) and token in parent:
            parent = parent[token]
        else:
            raise CompositionError(f"pointer parent does not exist: {pointer}")
    return parent, tokens[-1]


def has_child(parent, token: str) -> bool:
    if isinstance(parent, list):
        try:
            index = int(token)
        except ValueError:
            return False
        return 0 <= index < len(parent)
    return isinstance(parent, dict) and token in parent


def add_child(parent, token: str, value) -> None:
    if isinstance(parent, list):
        try:
            index = int(token)
        except ValueError as error:
            raise CompositionError(f"array target is not an index: {token}") from error
        if index == len(parent):
            parent.append(value)
        else:
            raise CompositionError("array add only supports appending at the next index")
    else:
        parent[token] = value


def validate_fragments(fragments: list[dict]) -> None:
    owners = {}
    for fragment in fragments:
        category = fragment.get("category")
        if not isinstance(category, str) or not category:
            raise CompositionError("fragment category must be a non-empty string")
        for claim in fragment.get("claims", []):
            operation = claim.get("operation")
            if operation not in SEMANTIC_OPERATIONS:
                raise CompositionError(f"unsupported semantic operation: {operation}")
            if operation != "remove" and "value" not in claim:
                raise CompositionError("materialized claim requires a value")
            if operation == "remove" and "value" in claim:
                raise CompositionError("absence assertion cannot contain a value")
            identity = target_identity(claim.get("target", {}))
            if identity in owners:
                raise CompositionError(
                    f"duplicate claim owned by {owners[identity]} and {category}: {identity}"
                )
            owners[identity] = category


def apply_claim(document: dict, claim: dict) -> None:
    selected, pointer = resolve_target(document, claim["target"])
    parent, token = pointer_parent(selected, pointer)
    exists = has_child(parent, token)
    if exists:
        raise CompositionError(f"claim would overwrite static data: {target_identity(claim['target'])}")
    add_child(parent, token, copy.deepcopy(claim["value"]))


def assert_absence(document: dict, claim: dict) -> None:
    selected, pointer = resolve_target(document, claim["target"])
    try:
        parent, token = pointer_parent(selected, pointer)
    except CompositionError:
        return
    if has_child(parent, token):
        raise CompositionError(
            f"required absence is present: {target_identity(claim['target'])}"
        )


def compose(static_policy: dict, fragments: list[dict]) -> dict:
    validate_fragments(fragments)
    result = copy.deepcopy(static_policy)
    for fragment in fragments:
        for claim in fragment.get("claims", []):
            if claim["operation"] != "remove":
                apply_claim(result, claim)
    for fragment in fragments:
        for claim in fragment.get("claims", []):
            if claim["operation"] == "remove":
                assert_absence(result, claim)
    return result


def escaped_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def first_mismatch(actual, expected, path="") -> str | None:
    if type(actual) is not type(expected):
        return path or "/"
    if isinstance(expected, dict):
        for key in sorted(expected.keys() | actual.keys()):
            child_path = f"{path}/{escaped_pointer_token(key)}"
            if key not in actual or key not in expected:
                return child_path
            mismatch = first_mismatch(actual[key], expected[key], child_path)
            if mismatch is not None:
                return mismatch
        return None
    if isinstance(expected, list):
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            mismatch = first_mismatch(actual_item, expected_item, f"{path}/{index}")
            if mismatch is not None:
                return mismatch
        if len(actual) != len(expected):
            return f"{path}/{min(len(actual), len(expected))}"
        return None
    return None if actual == expected else path or "/"


def verify_expected_policy(actual: dict, expected: dict) -> None:
    mismatch = first_mismatch(actual, expected)
    if mismatch is not None:
        raise CompositionError(f"composed policy does not match expected policy at {mismatch}")


def materialize_subject(subject: dict) -> dict:
    policy = copy.deepcopy(subject["policy"])
    for pointer, encoding in subject.get("collection_encodings", {}).items():
        value = get_pointer(policy, pointer)
        if encoding != "env-map":
            raise CompositionError(f"unsupported collection encoding: {encoding}")
        if not isinstance(value, dict):
            raise CompositionError(f"env-map collection is not an object: {pointer}")
        if any(not isinstance(name, str) or "=" in name for name in value):
            raise CompositionError(f"env-map contains an invalid variable name: {pointer}")
        parent, token = pointer_parent(policy, pointer)
        parent[token] = [f"{name}={value[name]}" for name in sorted(value)]
    return policy


def materialize(
    static_ir: dict, fragments: list[dict], expected_policy: dict | None = None
) -> dict:
    composed = compose(static_ir, fragments)
    if "subjects" not in composed or "policy_data" not in composed:
        result = composed
    else:
        result = composed["policy_data"]
        result["containers"] = [
            materialize_subject(subject)
            for subject in sorted(composed["subjects"], key=lambda item: item["ordinal"])
        ]
    if expected_policy is not None:
        verify_expected_policy(result, expected_policy)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-policy", required=True, type=Path)
    parser.add_argument("--fragment", action="append", default=[], type=Path)
    parser.add_argument("--expected-policy", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    static_policy = json.loads(args.static_policy.read_text(encoding="utf-8"))
    fragments = [json.loads(path.read_text(encoding="utf-8")) for path in args.fragment]
    expected_policy = (
        json.loads(args.expected_policy.read_text(encoding="utf-8"))
        if args.expected_policy is not None
        else None
    )
    result = materialize(static_policy, fragments, expected_policy)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
