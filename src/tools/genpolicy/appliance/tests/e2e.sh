#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
engine="${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}"
image="${IMAGE:?IMAGE is required}"
reference_image="${REFERENCE_IMAGE:?REFERENCE_IMAGE is required}"
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT

mkdir -p "${temporary}/input/images" "${temporary}/output"
cp "${script_dir}/fixtures/complex-workload.yaml" \
	"${temporary}/input/workload.yaml"
cp "${script_dir}/fixtures/configuration.toml" \
    "${temporary}/input/configuration.toml"

"${engine}" run --rm --entrypoint /bin/sh "${image}" -c \
	'command -v genpolicy-oci-compiler >/dev/null && ! command -v genpolicy >/dev/null'

"${engine}" run --rm --privileged --network=none \
	-e GENPOLICY_BALANCED=1 \
    -e GENPOLICY_KATA_CONFIG=/input/configuration.toml \
	--cgroupns=host \
	-v "${temporary}/input:/input:ro" \
	-v "${temporary}/output:/output" \
	"${reference_image}"

test -s "${temporary}/output/dynamic-tags.json"
test -s "${temporary}/output/policy.rego"
test -s "${temporary}/output/legacy-reference-policy.rego"
test -s "${temporary}/output/policy-oci-diff.json"
test -s "${temporary}/output/policy-annotation.txt"
test -s "${temporary}/output/provenance.json"
test -s "${temporary}/output/pods.json"
test -s "${temporary}/output/workload-policy.yaml"
test -s "${temporary}/output/policy-balanced.rego"
test -s "${temporary}/output/policy-mode-report.json"
test "$(find "${temporary}/output/tagged-requests" -type f -name '*.json' | wc -l)" -ge 2
if [[ "${CAPTURE_BACKEND:-runtime-rs}" == "runtime-rs" ]]; then
    test "$(find "${temporary}/output/execprocess-requests" -type f -name '*.json' | wc -l)" -ge 1
    grep -R -q '"/bin/busybox"' "${temporary}/output/execprocess-requests"
    grep -R -q '"true"' "${temporary}/output/execprocess-requests"
fi
grep -R -q '{{GENPOLICY_DYNAMIC:' "${temporary}/output/tagged-requests"
grep -q 'policy_data :=' "${temporary}/output/policy.rego"
grep -q 'io.katacontainers.config.hypervisor.cc_init_data' \
	"${temporary}/output/workload-policy.yaml"
python3 - "${temporary}/output" <<'PY'
import base64
import gzip
import json
import sys
import tomllib
from pathlib import Path

output = Path(sys.argv[1])

def policy_data(name):
    text = (output / name).read_text(encoding="utf-8")
    return json.loads(text.rsplit("\npolicy_data := ", 1)[1])

def workload(data):
    return next(
        container
        for container in data["containers"]
        if container["OCI"]["Annotations"].get(
            "io.kubernetes.cri.container-name"
        ) == "workload"
    )

final = workload(policy_data("policy.rego"))
final_data = policy_data("policy.rego")
legacy_reference_workload = workload(policy_data("legacy-reference-policy.rego"))
assert final["OCI"]["Process"]["Cwd"] == "/work"
assert legacy_reference_workload["OCI"]["Process"]["Cwd"] == "/"
assert (
    final["OCI"]["Process"]["Args"]
    == legacy_reference_workload["OCI"]["Process"]["Args"]
)
assert final["OCI"]["Process"]["User"]["UID"] == 0
assert final["OCI"]["Process"]["User"]["GID"] == 0
assert set(
    legacy_reference_workload["OCI"]["Process"]["User"]["AdditionalGids"]
).issubset(final["OCI"]["Process"]["User"]["AdditionalGids"])
assert (
    final["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"]
    == legacy_reference_workload["OCI"]["Annotations"][
        "io.kubernetes.cri.sandbox-name"
    ]
)
assert "{{GENPOLICY_DYNAMIC:" not in json.dumps(final)
expected_guest_pull_images = {
    "sandbox": ["pause"],
    "workload": ["genpolicy.local:5000/busybox:1.36.1"],
    "sidecar": ["genpolicy.local:5000/busybox:1.36.1"],
}
for container in final_data["containers"]:
    annotations = container["OCI"]["Annotations"]
    identity = annotations.get("io.kubernetes.cri.container-name", "sandbox")
    assert len(container["storages"]) == 1
    marker = container["storages"][0]
    assert marker["driver"] == "guest-pull-images"
    assert marker["options"] == expected_guest_pull_images[identity]
assert final_data["sandbox"]["storages"]
pause = next(
    container
    for container in final_data["containers"]
    if container["OCI"]["Annotations"].get(
        "io.kubernetes.cri.container-type"
    ) == "sandbox"
)
assert "nerdctl/network-namespace" in pause["OCI"]["Annotations"]
assert pause["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-log-directory"].startswith(
    "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_"
)
annotation = (output / "policy-annotation.txt").read_text().strip()
initdata = tomllib.loads(gzip.decompress(base64.b64decode(annotation)).decode())
assert initdata["data"]["policy.rego"] == (output / "policy.rego").read_text()

report = json.loads((output / "policy-oci-diff.json").read_text())
entry = next(
    item
    for item in report["containers"]
    if item["identity"]["container_name"] == "workload"
)
assert entry["fields"]["/OCI/Process"]["source"] == "captured-oci"
assert entry["legacy_service_env_regex_coverage"]["checked"] > 0
assert entry["legacy_service_env_regex_coverage"]["uncovered"] == 0

mode_report = json.loads((output / "policy-mode-report.json").read_text())
legacy = mode_report["modes"]["legacy"]["policy"]
balanced = mode_report["modes"]["balanced"]["policy"]
reference = mode_report["modes"]["legacy-reference"]["policy"]
balanced_workload = workload(policy_data("policy-balanced.rego"))
assert legacy["service_endpoint_regex_count"] > 0
assert reference["allow_env_regex_count"] == legacy["allow_env_regex_count"]
assert (
    reference["service_endpoint_regex_count"]
    == legacy["service_endpoint_regex_count"]
)
assert balanced["service_endpoint_regex_count"] == 0
assert balanced["identity_or_partition_regex_count"] == 0
assert balanced["exact_service_env_count"] > 0
assert balanced["termination_path_patterns"] == ["^/dev/termination\\-log$"]
assert balanced["network_namespace_patterns"]
assert (
    balanced_workload["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"]
    == legacy_reference_workload["OCI"]["Annotations"][
        "io.kubernetes.cri.sandbox-name"
    ]
)
assert "POD_UID=$(pod-uid)" in balanced_workload["OCI"]["Process"]["Env"]
provenance = json.loads((output / "provenance.json").read_text())
assert len(provenance["outputs"]["raw_create_requests"]) == 3
assert "policy-balanced.rego" in provenance["outputs"]["generated"]
comparison = mode_report["comparisons"]["legacy-reference-vs-oci-legacy"]
assert comparison["rules_equal_ignoring_trailing_whitespace"]
workload_comparison = comparison["containers"]["container/workload"]
assert workload_comparison["cwd"] == {
    "reference": "/",
    "candidate": "/work",
}
assert workload_comparison["exec_commands"] == {
    "reference": [["/bin/busybox", "true"]],
    "candidate": [["/bin/busybox", "true"]],
}
assert "/var/run/secrets/kubernetes.io/serviceaccount" in (
    workload_comparison["mount_destinations_only_in_reference"]
)
PY

echo "appliance end-to-end validation passed"
