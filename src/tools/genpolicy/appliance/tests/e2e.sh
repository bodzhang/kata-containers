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
cp "${script_dir}/fixtures/pod.yaml" "${temporary}/input/workload.yaml"

"${engine}" run --rm --entrypoint /bin/sh "${image}" -c \
	'command -v genpolicy-oci-compiler >/dev/null && ! command -v genpolicy >/dev/null'

"${engine}" run --rm --privileged --network=none \
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
test "$(find "${temporary}/output/tagged" -type f -name '*.json' | wc -l)" -ge 2
grep -R -q '{{GENPOLICY_DYNAMIC:' "${temporary}/output/tagged"
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
legacy = workload(policy_data("legacy-reference-policy.rego"))
assert final["OCI"]["Process"]["Cwd"] == "/work"
assert legacy["OCI"]["Process"]["Cwd"] == "/"
assert final["OCI"]["Process"]["Args"] == legacy["OCI"]["Process"]["Args"]
assert final["OCI"]["Process"]["User"] == legacy["OCI"]["Process"]["User"]
assert "{{GENPOLICY_DYNAMIC:" not in json.dumps(final)
assert all(not container["storages"] for container in final_data["containers"])
assert final_data["sandbox"]["storages"]
pause = next(
    container
    for container in final_data["containers"]
    if container["OCI"]["Annotations"].get(
        "io.kubernetes.cri.container-type"
    ) == "sandbox"
)
assert "nerdctl/network-namespace" in pause["OCI"]["Annotations"]
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
PY

echo "appliance end-to-end validation passed"
