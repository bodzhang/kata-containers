#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
engine="${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}"
image="${IMAGE:?IMAGE is required}"
analysis_image="${ANALYSIS_IMAGE:?ANALYSIS_IMAGE is required}"
reference_image="${REFERENCE_IMAGE:?REFERENCE_IMAGE is required}"
agent_ctl="${AGENT_CTL:?AGENT_CTL is required}"
kata_agent="${KATA_AGENT:?KATA_AGENT is required}"
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT

mkdir -p "${temporary}/input/images" "${temporary}/output" \
    "${temporary}/reanalysis" "${temporary}/policy-test"
cp "${script_dir}/fixtures/complex-workload.yaml" \
	"${temporary}/input/workload.yaml"
cp "${script_dir}/fixtures/configuration.toml" \
    "${temporary}/input/configuration.toml"

"${engine}" run --rm --entrypoint /bin/sh "${image}" -c \
    '! command -v genpolicy-oci-compiler >/dev/null && ! command -v genpolicy >/dev/null'
"${engine}" run --rm --entrypoint /bin/sh "${analysis_image}" -c \
    'command -v genpolicy-oci-compiler >/dev/null && ! command -v genpolicy >/dev/null'

"${engine}" run --rm --privileged --network=none \
    -e GENPOLICY_CAPTURE_ONLY=0 \
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
test -s "${temporary}/output/capture/manifest.json"
test -s "${temporary}/output/capture/profile.json"
test -s "${temporary}/output/capture/images/index.json"
test -s "${temporary}/output/pods.json"
test -s "${temporary}/output/workload-policy.yaml"
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
python3 "${appliance_dir}/scripts/capture_bundle.py" validate \
    --bundle "${temporary}/output/capture" \
    --require-complete
"${engine}" run --rm --network=none \
    --entrypoint /bin/bash \
    -v "${temporary}/output/capture:/capture:ro" \
    -v "${temporary}/reanalysis:/analysis" \
    "${analysis_image}" /opt/genpolicy/appliance/scripts/analyze_capture.sh \
    /capture /analysis
cmp "${temporary}/output/policy.rego" \
    "${temporary}/reanalysis/policy.rego"
test -s "${temporary}/reanalysis/request-transformations.json"
test -s "${temporary}/reanalysis/request-field-provenance.json"
test -s "${temporary}/reanalysis/storage-mount-analysis.json"
python3 - "${temporary}/reanalysis" <<'PY'
import json
import sys
from pathlib import Path

analysis = Path(sys.argv[1])
transformations = json.loads(
    (analysis / "request-transformations.json").read_text(encoding="utf-8")
)
provenance = json.loads(
    (analysis / "request-field-provenance.json").read_text(encoding="utf-8")
)
storage_mounts = json.loads(
    (analysis / "storage-mount-analysis.json").read_text(encoding="utf-8")
)
assert len(transformations["requests"]) == 3
assert all(request["status"] == "paired" for request in transformations["requests"])
assert {entry["source"] for entry in provenance["entries"]} >= {
    "kubernetes-resolved",
    "profile-runtime",
}
claims = {entry["id"]: entry for entry in storage_mounts["claims"]}
if storage_mounts["capture"]["request_authority"] == "recording-agent":
    assert claims["kubernetes-generated-files"]["status"] == "confirmed"
    assert claims["uvm-dev-shm"]["status"] == "confirmed"
    rootfs_claim = {
        "guest-pull": "guest-pull-rootfs",
        "erofs-dmverity": "erofs-overlay-rootfs",
    }[storage_mounts["capture"]["rootfs_mode"]]
    assert claims[rootfs_claim]["status"] == "confirmed"
else:
    assert all(entry["status"] == "not-authoritative" for entry in claims.values())
PY
python3 - "${temporary}/output" "${CAPTURE_BACKEND:-runtime-rs}" \
    "${ROOTFS_MODE:?ROOTFS_MODE is required}" \
    "${REQUEST_AUTHORITY:?REQUEST_AUTHORITY is required}" <<'PY'
import base64
import gzip
import json
import sys
import tomllib
from pathlib import Path

output = Path(sys.argv[1])
capture_backend = sys.argv[2]
rootfs_mode = sys.argv[3]
request_authority = sys.argv[4]

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
for container in final_data["containers"]:
    annotations = container["OCI"]["Annotations"]
    identity = annotations.get("io.kubernetes.cri.container-name", "sandbox")
    assert len(container["storages"]) == 1
    marker = container["storages"][0]
    assert marker["driver"] == "guest-pull-images"
    expected_image = (
        "pause"
        if identity == "sandbox"
        else annotations["io.kubernetes.cri.image-name"]
    )
    assert marker["options"] == [expected_image]
assert final_data["sandbox"]["storages"]
pause = next(
    container
    for container in final_data["containers"]
    if container["OCI"]["Annotations"].get(
        "io.kubernetes.cri.container-type"
    ) == "sandbox"
)
assert pause["OCI"]["Annotations"]["nerdctl/network-namespace"] == (
    "^/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    "[0-9a-f]{4}-[0-9a-f]{12}$"
)
assert pause["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-log-directory"].startswith(
    "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_"
)
annotation = (output / "policy-annotation.txt").read_text().strip()
initdata = tomllib.loads(gzip.decompress(base64.b64decode(annotation)).decode())
assert initdata["data"]["policy.rego"] == (output / "policy.rego").read_text()

report = json.loads((output / "policy-oci-diff.json").read_text())
assert report["schema_version"] == 3
assert report["policy_mode"] == "request-derived"
sandbox_contract = report["sandbox_storage_contract"]
assert sandbox_contract["authority"] == "versioned-settings"
assert sandbox_contract["capture_status"] == "not-captured"
assert sandbox_contract["storages"] == final_data["sandbox"]["storages"]
entry = next(
    item
    for item in report["containers"]
    if item["identity"]["container_name"] == "workload"
)
assert entry["fields"]["/OCI/Process"]["source"] == "captured-oci"
env_regexes = final_data["request_defaults"]["CreateContainerRequest"][
    "allow_env_regex"
]
assert any(
    regex.startswith("^BACKEND_SERVICE_HOST=") for regex in env_regexes
), env_regexes
assert not any("$(svc_name_downward_env)" in regex for regex in env_regexes)
explicit_service_env = [
    value
    for container in final_data["containers"]
    if container["OCI"]["Annotations"].get("io.kubernetes.cri.container-type")
    != "sandbox"
    for value in container["OCI"]["Process"]["Env"]
    if "_SERVICE_" in value or "_PORT=" in value
]
assert not explicit_service_env, explicit_service_env
termination_patterns = {
    value
    for container in final_data["containers"]
    for key, value in container["runtime_anno_patterns"].items()
    if "terminationMessagePath" in key
}
assert termination_patterns == {"^/dev/termination\\-log$"}
assert (
    final["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"]
    == legacy_reference_workload["OCI"]["Annotations"][
        "io.kubernetes.cri.sandbox-name"
    ]
)
assert "POD_UID=$(pod-uid)" in final["OCI"]["Process"]["Env"]
provenance = json.loads((output / "provenance.json").read_text())
assert len(provenance["outputs"]["raw_create_requests"]) == 3
assert "policy.rego" in provenance["outputs"]["generated"]
capture_manifest = json.loads(
    (output / "capture" / "manifest.json").read_text(encoding="utf-8")
)
assert capture_manifest["bundle_type"] == "genpolicy-request-capture"
assert capture_manifest["capture"]["complete"] is True
assert capture_manifest["capture"]["backend"] == capture_backend
assert capture_manifest["capture"]["rootfs_mode"] == rootfs_mode
assert capture_manifest["capture"]["request_authority"] == request_authority
assert capture_manifest["capture"]["counts"] == {
    "createcontainer": 3,
    "execprocess": 2 if capture_backend == "runtime-rs" else 0,
    "expected_createcontainer": 3,
    "raw_oci": 3,
}
image_index = json.loads(
    (output / "capture" / "images" / "index.json").read_text(encoding="utf-8")
)
requested_images = {
    line
    for line in (output / "requested-images.txt").read_text(encoding="utf-8").splitlines()
    if line
}
assert set(image_index["images"]) == requested_images
for image in image_index["images"].values():
    assert (output / "capture" / "images" / image["manifest_path"]).is_file()
    assert (output / "capture" / "images" / image["config_path"]).is_file()
captured_images = set()
for request_path in (output / "capture" / "createcontainer-requests").glob("*.json"):
    request = json.loads(request_path.read_text(encoding="utf-8"))
    annotations = request["oci"]["annotations"]
    if annotations.get("io.kubernetes.cri.container-type") == "container":
        captured_images.add(annotations["io.kubernetes.cri.image-name"])
requested_digests = {image.rsplit("@", 1)[1] for image in requested_images}
captured_digests = {image.rsplit("@", 1)[1] for image in captured_images}
assert captured_digests == requested_digests
PY

KATA_AGENT="${kata_agent}" AGENT_CTL="${agent_ctl}" \
    "${appliance_dir}/scripts/analyze_capture.sh" \
    --policy "${temporary}/output/policy.rego" \
    "${temporary}/output/capture" "${temporary}/policy-test"

python3 - "${temporary}/policy-test/policy-test-result.json" \
    "${CAPTURE_BACKEND:-runtime-rs}" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
capture_backend = sys.argv[2]
assert result["result"] == "pass"
assert result["exit_code"] == 0
assert result["checked_requests"] == (5 if capture_backend == "runtime-rs" else 3)
assert result["phase"] == "complete"
assert result["failed_request"] is None
PY
test -s "${temporary}/policy-test/policy-runtime-inputs.jsonl"
test ! -e "${temporary}/policy-test/policy.rego"
test ! -e "${temporary}/policy-test/policy-annotation.txt"
test ! -e "${temporary}/policy-test/tagged-requests"

echo "appliance end-to-end validation passed"
