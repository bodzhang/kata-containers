#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
repo_root=$(cd "${appliance_dir}/../../../.." && pwd)
run_complex="${appliance_dir}/demo-compare/run-complex"
composer="${appliance_dir}/fragment-policy-composer"
capture="${composer}/fixtures/run-complex-capture"
profile_fragments="${composer}/profiles/k8s-1.33-containerd-2.3-guest-pull"
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT

python3 "${appliance_dir}/scripts/generate_regorus_fragment_inputs.py" \
	--capture "${capture}" \
	--rootfs-mode guest-pull \
	--uvm-baseline "${composer}/fixtures/run-complex-uvm-baseline.json" \
	--compiler-policy "${run_complex}/output/policy.rego" \
	--tag-manifest "${run_complex}/output/dynamic-tags.json" \
	--tagged-requests-dir "${run_complex}/output/tagged" \
	--source-report "${run_complex}/output/policy-oci-diff.json" \
	--profile-fragments-dir "${profile_fragments}" \
	--static-output "${temporary}/static-ir.rego" \
	--materializations-output "${temporary}/materializations.rego" \
	--expected-output "${temporary}/expected-policy.json"

(
	cd "${repo_root}"
	cargo run --locked --quiet --package fragment-policy-composer -- \
		"${temporary}/static-ir.rego" \
		"${profile_fragments}" \
		"${temporary}/materializations.rego" \
		"${composer}/policies/compose.rego" \
		"${temporary}/final-policy.json" \
		"${repo_root}/src/tools/genpolicy/rules.rego" \
		"${temporary}/policy.rego"
)

cmp "${temporary}/expected-policy.json" "${temporary}/final-policy.json"

python3 - \
	"${temporary}/static-ir.rego" \
	"${temporary}/materializations.rego" \
	"${temporary}/final-policy.json" \
	"${temporary}/policy.rego" \
	"${run_complex}/output/dynamic-tags.json" \
	"${profile_fragments}" <<'PY'
import json
import sys
from pathlib import Path


def assignment(path: str, marker: str):
    return json.loads(Path(path).read_text(encoding="utf-8").split(marker, 1)[1])


static_ir = assignment(sys.argv[1], "ir := ")
materializations = assignment(sys.argv[2], "materializations := ")
profile_fragments = [
	assignment(str(path), "fragment := ")
	for path in sorted(Path(sys.argv[6]).glob("*.rego"))
	if "fragment := " in path.read_text(encoding="utf-8")
]
result = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))

assert "BACKEND_SERVICE" not in json.dumps(static_ir)
assert profile_fragments
# Every final-policy leaf is now produced by the typed static IR or a reviewed
# fragment rule, so the composition carries no residual capture materializations.
assert materializations == []
assert all(fragment["scope"] == "profile" for fragment in profile_fragments)
assert {fragment["category"] for fragment in profile_fragments} == {
	"containerd-oci",
	"kubelet-or-containerd",
	"kubelet-resolution",
	"kubernetes-controller",
	"policy-framework-settings",
	"runtime-rs",
	"runtime-rs-envelope",
}
assert sum(len(fragment["claims"]) for fragment in profile_fragments) == 56
assert all(
	fragment.get("materialization_contracts", []) == []
	for fragment in profile_fragments
)
forbidden_materialization_paths = {
	"/devices",
	"/OCI/Linux/Devices",
	"/OCI/Mounts",
	"/storages",
}
assert all(
	claim["target"]["path"] not in forbidden_materialization_paths
	and not claim["target"]["path"].startswith("/runtime_anno_patterns")
	for fragment in materializations
	for claim in fragment["claims"]
)
assert all(
	contract["path_regex"].startswith("^")
	and contract["path_regex"].endswith("$")
	for fragment in profile_fragments
	for contract in fragment.get("materialization_contracts", [])
	if "path_regex" in contract
)
reviewed_profile = json.dumps(profile_fragments)
kubelet_fragment = next(
	fragment
	for fragment in profile_fragments
	if fragment["category"] == "kubelet-resolution"
)
# Every kubelet-resolution path is now produced by a reviewed rule, so the
# fragment holds no materialization authority at all.
assert kubelet_fragment.get("materialization_contracts", []) == []
runtime_rs_fragment = next(
	fragment
	for fragment in profile_fragments
	if fragment["category"] == "runtime-rs"
)
assert runtime_rs_fragment.get("materialization_contracts", []) == []
envelope_fragment = next(
	fragment
	for fragment in profile_fragments
	if fragment["category"] == "runtime-rs-envelope"
)
assert envelope_fragment.get("materialization_contracts", []) == []
workload_subject = next(
	subject for subject in static_ir["subjects"] if subject["id"] == "container/workload"
)
assert {
	resolution["target"]["path"]
	for resolution in workload_subject["environment_resolutions"]
} == {
	"/OCI/Process/Env/NODE_NAME",
	"/OCI/Process/Env/POD_NAME",
	"/OCI/Process/Env/POD_UID",
}
assert all(
	claim["target"]["path"] not in {
		"/OCI/Process/Env/NODE_NAME",
		"/OCI/Process/Env/POD_NAME",
		"/OCI/Process/Env/POD_UID",
	}
	for fragment in materializations
	for claim in fragment["claims"]
)
assert "[A-Z][A-Z0-9_]*" not in reviewed_profile
assert all(
	token not in reviewed_profile
	for token in (
		"BACKEND",
		"balanced-mode",
		"container/workload",
		"container/sidecar",
		"gp-deployment",
	)
)
assert all(
    "subject" not in claim["target"]
    for fragment in profile_fragments
    for claim in fragment["claims"]
)
assert "BACKEND_SERVICE" not in json.dumps(materializations)
assert all(
	claim["target"]["path"] not in {"/OCI/Mounts", "/storages"}
	for fragment in materializations
	for claim in fragment["claims"]
)
assert all(
	claim["target"]["path"] not in {
		"/OCI/Annotations/io.katacontainers.pkg.oci.bundle_path",
		"/OCI/Annotations/io.katacontainers.pkg.oci.container_type",
		"/OCI/Annotations/io.kubernetes.cri.sandbox-id",
		"/OCI/Annotations/io.kubernetes.cri.sandbox-log-directory",
		"/OCI/Annotations/io.kubernetes.cri.sandbox-namespace",
		"/OCI/Annotations/nerdctl~1network-namespace",
	}
	for fragment in materializations
	for claim in fragment["claims"]
)
assert len(result["containers"]) == 3
assert result["framework"] == {
	"annotations": {
		"container_name": "io.kubernetes.cri.container-name",
		"cri_container_type": "io.kubernetes.cri.container-type",
		"cri_prefix": "io.kubernetes.cri.",
		"kata_container_type": "io.katacontainers.pkg.oci.container_type",
		"network_namespace": "nerdctl/network-namespace",
		"sandbox_id": "io.kubernetes.cri.sandbox-id",
		"sandbox_log_directory": "io.kubernetes.cri.sandbox-log-directory",
		"sandbox_name": "io.kubernetes.cri.sandbox-name",
		"sandbox_namespace": "io.kubernetes.cri.sandbox-namespace",
		"sandbox_uid": "io.kubernetes.cri.sandbox-uid",
	},
	"paths": {"pod_log_directory_format": "/var/log/pods/%s_%s_%s"},
	"roles": {
		"cri_container": "container",
		"cri_sandbox": "sandbox",
		"kata_container": "pod_container",
		"kata_sandbox": "pod_sandbox",
	},
}
serialized = json.dumps(result)
for disposable_value in (
	"10.100.240.108",
	"10.96.0.1",
	"fc661901-c6de-4946-9e2b-c5d66c6a07eb",
	"gp-deployment-balanced-mode-chnlp",
	"genpolicy-node",
	# The clean-room registry the capture was taken against carries no
	# authority, so no reusable claim may pin appliance configuration to it.
	"genpolicy.local",
):
	assert disposable_value not in serialized
for fragment_source in (Path(sys.argv[6]).glob("*.rego")):
	assert "genpolicy.local" not in fragment_source.read_text(encoding="utf-8")
assert result["request_defaults"]["CreateContainerRequest"]["allow_env_regex"] == []
application_processes = [
	container["OCI"]["Process"]
	for container in result["containers"]
	if container["OCI"].get("Annotations", {}).get(
		"io.kubernetes.cri.container-type"
	) != "sandbox"
]
manifest = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
service_patterns = {
	f"^{item['tag'].removeprefix('service-env.')}={item['suggested_regex']}$"
	for item in manifest["tags"]
	if item["tag"].startswith("service-env.")
}
service_names = {
	item["tag"].removeprefix("service-env.")
	for item in manifest["tags"]
	if item["tag"].startswith("service-env.")
}
assert len(service_patterns) == 14
assert all(
	{
		"BACKEND_SERVICE_PORT_HTTPS=8443",
		"KUBERNETES_SERVICE_PORT_HTTPS=443",
	}.issubset(process.get("Env", []))
	for process in application_processes
)
assert all(
	entry.partition("=")[0] not in service_names
	for process in application_processes
	for entry in process.get("Env", [])
)
assert all(
	set(process.get("EnvRegex", [])) == service_patterns
	for process in application_processes
)
assert all(
	not container["OCI"]["Process"].get("EnvRegex", [])
	for container in result["containers"]
	if container["OCI"].get("Annotations", {}).get(
		"io.kubernetes.cri.container-type"
	) == "sandbox"
)
# Fields that used to arrive as capture materializations now come from reviewed
# profile rules, so they must still be present in the composed policy.
assert all(
	"HOSTNAME=$(sandbox-name)" in process.get("Env", [])
	for process in application_processes
)
assert all(
	container["OCI"]["Root"]["Path"] == "$(root_path)"
	and container["OCI"]["Linux"]["Namespaces"] == [
		{"Path": "", "Type": "ipc"},
		{"Path": "", "Type": "uts"},
		{"Path": "", "Type": "mount"},
	]
	for container in result["containers"]
)
# rules.rego never correlates the CRI image-name value, so the composed policy
# binds image identity through the guest-pull digest alone.
assert all(
	"io.kubernetes.cri.image-name" not in container["OCI"]["Annotations"]
	for container in result["containers"]
)
sandbox_container = next(
	container
	for container in result["containers"]
	if container["OCI"].get("Annotations", {}).get(
		"io.kubernetes.cri.container-type"
	) == "sandbox"
)
assert sandbox_container["OCI"]["Process"]["Terminal"] is False
assert len(sandbox_container["OCI"]["Process"]["Capabilities"]["Bounding"]) == 14
assert sandbox_container["OCI"]["Process"]["Capabilities"]["Ambient"] == []
assert sandbox_container["exec_commands"] == []

# The sandbox-name annotation is derived from the Deployment's typed identity,
# so every subject carries the controller-generated Pod name grammar.
suffix = "[bcdfghjklmnpqrstvwxz2456789]+"
assert all(
	container["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"]
	== f"^balanced-mode-{suffix}-{suffix}$"
	for container in result["containers"]
)

# The application user is resolved from the image's digest-bound /etc/passwd and
# /etc/group rather than copied from what the host happened to run as.
application_containers = [
	container
	for container in result["containers"]
	if container["OCI"]["Annotations"]["io.katacontainers.pkg.oci.container_type"]
	!= "pod_sandbox"
]
assert len(application_containers) == 2
assert all(
	container["OCI"]["Process"]["User"]
	== {"AdditionalGids": [0, 10], "GID": 0, "UID": 0, "Username": ""}
	for container in application_containers
)

policy = Path(sys.argv[4]).read_text(encoding="utf-8")
assert "\npackage agent_policy\n" in policy
assert json.loads(policy.rsplit("\npolicy_data := ", 1)[1]) == result
PY
