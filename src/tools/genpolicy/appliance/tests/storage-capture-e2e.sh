#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
engine="${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}"
image="${IMAGE:?IMAGE is required}"
analysis_image="${ANALYSIS_IMAGE:?ANALYSIS_IMAGE is required}"
temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT

capture_and_analyze() {
	local name=$1
	local configuration=$2
	local run_dir="${temporary}/${name}"

	mkdir -p "${run_dir}/input" "${run_dir}/output" "${run_dir}/analysis"
	cp "${script_dir}/fixtures/storage-classes-workload.yaml" \
		"${run_dir}/input/workload.yaml"
	cp "${configuration}" "${run_dir}/input/configuration.toml"

	"${engine}" run --rm --privileged --network=none \
		--cgroupns=host \
		-e GENPOLICY_CAPTURE_ONLY=1 \
		-e GENPOLICY_KATA_CONFIG=/input/configuration.toml \
		-v "${run_dir}/input:/input:ro" \
		-v "${run_dir}/output:/output" \
		"${image}"

	python3 "${appliance_dir}/scripts/capture_bundle.py" validate \
		--bundle "${run_dir}/output/capture" \
		--require-complete

	"${engine}" run --rm --network=none \
		--entrypoint /bin/bash \
		-v "${run_dir}/output/capture:/capture:ro" \
		-v "${run_dir}/analysis:/analysis" \
		"${analysis_image}" /opt/genpolicy/appliance/scripts/analyze_capture.sh \
		/capture /analysis
}

capture_and_analyze shared-fs "${script_dir}/fixtures/configuration.toml"

python3 - "${temporary}/shared-fs/analysis/storage-mount-analysis.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert report["capture"]["backend"] == "runtime-rs"
assert report["capture"]["request_authority"] == "recording-agent"
assert report["observations"]["runtime"]["shared_fs"] == "none"

claims = {entry["id"]: entry for entry in report["claims"]}
for identifier in (
    "emptydir-local-storage",
    "emptydir-tmpfs-storage",
    "shared-fs-none-volume-copy",
    "uvm-dev-shm",
):
    assert claims[identifier]["status"] == "confirmed", claims[identifier]
    assert claims[identifier]["evidence"], claims[identifier]

assert report["observations"]["workload"]["volume_types"] == {
    "configMap": 1,
    "downwardAPI": 1,
    "emptyDir": 2,
    "secret": 1,
}
assert report["observations"]["storage_classes"]["volume-local"] == 1
assert report["observations"]["storage_classes"]["volume-tmpfs"] == 1
mounts = report["observations"]["mount_classes"]
assert mounts["volume-copy-configMap"] == 1
assert mounts["volume-copy-secret"] == 1
assert mounts["volume-copy-downwardAPI"] == 1
PY

capture_and_analyze block-plain \
	"${script_dir}/fixtures/configuration-block-plain.toml"

python3 - \
	"${temporary}/block-plain/analysis/storage-mount-analysis.json" \
	"${temporary}/block-plain/output/capture" <<'PY'
import base64
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
capture = Path(sys.argv[2])
claims = {entry["id"]: entry for entry in report["claims"]}
assert claims["emptydir-block-storage"]["status"] == "confirmed"
assert claims["emptydir-block-encrypted-storage"]["status"] == "not-exercised"
assert report["observations"]["storage_classes"] == {
	"rootfs-guest-pull": 2,
	"volume-block-emptydir": 1,
	"volume-tmpfs": 1,
}

requests = []
for path in sorted((capture / "createcontainer-requests").glob("*.json")):
	request = json.loads(path.read_text(encoding="utf-8"))
	annotations = (request.get("oci") or {}).get("annotations") or {}
	if annotations.get("io.kubernetes.cri.container-name") == "workload":
		requests.append(request)
assert len(requests) == 1
request = requests[0]
plain = [
	storage
	for storage in request["storages"]
	if "create_filesystem" in set(storage.get("driver_options") or [])
]
assert len(plain) == 1
storage = plain[0]
assert "encryption_key=ephemeral" not in storage["driver_options"]
assert storage["driver"] == "blk"
assert storage["fs_type"] == "ext4"
assert storage["shared"] is True
assert storage["fs_group"] == {
	"group_change_policy": "Always",
	"group_id": 2000,
}
encoded_source = base64.urlsafe_b64encode(storage["source"].encode()).decode()
assert storage["mount_point"] == (
	f"/run/kata-containers/sandbox/storage/{encoded_source}"
)
mounts = [
	mount
	for mount in request["oci"]["mounts"]
	if mount.get("destination") == "/scratch-disk"
]
assert len(mounts) == 1
assert mounts[0]["type"] == "bind"
assert mounts[0]["source"] == storage["mount_point"]
PY

capture_and_analyze block-encrypted \
	"${script_dir}/fixtures/configuration-block-encrypted.toml"

python3 - \
	"${temporary}/block-encrypted/analysis/storage-mount-analysis.json" \
	"${temporary}/block-encrypted/output/capture" <<'PY'
import base64
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
capture = Path(sys.argv[2])
claims = {entry["id"]: entry for entry in report["claims"]}
for identifier in (
	"emptydir-block-storage",
	"emptydir-block-encrypted-storage",
	"emptydir-tmpfs-storage",
):
	assert claims[identifier]["status"] == "confirmed", claims[identifier]
	assert claims[identifier]["evidence"], claims[identifier]

assert report["observations"]["storage_classes"] == {
	"rootfs-guest-pull": 2,
	"volume-block-encrypted-emptydir": 1,
	"volume-tmpfs": 1,
}

requests = []
for path in sorted((capture / "createcontainer-requests").glob("*.json")):
	request = json.loads(path.read_text(encoding="utf-8"))
	annotations = (request.get("oci") or {}).get("annotations") or {}
	if annotations.get("io.kubernetes.cri.container-name") == "workload":
		requests.append(request)
assert len(requests) == 1
request = requests[0]
encrypted = [
	storage
	for storage in request["storages"]
	if set(storage.get("driver_options") or [])
	>= {"encryption_key=ephemeral", "create_filesystem"}
]
assert len(encrypted) == 1
storage = encrypted[0]
assert storage["driver"] == "blk"
assert storage["fs_type"] == "ext4"
assert storage["shared"] is True
assert storage["fs_group"] == {
	"group_change_policy": "Always",
	"group_id": 2000,
}
encoded_source = base64.urlsafe_b64encode(storage["source"].encode()).decode()
assert storage["mount_point"] == (
	f"/run/kata-containers/sandbox/storage/{encoded_source}"
)
mounts = [
	mount
	for mount in request["oci"]["mounts"]
	if mount.get("destination") == "/scratch-disk"
]
assert len(mounts) == 1
assert mounts[0]["type"] == "bind"
assert mounts[0]["source"] == storage["mount_point"]
PY

echo "authoritative storage capture validation passed"
