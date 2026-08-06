#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-/opt/genpolicy/appliance}"
readonly input_dir="${GENPOLICY_INPUT_DIR:-/input}"
readonly output_dir="${GENPOLICY_OUTPUT_DIR:-/output}"
readonly workload="${input_dir}/workload.yaml"

profile_name="${GENPOLICY_PROFILE_NAME:-k8s-1.33-containerd-2.3-native}"
profile_path="${appliance_root}/profiles/${profile_name}.env"
[[ -f "${profile_path}" ]] || {
	echo "ERROR: unknown capture profile: ${profile_name}" >&2
	exit 1
}
# shellcheck source=/dev/null
source "${profile_path}"
export GENPOLICY_ROOTFS_MODE="${ROOTFS_MODE}"

mkdir -p "${output_dir}/raw" "${output_dir}/logs"

pids=()
cleanup() {
	local pid
	for pid in "${pids[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

wait_for() {
	local description=$1
	shift
	local attempt
	for attempt in $(seq 1 120); do
		if "$@" >/dev/null 2>&1; then
			return
		fi
		sleep 1
	done
	fail "timed out waiting for ${description}"
}

[[ "$(id -u)" == "0" ]] || fail "the appliance must run as root"
[[ -f "${workload}" ]] || fail "${workload} is required"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] ||
	fail "cgroup v2 is required"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--images-output "${output_dir}/requested-images.txt" \
	--validate-only

containerd_config="${appliance_root}/config/containerd.toml"
case "${GENPOLICY_CAPTURE_BACKEND:-runtime-rs}" in
runc) ;;
runtime-rs) containerd_config="${appliance_root}/config/containerd-runtime-rs.toml" ;;
*) fail "unsupported capture backend: ${GENPOLICY_CAPTURE_BACKEND}" ;;
esac
if [[ "${ROOTFS_MODE}" == "erofs-dmverity" ]]; then
	[[ "${GENPOLICY_CAPTURE_BACKEND:-runtime-rs}" == "runtime-rs" ]] ||
		fail "EROFS dm-verity requires the runtime-rs capture backend"
	containerd_config="${appliance_root}/config/containerd-runtime-rs-erofs.toml"
fi
install -D -m 0644 "${containerd_config}" /etc/containerd/config.toml
install -D -m 0644 "${appliance_root}/config/kubelet.yaml" /etc/kubernetes/kubelet.yaml
install -D -m 0644 "${appliance_root}/config/10-genpolicy.conflist" /etc/cni/net.d/10-genpolicy.conflist
install -D -m 0755 "${appliance_root}/scripts/runc-capture" /usr/local/bin/runc-capture
if [[ "${ROOTFS_MODE}" == "erofs-dmverity" ]]; then
	/lib/systemd/systemd-udevd --daemon
	wait_for udev udevadm control --ping
	python3 "${appliance_root}/scripts/watch_device_mapper_nodes.py" \
		>"${output_dir}/logs/device-mapper-nodes.log" 2>&1 &
	pids+=("$!")
fi
mkdir -p "/etc/containerd/certs.d/${LOCAL_REGISTRY}"
cat >"/etc/containerd/certs.d/${LOCAL_REGISTRY}/hosts.toml" <<EOF
server = "http://${LOCAL_REGISTRY}"

[host."http://${LOCAL_REGISTRY}"]
  capabilities = ["pull", "resolve", "push"]
EOF

mkdir -p /etc/kubernetes/pki /var/lib/etcd /var/lib/kubelet /var/lib/containerd /run/containerd
printf '127.0.0.1 genpolicy.local\n' >>/etc/hosts
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=kube-apiserver" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc" \
	-keyout /etc/kubernetes/pki/apiserver.key \
	-out /etc/kubernetes/pki/apiserver.crt \
	>"${output_dir}/logs/openssl.log" 2>&1
openssl genrsa -out /etc/kubernetes/pki/sa.key 2048 >>"${output_dir}/logs/openssl.log" 2>&1
openssl rsa -in /etc/kubernetes/pki/sa.key -pubout \
	-out /etc/kubernetes/pki/sa.pub >>"${output_dir}/logs/openssl.log" 2>&1
printf '%s\n' \
	'genpolicy-clean-room-token,genpolicy,1000,"system:masters"' \
	>/etc/kubernetes/token.csv

etcd \
	--data-dir=/var/lib/etcd \
	--listen-client-urls=http://127.0.0.1:2379 \
	--advertise-client-urls=http://127.0.0.1:2379 \
	>"${output_dir}/logs/etcd.log" 2>&1 &
pids+=("$!")
wait_for etcd etcdctl --endpoints=http://127.0.0.1:2379 endpoint health

kube-apiserver \
	--advertise-address="$(hostname -i | awk '{print $1}')" \
	--allow-privileged=true \
	--anonymous-auth=true \
	--authorization-mode=AlwaysAllow \
	--disable-admission-plugins=DefaultStorageClass,DefaultTolerationSeconds,ServiceAccount \
	--etcd-servers=http://127.0.0.1:2379 \
	--secure-port=6443 \
	--service-account-issuer=https://kubernetes.default.svc \
	--service-account-key-file=/etc/kubernetes/pki/sa.pub \
	--service-account-signing-key-file=/etc/kubernetes/pki/sa.key \
	--service-cluster-ip-range=10.96.0.0/12 \
	--tls-cert-file=/etc/kubernetes/pki/apiserver.crt \
	--tls-private-key-file=/etc/kubernetes/pki/apiserver.key \
	--token-auth-file=/etc/kubernetes/token.csv \
	>"${output_dir}/logs/kube-apiserver.log" 2>&1 &
pids+=("$!")
wait_for kube-apiserver curl -kfsS \
	-H 'Authorization: Bearer genpolicy-clean-room-token' \
	https://127.0.0.1:6443/livez

cat >/etc/kubernetes/kubeconfig <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: genpolicy
  user:
    token: genpolicy-clean-room-token
contexts:
- name: local
  context:
    cluster: local
    user: genpolicy
current-context: local
EOF
export KUBECONFIG=/etc/kubernetes/kubeconfig

kubectl get namespace default >/dev/null 2>&1 || kubectl create namespace default >/dev/null
kubectl get namespace kube-system >/dev/null 2>&1 || kubectl create namespace kube-system >/dev/null
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
EOF

export GENPOLICY_CAPTURE_OUTPUT="${output_dir}"
containerd --config /etc/containerd/config.toml \
	>"${output_dir}/logs/containerd.log" 2>&1 &
pids+=("$!")
wait_for containerd ctr --address /run/containerd/containerd.sock version

ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
	--digests /opt/genpolicy/images/pause.tar >/dev/null
ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
	--digests /opt/genpolicy/images/busybox.tar >/dev/null
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
			--digests "${image}" >/dev/null
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi
while IFS= read -r image_ref; do
	digest=${image_ref##*@}
	if ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images list -q | grep -Fxq "${image_ref}"; then
		continue
	fi
	source_ref=$(
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images list |
			awk -v digest="${digest}" 'NR > 1 && $3 == digest { print $1; exit }'
	)
	if [[ -n "${source_ref}" ]]; then
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images tag \
			"${source_ref}" "${image_ref}" >/dev/null
	else
		[[ "${image_ref}" != "${LOCAL_REGISTRY}/"* ]] ||
			fail "no imported image has requested manifest digest ${digest}"
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images pull --hosts-dir /etc/containerd/certs.d "${image_ref}" >/dev/null
	fi
done <"${output_dir}/requested-images.txt"

case "$(uname -m)" in
x86_64) image_architecture=amd64 ;;
aarch64) image_architecture=arm64 ;;
ppc64le | s390x) image_architecture=$(uname -m) ;;
*) fail "unsupported image architecture: $(uname -m)" ;;
esac
python3 "${appliance_root}/scripts/capture_image_metadata.py" \
	--requested-images "${output_dir}/requested-images.txt" \
	--output "${output_dir}/images" \
	--ctr /usr/local/bin/ctr \
	--address /run/containerd/containerd.sock \
	--namespace k8s.io \
	--os linux \
	--architecture "${image_architecture}"

iptables --flush OUTPUT
iptables --append OUTPUT --out-interface lo --jump ACCEPT
iptables --policy OUTPUT DROP
ip6tables --flush OUTPUT
ip6tables --append OUTPUT --out-interface lo --jump ACCEPT
ip6tables --policy OUTPUT DROP
[[ "$(iptables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv4 outbound traffic"
iptables --check OUTPUT --out-interface lo --jump ACCEPT
[[ "$(ip6tables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv6 outbound traffic"
ip6tables --check OUTPUT --out-interface lo --jump ACCEPT

if [[ "${GENPOLICY_LEGACY_REFERENCE:-0}" == "1" ]]; then
	mkdir -p /etc/docker/registry /var/lib/registry
	cat >/etc/docker/registry/config.yml <<'EOF'
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: 127.0.0.1:5000
EOF
	registry serve /etc/docker/registry/config.yml \
		>"${output_dir}/logs/registry.log" 2>&1 &
	pids+=("$!")
	wait_for local-registry curl -fsS http://127.0.0.1:5000/v2/
	while IFS= read -r image_ref; do
		[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] || continue
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images push \
			--plain-http "${image_ref}" >/dev/null
	done < <(ctr --address /run/containerd/containerd.sock --namespace k8s.io images list -q)
fi

kubelet \
	--config=/etc/kubernetes/kubelet.yaml \
	--hostname-override="${NODE_NAME}" \
	--kubeconfig=/etc/kubernetes/kubeconfig \
	--node-ip="$(hostname -i | awk '{print $1}')" \
	--root-dir=/var/lib/kubelet \
	>"${output_dir}/logs/kubelet.log" 2>&1 &
pids+=("$!")
wait_for kubelet-node kubectl get "node/${NODE_NAME}"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--node-name "${NODE_NAME}" \
	--objects-output "${output_dir}/submitted-objects.json" \
	--pods-output "${output_dir}/pods.json" \
	--dynamic-output "${output_dir}/dynamic-values.json"

while IFS=$'\t' read -r namespace pod_name; do
	kubectl wait \
		--namespace "${namespace}" \
		--for=condition=Ready \
		--timeout=180s \
		"pod/${pod_name}"
done < <(python3 - "${output_dir}/pods.json" <<'PY'
import json
import sys

for pod in json.load(open(sys.argv[1], encoding="utf-8")):
    metadata = pod["metadata"]
    print(metadata.get("namespace", "default"), metadata["name"], sep="\t")
PY
)

expected_captures=$(python3 - "${output_dir}/pods.json" <<'PY'
import json
import sys

pods = json.load(open(sys.argv[1], encoding="utf-8"))
print(sum(1 + len(pod["spec"].get("initContainers", [])) + len(pod["spec"]["containers"]) for pod in pods))
PY
)

for _ in $(seq 1 180); do
	captures=$(find "${output_dir}/raw" -type f -name '*.config.json' | wc -l)
	if [[ "${captures}" -ge "${expected_captures}" ]]; then
		break
	fi
	sleep 1
done
captures=$(find "${output_dir}/raw" -type f -name '*.config.json' | wc -l)
[[ "${captures}" -eq "${expected_captures}" ]] ||
	fail "expected ${expected_captures} OCI captures, found ${captures}"

# Request capture needs the deployment's shim configuration and is mandatory,
# so reject an incomplete invocation before running audit-only prediction.
[[ -n "${GENPOLICY_KATA_CONFIG:-}" && -f "${GENPOLICY_KATA_CONFIG}" ]] ||
	fail "GENPOLICY_KATA_CONFIG must name a readable Kata configuration"

if [[ "${GENPOLICY_CAPTURE_BACKEND:-runtime-rs}" == "runc" ]]; then
	mkdir -p "${output_dir}/createcontainer-requests"
	direct_vol_arg=()
	[[ -n "${GENPOLICY_DIRECT_VOLUME_MOUNTS:-}" && -f "${GENPOLICY_DIRECT_VOLUME_MOUNTS}" ]] &&
		direct_vol_arg=(--direct-volume-mounts "${GENPOLICY_DIRECT_VOLUME_MOUNTS}")
	for spec in "${output_dir}"/raw/*.config.json; do
		name="$(basename "${spec}" .config.json)"
		meta="${spec%.config.json}.meta.json"
		cid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["container_id"])' "${meta}")"
		bundle="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("bundle",""))' "${meta}")"
		rootfs_mounts_arg=()
		[[ -f "${output_dir}/raw/${name}.rootfs-mounts.json" ]] &&
			rootfs_mounts_arg=(--rootfs-mounts "${output_dir}/raw/${name}.rootfs-mounts.json")
		/usr/local/bin/createreq-capture \
			--container-id "${cid}" \
			--bundle "${bundle:-/tmp/${cid}}" \
			--spec "${spec}" \
			--kata-config "${GENPOLICY_KATA_CONFIG}" \
			"${rootfs_mounts_arg[@]}" \
			"${direct_vol_arg[@]}" \
			--output "${output_dir}/createcontainer-requests/${name}.json" \
			2>>"${output_dir}/logs/createreq-capture.log" ||
			fail "createreq-capture failed for ${name}; see logs/createreq-capture.log"
	done
fi

request_captures=$(find "${output_dir}/createcontainer-requests" -type f -name '*.json' | wc -l)
[[ "${request_captures}" -eq "${expected_captures}" ]] ||
	fail "expected ${expected_captures} CreateContainerRequest captures, found ${request_captures}"

if [[ "${ROOTFS_MODE}" == "erofs-dmverity" ]]; then
	python3 - "${output_dir}/createcontainer-requests" <<'PY'
import json
import sys
from pathlib import Path

required = {
	"X-kata.dmverity-enabled=true",
	"X-kata.multi-layer=true",
}
for path in Path(sys.argv[1]).glob("*.json"):
	request = json.loads(path.read_text(encoding="utf-8"))
	protected = [
		storage
		for storage in request.get("storages", [])
		if required.issubset(storage.get("options", []))
		and any(option.startswith("X-kata.dmverity.roothash=") for option in storage.get("options", []))
		and any(option.startswith("X-kata.dmverity.hashoffset=") for option in storage.get("options", []))
	]
	if not protected:
		raise SystemExit(f"{path.name}: no strict dm-verity EROFS storage in final Agent request")
PY
fi

rootfs_mode="${ROOTFS_MODE}"

capture_bundle_args=(
	--source "${output_dir}"
	--bundle "${output_dir}/capture"
	--workload "${workload}"
	--profile "${profile_path}"
	--capture-backend "${GENPOLICY_CAPTURE_BACKEND:-runtime-rs}"
	--rootfs-mode "${rootfs_mode}"
	--outbound-sealed
	--configuration "containerd.toml=/etc/containerd/config.toml"
	--configuration "kubelet.yaml=/etc/kubernetes/kubelet.yaml"
	--configuration "cni.conflist=/etc/cni/net.d/10-genpolicy.conflist"
	--configuration "kata-configuration.toml=${GENPOLICY_KATA_CONFIG}"
	--input-image "pause.tar=/opt/genpolicy/images/pause.tar"
	--input-image "busybox.tar=/opt/genpolicy/images/busybox.tar"
)
if [[ "${GENPOLICY_CAPTURE_BACKEND:-runtime-rs}" == "runtime-rs" ]]; then
	capture_bundle_args+=(
		--capture-binary \
		"containerd-shim-kata-capture-v2=/usr/local/bin/containerd-shim-kata-capture-v2"
	)
else
	capture_bundle_args+=(
		--capture-binary "createreq-capture=/usr/local/bin/createreq-capture"
		--capture-binary "runc-capture=/usr/local/bin/runc-capture"
	)
fi
if [[ -d "${input_dir}/images" ]]; then
	input_image_number=0
	while IFS= read -r -d '' image; do
		input_image_number=$((input_image_number + 1))
		capture_bundle_args+=(
			--input-image \
			"$(printf 'input-image-%04d' "${input_image_number}")=${image}"
		)
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0 | sort -z)
fi

python3 "${appliance_root}/scripts/capture_bundle.py" build \
	"${capture_bundle_args[@]}"

if [[ "${GENPOLICY_CAPTURE_ONLY:-1}" == "1" ]]; then
	echo "Captured ${request_captures} CreateContainerRequests in ${output_dir}/capture"
	exit 0
fi

python3 "${appliance_root}/scripts/tag_oci.py" \
	--raw-requests-dir "${output_dir}/createcontainer-requests" \
	--dynamic-values "${output_dir}/dynamic-values.json" \
	--output-dir "${output_dir}/tagged-requests" \
	--manifest "${output_dir}/dynamic-tags.json"

# Opt-in coverage gate: refuse to generate a policy that would fail closed on an
# unsupported volume storage class (STRICT_STORAGE_COVERAGE=1).
coverage_arg=()
[[ "${STRICT_STORAGE_COVERAGE:-0}" == "1" ]] &&
	coverage_arg=(--strict-storage-coverage true)

genpolicy-oci-compiler \
	--raw-requests-dir "${output_dir}/createcontainer-requests" \
	--tagged-requests-dir "${output_dir}/tagged-requests" \
	--tag-manifest "${output_dir}/dynamic-tags.json" \
	--rules /opt/genpolicy/policy/rules.rego \
	--settings /opt/genpolicy/policy/settings \
	--workload "${workload}" \
	--output "${output_dir}/policy.rego" \
	--diff-output "${output_dir}/policy-oci-diff.json" \
	--annotation-output "${output_dir}/policy-annotation.txt" \
	--annotated-yaml-output "${output_dir}/workload-policy.yaml" \
	"${coverage_arg[@]}"

if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	python3 "${appliance_root}/scripts/tag_oci.py" \
		--raw-requests-dir "${output_dir}/createcontainer-requests" \
		--dynamic-values "${output_dir}/dynamic-values.json" \
		--output-dir "${output_dir}/tagged-requests-balanced" \
		--manifest "${output_dir}/dynamic-tags-balanced.json" \
		--regex-policy-mode balanced

	genpolicy-oci-compiler \
		--raw-requests-dir "${output_dir}/createcontainer-requests" \
		--tagged-requests-dir "${output_dir}/tagged-requests-balanced" \
		--tag-manifest "${output_dir}/dynamic-tags-balanced.json" \
		--rules /opt/genpolicy/policy/rules.rego \
		--settings /opt/genpolicy/policy/settings \
		--workload "${workload}" \
		--output "${output_dir}/policy-balanced.rego" \
		--diff-output "${output_dir}/policy-oci-diff-balanced.json" \
		--annotation-output "${output_dir}/policy-annotation-balanced.txt" \
		--annotated-yaml-output "${output_dir}/workload-policy-balanced.yaml" \
		--regex-policy-mode balanced \
		"${coverage_arg[@]}"
fi

if [[ "${GENPOLICY_LEGACY_REFERENCE:-0}" == "1" ]]; then
	policy_work_dir=/var/lib/genpolicy-appliance
	mkdir -p "${policy_work_dir}"
	cp "${workload}" "${policy_work_dir}/workload.yaml"
	genpolicy \
		--yaml-file "${policy_work_dir}/workload.yaml" \
		--rego-rules-path /opt/genpolicy/policy/rules.rego \
		--json-settings-path /opt/genpolicy/policy/settings \
		--containerd-socket-path=/run/containerd/containerd.sock \
		--insecure-registry "${LOCAL_REGISTRY}" \
		--silent-unsupported-fields \
		--raw-out \
		>"${output_dir}/legacy-reference-policy.rego" \
		2>"${output_dir}/logs/genpolicy-reference.log"
fi

if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	python3 "${appliance_root}/scripts/compare_policy_modes.py" \
		--output-dir "${output_dir}" \
		--output "${output_dir}/policy-mode-report.json"
fi

provenance_artifacts=(
	--artifact "kube-apiserver=/usr/local/bin/kube-apiserver"
	--artifact "kubelet=/usr/local/bin/kubelet"
	--artifact "kubectl=/usr/local/bin/kubectl"
	--artifact "etcd=/usr/local/bin/etcd"
	--artifact "containerd=/usr/local/bin/containerd"
	--artifact "runc=/usr/local/bin/runc.real"
	--artifact "genpolicy-oci-compiler=/usr/local/bin/genpolicy-oci-compiler"
	--artifact "storage-predictor=/usr/local/bin/storage-predictor"
	--artifact "createreq-capture=/usr/local/bin/createreq-capture"
	--artifact "containerd-config=/etc/containerd/config.toml"
	--artifact "kubelet-config=/etc/kubernetes/kubelet.yaml"
	--artifact "cni-config=/etc/cni/net.d/10-genpolicy.conflist"
	--artifact "genpolicy-settings=/opt/genpolicy/policy/settings/genpolicy-settings.json"
	--artifact "genpolicy-appliance-settings=/opt/genpolicy/policy/settings/genpolicy-settings.d/10-appliance.json"
	--artifact "pause-image=/opt/genpolicy/images/pause.tar"
	--artifact "busybox-image=/opt/genpolicy/images/busybox.tar"
)
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		provenance_artifacts+=(--artifact "input-image-$(basename "${image}")=${image}")
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi

provenance_generated=(
	--generated "policy.rego=${output_dir}/policy.rego"
	--generated "requested-images.txt=${output_dir}/requested-images.txt"
	--generated "policy-oci-diff.json=${output_dir}/policy-oci-diff.json"
	--generated "policy-annotation.txt=${output_dir}/policy-annotation.txt"
	--generated "workload-policy.yaml=${output_dir}/workload-policy.yaml"
)
if [[ -f "${output_dir}/storages-devices-predicted.json" ]]; then
	provenance_generated+=(
		--generated "storages-devices-predicted.json=${output_dir}/storages-devices-predicted.json"
	)
fi
if [[ -f "${output_dir}/rootfs-mounts-captured.json" ]]; then
	provenance_generated+=(
		--generated "rootfs-mounts-captured.json=${output_dir}/rootfs-mounts-captured.json"
	)
fi
if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	provenance_generated+=(
		--generated "dynamic-tags-balanced.json=${output_dir}/dynamic-tags-balanced.json"
		--generated "policy-balanced.rego=${output_dir}/policy-balanced.rego"
		--generated "policy-oci-diff-balanced.json=${output_dir}/policy-oci-diff-balanced.json"
		--generated "policy-annotation-balanced.txt=${output_dir}/policy-annotation-balanced.txt"
		--generated "workload-policy-balanced.yaml=${output_dir}/workload-policy-balanced.yaml"
		--generated "policy-mode-report.json=${output_dir}/policy-mode-report.json"
	)
fi

python3 "${appliance_root}/scripts/write_provenance.py" \
	--profile "${profile_path}" \
	--input "${workload}" \
	--tag-manifest "${output_dir}/dynamic-tags.json" \
	--raw-dir "${output_dir}/createcontainer-requests" \
	--tagged-dir "${output_dir}/tagged-requests" \
	--output "${output_dir}/provenance.json" \
	"${provenance_generated[@]}" \
	"${provenance_artifacts[@]}"

echo "Generated ${request_captures} tagged CreateContainerRequests and ${output_dir}/policy.rego"
