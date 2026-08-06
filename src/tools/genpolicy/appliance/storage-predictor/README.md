# storage-predictor

`storage-predictor` runs selected runtime-rs storage and volume handlers without
booting a VM. Given an OCI `config.json` and deployment settings, it emits the
Agent `Storage` objects, devices, and rewritten OCI mounts that those handlers
would produce.

The predictor is standalone diagnostic and test tooling. It is not part of
capture-bundle analysis and its output is not a policy-compiler input.
For conclusions derived from final captured requests, see
[Kata-CC Storage and Mount Evidence](../policy-compiler/STORAGE_MOUNT_EVIDENCE.md).

## Relationship to capture and analysis

For the runtime-rs profiles, `RecordingAgent` records the final
`CreateContainerRequest` after runtime-rs has transformed the OCI specification,
rootfs, volumes, storages, and devices. Those recorded requests are the policy
compiler's authority. The compiler templates supported storages and mounts
directly from each request's `storages` and `oci.mounts` fields.

For the runc-native profile, raw OCI is authoritative. Its reconstructed
`CreateContainerRequest` files are diagnostic and must not be treated as
evidence of runtime-rs or Agent behavior.

`scripts/analyze_capture.sh` does not invoke `storage-predictor` or
`scripts/predict_storages.py`. A `storages-devices-predicted.json` report is not
part of the capture-bundle schema.

## Usage

```console
storage-predictor \
  --config <oci-config.json> \
  --output <predicted.json> \
  [--sid <sandbox-id>] \
  [--cid <container-id>] \
  [--kata-config <configuration.toml>] \
  [--emptydir-mode <mode>] \
  [--block-driver <driver>] \
  [--disable-guest-empty-dir] \
  [--guest-pull-rootfs | --rootfs-mounts <mounts.json>]
```

`--kata-config` supplies the active runtime and hypervisor settings. Without it,
the predictor uses `--emptydir-mode` and `--block-driver`, whose defaults are
`shared-fs` and `virtio-blk-pci`.

`--guest-pull-rootfs` asks the predictor to model a guest-pull rootfs.
`--rootfs-mounts` runs the rootfs handler against an explicitly supplied Kata
mount artifact. These options are mutually exclusive and are intended for
focused diagnostics; neither reproduces evidence from a capture bundle.

The audit-only `scripts/predict_storages.py` wrapper can run the predictor over
a directory of raw OCI files and combine the results. Per-container failures are
recorded in the report instead of aborting the whole run.

## Output and execution requirements

The standalone binary writes a schema-versioned JSON object containing the
sandbox and container IDs, optional CRI container name, resolved
`emptydir_mode`, predicted volumes, and optional rootfs result. Each volume
contains its storages, rewritten OCI mounts, and optional device ID. A rootfs
handler failure is retained as `rootfs.error` so it does not discard successful
volume diagnostics.

The `predict_storages.py` wrapper emits `{schema_version, predictions}`. A
binary failure becomes a per-container `{container_id, sandbox_id, error}`
entry; it does not abort the remaining predictions. This non-gating behavior is
intentional because prediction is a compatibility signal, not request evidence.

Some handlers require more than the serialized OCI spec:

- `update_ephemeral_storage_type` inspects live host `mountinfo` and filesystem
  metadata, so emptyDir classification must run while the captured host volume
  paths still exist;
- block and EROFS handlers stat backing files or devices, so diagnostic rootfs
  mount sources must exist in the predictor's mount namespace;
- `--kata-config` should point to the deployment configuration when comparing
  behavior because `shared_fs`, `emptydir_mode`, and block driver change the
  resulting request shape.

## What current captures establish

The exact profile captures used to validate the appliance establish the
following request shapes:

| Profile | Request authority | Observed storage and mount behavior |
|---|---|---|
| guest-pull | final request recorded by `RecordingAgent` | Each container has an `image_guest_pull` rootfs storage. Kubernetes-generated files such as `hosts`, `hostname`, `resolv.conf`, and `termination-log` are rewritten to guest paths below `/run/kata-containers/shared/containers/`. `/dev/shm` is a bind mount from `/run/kata-containers/sandbox/shm`. |
| EROFS dm-verity | final request recorded by `RecordingAgent` | Each rootfs has a writable `ext4` upper and a read-only EROFS lower. The lower carries `X-kata.dmverity.*`, `X-kata.overlay-lower`, `X-kata.multi-layer=true`, and mkdir hints; the upper carries `X-kata.overlay-upper` and `X-kata.multi-layer=true`. |
| guest-pull, `shared_fs = "none"` storage matrix | final request recorded by `RecordingAgent` | Memory emptyDir becomes `ephemeral`/`tmpfs`; disk emptyDir becomes `local`; mounted ConfigMap, Secret, and downwardAPI volumes use copy-to-rootfs guest paths. |
| guest-pull, `emptydir_mode = "block-encrypted"` storage matrix | final request recorded by `RecordingAgent` | Disk emptyDir becomes shared `blk`/`ext4` storage with `encryption_key=ephemeral`, `create_filesystem`, exact `fs_group`, and a correlated storage-backed OCI bind mount. This confirms the CDH trigger at the request boundary, not CDH, LUKS, or dm-crypt execution. |
| runc-native | raw OCI | No authoritative Agent storage or device behavior is available. Any reconstructed request is diagnostic only. |

The standard validation workload references a ConfigMap and Secret through
`envFrom`, but the separate `storage-e2e` workload mounts projected volumes and
emptyDirs. Current authoritative captures still do not exercise hugepage,
block PVC, VFIO, virtio-fs watchable mounts, or single-layer block dm-verity.
Hugepage capture requires a host with a nonzero hugepage pool. Single-layer
block dm-verity requires a real containerd producer for one block rootfs mount
and its `X-containerd.dmverity` metadata; a hand-written `--rootfs-mounts`
artifact remains diagnostic.

## Handler coverage

The predictor and its tests exercise these runtime-rs paths independently of
the captured bundles:

- guest-pull rootfs transformation;
- EROFS multi-layer and single-layer dm-verity rootfs handling when supplied
  suitable diagnostic mount input;
- shared, local, ephemeral, and hugepage volume handlers;
- block-plain and block-encrypted emptyDir handlers;
- ConfigMap, Secret, projected, and downwardAPI handling for
  `shared_fs = "none"` and virtio-fs;
- dry-run block-device address assignment for supported block drivers.

This is implementation and test coverage, not capture evidence. The predictor
uses a dry-run hypervisor/device manager, and its share-fs implementation
contains a small reproduction of behavior that cannot run without virtiofsd and
host mounts. Results should be compared with a final recorded request before
being used to diagnose runtime drift.

### ConfigMap and Secret volumes

Source inspection and focused tests show two runtime-rs mechanisms:

- With `shared_fs = "none"`, runtime-rs copies projected files through Agent
  `CopyFile` calls and rewrites the OCI bind-mount source to a path shaped like
  `<guest-share>/<container-id>-<16-hex>-<destination-name>`. It emits no
  `Storage` for that mount.
- With virtio-fs, watchable Kubernetes volumes may produce a `watchable-bind`
  storage and a guest path containing `watchable/sandbox-<8-hex>-<name>`.
  Watchability is decided by runtime-rs from the source path and file state.

The `shared_fs = "none"` mechanism is confirmed by `storage-e2e`. The virtio-fs
mechanism is not capture-confirmed because production ShareFs initialization is
part of VM startup and the no-VM capture shim does not model it. In particular,
the presence of ConfigMap or Secret values in container environment variables
does not imply a ConfigMap/Secret volume storage or mount.

### Rootfs identity

In current policy generation, rootfs identity comes from the captured request:

- `image_guest_pull` source values supply per-container image identity;
- `X-kata.dmverity.roothash=` options supply per-container EROFS or block-rootfs
  identity.

The compiler adds per-container marker storages to the policy so one workload
container cannot use another container's captured rootfs identity. This process
does not consume predictor output. Root-hash marker matching currently uses set
membership, so it does not enforce lower-layer order or multiplicity.

### Volumes and devices

The compiler templates supported non-rootfs storages directly from the captured
request. Current templates cover `tmpfs`, `local`, `hugetlbfs`,
`watchable-bind`, and block-backed emptyDir storages marked with
`create_filesystem`. Unsupported storage classes are omitted so runtime policy
evaluation fails closed; strict coverage turns that condition into a compiler
error.

Raw block `volumeDevices[]` and requested NVIDIA VFIO device counts are also
bounded by workload declarations. A device path or count does not attest device
contents. The current profile bundles contain no devices, so those behaviors are
supported by code and policy tests rather than by the available capture
evidence.

## Security boundary

The policy can constrain storage type, options, mount shape, image digest, and
dm-verity root hash where those values are available. It does not make
host-supplied ConfigMap, Secret, hostPath, or raw block contents trusted.
Confidential data requires a trusted in-guest delivery mechanism such as KBS or
CDH; guest-pull verifies image identity inside the guest, and dm-verity protects
the bytes covered by its root hash.

Nydus rootfs is outside this predictor's confidential-rootfs coverage because
the runtime path depends on host-prepared data shared through virtio-fs. The
supported confidential rootfs profiles use guest-pull or EROFS dm-verity.

## Validation

Run the focused unit and integration tests with:

```console
cargo test --locked --package kata-storage-predictor
python3 -m unittest \
  src/tools/genpolicy/appliance/tests/test_predict_storages.py
```

The appliance-wide validation additionally checks the request compiler and Rego
storage rules:

```console
cd src/tools/genpolicy/appliance
./tests/validate.sh
make storage-e2e PROFILE=k8s-1.33-containerd-2.3-guest-pull
```
