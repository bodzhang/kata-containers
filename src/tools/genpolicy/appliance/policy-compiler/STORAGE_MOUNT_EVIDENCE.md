# Kata-CC Storage and Mount Evidence

This document records what the appliance has established about Kata-CC storage
and mount handling from final captured `CreateContainerRequest` objects. It also
separates those observations from behavior known only through source inspection
or focused handler tests.

The distinction matters because a no-VM prediction can establish what a handler
is intended to produce, while a request recorded by `RecordingAgent` establishes
what the complete pinned runtime stack actually sent to the Agent boundary.

## Evidence report

`scripts/analyze_storage_mounts.py` analyzes a capture bundle and writes
`storage-mount-analysis.json`. `scripts/analyze_capture.sh` runs it as part of
normal offline bundle analysis in the analysis container.

Each claim has one of these statuses:

- `confirmed`: an authoritative final request contains the required shape;
- `not-exercised`: the authoritative bundle does not contain that workload or
  storage class;
- `not-authoritative`: the bundle's request authority is not
  `recording-agent`. This is the expected result for runc-native reconstructed
  requests;
- `configuration-unverified` or `contradicted`: a mode-specific request shape
  lacks the required bundled configuration evidence or conflicts with it.

Evidence entries name the request artifact and JSON pointer. The analyzer also
parses workload volume declarations so a ConfigMap or Secret used only through
`envFrom` is not mistaken for a mounted volume. Mode-specific claims also read
the exact bundled `config/kata-configuration.toml`; path shape alone does not
prove the active `shared_fs` mode.

## Capture-confirmed behavior

The following observations were reproduced with the exact guest-pull and EROFS
profiles. The standard workload provides sandbox plus two workload-container
requests. The targeted `storage-boundary-workload.yaml` provides sandbox plus
one workload-container request with emptyDir, ConfigMap, and hostPath inputs.
The reusable `storage-classes-workload.yaml` adds memory and disk emptyDir plus
mounted ConfigMap, Secret, and downwardAPI volumes. Run its authoritative
capture and report assertions with `make storage-e2e`.

### Guest-pull rootfs

Every final request in the guest-pull captures has one rootfs storage with:

- `driver = image_guest_pull`;
- `fs_type = overlay`;
- `source` equal to the digest-pinned workload image for workload containers;
- `mount_point` equal to the final OCI root path.

The sandbox uses its trusted pause identity rather than a workload image
digest. Policy generation takes each workload container's guest-pull identity
from this captured storage, not from predictor output.

### EROFS dm-verity rootfs

Every final request in the current EROFS capture has two storages at the OCI
root path:

- a writable `ext4` upper with `X-kata.overlay-upper` and
  `X-kata.multi-layer=true`;
- a read-only EROFS lower with `X-kata.dmverity-enabled=true`, an exact
  `X-kata.dmverity.roothash`, hash offset, salt and superblock settings,
  `X-kata.overlay-lower`, `X-kata.multi-layer=true`, and upper/work mkdir hints.

The two busybox workload containers share this captured lower identity:

```text
roothash=5cca62ebb3022c076db159f46431755bbd315afc5136b82231a91dae998789a9
hashoffset=4472832
```

The sandbox pause image has its own root hash and offset. The analyzer certifies
the EROFS claim only when the lower is read-only and contains both the enabled
flag and root hash, and the upper is writable.

### Kubernetes-generated files and `/dev/shm`

The standard and targeted captures confirm that kubelet/containerd-generated
files such as `hosts`, `hostname`, `resolv.conf`, and `termination-log` are bind
mounted from generated paths below:

```text
/run/kata-containers/shared/containers/<container-id>-<16-hex>-<name>
```

They also confirm that `/dev/shm` is a UVM-local bind mount whose exact source
is:

```text
/run/kata-containers/sandbox/shm
```

The compiler confines generated external bind sources to Kata's shared
filesystem domain and treats `/dev/shm` as an exact special case.

### `shared_fs = "none"` ConfigMap and hostPath directory

The targeted capture mounts a ConfigMap at `/configuration`. Its final OCI bind
source has this shape:

```text
/run/kata-containers/shared/containers/<container-id>-<16-hex>-configuration
```

No ConfigMap `Storage` appears in the request. This confirms the runtime-rs
copy-to-rootfs path for this profile: the mount is represented by its rewritten
OCI source rather than an Agent storage.

A declared hostPath directory mounted at `/external-data` is rewritten into the
same generated guest-share domain and likewise has no Agent storage. This
observation describes the captured request shape; it does not make the host
contents trusted.

The fixture also declares `/dev/null` as a character-device hostPath at
`/external-device`. That destination appears in neither final OCI mounts nor
Agent devices. The current bundle therefore does not support a claim that this
host-device declaration reaches the Agent request.

### Disk emptyDir in shared-fs mode

The targeted capture confirms that its disk emptyDir becomes:

- Agent storage with `driver = local`, `source = local`, `fs_type = local`, and
  `options = ["mode=0777"]`;
- an OCI mount with `type = local` at the declared `/cache` destination;
- a guest mount point below the sandbox-correlated
  `rootfs/local/cache` path.

The `storage-classes-workload.yaml` capture also confirms the memory emptyDir
case: runtime-rs emits `driver = ephemeral`, `source = tmpfs`, and
`fs_type = tmpfs`, with a mount point below
`/run/kata-containers/sandbox/ephemeral/`. The shared-fs capture is not evidence
for hugepage mode.

### Plain block emptyDir

The `storage-e2e` matrix also runs the workload with
`emptydir_mode = "block-plain"`. The final RecordingAgent request confirms the
same block source, ext4 filesystem, `create_filesystem`, `fs_group`, sharing,
source-derived mount point, and correlated OCI bind mount as encrypted mode,
but without `encryption_key=ephemeral`. The current authoritative fixture uses
the `blk` transport; `scsi`, `mmioblk`, `blk-ccw`, and `nvdimm` source grammars
and mount-point derivation are covered by shared Rego tests.

### CDH-managed encrypted block emptyDir

The `storage-e2e` matrix runs the same Kubernetes workload again with
`emptydir_mode = "block-encrypted"`. The final RecordingAgent request confirms
that its disk emptyDir becomes:

- `driver = blk`, `fs_type = ext4`, and a dry-run device source assigned by the
  real runtime-rs device manager;
- both `encryption_key=ephemeral` and `create_filesystem` driver options;
- `shared = true` and an exact `fs_group` copied from the pod's `fsGroup`;
- a mount point below `/run/kata-containers/sandbox/storage/` whose final
  component is the base64url-encoded device source;
- an OCI bind mount whose source exactly equals that storage mount point.

This is authoritative for the shim-to-Agent request and policy boundary. The
RecordingAgent does not execute CDH, create a dm-crypt mapping, format ext4, or
mount it in a guest. Those operations remain production Agent/CDH integration
behavior rather than no-VM capture behavior.

## Not yet capture-confirmed

The recovered storage analysis also described the following behaviors. They
remain useful implementation knowledge, but the current authoritative bundles
do not exercise them:

| Behavior | Current support evidence | Missing capture evidence |
|---|---|---|
| virtio-fs watchable ConfigMap/Secret/projected volume emits `watchable-bind` storage and a `watchable/sandbox-<8-hex>-<name>` mount | runtime-rs source, predictor integration test, Rego tests | exact runtime-rs profile with virtio-fs and a mounted projected volume |
| hugepage emptyDir emits `hugetlbfs` storage | runtime-rs handler and predictor/Rego tests | workload requesting hugepages |
| single-layer block rootfs carries `X-kata.dmverity.*` | rootfs handler and predictor/Rego tests | a containerd snapshotter/differ that produces one block rootfs mount with real dm-verity metadata |
| raw block `volumeDevices[]` and NVIDIA VFIO requests are bounded per container | compiler and Rego tests | workload plus host devices that produce final Agent devices |
| filesystem-mode block PVC or raw direct volume emits block-driver storage and a correlated OCI bind mount without `create_filesystem` | runtime-rs `BlockVolume` and direct-volume handlers | a CSI/PVC deployment with authoritative device-manager output |
| SPDK/spool or VFIO direct volume emits device-backed storage and a correlated OCI bind mount | runtime-rs direct-volume handlers | the required vhost-user socket or VFIO hardware and CSI direct-volume metadata |
| non-watchable virtio-fs hostPath, projected, or filesystem PVC rewrites the OCI bind source without necessarily emitting Agent storage | runtime-rs ShareFs handler and compiler path-shape tests | production ShareFs initialization or a dedicated no-VM model |

These rows must not be promoted to `confirmed` merely because a unit test
constructs the expected object. A targeted bundle must contain the final Agent
request and the analyzer must point to it.

The no-VM capture shim cannot currently provide authoritative watchable-bind
evidence. Production initializes ShareFs from
`ResourceManager::prepare_before_start_vm()` during `VirtSandbox::start()`, but
`CaptureSandbox` deliberately skips VM startup and `DryRunHypervisor` advertises
no filesystem-sharing capability. Calling the production ShareFs preparation
stage directly requires VM/daemon device setup and terminates the capture shim.
Until a dedicated no-VM ShareFs model exists, a virtio-fs configuration alone
must not be interpreted as watchable-bind evidence.

Hugepage capture is conditional on the host exposing a nonzero hugepage pool.
A host with zero configured and free 2 MiB and 1 GiB pages cannot admit a
meaningful Kubernetes hugepage workload, so predictor tests remain
non-authoritative for that class on such a host.

Single-layer block dm-verity has a different producer gap. Runtime-rs consumes
one block rootfs mount carrying `X-containerd.dmverity=<metadata-file>` and
translates it to guest-facing `X-kata.dmverity.*` options. The current
containerd 2.3 appliance profiles produce either guest-pull rootfs or
multi-layer EROFS dm-verity; none produces that single block mount and metadata
contract. A hand-written `--rootfs-mounts` array can test the handler but is not
authoritative capture evidence. This class remains `not-exercised` until a real
snapshotter/differ supplies it to the capture shim.

Nydus is deliberately outside the current confidential-rootfs profile set. Its
host-prepared virtio-fs path is not established by these captures and should not
be described as a supported confidential rootfs mechanism.

The compiler now treats storage-bearing rootfs classes differently from
ordinary unsupported volumes. Guest-pull, a valid EROFS lower/upper pair, and a
read-only single-layer dm-verity block rootfs are accepted. Nydus overlay
storage, unprotected block rootfs, malformed EROFS, and unknown rootfs storage
fail generation unconditionally. Generic block/direct volumes remain omitted
to fail closed, or fail generation under strict storage coverage, until their
device and mount correlation is supported.

## Sandbox storage contract

Runtime-rs constructs `CreateSandboxRequest.storages` only after VM startup. It
includes the sandbox `/dev/shm` `ephemeral`/`tmpfs` storage and may prepend
ShareFs-provided storage. The no-VM appliance therefore does not capture this
request. `policy-oci-diff.json` records the enforced sandbox storages from the
effective versioned settings as `authority = versioned-settings` and
`capture_status = not-captured`. This is an explicit configuration contract,
not a claim that `RecordingAgent` observed the production request.

## Security interpretation

Capture proves request structure, not trust in host-provided bytes. ConfigMap,
Secret, hostPath, and raw block contents remain host-supplied even when policy
pins their mount shape. Confidential data needs a trusted in-guest delivery
path such as KBS or CDH. Guest-pull binds image identity to a digest inside the
guest, while dm-verity binds protected bytes to the captured root hash.

The compiler derives supported volume storage templates and rootfs identities
directly from each final request. Predictor output is useful for focused handler
diagnostics but is neither evidence in this document nor a policy input.
