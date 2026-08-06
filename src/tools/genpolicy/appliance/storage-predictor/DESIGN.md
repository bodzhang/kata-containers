# storage-predictor design

This document holds the design rationale and prediction internals for the
storage-predictor. Usage, current capture coverage, and validation commands are
in [README.md](README.md).

The predictor's job is to produce the Kata Agent `storages` and `devices` a
workload would generate **without booting a VM** for focused diagnostics and
runtime-drift tests. It is not part of capture-bundle analysis and its output is
not a policy-compiler input. Final requests recorded by `RecordingAgent` are the
authority for runtime-rs policy generation. The sections below explain why the
downstream Agent shape matters and how the predictor exercises selected
runtime-rs handlers independently.

## Design

### What "storage" is in a Kata-CC UVM, and who decides it

A confidential Kata guest (UVM) never sees the Kubernetes volume spec. It sees a
kata-agent `CreateContainerRequest` carrying a list of **`storages`** (rootfs
layers, emptyDir/configMap/secret volumes, …) and **`devices`**, each fully
concrete: a driver, a guest source (`/dev/vdX`, a PCI/SCSI address, a shared-fs
tag), a mount point, options, `fs_group`. That concrete shape is the product of a
pipeline of authorities, each of which adds to or *mutates* the storage:

| Authority | Trust (CoCo) | What it decides |
|---|---|---|
| **Workload YAML** (author) | trusted *intent* | the volume/device **set** (emptyDir, configMap, secret, projected, hostPath, PVC `volumeDevices`), the **image** (must be digest-pinned), `securityContext.fsGroup`, hugepage / `nvidia.com/pgpu` requests |
| **Kubelet / K8s** | untrusted (host) | materializes volumes on the host — creates the emptyDir dir and sets its **GID** from `fsGroup`, projects secret/configMap files — and emits the CRI `ContainerConfig` |
| **containerd** (CRI + snapshotter) | untrusted (host) | lowers CRI → OCI bundle `config.json` (a runtime-agnostic **bind/tmpfs** mount list), and the **snapshotter** produces the rootfs mounts (overlay for runc; erofs / guest-pull / block for kata) |
| **Kata-CC shim** (`runtime-rs`) | trusted code, **host-controlled config** | the step where concrete Agent storage is *born*: rewrites bind/tmpfs → `ephemeral`/`local`, plugs block devices, applies `emptydir_mode` (shared-fs / local / **block-encrypted** / block-plain), computes guest paths, dm-verity options, `fs_group`, the guest-pull `KataVirtualVolume` |
| **Kata-CC agent** (in-TEE) | trusted, **enforces** | receives the request and checks every storage/device against the attested policy |

Two facts drive every design choice below:

1. **Only the shim's output (row 4) is enforceable**, because that is exactly
   what the agent (row 5) sees. The YAML (row 1) is authoritative for *intent*
   but not for the guest storage *shape* — rows 2–4 mutate it (a YAML `emptyDir`
   becomes a `tmpfs` `ephemeral` storage, or an `ext4` `blk` device, depending on
   configuration the YAML never states).
2. **Part of the shape is decided by host-controlled Kata configuration, not by
   the YAML** — `shared_fs`, the block driver, and `emptydir_mode` live in the
   deployment's `configuration.toml`, so the *same* YAML yields *different*
   storages on different CC profiles.

### Threat model the storage policy addresses

Under Confidential Containers the **host is untrusted** (hypervisor, containerd,
kubelet, node OS); the guest kernel, agent, and the attested policy are trusted.
A malicious host controls the `CreateContainerRequest`, so the storage policy
exists to bind that request to the workload author's intent and deny host
tampering:

- **rootfs substitution** — the host serves a different image → defended by
  guest-pull **digest** pinning and erofs / single-layer **dm-verity root-hash**
  pinning.
- **volume injection / redirection** — the host adds a storage, or repoints an
  existing one's source/mount_point to exfiltrate or inject data → defended by
  pinning each storage's `driver`, `source`, `mount_point`, `options`, `fs_group`.
- **trusted-device swap** — the host swaps a verity-protected device for an
  untrusted one → defended by pinning the root hash (device *identity*).
- **extra devices** — defended by pinning the device *set*.

Explicitly **out of scope**: the *content* of host-supplied block `volumeDevices`
(baseline-untrusted under CoCo — the guest treats them as untrusted input), host
denial-of-service, and side channels. That scoping is why, e.g., raw block
volumes are pinned only by `container_path` (bounding the set) rather than by
content.

### Design choices that follow

- **Dry-run the real mutation handlers.** The predictor runs runtime-rs
  `VolumeResource::handler_volumes` and `RootFsResource::handler_rootfs` over
  explicit diagnostic inputs. Linking the `resource` crate keeps those handler
  encodings aligned without making prediction authoritative.
- **Skip the VM at the `Hypervisor` seam.** Storage synthesis is separable from
  VM lifecycle, so the predictor supplies a no-op *dry-run* `Hypervisor` and a
  stub `Agent`; guest device paths come from the device manager's deterministic
  index allocation and a synthesized PCI/SCSI address (see *Dry-run block device
  address synthesis*), not from live hotplug.
- **Feed the shim the deployment's Kata-CC configuration.** Since the storage
  shape depends on `shared_fs` / block driver / `emptydir_mode` (host-controlled
  config, not YAML), the predictor sources the *same* `configuration.toml`
  (`--kata-config`) so its prediction matches the CC shim the workload will
  actually run under.
- **Keep prediction separate from declarations and evidence.** Workload YAML
  describes intent, while the final captured request describes the actual Agent
  input. Predictor output can explain differences between them but replaces
  neither source.
- **Reproduce only the unavoidable host-side rewriting.** The shim's
  `kata_sys_util::k8s::update_ephemeral_storage_type` rewrites containerd
  `bind`/`tmpfs` mounts into Kata `ephemeral`/`local` types and today inspects
  live host mount state (`mountinfo`/`stat`) to classify a disk- vs memory-backed
  emptyDir — a **current implementation coupling**, not an inherent need, since
  that intent is also in the YAML (`emptyDir.medium`); see *Known gaps: fidelity
  assumptions*. The one path that cannot be reused as-is (`VirtiofsShareMount`,
  entangled with virtiofsd) is *mirrored*, with the drift surface documented (see
  *Drift risk*).
- **Record failures without gating.** The wrapper records per-container errors,
  and rootfs errors remain attached to otherwise successful volume output. The
  capture validator and compiler apply their own independent fail-closed checks.
- **Serialization mirror.** `agent::types::Storage`/`Device` are not `Serialize`,
  so the tool maps them to local serializable structs for the JSON output.

The remaining distinctions are fidelity questions: which handler code runs
directly, which inputs depend on live host state, and which virtio-fs behavior
must be mirrored because production initialization is VM-bound.

### Diagnostic fidelity and drift

Most volume and rootfs transforms call runtime-rs handlers directly. Two input
dependencies and one reproduced path can still diverge from production:

- `update_ephemeral_storage_type` reads live host mount state and filesystem
  metadata. Running later against stale or absent kubelet paths can misclassify
  memory and disk emptyDir mounts.
- Block and EROFS handlers stat their source files or devices and may create
  host-side directories. A serialized mount array without the referenced
  artifacts is insufficient.
- Real `VirtiofsShareMount` initialization requires virtiofsd, host mounts, and
  VM lifecycle. `StubShareFsMount` therefore mirrors its side-effect-free
  `share_volume` result. It reuses `do_get_guest_path`,
  `is_watchable_mount`, `kata_guest_share_dir`, and `PASSTHROUGH_FS_DIR`, but
  mirrors the private `watchable` and `watchable-bind` constants plus the small
  storage-construction branch. Upstream changes to that branch can drift until
  an alignment test or public side-effect-free helper replaces the mirror.

Watchability itself depends on live source contents. `is_watchable_mount`
accepts only ConfigMap or Secret paths with between one and eight files; an
empty directory, traversal/count error, or more than eight files takes the
non-watchable path. Predictor virtio-fs results therefore depend on the file set
present at execution time and remain diagnostic until compared with a final
request.

### Output and failure contract

The binary emits schema version 1 with container identity, resolved
`emptydir_mode`, predicted volumes, and optional rootfs output. Each volume
contains storages, rewritten OCI mounts, and an optional device ID. Rootfs
transform failures are serialized in `rootfs.error`; they do not discard volume
results. The directory wrapper similarly records binary failures per container
and continues, preserving partial diagnostic coverage.


## Rootfs prediction (design)

The predictor can exercise rootfs handlers from explicit diagnostic mounts even
when those mounts are unavailable in an OCI-only input. Runtime-rs produces the
container rootfs through
`RootFsResource::handler_rootfs` (`resource/src/rootfs/mod.rs`), which dispatches
by the shape of `rootfs_mounts`:

- empty → `ShareFsRootfs`
- erofs multi-layer (`is_erofs_multi_layer`) → `ErofsMultiLayerRootfs`
- single layer: guest-pull (`is_guest_pull_volume`) → `VirtualVolume`; block
  (`is_block_rootfs`) → `BlockRootfs`; nydus → `NydusRootfs`; else `ShareFsRootfs`

`handler_rootfs` takes exactly the three dependencies the predictor already stubs
(`Option<Arc<dyn ShareFs>>`, `RwLock<DeviceManager>`, `&dyn Hypervisor`) plus
`sid`/`cid`/`root`/`bundle_path`/`rootfs_mounts`/`annotations`. Two target models
matter for confidential guests:

### Guest-pull rootfs (mainstream CoCo) — tractable, no snapshotter

`VirtualVolume::new` → `handle_virtual_volume_storage`
(`resource/src/rootfs/virtual_volume.rs`) is a **pure** transform: no device
manager, no hypervisor, no snapshotter. For a
`KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL` volume it derives the Agent `Storage`
entirely from data the appliance already captures:

- `source` = image reference read from the OCI annotation
  `io.kubernetes.cri.image-name` (or the cri-o key) via `get_image_reference`
- `driver` = `image_guest_pull`, `fs_type` = `overlay`
- `mount_point` = `/run/kata-containers/<cid>/rootfs`
- `driver_options` = the serialized `ImagePull` metadata (the pod annotations)

Because the guest pulls and verifies the image by digest inside the TEE, this
storage is **deterministic from the diagnostic OCI spec** — the predictor
synthesizes the guest-pull `KataVirtualVolume` option (via the shim's own
`adjust_rootfs_mounts`), calls `handler_rootfs`, and emits the real Agent
`Storage` with no snapshotter, VM, or device. **Implemented** via
`--guest-pull-rootfs` and proven by the `predicts_guest_pull_rootfs` integration
test. Authoritative guest-pull identity comes from the final request's
`image_guest_pull` source.

### Multi-layer erofs rootfs — implemented (`--rootfs-mounts`)

The predictor consumes a diagnostic `rootfs_mounts` artifact via
`--rootfs-mounts <file>` (a JSON array of `kata_types::mount::Mount`). A
multi-layer erofs artifact (an `ext4` `rw` upper layer, an `erofs` lower layer,
and an `overlay` mount)
is routed by `handler_rootfs` to `ErofsMultiLayerRootfs`, which — like the block
path — runs `do_handle_device` for each layer. Under the dry-run device manager
each layer gets a deterministic `/dev/vdX` guest path with **no VM**, and
`get_storage()` returns the two Agent `Storage` objects the guest agent would use
to assemble the overlay (upper `ext4` + lower `erofs`, both `X-kata.multi-layer`).
The predicted rootfs is emitted under the `rootfs` key of the output. Proven by
the `dry_run_erofs_multi_layer_produces_layer_storages` unit test and the
`predicts_erofs_multi_layer_rootfs` integration test.

All three CC block drivers work under the dry-run: `virtio-blk-mmio`'s Agent
source is the deterministic `virt_path` (`/dev/vdX`), while `virtio-blk-pci`
(`blk`), `virtio-scsi` (`scsi`), and `virtio-blk-ccw` (`blk-ccw`) get a
deterministic `pci_path` / `scsi_addr` / `ccw_addr` synthesized by the dry-run
`add_device`. Proven by the `predicts_erofs_multi_layer_rootfs_pci` integration
test and the `erofs_pci_driver_synthesizes_pci_path` unit test. Confidential
guests use `virtio-scsi` (QEMU) or `virtio-blk-pci` (CLH/dragonball); the
synthetic predictor address only needs the shape expected by the handler and
storage grammar.

For focused diagnostics, callers may supply a rootfs mount artifact directly to
`--rootfs-mounts`. This exercises the same handler without a VM, but it is not a
capture input and never contributes to policy. The authoritative appliance path
uses containerd's real EROFS snapshotter and mount manager, then records the
final Agent storages through `RecordingAgent`.

For **integrity diagnostics**, this branch tracks upstream `erofs_rootfs.rs` +
   `kata-types::gpt_disk`, so the predictor emits the erofs **dm-verity root hash**
   through the real handler. When the captured `rootfs_mounts` has **more than one**
   erofs layer (GPT+VMDK mode) and each erofs layer carries an
   `X-containerd.dmverity=<metadata.json>` option, `ErofsMultiLayerRootfs` parses
   that metadata (`roothash`, `hashoffset`) and, via
   `gpt_disk::generate_dmverity_options`, appends to each erofs lower-layer
   `Storage.options`:

   ```
   X-kata.dmverity-enabled=true
   X-kata.dmverity.roothash=<hash>
   X-kata.dmverity.hashoffset=<off>
   X-kata.dmverity.salt=<salt>
   X-kata.gpt-partitioned=true, X-kata.partition-number=N
   ```

   Proven with no VM by `dry_run_erofs_gpt_dmverity_emits_roothash` (unit) and
   `predicts_erofs_dmverity_rootfs` (binary end-to-end). This is the containerd
   erofs dm-verity mode (`dmverity_mode = 'on'` + differ `enable_dmverity = true`,
   enabled by kata-deploy `erofs_dmverity`); the guest agent's `multi_layer_erofs.rs`
   activates a dm-verity device per layer from these options. A separate,
   Go-runtime dm-verity model exists via `KataVirtualVolume` `image_raw_block` /
   `layer_raw_block` / `*_nydus_block` carrying `DmVerityInfo`.

A `virtio-blk-pci` deployment works with no VM: the dry-run `add_device`
synthesizes a deterministic `pci_path` for each layer (see **Dry-run block
device address synthesis** below), so the erofs transform completes and each
layer's Agent `source` is a `PciPath` slot (`"xx"`) instead of `/dev/vdX`. Proven
by `predicts_erofs_multi_layer_rootfs_pci` (binary) and
`erofs_pci_driver_synthesizes_pci_path` (unit).

### Single-layer block / dm-verity rootfs — implemented

For a single-layer host-prepared block rootfs, `BlockRootfs::new`
(`resource/src/rootfs/block_rootfs.rs`) runs the same device flow. `BlockRootfs`
now honors the `X-containerd.dmverity` mount annotation and translates it into
the `X-kata.dmverity.*` storage options via the shared
`kata_types::gpt_disk` helpers (the same ones the multi-layer erofs path uses),
so a single verity-protected block image is pinned by its root hash exactly like
an erofs lower layer. `is_block_rootfs` needs a **real** source that stats as a
block device (`S_IFBLK`) or a loop-backed regular file (`S_IFREG` + the `loop`
option); the predictor test uses the loop-file form so the whole path runs with
no VM (`dry_run_single_layer_dmverity_emits_roothash`). Any CC block driver
works (`virtio-blk-mmio` `mmioblk` uses the deterministic `/dev/vdX` source;
`virtio-blk-pci`/`virtio-scsi`/`virtio-blk-ccw` get a synthesized address — see
**Dry-run block device address synthesis** below).

### Dry-run block device address synthesis

Block-backed handlers (`BlockRootfs`, `ErofsMultiLayerRootfs`,
`BlockEmptyDirVolume`, `block_volume`) set the Agent `storage.source` from the
guest device address the hypervisor backend assigns during attach, which varies
by driver: `virtio-blk-mmio` (`mmioblk`) uses `config.virt_path` (`/dev/vdX`),
but `virtio-blk-pci` (`blk`) reads `config.pci_path`, `virtio-scsi` (`scsi`)
reads `config.scsi_addr`, and `virtio-blk-ccw` (`blk-ccw`) reads
`config.ccw_addr`. Only `virt_path` is assigned by the device manager before
attach; the other three are populated by the real hypervisor's device-attach
round-trip, which the dry-run has no VM to perform.

The dry-run `DryRunHypervisor::add_device` therefore synthesizes them
deterministically from the device index, for `DeviceType::BlockModern` devices:

| driver (`driver_option`) | field set | value |
| --- | --- | --- |
| `blk` (`virtio-blk-pci`) | `pci_path` | `PciPath::try_from(index + 1)` — slot 0 is reserved, renders as `"01"`, `"02"`… |
| `scsi` (`virtio-scsi`) | `scsi_addr` | `"<index>>8>:<index&0xff>"` (SCSI-id:LUN) |
| `blk-ccw` (`virtio-blk-ccw`) | `ccw_addr` | `"0.0.<index:04x>"` |
| `mmioblk` (`virtio-blk-mmio`) | — | untouched; `virt_path` already assigned |

Because `add_device` receives the `Arc<Mutex<BlockDeviceModern>>` the handler
holds, the mutation flows back into the handler's `storage.source`. The value
need only be *shape-valid*, not runtime-exact: a final capture receives the
production-assigned address, while the predictor needs an address that lets the
same handler path complete. A `PciPath` renders as `"xx"`, matching the storage
grammar exercised by the policy tests.
This is a predictor-only change — no core Kata behavior is altered — and it lets
the block/erofs paths run under the drivers CC confidential guests actually use
(QEMU `virtio-scsi`, CLH/dragonball `virtio-blk-pci`, s390 `virtio-blk-ccw`),
which forbid `virtio-blk-mmio`.

**Remaining dry-run gaps for the block/erofs device paths:**

- `ErofsMultiLayerRootfs::new` stats each erofs source file (`get_erofs_layer_size`
  in GPT mode, `generate_merged_erofs_vmdk` in fsmerge mode) and creates a host
  rootfs directory (side effect), so the diagnostic artifact's `source` paths must
  exist when the predictor runs.
- The snapshotter needs kernel support (erofs / dm-verity) and the plugin present
  in the appliance image.

Diagnostic rootfs preparation does not establish trust by itself. Deployable
policy identity comes from a digest-pinned guest-pull source or a dm-verity root
hash in an authoritative final request. A hand-built rootfs mount artifact can
exercise transformation code but cannot prove that containerd produced it.
