# storage-predictor design

This document holds the design rationale and prediction internals for the
storage-predictor. Usage, requirements, coverage, the policy-generation
behaviour it drives, and known gaps are in [README.md](README.md).

The predictor's job is to produce the Kata Agent `storages` and `devices` a
workload would generate **without booting a VM**, so the appliance can pin them
in policy. It exists because the captured OCI `config.json` records containerd's
mount view, not the downstream Agent storage the Kata shim synthesizes. The two
sections below explain *why* that downstream shape is the only enforceable one
and *how* the predictor reproduces it — including the rootfs, the one storage
the runc bundle capture cannot provide.

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

- **Dry-run the real mutation pipeline; don't reimplement it.** Because only the
  shim's output is enforceable and rows 2–4 mutate the YAML, the predictor
  captures the OCI bundle **after** containerd's CRI→OCI lowering (from the runc
  handler, which is CRI-equivalent — see *Known gaps*) and runs the shim's own
  `VolumeResource::handler_volumes` / `handler_rootfs`. Legacy `genpolicy`
  instead *reimplements* row 4 in a separate model, which drifts (it omits
  hugepage, block, direct-volume, and all device synthesis); linking the real
  `runtime-rs` `resource` crate removes that drift by construction.
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
- **Keep the YAML as the authority for intent.** What a no-VM run cannot (or
  should not) derive is pinned from the YAML by the compiler instead: image
  **digests** are enforced at YAML validation (`submit_workload.py`), and the
  volume/device **set** (`volumeDevices`, `nvidia.com/pgpu`) is pinned from the
  manifest.
- **Reproduce only the unavoidable host-side rewriting.** The shim's
  `kata_sys_util::k8s::update_ephemeral_storage_type` rewrites containerd
  `bind`/`tmpfs` mounts into Kata `ephemeral`/`local` types and today inspects
  live host mount state (`mountinfo`/`stat`) to classify a disk- vs memory-backed
  emptyDir — a **current implementation coupling**, not an inherent need, since
  that intent is also in the YAML (`emptyDir.medium`); see *Known gaps: fidelity
  assumptions*. The one path that cannot be reused as-is (`VirtiofsShareMount`,
  entangled with virtiofsd) is *mirrored*, with the drift surface documented (see
  *Drift risk*).
- **Predict without gating; gate in the compiler.** The predictor records
  per-container failures and never blocks generation; gating (the dm-verity
  coverage gate, the opt-in `--strict-storage-coverage` gate) happens downstream
  where the policy is assembled (see *Driving policy generation*).
- **Serialization mirror.** `agent::types::Storage`/`Device` are not `Serialize`,
  so the tool maps them to local serializable structs for the JSON output.

Guided by this framing, **Known gaps** are narrowed to two kinds: (a) one missing
enforcement *capability* (dm-verity pinning of read-only data block volumes,
blocked upstream); and (b) *fidelity assumptions* where the no-VM prediction
could diverge from a real CC run. Tooling/config prerequisites live in
*Requirements*; out-of-scope paths (nydus rootfs, raw block *content*, host DoS,
side channels) live in *Coverage* / *Threat model*.


## Rootfs prediction (design)

The rootfs is the one storage the appliance cannot capture from the runc bundle:
runc uses overlayfs, while kata produces the container rootfs through
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
storage is **deterministic from the captured spec** — the predictor synthesizes
the guest-pull `KataVirtualVolume` option (via the shim's own
`adjust_rootfs_mounts`), calls `handler_rootfs`, and emits the real Agent
`Storage` with no snapshotter, VM, or device. **Implemented** via
`--guest-pull-rootfs`; the compiler pins `source` in that container's
`guest-pull-images` marker storage (see *Driving policy generation*). Proven by
the `predicts_guest_pull_rootfs` integration test.

### Multi-layer erofs rootfs — implemented (`--rootfs-mounts`)

The predictor consumes a snapshotter-captured `rootfs_mounts` artifact via
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
enforced policy wildcards the address via the base64url device id, so the
synthetic value only needs a valid shape.

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
need only be *shape-valid*, not runtime-exact: the generated policy wildcards the
source via the base64url device id (`$(spath)/$(b64_device_id)`), and a `PciPath`
renders as `"xx"` which matches the `rules.rego` `blk`/`scsi` device-id clauses.
This is a predictor-only change — no core Kata behavior is altered — and it lets
the block/erofs paths run under the drivers CC confidential guests actually use
(QEMU `virtio-scsi`, CLH/dragonball `virtio-blk-pci`, s390 `virtio-blk-ccw`),
which forbid `virtio-blk-mmio`.

**Remaining dry-run gaps for the block/erofs device paths:**

- `ErofsMultiLayerRootfs::new` stats each erofs source file (`get_erofs_layer_size`
  in GPT mode, `generate_merged_erofs_vmdk` in fsmerge mode) and creates a host
  rootfs directory (side effect), so the captured artifact's `source` paths must
  exist when the predictor runs.
- The snapshotter needs kernel support (erofs / dm-verity) and the plugin present
  in the appliance image.

Trust rationale: preparing the rootfs in the clean room is legitimate for
confidential guests because content is verified by **digest** (the guest's
trust anchor) — trust shifts from "host is honest" to "digest matches +
conversion is deterministic", and the recorded verity root hash lets the policy
pin it.
