# storage-predictor

Predicts the Kata Agent `storages` and `devices` a workload would produce,
**without booting a VM**. It exists because the captured OCI `config.json`
records containerd's mount view, not the Agent `storages`/`devices` that the Kata
shim synthesizes downstream.

The output (`storages-devices-predicted.json`) is **audit-only**. It is a
compatibility signal, not proof, and must not enter enforceable policy until
Agent-side enforcement and a versioned storage/device contract exist. Generated
`policy.rego` keeps workload `storages` and `devices` empty.

## Design

- **Real shim code, no drift.** The predictor links the `runtime-rs` `resource`
  crate and invokes `VolumeResource::handler_volumes`, so storage/device encoding
  is the shim's own logic. A reimplementation in `genpolicy` or appliance code
  would diverge — the legacy `genpolicy` model already omits hugepage, block,
  direct-volume, and all device synthesis.
- **VM boot skipped at the `Hypervisor` seam.** Volume synthesis is separable from
  VM lifecycle. The predictor supplies a no-op *dry-run* `Hypervisor` and a stub
  `Agent`; the guest device path (`/dev/vdX`) comes from the device manager's
  deterministic index allocation, not from live hotplug.
- **Shim mount rewriting reproduced.** Before dispatch it runs
  `kata_sys_util::k8s::update_ephemeral_storage_type`, which rewrites containerd
  mount types (`bind`/`tmpfs`) into Kata types (`ephemeral`/`local`). That
  rewriting inspects live host mount state (`mountinfo`/`stat`), so the predictor
  must run **inside the appliance while the workload's host volumes are still
  mounted**.
- **Serialization mirror.** `agent::types::Storage`/`Device` are not `Serialize`,
  so the tool maps them to local serializable structs for the JSON output.
- **Non-gating.** The pipeline stage records per-container failures and never
  blocks policy generation.

## Usage

```
storage-predictor \
  --config <oci config.json> \
  --output <predicted.json> \
  --sid <sandbox-id> \
  --cid <container-id> \
  --emptydir-mode <mode> \
  [--disable-guest-empty-dir]
```

In the appliance, `scripts/predict_storages.py` drives it per captured container
and assembles `storages-devices-predicted.json`.

## Coverage

- Authoritative (real pure handlers, no reproduction): `shm`, `local`,
  `ephemeral`, `hugepage`, passthrough `default`.
- Shared-filesystem classes (`ConfigMap`, `Secret`, `projected`, `downwardAPI`,
  regular `hostPath`) via a reproduced `ShareFs`/`ShareFsMount` stub: watchable
  `ConfigMap`/`Secret` mounts yield a `watchable-bind` storage; other shared-fs
  volumes yield a shared mount with no storage. See "Drift risk" below.

## Drift risk and mitigation

Unlike the volume handlers, the share-fs path cannot be reused as-is: the real
`VirtiofsShareMount` is entangled with virtiofsd/hypervisor setup and performs a
real host bind mount, which is incompatible with the no-VM design. The stub
therefore *reproduces* `VirtiofsShareMount::share_volume`
(`runtime-rs/crates/resource/src/share_fs/virtio_fs_share_mount.rs`).

Reused directly from the shim (kept aligned automatically):

- guest path — `resource::share_fs::do_get_guest_path` (same result as
  `share_to_guest`, without the mount);
- watchable detection — `kata_types::k8s::is_watchable_mount`;
- shared-dir root — `kata_guest_share_dir()` and `PASSTHROUGH_FS_DIR`.

Mirrored rather than reused (the drift surface):

- the constants `watchable` and `watchable-bind` (private upstream);
- the ~15-line `share_volume` control flow that assembles the `watchable-bind`
  `Storage`.

Residual risk:

- Security-relevant `Storage` fields (`driver`, `fs_type`, `options`) are exact.
  Path strings are policy-generalized by genpolicy's `sfprefix` regex, and the
  guest path carries a random `sandbox-<uuid>-<name>` component that is not
  deployment-stable regardless.
- If upstream renames the constants or changes `share_volume`'s storage shape,
  the stub diverges silently.

Mitigation options (not yet implemented):

- Make the two constants public in `virtio_fs_share_mount.rs` and import them.
- Upstream a side-effect-free `predict_share_volume` helper in `resource` and call
  it directly, removing the reproduction entirely.
- Add an alignment test that fails if the upstream storage shape changes.

## Known gaps

- **Device-backed classes** (block, encrypted `emptyDir`, direct volumes): the
  dry-run hypervisor echoes devices and returns a default `hypervisor_config`, so
  the device manager assigns the deterministic guest path `/dev/vdX` with no VM
  (proven by the `dry_run_block_device_gets_deterministic_virt_path` unit test).
  Predictor-level prediction through `handler_volumes` is still e2e-only, because
  `BlockVolume::new` `stat`s the real host block device and direct volumes read
  host mount-info metadata. The full `blockdev_info` (driver, aio, queues, sector
  sizes) plus `emptydir_mode`/`disable_guest_empty_dir` are sourced from the
  deployment's Kata `configuration.toml` when `--kata-config` is given; otherwise
  the block driver falls back to `--block-driver` / `GENPOLICY_BLOCK_DRIVER`.
- Only per-volume `device_id` is emitted, not full `agent::Device` objects; the
  `Volume` trait exposes no device enumeration, so full devices need
  device-manager introspection and the container-manager `spec.linux.devices`
  path.
- No authoritative CRI capture yet, so device requests not fully expressed in the
  OCI spec are not modeled, and the predictor depends on live host mount state
  rather than captured per-source metadata.
- Input-spec fidelity (runc vs kata handler): the predictor consumes containerd's
  bundle `config.json` captured from the runc handler. containerd generates that
  bundle from the runtime-agnostic CRI `ContainerConfig`, and the kata handler runs
  the same `handler_volumes` over the same bundle (see
  `virt_container/.../container_manager/container.rs`), so the container
  volume-mount list (emptyDir, ConfigMap, Secret, hostPath, local, ephemeral, shm)
  is representative regardless of handler. Residual, non-repo-verifiable risk: a
  containerd kata-handler-specific spec opt that adds/removes/retypes a container
  mount; standard CRI mount generation is handler-agnostic.
- Rootfs snapshotter: kata may use nydus/erofs/devmapper (block or guest image
  pull), producing a rootfs storage via `handler_rootfs` from the snapshotter
  mounts. The predictor now models the **multi-layer erofs** rootfs from a
  captured `rootfs_mounts` artifact (`--rootfs-mounts`); the snapshotter capture
  stage that produces the artifact, plus the guest-pull and single-layer block
  paths, remain. See **Rootfs prediction (design)** below.
- Config sourcing: `emptydir_mode`, `disable_guest_empty_dir`, and the full
  hypervisor `blockdev_info` come from the deployment's Kata `configuration.toml`
  via `--kata-config` (`GENPOLICY_KATA_CONFIG`), loaded raw (no hypervisor-binary
  validation); otherwise `emptydir_mode` and the block driver are profile-sourced
  from `profile.env`. `pci_path` is not reconstructed (acceptable for virtio-blk,
  whose Agent source is the deterministic `/dev/vdX`).

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
storage is **deterministic from the captured spec** — the predictor can synthesize
the guest-pull `KataVirtualVolume` option, call `handler_rootfs`, and emit the real
Agent `Storage` with no snapshotter, VM, or device. This is a good follow-up
increment.

### Multi-layer erofs rootfs — implemented (`--rootfs-mounts`)

The predictor consumes a snapshotter-captured `rootfs_mounts` artifact via
`--rootfs-mounts <file>` (a JSON array of `kata_types::mount::Mount`). A
multi-layer erofs artifact (an `ext4` `rw` upper layer + an `erofs` lower layer)
is routed by `handler_rootfs` to `ErofsMultiLayerRootfs`, which — like the block
path — runs `do_handle_device` for each layer. Under the dry-run device manager
each layer gets a deterministic `/dev/vdX` guest path with **no VM**, and
`get_storage()` returns the two Agent `Storage` objects the guest agent would use
to assemble the overlay (upper `ext4` + lower `erofs`, both `X-kata.multi-layer`).
The predicted rootfs is emitted under the `rootfs` key of the output. Proven by
the `dry_run_erofs_multi_layer_produces_layer_storages` unit test and the
`predicts_erofs_multi_layer_rootfs` integration test.

Driver constraint (same as the block path): the dry-run must use
`virtio-blk-mmio` (via `--block-driver` / `--kata-config`), whose Agent source is
the deterministic `virt_path` (`/dev/vdX`). `virtio-blk-pci` maps to the `blk`
driver, whose Agent source is a backend-assigned `pci_path` that the dry-run
`add_device` echo leaves `None` (`extract_block_device_info` then errors) — see
the gaps below.

The **capture stage** that produces the artifact is `capture_rootfs_mounts.py`:

1. **Prepare (out-of-band, prep host)** — pull the workload image by the digest
   pinned in the YAML with the erofs snapshotter, which converts each layer into
   an on-disk EROFS blob at `<root>/io.containerd.snapshotter.v1.erofs/snapshots/<N>/layer.erofs`:

   ```
   ctr images pull --snapshotter erofs <image>@<digest>
   ```

   Verified against containerd 2.3.3: `ctr snapshots --snapshotter erofs mounts`
   returns the **host** view — a single `overlay` mount (upperdir = the writable
   `fs`, lowerdir = the mount-manager-mounted erofs blob) — **not** the block
   mounts the guest sees. The block-device rootfs (`ext4` rw upper + `erofs` ro
   lower(s) with `device=`) that `ErofsMultiLayerRootfs` consumes is produced by
   the containerd erofs **mount-handler** when containerd hands the rootfs to the
   Kata shim. So the authoritative mounts are captured from a **Kata-runtime run**
   on the prep host (the mounts the shim receives), written per image as
   `<digest>.mounts` (mount-command text) or `<digest>.json` (containerd mount
   dicts). This preparation needs containerd ≥ 2.2, the erofs snapshotter/differ,
   `erofs-utils`, and the `erofs` kernel module.
2. **Convert (in-appliance)** — point `GENPOLICY_ROOTFS_MOUNTS_DIR` at that
   directory. `capture_rootfs_mounts.py` maps each captured container (via its
   `io.kubernetes.cri.image-name` digest) to its mounts file, converts the block
   mounts to `kata_types::mount::Mount` (preserving `device=` and
   `X-containerd.mkdir.path` options, deriving `read_only` from `ro`), and writes
   `raw/<name>.rootfs-mounts.json`. The conversion is unit-tested in
   `tests/test_capture_rootfs_mounts.py`.
3. **Predict** — `predict_storages.py` auto-detects `raw/<name>.rootfs-mounts.json`
   next to the OCI bundle and passes it to `--rootfs-mounts`; the predicted rootfs
   lands under the `rootfs` key. A `rootfs-mounts-captured.json` report and the
   per-container artifacts are recorded in provenance. The predictor was validated
   against a **real** `layer.erofs` blob produced by the containerd erofs
   snapshotter: the `erofs` lower resolves to `/dev/vdb` and the `ext4` upper to
   `/dev/vda`, no VM.
4. **Integrity (dm-verity)** — this branch tracks upstream `erofs_rootfs.rs` +
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

For a `virtio-blk-pci` deployment the erofs transform hits the `pci_path` gap and
`predict_rootfs` fails; that failure is captured into the output's
`rootfs.error` field (see `erofs_pci_driver_surfaces_error`) so the container's
volume prediction is never dropped.

### Single-layer block / dm-verity rootfs — needs a real block device

For a single-layer host-prepared block rootfs, `BlockRootfs::new`
(`resource/src/rootfs/block_rootfs.rs`) runs the same device flow, but
`is_block_rootfs` inspects a **real** block device to detect the layer and derive
its `dev_id`, so this single-layer path is snapshotter/e2e-only rather than an
offline unit test. The multi-layer erofs path above is preferred because its
detection keys on `fs_type` (`ext4`/`erofs`) rather than a live block device.

**Known dry-run gaps for the block/erofs device paths:**

- `extract_block_device_info` / `BlockRootfs` set `storage.source` from
  `device.config.pci_path` for `virtio-blk-pci` (the `blk` driver); the dry-run
  `add_device` echo leaves `pci_path = None`, so that driver needs the hypervisor's
  PCI-topology assignment reproduced. Use `virtio-blk-mmio` (the `mmioblk` driver),
  whose Agent source is the deterministic `virt_path` (`/dev/vdX`).
- `ErofsMultiLayerRootfs::new` stats each erofs source file
  (`generate_merged_erofs_vmdk`) and creates a host rootfs directory (side effect),
  so the captured artifact's `source` paths must exist when the predictor runs.
- The snapshotter needs kernel support (erofs / dm-verity) and the plugin present
  in the appliance image.

Trust rationale: preparing the rootfs in the clean room is legitimate for
confidential guests because content is verified by **digest** (the guest's trust
anchor) — trust shifts from "host is honest" to "digest matches + conversion is
deterministic", and the recorded verity root hash lets the policy pin it.

## Validation

Because the stage depends on live mounted volumes, its authoritative validation is
`make e2e`. `make validate` exercises only the unit tests and the offline
transform path (`tests/predict.rs`, `tests/test_predict_storages.py`).
