# storage-predictor

Predicts the Kata Agent `storages` and `devices` a workload would produce,
**without booting a VM**. It exists because the captured OCI `config.json`
records containerd's mount view, not the Agent `storages`/`devices` that the Kata
shim synthesizes downstream.

The predicted `storages` now **drive policy generation**: the policy compiler
consumes `storages-devices-predicted.json` to pin the container rootfs (by EROFS
dm-verity root hash, or by guest-pull image reference) and to inject each
container's volume `storages` into the generated `policy.rego`, so storage-bearing
workloads get a working, tightly-scoped policy instead of failing closed.
Predicted **devices** remain audit-only: the policy's device *set*
(`volumeDevices`, VFIO/NVIDIA GPU) is pinned by the compiler from the workload
YAML — the authority for device intent — not from the no-VM predictor (see
*Design* and *Known gaps*). See *Driving policy generation* below.

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
  `bind`/`tmpfs` mounts into Kata `ephemeral`/`local` types and inspects live host
  mount state (`mountinfo`/`stat`), so the predictor must run **inside the
  appliance while the workload's host volumes are still mounted**. The one path
  that cannot be reused as-is (`VirtiofsShareMount`, entangled with virtiofsd) is
  *mirrored*, with the drift surface documented (see *Drift risk*).
- **Predict without gating; gate in the compiler.** The predictor records
  per-container failures and never blocks generation; gating (the dm-verity
  coverage gate, the opt-in `--strict-storage-coverage` gate) happens downstream
  where the policy is assembled (see *Driving policy generation*).
- **Serialization mirror.** `agent::types::Storage`/`Device` are not `Serialize`,
  so the tool maps them to local serializable structs for the JSON output.

Guided by this framing, the **Known gaps** below fall into three kinds: (a)
mutations the no-VM predictor cannot yet reproduce (real `S_IFBLK` block volumes,
the snapshotter capture stage); (b) paths the **threat model excludes**, which
are therefore deliberately not modeled (nydus host-share rootfs); and (c)
fidelity caveats where a stub diverges from a real CC config (copy-to-rootfs
under `shared_fs = "none"`).

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

## Driving policy generation

The policy compiler (`policy-compiler`) reads the report via `--predicted-storages`
and turns it into enforceable `policy.rego`. It consumes the predictor's output as
the **authoritative** storage shape rather than reimplementing the shim (as legacy
`genpolicy` does), so the generated policy matches the real runtime-rs
`CreateContainerRequest`.

### Rootfs: dm-verity pinning (erofs multi-layer and single-layer block)

The compiler collects the union of dm-verity **root hashes** into
`policy_data.dmverity.allowed_roothashes`, covering two rootfs shapes:

- **multi-layer erofs**: each read-only **lower** layer is pinned by its root
  hash; the writable `ext4` upper is allowed by shape.
- **single-layer block**: one verity-protected block device mounted read-only as
  the container rootfs (`BlockRootfs`), pinned by its root hash. It is
  distinguished from an erofs lower by the absence of the `X-kata.multi-layer`
  marker, and allowed by a dedicated `rules.rego` clause.

A coverage gate fails generation if any dm-verity-enabled rootfs storage lacks a
root hash (it would fail closed at runtime). Both shapes are counted out of the
`allow_storages` balance (like guest pull) since they are validated by dedicated
clauses rather than `p_storages`. Legacy `genpolicy` emits no rootfs storages at
all, so verity-protected containers fail closed under it — this is a capability
the drive adds.

The single-layer path reuses the shim's own dm-verity translation
(`kata_types::gpt_disk::extract_dmverity_annotation` /
`parse_dmverity_metadata_file` / `generate_dmverity_options`): `BlockRootfs` now
honors the `X-containerd.dmverity` mount annotation and emits the same
`X-kata.dmverity.*` storage options the erofs path does, so the predictor
reproduces it with no VM (see the `dry_run_single_layer_dmverity_emits_roothash`
test).


### Image references must be digest-pinned

Every appliance rootfs solution (erofs dm-verity, single-layer dm-verity, guest
pull) exists to bind the generated policy to the **workload author's declared
image**. dm-verity pins the layer *bytes* and guest pull pins the image
*reference*, but that only faithfully encodes intent if the manifest names the
image by digest: a mutable tag (`nginx:1.27`) can be repointed by whoever
controls the registry, so it cannot specify which image the author meant. The
appliance enforces this at the **input YAML** — the artifact it processes and
annotates — in `scripts/submit_workload.py` (`validate_image_references`), which
rejects any container (init / regular / ephemeral, across Pod and the workload
kinds) whose `image:` is not a `name@sha256:<digest>` reference, before the
workload is ever run or captured. The generated policy therefore only ever pins
digest-anchored images.

### Rootfs: guest-pull image pinning

For the mainstream CoCo rootfs (guest pull), the predictor reuses the shim's own
`adjust_rootfs_mounts` to synthesize the guest-pull `KataVirtualVolume` and runs
it through the real `handler_rootfs` with no `ShareFs` (`--guest-pull-rootfs`; in
the appliance `GENPOLICY_GUEST_PULL=1`). The resulting `image_guest_pull`
`Storage` carries `source` = the image reference from
`io.kubernetes.cri.image-name` (digest-pinned, per above). The compiler collects
the union of those references into `policy_data.guest_pull.allowed_images`, and
the `rules.rego` `image_guest_pull` clause pins the pulled image to that
allowlist. To stay backward compatible (legacy genpolicy, or the predictor not
run), an empty allowlist falls back to the historical allow-by-shape. The huge,
non-deterministic `driver_options` metadata blob is intentionally not pinned; the
image reference is the security-relevant field (the guest pulls and verifies it
by digest inside the TEE).

### Volume storages: templated injection

Each container's predicted `volumes[].storages` are injected into
`ContainerPolicy.storages`, keyed by CRI container name (the predictor emits
`container_name` for the mapping). Concrete guest paths are re-templated to the
policy variables that `rules.rego`'s `allow_storage` clauses substitute at
enforcement, with literal file names regex-escaped and anchored so each storage
is pinned:

| Class | `fs_type` | Templated `mount_point` | Clause |
|---|---|---|---|
| ephemeral emptyDir | `tmpfs` | `^/run/kata-containers/sandbox/ephemeral/<file>$` | `tmpfs` |
| local emptyDir | `local` | `^$(cpath)/$(sandbox-id)/rootfs/local/<file>$` | `local` |
| hugepage emptyDir | `hugetlbfs` | `^/run/kata-containers/sandbox/ephemeral/<file>$` | `hugetlbfs` (added) |
| watchable configMap/secret/projected/downwardAPI | `bind` | `^$(cpath)/watchable/sandbox-[0-9a-f]{8}-<name>$` | `bind` |
| block-encrypted / block-plain emptyDir | `ext4` | `$(spath)/$(b64_device_id)` | `blk` / `scsi` device-id |

The block emptyDir row is the one device-backed volume the compiler drives. The
predictor models it no-VM (the dry-run device manager plus the synthesized
PCI/SCSI address — see *Dry-run block device address synthesis*), emitting a
virtio-blk/scsi `Storage` whose `driver_options` carry `create_filesystem` (plus
`encryption_key=ephemeral` when encrypted). The compiler recognizes that gate and
templates it exactly like legacy genpolicy's `emptyDir_encrypted` /
`emptyDir_plain` settings: the policy `p_storage` carries an **empty** `driver`
and `source` (the shared `rules.rego` `allow_storage with blk`/`with scsi`
clauses match by the runtime input driver and wildcard the device address), the
`mount_point` becomes the device-id template `$(spath)/$(b64_device_id)`, and
`driver_options`, `fstype`, `fs_group`, `options` and `shared` are pinned
exactly. `fs_group` mirrors the pod `securityContext.fsGroup` (the emptyDir
directory GID) so the agent's exact-equality check passes.

The watchable case deliberately does **not** reuse genpolicy's `$(sfprefix)`
(`<bundle-id>-[a-z0-9]{16}-`): runtime-rs names the shared file
`sandbox-<8 hex>-<name>` via a random UUID segment
(`share_fs_volume::generate_mount_path`), so the compiler wildcards the hash as
`[0-9a-f]{8}` and pins the escaped name, and keeps the real `watchable-bind`
driver (not the legacy `local`). Legacy genpolicy's configMap policy therefore
does not match runtime-rs — another reason the drive is predictor-authoritative.

### Coverage gate

Storage classes the compiler cannot yet template are logged and omitted by
default; the container then fails closed at runtime, exactly as it does without a
predicted report (no silent loosening). Pass `--strict-storage-coverage true`
(or set `STRICT_STORAGE_COVERAGE=1` in the appliance entrypoint) to make an
unsupported class a hard generation error instead — the fail-closed-at-generation
choice for operators who want to guarantee full coverage.

### Not yet driven (rationale)

- **Per-container dm-verity allowlist.** The allowlist is pod-scoped (a union),
  so a container could present another same-pod container's rootfs hash.
  Tightening to per-container would require threading a container-scoped list
  through `allow_storages`/`allow_storage`, but those are **shared** upstream
  `rules.rego` functions (legacy genpolicy calls them too); changing their
  signature would break that contract, so this is deferred pending an
  additive per-container mechanism.
- **Block/direct volume devices.** Block `volumeDevices[]` and direct-assigned
  volumes remain compiler-side `container_path` pins (see *Known gaps*): their
  handlers `stat` a real host `S_IFBLK` device, so the no-VM predictor cannot
  model their content. Block **emptyDir** (encrypted/plain) IS now driven end to
  end (predictor + compiler), since its handler backs the volume with a
  hypervisor-plugged sparse disk the dry-run device manager can synthesize.

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
  Path strings are policy-generalized by the compiler when injected (the random
  `sandbox-<8 hex>-<name>` component is wildcarded to `[0-9a-f]{8}` and the name
  pinned; see *Driving policy generation*), so the non-deterministic hash does
  not break enforcement.
- If upstream renames the constants or changes `share_volume`'s storage shape,
  the stub diverges silently.

Mitigation options (not yet implemented):

- Make the two constants public in `virtio_fs_share_mount.rs` and import them.
- Upstream a side-effect-free `predict_share_volume` helper in `resource` and call
  it directly, removing the reproduction entirely.
- Add an alignment test that fails if the upstream storage shape changes.

## Known gaps

Read against the *Design* summary: an item matters only if it affects a storage
the shim actually produces for a CC workload (row 4) and that the threat model
cares about. Each entry is one of — **pinned at parity** (already enforced, no
gap: raw `volumeDevices`, VFIO GPU); **not-yet-reproducible** no-VM (real
`S_IFBLK` block volumes, the snapshotter capture stage); **excluded by the
threat model** (nydus host-share rootfs); or a **fidelity caveat** where a stub
diverges from a real CC config (copy-to-rootfs under `shared_fs = "none"`).

- **Device-backed classes** (block emptyDir, block/direct volumes): the
  dry-run hypervisor returns a default `hypervisor_config`, so the device manager
  assigns the deterministic guest path `/dev/vdX`, and `add_device` synthesizes a
  deterministic guest address (`pci_path` for `virtio-blk-pci`, `scsi_addr` for
  `virtio-scsi`, `ccw_addr` for `virtio-blk-ccw`) so the block handlers complete
  with no VM. **Block emptyDir (encrypted/plain) is now modeled end to end** and
  driven into the policy by the compiler (empty-driver + `$(spath)/$(b64_device_id)`
  device-id templating; see *Driving policy generation*), because its handler
  backs the volume with a hypervisor-plugged sparse disk the dry-run device
  manager can synthesize. Block `volumeDevices[]` and direct-assigned volumes
  remain e2e-only, because `BlockVolume::new` `stat`s a real host `S_IFBLK`
  device and direct volumes read host mount-info metadata; they are pinned by
  `container_path` at the compiler/YAML level instead. The full `blockdev_info`
  (driver, aio, queues, sector sizes) and `emptydir_mode` are sourced from the
  deployment's Kata `configuration.toml` when `--kata-config` is given; otherwise
  the block driver falls back to `--block-driver` / `GENPOLICY_BLOCK_DRIVER`.
- Block-device volumes (`spec.containers[].volumeDevices[]`) ARE pinned in the
  generated policy by their `container_path`, at parity with legacy genpolicy:
  the policy compiler reads them from the workload YAML (not the predictor) and
  emits an `agent::Device{container_path}` per declared device, matched by the
  `rules.rego` `allow_volume_devices` clause. This bounds the device *set* the
  host may present but does not pin device identity/content — under the CC model
  a raw block device is untrusted content anyway. The security-meaningful follow-up
  is dm-verity root-hash pinning of read-only *data* volumes (making them trusted
  devices, so a swap for an untrusted device is denied), but that is blocked
  upstream: no runtime volume handler emits `X-kata.dmverity.*` for a data volume
  (the `KataVirtualVolume.dm_verity` field is unused), and `is_block_volume`
  requires a real `S_IFBLK` device so the no-VM predictor cannot reproduce it.
- NVIDIA passthrough GPU (VFIO) is ALSO pinned, at parity with legacy genpolicy:
  the compiler counts `nvidia.com/pgpu` resource limits per container and emits
  one VFIO `agent::Device{container_path=<vfio prefix>, type, vm_path=""}` per GPU
  plus the CDI-annotation `runtime_anno_pattern`, matched by the `rules.rego`
  `allow_vfio_devices` clause (device number ↔ CDI annotation correlation, PCI
  address regex). Both device kinds come from the workload YAML, so no predictor
  or shim change is involved.
- **Input-spec fidelity (runc-captured bundle vs the kata handler).** The
  predictor consumes containerd's OCI bundle `config.json` captured from the
  **runc** handler. containerd builds that bundle from the runtime-agnostic CRI
  `ContainerConfig`, and the kata handler runs the same `handler_volumes` over the
  same bundle (see `virt_container/.../container_manager/container.rs`), so the
  container volume-mount list (emptyDir, ConfigMap, Secret, hostPath, local,
  ephemeral, shm) is representative regardless of handler — this is what makes the
  *dry-run the real mutation pipeline* design choice sound. Two residual,
  non-repo-verifiable risks remain: (1) a containerd kata-handler-specific spec
  option that adds/removes/retypes a container mount (standard CRI mount
  generation is handler-agnostic); and (2) the shim's mount-**rewriting** step
  (`update_ephemeral_storage_type`) reads live host mount state, so the predictor
  must run while the workload's host volumes are still mounted rather than from
  fully captured per-source metadata. An authoritative capture of the kata-handler
  bundle (or the CRI `ContainerConfig`) would close both. Device requests are
  unaffected: the policy's device set is pinned from the YAML (see the
  `volumeDevices` / VFIO bullets above), not derived from the captured spec.
- Rootfs snapshotter: kata produces the container rootfs via `handler_rootfs`
  from the snapshotter mounts. The predictor models every rootfs shape that
  applies to confidential guests: **guest-pull** (`--guest-pull-rootfs`),
  **multi-layer erofs** and **single-layer dm-verity block** (`--rootfs-mounts`).
  What remains is the host-side **snapshotter capture stage** that produces the
  `rootfs_mounts` artifact (`capture_rootfs_mounts.py`), not the prediction.
  **Nydus rootfs (`NydusRootfs`) is intentionally out of scope and not a gap for
  Kata-CC**: it shares a host-prepared nydus bootstrap + blobs into the guest
  over virtio-fs (`NydusShareFs`), i.e. the *host* supplies the rootfs content.
  That is incompatible with the confidential trust model, which requires the
  image to be pulled and verified **inside** the TEE (guest-pull) or pinned by a
  dm-verity root hash (erofs / single-layer block). A CC deployment therefore
  never routes its rootfs through `NydusRootfs`, so modeling it would add a
  no-VM stub for a path the threat model already excludes.
- Config sourcing: `emptydir_mode` and the full hypervisor `blockdev_info` come
  from the deployment's Kata `configuration.toml`
  via `--kata-config` (`GENPOLICY_KATA_CONFIG`), loaded raw (no hypervisor-binary
  validation); otherwise `emptydir_mode` and the block driver are profile-sourced
  from `profile.env`. The guest device address (`pci_path` / `scsi_addr` /
  `ccw_addr`) is synthesized deterministically by the dry-run `add_device`; the
  exact value is irrelevant because the generated policy wildcards it via the
  base64url device id, so only its shape needs to be valid.
- `fs_sharing_supported` (the `VolumeContext` flag that mirrors the shim's
  `capabilities.is_fs_sharing_supported()`) is derived from the sourced config's
  `shared_fs`: true unless `shared_fs = "none"`. It materially changes routing —
  upstream's `need_local_volume` is `!fs_sharing_supported && … && is_disk_empty_dir`,
  so with virtio-fs a disk-backed `emptyDir`/`local` volume is shared over
  virtio-fs (no `Storage`), while under `shared_fs = "none"` (block-only / many
  CoCo profiles) it yields a `local` `Storage`. Caveat (fidelity, **fails
  closed**): under `shared_fs = "none"` the real shim has **no** `ShareFs`, so
  ConfigMap/Secret volumes take a different mechanism entirely — `ShareFsVolume`'s
  `None` branch **copies** the files into the guest rootfs via the agent
  `copy_file` RPC and emits **no `Storage`** (just an OCI bind mount to the copied
  guest path, plus an `FsWatcher` that re-copies on change). The predictor keeps
  the virtio-fs stub (reproducing the copy-to-rootfs path needs a real Agent,
  which the no-VM run stubs out), so it still models those as `watchable-bind`.
  The generated policy then pins a `watchable-bind` storage the runtime never
  produces, and does **not** authorize the actual `CopyFile` RPCs / bind mount, so
  ConfigMap/Secret **fail closed** on a `shared_fs = "none"` deployment — a
  fidelity bug, not a bypass. (A related, milder fidelity point: even with
  virtio-fs, a ConfigMap/Secret with **> 8 files** is not "watchable"
  (`is_watchable_mount` caps the count at 8) and the shim emits a plain
  `virtio-fs-mount` with no `Storage` rather than `watchable-bind`; the predictor
  classifies by the **live** host file count, so this depends on capture
  fidelity.) `block_device_discard_supported` is left false (it only affects the
  e2e-only block-volume path).

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
`--guest-pull-rootfs`; the compiler pins `source` into
`policy_data.guest_pull.allowed_images` (see *Driving policy generation*). Proven
by the `predicts_guest_pull_rootfs` integration test.

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
confidential guests because content is verified by **digest** (the guest's trust
anchor) — trust shifts from "host is honest" to "digest matches + conversion is
deterministic", and the recorded verity root hash lets the policy pin it.

## Validation

Because the stage depends on live mounted volumes, its authoritative validation is
`make e2e`. `make validate` exercises only the unit tests and the offline
transform path (`tests/predict.rs`, `tests/test_predict_storages.py`).
