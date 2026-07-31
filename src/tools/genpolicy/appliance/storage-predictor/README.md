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

- **Device-backed classes** (block, encrypted `emptyDir`, direct volumes) remain
  fail-closed: the dry-run `Hypervisor::add_device` is unimplemented and the block
  path needs the host backing object to `stat`. Enabling them requires echoing the
  device through the dry-run hypervisor and a profile-backed `hypervisor_config`.
- Only per-volume `device_id` is emitted, not full `agent::Device` objects; those
  need device-manager introspection and the container-manager `spec.linux.devices`
  path.
- No authoritative CRI capture yet, so device requests not fully expressed in the
  OCI spec are not modeled, and the predictor depends on live host mount state
  rather than captured per-source metadata.
- Input fidelity: the captured spec is containerd's runc-handler spec; equivalence
  with the kata-handler spec is not yet verified. `pci_path` is not reconstructed
  (acceptable for virtio-blk, whose Agent source is the deterministic `/dev/vdX`).
  `emptydir_mode` defaults to `shared-fs` and should be sourced from the pinned
  runtime-rs profile.

## Validation

Because the stage depends on live mounted volumes, its authoritative validation is
`make e2e`. `make validate` exercises only the unit tests and the offline
transform path (`tests/predict.rs`, `tests/test_predict_storages.py`).
