// Copyright (c) 2026 Kata Containers
//
// SPDX-License-Identifier: Apache-2.0
//
// North-star CreateContainerRequest capture (no VM).
//
// Drives the REAL runtime-rs Kata shim container-create path
// (`VirtContainerManager::create_container` -> `Container::create`) behind a
// no-op ("dry-run") `Hypervisor` and a RECORDING `Agent`, so NO VM is booted.
// The recording agent captures the exact `CreateContainerRequest` the in-TEE
// agent would receive -- OCI spec + storages + devices unified in one
// authoritative artifact produced by real shim code, instead of reconstructing
// the OCI normalization with templates.
//
// This uses only the public `virt_container::VirtContainerManager` surface, so
// the core runtime crate is unchanged.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::sync::Mutex;

use hypervisor::Hypervisor;
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use kata_types::config::TomlConfig;

use agent::Agent;

use common::types::ContainerConfig;
use common::ContainerManager;
use resource::cpu_mem::initial_size::InitialSizeManager;
use resource::ResourceManager;
use virt_container::VirtContainerManager;

use oci_spec::runtime as oci;
use kata_createreq_capture::{
    serialize_create_request, stage_direct_volume_mounts, DryRunHypervisor, RecordingAgent,
};

// ---- CLI ----

struct Args {
    container_id: String,
    sandbox_id: String,
    bundle: String,
    spec: PathBuf,
    kata_config: PathBuf,
    output: PathBuf,
    // Snapshotter-captured rootfs mounts (erofs/block/dm-verity). Absent = guest-pull.
    rootfs_mounts: Option<PathBuf>,
    // Operator-supplied direct-volume mountInfo replay fixtures.
    direct_volume_mounts: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut container_id = None;
    let mut sandbox_id = None;
    let mut bundle = None;
    let mut spec = None;
    let mut kata_config = None;
    let mut output = None;
    let mut rootfs_mounts = None;
    let mut direct_volume_mounts = None;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| anyhow!("missing value for {flag}"));
        match flag.as_str() {
            "--container-id" => container_id = Some(value()?),
            "--sandbox-id" => sandbox_id = Some(value()?),
            "--bundle" => bundle = Some(value()?),
            "--spec" => spec = Some(PathBuf::from(value()?)),
            "--kata-config" => kata_config = Some(PathBuf::from(value()?)),
            "--output" => output = Some(PathBuf::from(value()?)),
            "--rootfs-mounts" => rootfs_mounts = Some(PathBuf::from(value()?)),
            "--direct-volume-mounts" => direct_volume_mounts = Some(PathBuf::from(value()?)),
            other => return Err(anyhow!("unknown flag {other}")),
        }
    }

    let container_id = container_id.ok_or_else(|| anyhow!("--container-id is required"))?;
    Ok(Args {
        sandbox_id: sandbox_id.unwrap_or_else(|| container_id.clone()),
        container_id,
        bundle: bundle.ok_or_else(|| anyhow!("--bundle is required"))?,
        spec: spec.ok_or_else(|| anyhow!("--spec is required"))?,
        kata_config: kata_config.ok_or_else(|| anyhow!("--kata-config is required"))?,
        output: output.ok_or_else(|| anyhow!("--output is required"))?,
        rootfs_mounts,
        direct_volume_mounts,
    })
}

fn resolve_hypervisor_config(toml: &TomlConfig) -> HypervisorConfig {
    toml.hypervisor
        .get(&toml.runtime.hypervisor_name)
        .cloned()
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let spec: oci::Spec = serde_json::from_slice(
        &std::fs::read(&args.spec).with_context(|| format!("read spec {}", args.spec.display()))?,
    )
    .context("parse OCI spec (config.json)")?;

    // Raw load avoids validating hypervisor binary paths absent in the clean room.
    let (mut toml, _) = TomlConfig::load_raw_from_file(
        args.kata_config
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 kata config path"))?,
    )
    .with_context(|| format!("load kata config {}", args.kata_config.display()))?;
    // Skip the CPU/memory resize + online_cpu_mem calls the dry-run hypervisor
    // cannot service; the host cgroup write in update_linux_resource remains.
    toml.runtime.static_sandbox_resource_mgmt = true;
    let hv_config = resolve_hypervisor_config(&toml);
    let toml = Arc::new(toml);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let agent: Arc<dyn Agent> = Arc::new(RecordingAgent::in_memory(captured.clone()));
    let hypervisor: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor::new(hv_config));

    let init_size_manager =
        InitialSizeManager::new(&spec).context("construct InitialSizeManager")?;

    let resource_manager = Arc::new(
        ResourceManager::new(
            &args.sandbox_id,
            agent.clone(),
            hypervisor.clone(),
            toml.clone(),
            init_size_manager,
        )
        .await
        .context("construct ResourceManager")?,
    );

    let manager = VirtContainerManager::new(
        &args.sandbox_id,
        std::process::id(),
        agent.clone(),
        hypervisor.clone(),
        resource_manager,
    );

    // Rootfs input, matching the storage-predictor: a snapshotter-captured
    // `--rootfs-mounts` artifact (JSON `Vec<kata_types::mount::Mount>`) routes
    // handler_rootfs to the erofs multi-layer / single-layer block / dm-verity
    // paths (root-hash pinned); absent, we synthesize the guest-pull
    // KataVirtualVolume mount with the shim's own helper (the CC default, a pure
    // `VirtualVolume` transform needing no share-fs, snapshotter, VM, or device).
    let rootfs_mounts = match &args.rootfs_mounts {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read --rootfs-mounts {}", path.display()))?;
            serde_json::from_str::<Vec<kata_types::mount::Mount>>(&text)
                .context("parse --rootfs-mounts json")?
        }
        None => kata_types::mount::adjust_rootfs_mounts()
            .context("adjust_rootfs_mounts (guest-pull)")?,
    };

    // Stage operator-supplied direct-volume mountInfo replay fixtures exactly
    // where a CSI driver would, so the shim's real
    // handle_direct_volume path exposes the device (no VM) and the captured request
    // records its Storage. Direct-volume metadata does not itself invoke CDH.
    if let Some(path) = &args.direct_volume_mounts {
        stage_direct_volume_mounts(path)
            .with_context(|| format!("stage --direct-volume-mounts {}", path.display()))?;
    }

    let config = ContainerConfig {
        container_id: args.container_id.clone(),
        bundle: args.bundle.clone(),
        rootfs_mounts,
        terminal: false,
        options: None,
        stdin: None,
        stdout: None,
        stderr: None,
    };

    manager
        .create_container(config, spec)
        .await
        .context("drive create_container (no-VM)")?;

    let captured = captured.lock().await;
    let request = captured
        .first()
        .ok_or_else(|| anyhow!("no CreateContainerRequest captured"))?;
    std::fs::write(
        &args.output,
        serialize_create_request(request)? + "\n",
    )
    .with_context(|| format!("write {}", args.output.display()))?;

    eprintln!(
        "captured CreateContainerRequest -> {} ({} storages, {} devices)",
        args.output.display(),
        request.storages.len(),
        request.devices.len()
    );
    Ok(())
}
