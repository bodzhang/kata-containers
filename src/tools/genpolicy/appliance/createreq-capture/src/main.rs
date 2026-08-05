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

use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use hypervisor::hypervisor_persist::HypervisorState;
use hypervisor::device::DeviceType;
use hypervisor::{Hypervisor, MemoryConfig, PciPath, VcpuThreadIds};
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use kata_types::config::TomlConfig;
use kata_types::device::{DRIVER_BLK_CCW_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_SCSI_TYPE};

use agent::types::*;
use agent::{Agent, AgentManager, HealthService};
use kata_types::config::Agent as AgentConfig;

use common::types::ContainerConfig;
use common::ContainerManager;
use resource::cpu_mem::initial_size::InitialSizeManager;
use resource::ResourceManager;
use virt_container::VirtContainerManager;

use oci_spec::runtime as oci;

/// A Hypervisor that performs no VMM I/O. Mirrors the storage-predictor's
/// DryRunHypervisor, plus the three methods the `VirtContainerManager`
/// create-container path calls that the direct-handler predictor did not:
/// `get_vmm_master_tid`, `get_ns_path`, `get_passfd_listener_addr`.
#[derive(Debug, Default)]
struct DryRunHypervisor {
    config: HypervisorConfig,
}

#[async_trait]
impl Hypervisor for DryRunHypervisor {
    async fn prepare_vm(
        &self,
        _id: &str,
        _netns: Option<String>,
        _annotations: &HashMap<String, String>,
        _selinux_label: Option<String>,
    ) -> Result<()> {
        unimplemented!("dry-run hypervisor does not create a VM")
    }
    async fn start_vm(&self, _timeout: i32) -> Result<()> {
        unimplemented!()
    }
    async fn stop_vm(&self) -> Result<()> {
        unimplemented!()
    }
    async fn wait_vm(&self) -> Result<i32> {
        unimplemented!()
    }
    async fn pause_vm(&self) -> Result<()> {
        unimplemented!()
    }
    async fn save_vm(&self) -> Result<()> {
        unimplemented!()
    }
    async fn resume_vm(&self) -> Result<()> {
        unimplemented!()
    }
    async fn resize_vcpu(&self, _old_vcpus: u32, _new_vcpus: u32) -> Result<(u32, u32)> {
        unimplemented!()
    }
    async fn resize_memory(&self, _new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        unimplemented!()
    }
    // Synthesize a deterministic guest block-device address so the block
    // rootfs/volume handlers complete with no VM (identical to the predictor).
    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        if let DeviceType::BlockModern(ref block) = device {
            let mut dev = block.lock().await;
            let index = dev.config.index;
            let driver = dev.config.driver_option.clone();
            if driver == DRIVER_BLK_PCI_TYPE {
                dev.config.pci_path = Some(PciPath::try_from((index + 1) as u32)?);
            } else if driver == DRIVER_SCSI_TYPE {
                dev.config.scsi_addr = Some(format!("{}:{}", index >> 8, index & 0xff));
            } else if driver == DRIVER_BLK_CCW_TYPE {
                dev.config.ccw_addr = Some(format!("0.0.{:04x}", index));
            }
        }
        Ok(device)
    }
    async fn remove_device(&self, _device: DeviceType) -> Result<()> {
        Ok(())
    }
    async fn update_device(&self, _device: DeviceType) -> Result<()> {
        Ok(())
    }
    async fn get_agent_socket(&self) -> Result<String> {
        unimplemented!()
    }
    async fn disconnect(&self) {
        unimplemented!()
    }
    async fn hypervisor_config(&self) -> HypervisorConfig {
        self.config.clone()
    }
    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        Ok(VcpuThreadIds::default())
    }
    async fn get_pids(&self) -> Result<Vec<u32>> {
        unimplemented!()
    }
    async fn get_vmm_master_tid(&self) -> Result<u32> {
        // The manager records this as the container "pid"; any stable value
        // works because no VM/process is created.
        Ok(std::process::id())
    }
    async fn get_ns_path(&self) -> Result<String> {
        // The manager builds `<ns_path>/net` for a NetnsGuard around the
        // (typically empty) createContainer hooks. Point it at this process's
        // own namespace dir so the guard enters the current netns (a no-op).
        Ok("/proc/self/ns".to_string())
    }
    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }
    async fn check(&self) -> Result<()> {
        unimplemented!()
    }
    async fn get_jailer_root(&self) -> Result<String> {
        unimplemented!()
    }
    async fn save_state(&self) -> Result<HypervisorState> {
        unimplemented!()
    }
    async fn capabilities(&self) -> Result<Capabilities> {
        Ok(Capabilities::default())
    }
    async fn get_hypervisor_metrics(&self) -> Result<String> {
        unimplemented!()
    }
    async fn set_capabilities(&self, _flag: CapabilityBits) {
        unimplemented!()
    }
    async fn set_guest_memory_block_size(&self, _size: u32) {
        unimplemented!()
    }
    async fn guest_memory_block_size(&self) -> u32 {
        0
    }
    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        // The caller does `.ok()`, so returning Err yields None (no passfd io).
        Err(anyhow!("dry-run hypervisor has no passfd listener"))
    }
}

/// An Agent that records the `CreateContainerRequest` instead of sending it over
/// ttrpc. `create_container` captures the request; `copy_file` is accepted so
/// the shared_fs="none" configMap/secret copy-to-rootfs path completes. Every
/// other RPC is never reached on the create path.
struct RecordingAgent {
    captured: Arc<Mutex<Vec<CreateContainerRequest>>>,
}

#[async_trait]
impl AgentManager for RecordingAgent {
    async fn start(&self, _address: &str) -> Result<()> {
        unimplemented!()
    }
    async fn stop(&self) {
        unimplemented!()
    }
    async fn disconnect(&self) -> Result<()> {
        unimplemented!()
    }
    async fn agent_sock(&self) -> Result<String> {
        unimplemented!()
    }
    async fn agent_config(&self) -> AgentConfig {
        unimplemented!()
    }
}

#[async_trait]
impl HealthService for RecordingAgent {
    async fn check(&self, _req: CheckRequest) -> Result<HealthCheckResponse> {
        unimplemented!()
    }
    async fn version(&self, _req: CheckRequest) -> Result<VersionCheckResponse> {
        unimplemented!()
    }
}

#[async_trait]
impl Agent for RecordingAgent {
    async fn create_sandbox(&self, _req: CreateSandboxRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn destroy_sandbox(&self, _req: Empty) -> Result<Empty> {
        unimplemented!()
    }
    async fn online_cpu_mem(&self, _req: OnlineCPUMemRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn add_arp_neighbors(&self, _req: AddArpNeighborRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn list_interfaces(&self, _req: Empty) -> Result<Interfaces> {
        unimplemented!()
    }
    async fn list_routes(&self, _req: Empty) -> Result<Routes> {
        unimplemented!()
    }
    async fn update_interface(&self, _req: UpdateInterfaceRequest) -> Result<Interface> {
        unimplemented!()
    }
    async fn update_routes(&self, _req: UpdateRoutesRequest) -> Result<Routes> {
        unimplemented!()
    }
    async fn create_container(&self, req: CreateContainerRequest) -> Result<Empty> {
        self.captured.lock().await.push(req);
        Ok(Empty::default())
    }
    async fn pause_container(&self, _req: ContainerID) -> Result<Empty> {
        unimplemented!()
    }
    async fn remove_container(&self, _req: RemoveContainerRequest) -> Result<Empty> {
        // Reached only via the manager's cleanup path when create() fails;
        // accept it so the original create() error surfaces instead of a panic.
        Ok(Empty::default())
    }
    async fn resume_container(&self, _req: ContainerID) -> Result<Empty> {
        unimplemented!()
    }
    async fn start_container(&self, _req: ContainerID) -> Result<Empty> {
        unimplemented!()
    }
    async fn stats_container(&self, _req: ContainerID) -> Result<StatsContainerResponse> {
        unimplemented!()
    }
    async fn update_container(&self, _req: UpdateContainerRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn exec_process(&self, _req: ExecProcessRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn signal_process(&self, _req: SignalProcessRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn wait_process(&self, _req: WaitProcessRequest) -> Result<WaitProcessResponse> {
        unimplemented!()
    }
    async fn close_stdin(&self, _req: CloseStdinRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn read_stderr(&self, _req: ReadStreamRequest) -> Result<ReadStreamResponse> {
        unimplemented!()
    }
    async fn read_stdout(&self, _req: ReadStreamRequest) -> Result<ReadStreamResponse> {
        unimplemented!()
    }
    async fn tty_win_resize(&self, _req: TtyWinResizeRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn write_stdin(&self, _req: WriteStreamRequest) -> Result<WriteStreamResponse> {
        unimplemented!()
    }
    async fn copy_file(&self, _req: CopyFileRequest) -> Result<Empty> {
        Ok(Empty::default())
    }
    async fn get_metrics(&self, _req: Empty) -> Result<MetricsResponse> {
        unimplemented!()
    }
    async fn get_oom_event(&self, _req: Empty) -> Result<OomEventResponse> {
        unimplemented!()
    }
    async fn get_ip_tables(&self, _req: GetIPTablesRequest) -> Result<GetIPTablesResponse> {
        unimplemented!()
    }
    async fn set_ip_tables(&self, _req: SetIPTablesRequest) -> Result<SetIPTablesResponse> {
        unimplemented!()
    }
    async fn get_volume_stats(&self, _req: VolumeStatsRequest) -> Result<VolumeStatsResponse> {
        unimplemented!()
    }
    async fn resize_volume(&self, _req: ResizeVolumeRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn get_guest_details(
        &self,
        _req: GetGuestDetailsRequest,
    ) -> Result<GuestDetailsResponse> {
        unimplemented!()
    }
    async fn add_swap(&self, _req: AddSwapRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn add_swap_path(&self, _req: AddSwapPathRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn set_policy(&self, _req: SetPolicyRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn get_diagnostic_data(
        &self,
        _req: GetDiagnosticDataRequest,
    ) -> Result<GetDiagnosticDataResponse> {
        unimplemented!()
    }
}

// ---- Serializable dump of the captured request (agent types are not Serialize) ----

#[derive(Serialize)]
struct FsGroupDump {
    group_id: u32,
    group_change_policy: String,
}

impl From<&FSGroup> for FsGroupDump {
    fn from(g: &FSGroup) -> Self {
        Self {
            group_id: g.group_id,
            group_change_policy: format!("{:?}", g.group_change_policy),
        }
    }
}

#[derive(Serialize)]
struct StorageDump {
    driver: String,
    driver_options: Vec<String>,
    source: String,
    fs_type: String,
    fs_group: Option<FsGroupDump>,
    options: Vec<String>,
    mount_point: String,
    shared: bool,
}

impl From<&Storage> for StorageDump {
    fn from(s: &Storage) -> Self {
        Self {
            driver: s.driver.clone(),
            driver_options: s.driver_options.clone(),
            source: s.source.clone(),
            fs_type: s.fs_type.clone(),
            fs_group: s.fs_group.as_ref().map(FsGroupDump::from),
            options: s.options.clone(),
            mount_point: s.mount_point.clone(),
            shared: s.shared,
        }
    }
}

#[derive(Serialize)]
struct DeviceDump {
    id: String,
    field_type: String,
    vm_path: String,
    container_path: String,
    options: Vec<String>,
}

impl From<&Device> for DeviceDump {
    fn from(d: &Device) -> Self {
        Self {
            id: d.id.clone(),
            field_type: d.field_type.clone(),
            vm_path: d.vm_path.clone(),
            container_path: d.container_path.clone(),
            options: d.options.clone(),
        }
    }
}

#[derive(Serialize)]
struct SharedMountDump {
    name: String,
    src_ctr: String,
    src_path: String,
    dst_ctr: String,
    dst_path: String,
}

impl From<&SharedMount> for SharedMountDump {
    fn from(m: &SharedMount) -> Self {
        Self {
            name: m.name.clone(),
            src_ctr: m.src_ctr.clone(),
            src_path: m.src_path.clone(),
            dst_ctr: m.dst_ctr.clone(),
            dst_path: m.dst_path.clone(),
        }
    }
}

#[derive(Serialize)]
struct CreateContainerRequestDump {
    container_id: String,
    exec_id: String,
    sandbox_pidns: bool,
    oci: Option<oci::Spec>,
    storages: Vec<StorageDump>,
    devices: Vec<DeviceDump>,
    shared_mounts: Vec<SharedMountDump>,
    stdin_port: Option<u32>,
    stdout_port: Option<u32>,
    stderr_port: Option<u32>,
}

impl From<&CreateContainerRequest> for CreateContainerRequestDump {
    fn from(r: &CreateContainerRequest) -> Self {
        Self {
            container_id: r.process_id.container_id.container_id.clone(),
            exec_id: r.process_id.exec_id.clone(),
            sandbox_pidns: r.sandbox_pidns,
            oci: r.oci.clone(),
            storages: r.storages.iter().map(StorageDump::from).collect(),
            devices: r.devices.iter().map(DeviceDump::from).collect(),
            shared_mounts: r.shared_mounts.iter().map(SharedMountDump::from).collect(),
            stdin_port: r.stdin_port,
            stdout_port: r.stdout_port,
            stderr_port: r.stderr_port,
        }
    }
}

// ---- CLI ----

/// One operator-declared direct volume: the OCI mount `source` the shim matches
/// on, plus the `mountInfo.json` a CSI driver would register for it.
#[derive(Deserialize)]
struct DirectVolumeEntry {
    source: String,
    mount_info: kata_types::mount::DirectVolumeMountInfo,
}

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
    let agent: Arc<dyn Agent> = Arc::new(RecordingAgent {
        captured: captured.clone(),
    });
    let hypervisor: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor { config: hv_config });

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
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read --direct-volume-mounts {}", path.display()))?;
        let entries: Vec<DirectVolumeEntry> =
            serde_json::from_str(&text).context("parse --direct-volume-mounts json")?;
        for entry in &entries {
            kata_types::mount::add_volume_mount_info(&entry.source, &entry.mount_info)
                .with_context(|| format!("stage direct-volume mountInfo for {}", entry.source))?;
        }
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
    let dump = CreateContainerRequestDump::from(request);
    std::fs::write(
        &args.output,
        serde_json::to_string_pretty(&dump)? + "\n",
    )
    .with_context(|| format!("write {}", args.output.display()))?;

    eprintln!(
        "captured CreateContainerRequest -> {} ({} storages, {} devices)",
        args.output.display(),
        dump.storages.len(),
        dump.devices.len()
    );
    Ok(())
}
