// Copyright (c) 2026 Kata Containers
//
// SPDX-License-Identifier: Apache-2.0
//
// Appliance storage/device predictor (audit-only).
//
// Reproduces the Kata shim's OCI->agent Storage/Device transformation using the
// REAL runtime-rs `resource` volume handlers, driven by a no-op ("dry-run")
// Hypervisor and a stub Agent, so NO VM is created. It first applies the shim's
// mount-type rewriting (`update_ephemeral_storage_type`), which inspects live
// host mount state, then runs `handler_volumes` and emits predicted storages.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::RwLock;

use hypervisor::device::device_manager::DeviceManager;
use hypervisor::device::DeviceType;
use hypervisor::hypervisor_persist::HypervisorState;
use hypervisor::{Hypervisor, MemoryConfig, VcpuThreadIds};
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;

use agent::types::*;
use agent::{Agent, AgentManager, HealthService};
use kata_types::config::Agent as AgentConfig;

use kata_sys_util::k8s::update_ephemeral_storage_type;
use resource::share_fs::ShareFs;
use resource::volume::{VolumeContext, VolumeResource};

/// A Hypervisor implementation that performs no VMM I/O. Its methods are never
/// invoked by the ephemeral/local storage transformation path; they exist only
/// so `DeviceManager` can be constructed. `unimplemented!()` diverges, so every
/// method type-checks regardless of its declared return type.
#[derive(Debug)]
struct DryRunHypervisor;

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
    async fn add_device(&self, _device: DeviceType) -> Result<DeviceType> {
        unimplemented!("dry-run hypervisor does not hotplug devices")
    }
    async fn remove_device(&self, _device: DeviceType) -> Result<()> {
        unimplemented!()
    }
    async fn update_device(&self, _device: DeviceType) -> Result<()> {
        unimplemented!()
    }
    async fn get_agent_socket(&self) -> Result<String> {
        unimplemented!()
    }
    async fn disconnect(&self) {
        unimplemented!()
    }
    async fn hypervisor_config(&self) -> HypervisorConfig {
        unimplemented!()
    }
    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        unimplemented!()
    }
    async fn get_pids(&self) -> Result<Vec<u32>> {
        unimplemented!()
    }
    async fn get_vmm_master_tid(&self) -> Result<u32> {
        unimplemented!()
    }
    async fn get_ns_path(&self) -> Result<String> {
        unimplemented!()
    }
    async fn cleanup(&self) -> Result<()> {
        unimplemented!()
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
        unimplemented!()
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
        unimplemented!()
    }
    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        unimplemented!()
    }
}

/// A no-op Agent. Not invoked by the ephemeral/local storage path; present only
/// to satisfy `VolumeContext`.
#[derive(Debug)]
struct StubAgent;

#[async_trait]
impl AgentManager for StubAgent {
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
impl HealthService for StubAgent {
    async fn check(&self, _req: CheckRequest) -> Result<HealthCheckResponse> {
        unimplemented!()
    }
    async fn version(&self, _req: CheckRequest) -> Result<VersionCheckResponse> {
        unimplemented!()
    }
}

#[async_trait]
impl Agent for StubAgent {
    async fn create_sandbox(&self, _req: CreateSandboxRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn create_secondary_sandbox(
        &self,
        _req: CreateSecondarySandboxRequest,
    ) -> Result<Empty> {
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
    async fn create_container(&self, _req: CreateContainerRequest) -> Result<Empty> {
        unimplemented!()
    }
    async fn pause_container(&self, _req: ContainerID) -> Result<Empty> {
        unimplemented!()
    }
    async fn remove_container(&self, _req: RemoveContainerRequest) -> Result<Empty> {
        unimplemented!()
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
        unimplemented!()
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

#[derive(Debug)]
struct Args {
    config: PathBuf,
    output: PathBuf,
    sid: String,
    cid: String,
    emptydir_mode: String,
    disable_guest_empty_dir: bool,
}

fn parse_args() -> Result<Args> {
    let mut config = None;
    let mut output = None;
    let mut sid = "sandbox".to_string();
    let mut cid = "container".to_string();
    let mut emptydir_mode = "shared-fs".to_string();
    let mut disable_guest_empty_dir = false;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(iter.next().context("--config needs a value")?)),
            "--output" => output = Some(PathBuf::from(iter.next().context("--output needs a value")?)),
            "--sid" => sid = iter.next().context("--sid needs a value")?,
            "--cid" => cid = iter.next().context("--cid needs a value")?,
            "--emptydir-mode" => {
                emptydir_mode = iter.next().context("--emptydir-mode needs a value")?
            }
            "--disable-guest-empty-dir" => disable_guest_empty_dir = true,
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        config: config.context("--config is required")?,
        output: output.context("--output is required")?,
        sid,
        cid,
        emptydir_mode,
        disable_guest_empty_dir,
    })
}

/// Serializable mirror of `agent::types::FSGroup` (the source type is not
/// `Serialize`).
#[derive(Serialize)]
struct PredictedFsGroup {
    group_id: u32,
    group_change_policy: String,
}

/// Serializable mirror of `agent::types::Storage`.
#[derive(Serialize)]
struct PredictedStorage {
    driver: String,
    driver_options: Vec<String>,
    source: String,
    fs_type: String,
    fs_group: Option<PredictedFsGroup>,
    options: Vec<String>,
    mount_point: String,
    shared: bool,
}

#[derive(Serialize)]
struct PredictedMount {
    destination: String,
    r#type: Option<String>,
    source: Option<String>,
    options: Option<Vec<String>>,
}

#[derive(Serialize)]
struct PredictedVolume {
    storages: Vec<PredictedStorage>,
    mounts: Vec<PredictedMount>,
    device_id: Option<String>,
}

#[derive(Serialize)]
struct Prediction {
    schema_version: u32,
    sandbox_id: String,
    container_id: String,
    emptydir_mode: String,
    volumes: Vec<PredictedVolume>,
}

fn map_storage(s: &Storage) -> PredictedStorage {
    PredictedStorage {
        driver: s.driver.clone(),
        driver_options: s.driver_options.clone(),
        source: s.source.clone(),
        fs_type: s.fs_type.clone(),
        fs_group: s.fs_group.as_ref().map(|g| PredictedFsGroup {
            group_id: g.group_id,
            group_change_policy: format!("{:?}", g.group_change_policy),
        }),
        options: s.options.clone(),
        mount_point: s.mount_point.clone(),
        shared: s.shared,
    }
}

fn map_mount(m: &oci_spec::runtime::Mount) -> PredictedMount {
    PredictedMount {
        destination: m.destination().display().to_string(),
        r#type: m.typ().clone(),
        source: m.source().as_ref().map(|s| s.display().to_string()),
        options: m.options().clone(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let spec_text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;
    let mut spec: oci_spec::runtime::Spec =
        serde_json::from_str(&spec_text).context("parse OCI config.json")?;

    // Reproduce the shim's mount-type rewriting. This inspects live host mount
    // state (mountinfo / stat), so it is only authoritative while the workload's
    // host volume mounts are still present.
    update_ephemeral_storage_type(&mut spec, args.disable_guest_empty_dir, &args.emptydir_mode);

    // Real DeviceManager, backed by a dry-run hypervisor: no VM is created.
    let hv: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor);
    let device_manager = RwLock::new(DeviceManager::new(hv, None).await?);

    let share_fs: Option<Arc<dyn ShareFs>> = None;
    let agent: Arc<dyn Agent> = Arc::new(StubAgent);

    let ctx = VolumeContext {
        share_fs: &share_fs,
        d: &device_manager,
        sid: &args.sid,
        agent,
        emptydir_mode: &args.emptydir_mode,
    };

    let volume_resource = VolumeResource::new();
    let volumes = volume_resource
        .handler_volumes(&ctx, &args.cid, &spec)
        .await
        .context("handler_volumes")?;

    let mut predicted_volumes = Vec::with_capacity(volumes.len());
    for volume in &volumes {
        predicted_volumes.push(PredictedVolume {
            storages: volume.get_storage()?.iter().map(map_storage).collect(),
            mounts: volume.get_volume_mount()?.iter().map(map_mount).collect(),
            device_id: volume.get_device_id()?,
        });
    }

    let output_path = args.output.clone();
    let prediction = Prediction {
        schema_version: 1,
        sandbox_id: args.sid,
        container_id: args.cid,
        emptydir_mode: args.emptydir_mode,
        volumes: predicted_volumes,
    };

    let mut json = serde_json::to_string_pretty(&prediction)?;
    json.push('\n');
    std::fs::write(&output_path, json)
        .with_context(|| format!("write {}", output_path.display()))?;

    eprintln!(
        "predicted {} volume(s) -> {} (no VM)",
        volumes.len(),
        output_path.display()
    );
    Ok(())
}
