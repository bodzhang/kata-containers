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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

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
use kata_types::config::TomlConfig;
use kata_types::k8s::is_watchable_mount;
use kata_types::mount::Mount as KataMount;
use resource::rootfs::RootFsResource;
use resource::share_fs::{
    do_get_guest_path, kata_guest_share_dir, MountedInfo, ShareFs, ShareFsMount,
    ShareFsMountResult, ShareFsRootfsConfig, ShareFsVolumeConfig, PASSTHROUGH_FS_DIR,
};
use resource::volume::{VolumeContext, VolumeResource};

/// A Hypervisor implementation that performs no VMM I/O. Its methods are never
/// invoked by the ephemeral/local storage transformation path; they exist only
/// so `DeviceManager` can be constructed. `unimplemented!()` diverges, so every
/// method type-checks regardless of its declared return type.
#[derive(Debug, Default)]
struct DryRunHypervisor {
    // Sourced from the profile fallback or the deployment's Kata config.
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
    // Echo the device unchanged: the guest device path (/dev/vdX) is assigned
    // deterministically by the device manager before attach, so no VM is needed.
    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
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

// Constants mirrored from runtime-rs/crates/resource/src/share_fs/
// virtio_fs_share_mount.rs (private there). Alignment risk: if upstream renames
// these, update here. Verified against that file's `share_volume`.
const WATCHABLE_PATH_NAME: &str = "watchable";
const WATCHABLE_BIND_DEV_TYPE: &str = "watchable-bind";

/// Reproduces `VirtiofsShareMount::share_volume`'s storage output for share-fs
/// volumes without performing the real host bind mount. Guest paths come from the
/// shim's own `do_get_guest_path`; watchable detection uses the shim's own
/// `is_watchable_mount`. Only the two constants above are mirrored.
struct StubShareFsMount;

#[async_trait]
impl ShareFsMount for StubShareFsMount {
    async fn share_rootfs(&self, _config: &ShareFsRootfsConfig) -> Result<ShareFsMountResult> {
        unimplemented!()
    }

    async fn share_volume(&self, config: &ShareFsVolumeConfig) -> Result<ShareFsMountResult> {
        // Mirrors virtio_fs_share_mount.rs `share_volume`, minus side effects:
        // reuse the shim's guest-path computation instead of `share_to_guest`,
        // and skip the host `mkdir` of the watchable directory.
        let guest_path = do_get_guest_path(&config.target, &config.cid, true, config.is_rafs);

        if is_watchable_mount(&config.source) {
            let file_name = Path::new(&guest_path)
                .file_name()
                .context("get file name from guest path")?;
            let watchable_guest_mount = Path::new(kata_guest_share_dir().as_str())
                .join(PASSTHROUGH_FS_DIR)
                .join(WATCHABLE_PATH_NAME)
                .join(file_name)
                .into_os_string()
                .into_string()
                .map_err(|e| anyhow::anyhow!("watchable guest mount path {:?}", e))?;

            let storage = Storage {
                driver: WATCHABLE_BIND_DEV_TYPE.to_string(),
                driver_options: Vec::new(),
                source: guest_path,
                fs_type: "bind".to_string(),
                fs_group: None,
                options: config.mount_options.clone(),
                mount_point: watchable_guest_mount.clone(),
                shared: false,
            };
            return Ok(ShareFsMountResult {
                guest_path: watchable_guest_mount,
                storages: vec![storage],
            });
        }

        Ok(ShareFsMountResult {
            guest_path,
            storages: Vec::new(),
        })
    }

    async fn upgrade_to_rw(&self, _file_name: &str) -> Result<()> {
        unimplemented!()
    }
    async fn downgrade_to_ro(&self, _file_name: &str) -> Result<()> {
        unimplemented!()
    }
    async fn umount_volume(&self, _file_name: &str) -> Result<()> {
        unimplemented!()
    }
    async fn umount_rootfs(&self, _config: &ShareFsRootfsConfig) -> Result<()> {
        unimplemented!()
    }
    async fn cleanup(&self, _sid: &str) -> Result<()> {
        unimplemented!()
    }
}

/// Minimal `ShareFs` so `handler_volumes` takes the shared-fs path rather than
/// the copy-to-rootfs fallback (which needs a real Agent). Only
/// `get_share_fs_mount` and an empty `mounted_info_set` are exercised.
struct StubShareFs {
    mount: Arc<dyn ShareFsMount>,
    mounted_info: Arc<Mutex<HashMap<String, MountedInfo>>>,
}

impl StubShareFs {
    fn new() -> Self {
        Self {
            mount: Arc::new(StubShareFsMount),
            mounted_info: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ShareFs for StubShareFs {
    fn get_share_fs_mount(&self) -> Arc<dyn ShareFsMount> {
        self.mount.clone()
    }
    async fn setup_device_before_start_vm(
        &self,
        _h: &dyn Hypervisor,
        _d: &RwLock<DeviceManager>,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn setup_device_after_start_vm(
        &self,
        _h: &dyn Hypervisor,
        _d: &RwLock<DeviceManager>,
    ) -> Result<()> {
        unimplemented!()
    }
    async fn get_storages(&self) -> Result<Vec<Storage>> {
        Ok(Vec::new())
    }
    fn mounted_info_set(&self) -> Arc<Mutex<HashMap<String, MountedInfo>>> {
        self.mounted_info.clone()
    }
}

#[derive(Debug)]
struct Args {
    config: PathBuf,
    output: PathBuf,
    sid: String,
    cid: String,
    emptydir_mode: String,
    block_driver: String,
    disable_guest_empty_dir: bool,
    kata_config: Option<PathBuf>,
    rootfs_mounts: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut config = None;
    let mut output = None;
    let mut sid = "sandbox".to_string();
    let mut cid = "container".to_string();
    let mut emptydir_mode = "shared-fs".to_string();
    let mut block_driver = "virtio-blk-pci".to_string();
    let mut disable_guest_empty_dir = false;
    let mut kata_config: Option<PathBuf> = None;
    let mut rootfs_mounts: Option<PathBuf> = None;

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
            "--block-driver" => {
                block_driver = iter.next().context("--block-driver needs a value")?
            }
            "--kata-config" => {
                kata_config = Some(PathBuf::from(iter.next().context("--kata-config needs a value")?))
            }
            "--rootfs-mounts" => {
                rootfs_mounts =
                    Some(PathBuf::from(iter.next().context("--rootfs-mounts needs a value")?))
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
        block_driver,
        disable_guest_empty_dir,
        kata_config,
        rootfs_mounts,
    })
}

/// Extracts the active hypervisor config and empty-dir runtime settings from a
/// parsed Kata `configuration.toml`.
fn resolve_from_toml(toml: &TomlConfig) -> (HypervisorConfig, String, bool) {
    let config = toml
        .hypervisor
        .get(&toml.runtime.hypervisor_name)
        .cloned()
        .unwrap_or_default();
    let emptydir_mode = if toml.runtime.emptydir_mode.is_empty() {
        "shared-fs".to_string()
    } else {
        toml.runtime.emptydir_mode.clone()
    };
    // Upstream `Runtime` no longer carries `disable_guest_empty_dir`.
    (config, emptydir_mode, false)
}

/// Resolves the hypervisor config and empty-dir settings from `--kata-config`
/// (authoritative) or, failing that, the individual profile-sourced args.
fn resolve_runtime_config(args: &Args) -> Result<(HypervisorConfig, String, bool)> {
    if let Some(path) = &args.kata_config {
        // Raw load: parse the config values without `adjust_config`, which would
        // validate hypervisor binary paths that are absent in the clean room.
        let (toml, _) = TomlConfig::load_raw_from_file(path)
            .with_context(|| format!("load kata config {}", path.display()))?;
        Ok(resolve_from_toml(&toml))
    } else {
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = args.block_driver.clone();
        Ok((config, args.emptydir_mode.clone(), args.disable_guest_empty_dir))
    }
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

/// Predicted container rootfs, produced by the real `handler_rootfs` from a
/// snapshotter-captured `rootfs_mounts` artifact (e.g. multi-layer erofs).
/// `error` is set (and the other fields left empty) when the transform fails, so
/// a rootfs failure never drops the container's volume prediction.
#[derive(Serialize, Default)]
struct PredictedRootfs {
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_path: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    storages: Vec<PredictedStorage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct Prediction {
    schema_version: u32,
    sandbox_id: String,
    container_id: String,
    emptydir_mode: String,
    volumes: Vec<PredictedVolume>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rootfs: Option<PredictedRootfs>,
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

/// Reproduces the shim's `handler_rootfs` over a snapshotter-captured
/// `rootfs_mounts` artifact. Multi-layer erofs is routed to
/// `ErofsMultiLayerRootfs`, whose block layers get deterministic `/dev/vdX`
/// guest paths from the dry-run device manager (no VM).
async fn predict_rootfs(
    rootfs_path: &Path,
    spec: &oci_spec::runtime::Spec,
    share_fs: &Option<Arc<dyn ShareFs>>,
    device_manager: &RwLock<DeviceManager>,
    hv: &dyn Hypervisor,
    sid: &str,
    cid: &str,
) -> Result<PredictedRootfs> {
    let text = std::fs::read_to_string(rootfs_path)
        .with_context(|| format!("read {}", rootfs_path.display()))?;
    let mounts: Vec<KataMount> =
        serde_json::from_str(&text).context("parse --rootfs-mounts json")?;
    let root = spec.root().clone().unwrap_or_default();
    let annotations = spec.annotations().clone().unwrap_or_default();
    let rootfs = RootFsResource::new()
        .handler_rootfs(
            share_fs,
            &None,
            device_manager,
            hv,
            sid,
            cid,
            &root,
            "",
            &mounts,
            &annotations,
        )
        .await
        .context("handler_rootfs")?;
    let storages = rootfs.get_storage().await.unwrap_or_default();
    Ok(PredictedRootfs {
        guest_path: Some(rootfs.get_guest_rootfs_path().await?),
        storages: storages.iter().map(map_storage).collect(),
        device_id: rootfs.get_device_id().await?,
        error: None,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let spec_text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;
    let mut spec: oci_spec::runtime::Spec =
        serde_json::from_str(&spec_text).context("parse OCI config.json")?;

    let (hypervisor_config, emptydir_mode, _disable_guest_empty_dir) =
        resolve_runtime_config(&args)?;

    // Reproduce the shim's mount-type rewriting. This inspects live host mount
    // state (mountinfo / stat), so it is only authoritative while the workload's
    // host volume mounts are still present.
    update_ephemeral_storage_type(&mut spec);

    // Real DeviceManager, backed by a dry-run hypervisor: no VM is created.
    let hv: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor {
        config: hypervisor_config,
    });
    let device_manager = RwLock::new(DeviceManager::new(hv.clone(), None).await?);

    // A stub ShareFs routes share-fs volumes (configmap/secret/projected/
    // downwardAPI/hostPath) through the shared-fs path instead of the
    // copy-to-rootfs fallback that needs a real Agent.
    let share_fs: Option<Arc<dyn ShareFs>> = Some(Arc::new(StubShareFs::new()));
    let agent: Arc<dyn Agent> = Arc::new(StubAgent);

    let ctx = VolumeContext {
        share_fs: &share_fs,
        d: &device_manager,
        sid: &args.sid,
        agent,
        emptydir_mode: &emptydir_mode,
        fs_sharing_supported: true,
        block_device_discard_supported: false,
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

    // Optional rootfs prediction from a snapshotter-captured `rootfs_mounts`
    // artifact. A transform failure (e.g. a virtio-blk-pci deployment hitting the
    // pci_path gap) is captured into the `error` field so the container's volume
    // prediction still succeeds.
    let rootfs = match &args.rootfs_mounts {
        None => None,
        Some(rootfs_path) => Some(
            predict_rootfs(
                rootfs_path,
                &spec,
                &share_fs,
                &device_manager,
                hv.as_ref(),
                &args.sid,
                &args.cid,
            )
            .await
            .unwrap_or_else(|e| PredictedRootfs {
                error: Some(format!("{e:#}")),
                ..Default::default()
            }),
        ),
    };

    let output_path = args.output.clone();
    let prediction = Prediction {
        schema_version: 1,
        sandbox_id: args.sid,
        container_id: args.cid,
        emptydir_mode,
        volumes: predicted_volumes,
        rootfs,
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

#[cfg(test)]
mod tests {
    use super::*;

    // The profile-sourced block driver flows into the hypervisor config.
    #[tokio::test]
    async fn hypervisor_config_uses_profile_block_driver() {
        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = "virtio-blk-mmio".to_string();
        let hv = DryRunHypervisor { config };
        let config = hv.hypervisor_config().await;
        assert_eq!(config.blockdev_info.block_device_driver, "virtio-blk-mmio");
    }

    // A multi-layer erofs `rootfs_mounts` artifact (ext4 rw upper + erofs lower)
    // is transformed by the real `handler_rootfs` into two block-backed rootfs
    // storages with deterministic `/dev/vdX` guest paths, no VM. Uses the
    // virtio-blk-mmio driver, whose Agent source is `virt_path` (the pci driver
    // needs a backend-assigned pci_path the dry-run does not synthesize).
    #[tokio::test]
    async fn dry_run_erofs_multi_layer_produces_layer_storages() {
        // generate_merged_erofs_vmdk stats the erofs source, so it must exist.
        let dir = std::env::temp_dir().join(format!("gp-erofs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let erofs_src = dir.join("layer.erofs");
        std::fs::write(&erofs_src, b"erofs-image-bytes").unwrap();

        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = "virtio-blk-mmio".to_string();
        let hv: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor { config });
        let device_manager = RwLock::new(DeviceManager::new(hv.clone(), None).await.unwrap());

        let rootfs_mounts = vec![
            KataMount {
                source: "/dev/loop0".to_string(),
                destination: PathBuf::from("/"),
                fs_type: "ext4".to_string(),
                options: vec!["rw".to_string()],
                ..Default::default()
            },
            KataMount {
                source: erofs_src.display().to_string(),
                destination: PathBuf::from("/"),
                fs_type: "erofs".to_string(),
                options: vec!["ro".to_string()],
                ..Default::default()
            },
            // The snapshotter also emits the overlay mount that combines the
            // upper + lower; upstream `is_erofs_multi_layer` requires it.
            KataMount {
                source: "overlay".to_string(),
                destination: PathBuf::from("/"),
                fs_type: "overlay".to_string(),
                options: vec![],
                ..Default::default()
            },
        ];

        let share_fs: Option<Arc<dyn ShareFs>> = None;
        let root = oci_spec::runtime::Root::default();
        let annotations = HashMap::new();
        let resource = RootFsResource::new();
        let rootfs = resource
            .handler_rootfs(
                &share_fs,
                &None,
                &device_manager,
                hv.as_ref(),
                "erofs-sid",
                "erofs-cid",
                &root,
                "",
                &rootfs_mounts,
                &annotations,
            )
            .await
            .unwrap();

        let storages = rootfs.get_storage().await.unwrap();
        assert_eq!(storages.len(), 2);
        // rw ext4 upper layer -> first block device /dev/vda
        assert_eq!(storages[0].fs_type, "ext4");
        assert_eq!(storages[0].driver, "mmioblk");
        assert_eq!(storages[0].source, "/dev/vda");
        // read-only erofs lower layer -> second block device /dev/vdb
        assert_eq!(storages[1].fs_type, "erofs");
        assert_eq!(storages[1].driver, "mmioblk");
        assert_eq!(storages[1].source, "/dev/vdb");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A virtio-blk-pci deployment hits the pci_path gap: the erofs transform
    // errors, and `predict_rootfs` surfaces that error (the caller captures it
    // into the `error` field rather than dropping the volume prediction).
    #[tokio::test]
    async fn erofs_pci_driver_surfaces_error() {
        let dir = std::env::temp_dir().join(format!("gp-erofs-pci-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let erofs_src = dir.join("layer.erofs");
        std::fs::write(&erofs_src, b"erofs-image-bytes").unwrap();
        let rootfs_mounts = dir.join("rootfs-mounts.json");
        let mounts = serde_json::json!([
            { "source": "/dev/loop0", "destination": "/", "fs_type": "ext4",
              "options": ["rw"], "device_id": null, "host_shared_fs_path": null, "read_only": false },
            { "source": erofs_src.to_string_lossy(), "destination": "/", "fs_type": "erofs",
              "options": ["ro"], "device_id": null, "host_shared_fs_path": null, "read_only": true },
            { "source": "overlay", "destination": "/", "fs_type": "overlay",
              "options": [], "device_id": null, "host_shared_fs_path": null, "read_only": false }
        ]);
        std::fs::write(&rootfs_mounts, serde_json::to_string(&mounts).unwrap()).unwrap();

        let mut config = HypervisorConfig::default();
        config.blockdev_info.block_device_driver = "virtio-blk-pci".to_string();
        let hv: Arc<dyn Hypervisor> = Arc::new(DryRunHypervisor { config });
        let device_manager = RwLock::new(DeviceManager::new(hv.clone(), None).await.unwrap());

        let spec = oci_spec::runtime::Spec::default();
        let share_fs: Option<Arc<dyn ShareFs>> = None;
        let result = predict_rootfs(
            &rootfs_mounts,
            &spec,
            &share_fs,
            &device_manager,
            hv.as_ref(),
            "erofs-sid",
            "erofs-cid",
        )
        .await;
        assert!(result.is_err(), "pci erofs rootfs should error under dry-run");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A Kata configuration.toml sources the active hypervisor config and the
    // empty-dir runtime settings.
    #[test]
    fn kata_config_sources_hypervisor_and_runtime() {
        let dir = std::env::temp_dir().join(format!("gp-kata-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("configuration.toml");
        std::fs::write(
            &path,
            r#"
[hypervisor.qemu]
block_device_driver = "virtio-blk-mmio"

[runtime]
hypervisor_name = "qemu"
emptydir_mode = "block-encrypted"
disable_guest_empty_dir = true
"#,
        )
        .unwrap();

        let (toml, _) = TomlConfig::load_raw_from_file(&path).unwrap();
        let (config, emptydir_mode, _disable) = resolve_from_toml(&toml);
        assert_eq!(config.blockdev_info.block_device_driver, "virtio-blk-mmio");
        assert_eq!(emptydir_mode, "block-encrypted");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
