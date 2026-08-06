use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agent::types::*;
use agent::{Agent, AgentManager, HealthService};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::message::{Action, Message};
use common::types::{ContainerProcess, SandboxExitInfo, SandboxStatus};
use common::{ContainerManager, Sandbox};
use hypervisor::device::DeviceType;
use hypervisor::hypervisor_persist::HypervisorState;
use hypervisor::{Hypervisor, MemoryConfig, PciPath, VcpuThreadIds};
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use kata_types::config::Agent as AgentConfig;
use kata_types::device::{DRIVER_BLK_CCW_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_SCSI_TYPE};
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, Notify};

use crate::{serialize_create_request, serialize_exec_request};

pub struct CaptureSandbox {
    sandbox_id: String,
    message_sender: Sender<Message>,
    started_at: Mutex<Option<std::time::SystemTime>>,
    exited_at: Mutex<Option<std::time::SystemTime>>,
    exit_notify: Notify,
}

impl CaptureSandbox {
    pub fn new(sandbox_id: String, message_sender: Sender<Message>) -> Self {
        Self {
            sandbox_id,
            message_sender,
            started_at: Mutex::new(None),
            exited_at: Mutex::new(None),
            exit_notify: Notify::new(),
        }
    }

    async fn mark_stopped(&self) {
        let mut exited_at = self.exited_at.lock().await;
        if exited_at.is_none() {
            *exited_at = Some(std::time::SystemTime::now());
            self.exit_notify.notify_waiters();
        }
    }
}

#[async_trait]
impl Sandbox for CaptureSandbox {
    async fn start(&self) -> Result<()> {
        let mut started_at = self.started_at.lock().await;
        if started_at.is_none() {
            *started_at = Some(std::time::SystemTime::now());
        }
        Ok(())
    }

    async fn start_template(&self) -> Result<()> {
        self.start().await
    }

    async fn stop(&self) -> Result<()> {
        self.mark_stopped().await;
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.mark_stopped().await;
        self.message_sender
            .send(Message::new(Action::Shutdown))
            .await
            .context("send capture shim shutdown")
    }

    async fn status(&self) -> Result<SandboxStatus> {
        let created_at = *self.started_at.lock().await;
        let stopped = self.exited_at.lock().await.is_some();
        Ok(SandboxStatus {
            sandbox_id: self.sandbox_id.clone(),
            pid: std::process::id(),
            state: if stopped { "stopped" } else { "running" }.to_string(),
            info: HashMap::new(),
            created_at,
        })
    }

    async fn wait(&self) -> Result<SandboxExitInfo> {
        loop {
            if let Some(exited_at) = *self.exited_at.lock().await {
                return Ok(SandboxExitInfo {
                    exit_status: 0,
                    exited_at: Some(exited_at),
                });
            }
            self.exit_notify.notified().await;
        }
    }

    async fn set_iptables(&self, _is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(data)
    }

    async fn get_iptables(&self, _is_ipv6: bool) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn direct_volume_stats(&self, _volume_path: &str) -> Result<String> {
        Ok("{}".to_string())
    }

    async fn direct_volume_resize(&self, _resize_req: ResizeVolumeRequest) -> Result<()> {
        Ok(())
    }

    async fn agent_sock(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn wait_process(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        _shim_pid: u32,
    ) -> Result<()> {
        container_manager.wait_process(&process_id).await?;
        Ok(())
    }

    async fn rescan_network(&self) -> Result<()> {
        Ok(())
    }

    async fn agent_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn hypervisor_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn set_policy(&self, _policy: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct DryRunHypervisor {
    config: HypervisorConfig,
}

impl DryRunHypervisor {
    pub fn new(config: HypervisorConfig) -> Self {
        Self { config }
    }
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
        Err(anyhow!("capture hypervisor does not create a VM"))
    }

    async fn start_vm(&self, _timeout: i32) -> Result<()> {
        Err(anyhow!("capture hypervisor does not start a VM"))
    }

    async fn stop_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn wait_vm(&self) -> Result<i32> {
        Err(anyhow!("capture hypervisor has no VM to wait for"))
    }

    async fn pause_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn save_vm(&self) -> Result<()> {
        Err(anyhow!("capture hypervisor cannot save a VM"))
    }

    async fn resume_vm(&self) -> Result<()> {
        Ok(())
    }

    async fn resize_vcpu(&self, old_vcpus: u32, new_vcpus: u32) -> Result<(u32, u32)> {
        Ok((old_vcpus, new_vcpus))
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        Ok((new_mem_mb, MemoryConfig::default()))
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        if let DeviceType::BlockModern(ref block) = device {
            let mut device_guard = block.lock().await;
            let index = device_guard.config.index;
            let driver = device_guard.config.driver_option.clone();
            if driver == DRIVER_BLK_PCI_TYPE {
                device_guard.config.pci_path = Some(PciPath::try_from((index + 1) as u32)?);
            } else if driver == DRIVER_SCSI_TYPE {
                device_guard.config.scsi_addr = Some(format!("{}:{}", index >> 8, index & 0xff));
            } else if driver == DRIVER_BLK_CCW_TYPE {
                device_guard.config.ccw_addr = Some(format!("0.0.{:04x}", index));
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
        Err(anyhow!("capture hypervisor has no Agent socket"))
    }

    async fn disconnect(&self) {}

    async fn hypervisor_config(&self) -> HypervisorConfig {
        self.config.clone()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        Ok(VcpuThreadIds::default())
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        Ok(vec![std::process::id()])
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        Ok(std::process::id())
    }

    async fn get_ns_path(&self) -> Result<String> {
        Ok("/proc/self/ns".to_string())
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    async fn check(&self) -> Result<()> {
        Ok(())
    }

    async fn get_jailer_root(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn save_state(&self) -> Result<HypervisorState> {
        Ok(HypervisorState::default())
    }

    async fn capabilities(&self) -> Result<Capabilities> {
        Ok(Capabilities::default())
    }

    async fn get_hypervisor_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn set_capabilities(&self, _flag: CapabilityBits) {}

    async fn set_guest_memory_block_size(&self, _size: u32) {}

    async fn guest_memory_block_size(&self) -> u32 {
        0
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow!("capture hypervisor has no passfd listener"))
    }
}

pub struct RecordingAgent {
    captured_create: Arc<Mutex<Vec<CreateContainerRequest>>>,
    output_dir: Option<PathBuf>,
    sequence: AtomicU64,
    init_processes: Mutex<HashMap<String, Arc<Notify>>>,
}

impl RecordingAgent {
    pub fn in_memory(captured_create: Arc<Mutex<Vec<CreateContainerRequest>>>) -> Self {
        Self {
            captured_create,
            output_dir: None,
            sequence: AtomicU64::new(0),
            init_processes: Mutex::new(HashMap::new()),
        }
    }

    pub fn to_directory(output_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(output_dir.join("createcontainer-requests"))?;
        std::fs::create_dir_all(output_dir.join("execprocess-requests"))?;
        std::fs::create_dir_all(output_dir.join("raw"))?;
        Ok(Self {
            captured_create: Arc::new(Mutex::new(Vec::new())),
            output_dir: Some(output_dir),
            sequence: AtomicU64::new(0),
            init_processes: Mutex::new(HashMap::new()),
        })
    }

    fn safe_id(id: &str) -> String {
        id.chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn write_request(&self, directory: &str, kind: &str, id: &str, json: String) -> Result<()> {
        let Some(output_dir) = &self.output_dir else {
            return Ok(());
        };
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let safe_id = Self::safe_id(id);
        let path = output_dir
            .join(directory)
            .join(format!("{sequence:04}-{kind}-{safe_id}.json"));
        std::fs::write(&path, json + "\n")
            .with_context(|| format!("write captured request {}", path.display()))
    }
}

#[async_trait]
impl AgentManager for RecordingAgent {
    async fn start(&self, _address: &str) -> Result<()> {
        Ok(())
    }

    async fn stop(&self) {}

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    async fn agent_sock(&self) -> Result<String> {
        Ok(String::new())
    }

    async fn agent_config(&self) -> AgentConfig {
        AgentConfig::default()
    }
}

#[async_trait]
impl HealthService for RecordingAgent {
    async fn check(&self, _req: CheckRequest) -> Result<HealthCheckResponse> {
        Ok(HealthCheckResponse::default())
    }

    async fn version(&self, _req: CheckRequest) -> Result<VersionCheckResponse> {
        Ok(VersionCheckResponse::default())
    }
}

#[async_trait]
impl Agent for RecordingAgent {
    async fn create_sandbox(&self, _req: CreateSandboxRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn destroy_sandbox(&self, _req: Empty) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn online_cpu_mem(&self, _req: OnlineCPUMemRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn add_arp_neighbors(&self, _req: AddArpNeighborRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn list_interfaces(&self, _req: Empty) -> Result<Interfaces> {
        Ok(Interfaces::default())
    }

    async fn list_routes(&self, _req: Empty) -> Result<Routes> {
        Ok(Routes::default())
    }

    async fn update_interface(&self, req: UpdateInterfaceRequest) -> Result<Interface> {
        Ok(req.interface.unwrap_or_default())
    }

    async fn update_routes(&self, req: UpdateRoutesRequest) -> Result<Routes> {
        Ok(req.route.unwrap_or_default())
    }

    async fn create_container(&self, req: CreateContainerRequest) -> Result<Empty> {
        let container_id = req.process_id.container_id.container_id.clone();
        if let Some(output_dir) = &self.output_dir {
            let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            let basename = format!("{sequence:04}-{}", Self::safe_id(&container_id));
            std::fs::write(
                output_dir
                    .join("createcontainer-requests")
                    .join(format!("{basename}.json")),
                serialize_create_request(&req)? + "\n",
            )?;
            if let Some(spec) = &req.oci {
                let bundle = spec
                    .annotations()
                    .as_ref()
                    .and_then(|annotations| {
                        annotations.get(kata_types::annotations::BUNDLE_PATH_KEY)
                    })
                    .context("captured create request has no runtime bundle annotation")?;
                let raw_config_path = PathBuf::from(bundle).join("config.json");
                let raw_config = std::fs::read_to_string(&raw_config_path).with_context(|| {
                    format!("read raw OCI config {}", raw_config_path.display())
                })?;
                serde_json::from_str::<serde_json::Value>(&raw_config).with_context(|| {
                    format!("parse raw OCI config {}", raw_config_path.display())
                })?;
                std::fs::write(
                    output_dir.join("raw").join(format!("{basename}.config.json")),
                    raw_config,
                )?;
                std::fs::write(
                    output_dir.join("raw").join(format!("{basename}.meta.json")),
                    serde_json::to_string_pretty(&serde_json::json!({
                        "bundle": bundle,
                        "container_id": container_id,
                    }))? + "\n",
                )?;
            }
        }
        self.init_processes
            .lock()
            .await
            .entry(container_id)
            .or_insert_with(|| Arc::new(Notify::new()));
        self.captured_create.lock().await.push(req);
        Ok(Empty::default())
    }

    async fn pause_container(&self, _req: ContainerID) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn remove_container(&self, req: RemoveContainerRequest) -> Result<Empty> {
        if let Some(notify) = self.init_processes.lock().await.remove(&req.container_id) {
            notify.notify_one();
        }
        Ok(Empty::default())
    }

    async fn resume_container(&self, _req: ContainerID) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn start_container(&self, _req: ContainerID) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn stats_container(&self, _req: ContainerID) -> Result<StatsContainerResponse> {
        Ok(StatsContainerResponse::default())
    }

    async fn update_container(&self, _req: UpdateContainerRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn exec_process(&self, req: ExecProcessRequest) -> Result<Empty> {
        let id = format!(
            "{}-{}",
            req.process_id.container_id.container_id, req.process_id.exec_id
        );
        self.write_request(
            "execprocess-requests",
            "exec",
            &id,
            serialize_exec_request(&req)?,
        )?;
        Ok(Empty::default())
    }

    async fn signal_process(&self, req: SignalProcessRequest) -> Result<Empty> {
        if req.process_id.exec_id.is_empty() {
            if let Some(notify) = self
                .init_processes
                .lock()
                .await
                .get(&req.process_id.container_id.container_id)
            {
                notify.notify_one();
            }
        }
        Ok(Empty::default())
    }

    async fn wait_process(&self, req: WaitProcessRequest) -> Result<WaitProcessResponse> {
        if req.process_id.exec_id.is_empty() {
            let notify = self
                .init_processes
                .lock()
                .await
                .entry(req.process_id.container_id.container_id)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone();
            notify.notified().await;
        }
        Ok(WaitProcessResponse { status: 0 })
    }

    async fn close_stdin(&self, _req: CloseStdinRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn read_stderr(&self, _req: ReadStreamRequest) -> Result<ReadStreamResponse> {
        Ok(ReadStreamResponse::default())
    }

    async fn read_stdout(&self, _req: ReadStreamRequest) -> Result<ReadStreamResponse> {
        Ok(ReadStreamResponse::default())
    }

    async fn tty_win_resize(&self, _req: TtyWinResizeRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn write_stdin(&self, req: WriteStreamRequest) -> Result<WriteStreamResponse> {
        Ok(WriteStreamResponse {
            length: req.data.len() as u32,
        })
    }

    async fn copy_file(&self, _req: CopyFileRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn get_metrics(&self, _req: Empty) -> Result<MetricsResponse> {
        Ok(MetricsResponse::default())
    }

    async fn get_oom_event(&self, _req: Empty) -> Result<OomEventResponse> {
        Err(anyhow!("capture Agent has no OOM event stream"))
    }

    async fn get_ip_tables(&self, _req: GetIPTablesRequest) -> Result<GetIPTablesResponse> {
        Ok(GetIPTablesResponse::default())
    }

    async fn set_ip_tables(&self, req: SetIPTablesRequest) -> Result<SetIPTablesResponse> {
        Ok(SetIPTablesResponse { data: req.data })
    }

    async fn get_volume_stats(&self, _req: VolumeStatsRequest) -> Result<VolumeStatsResponse> {
        Ok(VolumeStatsResponse::default())
    }

    async fn resize_volume(&self, _req: ResizeVolumeRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn get_guest_details(&self, _req: GetGuestDetailsRequest) -> Result<GuestDetailsResponse> {
        Ok(GuestDetailsResponse::default())
    }

    async fn add_swap(&self, _req: AddSwapRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn add_swap_path(&self, _req: AddSwapPathRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn set_policy(&self, _req: SetPolicyRequest) -> Result<Empty> {
        Ok(Empty::default())
    }

    async fn get_diagnostic_data(
        &self,
        _req: GetDiagnosticDataRequest,
    ) -> Result<GetDiagnosticDataResponse> {
        Ok(GetDiagnosticDataResponse::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_agent_writes_create_and_exec_artifacts_in_order() {
        let output = std::env::temp_dir().join(format!(
            "kata-createreq-capture-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&output);
        let agent = RecordingAgent::to_directory(output.clone()).unwrap();
        let bundle_dir = output.join("bundle");
        std::fs::create_dir_all(&bundle_dir).unwrap();
        std::fs::write(
            bundle_dir.join("config.json"),
            r#"{"ociVersion":"1.0.2","process":{"cwd":"/raw"}}"#,
        )
        .unwrap();
        let bundle = bundle_dir.to_string_lossy().into_owned();
        let spec = serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "process": {
                "args": [],
                "cwd": "/final",
                "env": [],
                "user": {"gid": 0, "uid": 0},
            },
            "annotations": {
                kata_types::annotations::BUNDLE_PATH_KEY: &bundle,
            },
        }))
        .unwrap();

        agent
            .create_container(CreateContainerRequest {
                process_id: ContainerProcessID::new("container/one", ""),
                oci: Some(spec),
                ..Default::default()
            })
            .await
            .unwrap();
        agent
            .exec_process(ExecProcessRequest {
                process_id: ContainerProcessID::new("container/one", "probe/ready"),
                ..Default::default()
            })
            .await
            .unwrap();

        let create = output.join("createcontainer-requests/0001-container_one.json");
        let raw = output.join("raw/0001-container_one.config.json");
        let metadata = output.join("raw/0001-container_one.meta.json");
        let exec = output
            .join("execprocess-requests/0002-exec-container_one-probe_ready.json");
        assert!(create.exists());
        assert!(raw.exists());
        assert!(exec.exists());

        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(raw).unwrap()).unwrap();
        let final_request: serde_json::Value =
            serde_json::from_slice(&std::fs::read(create).unwrap()).unwrap();
        assert_eq!(raw["process"]["cwd"], "/raw");
        assert_eq!(final_request["oci"]["process"]["cwd"], "/final");

        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(metadata).unwrap()).unwrap();
        assert_eq!(metadata["container_id"], "container/one");
        assert_eq!(metadata["bundle"], bundle);

        let exec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(exec).unwrap()).unwrap();
        assert_eq!(exec["exec_id"], "probe/ready");
        std::fs::remove_dir_all(output).unwrap();
    }
}