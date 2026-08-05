use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent::Agent;
use anyhow::{anyhow, Context, Result};
use common::message::Message;
use common::{RuntimeInstance, Sandbox};
use containerd_shim_protos::api;
use hypervisor::Hypervisor;
use kata_createreq_capture::{
    stage_direct_volume_mounts, CaptureSandbox, DryRunHypervisor, RecordingAgent,
};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use kata_types::config::TomlConfig;
use kata_types::mount::KATA_IMAGE_FORCE_GUEST_PULL;
use oci_spec::runtime as oci;
use resource::cpu_mem::initial_size::InitialSizeManager;
use resource::ResourceManager;
use runtimes::RuntimeHandlerManager;
use service::ServiceManager;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::channel;
use virt_container::VirtContainerManager;

const MESSAGE_BUFFER_SIZE: usize = 8;
const CAPTURE_CONFIG_ENV: &str = "GENPOLICY_KATA_CONFIG";
const DIRECT_VOLUME_MOUNTS_ENV: &str = "GENPOLICY_DIRECT_VOLUME_MOUNTS";
const CAPTURE_OUTPUT_ENV: &str = "GENPOLICY_CAPTURE_OUTPUT";
const SERVER_FD_ENV: &str = "KATA_RUNTIME_BIND_FD";
const SOCKET_ROOT: &str = "/run/containerd";

#[derive(Clone, Debug, Default)]
struct Args {
    id: String,
    namespace: String,
    address: String,
    publish_binary: String,
    bundle: String,
    debug: bool,
}

impl Args {
    fn validate(&self, require_bundle: bool) -> Result<()> {
        if self.id.is_empty() || self.namespace.is_empty() || self.publish_binary.is_empty() {
            return Err(anyhow!("id, namespace, and publish-binary are required"));
        }
        if require_bundle && self.bundle.is_empty() {
            return Err(anyhow!("bundle is required"));
        }
        Ok(())
    }
}

enum Action {
    Run(Args),
    Start(Args),
    Delete(Args),
    Help,
    Version,
}

fn parse_args(arguments: &[OsString]) -> Result<Action> {
    let mut help = false;
    let mut version = false;
    let mut args = Args::default();
    let rest = go_flag::parse_args_with_warnings::<String, _, _>(
        &arguments[1..],
        None,
        |flags| {
            flags.add_flag("address", &mut args.address);
            flags.add_flag("bundle", &mut args.bundle);
            flags.add_flag("debug", &mut args.debug);
            flags.add_flag("id", &mut args.id);
            flags.add_flag("namespace", &mut args.namespace);
            flags.add_flag("publish-binary", &mut args.publish_binary);
            flags.add_flag("help", &mut help);
            flags.add_flag("version", &mut version);
        },
    )?;

    if help {
        Ok(Action::Help)
    } else if version {
        Ok(Action::Version)
    } else if rest.is_empty() {
        Ok(Action::Run(args))
    } else if rest[0] == "start" {
        Ok(Action::Start(args))
    } else if rest[0] == "delete" {
        Ok(Action::Delete(args))
    } else {
        Err(anyhow!("unsupported shim action {}", rest[0]))
    }
}

fn resolve_hypervisor_config(config: &TomlConfig) -> HypervisorConfig {
    config
        .hypervisor
        .get(&config.runtime.hypervisor_name)
        .cloned()
        .unwrap_or_default()
}

fn socket_address(args: &Args, id: &str) -> Result<PathBuf> {
    if id.is_empty() {
        return Err(anyhow!("sandbox id is empty"));
    }
    let mut hasher = Sha256::new();
    hasher.update([&args.address, &args.namespace, id].join("/"));
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    Ok(PathBuf::from(format!(
        "unix://{SOCKET_ROOT}/s/{digest}"
    )))
}

fn socket_file(address: &Path) -> Result<PathBuf> {
    let path = address
        .strip_prefix("unix:")
        .context("strip shim socket scheme")?;
    Ok(Path::new("/").join(path))
}

fn write_bundle_file(name: &str, value: &OsStr) -> Result<()> {
    std::fs::write(name, value.as_bytes()).with_context(|| format!("write {name}"))
}

fn clear_close_on_exec(fd: RawFd) -> Result<()> {
    // SAFETY: fd is owned by the listener for the duration of both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("read listener fd flags");
    }
    // SAFETY: F_SETFD updates flags on the same valid listener descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("clear listener close-on-exec");
    }
    Ok(())
}

fn start_shim(args: Args) -> Result<()> {
    args.validate(false)?;
    let spec = oci::Spec::load("config.json").context("load start OCI config")?;
    let (container_type, sandbox_id) = kata_types::k8s::container_type_with_id(&spec);
    let address = match container_type {
        kata_types::container::ContainerType::PodContainer => {
            socket_address(&args, sandbox_id.as_deref().context("pod container has no sandbox id")?)?
        }
        _ => {
            let address = socket_address(&args, &args.id)?;
            let socket_path = socket_file(&address)?;
            if let Some(parent) = socket_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let listener = UnixListener::bind(&socket_path)
                .with_context(|| format!("bind capture shim socket {}", socket_path.display()))?;
            clear_close_on_exec(listener.as_raw_fd())?;
            let current_exe = std::env::current_exe()?;
            let child = std::process::Command::new(current_exe)
                .current_dir(std::env::current_dir()?)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .arg("-id")
                .arg(&args.id)
                .arg("-namespace")
                .arg(&args.namespace)
                .arg("-address")
                .arg(&args.address)
                .arg("-publish-binary")
                .arg(&args.publish_binary)
                .env(SERVER_FD_ENV, listener.into_raw_fd().to_string())
                .spawn()
                .context("spawn capture shim")?;
            write_bundle_file("shim.pid", OsStr::new(&child.id().to_string()))?;
            address
        }
    };
    write_bundle_file("address", address.as_os_str())?;
    std::io::stdout().write_all(address.as_os_str().as_bytes())?;
    Ok(())
}

fn delete_shim(args: Args) -> Result<()> {
    args.validate(true)?;
    let address = socket_address(&args, &args.id)?;
    std::fs::remove_file(socket_file(&address)?).ok();
    let mut response = api::DeleteResponse::new();
    response.set_exit_status(0);
    let mut exited_at = protobuf::well_known_types::timestamp::Timestamp::new();
    exited_at.seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    response.set_exited_at(exited_at);
    protobuf::Message::write_to_writer(&response, &mut std::io::stdout())?;
    Ok(())
}

async fn run_capture_shim(args: Args) -> Result<()> {
    args.validate(false)?;
    let server_fd = std::env::var(SERVER_FD_ENV)
        .context("read inherited containerd shim server fd")?
        .parse::<RawFd>()
        .context("parse inherited containerd shim server fd")?;
    let config_path = std::env::var(CAPTURE_CONFIG_ENV)
        .with_context(|| format!("{CAPTURE_CONFIG_ENV} must name the Kata configuration"))?;
    let output_dir = PathBuf::from(
        std::env::var(CAPTURE_OUTPUT_ENV).unwrap_or_else(|_| "/output".to_string()),
    );
    let spec = oci::Spec::load("config.json").context("load sandbox OCI config.json")?;
    let (mut config, _) = TomlConfig::load_raw_from_file(&config_path)
        .with_context(|| format!("load capture Kata configuration {config_path}"))?;
    if let Some(path) = std::env::var_os(DIRECT_VOLUME_MOUNTS_ENV) {
        stage_direct_volume_mounts(Path::new(&path)).with_context(|| {
            format!("stage {DIRECT_VOLUME_MOUNTS_ENV} {}", Path::new(&path).display())
        })?;
    }
    if !config
        .runtime
        .experimental
        .iter()
        .any(|feature| feature == KATA_IMAGE_FORCE_GUEST_PULL)
    {
        config
            .runtime
            .experimental
            .push(KATA_IMAGE_FORCE_GUEST_PULL.to_string());
    }
    config.runtime.static_sandbox_resource_mgmt = true;
    let hypervisor_config = resolve_hypervisor_config(&config);
    let config = Arc::new(config);

    let agent: Arc<dyn Agent> = Arc::new(RecordingAgent::to_directory(output_dir)?);
    let hypervisor: Arc<dyn Hypervisor> =
        Arc::new(DryRunHypervisor::new(hypervisor_config));
    let initial_size_manager =
        InitialSizeManager::new(&spec).context("construct capture InitialSizeManager")?;
    let resource_manager = Arc::new(
        ResourceManager::new(
            &args.id,
            agent.clone(),
            hypervisor.clone(),
            config,
            initial_size_manager,
        )
        .await
        .context("construct capture ResourceManager")?,
    );

    let (message_sender, message_receiver) = channel::<Message>(MESSAGE_BUFFER_SIZE);
    let sandbox: Arc<dyn Sandbox> = Arc::new(CaptureSandbox::new(
        args.id.clone(),
        message_sender.clone(),
    ));
    let container_manager = Arc::new(VirtContainerManager::new(
        &args.id,
        std::process::id(),
        agent,
        hypervisor,
        resource_manager,
    ));
    let runtime_instance = RuntimeInstance {
        sandbox,
        container_manager,
    };
    let runtime_manager = Arc::new(RuntimeHandlerManager::new_with_runtime_instance(
        &args.id,
        message_sender,
        Some(runtime_instance),
    )?);
    let service_manager = ServiceManager::new_with_runtime_handler(
        &args.publish_binary,
        &args.address,
        &args.namespace,
        server_fd,
        runtime_manager,
        message_receiver,
    )
    .await?;
    service_manager.run().await
}

fn main() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("prepare capture shim runtime")?;

    match parse_args(&arguments)? {
        Action::Run(args) => runtime.block_on(run_capture_shim(args)),
        Action::Start(args) => start_shim(args),
        Action::Delete(args) => delete_shim(args),
        Action::Help => {
            println!("containerd-shim-kata-capture-v2 [start|delete]");
            Ok(())
        }
        Action::Version => {
            println!("containerd-shim-kata-capture-v2 0.1.0");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_survives_exec() {
        let path = std::env::temp_dir().join(format!(
            "kata-capture-shim-listener-test-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let fd = listener.as_raw_fd();

        clear_close_on_exec(fd).unwrap();

        // SAFETY: fd remains owned by listener for this query.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
        std::fs::remove_file(path).unwrap();
    }
}