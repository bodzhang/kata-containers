//! # Initdata Module
//!
//! This module will do the following things if a proper initdata device with initdata exists.
//! 1. Parse the initdata block device and extract the config files to [`INITDATA_PATH`].
//! 2. Return the initdata and the policy (if any).

// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//#[cfg(feature = "init-data")]
//use std::{os::unix::fs::FileTypeExt, path::Path};

use anyhow::{bail, Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use base64::{engine::general_purpose::STANDARD, Engine};
use const_format::concatcp;
use kata_types::initdata::InitData;
use sha2::{Digest, Sha256, Sha384, Sha512};
use slog::Logger;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// This is the target directory to store the extracted initdata.
pub const INITDATA_PATH: &str = "/run/confidential-containers/initdata";

const AA_CONFIG_KEY: &str = "aa.toml";
const CDH_CONFIG_KEY: &str = "cdh.toml";
const POLICY_KEY: &str = "policy.rego";

/// The path of initdata toml
pub const INITDATA_TOML_PATH: &str = concatcp!(INITDATA_PATH, "/initdata.toml");

/// The path of AA's config file
pub const AA_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/aa.toml");

/// The path of CDH's config file
pub const CDH_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/cdh.toml");

/// Magic number of initdata device
// #[cfg(feature = "init-data")]
// pub const INITDATA_MAGIC_NUMBER: &[u8] = b"initdata";

/// initdata device with disk type 'vd*'
// #[cfg(feature = "init-data")]
// const INITDATA_PREFIX_DISK_VDX: &str = "vd";

/// initdata device with disk type 'sd*'
// #[cfg(feature = "init-data")]
// const INITDATA_PREFIX_DISK_SDX: &str = "sd";

#[cfg(not(feature = "init-data"))]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    debug!(logger, "Initdata is disabled");
    Ok(None)
}

#[cfg(feature = "init-data")]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    debug!(logger, "detect_initdata_device: disabled");
    /*
    let dev_dir = Path::new("/dev");
    let mut read_dir = tokio::fs::read_dir(dev_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        debug!(logger, "Initdata check device `{filename}`");

        // Currently there're two disk types supported:
        // virtio-blk (vd*) and virtio-scsi (sd*)
        if !filename.starts_with(INITDATA_PREFIX_DISK_VDX)
            && !filename.starts_with(INITDATA_PREFIX_DISK_SDX)
        {
            continue;
        }

        let path = entry.path();

        debug!(logger, "Initdata find potential device: `{path:?}`");
        let metadata = std::fs::metadata(path.clone())?;
        if !metadata.file_type().is_block_device() {
            continue;
        }

        let mut file = tokio::fs::File::open(&path).await?;
        let mut magic = [0; 8];
        match file.read_exact(&mut magic).await {
            Ok(_) => {
                debug!(
                    logger,
                    "Initdata read device `{filename}` first 8 bytes: {magic:?}"
                );
                if magic == INITDATA_MAGIC_NUMBER {
                    let path = path.as_path().to_string_lossy().to_string();
                    debug!(logger, "Found initdata device {path}");
                    return Ok(Some(path));
                }
            }
            Err(e) => debug!(logger, "Initdata read device `{filename}` failed: {e:?}"),
        }
    }
    */

    Ok(None)
}

pub async fn read_initdata(device_path: &str) -> Result<Vec<u8>> {
    let initdata_devfile = tokio::fs::File::open(device_path).await?;
    let mut buf_reader = tokio::io::BufReader::new(initdata_devfile);
    // skip the magic number "initdata"
    buf_reader.seek(std::io::SeekFrom::Start(8)).await?;

    let mut len_buf = [0u8; 8];
    buf_reader.read_exact(&mut len_buf).await?;
    let length = u64::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0; length];
    buf_reader.read_exact(&mut buf).await?;
    let mut gzip_decoder = GzipDecoder::new(&buf[..]);

    let mut initdata = Vec::new();
    let _ = gzip_decoder.read_to_end(&mut initdata).await?;
    Ok(initdata)
}

pub struct InitdataReturnValue {
    pub _digest: Vec<u8>,
    pub _policy: Option<String>,
}

pub async fn initialize_initdata(logger: &Logger) -> Result<Option<InitdataReturnValue>> {
    let logger = logger.new(o!("subsystem" => "initdata"));
    let Some(initdata_device) = detect_initdata_device(&logger).await? else {
        info!(
            logger,
            "Initdata device not found, skip initdata initialization"
        );
        return Ok(None);
    };

    tokio::fs::create_dir_all(INITDATA_PATH)
        .await
        .inspect_err(|e| error!(logger, "Failed to create initdata dir: {e:?}"))?;

    let initdata_content = read_initdata(&initdata_device)
        .await
        .inspect_err(|e| error!(logger, "Failed to read initdata: {e:?}"))?;

    let initdata: InitData =
        toml::from_slice(&initdata_content).context("parse initdata failed")?;
    info!(logger, "Initdata version: {}", initdata.version());
    initdata.validate()?;

    tokio::fs::write(INITDATA_TOML_PATH, &initdata_content)
        .await
        .context("write initdata toml failed")?;

    let _digest = match initdata.algorithm() {
        "sha256" => Sha256::digest(&initdata_content).to_vec(),
        "sha384" => Sha384::digest(&initdata_content).to_vec(),
        "sha512" => Sha512::digest(&initdata_content).to_vec(),
        others => bail!("Unsupported hash algorithm {others}"),
    };

    if let Some(config) = initdata.get_coco_data(AA_CONFIG_KEY) {
        tokio::fs::write(AA_CONFIG_PATH, config)
            .await
            .context("write aa config failed")?;
        info!(logger, "write AA config from initdata");
    }

    if let Some(config) = initdata.get_coco_data(CDH_CONFIG_KEY) {
        tokio::fs::write(CDH_CONFIG_PATH, config)
            .await
            .context("write cdh config failed")?;
        info!(logger, "write CDH config from initdata");
    }

    debug!(logger, "Initdata digest: {}", STANDARD.encode(&_digest));

    let res = InitdataReturnValue {
        _digest,
        _policy: initdata.get_coco_data(POLICY_KEY).cloned(),
    };

    // Boot-time initdata->launch binding gate.
    //
    // The initdata blob (policy.rego, aa.toml, cdh.toml) is supplied by the
    // untrusted host. Its integrity is guaranteed only by the TEE launch
    // measurement: the host must program the initdata digest into a launch-bound
    // register that the hardware authenticates into every signed attestation
    // report -- SEV-SNP `HOST_DATA` (32 bytes), TDX `MRCONFIGID` (48 bytes), or
    // Arm CCA Realm Personalization Value (64 bytes). Nothing else ties this
    // host-supplied blob to the measured guest.
    //
    // We MUST verify that binding here -- inside the launch-measured agent,
    // synchronously, against a live hardware report -- BEFORE any
    // initdata-provided policy or config is consumed and potentially used to
    // admit containers. The binding must NOT be delegated to the in-UVM
    // attestation-agent, because that creates a time-of-check/time-of-use race:
    // if the policy binding is not yet verified but the policy is already used
    // to admit containers, a malicious privileged container admitted by that
    // unbound policy could tamper with the AA -- its binary/config, or the
    // initdata file it reads -- so that the AA's later binding check still
    // passes. Attestation would then report an acceptable, bound policy while
    // the malicious unbound policy is what actually admitted containers. The
    // binding check must therefore complete in launch-measured code before any
    // container can be admitted.
    //
    // Fails closed: any mismatch, or inability to obtain the report, aborts
    // initdata initialization so the host-supplied policy is never enforced.
    #[cfg(feature = "init-data")]
    verify_initdata_binding(&logger, &res._digest)
        .await
        .context("verify initdata launch binding")?;

    Ok(Some(res))
}

/// Verify that the launch measurement binds the initdata this agent has read,
/// failing closed otherwise.
///
/// `digest` is the raw (pre-adjustment) initdata digest computed in
/// [`initialize_initdata`]. The comparison is delegated to the guest-components
/// `attester` crate -- the exact code the attestation-agent is built from -- but
/// it runs *in-process* inside the launch-measured kata-agent, NOT in the
/// separate AA daemon. The attester detects the TEE and compares the digest
/// against the platform's launch-bound register:
/// - SEV-SNP: `HOST_DATA` (digest truncated/zero-padded to 32 bytes),
/// - TDX: `MRCONFIGID` (digest truncated/zero-padded to 48 bytes).
///
/// Arm CCA is detected but its binding anchor (the Realm Personalization Value,
/// 64 bytes) is not yet checkable because upstream `CcaAttester` does not
/// implement `bind_init_data`; a detected CCA platform is therefore treated as a
/// temporary, CCA-specific fail-closed refusal until that lands upstream.
#[cfg(all(feature = "init-data", any(target_arch = "x86_64", target_arch = "aarch64")))]
async fn verify_initdata_binding(logger: &Logger, digest: &[u8]) -> Result<()> {
    use attester::{detect_tee_type, BoxedAttester, InitDataResult};
    use std::convert::TryFrom;

    let logger = logger.new(o!("subsystem" => "initdata", "check" => "launch-binding"));

    let tee = detect_tee_type();
    let tee_dbg = format!("{tee:?}");
    let attester =
        BoxedAttester::try_from(tee).context("construct attester for detected TEE")?;

    match attester
        .bind_init_data(digest)
        .await
        .context("bind initdata to TEE launch measurement")?
    {
        InitDataResult::Ok => {
            info!(logger, "initdata launch binding verified"; "tee" => tee_dbg);
            Ok(())
        }
        // No launch-bound register to check (e.g. no TEE detected, or a platform
        // whose attester does not implement init-data binding). We cannot
        // establish the binding, so refuse the host-supplied initdata.
        InitDataResult::Unsupported => {
            // TEMP(cca): upstream `CcaAttester` does not implement
            // `bind_init_data` yet, so a genuine Arm CCA platform also lands here
            // (via the trait default) rather than binding the digest to the CCA
            // Realm Personalization Value. Distinguish it so the failure is
            // actionable. This branch should be removed once guest-components
            // implements `CcaAttester::bind_init_data` (RPV, 64 bytes); CCA will
            // then resolve to `Ok`/mismatch like SNP/TDX.
            if tee_dbg == "Cca" {
                error!(
                    logger,
                    "initdata launch binding not yet implemented for CCA";
                    "tee" => tee_dbg,
                );
                bail!(
                    "initdata launch binding not yet implemented for Arm CCA \
                     (upstream CcaAttester lacks bind_init_data / RPV support); \
                     refusing host-supplied initdata (fail closed)"
                )
            }
            error!(
                logger,
                "initdata launch binding unsupported for detected TEE";
                "tee" => tee_dbg,
            );
            bail!(
                "initdata launch binding unsupported for detected TEE; \
                 refusing host-supplied initdata (fail closed)"
            )
        }
    }
}

/// On architectures without a supported TEE attester the SEV-SNP / TDX / CCA
/// binding cannot be performed. Since initdata integrity depends on that
/// binding, refuse host-supplied initdata rather than consume it unverified.
#[cfg(all(feature = "init-data", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
async fn verify_initdata_binding(_logger: &Logger, _digest: &[u8]) -> Result<()> {
    bail!(
        "initdata launch binding is not supported on this architecture; \
         refusing host-supplied initdata (fail closed)"
    )
}

#[cfg(test)]
mod tests {
    use crate::initdata::read_initdata;

    const INITDATA_IMG_PATH: &str = "testdata/initdata.img";
    const INITDATA_PLAINTEXT: &[u8] = b"some content";

    #[tokio::test]
    async fn parse_initdata() {
        let initdata = read_initdata(INITDATA_IMG_PATH).await.unwrap();
        assert_eq!(initdata, INITDATA_PLAINTEXT);
    }
}
