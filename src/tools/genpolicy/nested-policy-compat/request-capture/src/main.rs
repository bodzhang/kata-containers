// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use protobuf::reflect::{FileDescriptor, MessageRef, ReflectFieldRef, ReflectValueRef};
use protobuf::Message;
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;
const TTRPC_HEADER_LENGTH: usize = 10;
const TTRPC_REQUEST: u8 = 1;
const TTRPC_MAX_MESSAGE_LENGTH: usize = 4 << 20;
const AGENT_TTRPC_PORT: u32 = 1024;

#[derive(Debug)]
struct Args {
    input: PathBuf,
    output: PathBuf,
}

#[derive(Default)]
struct Summary {
    connections: u64,
    frames: u64,
    requests: u64,
    decoded_requests: u64,
    unsupported_requests: u64,
    requests_with_unknown_fields: u64,
    malformed_requests: u64,
    non_request_frames: u64,
    skipped_connections: u64,
    truncated_connections: u64,
    failed_connections: u64,
}

fn parse_args() -> Result<Args> {
    let mut args = env::args_os().skip(1);
    let mut input = None;
    let mut output = None;

    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--input") => input = args.next().map(PathBuf::from),
            Some("--output") => output = args.next().map(PathBuf::from),
            Some("-h" | "--help") => {
                println!("usage: agent-request-capture --input AGENT_RPCS --output DIRECTORY");
                std::process::exit(0);
            }
            _ => bail!("unknown argument: {}", argument.to_string_lossy()),
        }
    }

    Ok(Args {
        input: input.context("--input is required")?,
        output: output.context("--output is required")?,
    })
}

fn service_registry() -> BTreeMap<(String, String), protobuf::reflect::MessageDescriptor> {
    let descriptors = [
        protocols::agent::file_descriptor(),
        protocols::health::file_descriptor(),
        protocols::remote::file_descriptor(),
        protocols::confidential_data_hub::file_descriptor(),
    ];
    let mut registry = BTreeMap::new();

    for file in descriptors {
        register_file(file, &mut registry);
    }
    registry
}

fn register_file(
    file: &FileDescriptor,
    registry: &mut BTreeMap<(String, String), protobuf::reflect::MessageDescriptor>,
) {
    for service in file.services() {
        let service_name = if file.package().is_empty() {
            service.proto().name().to_owned()
        } else {
            format!("{}.{}", file.package(), service.proto().name())
        };
        for method in service.methods() {
            registry.insert(
                (service_name.clone(), method.proto().name().to_owned()),
                method.input_type(),
            );
        }
    }
}

fn value_to_json(value: ReflectValueRef<'_>) -> (Value, bool) {
    match value {
        ReflectValueRef::U32(value) => (Value::Number(value.into()), false),
        ReflectValueRef::U64(value) => (Value::String(value.to_string()), false),
        ReflectValueRef::I32(value) => (Value::Number(value.into()), false),
        ReflectValueRef::I64(value) => (Value::String(value.to_string()), false),
        ReflectValueRef::F32(value) => Number::from_f64(value.into())
            .map(Value::Number)
            .map(|value| (value, false))
            .unwrap_or_else(|| (Value::String(value.to_string()), false)),
        ReflectValueRef::F64(value) => Number::from_f64(value)
            .map(Value::Number)
            .map(|value| (value, false))
            .unwrap_or_else(|| (Value::String(value.to_string()), false)),
        ReflectValueRef::Bool(value) => (Value::Bool(value), false),
        ReflectValueRef::String(value) => (Value::String(value.to_owned()), false),
        ReflectValueRef::Bytes(value) => (Value::String(BASE64.encode(value)), false),
        ReflectValueRef::Enum(descriptor, number) => descriptor
            .value_by_number(number)
            .map(|value| (Value::String(value.name().to_owned()), false))
            .unwrap_or_else(|| (Value::Number(number.into()), true)),
        ReflectValueRef::Message(message) => message_to_json(message),
    }
}

fn map_key(value: ReflectValueRef<'_>) -> String {
    match value {
        ReflectValueRef::String(value) => value.to_owned(),
        ReflectValueRef::Bool(value) => value.to_string(),
        ReflectValueRef::U32(value) => value.to_string(),
        ReflectValueRef::U64(value) => value.to_string(),
        ReflectValueRef::I32(value) => value.to_string(),
        ReflectValueRef::I64(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn message_to_json(message: MessageRef<'_>) -> (Value, bool) {
    let descriptor = message.descriptor_dyn();
    let mut object = Map::new();
    let mut has_unknown_fields = message
        .special_fields_dyn()
        .unknown_fields()
        .iter()
        .next()
        .is_some();

    for field in descriptor.fields() {
        match field.get_reflect(&*message) {
            ReflectFieldRef::Optional(value) => {
                if let Some(value) = value.value() {
                    let (value, nested_unknown_fields) = value_to_json(value);
                    has_unknown_fields |= nested_unknown_fields;
                    object.insert(field.name().to_owned(), value);
                }
            }
            ReflectFieldRef::Repeated(values) => {
                if !values.is_empty() {
                    let mut items = Vec::with_capacity(values.len());
                    for value in &values {
                        let (value, nested_unknown_fields) = value_to_json(value);
                        has_unknown_fields |= nested_unknown_fields;
                        items.push(value);
                    }
                    object.insert(field.name().to_owned(), Value::Array(items));
                }
            }
            ReflectFieldRef::Map(values) => {
                if !values.is_empty() {
                    let mut sorted = BTreeMap::new();
                    for (key, value) in &values {
                        let (value, nested_unknown_fields) = value_to_json(value);
                        has_unknown_fields |= nested_unknown_fields;
                        sorted.insert(map_key(key), value);
                    }
                    object.insert(
                        field.name().to_owned(),
                        Value::Object(sorted.into_iter().collect()),
                    );
                }
            }
        }
    }

    (Value::Object(object), has_unknown_fields)
}

fn split_handshake(data: &[u8]) -> Result<(Option<String>, Option<u32>, usize)> {
    if data.len() < b"connect ".len()
        || !data[..b"connect ".len()].eq_ignore_ascii_case(b"connect ")
    {
        return Ok((None, None, 0));
    }
    let newline = data
        .iter()
        .position(|byte| *byte == b'\n')
        .context("truncated hybrid-vsock CONNECT handshake")?;
    let line = std::str::from_utf8(&data[..newline])
        .context("hybrid-vsock CONNECT handshake is not UTF-8")?;
    let port = &line[b"connect ".len()..];
    let port = port
        .parse::<u32>()
        .with_context(|| format!("invalid hybrid-vsock CONNECT port: {port}"))?;
    Ok((Some(line.to_owned()), Some(port), newline + 1))
}

fn decode_connection(
    connection_dir: &Path,
    requests: &mut BufWriter<File>,
    registry: &BTreeMap<(String, String), protobuf::reflect::MessageDescriptor>,
    summary: &mut Summary,
) -> Result<Value> {
    let connection = connection_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("connection directory name is not UTF-8")?;
    let stream_path = connection_dir.join("shim-to-agent.bin");
    let metadata_path = connection_dir.join("metadata.json");
    let connection_metadata: Value = serde_json::from_slice(
        &fs::read(&metadata_path).with_context(|| format!("read {}", metadata_path.display()))?,
    )
    .with_context(|| format!("parse {}", metadata_path.display()))?;
    let started_unix_ns = connection_metadata
        .get("started_unix_ns")
        .and_then(Value::as_u64)
        .context("connection metadata has no numeric started_unix_ns")?;
    let data = fs::read(&stream_path).with_context(|| format!("read {}", stream_path.display()))?;
    let digest = format!("{:x}", Sha256::digest(&data));
    let (handshake, port, mut offset) = split_handshake(&data)?;
    let frame_start = offset;
    let mut frame_index = 0u64;
    let mut connection_requests = 0u64;
    let mut connection_decoded = 0u64;
    let mut connection_unsupported = 0u64;
    let mut connection_unknown_fields = 0u64;
    let mut connection_malformed = 0u64;
    let mut connection_non_request = 0u64;
    let mut truncated_tail = None;

    if port.is_some_and(|port| port != AGENT_TTRPC_PORT) {
        summary.connections += 1;
        summary.skipped_connections += 1;
        return Ok(json!({
            "connection": connection,
            "started_unix_ns": started_unix_ns,
            "finished_unix_ns": connection_metadata.get("finished_unix_ns"),
            "socket": connection_metadata.get("socket"),
            "source": stream_path.file_name().unwrap().to_string_lossy(),
            "sha256": digest,
            "bytes": data.len(),
            "handshake": handshake,
            "port": port,
            "decode_status": "skipped-non-agent-port",
            "frames": 0,
            "requests": 0,
            "decoded_requests": 0,
            "unsupported_requests": 0,
            "requests_with_unknown_fields": 0,
            "malformed_requests": 0,
            "non_request_frames": 0,
            "truncated_tail": null,
        }));
    }

    while offset < data.len() {
        if data.len() - offset < TTRPC_HEADER_LENGTH {
            truncated_tail = Some(json!({
                "byte_offset": offset,
                "expected": TTRPC_HEADER_LENGTH,
                "found": data.len() - offset,
                "part": "header",
            }));
            summary.truncated_connections += 1;
            break;
        }
        let header_offset = offset;
        let length = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let stream_id = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        let message_type = data[offset + 8];
        let flags = data[offset + 9];
        offset += TTRPC_HEADER_LENGTH;
        if length > TTRPC_MAX_MESSAGE_LENGTH {
            truncated_tail = Some(json!({
                "byte_offset": header_offset,
                "declared_length": length,
                "maximum_length": TTRPC_MAX_MESSAGE_LENGTH,
                "part": "oversized-frame",
            }));
            summary.truncated_connections += 1;
            break;
        }
        let payload_end = offset
            .checked_add(length)
            .context("ttRPC frame length overflow")?;
        if payload_end > data.len() {
            truncated_tail = Some(json!({
                "byte_offset": header_offset,
                "expected": length,
                "found": data.len() - offset,
                "part": "payload",
            }));
            summary.truncated_connections += 1;
            break;
        }
        let payload = &data[offset..payload_end];
        offset = payload_end;
        frame_index += 1;
        summary.frames += 1;

        if message_type != TTRPC_REQUEST {
            connection_non_request += 1;
            summary.non_request_frames += 1;
            continue;
        }

        connection_requests += 1;
        summary.requests += 1;
        let request = match ttrpc::Request::parse_from_bytes(payload) {
            Ok(request) => request,
            Err(error) => {
                connection_malformed += 1;
                summary.malformed_requests += 1;
                let record = json!({
                    "schema_version": SCHEMA_VERSION,
                    "connection": connection,
                    "connection_started_unix_ns": started_unix_ns,
                    "frame_index": frame_index,
                    "byte_offset": header_offset,
                    "stream_id": stream_id,
                    "flags": flags,
                    "decode_status": "malformed-envelope",
                    "decode_error": error.to_string(),
                    "undecoded_payload_base64": BASE64.encode(payload),
                });
                serde_json::to_writer(&mut *requests, &record)?;
                requests.write_all(b"\n")?;
                continue;
            }
        };

        let key = (request.service.clone(), request.method.clone());
        let (decode_status, request_type, decoded, has_unknown_fields, undecoded_payload) =
            if let Some(descriptor) = registry.get(&key) {
                match descriptor.parse_from_bytes(&request.payload) {
                    Ok(message) => {
                        let (decoded, has_unknown_fields) = message_to_json((&*message).into());
                        connection_decoded += 1;
                        summary.decoded_requests += 1;
                        if has_unknown_fields {
                            connection_unknown_fields += 1;
                            summary.requests_with_unknown_fields += 1;
                        }
                        (
                            if has_unknown_fields {
                                "decoded-with-unknown-fields"
                            } else {
                                "decoded"
                            },
                            Some(descriptor.full_name()),
                            Some(decoded),
                            has_unknown_fields,
                            has_unknown_fields.then(|| BASE64.encode(&request.payload)),
                        )
                    }
                    Err(error) => {
                        connection_malformed += 1;
                        summary.malformed_requests += 1;
                        (
                            "malformed-known-payload",
                            Some(descriptor.full_name()),
                            Some(json!({"decode_error": error.to_string()})),
                            false,
                            Some(BASE64.encode(&request.payload)),
                        )
                    }
                }
            } else {
                connection_unsupported += 1;
                summary.unsupported_requests += 1;
                (
                    "unsupported",
                    None,
                    None,
                    false,
                    Some(BASE64.encode(&request.payload)),
                )
            };

        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "connection": connection,
            "connection_started_unix_ns": started_unix_ns,
            "frame_index": frame_index,
            "byte_offset": header_offset,
            "stream_id": stream_id,
            "flags": flags,
            "service": request.service,
            "method": request.method,
            "timeout_nano": request.timeout_nano.to_string(),
            "metadata": request.metadata.into_iter().map(|item| {
                json!({"key": item.key, "value": item.value})
            }).collect::<Vec<_>>(),
            "decode_status": decode_status,
            "request_type": request_type,
            "request": decoded,
            "has_unknown_fields": has_unknown_fields,
            "undecoded_payload_base64": undecoded_payload,
        });
        serde_json::to_writer(&mut *requests, &record)?;
        requests.write_all(b"\n")?;
    }

    summary.connections += 1;
    Ok(json!({
        "connection": connection,
        "started_unix_ns": started_unix_ns,
        "finished_unix_ns": connection_metadata.get("finished_unix_ns"),
        "socket": connection_metadata.get("socket"),
        "source": stream_path.file_name().unwrap().to_string_lossy(),
        "sha256": digest,
        "bytes": data.len(),
        "handshake": handshake,
        "port": port,
        "decode_status": "decoded",
        "ttrpc_offset": frame_start,
        "frames": frame_index,
        "requests": connection_requests,
        "decoded_requests": connection_decoded,
        "unsupported_requests": connection_unsupported,
        "requests_with_unknown_fields": connection_unknown_fields,
        "malformed_requests": connection_malformed,
        "non_request_frames": connection_non_request,
        "truncated_tail": truncated_tail,
    }))
}

fn create_private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn run(args: Args) -> Result<()> {
    if !args.input.is_dir() {
        bail!(
            "capture input directory not found: {}",
            args.input.display()
        );
    }
    fs::create_dir_all(&args.output)
        .with_context(|| format!("create {}", args.output.display()))?;
    fs::set_permissions(&args.output, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod {}", args.output.display()))?;

    let requests_path = args.output.join("requests.jsonl");
    let manifest_path = args.output.join("manifest.json");
    let requests_tmp = args.output.join(".requests.jsonl.tmp");
    let manifest_tmp = args.output.join(".manifest.json.tmp");
    for path in [&requests_path, &manifest_path, &requests_tmp, &manifest_tmp] {
        if path.exists() {
            fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
        }
    }

    let result = (|| -> Result<()> {
        let state_path = args.input.join("state.json");
        let capture_state: Value = serde_json::from_slice(
            &fs::read(&state_path).with_context(|| format!("read {}", state_path.display()))?,
        )
        .with_context(|| format!("parse {}", state_path.display()))?;
        let capture_has_errors = !capture_state
            .get("errors")
            .and_then(Value::as_array)
            .context("capture state has no errors array")?
            .is_empty();
        let expected_connections = capture_state
            .get("connections")
            .and_then(Value::as_u64)
            .context("capture state has no numeric connections count")?;

        let registry = service_registry();
        let mut directories = Vec::new();
        for entry in
            fs::read_dir(&args.input).with_context(|| format!("read {}", args.input.display()))?
        {
            let path = entry
                .with_context(|| format!("read entry in {}", args.input.display()))?
                .path();
            if path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            {
                directories.push(path);
            }
        }
        directories.sort();
        let connection_count_matches = directories.len() as u64 == expected_connections;

        let mut requests = BufWriter::new(create_private_file(&requests_tmp)?);
        let mut summary = Summary::default();
        let mut connections = Vec::new();
        for directory in directories {
            match decode_connection(&directory, &mut requests, &registry, &mut summary) {
                Ok(connection) => connections.push(connection),
                Err(error) => {
                    summary.connections += 1;
                    summary.failed_connections += 1;
                    connections.push(json!({
                        "connection": directory.file_name().map(|name| name.to_string_lossy()),
                        "decode_status": "connection-error",
                        "error": error.to_string(),
                    }));
                }
            }
        }
        requests.flush()?;
        if summary.connections == 0 {
            bail!(
                "no captured connection directories found in {}",
                args.input.display()
            );
        }
        if summary.requests == 0 {
            bail!("captured streams contain no ttRPC requests");
        }

        let manifest = json!({
            "schema_version": SCHEMA_VERSION,
            "source": args.input,
            "raw_capture_authoritative": true,
            "analysis_only": true,
            "typed_decode_complete": summary.unsupported_requests == 0
                && summary.requests_with_unknown_fields == 0
                && summary.malformed_requests == 0
                && summary.truncated_connections == 0
                && summary.failed_connections == 0
                && !capture_has_errors
                && connection_count_matches,
            "capture_complete": summary.truncated_connections == 0
                && summary.failed_connections == 0
                && !capture_has_errors
                && connection_count_matches,
            "connection_count_matches": connection_count_matches,
            "capture_state": capture_state,
            "connections": connections,
            "summary": {
                "connections": summary.connections,
                "frames": summary.frames,
                "requests": summary.requests,
                "decoded_requests": summary.decoded_requests,
                "unsupported_requests": summary.unsupported_requests,
                "requests_with_unknown_fields": summary.requests_with_unknown_fields,
                "malformed_requests": summary.malformed_requests,
                "non_request_frames": summary.non_request_frames,
                "skipped_connections": summary.skipped_connections,
                "truncated_connections": summary.truncated_connections,
                "failed_connections": summary.failed_connections,
            },
        });
        let mut manifest_file = BufWriter::new(create_private_file(&manifest_tmp)?);
        serde_json::to_writer_pretty(&mut manifest_file, &manifest)?;
        manifest_file.write_all(b"\n")?;
        manifest_file.flush()?;

        fs::rename(&requests_tmp, &requests_path)?;
        fs::rename(&manifest_tmp, &manifest_path)?;
        Ok(())
    })();

    if result.is_err() {
        for path in [&requests_path, &manifest_path, &requests_tmp, &manifest_tmp] {
            let _ = fs::remove_file(path);
        }
    }
    result
}

fn main() -> Result<()> {
    run(parse_args()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::Message;
    use tempfile::tempdir;

    fn frame(stream_id: u32, message_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&stream_id.to_be_bytes());
        bytes.push(message_type);
        bytes.push(0);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn parses_optional_hybrid_vsock_handshake() {
        assert_eq!(
            split_handshake(b"connect 1024\nrest").unwrap(),
            (Some("connect 1024".to_owned()), Some(1024), 13)
        );
        assert_eq!(
            split_handshake(b"CONNECT 1024\nrest").unwrap(),
            (Some("CONNECT 1024".to_owned()), Some(1024), 13)
        );
        assert_eq!(split_handshake(b"rest").unwrap(), (None, None, 0));
        assert!(split_handshake(b"CONNECT 1024").is_err());
        assert!(split_handshake(b"CONNECT bad\n").is_err());
    }

    #[test]
    fn decodes_known_request_and_preserves_unknown_request() {
        let temporary = tempdir().unwrap();
        let root = temporary.path();
        let input = root.join("raw");
        let connection = input.join("000001");
        let output = root.join("decoded");
        fs::create_dir_all(&connection).unwrap();
        fs::write(
            input.join("state.json"),
            r#"{"connections":1,"errors":[],"intercepted_sockets":["/run/test.sock"]}"#,
        )
        .unwrap();
        fs::write(
            connection.join("metadata.json"),
            r#"{"connection":1,"socket":"/run/test.sock","started_unix_ns":123,"finished_unix_ns":456}"#,
        )
        .unwrap();

        let mut known_payload = protocols::agent::StartContainerRequest {
            container_id: "sandbox/container".to_owned(),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        // Field 99 is intentionally unknown to the checked-out descriptor.
        known_payload.extend_from_slice(&[0x98, 0x06, 0x07]);
        let known = ttrpc::Request {
            service: "grpc.AgentService".to_owned(),
            method: "StartContainer".to_owned(),
            payload: known_payload,
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        let unknown = ttrpc::Request {
            service: "grpc.FutureService".to_owned(),
            method: "FutureRequest".to_owned(),
            payload: vec![1, 2, 3],
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();

        let mut stream = b"CONNECT 1024\n".to_vec();
        stream.extend_from_slice(&frame(1, TTRPC_REQUEST, &known));
        stream.extend_from_slice(&frame(3, TTRPC_REQUEST, &unknown));
        fs::write(connection.join("shim-to-agent.bin"), stream).unwrap();

        run(Args {
            input,
            output: output.clone(),
        })
        .unwrap();

        let records = fs::read_to_string(output.join("requests.jsonl")).unwrap();
        let records = records
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["decode_status"], "decoded-with-unknown-fields");
        assert_eq!(records[0]["connection_started_unix_ns"], 123);
        assert_eq!(records[0]["request"]["container_id"], "sandbox/container");
        assert_eq!(records[0]["has_unknown_fields"], true);
        assert!(records[0]["undecoded_payload_base64"].is_string());
        assert_eq!(records[1]["decode_status"], "unsupported");
        assert_eq!(records[1]["undecoded_payload_base64"], "AQID");

        let manifest: Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["typed_decode_complete"], false);
        assert_eq!(manifest["summary"]["requests"], 2);
        assert_eq!(manifest["summary"]["decoded_requests"], 1);
        assert_eq!(manifest["summary"]["unsupported_requests"], 1);
        assert_eq!(manifest["summary"]["requests_with_unknown_fields"], 1);
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(output.join("requests.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_truncated_frames_without_publishing_output() {
        let temporary = tempdir().unwrap();
        let root = temporary.path();
        let input = root.join("raw");
        let connection = input.join("000001");
        let output = root.join("decoded");
        fs::create_dir_all(&connection).unwrap();
        fs::write(
            input.join("state.json"),
            r#"{"connections":1,"errors":[],"intercepted_sockets":["/run/test.sock"]}"#,
        )
        .unwrap();
        fs::write(
            connection.join("metadata.json"),
            r#"{"connection":1,"socket":"/run/test.sock","started_unix_ns":123}"#,
        )
        .unwrap();
        fs::write(
            connection.join("shim-to-agent.bin"),
            [b"CONNECT 1024\n".as_slice(), &[0, 0, 0, 4, 0]].concat(),
        )
        .unwrap();

        assert!(run(Args {
            input,
            output: output.clone(),
        })
        .is_err());
        assert!(!output.join("requests.jsonl").exists());
        assert!(!output.join("manifest.json").exists());
    }

    #[test]
    fn records_truncated_tail_after_complete_requests() {
        let temporary = tempdir().unwrap();
        let input = temporary.path().join("raw");
        let connection = input.join("000001");
        let output = temporary.path().join("decoded");
        fs::create_dir_all(&connection).unwrap();
        fs::write(
            input.join("state.json"),
            r#"{"connections":1,"errors":[],"intercepted_sockets":["/run/test.sock"]}"#,
        )
        .unwrap();
        fs::write(
            connection.join("metadata.json"),
            r#"{"connection":1,"socket":"/run/test.sock","started_unix_ns":123}"#,
        )
        .unwrap();
        let payload = protocols::agent::StartContainerRequest {
            container_id: "sandbox/container".to_owned(),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        let request = ttrpc::Request {
            service: "grpc.AgentService".to_owned(),
            method: "StartContainer".to_owned(),
            payload,
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        let mut stream = b"connect 1024\n".to_vec();
        stream.extend_from_slice(&frame(1, TTRPC_REQUEST, &request));
        stream.extend_from_slice(&[0, 0, 0, 4, 0]);
        fs::write(connection.join("shim-to-agent.bin"), stream).unwrap();

        run(Args {
            input,
            output: output.clone(),
        })
        .unwrap();

        let manifest: Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["capture_complete"], false);
        assert_eq!(manifest["typed_decode_complete"], false);
        assert_eq!(manifest["summary"]["requests"], 1);
        assert_eq!(manifest["summary"]["truncated_connections"], 1);
        assert_eq!(
            manifest["connections"][0]["truncated_tail"]["part"],
            "header"
        );
    }

    #[test]
    fn skips_non_agent_hybrid_vsock_ports() {
        let temporary = tempdir().unwrap();
        let input = temporary.path().join("raw");
        let connection = input.join("000001");
        let output = temporary.path().join("decoded");
        fs::create_dir_all(&connection).unwrap();
        fs::write(
            input.join("state.json"),
            r#"{"connections":1,"errors":[],"intercepted_sockets":["/run/test.sock"]}"#,
        )
        .unwrap();
        fs::write(
            connection.join("metadata.json"),
            r#"{"connection":1,"socket":"/run/test.sock","started_unix_ns":123}"#,
        )
        .unwrap();
        fs::write(
            connection.join("shim-to-agent.bin"),
            b"connect 1026\nnot ttRPC",
        )
        .unwrap();

        let error = run(Args { input, output }).unwrap_err().to_string();
        assert_eq!(error, "captured streams contain no ttRPC requests");
    }
}
