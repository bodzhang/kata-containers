package profile_runtime_rs

# Rewrites typed workload intent into runtime-rs-owned OCI policy, including
# reviewed base mounts and exact emptyDir, ConfigMap, and Secret volume mounts.
resource_volume_transport := "copy-to-rootfs"

application_base_mounts := [
  {"destination": "/proc", "options": ["nosuid", "noexec", "nodev"], "source": "proc", "type_": "proc"},
  {"destination": "/dev", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"], "source": "tmpfs", "type_": "tmpfs"},
  {"destination": "/dev/pts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"], "source": "devpts", "type_": "devpts"},
  {"destination": "/dev/mqueue", "options": ["nosuid", "noexec", "nodev"], "source": "mqueue", "type_": "mqueue"},
  {"destination": "/sys", "options": ["nosuid", "noexec", "nodev", "ro"], "source": "sysfs", "type_": "sysfs"},
  {"destination": "/sys/fs/cgroup", "options": ["nosuid", "noexec", "nodev", "relatime", "ro"], "source": "cgroup", "type_": "cgroup"},
  {"destination": "/etc/hosts", "options": ["rbind", "rprivate", "rw"], "source": "$(sfprefix)hosts$", "type_": "bind"},
  {"destination": "/dev/termination-log", "options": ["rbind", "rprivate", "rw"], "source": "$(sfprefix)termination-log$", "type_": "bind"},
  {"destination": "/etc/hostname", "options": ["rbind", "rprivate", "rw"], "source": "$(sfprefix)hostname$", "type_": "bind"},
  {"destination": "/etc/resolv.conf", "options": ["rbind", "rprivate", "rw"], "source": "$(sfprefix)resolv.conf$", "type_": "bind"},
  {"destination": "/dev/shm", "options": ["rbind"], "source": "/run/kata-containers/sandbox/shm", "type_": "bind"},
]

sandbox_base_mounts := [
  {"destination": "/proc", "options": ["nosuid", "noexec", "nodev"], "source": "proc", "type_": "proc"},
  {"destination": "/dev", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"], "source": "tmpfs", "type_": "tmpfs"},
  {"destination": "/dev/pts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"], "source": "devpts", "type_": "devpts"},
  {"destination": "/dev/mqueue", "options": ["nosuid", "noexec", "nodev"], "source": "mqueue", "type_": "mqueue"},
  {"destination": "/sys", "options": ["nosuid", "noexec", "nodev", "ro"], "source": "sysfs", "type_": "sysfs"},
  {"destination": "/dev/shm", "options": ["rbind"], "source": "/run/kata-containers/sandbox/shm", "type_": "bind"},
  {"destination": "/etc/resolv.conf", "options": ["rbind", "ro", "nosuid", "nodev", "noexec"], "source": "$(sfprefix)resolv.conf$", "type_": "bind"},
]

base_mounts(subject) := application_base_mounts if { subject.role == "application" }
base_mounts(subject) := sandbox_base_mounts if { subject.role == "sandbox" }

empty_dir_mount_options(volume) := ["rbind", "rprivate", "ro"] if { volume.read_only }
empty_dir_mount_options(volume) := ["rbind", "rprivate", "rw"] if { not volume.read_only }

empty_dir_mount(volume) := {
  "destination": volume.destination,
  "options": empty_dir_mount_options(volume),
  "source": "",
  "type_": "bind",
}

resource_mount(volume) := {
  "destination": volume.destination,
  "options": ["rbind", "rprivate", "ro"],
  "source": sprintf("^$(cpath)/$(bundle-id)-[0-9a-f]{16}-%s$", [volume.destination_basename]),
  "type_": "bind",
} if {
  resource_volume_transport == "copy-to-rootfs"
}

volume_mount(volume) := empty_dir_mount(volume) if { volume.role == "empty-dir" }
volume_mount(volume) := resource_mount(volume) if { volume.role in {"config-map", "secret"} }

volume_supported(volume) if {
  volume.role == "empty-dir"
  volume.medium in {"memory", "node-default"}
  object.get(volume, "size_limit", "") == ""
  object.get(volume, "sub_path", "") == ""
  object.get(volume, "mount_propagation", "") == ""
  object.get(volume, "recursive_read_only", false) == false
}

volume_supported(volume) if {
  volume.role in {"config-map", "secret"}
  resource_volume_transport == "copy-to-rootfs"
  volume.source.status == "resolved"
  regex.match("^[A-Za-z0-9_-]+$", volume.destination_basename)
  object.get(volume, "sub_path", "") == ""
  object.get(volume, "mount_propagation", "") == ""
  object.get(volume, "recursive_read_only", false) == false
}

volumes_supported(subject) if {
  every volume in subject.volumes {
    volume_supported(volume)
  }
}

# Replaces the complete OCI mount array for a fully supported subject. The
# result combines reviewed role-specific base mounts with typed emptyDir and
# copy-to-rootfs ConfigMap/Secret mounts; partial subjects remain materialized.
volume_mount_claims(ir) := [claim |
  some subject in ir.subjects
  volumes_supported(subject)
  volume_mounts := [volume_mount(volume) | some volume in subject.volumes]
  mounts := array.concat(base_mounts(subject), volume_mounts)
  claim := {
    "addition": {"OCI": {"Mounts": mounts}},
    "category": "runtime-rs",
    "operation": "rewrite",
    "subject": subject.id,
    "target": {"path": "/OCI/Mounts"},
  }
]

# Remaining runtime-rs materializations are restricted to explicit OCI rewrite
# paths whose typed transformations have not yet moved into this module.
fragment := {
  "applies_to": {
    "rootfs_mode": ["guest-pull"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "runtime-rs",
  "claims": [],
  "materialization_contracts": [
    {
      "operations": ["rewrite"],
      "path_regex": "^/OCI/(Root/Path|Linux/Namespaces|Process/(Terminal|Capabilities/(Ambient|Bounding|Effective|Inheritable|Permitted)|EnvRegex))$"
    }
  ],
  "schema_version": 1,
  "scope": "profile"
}