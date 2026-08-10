package profile_policy_framework_settings

# Defines profile-wide Agent framework constants and request defaults that do
# not depend on a particular workload or disposable cluster identity. These are
# the values GenPolicy would otherwise bake in from its own compiler settings;
# stating them as reviewable claims makes the profile, not the compiler, their
# owner.
#
# How the composer consumes each claim:
# - target.scope is "policy" throughout, so every claim lands in the single
#   shared policy_data object rather than fanning out per container subject.
# - target.path is the JSON pointer this fragment takes ownership of. The whole
#   policy fails closed if the static IR already owns that path or if another
#   fragment claims one that overlaps it, so ownership here is exclusive.
# - addition must be the one object branch that reaches target.path; a claim
#   cannot mutate anything outside the path it declares.
# - value restates the leaf that addition places, so a reviewer can diff intent
#   against effect without walking the nested object.
# - operation is "default" throughout: this fragment only establishes
#   baselines and never rewrites a value some other owner produced.
# - evidence records provenance, distinguishing a value read from compiler
#   settings from one chosen to be deliberately restrictive.
#
# applies_to is what the composer checks to accept this fragment, against the
# environment recorded in the static IR. It spans three dimensions because the
# claims below answer to three independent owners: containerd and runc supply
# the capability baselines and cgroup and pause conventions, Kubernetes supplies
# the Service-derived variable shape and pause image, and the remainder is Kata
# and Agent owned. Any one of the three moving invalidates the whole fragment,
# which is the cost of keeping them together.
#
# capture_provenance records which capture profile these mutations were
# discovered from. It is recorded for review, not enforced, so that this
# fragment can be replaced without regenerating the static IR.
#
# The fragment declares no materialization_contracts, so this category grants
# no authority to generated claims; every path below is fixed at review time.
#
# Claims whose value is an empty list are deny-by-default rather than
# placeholders: they clear a permission surface that the framework would
# otherwise apply globally, forcing workload-scoped rules to grant it
# explicitly. This is why allow_env_regex, both ExecProcessRequest lists,
# dmverity/allowed_roothashes, and guest_pull/allowed_images start empty.
#
# Keep comments above "fragment :=". Everything after that marker is parsed as
# JSON by scripts/generate_regorus_fragment_inputs.py and must stay JSON-valid.
#
# Common path and syntax mutations:
# - /common/cpath constrains the runtime shared-container directory.
# - /common/root_path parameterizes the container rootfs by bundle ID.
# - /common/sfprefix constrains runtime-generated shared-file names.
# - /common/spath pins the sandbox storage directory.
# - /common/ipv4_a constrains IPv4 values accepted by framework rules.
# - /common/ip_p constrains network port values.
# - /common/svc_name_downward_env constrains Service-derived variable names.
# - /common/dns_label constrains DNS-label values.
# - /common/default_caps defines the unprivileged container capability baseline.
# - /common/privileged_caps defines the reviewed privileged capability set.
#
# Sandbox and request-default mutations:
# - /sandbox/storages pins the sandbox shared-memory tmpfs.
# - /request_defaults/AddARPNeighborsRequest/allowed_states limits neighbor
#   updates to the reviewed NUD states.
# - /request_defaults/AddARPNeighborsRequest/forbidden_cidrs_regex blocks
#   loopback neighbor addresses.
# - /request_defaults/AddARPNeighborsRequest/forbidden_device_names blocks the
#   loopback device.
# - /request_defaults/CloseStdinRequest disables closing standard input.
# - /request_defaults/CreateContainerRequest/allow_env_regex clears the global
#   environment regex allowlist so workload-scoped rules own dynamic values.
# - /request_defaults/ExecProcessRequest/allowed_commands clears globally
#   allowed exact exec commands.
# - /request_defaults/ExecProcessRequest/regex clears globally allowed exec
#   command regexes.
# - /request_defaults/GetDiagnosticDataRequest disables diagnostic collection.
# - /request_defaults/ReadStreamRequest disables stream reads.
# - /request_defaults/UpdateEphemeralMountsRequest disables ephemeral updates.
# - /request_defaults/UpdateInterfaceRequest/allow_raw_flags permits only the
#   reviewed raw interface flag mask.
# - /request_defaults/UpdateInterfaceRequest/forbidden_hw_addrs blocks the null
#   hardware address.
# - /request_defaults/UpdateInterfaceRequest/forbidden_names blocks loopback.
# - /request_defaults/UpdateRoutesRequest/forbidden_device_names blocks routes
#   through loopback.
# - /request_defaults/UpdateRoutesRequest/forbidden_source_regex blocks IPv4
#   and IPv6 loopback route sources.
# - /request_defaults/WriteStreamRequest disables stream writes.
#
# Device, cluster, and rootfs mutations:
# - /devices/vfio/device_path pins the Kata VFIO device path prefix.
# - /devices/vfio/nvidia initializes reviewed NVIDIA VFIO settings.
# - /cluster_config/pause_container_image pins the profile pause image.
# - /cluster_config/guest_pull enables the selected guest-pull transport.
# - /cluster_config/pause_container_id_policy selects pause ID policy v1.
# - /cluster_config/emptydir_type selects encrypted block emptyDir by default.
# - /cluster_config/cgroup_mount_extras_allowed limits accepted cgroup options.
# - /dmverity/allowed_roothashes starts with no global dm-verity authorization.
# - /guest_pull/allowed_images starts with no global image authorization.
fragment := {
  "applies_to": {
    "containerd": ["v2.3.3"],
    "kubernetes": ["v1.33.13"],
    "runc": ["v1.2.8"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "policy-framework-settings",
  "claims": [
    {
      "addition": {
        "common": {
          "cpath": "/run/kata-containers/shared/containers(?:/passthrough)?"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/cpath",
        "scope": "policy"
      },
      "value": "/run/kata-containers/shared/containers(?:/passthrough)?"
    },
    {
      "addition": {
        "common": {
          "root_path": "/run/kata-containers/$(bundle-id)/rootfs"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/root_path",
        "scope": "policy"
      },
      "value": "/run/kata-containers/$(bundle-id)/rootfs"
    },
    {
      "addition": {
        "common": {
          "sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/sfprefix",
        "scope": "policy"
      },
      "value": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
    },
    {
      "addition": {
        "common": {
          "spath": "/run/kata-containers/sandbox/storage"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/spath",
        "scope": "policy"
      },
      "value": "/run/kata-containers/sandbox/storage"
    },
    {
      "addition": {
        "common": {
          "ipv4_a": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/ipv4_a",
        "scope": "policy"
      },
      "value": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    },
    {
      "addition": {
        "common": {
          "ip_p": "[0-9]{1,5}"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/ip_p",
        "scope": "policy"
      },
      "value": "[0-9]{1,5}"
    },
    {
      "addition": {
        "common": {
          "svc_name_downward_env": "[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/svc_name_downward_env",
        "scope": "policy"
      },
      "value": "[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?"
    },
    {
      "addition": {
        "common": {
          "dns_label": "[a-zA-Z0-9_\\.\\-]+"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/dns_label",
        "scope": "policy"
      },
      "value": "[a-zA-Z0-9_\\.\\-]+"
    },
    {
      "addition": {
        "common": {
          "default_caps": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/default_caps",
        "scope": "policy"
      },
      "value": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ]
    },
    {
      "addition": {
        "common": {
          "privileged_caps": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/privileged_caps",
        "scope": "policy"
      },
      "value": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE"
      ]
    },
    {
      "addition": {
        "sandbox": {
          "storages": [
            {
              "driver": "ephemeral",
              "driver_options": [],
              "fs_group": null,
              "fstype": "tmpfs",
              "mount_point": "/run/kata-containers/sandbox/shm",
              "options": [
                "noexec",
                "nosuid",
                "nodev",
                "mode=1777",
                "size=67108864"
              ],
              "shared": false,
              "source": "shm"
            }
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/sandbox/storages",
        "scope": "policy"
      },
      "value": [
        {
          "driver": "ephemeral",
          "driver_options": [],
          "fs_group": null,
          "fstype": "tmpfs",
          "mount_point": "/run/kata-containers/sandbox/shm",
          "options": [
            "noexec",
            "nosuid",
            "nodev",
            "mode=1777",
            "size=67108864"
          ],
          "shared": false,
          "source": "shm"
        }
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "allowed_states": [
              2,
              128
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/allowed_states",
        "scope": "policy"
      },
      "value": [
        2,
        128
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "forbidden_cidrs_regex": [
              "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/forbidden_cidrs_regex",
        "scope": "policy"
      },
      "value": [
        "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "forbidden_device_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/forbidden_device_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "CloseStdinRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/CloseStdinRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "CreateContainerRequest": {
            "allow_env_regex": []
          }
        }
      },
      "evidence": "compiler-security-default",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/CreateContainerRequest/allow_env_regex",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "ExecProcessRequest": {
            "allowed_commands": []
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ExecProcessRequest/allowed_commands",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "ExecProcessRequest": {
            "regex": []
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ExecProcessRequest/regex",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "GetDiagnosticDataRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/GetDiagnosticDataRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "ReadStreamRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ReadStreamRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateEphemeralMountsRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateEphemeralMountsRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "allow_raw_flags": 128
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/allow_raw_flags",
        "scope": "policy"
      },
      "value": 128
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "forbidden_hw_addrs": [
              "00:00:00:00:00:00"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/forbidden_hw_addrs",
        "scope": "policy"
      },
      "value": [
        "00:00:00:00:00:00"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "forbidden_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/forbidden_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateRoutesRequest": {
            "forbidden_device_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateRoutesRequest/forbidden_device_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateRoutesRequest": {
            "forbidden_source_regex": [
              "^(?:0{0,4}:){0,7}0{0,3}1$",
              "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateRoutesRequest/forbidden_source_regex",
        "scope": "policy"
      },
      "value": [
        "^(?:0{0,4}:){0,7}0{0,3}1$",
        "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "WriteStreamRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/WriteStreamRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "device_path": "/dev/vfio/devices/vfio"
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/device_path",
        "scope": "policy"
      },
      "value": "/dev/vfio/devices/vfio"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "nvidia": {}
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/nvidia",
        "scope": "policy"
      },
      "value": {}
    },
    {
      "addition": {
        "cluster_config": {
          "pause_container_image": "genpolicy.local:5000/pause:3.10"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/pause_container_image",
        "scope": "policy"
      },
      "value": "genpolicy.local:5000/pause:3.10"
    },
    {
      "addition": {
        "cluster_config": {
          "guest_pull": true
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/guest_pull",
        "scope": "policy"
      },
      "value": true
    },
    {
      "addition": {
        "cluster_config": {
          "pause_container_id_policy": "v1"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/pause_container_id_policy",
        "scope": "policy"
      },
      "value": "v1"
    },
    {
      "addition": {
        "cluster_config": {
          "emptydir_type": "block-encrypted"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/emptydir_type",
        "scope": "policy"
      },
      "value": "block-encrypted"
    },
    {
      "addition": {
        "cluster_config": {
          "cgroup_mount_extras_allowed": [
            "nsdelegate",
            "memory_recursiveprot"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/cgroup_mount_extras_allowed",
        "scope": "policy"
      },
      "value": [
        "nsdelegate",
        "memory_recursiveprot"
      ]
    },
    {
      "addition": {
        "dmverity": {
          "allowed_roothashes": []
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/dmverity/allowed_roothashes",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "guest_pull": {
          "allowed_images": []
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/guest_pull/allowed_images",
        "scope": "policy"
      },
      "value": []
    }
  ],
  "schema_version": 1,
  "scope": "profile"
}
