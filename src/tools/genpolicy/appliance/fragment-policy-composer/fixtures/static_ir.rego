package static_policy_ir

ir := {
    "agent_framework_version": 1,
    "schema_version": 1,
    "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
    "environment": {
        "containerd": "v2.3.3",
        "kubernetes": "v1.33.13",
        "rootfs_mode": "guest-pull",
        "runc": "v1.2.8",
    },
    "requires": {"categories": ["kubelet-resolution"]},
    "static_base_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "policy_data": {},
    "policy_owned_paths": [],
    "subjects": [{
        "collection_encodings": {"/OCI/Process/Env": "env-map"},
        "id": "container/app",
        "ordinal": 0,
        "owned_paths": [
            "/OCI/Annotations/io.kubernetes.cri.container-name",
            "/OCI/Process/Args",
            "/OCI/Process/Env/MODE",
        ],
        "policy": {
            "OCI": {
                "Annotations": {"io.kubernetes.cri.container-name": "app"},
                "Process": {
                    "Args": ["/usr/bin/app"],
                    "Env": {"MODE": "production"},
                },
            },
        },
        "role": "application",
    }],
}