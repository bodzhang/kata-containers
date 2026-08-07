package kata_fragment_framework

container_type_key := "io.kubernetes.cri.container-type"
sandbox_id_key := "io.kubernetes.cri.sandbox-id"
pod_uid_key := "io.kubernetes.cri.sandbox-uid"
pod_name_key := "io.kubernetes.cri.sandbox-name"
pod_namespace_key := "io.kubernetes.cri.sandbox-namespace"
sandbox_log_directory_key := "io.kubernetes.cri.sandbox-log-directory"

sandbox_id_pattern := "^[0-9a-f]{64}$"
pod_uid_pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
dns_label_pattern := "^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
dns_subdomain_pattern := "^[a-z0-9](?:[-.a-z0-9]*[a-z0-9])?$"

default validate_create_container(_, _) := {"allowed": false, "ops": []}

pod_identity_state_key(sandbox_id) := concat("", ["pod-identity.", sandbox_id])

pod_identity_state_path(sandbox_id) := concat("", ["/pstate/", pod_identity_state_key(sandbox_id)])

pod_identity(identity) := {
	"pod_name": identity.pod_name,
	"pod_namespace": identity.pod_namespace,
	"pod_uid": identity.pod_uid,
}

sandbox_log_directory(identity) := sprintf(
	"/var/log/pods/%s_%s_%s",
	[identity.pod_namespace, identity.pod_name, identity.pod_uid],
)

request_identity(request, context) := identity if {
	annotations := request.OCI.Annotations
	identity := {
		"container_type": annotations[container_type_key],
		"log_directory": annotations[sandbox_log_directory_key],
		"pod_name": annotations[pod_name_key],
		"pod_namespace": annotations[pod_namespace_key],
		"pod_uid": annotations[pod_uid_key],
		"sandbox_id": annotations[sandbox_id_key],
	}
	identity.container_type in {"container", "sandbox"}
	regex.match(pod_uid_pattern, identity.pod_uid)
	regex.match(sandbox_id_pattern, identity.sandbox_id)
	count(identity.pod_name) <= 253
	regex.match(dns_subdomain_pattern, identity.pod_name)
	count(identity.pod_namespace) <= 63
	regex.match(dns_label_pattern, identity.pod_namespace)
	identity.pod_namespace == context.pod_namespace
	startswith(context.pod_name_pattern, "^")
	endswith(context.pod_name_pattern, "$")
	regex.match(context.pod_name_pattern, identity.pod_name)
	identity.log_directory == sandbox_log_directory(identity)
}

validate_create_container(request, context) := {"allowed": true, "ops": [operation]} if {
	identity := request_identity(request, context)
	identity.container_type == "sandbox"
	state_key := pod_identity_state_key(identity.sandbox_id)
	object.get(data.pstate, state_key, null) == null
	operation := {
		"op": "add",
		"path": pod_identity_state_path(identity.sandbox_id),
		"value": pod_identity(identity),
	}
}

validate_create_container(request, context) := {"allowed": true, "ops": []} if {
	identity := request_identity(request, context)
	identity.container_type == "sandbox"
	data.pstate[pod_identity_state_key(identity.sandbox_id)] == pod_identity(identity)
}

validate_create_container(request, context) := {"allowed": true, "ops": []} if {
	identity := request_identity(request, context)
	identity.container_type == "container"
	data.pstate[pod_identity_state_key(identity.sandbox_id)] == pod_identity(identity)
}
