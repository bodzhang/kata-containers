package kata_fragment_framework

sandbox_id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
other_sandbox_id := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
pod_uid := "12345678-1234-4234-8234-123456789abc"
other_pod_uid := "87654321-4321-4321-8321-cba987654321"
pod_name := "demo-abcde"
other_pod_name := "demo-fghij"
pod_namespace := "default"
static_context := {
	"pod_name_pattern": "^demo-[a-z0-9]{5}$",
	"pod_namespace": pod_namespace,
}

binding := {
	"pod_name": pod_name,
	"pod_namespace": pod_namespace,
	"pod_uid": pod_uid,
}

binding_state := {concat("", ["pod-identity.", sandbox_id]): binding}

log_directory(namespace, name, uid) := sprintf(
	"/var/log/pods/%s_%s_%s",
	[namespace, name, uid],
)

create_request_with_log(
	container_type,
	requested_sandbox_id,
	requested_pod_uid,
	requested_pod_name,
	requested_namespace,
	requested_log_directory,
) := {
	"OCI": {
		"Annotations": {
			container_type_key: container_type,
			pod_name_key: requested_pod_name,
			pod_namespace_key: requested_namespace,
			pod_uid_key: requested_pod_uid,
			sandbox_id_key: requested_sandbox_id,
			sandbox_log_directory_key: requested_log_directory,
		},
	},
}

create_request(container_type, requested_sandbox_id, requested_pod_uid, requested_pod_name, requested_namespace) := create_request_with_log(
	container_type,
	requested_sandbox_id,
	requested_pod_uid,
	requested_pod_name,
	requested_namespace,
	log_directory(requested_namespace, requested_pod_name, requested_pod_uid),
)

test_sandbox_binds_pod_identity_once if {
	response := validate_create_container(
		create_request("sandbox", sandbox_id, pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as {}
	response == {
		"allowed": true,
		"ops": [{
			"op": "add",
			"path": concat("", ["/pstate/pod-identity.", sandbox_id]),
			"value": binding,
		}],
	}
}

test_same_sandbox_binding_is_idempotent if {
	response := validate_create_container(
		create_request("sandbox", sandbox_id, pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as binding_state
	response == {"allowed": true, "ops": []}
}

test_application_container_must_match_bound_pod_identity if {
	response := validate_create_container(
		create_request("container", sandbox_id, pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as binding_state
	response == {"allowed": true, "ops": []}
}

test_application_container_before_sandbox_binding_is_denied if {
	response := validate_create_container(
		create_request("container", sandbox_id, pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as {}
	not response.allowed
}

test_different_valid_pod_uid_is_denied if {
	response := validate_create_container(
		create_request("container", sandbox_id, other_pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as binding_state
	not response.allowed
}

test_binding_from_another_sandbox_is_denied if {
	response := validate_create_container(
		create_request("container", other_sandbox_id, pod_uid, pod_name, pod_namespace),
		static_context,
	) with data.pstate as binding_state
	not response.allowed
}

test_malformed_identity_is_denied if {
	response := validate_create_container(
		create_request("sandbox", sandbox_id, "not-a-uuid", pod_name, pod_namespace),
		static_context,
	) with data.pstate as {}
	not response.allowed
}

test_different_valid_pod_name_is_denied if {
	response := validate_create_container(
		create_request("container", sandbox_id, pod_uid, other_pod_name, pod_namespace),
		static_context,
	) with data.pstate as binding_state
	not response.allowed
}

test_pod_name_outside_static_pattern_is_denied if {
	response := validate_create_container(
		create_request("sandbox", sandbox_id, pod_uid, "attacker", pod_namespace),
		static_context,
	) with data.pstate as {}
	not response.allowed
}

test_namespace_outside_static_context_is_denied if {
	response := validate_create_container(
		create_request("sandbox", sandbox_id, pod_uid, pod_name, "other"),
		static_context,
	) with data.pstate as {}
	not response.allowed
}

test_log_directory_must_be_derived_from_bound_identity if {
	response := validate_create_container(
		create_request_with_log(
			"container",
			sandbox_id,
			pod_uid,
			pod_name,
			pod_namespace,
			"/var/log/pods/default_other_uid",
		),
		static_context,
	) with data.pstate as binding_state
	not response.allowed
}
