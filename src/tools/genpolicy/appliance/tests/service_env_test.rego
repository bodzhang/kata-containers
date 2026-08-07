package agent_policy

policy_data := json.unmarshal(`{"request_defaults":{"CreateContainerRequest":{"allow_env_regex":[]}}}`)

service_env := "BACKEND_SERVICE_HOST=10.100.65.106"

test_captured_service_environment_allowed_for_selected_container if {
	process := {
		"Env": [],
		"EnvRegex": ["^BACKEND_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"],
	}
	allow_var(process, {}, service_env, "pod", "default")
}

test_captured_service_environment_denied_for_other_container if {
	process := {"Env": [], "EnvRegex": []}
	not allow_var(process, {}, service_env, "pod", "default")
}

test_undeclared_service_environment_name_denied if {
	process := {
		"Env": [],
		"EnvRegex": ["^BACKEND_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"],
	}
	not allow_var(
		process,
		{},
		"ATTACKER_SERVICE_HOST=10.100.65.106",
		"pod",
		"default",
	)
}
