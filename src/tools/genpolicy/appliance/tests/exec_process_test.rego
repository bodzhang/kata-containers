package agent_policy

policy_data := {}

exec_input := {
	"string_user": null,
	"stdin_port": 0,
	"stdout_port": 0,
	"stderr_port": 0,
	"process": {
		"SelinuxLabel": "",
		"ApparmorProfile": "",
	},
}

test_exec_without_passfd_allowed_by_precheck if {
	allow_exec_process_input with input as exec_input
}

test_exec_stdin_passfd_denied_by_precheck if {
	not allow_exec_process_input with input as object.union(exec_input, {"stdin_port": 100})
}

test_exec_stdout_passfd_denied_by_precheck if {
	not allow_exec_process_input with input as object.union(exec_input, {"stdout_port": 101})
}

test_exec_stderr_passfd_denied_by_precheck if {
	not allow_exec_process_input with input as object.union(exec_input, {"stderr_port": 102})
}