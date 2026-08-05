SHELL := /bin/bash

include profile.env

CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
CAPTURE_BACKEND ?= runtime-rs
IMAGE ?= genpolicy-appliance:$(PROFILE_NAME)
REFERENCE_IMAGE ?= $(IMAGE)-legacy-reference
REPO_ROOT := $(abspath ../../../..)
RUST_HOST := $(shell rustc -vV | awk '/^host:/ { print $$2 }')

.PHONY: validate image reference-image policy-tools e2e

validate:
	./tests/validate.sh

image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--build-arg CAPTURE_BACKEND=$(CAPTURE_BACKEND) \
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--tag $(IMAGE) $(REPO_ROOT)

reference-image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--target legacy-reference \
		--build-arg CAPTURE_BACKEND=$(CAPTURE_BACKEND) \
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--tag $(REFERENCE_IMAGE) $(REPO_ROOT)

policy-tools:
	cargo build --manifest-path $(REPO_ROOT)/Cargo.toml -p kata-agent-ctl
	$(MAKE) -C $(REPO_ROOT)/src/agent AGENT_POLICY=yes INIT_DATA=no LIBC=gnu

e2e: image reference-image policy-tools
	CAPTURE_BACKEND="$(CAPTURE_BACKEND)" \
		CONTAINER_ENGINE="$(CONTAINER_ENGINE)" IMAGE="$(IMAGE)" \
		REFERENCE_IMAGE="$(REFERENCE_IMAGE)" \
		AGENT_CTL="$(REPO_ROOT)/target/debug/kata-agent-ctl" \
		KATA_AGENT="$(REPO_ROOT)/target/$(RUST_HOST)/release/kata-agent" \
		./tests/e2e.sh
