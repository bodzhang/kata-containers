SHELL := /bin/bash

PROFILE ?= k8s-1.33-containerd-2.3-guest-pull
PROFILE_FILE := profiles/$(PROFILE).env
include $(PROFILE_FILE)

CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
CAPTURE_TARGET := capture-$(CAPTURE_BACKEND)-$(ROOTFS_MODE)
IMAGE ?= genpolicy-appliance:$(PROFILE_NAME)
ANALYSIS_IMAGE ?= genpolicy-analysis:latest
REFERENCE_IMAGE ?= $(IMAGE)-legacy-reference
REPO_ROOT := $(abspath ../../../..)
RUST_HOST := $(shell rustc -vV | awk '/^host:/ { print $$2 }')

.PHONY: validate image analysis-image reference-image policy-tools e2e

validate:
	./tests/validate.sh

image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--target $(CAPTURE_TARGET) \
		--build-arg CAPTURE_BACKEND=$(CAPTURE_BACKEND) \
		--build-arg ROOTFS_MODE=$(ROOTFS_MODE) \
		--build-arg PROFILE_NAME=$(PROFILE_NAME) \
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--tag $(IMAGE) $(REPO_ROOT)

analysis-image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--target analysis-runtime \
		--tag $(ANALYSIS_IMAGE) $(REPO_ROOT)

reference-image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
		--target legacy-reference \
		--build-arg CAPTURE_BACKEND=$(CAPTURE_BACKEND) \
		--build-arg ROOTFS_MODE=$(ROOTFS_MODE) \
		--build-arg PROFILE_NAME=$(PROFILE_NAME) \
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--tag $(REFERENCE_IMAGE) $(REPO_ROOT)

policy-tools:
	cargo build --manifest-path $(REPO_ROOT)/Cargo.toml -p kata-agent-ctl
	$(MAKE) -C $(REPO_ROOT)/src/agent AGENT_POLICY=yes INIT_DATA=no LIBC=gnu

e2e: image analysis-image reference-image policy-tools
	CAPTURE_BACKEND="$(CAPTURE_BACKEND)" \
		ROOTFS_MODE="$(ROOTFS_MODE)" REQUEST_AUTHORITY="$(REQUEST_AUTHORITY)" \
		CONTAINER_ENGINE="$(CONTAINER_ENGINE)" IMAGE="$(IMAGE)" \
		ANALYSIS_IMAGE="$(ANALYSIS_IMAGE)" \
		REFERENCE_IMAGE="$(REFERENCE_IMAGE)" \
		AGENT_CTL="$(REPO_ROOT)/target/debug/kata-agent-ctl" \
		KATA_AGENT="$(REPO_ROOT)/target/$(RUST_HOST)/release/kata-agent" \
		./tests/e2e.sh
