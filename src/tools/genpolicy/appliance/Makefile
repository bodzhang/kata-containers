SHELL := /bin/bash

include profile.env

CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
IMAGE ?= genpolicy-appliance:$(PROFILE_NAME)
REFERENCE_IMAGE ?= $(IMAGE)-legacy-reference
REPO_ROOT := $(abspath ../../../..)

.PHONY: validate image reference-image e2e

validate:
	./tests/validate.sh

image:
	@test -n "$(CONTAINER_ENGINE)" || { echo "docker or podman is required"; exit 1; }
	$(CONTAINER_ENGINE) build \
		--file $(CURDIR)/Dockerfile \
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
		--build-arg KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		--build-arg CONTAINERD_VERSION=$(CONTAINERD_VERSION) \
		--build-arg RUNC_VERSION=$(RUNC_VERSION) \
		--build-arg ETCD_VERSION=$(ETCD_VERSION) \
		--build-arg CNI_PLUGINS_VERSION=$(CNI_PLUGINS_VERSION) \
		--tag $(REFERENCE_IMAGE) $(REPO_ROOT)

e2e: image reference-image
	CONTAINER_ENGINE="$(CONTAINER_ENGINE)" IMAGE="$(IMAGE)" \
		REFERENCE_IMAGE="$(REFERENCE_IMAGE)" ./tests/e2e.sh
