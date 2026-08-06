ARG CAPTURE_BACKEND=runtime-rs

FROM registry.k8s.io/pause:3.10 AS pause
FROM busybox:1.36.1 AS busybox
FROM docker.io/library/registry:2.8.3 AS registry

# Build erofs-utils >= 1.8.2, required by the containerd erofs differ for the
# in-appliance dm-verity root-hash generation (Debian bookworm ships 1.6).
FROM debian:bookworm-slim AS erofs-utils-builder
ARG EROFS_UTILS_VERSION=1.8.4
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        autoconf automake build-essential ca-certificates curl libtool \
        liblz4-dev pkg-config uuid-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    curl -fsSL -o /tmp/erofs-utils.tar.gz \
        "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/snapshot/erofs-utils-${EROFS_UTILS_VERSION}.tar.gz"; \
    tar -xzf /tmp/erofs-utils.tar.gz -C /tmp; \
    cd "/tmp/erofs-utils-${EROFS_UTILS_VERSION}"; \
    ./autogen.sh; \
    ./configure --enable-lz4; \
    make -j"$(nproc)"; \
    make install

FROM docker.io/library/rust:1.95-bookworm AS rust-builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        perl \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tools/packaging/kata-deploy/binary ./tools/packaging/kata-deploy/binary
COPY tools/packaging/kata-deploy/job-dispatcher ./tools/packaging/kata-deploy/job-dispatcher

RUN sed 's/@COMMIT_INFO@/genpolicy-appliance/' \
        src/tools/genpolicy/src/version.rs.in \
    >src/tools/genpolicy/src/version.rs

FROM rust-builder AS analysis-builder
RUN --mount=type=cache,id=genpolicy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=genpolicy-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=genpolicy-analysis-target,target=/workspace/target \
    cargo build --locked --release --package genpolicy-oci-compiler \
    && mkdir -p /out \
    && cp target/release/genpolicy-oci-compiler /out/

FROM rust-builder AS capture-runc-builder
RUN --mount=type=cache,id=genpolicy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=genpolicy-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=genpolicy-capture-target,target=/workspace/target \
    cargo build --locked --release \
    --package kata-createreq-capture \
        --bin createreq-capture \
    && mkdir -p /out \
    && cp target/release/createreq-capture /out/

FROM rust-builder AS capture-runtime-rs-builder
RUN --mount=type=cache,id=genpolicy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=genpolicy-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=genpolicy-capture-target,target=/workspace/target \
    cargo build --locked --release \
        --package kata-createreq-capture \
        --features runtime-rs-capture \
        --bin containerd-shim-kata-capture-v2 \
    && mkdir -p /out \
    && cp target/release/containerd-shim-kata-capture-v2 /out/

FROM rust-builder AS predictor-builder
RUN --mount=type=cache,id=genpolicy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=genpolicy-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=genpolicy-analysis-target,target=/workspace/target \
    cargo build --locked --release --package kata-storage-predictor \
    && mkdir -p /out \
    && cp target/release/storage-predictor /out/

FROM rust-builder AS legacy-builder

RUN --mount=type=cache,id=genpolicy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=genpolicy-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=genpolicy-analysis-target,target=/workspace/target \
    cargo build --locked --release --package genpolicy \
    && mkdir -p /out \
    && cp target/release/genpolicy /out/

FROM debian:bookworm-slim AS capture-base

ARG CAPTURE_BACKEND=runtime-rs
ARG PROFILE_NAME=k8s-1.33-containerd-2.3-native
ARG TARGETARCH=amd64
ARG KUBERNETES_VERSION=v1.33.13
ARG CONTAINERD_VERSION=v2.3.3
ARG RUNC_VERSION=v1.2.8
ARG ETCD_VERSION=v3.5.21
ARG CNI_PLUGINS_VERSION=v1.7.1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        conntrack \
        curl \
        iproute2 \
        iptables \
        kmod \
        openssl \
        python3 \
        python3-yaml \
        socat \
        tar \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSLo /usr/local/bin/kube-apiserver \
        "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/${TARGETARCH}/kube-apiserver"; \
    curl -fsSLo /usr/local/bin/kubelet \
        "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/${TARGETARCH}/kubelet"; \
    curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/${KUBERNETES_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    chmod 0755 /usr/local/bin/kube-apiserver /usr/local/bin/kubelet /usr/local/bin/kubectl

RUN set -eux; \
    curl -fsSL \
        "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${TARGETARCH}.tar.gz" \
        | tar -xz --strip-components=1 -C /usr/local/bin \
            "etcd-${ETCD_VERSION}-linux-${TARGETARCH}/etcd" \
            "etcd-${ETCD_VERSION}-linux-${TARGETARCH}/etcdctl"; \
    curl -fsSL \
        "https://github.com/containerd/containerd/releases/download/${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION#v}-linux-${TARGETARCH}.tar.gz" \
        | tar -xz -C /usr/local; \
    curl -fsSLo /usr/local/bin/runc.real \
        "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${TARGETARCH}"; \
    chmod 0755 /usr/local/bin/runc.real

RUN set -eux; \
    mkdir -p /opt/cni/bin; \
    curl -fsSL \
        "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz" \
        | tar -xz -C /opt/cni/bin

COPY --from=pause /pause /opt/genpolicy/rootfs/pause/pause
COPY --from=busybox / /opt/genpolicy/rootfs/busybox
RUN mkdir -p /opt/genpolicy/rootfs/busybox/work
COPY src/tools/genpolicy/appliance/config /opt/genpolicy/appliance/config
COPY src/tools/genpolicy/appliance/profiles /opt/genpolicy/appliance/profiles
COPY src/tools/genpolicy/appliance/scripts/capture_bundle.py \
    src/tools/genpolicy/appliance/scripts/capture_image_metadata.py \
    src/tools/genpolicy/appliance/scripts/entrypoint.sh \
    src/tools/genpolicy/appliance/scripts/make_oci_image.py \
    src/tools/genpolicy/appliance/scripts/runc-capture \
    src/tools/genpolicy/appliance/scripts/submit_workload.py \
    /opt/genpolicy/appliance/scripts/

RUN set -eux; \
    chmod 0755 \
        /opt/genpolicy/appliance/scripts/*.sh \
        /opt/genpolicy/appliance/scripts/runc-capture; \
    mkdir -p /opt/genpolicy/images; \
    python3 /opt/genpolicy/appliance/scripts/make_oci_image.py \
        --rootfs /opt/genpolicy/rootfs/pause \
        --reference genpolicy.local:5000/pause:3.10 \
        --entrypoint '["/pause"]' \
        --output /opt/genpolicy/images/pause.tar; \
    python3 /opt/genpolicy/appliance/scripts/make_oci_image.py \
        --rootfs /opt/genpolicy/rootfs/busybox \
        --reference genpolicy.local:5000/busybox:1.36.1 \
        --entrypoint '["/bin/busybox","sleep","3600"]' \
        --output /opt/genpolicy/images/busybox.tar; \
    rm -rf /opt/genpolicy/rootfs

ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GENPOLICY_APPLIANCE_ROOT=/opt/genpolicy/appliance
ENV GENPOLICY_CAPTURE_BACKEND=${CAPTURE_BACKEND}
ENV GENPOLICY_PROFILE_NAME=${PROFILE_NAME}

ENTRYPOINT ["/opt/genpolicy/appliance/scripts/entrypoint.sh"]

FROM capture-base AS capture-runtime-rs-native
COPY --from=capture-runtime-rs-builder \
    /out/containerd-shim-kata-capture-v2 /usr/local/bin/

FROM capture-runtime-rs-native AS capture-runtime-rs-erofs-dmverity
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        cryptsetup-bin liblz4-1 libuuid1 udev zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=erofs-utils-builder /usr/local/bin/mkfs.erofs /usr/local/bin/mkfs.erofs
COPY src/tools/genpolicy/appliance/scripts/watch_device_mapper_nodes.py \
    /opt/genpolicy/appliance/scripts/watch_device_mapper_nodes.py

FROM capture-base AS capture-runc-native
COPY --from=capture-runc-builder /out/createreq-capture \
    /usr/local/bin/createreq-capture

FROM debian:bookworm-slim AS analysis-runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends python3 python3-yaml \
    && rm -rf /var/lib/apt/lists/*

COPY --from=analysis-builder /out/genpolicy-oci-compiler \
    /usr/local/bin/genpolicy-oci-compiler
COPY --from=predictor-builder /out/storage-predictor \
    /usr/local/bin/storage-predictor
COPY src/tools/genpolicy/appliance /opt/genpolicy/appliance
COPY src/tools/genpolicy/rules.rego /opt/genpolicy/policy/rules.rego
COPY src/tools/genpolicy/genpolicy-settings.json /opt/genpolicy/policy/settings/genpolicy-settings.json
COPY src/tools/genpolicy/appliance/policy-settings.d \
    /opt/genpolicy/policy/settings/genpolicy-settings.d
RUN chmod 0755 /opt/genpolicy/appliance/scripts/*.sh

ENV GENPOLICY_APPLIANCE_ROOT=/opt/genpolicy/appliance
ENTRYPOINT ["/opt/genpolicy/appliance/scripts/analyze_capture.sh"]

FROM capture-${CAPTURE_BACKEND}-native AS legacy-reference

COPY --from=registry /bin/registry /usr/local/bin/registry
COPY --from=legacy-builder /out/genpolicy /usr/local/bin/genpolicy
COPY --from=analysis-builder /out/genpolicy-oci-compiler \
    /usr/local/bin/genpolicy-oci-compiler
COPY src/tools/genpolicy/rules.rego /opt/genpolicy/policy/rules.rego
COPY src/tools/genpolicy/genpolicy-settings.json /opt/genpolicy/policy/settings/genpolicy-settings.json
COPY src/tools/genpolicy/appliance/policy-settings.d \
    /opt/genpolicy/policy/settings/genpolicy-settings.d
COPY src/tools/genpolicy/appliance /opt/genpolicy/appliance

ENV GENPOLICY_LEGACY_REFERENCE=1

FROM capture-runtime-rs-native
