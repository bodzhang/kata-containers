FROM registry.k8s.io/pause:3.10 AS pause
FROM busybox:1.36.1 AS busybox
FROM docker.io/library/registry:2.8.3 AS registry

FROM docker.io/library/rust:1.88-bookworm AS policy-builder

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

RUN sed 's/@COMMIT_INFO@/genpolicy-appliance/' \
        src/tools/genpolicy/src/version.rs.in \
        >src/tools/genpolicy/src/version.rs \
    && cargo build --locked --release --package genpolicy-oci-compiler

FROM policy-builder AS legacy-builder

RUN cargo build --locked --release --package genpolicy

FROM debian:bookworm-slim AS appliance-runtime

ARG TARGETARCH=amd64
ARG KUBERNETES_VERSION=v1.33.13
ARG CONTAINERD_VERSION=v1.7.29
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
COPY --from=busybox /bin/busybox /opt/genpolicy/rootfs/busybox/bin/busybox
COPY --from=policy-builder /workspace/target/release/genpolicy-oci-compiler \
    /usr/local/bin/genpolicy-oci-compiler
COPY src/tools/genpolicy/appliance /opt/genpolicy/appliance
COPY src/tools/genpolicy/rules.rego /opt/genpolicy/policy/rules.rego
COPY src/tools/genpolicy/genpolicy-settings.json /opt/genpolicy/policy/settings/genpolicy-settings.json
COPY src/tools/genpolicy/appliance/policy-settings.d \
    /opt/genpolicy/policy/settings/genpolicy-settings.d

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

ENTRYPOINT ["/opt/genpolicy/appliance/scripts/entrypoint.sh"]

FROM appliance-runtime AS legacy-reference

COPY --from=registry /bin/registry /usr/local/bin/registry
COPY --from=legacy-builder /workspace/target/release/genpolicy /usr/local/bin/genpolicy

ENV GENPOLICY_LEGACY_REFERENCE=1

FROM appliance-runtime
