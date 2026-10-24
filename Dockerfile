# Two stages: build the collector, then ship a runtime that carries only that
# binary and AgentSight. The builder image is ~1.5GB of Rust toolchain and none
# of it needs to reach a host that is already running an agent under eBPF.
# Every eBPF probe the image runs is AgentSight's: TLS/HTTP capture for
# `collect`, and its process probe behind `listen` and `files` (DR-170).
FROM rust:1-slim-bookworm AS build

WORKDIR /src

# Dependencies first, against a stub main, so editing collector source does not
# re-download and re-compile the whole tree on every build. agentsight-capture
# pulls hyper, tokio and rusqlite; that layer is worth caching.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src/ ./src/
# cargo skips a rebuild when only mtime changed, so touch the real entrypoint to
# force it — otherwise the stub above is what gets shipped.
RUN touch src/main.rs && cargo build --release --locked

# python:3.13-slim, not debian-slim, and the version is the point. RailScan's
# image was 3.13 and its CI pinned 3.13; folding the scanner in on top of
# debian-bookworm would have handed it Python 3.11 while CI kept testing 3.13 —
# a silent runtime downgrade, and drift in the direction where a 3.12-or-later
# construct passes CI and dies in the image. This base is Debian too, so
# AgentSight's libraries install the same way.
FROM python:3.13-slim

# libelf and zlib are AgentSight's, not ours: it loads eBPF objects at runtime.
# openssl is `railmon demo`'s (tools/local-demo): it generates a throwaway
# self-signed cert for its own local HTTPS pair, nothing else in the image
# touches it. No pip: the scanner and forwarder are deliberately
# standard-library only.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libelf1 zlib1g openssl \
    && rm -rf /var/lib/apt/lists/*

# Pinned to one AgentSight release and checked against its SHA-256 (DR-204).
# The image used to follow releases/latest, so two builds of the same commit
# could ship different probes and an upstream release could change or break
# the stack without a change here. Now a new AgentSight reaches the image only
# through a commit, and the build fails, not warns, when the downloaded bytes
# are not the ones pinned.
#
# Bumping is one edit of the three ARGs below: the release tag, and the sha256
# GitHub records for its `agentsight` and `agentsight-aarch64` assets (`gh
# release view <tag> --repo eunomia-bpf/agentsight --json assets`, or
# sha256sum of the download).
# `make fetch-agentsight` reads them from here, so the local binary and the
# image's stay the same release. A bump changes what the pack observes (the
# listener and file-open evidence come from this release too, DR-170), so it
# goes with a rule_pack_version bump unless the release leaves that alone.
#
# Both architectures, from the same release (DR-208): upstream publishes
# `agentsight` (x86-64) and `agentsight-aarch64`, and each is checked against
# its own pinned sha256. arm64 is how the stack runs on Apple Silicon under
# Docker Desktop and on arm64 Linux. The legacy builder sets no TARGETARCH,
# so the build host's own architecture stands in for it.
#
# The Docker client is the scanner's, and it is not optional: `scan --mode
# docker` reaches the scanned container only through `docker inspect` and
# `docker exec`, so without a client on PATH that mode fails with a message
# naming the container rather than the missing binary. RailScan's image carried
# it for exactly this reason and the consolidation has to carry it too,
# otherwise the single container is less capable than the two it replaces.
#
# The static release rather than the Debian package: `docker.io` pulls the
# daemon and containerd for a client we invoke read-only against a mounted
# socket. Pinned, because "latest" in an image build is a version nobody chose.
# Callers still have to mount /var/run/docker.sock — necessary, not sufficient.
ARG AGENTSIGHT_VERSION=v1.0.35
ARG AGENTSIGHT_SHA256=6b7c7760bf1fddd1308587e873025b4b001de62216010499938effa946cc2d9e
ARG AGENTSIGHT_SHA256_ARM64=0d32e5f53301b9102836646c02df1fbc4f59e87a940aa417b67938db382b008f
ARG DOCKER_CLI_VERSION=27.3.1
ARG TARGETARCH
RUN case "${TARGETARCH:-$(uname -m)}" in \
      amd64|x86_64)  AS_ASSET=agentsight;         AS_SHA256="$AGENTSIGHT_SHA256" ;; \
      arm64|aarch64) AS_ASSET=agentsight-aarch64; AS_SHA256="$AGENTSIGHT_SHA256_ARM64" ;; \
      *) echo "no AgentSight release for ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /usr/local/bin/agentsight \
      "https://github.com/eunomia-bpf/agentsight/releases/download/${AGENTSIGHT_VERSION}/${AS_ASSET}" \
    && echo "${AS_SHA256}  /usr/local/bin/agentsight" | sha256sum -c - \
    && chmod +x /usr/local/bin/agentsight \
    && case "$(uname -m)" in \
         aarch64) DOCKER_ARCH=aarch64 ;; \
         x86_64)  DOCKER_ARCH=x86_64 ;; \
         *) echo "no Docker static release for $(uname -m)" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp docker/docker \
    && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker.tgz /tmp/docker

# The OpenShell CLI, for the opt-in `railmon openshell` collector only
# (DR-249): it reads a sandbox's policy and log from OpenShell's gateway.
# Pinned and checked as AgentSight is: the static musl build OpenShell
# publishes per architecture, against the sha256 its release's
# openshell-checksums-sha256.txt records. The version is the one
# datrail-project's CI installs (tests/openshell/install.sh). It adds one
# 26 MB static binary; nothing runs it unless the collector is started.
# Bumping is one edit of the three ARGs, after the fixture workflow in
# datrail-project has recorded the new release's output.
ARG OPENSHELL_VERSION=0.1.3
ARG OPENSHELL_SHA256=ed08ea7874c47f22d6e5dcc4b27d9ef1ef5d2060f83035b35ff725d5160830a3
ARG OPENSHELL_SHA256_ARM64=07687dacefc52bc73b01943f5b58f7a5082c1ceaa228461b9a2a78023b8057c0
RUN case "${TARGETARCH:-$(uname -m)}" in \
      amd64|x86_64)  OS_ARCH=x86_64;  OS_SHA256="$OPENSHELL_SHA256" ;; \
      arm64|aarch64) OS_ARCH=aarch64; OS_SHA256="$OPENSHELL_SHA256_ARM64" ;; \
      *) echo "no OpenShell release for ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/openshell.tgz \
      "https://github.com/NVIDIA/OpenShell/releases/download/v${OPENSHELL_VERSION}/openshell-${OS_ARCH}-unknown-linux-musl.tar.gz" \
    && echo "${OS_SHA256}  /tmp/openshell.tgz" | sha256sum -c - \
    && tar -xzf /tmp/openshell.tgz -C /tmp openshell \
    && install -m 0755 /tmp/openshell /usr/local/bin/openshell \
    && rm -f /tmp/openshell.tgz /tmp/openshell

# The collector keeps a distinct name so the entrypoint can dispatch to it
# without recursing into itself.
COPY --from=build /src/target/release/railmon /usr/local/bin/railmon-collector
# With RAIL_LISTEN_SOURCE=listensnoop or RAIL_FILES_SOURCE=filesnoop, the
# supervisor behind `railmon listen` and `railmon files` runs an operator's
# own probe binary inside the agent's PID namespace with nsenter
# (util-linux, in the base image); fail here rather than at first use.
RUN command -v nsenter

# tools/ carries symlinks from the RailScan-era paths
# (tools/agent-environment-scanner, tools/skills-scanner) to tools/scan and
# tools/skills, and rail-collector/rail_collector.py points at
# tools/forward/forward.py, so a deployment that calls a script by its old
# path keeps working. COPY keeps them as symlinks.
COPY tools/ /opt/railmon/tools/
COPY rail-collector/ /opt/railmon/rail-collector/
# The evidence-bundle schemas are the scanner's own contract, read (not merely
# tested against) at import time by tools/scan/evidence_bundle.py — both
# versions have to ship, unlike schemas/'s other,
# test-only copies. A missing one is a FileNotFoundError on every scan, which
# is what v2 was until CI started running a scan in the built image.
COPY schemas/evidence-bundle-v1.schema.json schemas/evidence-bundle-v2.schema.json /opt/railmon/schemas/
COPY entrypoint.sh /usr/local/bin/railmon
RUN chmod +x /usr/local/bin/railmon /opt/railmon/tools/local-demo/run_local_demo.sh

ENV AGENTSIGHT_PATH=/usr/local/bin/agentsight \
    RAILMON_ROOT=/opt/railmon
ENTRYPOINT ["/usr/local/bin/railmon"]
CMD ["help"]
