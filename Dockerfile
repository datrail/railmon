# Three stages: build the collector, build the eBPF probes (listensnoop and
# filesnoop), then ship a runtime that carries only those binaries and
# AgentSight. The builder image is ~1.5GB of Rust toolchain and none
# of it needs to reach a host that is already running an agent under eBPF.
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

# The eBPF probes from ebpf-tls-tap: listensnoop (DR-124/DR-125), behind
# `railmon listen`, reporting each socket an agent opens to accept inbound
# traffic; and filesnoop (DR-152), behind `railmon files`, reporting each
# regular file it opens to read, write or run (DR-154).
# Built from the ebpf-tls-tap submodule, which pins the probes together with
# their libbpf, bpftool and kernel headers, on the same base as the runtime below so
# the libelf and glibc they link against are the ones they run with. The build
# fails, not skips, when the submodule was not checked out: an image without
# a probe would answer `listen` or `files` with "not found".
FROM python:3.13-slim AS probes
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm gcc libc6-dev libelf-dev zlib1g-dev libssl-dev make pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY ebpf-tls-tap/ ./
RUN test -f libbpf/src/Makefile || { \
      echo "ebpf-tls-tap submodule is empty: git submodule update --init --recursive" >&2; \
      exit 1; } \
    && make -C bpf listensnoop filesnoop

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
# image's stay the same release. DR-170 bumps this when the release carrying
# the listener and file capture it moves onto is cut.
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
ARG AGENTSIGHT_VERSION=v1.0.34
ARG AGENTSIGHT_SHA256=02f8b04c0b463b3c21b12027ef3deaccccaffd265e0249dee0156ad352e3e12d
ARG AGENTSIGHT_SHA256_ARM64=a333075ff5b89e998d4c4c11352d90e2b9740d5cb1eebb535703c7648e947f0a
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

# The collector keeps a distinct name so the entrypoint can dispatch to it
# without recursing into itself.
COPY --from=build /src/target/release/railmon /usr/local/bin/railmon-collector
COPY --from=probes /src/bpf/listensnoop /usr/local/bin/listensnoop
COPY --from=probes /src/bpf/filesnoop /usr/local/bin/filesnoop
# The supervisor behind `railmon listen` and `railmon files` enters the
# agent's PID namespace with nsenter (util-linux, in the base image); fail
# here rather than at first use.
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
