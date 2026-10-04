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

# Tracked, not pinned. AgentSight moves with us and a stale tap sees nothing —
# the same decision the Cargo dependency makes with a caret requirement.
#
# Upstream publishes an x86-64 release binary only, and the URL carries no
# architecture, so curl happily succeeds on arm64 and installs a binary that
# cannot exec. Guarded rather than downloaded blindly: an arm64 image is short a
# probe, which fails honestly, instead of shipping something that builds and
# then dies at runtime. RailScan's Dockerfile makes the same call.
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
ARG DOCKER_CLI_VERSION=27.3.1
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      curl -fsSL -o /usr/local/bin/agentsight \
        https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight \
      && chmod +x /usr/local/bin/agentsight; \
    else \
      echo "no AgentSight release for ${TARGETARCH:-this architecture}; skipping" >&2; \
    fi \
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
