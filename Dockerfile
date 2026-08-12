# Two stages: build the collector, then ship a runtime that carries only the
# binary and AgentSight. The builder image is ~1.5GB of Rust toolchain and none
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

FROM debian:bookworm-slim

# libelf and zlib are AgentSight's, not ours: it loads eBPF objects at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Tracked, not pinned. AgentSight moves with us and a stale tap sees nothing —
# the same decision the Cargo dependency makes with a caret requirement.
RUN curl -fsSL -o /usr/local/bin/agentsight \
      https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight \
    && chmod +x /usr/local/bin/agentsight

COPY --from=build /src/target/release/railmon /usr/local/bin/railmon

ENV AGENTSIGHT_PATH=/usr/local/bin/agentsight
ENTRYPOINT ["/usr/local/bin/railmon"]
CMD ["--help"]
