FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm gcc libelf-dev zlib1g-dev make \
    && rm -rf /var/lib/apt/lists/*

COPY ebpf-tls-tap/ /build/ebpf-tls-tap/
WORKDIR /build/ebpf-tls-tap/bpf
RUN make sslsniff

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 libelf1 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/ebpf-tls-tap/bpf/sslsniff /usr/local/bin/sslsniff
COPY collector/ /opt/railmon/
RUN chmod +x /opt/railmon/entrypoint.sh

WORKDIR /opt/railmon
ENV SSLSNIFF_PATH=/usr/local/bin/sslsniff
ENTRYPOINT ["/opt/railmon/entrypoint.sh"]
CMD ["--help"]
