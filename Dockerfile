FROM debian:bookworm-slim

ARG AGENTSIGHT_VERSION=v0.2.65

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates curl libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Prebuilt AgentSight release (embeds sslsniff eBPF probes).
RUN curl -fsSL -o /usr/local/bin/agentsight \
      "https://github.com/eunomia-bpf/agentsight/releases/download/${AGENTSIGHT_VERSION}/agentsight" \
    && chmod +x /usr/local/bin/agentsight

COPY collector/ /opt/railmon/
RUN chmod +x /opt/railmon/entrypoint.sh

WORKDIR /opt/railmon
ENV AGENTSIGHT_PATH=/usr/local/bin/agentsight
ENTRYPOINT ["/opt/railmon/entrypoint.sh"]
CMD ["--help"]
