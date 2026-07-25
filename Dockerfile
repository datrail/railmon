FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates curl libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Direct download of the agentsight release binary.
RUN curl -fsSL -o /usr/local/bin/agentsight \
      https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight \
    && chmod +x /usr/local/bin/agentsight

COPY collector/ /opt/railmon/
RUN chmod +x /opt/railmon/entrypoint.sh

WORKDIR /opt/railmon
ENV AGENTSIGHT_PATH=/usr/local/bin/agentsight
ENTRYPOINT ["/opt/railmon/entrypoint.sh"]
CMD ["--help"]
