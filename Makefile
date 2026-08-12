.PHONY: build test fmt clippy docker clean fetch-agentsight build-ebpf

AGENTSIGHT_URL ?= https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight
AGENTSIGHT_BIN := bin/agentsight

build:
	cargo build --release

# fmt and clippy run here rather than only in CI, so the feedback arrives while
# the change is still in your head. Warnings are denied: a warning nobody has to
# fix is one nobody reads.
test:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

# Only needed to run the collector outside the container; the image downloads
# AgentSight itself. Unpinned on purpose — we track upstream.
fetch-agentsight:
	mkdir -p bin
	curl -fsSL -o $(AGENTSIGHT_BIN) $(AGENTSIGHT_URL)
	chmod +x $(AGENTSIGHT_BIN)
	$(AGENTSIGHT_BIN) --version

# Back-compat alias.
build-ebpf: fetch-agentsight

docker:
	docker build -t railmon .

clean:
	cargo clean
	rm -f $(AGENTSIGHT_BIN)
